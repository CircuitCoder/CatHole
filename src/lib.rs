use std::{borrow::{Cow, Borrow}, io::Write, future::Future};

use aead::{AeadCore, AeadInPlace, Aead, KeySizeUser, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key};
use elliptic_curve::group::GroupEncoding;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use p256::{ecdh::EphemeralSecret, AffinePoint, ecdsa::signature::{Signer, Signature}};
use tokio::{net::{tcp::{OwnedWriteHalf, OwnedReadHalf}, TcpStream}, io::{AsyncReadExt, AsyncWriteExt}};

const GARBAGE: [u8; 2048] = [0; 2048];

#[derive(Clone, Copy, IntoPrimitive, TryFromPrimitive)]
#[repr(u64)]
pub enum CtrlCode {
    Close = 0,
}

pub enum Datagram<'a> {
    Msg(Cow<'a, [u8]>),
    Ctrl(CtrlCode),
}

impl<'a> Datagram<'a> {
    fn repr_len(&self) -> usize {
        match self {
            Datagram::Msg(inner) => inner.len(),
            Datagram::Ctrl(_) => 0,
        }
    }

    fn encoded_len(&self) -> usize {
        match self {
            Datagram::Msg(inner) => inner.len(),
            Datagram::Ctrl(_) => 8,
        }
    }

    fn write_to<W: Write>(&self, w: &mut W) -> std::io::Result<()> {
        match self {
            Datagram::Msg(inner) => w.write_all(inner.borrow()),
            Datagram::Ctrl(code) => {
                let encoded: u64 = (*code).into();
                let encoded: [u8; 8] = encoded.to_ne_bytes();
                w.write_all(&encoded)
            },
        }
    }
}

impl<'a> From<&'a [u8]> for Datagram<'a> {
    fn from(f: &'a [u8]) -> Self {
        Datagram::Msg(Cow::Borrowed(f))
    }
}

// FIXME: bloom filter nonce
pub async fn encrypted_send<'a>(client: &mut OwnedWriteHalf, cipher: ChaCha20Poly1305, data: Datagram<'a>, padding_len: usize) -> anyhow::Result<()> {
    if let Datagram::Ctrl(_) = data{
        if padding_len > 0  {
            return Err(anyhow::anyhow!("Unable to add padding to ctrl frames"));
        }
    }

    let repr_len = data.repr_len() + padding_len;
    let real_len = data.encoded_len() + padding_len; // Counter length
    let len: [u8; 8] = repr_len.to_ne_bytes();

    let len_nonce = ChaCha20Poly1305::generate_nonce(&mut rand::thread_rng());
    let data_nonce = ChaCha20Poly1305::generate_nonce(&mut rand::thread_rng());

    let mut buf = Vec::new();
    std::io::Write::write_all(&mut buf, len.as_slice())?;
    cipher.encrypt_in_place(&len_nonce, b"", &mut buf).map_err(|e| anyhow::anyhow!("Unable to encrypt len in place: {:?}", e))?;

    assert!(buf.len() == 16 + 8);

    log::debug!("Sending length = {} ({}), self = {}", repr_len, real_len, buf.len());
    client.write_all(len_nonce.as_slice()).await?;
    client.write_all(buf.as_slice()).await?;

    buf.clear();
    data.write_to(&mut buf)?;
    std::io::Write::write_all(&mut buf, &GARBAGE[0..padding_len.min(2048)])?;
    cipher.encrypt_in_place(&data_nonce, b"", &mut buf).map_err(|e| anyhow::anyhow!("Unable to encrypt data in place: {:?}", e))?;

    assert!(buf.len() == real_len + 16);

    log::debug!("Sending data, length = {}", buf.len());

    client.write_all(data_nonce.as_slice()).await?;
    client.write_all(buf.as_slice()).await?;

    Ok(())
}

pub async fn encrypted_recv<Fut: Future<Output = bool>, F: FnMut([u8; 12]) -> Fut>(client: &mut OwnedReadHalf, cipher: ChaCha20Poly1305, mut filter: F) -> anyhow::Result<Datagram<'static>> {
    let mut nonce_tag_len = vec![0u8; 12 + 16 + 8]; // Nonce = 12, Tag = 16, Length = 8
    client.read_exact(&mut nonce_tag_len).await?;

    let (nonce, tag_len) = nonce_tag_len.split_at(12);
    let nonce_fixed_len: [u8; 12] = nonce.try_into().unwrap();
    if !filter(nonce_fixed_len).await {
        return Err(anyhow::anyhow!("Duplicated nonce at length!"));
    }

    let len_dec = cipher.decrypt(nonce.into(), tag_len).map_err(|e| anyhow::anyhow!("Unable to decrypt len: {}", e))?;
    assert!(len_dec.len() == 8);
    let len = u64::from_ne_bytes(len_dec.as_slice().try_into().unwrap()) as usize;

    log::debug!("Got length = {}", len);
    let effective_len = if len == 0 { 8 } else { len };

    let mut data = vec![0u8; 12 + 16 + effective_len];
    client.read_exact(&mut data).await?;
    let (nonce, tag_data) = data.split_at(12);
    let nonce_fixed_len: [u8; 12] = nonce.try_into().unwrap();
    if !filter(nonce_fixed_len).await {
        return Err(anyhow::anyhow!("Duplicated nonce at data!"));
    }
    let data = cipher.decrypt(nonce.into(), tag_data).map_err(|e| anyhow::anyhow!("Unable to decrypt data: {}", e))?;

    log::debug!("Got data, real length = {}", data.len());
    match len {
        0 => {
            assert!(data.len() == 8);
            let decoded = u64::from_ne_bytes(data.try_into().unwrap());
            let decoded: CtrlCode = decoded.try_into()?;
            Ok(Datagram::Ctrl(decoded))
        },
        _ => {
            Ok(Datagram::Msg(Cow::Owned(data)))
        },
    }
}

pub async fn setup_connection(remote: TcpStream, key: p256::ecdsa::SigningKey) -> anyhow::Result<(OwnedReadHalf, OwnedWriteHalf, ChaCha20Poly1305, p256::ecdsa::Signature, Vec<u8>)> {
    remote.set_nodelay(true)?;

    let (mut remote_read, mut remote_write) = remote.into_split();

    let secret = {
        let mut rng = rand::thread_rng();
        EphemeralSecret::random(&mut rng)
    };
    let ecdhe_public = secret.public_key();
    let ecdhe_public = ecdhe_public.as_ref().to_bytes();
    let ecdhe_public: &[u8] = ecdhe_public.as_ref();

    let ecdhe_public_sig = key.sign(ecdhe_public);
    assert!(ecdhe_public_sig.as_bytes().len() == 64);

    remote_write.write_all(ecdhe_public).await?;
    let mut ecdhe_remote_buffer = vec![0u8; ecdhe_public.len()];
    remote_read.read_exact(&mut ecdhe_remote_buffer).await?;

    let remote_pt = AffinePoint::from_bytes(ecdhe_remote_buffer.as_slice().into());
    if remote_pt.is_none().into() {
        return Err(anyhow::anyhow!("Unable to parse ECDHE pub key"));
    };
    let recv_pt = remote_pt.unwrap();
    let remote_pubkey = p256::PublicKey::from_affine(recv_pt)?;

    let session_key_kdf = secret.diffie_hellman(&remote_pubkey);
    let session_key_kdf = session_key_kdf.extract::<sha2::Sha256>(None);
    let mut session_key = vec![0u8; <ChaCha20Poly1305 as KeySizeUser>::key_size()];
    session_key_kdf.expand(&[], session_key.as_mut_slice()).map_err(|e| anyhow::anyhow!("Unable to expand shared secret: {}", e))?;
    let session_key: &Key = Key::from_slice(session_key.as_slice());
    let session_cipher = ChaCha20Poly1305::new(session_key);

    Ok((
        remote_read,
        remote_write,
        session_cipher,
        ecdhe_public_sig,
        ecdhe_remote_buffer
    ))
}