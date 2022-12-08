use std::{net::{SocketAddr, SocketAddrV4, Ipv4Addr, Ipv6Addr, SocketAddrV6}, path::PathBuf, sync::Mutex, collections::HashMap, ffi::OsStr};
use chacha20poly1305::{ChaCha20Poly1305, KeySizeUser, Key, AeadCore, KeyInit};
use elliptic_curve::group::GroupEncoding;
use structopt::StructOpt;
use tokio::{net::{TcpSocket, TcpStream, tcp::{OwnedWriteHalf, OwnedReadHalf}}, io::AsyncReadExt};
use tokio::io::AsyncWriteExt;

use p256::{ecdh::EphemeralSecret, AffinePoint, ecdsa::signature::Signature};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::signature::Verifier;

use chacha20poly1305::aead::AeadInPlace;
use chacha20poly1305::aead::Aead;
use uuid::Uuid;

#[derive(StructOpt)]
struct Args {
    /// Bind to host
    #[structopt(short, long, default_value = "0.0.0.0:1876")]
    bind: SocketAddr,

    /// Path to load the private key
    #[structopt(short, long, default_value = "privkey.pem")]
    key: PathBuf,

    /// Path containing all user credentials
    #[structopt(short, long)]
    users: PathBuf,
}

struct Connection {
    client: Option<OwnedWriteHalf>,
    external: OwnedWriteHalf,
    reconn_token: [u8; 32],
}

struct ConnectionStore {
    conns: HashMap<uuid::Uuid, Connection>,
    reconn_map: HashMap<[u8; 32], uuid::Uuid>,
}

impl ConnectionStore {
    fn new() -> Self {
        Self {
            conns: HashMap::new(),
            reconn_map: HashMap::new(),
        }
    }
}

lazy_static::lazy_static! {
    static ref STORE: tokio::sync::Mutex<ConnectionStore> = tokio::sync::Mutex::new(ConnectionStore::new());
    static ref USERS: Mutex<HashMap<uuid::Uuid, p256::PublicKey>> = Mutex::new(HashMap::new());
}

const GARBAGE: [u8; 2048] = [0; 2048];

// FIXME: bloom filter nonce
async fn encrypted_send(client: &mut OwnedWriteHalf, cipher: ChaCha20Poly1305, data: &[u8], padding_len: usize) -> anyhow::Result<()> {
    // TODO: update scheme
    let tot_len = data.len() + padding_len; // Counter length
    let len: [u8; 8] = tot_len.to_ne_bytes();

    let len_nonce = ChaCha20Poly1305::generate_nonce(&mut rand::thread_rng());
    let data_nonce = ChaCha20Poly1305::generate_nonce(&mut rand::thread_rng());

    let mut buf = Vec::new();
    buf.write_all(len.as_slice()).await?;
    cipher.encrypt_in_place(&len_nonce, b"", &mut buf).map_err(|e| anyhow::anyhow!("Unable to encrypt len in place: {:?}", e))?;

    assert!(buf.len() == 16 + 8);

    client.write_all(len_nonce.as_slice()).await?;
    client.write_all(buf.as_slice()).await?;

    buf.clear();
    buf.write_all(data).await?;
    buf.write_all(&GARBAGE[0..padding_len.min(2048)]).await?;
    cipher.encrypt_in_place(&data_nonce, b"", &mut buf).map_err(|e| anyhow::anyhow!("Unable to encrypt data in place: {:?}", e))?;

    assert!(tot_len == 16 + 8);

    client.write_all(data_nonce.as_slice()).await?;
    client.write_all(buf.as_slice()).await?;

    Ok(())
}

async fn encrypted_recv(client: &mut OwnedReadHalf, cipher: ChaCha20Poly1305) -> anyhow::Result<Vec<u8>> {
    let mut nonce_tag_len = vec![0u8; 12 + 16 + 8]; // Nonce = 12, Tag = 16, Length = 8
    client.read_exact(&mut nonce_tag_len).await?;

    let (nonce, tag_len) = nonce_tag_len.split_at(12);
    let len_dec = cipher.decrypt(nonce.into(), tag_len).map_err(|e| anyhow::anyhow!("Unable to decrypt len: {}", e))?;
    assert!(len_dec.len() == 8);
    let len = u64::from_ne_bytes(len_dec.as_slice().try_into().unwrap()) as usize;

    let mut data = vec![0u8; 12 + 16 + len];
    client.read_exact(&mut data).await?;
    let (nonce, tag_data) = nonce_tag_len.split_at(12);
    let data = cipher.decrypt(nonce.into(), tag_data).map_err(|e| anyhow::anyhow!("Unable to decrypt data: {}", e))?;
    Ok(data)
}

async fn handle_external_read(mut external: OwnedReadHalf, id: Uuid, cipher: ChaCha20Poly1305) -> anyhow::Result<()> {
    loop {
        let mut buf = vec![0u8; 2048];
        let len = external.read(&mut buf).await?;
        let data = &buf[..len];

        if data.len() == 0 {
            continue;
        }

        let mut store_lock = STORE.lock().await;
        let target = store_lock.conns.get_mut(&id);
        if target.is_none() {
            // Connection torn down
            return Ok(())
        }
        let target = target.unwrap();
        if target.client.is_none() {
            continue;
        }
        let client = target.client.as_mut().unwrap();
        encrypted_send(client, cipher.clone(), data, 0).await?;
    }
}

async fn handle_client_read(mut client: OwnedReadHalf, id: Uuid, cipher: ChaCha20Poly1305) -> anyhow::Result<()> {
    loop {
        let buf = encrypted_recv(&mut client, cipher.clone()).await?;

        let mut store_lock = STORE.lock().await;
        let target = store_lock.conns.get_mut(&id);
        if target.is_none() {
            // Connection torn down
            return Ok(())
        }
        let target = target.unwrap();
        target.external.write_all(buf.as_slice()).await?;
    }
}

async fn handle_client(client: TcpStream, key: p256::SecretKey) -> anyhow::Result<()> {
    client.set_nodelay(true)?;
    let sign_key = p256::ecdsa::SigningKey::from(key);
    let (mut client_read, mut client_write) = client.into_split();

    // Step 1, ecdhgg/ecdh

    let secret = {
        let mut rng = rand::thread_rng();
        EphemeralSecret::random(&mut rng)
    };
    let ecdhe_public = secret.public_key();
    let ecdhe_public = ecdhe_public.as_ref().to_bytes();
    let ecdhe_public: &[u8] = ecdhe_public.as_ref();

    let ecdhe_public_sig = sign_key.sign(ecdhe_public);
    assert!(ecdhe_public_sig.as_bytes().len() == 32);

    client_write.write_all(ecdhe_public).await?;
    let mut ecdhe_remote_buffer = vec![0u8; ecdhe_public.len()];
    client_read.read_exact(&mut ecdhe_remote_buffer).await?;

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

    encrypted_send(&mut client_write, session_cipher.clone(), ecdhe_public_sig.as_bytes(), 0).await?;
    let resp = encrypted_recv(&mut client_read, session_cipher.clone()).await?;

    if resp.len() < 34 {
        return Err(anyhow::anyhow!("Invalid handshake length: {}", resp.len()));
    }

    let opcode = resp[0];
    // TODO: handle reconnection

    let reconn_token = &resp[1..33];
    let addr_type = resp[33];
    let resp_rest = &resp[34..];

    let addr_type_ip = addr_type >> 4;
    let addr_type_l4 = addr_type & 0xF;
    if addr_type_ip > 1 || addr_type_l4 > 1 {
        return Err(anyhow::anyhow!("Invalid address type: {:x}", addr_type));
    }

    if (addr_type_ip == 0 && resp_rest.len() < 4 + 2 + 16 + 32) || (addr_type_ip == 1 && resp_rest.len() < 16 + 2 + 16 + 32) {
        return Err(anyhow::anyhow!("Invalid handshake length: {}", resp.len()));
    }

    let (addr, resp_rest) = if addr_type_ip == 0 {
        let seg = &resp_rest[0..4];
        let seg: [u8; 4] = seg.try_into().unwrap();
        let port = u16::from_ne_bytes((&resp_rest[4..6]).try_into().unwrap());
        let v4 = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(seg), port));
        (v4, &resp_rest[6..])
    } else {
        let seg = &resp_rest[0..16];
        let seg: [u8; 16] = seg.try_into().unwrap();
        let port = u16::from_ne_bytes((&resp_rest[16..18]).try_into().unwrap());
        let v4 = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(seg), port, 0, 0));
        (v4, &resp_rest[6..])
    };

    let uid = &resp_rest[0..16];
    let sig = &resp_rest[16..48];

    let uid = uuid::Uuid::from_bytes(uid.try_into().unwrap());
    {
        let users_lock = USERS.lock().unwrap();
        let user_key = match users_lock.get(&uid) {
            None => {
                return Err(anyhow::anyhow!("Non-existing user {}", uid));
            },
            Some(key) => key,
        };
        let sig = p256::ecdsa::Signature::from_bytes(sig)?;
        let verifier = p256::ecdsa::VerifyingKey::from(user_key);
        verifier.verify(&ecdhe_remote_buffer, &sig)?;
    }

    // Create internal id
    // TODO: support UDP
    let external_socket = TcpStream::connect(addr).await?;
    let (external_read, external_write) = external_socket.into_split();

    let internal_id = uuid::Uuid::new_v4();
    let mut store_lock = STORE.lock().await;
    store_lock.reconn_map.insert(reconn_token.try_into().unwrap(), internal_id);
    let conn = Connection {
        client: Some(client_write),
        external: external_write,
        reconn_token: reconn_token.try_into().unwrap(),
    };

    store_lock.conns.insert(internal_id, conn);

    let external_read_cipher = session_cipher.clone();
    let external_read_id = internal_id.clone();
    tokio::spawn(async move {
        let ret = handle_external_read(external_read, external_read_id, external_read_cipher).await;
        if let Err(e) = ret {
            log::error!("Error reading external socket {}", e);
            // TODO: tear down connection
        }
    });

    let client_read_cipher = session_cipher.clone();
    let client_read_id = internal_id.clone();
    tokio::spawn(async move {
        let ret = handle_client_read(client_read, client_read_id, client_read_cipher).await;
        if let Err(e) = ret {
            log::error!("Error reading client socket {}", e);
            // TODO: tear down connection
        }
    });

    Ok(())
}

#[paw::main]
#[tokio::main]
async fn main(args: Args) -> anyhow::Result<()> {
    env_logger::init();

    let key = std::fs::read_to_string(&args.key)?;
    let key = p256::SecretKey::from_sec1_pem(&key)?;

    for entry in std::fs::read_dir(args.users)? {
        let entry = entry?;
        let path = entry.path();
        let extname = path.extension();
        if extname != Some(OsStr::new("pem")) {
            log::info!("Ignoring non-pem file: {}", path.display());
            continue;
        }

        if let Some(inner) = path.file_stem().and_then(|e| e.to_str()).and_then(|e| uuid::Uuid::parse_str(e).ok()) {
            let key = std::fs::read_to_string(path)?;
            let key = p256::PublicKey::from_sec1_bytes(key.as_bytes())?;
            USERS.lock().unwrap().insert(inner, key);
        } else {
            log::info!("Ignoring invalid filename: {}", path.display());
        }
    }

    let sock = if args.bind.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    sock.set_reuseaddr(true)?;
    sock.bind(args.bind)?;

    let listener = sock.listen(1024)?;

    let mut client_handles = Vec::new();

    loop {
        let accepted = listener.accept().await;
        let accepted = match accepted {
            Err(e) => {
                log::warn!("Unable to accept client: {:?}", e);
                continue;
            },
            Ok(a) => a,
        };

        log::info!("Accepted client at {:?}", accepted.1);

        let k = key.clone();
        let handle = tokio::spawn(async move {
            let ret = handle_client(accepted.0, k).await;
            if let Err(e) = ret {
                log::error!("Error with client {:?}: {:?}", accepted.1, e);
            }
        });
        client_handles.push(handle);
    }
}
