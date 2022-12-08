use std::{path::PathBuf, net::SocketAddr};

use p256::ecdsa::signature::{Signature, Verifier};
use proxy::{setup_connection, encrypted_recv, encrypted_send};
use rand::RngCore;
use structopt::StructOpt;
use tokio::{net::{TcpStream, TcpSocket}, io::{AsyncWriteExt, AsyncReadExt}};
use uuid::Uuid;

#[derive(StructOpt)]
struct Args {
    /// Connect to server
    #[structopt(short, long, default_value = "127.0.0.1:1876")]
    server: SocketAddr,

    /// Remote address
    #[structopt(short, long, default_value = "47.93.189.174:80")]
    remote: SocketAddr,

    /// Remote address
    #[structopt(short, long, default_value = "0.0.0.0:1518")]
    bind: SocketAddr,

    /// UDP instead of TCP (WIP)
    #[structopt(short, long)]
    udp: bool,

    /// Path to load the private key
    #[structopt(short, long, default_value = "client.pem")]
    key: PathBuf,

    /// Path to load the server public key
    #[structopt(short, long, default_value = "pubkey.pem")]
    server_key: PathBuf,

    /// Path containing all user credentials
    #[structopt(short, long)]
    uid: Uuid,
}

#[paw::main]
#[tokio::main]
async fn main(args: Args) -> anyhow::Result<()> {
    env_logger::init();

    let key = std::fs::read_to_string(&args.key)?;
    let key = p256::SecretKey::from_sec1_pem(&key)?;

    let sign_key = p256::ecdsa::SigningKey::from(key);
    let server_key = p256::PublicKey::from_sec1_bytes(std::fs::read_to_string(&args.server_key)?.as_bytes())?;

    let server = TcpStream::connect(args.server).await?;

    let (
        mut server_read,
        mut server_write,
        session_cipher,
        ecdhe_public_sig,
        ecdhe_remote_buffer,
    ) = setup_connection(server, sign_key).await?;

    let resp = encrypted_recv(&mut server_read, session_cipher.clone()).await?;
    if resp.len() < 32 {
        log::error!("Server returning invalid signature size: {}", resp.len());
    }
    let sig = &resp[..32];
    let sig = p256::ecdsa::Signature::from_bytes(sig)?;
    let verifier = p256::ecdsa::VerifyingKey::from(server_key);
    verifier.verify(&ecdhe_remote_buffer, &sig)?;

    // Server verified, serializing request

    let mut reconn_token = vec![0u8; 32];
    rand::thread_rng().fill_bytes(&mut reconn_token);

    let mut buf = Vec::new();
    buf.write_u8(0).await?; // Create new connection
    buf.write_all(&reconn_token).await?;
    let mut addr_type: u8 = 0;
    if args.remote.is_ipv6() {
        addr_type += 0x10;
    }
    if args.udp {
        addr_type += 1;
    }
    buf.write_u8(addr_type).await?;
    match args.remote.ip() {
        std::net::IpAddr::V4(v4) => {
            buf.write(&v4.octets()).await?;
        }
        std::net::IpAddr::V6(v6) => {
            buf.write(&v6.octets()).await?;
        }
    }
    // BE = NE?
    buf.write_u16(args.remote.port()).await?;
    buf.write_all(args.uid.as_bytes()).await?;
    buf.write_all(ecdhe_public_sig.as_slice()).await?;
    proxy::encrypted_send(&mut server_write, session_cipher.clone(), buf.as_slice(), 0).await?;

    let sock = if args.bind.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    sock.set_reuseaddr(true)?;
    sock.bind(args.bind)?;

    let listener = sock.listen(1024)?;
    let (local, _local_addr) = listener.accept().await?;
    let (mut local_read, mut local_write) = local.into_split();

    let mut local_buf = vec![0u8; 1024];

    loop {
        tokio::select! {
            server_recv = encrypted_recv(&mut server_read, session_cipher.clone()) => {
                if server_recv.is_err() {
                    // TODO: retry connection
                    break;
                }
                local_write.write_all(server_recv.unwrap().as_slice()).await?;
            },
            local_recv_len = local_read.read(&mut local_buf) => {
                if local_recv_len.is_err() {
                    // TODO: gracefully close server
                    break;
                }
                let local_recv_len = local_recv_len.unwrap();
                if local_recv_len == 0 {
                    continue
                }
                let local_recv = &local_buf[..local_recv_len];
                encrypted_send(&mut server_write, session_cipher.clone(), local_recv, 0).await?;
            },
        }
    }

    Ok(())
}