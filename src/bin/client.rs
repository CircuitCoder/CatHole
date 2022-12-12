use std::{path::PathBuf, net::SocketAddr, str::FromStr, borrow::Borrow, collections::HashSet};

use p256::{ecdsa::signature::{Signature, Verifier}, SecretKey};
use proxy::{setup_connection, encrypted_recv, encrypted_send, Datagram, CtrlCode};
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
    // #[structopt(long)]
    // udp: bool,

    /// Path to load the private key
    #[structopt(short, long, default_value = "client.pem")]
    key: PathBuf,

    /// Path to load the server public key
    #[structopt(short="p", long, default_value = "pubkey.pem")]
    server_key: PathBuf,

    /// UID
    #[structopt(short, long)]
    uid: Uuid,
}

lazy_static::lazy_static! {
    static ref USED_NONCES: tokio::sync::Mutex<HashSet<[u8; 12]>> = tokio::sync::Mutex::new(HashSet::new());
}

async fn filter(input: [u8; 12]) -> bool {
    let mut locked = USED_NONCES.lock().await;
    locked.insert(input)
}

fn kickoff_connect_server(
    local: TcpStream,
    server: SocketAddr,
    remote: SocketAddr,
    udp: bool,
    uid: Uuid,
    key: SecretKey,
    server_key: p256::PublicKey,
    reconn_token: Option<[u8; 32]>,
) {
    tokio::spawn(async move {
        let ret = connect_server(local, server, remote, udp, uid, key, server_key, reconn_token).await;
        if let Err(e) = ret {
            log::error!("Error with socket: {}", e);
        }
    });
}

async fn connect_server(
    mut local: TcpStream,
    server: SocketAddr,
    remote: SocketAddr,
    udp: bool,
    uid: Uuid,
    key: SecretKey,
    server_key: p256::PublicKey,
    reconn_token: Option<[u8; 32]>,
) -> anyhow::Result<()> {
    let sign_key = p256::ecdsa::SigningKey::from(key.clone());
    let server_addr = server.clone();
    let server = TcpStream::connect(server).await?;

    let (
        mut server_read,
        mut server_write,
        session_cipher,
        ecdhe_public_sig,
        ecdhe_remote_buffer,
    ) = setup_connection(server, sign_key).await?;

    let resp = match encrypted_recv(&mut server_read, session_cipher.clone(), filter).await? {
        Datagram::Ctrl(c) => {
            let code: u64 = c.into();
            return Err(anyhow::anyhow!("Unexpected ctrl datagram at handshake: {}", code));
        },
        Datagram::Msg(m) => m,
    };
    if resp.len() < 32 {
        log::error!("Server returning invalid signature size: {}", resp.len());
    }
    let sig = &resp[..64];
    let sig = p256::ecdsa::Signature::from_bytes(sig)?;
    let verifier = p256::ecdsa::VerifyingKey::from(server_key);
    log::debug!("Got sig: {}", sig);
    verifier.verify(&ecdhe_remote_buffer, &sig)?;

    // Server verified, serializing request

    let opcode: u8 = if reconn_token.is_some() { 1 } else { 0 };
    let reconn_token = reconn_token.unwrap_or_else(|| {
        let mut buf = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut buf);
        buf
    });

    let mut buf = Vec::new();
    buf.write_u8(opcode).await?;
    buf.write_all(&reconn_token).await?;
    let mut addr_type: u8 = 0;
    if remote.is_ipv6() {
        addr_type += 0x10;
    }
    if udp {
        addr_type += 1;
    }
    buf.write_u8(addr_type).await?;
    match remote.ip() {
        std::net::IpAddr::V4(v4) => {
            buf.write(&v4.octets()).await?;
        }
        std::net::IpAddr::V6(v6) => {
            buf.write(&v6.octets()).await?;
        }
    }
    // BE = NE?
    buf.write_all(&remote.port().to_ne_bytes()).await?;
    buf.write_all(uid.as_bytes()).await?;
    buf.write_all(ecdhe_public_sig.as_bytes()).await?;
    proxy::encrypted_send(&mut server_write, session_cipher.clone(), buf.as_slice().into(), 0).await?;

    let mut local_buf = vec![0u8; 4096];

    loop {
        tokio::select! {
            server_recv = encrypted_recv(&mut server_read, session_cipher.clone(), filter) => {
                if server_recv.is_err() {
                    kickoff_connect_server(local, server_addr, remote, udp, uid, key, server_key, Some(reconn_token));
                    break;
                }
                match server_recv.unwrap() {
                    Datagram::Msg(m) => {
                        local.write_all(m.borrow()).await?;
                    },
                    Datagram::Ctrl(c) => {
                        let code: u64 = c.into();
                        log::info!("Got ctrl: {}", code);
                        match c {
                            proxy::CtrlCode::Close => break,
                        }
                    },
                }
            },
            local_recv_len = local.read(&mut local_buf) => {
                let local_recv_len = local_recv_len?;
                if local_recv_len == 0 {
                    // Shutdown
                    log::info!("Local socket EOF, shutting down server conn");
                    encrypted_send(&mut server_write, session_cipher.clone(), Datagram::Ctrl(CtrlCode::Close), 0).await?;
                    break;
                }
                let local_recv = &local_buf[..local_recv_len];
                encrypted_send(&mut server_write, session_cipher.clone(), local_recv.into(), 0).await?;
            },
        }
    }

    log::info!("Connection terminated.");

    Ok(())
}

#[paw::main]
#[tokio::main]
async fn main(args: Args) -> anyhow::Result<()> {
    env_logger::init();

    let key = std::fs::read_to_string(&args.key)?;
    let key = p256::SecretKey::from_sec1_pem(&key)?;

    let server_key = p256::PublicKey::from_str(&std::fs::read_to_string(&args.server_key)?)?;
    log::info!("Keys loaded");

    let sock = if args.bind.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    sock.set_reuseaddr(true)?;
    sock.bind(args.bind)?;

    log::info!("Binding {}...", args.bind);

    let listener = sock.listen(1024)?;

    loop {
        let (local, _local_addr) = listener.accept().await?;
        let key = key.clone();
        let server_key = server_key.clone();
        let server = args.server.clone();
        let remote = args.remote.clone();
        let udp = false;
        let uid = args.uid.clone();

        kickoff_connect_server(local, server, remote, udp, uid, key, server_key, None);
    }
}