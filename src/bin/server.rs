use std::{net::{SocketAddr, SocketAddrV4, Ipv4Addr, Ipv6Addr, SocketAddrV6}, path::PathBuf, sync::Mutex, collections::{HashMap, HashSet}, ffi::OsStr, str::FromStr, borrow::Borrow};
use proxy::{encrypted_send, encrypted_recv, setup_connection, Datagram, CtrlCode};
use structopt::StructOpt;
use tokio::net::{TcpSocket, TcpStream};
use tokio::io::AsyncWriteExt;
use tokio::io::AsyncReadExt;

use p256::{ecdsa::signature::Signature};
use p256::ecdsa::signature::Verifier;

#[derive(StructOpt)]
struct Args {
    /// Bind to host
    #[structopt(short, long, default_value = "0.0.0.0:1876")]
    bind: SocketAddr,

    /// Path to load the private key
    #[structopt(short, long, default_value = "privkey.pem")]
    key: PathBuf,

    /// Path containing all user credentials
    #[structopt(short, long, default_value = "users")]
    users: PathBuf,
}

struct ConnectionStore {
    parked: HashMap<[u8; 32], TcpStream>,
}

impl ConnectionStore {
    fn new() -> Self {
        Self {
            parked: HashMap::new(),
        }
    }
}

lazy_static::lazy_static! {
    static ref STORE: tokio::sync::Mutex<ConnectionStore> = tokio::sync::Mutex::new(ConnectionStore::new());
    static ref USERS: Mutex<HashMap<uuid::Uuid, p256::PublicKey>> = Mutex::new(HashMap::new());
    static ref USED_NONCES: tokio::sync::Mutex<HashSet<[u8; 12]>> = tokio::sync::Mutex::new(HashSet::new());
}

async fn filter(input: [u8; 12]) -> bool {
    let mut locked = USED_NONCES.lock().await;
    locked.insert(input)
}

async fn handle_client(client: TcpStream, key: p256::SecretKey) -> anyhow::Result<()> {
    let sign_key = p256::ecdsa::SigningKey::from(key);

    let (
        mut client_read,
        mut client_write,
        session_cipher,
        ecdhe_public_sig,
        ecdhe_remote_buffer,
    ) = setup_connection(client, sign_key).await?;

    log::debug!("Sending sig: {}", ecdhe_public_sig);
    encrypted_send(&mut client_write, session_cipher.clone(), ecdhe_public_sig.as_bytes().into(), 0).await?;
    let resp = match encrypted_recv(&mut client_read, session_cipher.clone(), filter).await? {
        Datagram::Ctrl(c) => {
            let code: u64 = c.into();
            return Err(anyhow::anyhow!("Unexpected ctrl datagram at handshake: {}", code));
        },
        Datagram::Msg(m) => m,
    };

    if resp.len() < 34 {
        return Err(anyhow::anyhow!("Invalid handshake length: {}", resp.len()));
    }

    let opcode = resp[0];

    let reconn_token = &resp[1..33];
    let reconn_token: &[u8; 32] = reconn_token.try_into().unwrap();
    let addr_type = resp[33];
    let resp_rest = &resp[34..];

    let addr_type_ip = addr_type >> 4;
    let addr_type_l4 = addr_type & 0xF;
    if addr_type_ip > 1 || addr_type_l4 > 1 {
        return Err(anyhow::anyhow!("Invalid address type: {:x}", addr_type));
    }

    if (addr_type_ip == 0 && resp_rest.len() < 4 + 2 + 16 + 64) || (addr_type_ip == 1 && resp_rest.len() < 16 + 2 + 16 + 64) {
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
    let sig = &resp_rest[16..80];

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

    // TODO: support UDP
    let mut external = if opcode == 0 {
        TcpStream::connect(addr).await?
    } else {
        let mut lock = STORE.lock().await;
        match lock.parked.remove(reconn_token) {
            Some(found) => found,
            None => return Err(anyhow::anyhow!("Reconnect token {:?} not found", reconn_token)),
        }
    };

    let mut external_buf = vec![0u8; 4096];

    loop {
        tokio::select! {
            client_recv = encrypted_recv(&mut client_read, session_cipher.clone(), filter) => {
                if client_recv.is_err() {
                    let mut lock = STORE.lock().await;
                    lock.parked.insert(reconn_token.clone(), external);
                    break;
                }
                match client_recv.unwrap() {
                    Datagram::Msg(m) => {
                        external.write_all(m.borrow()).await?;
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
            external_recv_len = external.read(&mut external_buf) => {
                let external_recv_len = external_recv_len?;
                if external_recv_len == 0 {
                    // Shutdown
                    log::info!("External socket EOF, shutting down client conn");
                    encrypted_send(&mut client_write, session_cipher.clone(), Datagram::Ctrl(CtrlCode::Close), 0).await?;
                    break;
                }
                let external_recv = &external_buf[..external_recv_len];
                encrypted_send(&mut client_write, session_cipher.clone(), external_recv.into(), 0).await?;
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

    log::info!("Key loaded!");

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
            let key = p256::PublicKey::from_str(&key)?;
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
