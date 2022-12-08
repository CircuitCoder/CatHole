use std::{path::PathBuf, fs::File};

use elliptic_curve::pkcs8::{EncodePublicKey, LineEnding};
use p256;
use structopt::StructOpt;

#[derive(StructOpt)]
struct Args {
    /// Output path for public key
    #[structopt(short, long, default_value="pubkey.pem")]
    r#pub: PathBuf,

    /// Output path for private key
    #[structopt(short, long, default_value="privkey.pem")]
    key: PathBuf,
}

#[paw::main]
fn main(args: Args) -> anyhow::Result<()> {
    let mut rng = rand::thread_rng();
    let privkey = p256::SecretKey::random(&mut rng);
    let pubkey = privkey.public_key();

    let pubkey_pem = pubkey.to_public_key_pem(LineEnding::LF).unwrap();
    std::fs::write(args.r#pub, pubkey_pem)?;

    let privkey_pem = privkey.to_pem(LineEnding::LF).unwrap();
    std::fs::write(args.r#key, privkey_pem)?;

    Ok(())
}