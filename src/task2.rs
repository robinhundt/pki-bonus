use anyhow::{Context, Result};
use openssl::base64;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::sign::Signer;
use std::path::PathBuf;

pub fn solve(task_1_cipher: &PathBuf, out_folder: &PathBuf) -> Result<()> {
    let (id, task1_sol) = load_and_decode_task_1_cipher(&task_1_cipher)?;
    let rsa_key = Rsa::generate(4096).context("RSA key gen")?;
    write_rsa_key_pair(&id, &rsa_key, out_folder).context("Writing RSA key pair")?;
    let key_pair = PKey::from_rsa(rsa_key)?;
    let mut signer =
        Signer::new(MessageDigest::sha256(), &key_pair).context("Constructing signer")?;
    let signature = signer
        .sign_oneshot_to_vec(task1_sol.as_slice())
        .context("Signing")?;
    let signature = base64::encode_block(signature.as_slice());
    std::fs::write(out_folder.join(format!("Sig_{}.txt", id)), signature)
        .context("Writing signature")?;
    Ok(())
}

fn load_and_decode_task_1_cipher(path: &PathBuf) -> Result<(String, Vec<u8>)> {
    let id = path
        .file_stem()
        .context("Not a file")?
        .to_string_lossy()
        .strip_prefix("Enc_")
        .context("File does not start with 'Enc_'")?
        .into();
    let file_contents = std::fs::read_to_string(path).context("Reading task 1 solution")?;
    let decoded = base64::decode_block(&file_contents).context("decoding task 1 solution")?;
    Ok((id, decoded))
}

fn write_rsa_key_pair(id: &str, key: &Rsa<Private>, out_folder: &PathBuf) -> Result<()> {
    let pub_key_path = out_folder.join(format!("PubKey_{}.pem", id));
    let priv_key_path = out_folder.join(format!("PrivKey_{}.pem", id));

    let pub_key_pem = key.public_key_to_pem().context("Pub Key to pem")?;
    let priv_key_pem = key.private_key_to_pem().context("Priv Key to pem")?;

    std::fs::write(pub_key_path, pub_key_pem).context("Writing pub key")?;
    std::fs::write(priv_key_path, priv_key_pem).context("Writing priv key")?;
    Ok(())
}
