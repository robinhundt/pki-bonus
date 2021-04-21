use anyhow::{Result, Context};
use openssl::sha::sha256;
use openssl::base64;
use openssl::rsa::{Rsa, Padding};
use openssl::pkey::{Public, PKey};
use std::fs::File;
use std::io::Read;
use openssl::encrypt::Encrypter;

#[derive(Debug, Eq, PartialEq)]
pub struct HashAndEnc {
    pub encoded_hash: String,
    pub encoded_enc: String,
}

pub fn solve(name: &str, email: &str, matrikel_no: &str) -> Result<HashAndEnc> {
    let formatted = format!("{};{};{}", name, email, matrikel_no);
    let hashed = sha256(formatted.as_bytes());
    let encoded_hash = base64::encode_block(&hashed);
    let formatted = format!("{};{}", formatted, &encoded_hash);
    let pub_key = load_pub_key().context("Loading pub key")?;
    let pkey = PKey::from_rsa(pub_key)?;
    let mut encrypter = Encrypter::new(&pkey).context("creating encrypter")?;
    encrypter.set_rsa_padding(Padding::PKCS1)?;
    let buffer_len = encrypter.encrypt_len(formatted.as_bytes())?;
    let mut encrypted = vec![0; buffer_len];
    encrypter.encrypt(formatted.as_bytes(), &mut encrypted).context("encryption")?;
    let encoded_enc = base64::encode_block(&encrypted);
    Ok(HashAndEnc{encoded_hash, encoded_enc})
}


fn load_pub_key() -> Result<Rsa<Public>> {
    let mut key_file = File::open("task1_enc_publicKey.pem").context("Opening pub key pem file")?;
    let mut key_file_contents = Vec::new();
    key_file.read_to_end(&mut key_file_contents).context("Reading pub key pem file")?;
    Rsa::public_key_from_pem(&key_file_contents).context("Parsing pub key")
}

