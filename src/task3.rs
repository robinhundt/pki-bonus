use anyhow::{Context, Result};
use openssl::asn1::Asn1Time;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private, Public};
use openssl::x509::extension::KeyUsage;
use openssl::x509::{X509Builder, X509Extension, X509Name, X509NameBuilder};
use std::fs;
use std::path::PathBuf;

/// The hash value created in task 1 serves as your ID
/// 1.  Open NextCloud, spreadsheet “Task3”:
///     Your ID will be added here, when your submission for Task 2 is correct.
///     In columns C,D,E,F next to your ID find the filenames relevant for this task.
///     In column B find your Entity ID.
/// 2.Create a self-signed certificate cert for your key pair from task 2
/// 3. Save cert as file <yourFilenameCertificate>.crt Use the PEM format.
/// 4.Upload your certificate to folder “Task3” (NextCloud)
///
/// **Certificate requirements:**
/// 1.Cert MUST be self signed: Issuer=Subject, verifiable with public key that is certified by the certificate (signing key pair from Task 2)
/// 2.Cert MUST be end entity certificate (basic constraints)
/// 3.Subject/Issuer DN: CN = <your entity ID>, OU = PKI, O = TU Darmstadt, L = Darmstadt, ST = Hessen, C = DE(only replace the value CN)(use X500Principal for correct order)
/// 4.Issuer Alternative Name = your ID hash value created in task 1
/// 5.Key Usage = digital signature
/// 6.The certificate must be currently valid
///
/// **Encoding and conversion rules:**
/// - Submitted certificates must be in PEM format and have the file ending “.crt
pub fn solve(
    hash_value: &str,
    public_key: &PathBuf,
    private_key: &PathBuf,
    out_folder: &PathBuf,
) -> Result<()> {
    let (id, pk, sk) = load_keys(public_key, private_key).context("Loading keys")?;
    let mut builder = X509Builder::new()?;
    let name = build_name(&id).context("Building name")?;
    builder.set_subject_name(&name)?;
    builder.set_issuer_name(&name)?;
    let issuer_alt = X509Extension::new_nid(
        None,
        Some(&builder.x509v3_context(None, None)),
        Nid::ISSUER_ALT_NAME,
        &format!("email:{}", hash_value),
    )
    .context("Building ISSUER_ALT ext")?;
    builder.append_extension(issuer_alt)?;
    let mut key_usage = KeyUsage::new();
    key_usage.critical();
    key_usage.digital_signature();
    builder.append_extension(key_usage.build()?)?;
    builder.set_pubkey(&pk)?;
    builder.set_version(2)?;
    builder.set_not_after(Asn1Time::days_from_now(365)?.as_ref())?;
    builder.set_not_before(Asn1Time::days_from_now(0)?.as_ref())?;

    builder.sign(&sk, MessageDigest::sha256())?;
    let cert = builder.build();
    std::fs::write(out_folder.join(format!("Cert_{}.crt", id)), cert.to_pem()?)
        .context("Writing certificate")?;
    Ok(())
}

/// Returns tuple of (id, pub_key, priv_key)
fn load_keys(pk: &PathBuf, sk: &PathBuf) -> Result<(String, PKey<Public>, PKey<Private>)> {
    let id = pk
        .file_stem()
        .context("Not a file")?
        .to_string_lossy()
        .strip_prefix("PubKey_")
        .context("PubKey file does not start with 'PubKey_'")?
        .into();
    let pk_content = fs::read(pk).context("Reading public key file")?;
    let pk = PKey::public_key_from_pem(&pk_content).context("Parsing pub key")?;
    let sk_content = fs::read(sk).context("Reading privage key file")?;
    let sk = PKey::private_key_from_pem(&sk_content).context("Parsing private key")?;

    Ok((id, pk, sk))
}

/// 3.Subject/Issuer DN: CN = <your entity ID>, OU = PKI, O = TU Darmstadt, L = Darmstadt, ST = Hessen, C = DE(only replace the value CN)(use X500Principal for correct order)
fn build_name(id: &str) -> Result<X509Name> {
    let mut x509_name = X509NameBuilder::new()?;
    x509_name.append_entry_by_text("C", "DE")?;
    x509_name.append_entry_by_text("ST", "Hessen")?;
    x509_name.append_entry_by_text("L", "Darmstadt")?;
    x509_name.append_entry_by_text("O", "TU Darmstadt")?;
    x509_name.append_entry_by_text("OU", "PKI")?;
    x509_name.append_entry_by_text("CN", id)?;
    Ok(x509_name.build())
}
