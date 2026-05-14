use crate::commands::CliResult;
use hellas_core::ProducerSigningKey;
use iroh::SecretKey;

pub fn show_node_id(secret_key: &SecretKey) -> CliResult<()> {
    println!("{}", secret_key.public());
    Ok(())
}

pub fn show_producer_key(key: &ProducerSigningKey) -> CliResult<()> {
    let public_key = key.public_key();
    println!("signature_kind: secp256k1");
    println!("public_key: {}", hex(public_key.bytes()));
    println!("producer_id: {}", hex(key.producer_id().as_bytes()));
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(out, "{byte:02x}");
    }
    out
}
