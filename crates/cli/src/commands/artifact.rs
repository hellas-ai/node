//! `hellas artifact` subcommand — put/get canonical artifact bytes
//! over the Courtesy service.

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{bail, Context};
use clap::Subcommand;
use hellas_core::Digest;
use hellas_rpc::pb::courtesy::{GetArtifactRequest, PutArtifactRequest};
use hellas_rpc::services::courtesy::{Courtesy, CourtesyClientImpl};
use hellas_wire::iroh::IrohTransport;
use hellas_wire::ServiceMarker;
use iroh::endpoint::presets;
use iroh::{Endpoint, EndpointAddr, EndpointId, SecretKey, TransportAddr};

use crate::commands::CliResult;

#[derive(Debug, Subcommand)]
pub enum ArtifactCommand {
    /// Store exact canonical artifact bytes on a provider and print the CID
    Put {
        node_id: EndpointId,
        #[arg(long = "node-addr", value_delimiter = ',')]
        node_addrs: Vec<SocketAddr>,
        path: PathBuf,
    },
    /// Fetch canonical artifact bytes by CID from a provider
    Get {
        node_id: EndpointId,
        #[arg(long = "node-addr", value_delimiter = ',')]
        node_addrs: Vec<SocketAddr>,
        /// 32-byte artifact CID as hex
        cid: String,
        #[arg(short = 'o', long = "output")]
        output: PathBuf,
    },
}

pub async fn run(command: ArtifactCommand, secret_key: SecretKey) -> CliResult<()> {
    match command {
        ArtifactCommand::Put {
            node_id,
            node_addrs,
            path,
        } => put(node_id, node_addrs, path, secret_key).await,
        ArtifactCommand::Get {
            node_id,
            node_addrs,
            cid,
            output,
        } => get(node_id, node_addrs, cid, output, secret_key).await,
    }
}

async fn put(
    node_id: EndpointId,
    node_addrs: Vec<SocketAddr>,
    path: PathBuf,
    secret_key: SecretKey,
) -> CliResult<()> {
    let canonical_artifact = tokio::fs::read(&path)
        .await
        .with_context(|| format!("failed to read artifact bytes from {}", path.display()))?;
    let client = connect_courtesy(node_id, node_addrs, secret_key).await?;
    let response = client
        .put_artifact(PutArtifactRequest { canonical_artifact })
        .await
        .map_err(|e| anyhow::anyhow!("put_artifact: {e}"))?;
    let cid = Digest::from_slice(&response.cid)
        .map_err(|e| anyhow::anyhow!("provider returned invalid artifact cid: {e}"))?;
    println!("{cid}");
    Ok(())
}

async fn get(
    node_id: EndpointId,
    node_addrs: Vec<SocketAddr>,
    cid: String,
    output: PathBuf,
    secret_key: SecretKey,
) -> CliResult<()> {
    let cid = parse_digest_hex(&cid)?;
    let client = connect_courtesy(node_id, node_addrs, secret_key).await?;
    let response = client
        .get_artifact(GetArtifactRequest {
            cid: cid.as_bytes().to_vec(),
        })
        .await
        .map_err(|e| anyhow::anyhow!("get_artifact: {e}"))?;
    let actual = Digest::hash(&response.canonical_artifact);
    if actual != cid {
        bail!("provider returned bytes with cid {actual}, expected {cid}");
    }
    tokio::fs::write(&output, response.canonical_artifact)
        .await
        .with_context(|| format!("failed to write artifact bytes to {}", output.display()))?;
    Ok(())
}

async fn connect_courtesy(
    node_id: EndpointId,
    node_addrs: Vec<SocketAddr>,
    secret_key: SecretKey,
) -> anyhow::Result<CourtesyClientImpl<IrohTransport>> {
    let endpoint = Endpoint::builder(presets::N0)
        .secret_key(secret_key)
        .alpns(vec![<Courtesy as ServiceMarker>::ALPN.as_bytes().to_vec()])
        .bind()
        .await
        .context("failed to bind iroh endpoint")?;
    let endpoint_addr = EndpointAddr::from_parts(
        node_id,
        node_addrs.into_iter().map(TransportAddr::Ip),
    );
    let connection = endpoint
        .connect(
            endpoint_addr,
            <Courtesy as ServiceMarker>::ALPN.as_bytes(),
        )
        .await
        .with_context(|| format!("failed to connect to {node_id}"))?;
    Ok(CourtesyClientImpl::new(IrohTransport::new(connection)))
}

fn parse_digest_hex(raw: &str) -> CliResult<Digest> {
    let raw = raw.trim();
    if raw.len() != 64 {
        bail!("artifact cid must be 64 hex chars, got {}", raw.len());
    }
    let mut bytes = [0u8; 32];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&raw[i * 2..i * 2 + 2], 16)
            .with_context(|| format!("invalid hex in artifact cid at position {}", i * 2))?;
    }
    Ok(Digest::from_bytes(bytes))
}
