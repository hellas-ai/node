//! `hellas artifact` subcommand — fetch retained canonical artifact bytes.

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{Context, bail};
use clap::Subcommand;
use hellas_rpc::Digest;
use hellas_rpc::pb::courtesy::GetArtifactRequest;
use hellas_rpc::services::courtesy::{Courtesy, CourtesyClientImpl};
use hellas_wire::ServiceMarker;
use hellas_wire::iroh::IrohTransport;
use iroh::endpoint::presets;
use iroh::{Endpoint, EndpointAddr, EndpointId, SecretKey, TransportAddr};

use crate::commands::CliResult;

#[derive(Debug, Subcommand)]
pub enum ArtifactCommand {
    /// Fetch canonical artifact bytes by digest from a provider
    Get {
        node_id: EndpointId,
        #[arg(long = "node-addr", value_delimiter = ',')]
        node_addrs: Vec<SocketAddr>,
        /// Artifact Xet hash.
        digest: Digest,
        #[arg(short = 'o', long = "output")]
        output: PathBuf,
    },
}

pub async fn run(command: ArtifactCommand, secret_key: SecretKey) -> CliResult<()> {
    match command {
        ArtifactCommand::Get {
            node_id,
            node_addrs,
            digest,
            output,
        } => get(node_id, node_addrs, digest, output, secret_key).await,
    }
}

async fn get(
    node_id: EndpointId,
    node_addrs: Vec<SocketAddr>,
    digest: Digest,
    output: PathBuf,
    secret_key: SecretKey,
) -> CliResult<()> {
    let client = connect_courtesy(node_id, node_addrs, secret_key).await?;
    let response = client
        .get_artifact(GetArtifactRequest {
            digest: digest.as_bytes().to_vec(),
        })
        .await
        .map_err(|e| anyhow::anyhow!("get_artifact: {e}"))?;
    let actual = Digest::hash(&response.canonical_artifact);
    if actual != digest {
        bail!("provider returned bytes with digest {actual}, expected {digest}");
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
    let endpoint_addr =
        EndpointAddr::from_parts(node_id, node_addrs.into_iter().map(TransportAddr::Ip));
    let connection = endpoint
        .connect(endpoint_addr, <Courtesy as ServiceMarker>::ALPN.as_bytes())
        .await
        .with_context(|| format!("failed to connect to {node_id}"))?;
    Ok(CourtesyClientImpl::new(IrohTransport::new(connection)))
}
