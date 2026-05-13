use crate::commands::CliResult;
use anyhow::{Context, bail};
use clap::Subcommand;
use hellas_core::Digest;
use hellas_pb::courtesy::{GetArtifactRequest, PutArtifactRequest};
use hellas_rpc::client::CourtesyClient;
use hellas_rpc::discovery::DiscoveryEndpoint;
use hellas_rpc::peers::{IrohPeerHandle, IrohTransport, PeerManager};
use std::net::SocketAddr;
use std::path::PathBuf;
use tonic_iroh_transport::iroh::{EndpointAddr, EndpointId, SecretKey, TransportAddr};

#[derive(Debug, Subcommand)]
pub enum ArtifactCommand {
    /// Store exact canonical artifact bytes on a provider and print the CID
    Put {
        /// Node ID of the provider to store on
        node_id: EndpointId,
        /// Direct UDP address hint for the provider. Repeat or use commas.
        #[arg(long = "node-addr", value_delimiter = ',')]
        node_addrs: Vec<SocketAddr>,
        /// File containing exact canonical artifact bytes
        path: PathBuf,
    },
    /// Fetch canonical artifact bytes by CID from a provider
    Get {
        /// Node ID of the provider to fetch from
        node_id: EndpointId,
        /// Direct UDP address hint for the provider. Repeat or use commas.
        #[arg(long = "node-addr", value_delimiter = ',')]
        node_addrs: Vec<SocketAddr>,
        /// 32-byte artifact CID as hex
        cid: String,
        /// File to write the fetched canonical artifact bytes
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
    let handle = connect(node_id, node_addrs, secret_key).await?;
    let response = handle
        .put_artifact(PutArtifactRequest { canonical_artifact })
        .await
        .context("put_artifact RPC failed")?
        .into_inner();
    let cid =
        Digest::from_slice(&response.cid).context("provider returned invalid artifact cid")?;
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
    let handle = connect(node_id, node_addrs, secret_key).await?;
    let response = handle
        .get_artifact(GetArtifactRequest {
            cid: cid.as_bytes().to_vec(),
        })
        .await
        .context("get_artifact RPC failed")?
        .into_inner();
    let actual = Digest::hash(&response.canonical_artifact);
    if actual != cid {
        bail!("provider returned bytes with cid {actual}, expected {cid}");
    }
    tokio::fs::write(&output, response.canonical_artifact)
        .await
        .with_context(|| format!("failed to write artifact bytes to {}", output.display()))?;
    Ok(())
}

async fn connect(
    node_id: EndpointId,
    node_addrs: Vec<SocketAddr>,
    secret_key: SecretKey,
) -> CliResult<IrohPeerHandle> {
    let peer_registry = PeerManager::default();
    let endpoint = DiscoveryEndpoint::bind(Some(secret_key)).await?.endpoint;
    let transport = IrohTransport::new(endpoint, peer_registry);
    Ok(if node_addrs.is_empty() {
        transport.peer(node_id)
    } else {
        let endpoint_addr =
            EndpointAddr::from_parts(node_id, node_addrs.into_iter().map(TransportAddr::Ip));
        transport.peer_at(node_id, endpoint_addr)
    })
}

fn parse_digest_hex(raw: &str) -> CliResult<Digest> {
    let bytes = raw.as_bytes();
    if bytes.len() != Digest::LEN * 2 {
        bail!(
            "artifact cid must be {} hex chars, got {}",
            Digest::LEN * 2,
            bytes.len()
        );
    }
    let mut out = [0_u8; Digest::LEN];
    for (idx, chunk) in bytes.chunks_exact(2).enumerate() {
        let high = hex_value(chunk[0]).with_context(|| format!("invalid artifact cid {raw:?}"))?;
        let low = hex_value(chunk[1]).with_context(|| format!("invalid artifact cid {raw:?}"))?;
        out[idx] = (high << 4) | low;
    }
    Ok(Digest::from_bytes(out))
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
