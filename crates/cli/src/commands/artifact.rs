use crate::commands::CliResult;
use anyhow::{Context, bail};
use clap::Subcommand;
use hellas_core::Digest;
use hellas_pb::courtesy::courtesy_client::CourtesyClient;
use hellas_pb::courtesy::{GetArtifactRequest, PutArtifactRequest};
use hellas_rpc::GRPC_MESSAGE_LIMIT;
use hellas_rpc::discovery::DiscoveryEndpoint;
use hellas_rpc::peers::ServiceKey;
use hellas_rpc::service::CourtesyService;
use std::net::SocketAddr;
use std::path::PathBuf;
use tonic_iroh_transport::iroh::{EndpointAddr, EndpointId, SecretKey, TransportAddr};
use tonic_iroh_transport::{ConnectionPool, IrohChannel, IrohConnect, PoolOptions};

use crate::peer_rpc::{SharedPeerRegistry, acquire_rpc};

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
    let peer_registry = SharedPeerRegistry::default();
    let mut permit = acquire_rpc(
        &peer_registry,
        node_id,
        <CourtesyService as ServiceKey>::NAME,
        "PutArtifact",
        1.0,
    )?;
    let mut client = match connect(node_id, node_addrs, secret_key).await {
        Ok(client) => client,
        Err(err) => {
            permit.finish_connect_err(err.to_string());
            return Err(err);
        }
    };
    let response = match client
        .put_artifact(PutArtifactRequest { canonical_artifact })
        .await
    {
        Ok(response) => {
            permit.finish_ok();
            response.into_inner()
        }
        Err(err) => {
            permit.finish_err(err.to_string());
            return Err(err).context("put_artifact RPC failed");
        }
    };
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
    let peer_registry = SharedPeerRegistry::default();
    let mut permit = acquire_rpc(
        &peer_registry,
        node_id,
        <CourtesyService as ServiceKey>::NAME,
        "GetArtifact",
        1.0,
    )?;
    let mut client = match connect(node_id, node_addrs, secret_key).await {
        Ok(client) => client,
        Err(err) => {
            permit.finish_connect_err(err.to_string());
            return Err(err);
        }
    };
    let response = match client
        .get_artifact(GetArtifactRequest {
            cid: cid.as_bytes().to_vec(),
        })
        .await
    {
        Ok(response) => {
            permit.finish_ok();
            response.into_inner()
        }
        Err(err) => {
            permit.finish_err(err.to_string());
            return Err(err).context("get_artifact RPC failed");
        }
    };
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
) -> CliResult<CourtesyClient<IrohChannel>> {
    let endpoint = DiscoveryEndpoint::bind(Some(secret_key)).await?.endpoint;
    let channel = if node_addrs.is_empty() {
        let pool = ConnectionPool::for_service::<CourtesyService>(
            endpoint.clone(),
            PoolOptions::default(),
        );
        pool.channel(node_id)
            .await
            .with_context(|| format!("failed to connect to courtesy service on node {node_id}"))?
    } else {
        CourtesyService::connect(
            &endpoint,
            EndpointAddr::from_parts(node_id, node_addrs.into_iter().map(TransportAddr::Ip)),
        )
        .await
        .with_context(|| format!("failed to connect to courtesy service on node {node_id}"))?
    };
    Ok(CourtesyClient::new(channel)
        .max_decoding_message_size(GRPC_MESSAGE_LIMIT)
        .max_encoding_message_size(GRPC_MESSAGE_LIMIT))
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
