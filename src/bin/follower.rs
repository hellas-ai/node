use clap::Parser;
use commonware_codec::DecodeExt;
use commonware_consensus::Heightable;
use commonware_cryptography::Digestible;
use commonware_runtime::{Runner as _, Supervisor as _, tokio};
use hellas_chain::pb::hellas::{ActivityEvent, ActivityEventKind, activity_event};
use hellas_chain::{
    Application, ApplicationConfig, ChainIndexer, ConsensusInfo, ConsensusVerifier,
    FinalizedBlockQuery, IngestError, LightClient as _, QueryError, spawn_follower_indexer,
};
use hellas_chain::{client::RemoteLightClient, config::Config};
use hellas_kernel::domain::{Digest, PublicKey};
use std::{path::PathBuf, time::Duration};
use thiserror::Error;
use tracing::warn;

const RECONNECT_DELAY: Duration = Duration::from_secs(1);
const ANNOUNCED_BLOCK_RETRIES: u32 = 50;
const ANNOUNCED_BLOCK_RETRY_DELAY: Duration = Duration::from_millis(100);

#[derive(Debug, Error)]
enum FollowerError {
    #[error("unable to determine local data directory")]
    MissingDataDirectory,
    #[error("storage directory is not valid UTF-8: {0}")]
    NonUtf8StorageDirectory(PathBuf),
    #[error("invalid validator key data")]
    InvalidValidatorKey,
    #[error("invalid {field}: expected 32 bytes, got {len}")]
    InvalidDigest { field: &'static str, len: usize },
    #[error("activity event was missing its event body")]
    MissingActivityEvent,
    #[error("finalization activity was missing its proposal")]
    MissingFinalizationProposal,
    #[error("activity stream ended")]
    ActivityStreamEnded,
    #[error("activity stream failed: {0}")]
    ActivityStream(String),
    #[error("remote latest is {remote_latest}, but finalized block at height {height} was absent")]
    MissingFinalizedBlock { height: u64, remote_latest: u64 },
    #[error("announced finalized block was unavailable for payload {payload:?}")]
    AnnouncedBlockUnavailable { payload: Digest },
    #[error("remote snapshot height {remote} is behind local height {local}")]
    RemoteBehind { local: u64, remote: u64 },
    #[error(
        "requested finalized height {requested}, but snapshot height was {snapshot} and block height was {block}"
    )]
    FinalizedBlockHeightMismatch {
        requested: u64,
        snapshot: u64,
        block: u64,
    },
    #[error("finalized snapshot height {snapshot} did not match block height {block}")]
    SnapshotBlockHeightMismatch { snapshot: u64, block: u64 },
    #[error("finalized snapshot payload {snapshot:?} did not match block payload {block:?}")]
    SnapshotBlockPayloadMismatch { snapshot: Digest, block: Digest },
    #[error("{0}")]
    Query(#[from] QueryError),
    #[error("{0}")]
    Consensus(#[from] hellas_chain::ConsensusVerificationError),
    #[error("{0}")]
    Ingest(#[from] IngestError),
}

impl FollowerError {
    const fn retryable(&self) -> bool {
        matches!(
            self,
            Self::ActivityStreamEnded
                | Self::ActivityStream(_)
                | Self::AnnouncedBlockUnavailable { .. }
                | Self::MissingFinalizedBlock { .. }
                | Self::Query(
                    QueryError::ChannelClosed | QueryError::Remote(_) | QueryError::Connect(_)
                )
        )
    }
}

#[derive(Parser)]
#[command(name = "follower")]
struct Cli {
    #[arg(long)]
    rpc: String,
    #[arg(long)]
    storage_dir: Option<PathBuf>,
    #[arg(long, default_value = "hellas-follower")]
    partition_prefix: String,
}

fn main() -> Result<(), FollowerError> {
    init_tracing();
    let cli = Cli::parse();
    let storage_dir = cli
        .storage_dir
        .clone()
        .map(Ok)
        .unwrap_or_else(default_storage_dir)?;
    let storage_dir_utf8 = storage_dir
        .to_str()
        .ok_or_else(|| FollowerError::NonUtf8StorageDirectory(storage_dir.clone()))?;
    let runtime_cfg = tokio::Config::new()
        .with_storage_directory(storage_dir_utf8)
        .with_tcp_nodelay(Some(true));
    tokio::Runner::new(runtime_cfg).start(move |context| async move { follow(context, cli).await })
}

async fn follow(context: tokio::Context, cli: Cli) -> Result<(), FollowerError> {
    let client = RemoteLightClient::connect(cli.rpc.clone()).await?;
    let consensus_info = client.get_consensus_info().await?;
    let verifier = ConsensusVerifier::new(&consensus_info)?;
    let genesis_leader = genesis_leader(&consensus_info)?;
    let application = Application::new(
        context.child("app"),
        genesis_leader,
        Vec::new(),
        &format!("{}-genesis", cli.partition_prefix),
        ApplicationConfig::default(),
    )
    .await;
    let (indexer, _marshal) = spawn_follower_indexer(
        context.child("indexer"),
        &cli.partition_prefix,
        Config::mainnet(),
        verifier,
        application.genesis_block(),
    )
    .await?;
    follow_remote(indexer, cli.rpc, consensus_info).await
}

async fn follow_remote(
    indexer: ChainIndexer,
    rpc: String,
    consensus_info: ConsensusInfo,
) -> Result<(), FollowerError> {
    loop {
        match follow_connection(&indexer, &rpc, &consensus_info).await {
            Ok(()) => unreachable!("follow_connection only returns when the stream disconnects"),
            Err(err) if err.retryable() => {
                warn!(error = %err, "follower upstream disconnected");
                ::tokio::time::sleep(RECONNECT_DELAY).await;
            }
            Err(err) => return Err(err),
        }
    }
}

async fn follow_connection(
    indexer: &ChainIndexer,
    rpc: &str,
    consensus_info: &ConsensusInfo,
) -> Result<(), FollowerError> {
    let client = RemoteLightClient::connect(rpc.to_string())
        .await?
        .with_consensus_info(consensus_info)?;
    catch_up(indexer, &client).await?;
    let mut stream = client
        .subscribe_activity(vec![ActivityEventKind::Finalization])
        .await?;
    catch_up(indexer, &client).await?;

    loop {
        let event = stream
            .message::<ActivityEvent>()
            .await
            .map_err(|err| FollowerError::ActivityStream(err.to_string()))?
            .ok_or(FollowerError::ActivityStreamEnded)?;
        let payload = match finalized_payload(event) {
            Ok(Some(payload)) => payload,
            Ok(None) => continue,
            Err(err) => {
                warn!(error = %err, "skipping malformed activity event");
                continue;
            }
        };
        catch_up_announced_payload(indexer, &client, payload).await?;
    }
}

async fn catch_up(indexer: &ChainIndexer, client: &RemoteLightClient) -> Result<(), FollowerError> {
    let mut next_height = indexer
        .get_latest_block()
        .await?
        .map_or(1, |block| block.height.saturating_add(1));
    let Some(remote_latest) = client.get_latest_block().await? else {
        return Ok(());
    };
    if next_height > remote_latest.height.saturating_add(1) {
        return Err(FollowerError::RemoteBehind {
            local: next_height.saturating_sub(1),
            remote: remote_latest.height,
        });
    }
    while next_height <= remote_latest.height {
        let Some(finalized) = client
            .get_finalized_block(FinalizedBlockQuery::Height(next_height))
            .await?
        else {
            return Err(FollowerError::MissingFinalizedBlock {
                height: next_height,
                remote_latest: remote_latest.height,
            });
        };
        ingest_finalized_block(indexer, finalized, next_height).await?;
        next_height = next_height.saturating_add(1);
    }
    Ok(())
}

async fn catch_up_announced_payload(
    indexer: &ChainIndexer,
    client: &RemoteLightClient,
    payload: Digest,
) -> Result<(), FollowerError> {
    for _ in 0..ANNOUNCED_BLOCK_RETRIES {
        match catch_up(indexer, client).await {
            Ok(()) if has_local_payload(indexer, payload).await? => return Ok(()),
            Ok(()) | Err(FollowerError::MissingFinalizedBlock { .. }) => {}
            Err(err) => return Err(err),
        }
        ::tokio::time::sleep(ANNOUNCED_BLOCK_RETRY_DELAY).await;
    }
    Err(FollowerError::AnnouncedBlockUnavailable { payload })
}

async fn has_local_payload(indexer: &ChainIndexer, payload: Digest) -> Result<bool, FollowerError> {
    match indexer
        .get_finalized_block(FinalizedBlockQuery::Payload(payload))
        .await
    {
        Ok(Some(_)) => Ok(true),
        Ok(None) | Err(QueryError::StateUnavailable(_)) => Ok(false),
        Err(err) => Err(FollowerError::Query(err)),
    }
}

async fn ingest_finalized_block(
    indexer: &ChainIndexer,
    finalized: hellas_chain::FinalizedBlock,
    requested: u64,
) -> Result<(), FollowerError> {
    let block = ChainIndexer::decode_block(&finalized.block)?;
    let block_height = block.height().get();
    let block_payload = block.digest();
    if finalized.snapshot.height != block_height {
        return Err(FollowerError::SnapshotBlockHeightMismatch {
            snapshot: finalized.snapshot.height,
            block: block_height,
        });
    }
    if finalized.snapshot.payload != block_payload {
        return Err(FollowerError::SnapshotBlockPayloadMismatch {
            snapshot: finalized.snapshot.payload,
            block: block_payload,
        });
    }
    if requested != block_height {
        return Err(FollowerError::FinalizedBlockHeightMismatch {
            requested,
            snapshot: finalized.snapshot.height,
            block: block_height,
        });
    }

    let finalization = ChainIndexer::decode_finalization(&finalized.snapshot.finalization)?;
    let outcome = indexer.ingest_finalized(block, finalization).await?;
    println!("height {block_height} {outcome:?}");
    Ok(())
}

fn finalized_payload(event: ActivityEvent) -> Result<Option<Digest>, FollowerError> {
    let Some(event) = event.event else {
        return Err(FollowerError::MissingActivityEvent);
    };
    match event {
        activity_event::Event::Finalization(finalization) => {
            let proposal = finalization
                .proposal
                .ok_or(FollowerError::MissingFinalizationProposal)?;
            Ok(Some(digest_from_bytes(
                proposal.payload,
                "finalization.proposal.payload",
            )?))
        }
        _ => Ok(None),
    }
}

fn digest_from_bytes(bytes: Vec<u8>, field: &'static str) -> Result<Digest, FollowerError> {
    let len = bytes.len();
    let raw: [u8; 32] = bytes
        .try_into()
        .map_err(|_| FollowerError::InvalidDigest { field, len })?;
    Ok(Digest::from(raw))
}

fn default_storage_dir() -> Result<PathBuf, FollowerError> {
    Ok(dirs::data_local_dir()
        .ok_or(FollowerError::MissingDataDirectory)?
        .join("hellas")
        .join("follower"))
}

fn genesis_leader(info: &ConsensusInfo) -> Result<PublicKey, FollowerError> {
    let validator = info
        .validators
        .first()
        .ok_or(FollowerError::InvalidValidatorKey)?;
    let bytes = hex::decode(validator).map_err(|_| FollowerError::InvalidValidatorKey)?;
    PublicKey::decode(bytes.as_slice()).map_err(|_| FollowerError::InvalidValidatorKey)
}

fn init_tracing() {
    use tracing_subscriber::prelude::*;

    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::registry()
        .with(env_filter)
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(std::io::stderr)
                .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()))
                .compact(),
        )
        .init();
}
