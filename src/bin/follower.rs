use clap::Parser;
use commonware_codec::DecodeExt;
use commonware_consensus::Heightable;
use commonware_runtime::{Runner as _, Supervisor as _, tokio};
use hellas_chain::{
    Application, ApplicationConfig, ChainIndexer, ConsensusInfo, ConsensusVerifier,
    FinalizedBlockQuery, IngestError, LightClient as _, QueryError, spawn_follower_indexer,
};
use hellas_chain::{client::RemoteLightClient, config::Config};
use hellas_kernel::domain::PublicKey;
use std::{path::PathBuf, time::Duration};
use thiserror::Error;

#[derive(Debug, Error)]
enum FollowerError {
    #[error("unable to determine local data directory")]
    MissingDataDirectory,
    #[error("storage directory is not valid UTF-8: {0}")]
    NonUtf8StorageDirectory(PathBuf),
    #[error("invalid validator key data")]
    InvalidValidatorKey,
    #[error("remote latest is {remote_latest}, but finalized block at height {height} was absent")]
    MissingFinalizedBlock { height: u64, remote_latest: u64 },
    #[error(
        "requested finalized height {requested}, but snapshot height was {snapshot} and block height was {block}"
    )]
    FinalizedBlockHeightMismatch {
        requested: u64,
        snapshot: u64,
        block: u64,
    },
    #[error("{0}")]
    Query(#[from] QueryError),
    #[error("{0}")]
    Consensus(#[from] hellas_chain::ConsensusVerificationError),
    #[error("{0}")]
    Ingest(#[from] IngestError),
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
    #[arg(long)]
    once: bool,
    #[arg(long, default_value = "500")]
    poll_ms: u64,
}

fn main() -> Result<(), FollowerError> {
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
    let client = RemoteLightClient::connect(cli.rpc).await?;
    let consensus_info = client.get_consensus_info().await?;
    let verifier = ConsensusVerifier::new(&consensus_info)?;
    let client = client.with_consensus_info(&consensus_info)?;
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
    sync_loop(
        indexer,
        client,
        cli.once,
        Duration::from_millis(cli.poll_ms),
    )
    .await
}

async fn sync_loop(
    indexer: ChainIndexer,
    client: RemoteLightClient,
    once: bool,
    poll: Duration,
) -> Result<(), FollowerError> {
    let mut next_height = indexer
        .get_latest_block()
        .await?
        .map_or(1, |block| block.height.saturating_add(1));
    loop {
        let Some(remote_latest) = client.get_latest_block().await? else {
            if once {
                return Ok(());
            }
            ::tokio::time::sleep(poll).await;
            continue;
        };
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
            let block = ChainIndexer::decode_block(&finalized.block)?;
            let block_height = block.height().get();
            if finalized.snapshot.height != next_height || block_height != next_height {
                return Err(FollowerError::FinalizedBlockHeightMismatch {
                    requested: next_height,
                    snapshot: finalized.snapshot.height,
                    block: block_height,
                });
            }
            let finalization = ChainIndexer::decode_finalization(&finalized.snapshot.finalization)?;
            let outcome = indexer.ingest_finalized(block, finalization).await?;
            println!("height {block_height} {outcome:?}");
            next_height = next_height.saturating_add(1);
        }
        if once {
            return Ok(());
        }
        ::tokio::time::sleep(poll).await;
    }
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
