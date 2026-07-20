#[cfg(any(feature = "indexer", feature = "validator"))]
use std::path::PathBuf;

use clap::Subcommand;
use hellas_chain::domain::{Digest, SettlementKey};
use hellas_chain::{FinalizedBlockQuery, LightClient as _, client::RemoteLightClient};

use crate::commands::CliResult;

#[derive(Subcommand)]
pub enum ChainCommand {
    /// Query the chain light-client API
    Query {
        /// RPC endpoint
        #[arg(long)]
        rpc: String,
        #[command(subcommand)]
        query: QueryCommand,
    },
    /// Run or manage a local indexer
    #[cfg(feature = "indexer")]
    Indexer {
        #[command(subcommand)]
        command: IndexerCommand,
    },
    /// Run or manage a validator
    #[cfg(feature = "validator")]
    Validator {
        #[command(subcommand)]
        command: ValidatorCommand,
    },
}

#[derive(Subcommand)]
pub enum QueryCommand {
    /// Get the latest finalized block
    LatestBlock,
    /// Get the current state root
    StateRoot,
    /// Get the finalization certificate for a payload
    Finalization {
        /// Hex-encoded 32-byte payload digest
        #[arg(long)]
        payload: String,
    },
    /// Get a finalized block by height, payload, or latest when neither is set
    FinalizedBlock {
        /// Finalized block height
        #[arg(long)]
        height: Option<u64>,
        /// Hex-encoded 32-byte payload digest
        #[arg(long)]
        payload: Option<String>,
    },
    /// Look up a coin by object ID at an indexed payload
    Coin {
        /// Hex-encoded 32-byte object ID
        #[arg(long)]
        object_id: String,
        /// Hex-encoded finalized payload to query
        #[arg(long)]
        payload: String,
    },
    /// Look up a kernel edge by object ID at an indexed payload
    Edge {
        /// Hex-encoded 32-byte object ID
        #[arg(long)]
        object_id: String,
        /// Hex-encoded finalized payload to query
        #[arg(long)]
        payload: String,
    },
    /// List all known validators
    Validators,
    /// List coins owned by an address
    CoinsByOwner {
        /// Base58-encoded settlement key
        #[arg(long)]
        owner: String,
    },
    /// List edge records associated with a settlement key
    EdgesByOwner {
        /// Base58-encoded settlement key
        #[arg(long)]
        owner: String,
    },
}

#[cfg(feature = "indexer")]
#[derive(Subcommand)]
pub enum IndexerCommand {
    /// Follow a validator and maintain a verified finalized-block archive
    Follow {
        /// Chain light-client RPC endpoint
        #[arg(long)]
        rpc: String,
        /// Local storage directory
        #[arg(long)]
        storage_dir: Option<PathBuf>,
        /// Storage partition prefix
        #[arg(long, default_value = "hellas-follower")]
        partition_prefix: String,
    },
}

#[cfg(feature = "validator")]
#[derive(Subcommand)]
pub enum ValidatorCommand {
    /// Generate a TOML config for one validator
    Config {
        /// Total number of validators in the network
        #[arg(short = 'n', long)]
        validators: u32,
        /// This validator's index
        #[arg(short = 'i', long = "validator", default_value = "0")]
        validator: u32,
        /// Starting port number
        #[arg(long, default_value = "3000")]
        start_port: u16,
        /// Deterministic seed for local setups
        #[arg(long)]
        seed: Option<u64>,
        /// Validator addresses in index order
        #[arg(long, value_delimiter = ',')]
        addresses: Option<Vec<String>>,
        /// Chain light-client WebSocket bind address
        #[arg(long)]
        ws_bind: Option<String>,
        /// Explorer WebSocket URL
        #[arg(long)]
        ws_push: Option<String>,
        /// Prometheus metrics port
        #[arg(long)]
        metrics_port: Option<u16>,
        /// Genesis allocation as address:balance
        #[arg(long = "genesis-allocation")]
        genesis_allocations: Vec<String>,
    },
    /// Run a validator
    Run {
        /// Path to validator TOML config
        #[arg(long)]
        config: PathBuf,
    },
    /// Validate a validator TOML config
    CheckConfig {
        /// Path to validator TOML config
        #[arg(long)]
        config: PathBuf,
    },
}

pub async fn run(command: ChainCommand) -> CliResult {
    match command {
        ChainCommand::Query { rpc, query } => run_query(rpc, query).await,
        #[cfg(feature = "indexer")]
        ChainCommand::Indexer { command } => run_indexer(command).await,
        #[cfg(feature = "validator")]
        ChainCommand::Validator { command } => run_validator(command).await,
    }
}

pub fn command_owns_tracing(command: &ChainCommand) -> bool {
    match command {
        #[cfg(feature = "validator")]
        ChainCommand::Validator {
            command: ValidatorCommand::Run { .. },
        } => true,
        _ => false,
    }
}

async fn run_query(rpc: String, query: QueryCommand) -> CliResult {
    let client = RemoteLightClient::connect(rpc).await?;
    let consensus_info = client.get_consensus_info().await?;
    let client = client.with_consensus_info(&consensus_info)?;
    match query {
        QueryCommand::LatestBlock => match client.get_latest_block().await? {
            Some(block) => {
                println!("height {}", block.height);
                println!("payload {}", hex::encode(block.payload));
                println!("state_root {}", hex::encode(block.state_root));
                println!("finalization {}", hex::encode(block.finalization));
            }
            None => println!("none"),
        },
        QueryCommand::StateRoot => match client.get_state_root().await? {
            Some(root) => println!("{}", hex::encode(root)),
            None => println!("none"),
        },
        QueryCommand::Finalization { payload } => {
            let payload = parse_hex_digest(&payload, "payload")?;
            match client.get_finalization(payload).await? {
                Some(finalization) => println!("{}", hex::encode(finalization)),
                None => println!("none"),
            }
        }
        QueryCommand::FinalizedBlock { height, payload } => {
            let query = finalized_block_query(height, payload)?;
            match client.get_finalized_block(query).await? {
                Some(block) => {
                    println!("height {}", block.snapshot.height);
                    println!("payload {}", hex::encode(block.snapshot.payload));
                    println!("state_root {}", hex::encode(block.snapshot.state_root));
                    println!("finalization {}", hex::encode(block.snapshot.finalization));
                    println!("block {}", hex::encode(block.block));
                }
                None => println!("none"),
            }
        }
        QueryCommand::Coin { object_id, payload } => {
            let object_id = parse_hex_digest(&object_id, "object_id")?;
            let payload = parse_hex_digest(&payload, "payload")?;
            match client.get_coin(payload, object_id).await? {
                Some(coin) => println!("{} {}", coin.owner, coin.value),
                None => println!("none"),
            }
        }
        QueryCommand::Edge { object_id, payload } => {
            let object_id = parse_hex_digest(&object_id, "object_id")?;
            let payload = parse_hex_digest(&payload, "payload")?;
            match client.get_edge(payload, object_id).await? {
                Some(lookup) => {
                    println!("state_root {}", hex::encode(lookup.state_root));
                    match lookup.edge {
                        Some(edge) => {
                            println!("value {}", edge.value);
                            println!("reserve {}", edge.reserve);
                            println!("close_fee_base {}", edge.close_fees.base());
                            println!("close_fee_slot {}", edge.close_fees.slot());
                            println!("close_fee_proof {}", edge.close_fees.proof());
                            println!("close_fee_lifetime {}", edge.close_fees.lifetime());
                            println!("timeout {}", edge.timeout.get());
                            println!("maker {}", edge.maker);
                            println!("taker {}", edge.taker);
                            println!("terms_hash {}", hex::encode(edge.terms_hash.to_bytes()));
                        }
                        None => println!("none"),
                    }
                }
                None => println!("none"),
            }
        }
        QueryCommand::Validators => {
            for validator in client.get_validators().await? {
                println!("{validator}");
            }
        }
        QueryCommand::CoinsByOwner { owner } => {
            let owner = owner
                .parse::<SettlementKey>()
                .map_err(|err| anyhow::anyhow!("invalid owner settlement key: {err}"))?;
            match client.get_coins_by_owner(owner).await? {
                Some(owner_coins) => {
                    println!("height {}", owner_coins.snapshot.height);
                    println!("payload {}", hex::encode(owner_coins.snapshot.payload));
                    println!(
                        "state_root {}",
                        hex::encode(owner_coins.snapshot.state_root)
                    );
                    println!(
                        "finalization {}",
                        hex::encode(owner_coins.snapshot.finalization)
                    );
                    for (object_id, value) in owner_coins.coins {
                        println!("{} {}", hex::encode(object_id), value);
                    }
                }
                None => println!("none"),
            }
        }
        QueryCommand::EdgesByOwner { owner } => {
            let owner = owner
                .parse::<SettlementKey>()
                .map_err(|err| anyhow::anyhow!("invalid owner settlement key: {err}"))?;
            match client.get_edges_by_owner(owner).await? {
                Some(owner_edges) => {
                    println!("height {}", owner_edges.snapshot.height);
                    println!("payload {}", hex::encode(owner_edges.snapshot.payload));
                    println!(
                        "state_root {}",
                        hex::encode(owner_edges.snapshot.state_root)
                    );
                    println!(
                        "finalization {}",
                        hex::encode(owner_edges.snapshot.finalization)
                    );
                    for edge in owner_edges.edges {
                        println!(
                            "{} {} {}",
                            hex::encode(edge.object_id),
                            edge.maker,
                            edge.taker
                        );
                    }
                }
                None => println!("none"),
            }
        }
    }
    Ok(())
}

#[cfg(feature = "indexer")]
async fn run_indexer(command: IndexerCommand) -> CliResult {
    match command {
        IndexerCommand::Follow {
            rpc,
            storage_dir,
            partition_prefix,
        } => {
            tokio::task::spawn_blocking(move || {
                hellas_chain::follower::run(hellas_chain::follower::FollowerOptions {
                    rpc,
                    storage_dir,
                    partition_prefix,
                    status: follower_status_sink(),
                })
            })
            .await??
        }
    }
    Ok(())
}

#[cfg(feature = "indexer")]
fn follower_status_sink() -> hellas_chain::follower::FollowerStatusSink {
    hellas_chain::follower::FollowerStatusSink::callback(|status| match status {
        hellas_chain::follower::FollowerStatus::ActivityStreamSubscribed => {
            println!("activity stream subscribed");
        }
        hellas_chain::follower::FollowerStatus::ActivityFinalization { payload } => {
            println!("activity finalization {}", hex::encode(payload));
        }
        hellas_chain::follower::FollowerStatus::BlockIngested { height, outcome } => {
            println!("height {height} {outcome:?}");
        }
    })
}

#[cfg(feature = "validator")]
async fn run_validator(command: ValidatorCommand) -> CliResult {
    let command = match command {
        ValidatorCommand::Config {
            validators,
            validator,
            start_port,
            seed,
            addresses,
            ws_bind,
            ws_push,
            metrics_port,
            genesis_allocations,
        } => hellas_chain::validator::Command::Config {
            validators,
            validator,
            start_port,
            seed,
            addresses,
            ws_bind,
            ws_push,
            metrics_port,
            genesis_allocations,
        },
        ValidatorCommand::Run { config } => hellas_chain::validator::Command::Run { config },
        ValidatorCommand::CheckConfig { config } => {
            hellas_chain::validator::Command::CheckConfig { config }
        }
    };
    tokio::task::spawn_blocking(move || hellas_chain::validator::run_command(command)).await??;
    Ok(())
}

fn parse_hex_digest(raw: &str, field: &'static str) -> CliResult<Digest> {
    let bytes = hex::decode(raw).map_err(|err| anyhow::anyhow!("bad hex for {field}: {err}"))?;
    let len = bytes.len();
    let raw: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("{field} must be 32 bytes, got {len}"))?;
    Ok(Digest::from(raw))
}

fn finalized_block_query(
    height: Option<u64>,
    payload: Option<String>,
) -> CliResult<FinalizedBlockQuery> {
    match (height, payload) {
        (Some(height), None) => Ok(FinalizedBlockQuery::Height(height)),
        (None, Some(payload)) => Ok(FinalizedBlockQuery::Payload(parse_hex_digest(
            &payload, "payload",
        )?)),
        (None, None) => Ok(FinalizedBlockQuery::Latest),
        (Some(_), Some(_)) => Err(anyhow::anyhow!(
            "--height and --payload are mutually exclusive"
        )),
    }
}
