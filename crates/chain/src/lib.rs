#[cfg(feature = "node")]
#[macro_use]
extern crate tracing;

#[cfg(feature = "node")]
mod app;
#[cfg(any(feature = "client", feature = "wasm-client"))]
pub mod client;
#[cfg(feature = "node")]
pub mod config;
#[cfg(any(feature = "client", feature = "wasm-client", feature = "node"))]
mod consensus;
#[cfg(feature = "node")]
mod execution;
#[cfg(feature = "node")]
pub mod indexer;
#[cfg(any(feature = "client", feature = "wasm-client", feature = "server"))]
pub mod light_client;
#[cfg(feature = "node")]
pub mod owner_index;
#[cfg(feature = "node")]
pub mod rpc;
#[cfg(feature = "server")]
pub mod server;

#[cfg(any(feature = "client", feature = "wasm-client", feature = "node"))]
pub const CONSENSUS_NAMESPACE: &[u8] = b"hellas";

#[cfg(feature = "node")]
pub use app::{ActivityReporter, Application, ApplicationConfig, HellasBlock, Mempool};
#[cfg(any(feature = "client", feature = "wasm-client", feature = "node"))]
pub use consensus::{ConsensusVerificationError, ConsensusVerifier, Finalization};
#[cfg(feature = "node")]
pub use execution::store::{UtxoDb, utxo_db_config};
#[cfg(feature = "node")]
pub use indexer::{
    BlockStore, ChainIndexer, FinalizationStore, IngestError, IngestOutcome, init_block_store,
    init_finalization_store, spawn_follower_indexer,
};
#[cfg(any(feature = "client", feature = "wasm-client", feature = "server"))]
pub use light_client::{
    ConsensusActivity, ConsensusInfo, FinalizedBlock, FinalizedBlockQuery, LatestBlock,
    LightClient, OwnerCoins, ProposalInfo, QueryError,
};
#[cfg(feature = "node")]
pub use owner_index::{ApplyOutcome, OwnerCursor, OwnerIndex, OwnerIndexError};
#[cfg(feature = "server")]
pub use server::spawn_light_client_server;
