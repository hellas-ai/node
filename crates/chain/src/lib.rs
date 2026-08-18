#[cfg(any(feature = "indexer", feature = "validator"))]
mod app;
#[cfg(feature = "block-view")]
pub mod block;
#[cfg(feature = "block-view")]
pub mod block_view;
#[cfg(feature = "client-core")]
pub mod client;
#[cfg(any(feature = "indexer", feature = "validator"))]
pub mod config;
#[cfg(any(feature = "client-core", feature = "indexer", feature = "validator"))]
mod consensus;
#[cfg(feature = "domain")]
pub mod domain;
#[cfg(feature = "domain")]
pub use hellas_genesis as genesis;
#[cfg(any(feature = "indexer", feature = "validator"))]
mod execution;
#[cfg(feature = "validator")]
pub mod faucet;
#[cfg(feature = "indexer")]
pub mod follower;
#[cfg(any(feature = "indexer", feature = "validator"))]
pub mod indexer;
#[cfg(any(feature = "client-core", feature = "server"))]
pub mod light_client;
#[cfg(any(feature = "indexer", feature = "validator"))]
pub mod owner_index;
#[cfg(feature = "validator")]
pub mod relay;
#[cfg(feature = "validator")]
pub mod rpc;
#[cfg(feature = "server")]
pub mod server;
#[cfg(feature = "validator")]
pub mod validator;
#[cfg(any(feature = "client-core", feature = "server"))]
pub mod work_view;

#[cfg(any(feature = "client-core", feature = "indexer", feature = "validator"))]
pub const CONSENSUS_NAMESPACE: &[u8] = b"hellas";

#[cfg(any(feature = "indexer", feature = "validator"))]
pub use app::{ActivityReporter, Application, ApplicationConfig, Mempool};
#[cfg(feature = "block-view")]
pub use block::{HellasBlock, UtxoSyncTarget};
#[cfg(feature = "block-view")]
pub use block_view::{BlockViewError, FinalizedBlockView};
#[cfg(any(feature = "client-core", feature = "indexer", feature = "validator"))]
pub use consensus::{ConsensusVerificationError, ConsensusVerifier, Finalization};
#[cfg(any(feature = "indexer", feature = "validator"))]
pub use execution::store::{UtxoDb, utxo_db_config};
#[cfg(feature = "validator")]
pub use execution::{ChainVerifier, ExecutionError};
#[cfg(any(feature = "indexer", feature = "validator"))]
pub use indexer::{
    BlockStore, ChainIndexer, FinalizationStore, IngestError, IngestOutcome, init_block_store,
    init_finalization_store, spawn_follower_indexer,
};
#[cfg(any(feature = "client-core", feature = "server"))]
pub use light_client::{
    ConsensusActivity, ConsensusInfo, EdgeLookup, EdgeRecord, EdgeState, FinalizedBlock,
    FinalizedBlockQuery, LatestBlock, LightClient, OwnerCoins, OwnerEdges, ProposalInfo,
    QueryError,
};
#[cfg(any(feature = "indexer", feature = "validator"))]
pub use owner_index::{ApplyOutcome, OwnerCursor, OwnerIndex, OwnerIndexError};
#[cfg(feature = "server")]
pub use server::{
    LightClientRpc, LightClientServerError, serve_light_client_transport, spawn_light_client_server,
};
#[cfg(any(feature = "client-core", feature = "server"))]
pub use work_view::{FinalizedWorkView, WorkChannelQuery, WorkChannelSnapshot};
