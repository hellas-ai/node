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
#[cfg(feature = "work-watcher")]
pub mod work_blocks;
/// The end-to-end money claim, against a real chain. Test-only.
#[cfg(all(test, feature = "validator", feature = "work-watcher"))]
mod work_e2e;
#[cfg(any(feature = "client-core", feature = "server"))]
pub mod work_view;

#[cfg(any(feature = "client-core", feature = "indexer", feature = "validator"))]
pub const CONSENSUS_NAMESPACE: &[u8] = b"hellas";

#[cfg(any(feature = "indexer", feature = "validator"))]
pub use app::{
    ActivityReporter, Application, ApplicationConfig, GENERAL_MEMPOOL_CAPACITY, Mempool,
};
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
/// The genesis document, at the path it has always had here.
///
/// It belongs to the kernel — it is the initial state of the kernel's
/// state machine, and a relay or a browser that only needs to know a
/// network's committee should not have to depend on a node. This
/// re-export is so that fact costs no caller anything.
#[cfg(feature = "domain")]
pub use hellas_kernel::genesis;
#[cfg(any(feature = "client-core", feature = "server"))]
pub use hellas_rpc::{
    MAX_CANONICAL_TRANSACTION_BYTES, MAX_SUBMIT_TX_PROTO_BYTES,
    MAX_SUBMIT_WORK_RESPONSE_PROTO_BYTES, SubmitTxOutcome,
};
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
    LightClientRpc, LightClientRpcState, LightClientServerError, serve_light_client_transport,
    spawn_light_client_server,
};
#[cfg(feature = "work-watcher")]
pub use work_blocks::WorkBlocks;
#[cfg(any(feature = "client-core", feature = "server"))]
pub use work_view::{FinalizedWorkView, WorkChannelQuery, WorkChannelSnapshot};

/// The genesis document moved to the kernel; the paths here did not.
///
/// A re-export that resolves is not the same claim as a re-export that
/// still names the same bytes: `include_str!` takes a path, and a path
/// survives a move that re-points it. So this reads the shipped
/// documents through `hellas_chain::genesis` — the way every caller in
/// this tree reaches them — and asserts the committee it gets.
#[cfg(all(test, feature = "domain"))]
mod genesis_reexport {
    use crate::genesis::{
        GENESIS_SCHEMA_VERSION, Genesis, HELLAS_DEVNET_1_ID, HELLAS_DEVNET_1_JSON,
        HELLAS_TESTNET_1_ID, HELLAS_TESTNET_1_JSON, KNOWN_NETWORKS, known_network,
        known_network_names,
    };

    #[test]
    fn old_paths_still_name_the_shipped_documents() {
        assert_eq!(GENESIS_SCHEMA_VERSION, 1);
        assert_eq!(HELLAS_DEVNET_1_ID, "hellas-devnet-1");
        assert_eq!(HELLAS_TESTNET_1_ID, "hellas-testnet-1");
        assert_eq!(known_network_names(), vec!["devnet", "testnet"]);

        for (json, id, validators) in [
            (HELLAS_DEVNET_1_JSON, HELLAS_DEVNET_1_ID, 6),
            (HELLAS_TESTNET_1_JSON, HELLAS_TESTNET_1_ID, 6),
        ] {
            let genesis: Genesis = serde_json::from_str(json).expect("shipped document parses");
            genesis.validate().expect("shipped document validates");
            assert_eq!(genesis.network_id, id);
            assert_eq!(genesis.validators.len(), validators);
            assert_eq!(known_network(id).expect("registered").json, json);
        }

        assert_eq!(KNOWN_NETWORKS.len(), 2);
    }
}
