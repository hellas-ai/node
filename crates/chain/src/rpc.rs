//! Local implementation of the light-client query interface.

use crate::domain::{Coin, Object, ObjectId, ObjectKind, SettlementKey, Transaction};
use crate::{
    app::Mempool,
    execution::store::UtxoDatabase,
    indexer::ChainIndexer,
    light_client::{
        ConsensusInfo, EdgeLookup, EdgeRecord, EdgeState, FinalizedBlock, FinalizedBlockQuery,
        LatestBlock, LightClient, OwnerCoins, OwnerEdges, QueryError,
    },
    owner_index::{OwnerIndex, OwnerIndexError},
};
use commonware_cryptography::sha256::Digest;

/// In-process [`LightClient`] backed by the local application handle.
#[derive(Clone)]
pub struct LocalLightClient {
    databases: UtxoDatabase<commonware_runtime::tokio::Context>,
    owner_index: OwnerIndex,
    mempool: Mempool,
    chain_indexer: ChainIndexer,
    consensus_info: ConsensusInfo,
}

impl LocalLightClient {
    pub fn new(
        databases: UtxoDatabase<commonware_runtime::tokio::Context>,
        owner_index: OwnerIndex,
        mempool: Mempool,
        chain_indexer: ChainIndexer,
        consensus_info: ConsensusInfo,
    ) -> Self {
        Self {
            databases,
            owner_index,
            mempool,
            chain_indexer,
            consensus_info,
        }
    }
}

fn owner_lookup_error(error: OwnerIndexError) -> QueryError {
    match error {
        OwnerIndexError::WrongObjectKind {
            expected, actual, ..
        } => QueryError::WrongObjectKind { expected, actual },
        error => QueryError::StateUnavailable(format!("owner index lookup failed: {error}")),
    }
}

async fn finalized_floor_height(
    chain_indexer: &ChainIndexer,
    payload: Digest,
) -> Result<u64, QueryError> {
    let Some(finalized) = chain_indexer
        .get_finalized_block(FinalizedBlockQuery::Payload(payload))
        .await?
    else {
        return Err(QueryError::StateUnavailable(
            "requested payload is not finalized".to_string(),
        ));
    };
    Ok(finalized.snapshot.height)
}

fn require_finalized_floor(floor_height: u64, cursor_height: u64) -> Result<(), QueryError> {
    if floor_height > cursor_height {
        return Err(QueryError::StateUnavailable(
            "requested payload is newer than the application state".to_string(),
        ));
    }
    Ok(())
}

async fn get_edge_at(
    databases: &UtxoDatabase<commonware_runtime::tokio::Context>,
    owner_index: &OwnerIndex,
    chain_indexer: &ChainIndexer,
    payload: Digest,
    object_id: ObjectId,
) -> Result<Option<EdgeLookup>, QueryError> {
    let cursor = owner_index.cursor();
    if cursor.height == 0 {
        return Ok(None);
    }
    let floor_height = finalized_floor_height(chain_indexer, payload).await?;

    let reader = databases.read().await;
    let state_root = reader.root();
    let cursor = owner_index.cursor();
    require_finalized_floor(floor_height, cursor.height)?;
    if cursor.state_root != state_root {
        return Err(QueryError::StateUnavailable(
            "owner index and application state are not synchronized".to_string(),
        ));
    }
    let edge = match reader
        .get(&object_id)
        .await
        .map_err(|error| QueryError::StateUnavailable(format!("edge read failed: {error:?}")))?
    {
        Some(Object::Edge(edge)) => Some(EdgeState::from(edge)),
        Some(Object::Coin(_)) => {
            return Err(QueryError::WrongObjectKind {
                expected: ObjectKind::Edge,
                actual: ObjectKind::Coin,
            });
        }
        None => None,
    };
    Ok(Some(EdgeLookup { state_root, edge }))
}

async fn get_coin_at(
    owner_index: &OwnerIndex,
    chain_indexer: &ChainIndexer,
    payload: Digest,
    object_id: ObjectId,
) -> Result<Option<Coin>, QueryError> {
    let (cursor, coin) = owner_index.get_coin_snapshot(&object_id);
    if cursor.height == 0 {
        return Ok(None);
    }
    let floor_height = finalized_floor_height(chain_indexer, payload).await?;
    require_finalized_floor(floor_height, cursor.height)?;
    coin.map_err(owner_lookup_error)
}

impl LightClient for LocalLightClient {
    async fn get_state_root(&self) -> Result<Option<Digest>, QueryError> {
        Ok(Some(self.databases.read().await.root()))
    }

    async fn get_proof(&self, object_id: ObjectId) -> Result<Option<Vec<u8>>, QueryError> {
        let _ = object_id;
        Err(QueryError::StateUnavailable(
            "key proofs are not available".to_string(),
        ))
    }

    async fn get_coin(
        &self,
        payload: Digest,
        object_id: ObjectId,
    ) -> Result<Option<Coin>, QueryError> {
        get_coin_at(&self.owner_index, &self.chain_indexer, payload, object_id).await
    }

    async fn get_edge(
        &self,
        payload: Digest,
        object_id: ObjectId,
    ) -> Result<Option<EdgeLookup>, QueryError> {
        get_edge_at(
            &self.databases,
            &self.owner_index,
            &self.chain_indexer,
            payload,
            object_id,
        )
        .await
    }

    async fn get_finalization(&self, payload: Digest) -> Result<Option<Vec<u8>>, QueryError> {
        self.chain_indexer.get_finalization(payload).await
    }

    async fn get_latest_block(&self) -> Result<Option<LatestBlock>, QueryError> {
        self.chain_indexer.get_latest_block().await
    }

    async fn get_finalized_block(
        &self,
        query: FinalizedBlockQuery,
    ) -> Result<Option<FinalizedBlock>, QueryError> {
        self.chain_indexer.get_finalized_block(query).await
    }

    async fn submit_tx(&self, tx: Transaction) -> Result<(), QueryError> {
        self.mempool.submit(tx).await;
        Ok(())
    }

    async fn get_validators(&self) -> Result<Vec<String>, QueryError> {
        Ok(self.consensus_info.validators.clone())
    }

    async fn get_consensus_info(&self) -> Result<ConsensusInfo, QueryError> {
        Ok(self.consensus_info.clone())
    }

    async fn get_coins_by_owner(
        &self,
        owner: SettlementKey,
    ) -> Result<Option<OwnerCoins>, QueryError> {
        let (cursor, coins) = self.owner_index.get_coins_by_owner_snapshot(&owner);
        if cursor.height == 0 {
            return Ok(None);
        }
        let Some(finalization) = self.chain_indexer.get_finalization(cursor.payload).await? else {
            return Err(QueryError::StateUnavailable(
                "owner index cursor finalization is unavailable".to_string(),
            ));
        };
        Ok(Some(OwnerCoins {
            snapshot: LatestBlock {
                height: cursor.height,
                payload: cursor.payload,
                state_root: cursor.state_root,
                finalization,
            },
            coins,
        }))
    }

    async fn get_edges_by_owner(
        &self,
        owner: SettlementKey,
    ) -> Result<Option<OwnerEdges>, QueryError> {
        let (cursor, edges) = self.owner_index.get_edges_by_owner_snapshot(&owner);
        if cursor.height == 0 {
            return Ok(None);
        }
        let Some(finalization) = self.chain_indexer.get_finalization(cursor.payload).await? else {
            return Err(QueryError::StateUnavailable(
                "owner index cursor finalization is unavailable".to_string(),
            ));
        };
        Ok(Some(OwnerEdges {
            snapshot: LatestBlock {
                height: cursor.height,
                payload: cursor.payload,
                state_root: cursor.state_root,
                finalization,
            },
            edges: edges
                .into_iter()
                .map(|(object_id, edge)| EdgeRecord {
                    object_id,
                    maker: edge.maker,
                    taker: edge.taker,
                })
                .collect(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::Config,
        domain::{KERNEL_FEES, ObjectKind, Transaction, edge_object_id, genesis_object_id},
        execution::{
            ChainVerifier, execute_all,
            store::utxo_db_config,
            test_support::{
                consensus_fixture, finalization, index_block, index_genesis, kernel_fixture,
                legacy_address, run_qmdb,
            },
        },
        indexer::spawn_follower_indexer,
        owner_index::ApplyOutcome,
    };
    use commonware_cryptography::Digestible as _;
    use commonware_glue::stateful::db::{DatabaseSet, Merkleized as _, Unmerkleized as _};
    use commonware_runtime::{Handle, Supervisor as _};
    use hellas_kernel::{BlockHash, BlockHeight, Context as KernelContext};

    async fn finalized_payload_indexer(
        context: commonware_runtime::tokio::Context,
        genesis: crate::HellasBlock,
        finalized: crate::HellasBlock,
    ) -> (ChainIndexer, Handle<()>) {
        let fixture = consensus_fixture(91);
        let config = Config {
            mailbox_size: 32,
            replay_buffer: 32,
            write_buffer: 32,
            page_cache_size: 1024,
            page_cache_count: 8,
            ..Config::default()
        };
        let (indexer, handle) = spawn_follower_indexer(
            context,
            "rpc_finalized_floor",
            config,
            fixture.verifier.clone(),
            genesis,
        )
        .await
        .expect("chain indexer");
        indexer
            .ingest_finalized(finalized.clone(), finalization(&fixture, &finalized))
            .await
            .expect("finalized floor ingest");
        (indexer, handle)
    }

    #[test]
    fn owner_index_wrong_kind_maps_structurally() {
        let id = ObjectId::from([0x42; 32]);
        let error = owner_lookup_error(OwnerIndexError::WrongObjectKind {
            id,
            expected: ObjectKind::Coin,
            actual: ObjectKind::Edge,
        });
        assert!(matches!(
            error,
            QueryError::WrongObjectKind {
                expected: ObjectKind::Coin,
                actual: ObjectKind::Edge,
            }
        ));
    }

    #[test]
    fn get_edge_reads_qmdb_with_served_root_and_typed_kind() {
        run_qmdb(|runtime| async move {
            let indexer_context = runtime.child("chain_indexer");
            let config = utxo_db_config(&runtime, "rpc_get_edge", 1024, 8);
            let database = <UtxoDatabase<_> as DatabaseSet<_>>::init(runtime, config).await;
            let fixture = kernel_fixture(3).expect("kernel fixture");
            let mut allocations = fixture.allocations.clone();
            allocations.push((SettlementKey::from(legacy_address(41)), 7));
            let genesis = index_genesis();

            let batches = database.new_batches().await;
            let batches = execute_all(
                KernelContext::with_fees(
                    crate::domain::TEST_NETWORK,
                    BlockHeight::new(1),
                    BlockHash::from_bytes([0; BlockHash::LENGTH]),
                    KERNEL_FEES,
                ),
                &ChainVerifier::new(),
                &[],
                &allocations,
                batches,
            )
            .await
            .expect("genesis allocations execute");
            let merkleized = batches.merkleize().await.expect("genesis merkleizes");
            let floor_root = merkleized.root();
            database.finalize(merkleized).await;

            let floor_block = index_block(&genesis, floor_root, Vec::new());
            let (chain_indexer, _indexer_handle) =
                finalized_payload_indexer(indexer_context, genesis.clone(), floor_block.clone())
                    .await;
            let latest = chain_indexer
                .get_latest_block()
                .await
                .expect("latest block query")
                .expect("finalized floor");
            assert_eq!(latest.payload, floor_block.digest());
            let finalized_payload = latest.payload;
            let uninitialized_index =
                OwnerIndex::new(crate::domain::TEST_NETWORK, &genesis, allocations.clone());
            assert!(matches!(
                get_edge_at(
                    &database,
                    &uninitialized_index,
                    &chain_indexer,
                    Digest::from([0x10; 32]),
                    ObjectId::from([0x20; 32]),
                )
                .await,
                Ok(None)
            ));

            let transactions = vec![Transaction::Kernel(fixture.open.clone())];
            let batches = database.new_batches().await;
            let batches = execute_all(
                KernelContext::with_fees(
                    crate::domain::TEST_NETWORK,
                    BlockHeight::new(2),
                    BlockHash::from_bytes([0; BlockHash::LENGTH]),
                    KERNEL_FEES,
                ),
                &ChainVerifier::new(),
                &transactions,
                &allocations,
                batches,
            )
            .await
            .expect("open executes");
            let merkleized = batches.merkleize().await.expect("state merkleizes");
            let state_root = merkleized.root();
            database.finalize(merkleized).await;

            let index = OwnerIndex::new(crate::domain::TEST_NETWORK, &genesis, allocations.clone());
            assert_eq!(
                index.apply_finalized(&floor_block),
                Ok(ApplyOutcome::Applied)
            );
            let block = index_block(&floor_block, state_root, transactions.clone());
            assert_eq!(index.apply_finalized(&block), Ok(ApplyOutcome::Applied));
            assert_ne!(index.cursor().payload, finalized_payload);
            let edge_id = edge_object_id(fixture.edge);
            let expected_edge = match database
                .read()
                .await
                .get(&edge_id)
                .await
                .expect("edge read")
            {
                Some(Object::Edge(edge)) => EdgeState::from(edge),
                other => panic!("expected stored edge, found {other:?}"),
            };

            let found = get_edge_at(
                &database,
                &index,
                &chain_indexer,
                finalized_payload,
                edge_id,
            )
            .await
            .expect("edge lookup")
            .expect("indexed state is available");
            assert_eq!(found.state_root, state_root);
            assert_eq!(found.edge, Some(expected_edge));

            let absent = get_edge_at(
                &database,
                &index,
                &chain_indexer,
                finalized_payload,
                ObjectId::from([0xa5; 32]),
            )
            .await
            .expect("absent edge lookup")
            .expect("indexed state is available");
            assert_eq!(absent.state_root, state_root);
            assert_eq!(absent.edge, None);

            assert!(matches!(
                get_edge_at(
                    &database,
                    &index,
                    &chain_indexer,
                    Digest::from([0x44; 32]),
                    edge_id,
                )
                .await,
                Err(QueryError::StateUnavailable(_))
            ));

            assert!(matches!(
                get_edge_at(
                    &database,
                    &index,
                    &chain_indexer,
                    finalized_payload,
                    genesis_object_id(2),
                )
                .await,
                Err(QueryError::WrongObjectKind {
                    expected: ObjectKind::Edge,
                    actual: ObjectKind::Coin,
                })
            ));

            assert!(
                get_coin_at(
                    &index,
                    &chain_indexer,
                    finalized_payload,
                    genesis_object_id(2),
                )
                .await
                .expect("finalized coin floor")
                .is_some()
            );
            assert!(matches!(
                get_coin_at(
                    &index,
                    &chain_indexer,
                    Digest::from([0x44; 32]),
                    genesis_object_id(2),
                )
                .await,
                Err(QueryError::StateUnavailable(_))
            ));

            let skewed_index = OwnerIndex::new(crate::domain::TEST_NETWORK, &genesis, allocations);
            assert_eq!(
                skewed_index.apply_finalized(&floor_block),
                Ok(ApplyOutcome::Applied)
            );
            let skewed_block = index_block(&floor_block, Digest::from([0x55; 32]), transactions);
            assert_eq!(
                skewed_index.apply_finalized(&skewed_block),
                Ok(ApplyOutcome::Applied)
            );
            assert!(matches!(
                get_edge_at(
                    &database,
                    &skewed_index,
                    &chain_indexer,
                    finalized_payload,
                    ObjectId::from([0xa6; 32]),
                )
                .await,
                Err(QueryError::StateUnavailable(_))
            ));
            let qmdb_root = database.read().await.root();
            assert_ne!(skewed_index.cursor().state_root, qmdb_root);
        });
    }
}
