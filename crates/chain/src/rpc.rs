//! Local implementation of the light-client query interface.

use crate::domain::{Coin, Object, ObjectId, ObjectKind, SettlementKey, Transaction};
use crate::{
    app::Mempool,
    execution::store::{UtxoDatabase, root as utxo_root},
    indexer::ChainIndexer,
    light_client::{
        ConsensusInfo, FinalizedBlock, FinalizedBlockQuery, LatestBlock, LightClient, OwnerCoins,
        QueryError,
    },
    owner_index::OwnerIndex,
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

fn coin_from_index_miss(object: Option<Object>) -> Result<Option<Coin>, QueryError> {
    match object {
        Some(Object::Coin(_)) => Ok(None),
        Some(object) => Err(QueryError::WrongObjectKind {
            expected: ObjectKind::Coin,
            actual: object.kind(),
        }),
        None => Ok(None),
    }
}

async fn resolve_indexed_coin<F, Fut>(
    indexed_coin: Option<Coin>,
    load_object: F,
) -> Result<Option<Coin>, QueryError>
where
    F: FnOnce() -> Fut,
    Fut: core::future::Future<Output = Result<Option<Object>, QueryError>>,
{
    if let Some(coin) = indexed_coin {
        return Ok(Some(coin));
    }

    // M3a consistency shim: the owner index is authoritative for coin values,
    // while QMDB classifies index misses. Retire this when M4 gives the index
    // an object-kind map.
    coin_from_index_miss(load_object().await?)
}

impl LightClient for LocalLightClient {
    async fn get_state_root(&self) -> Result<Option<Digest>, QueryError> {
        Ok(Some(utxo_root(&self.databases).await))
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
        let (cursor, coin) = self.owner_index.get_coin_snapshot(&object_id);
        if cursor.height == 0 {
            return Ok(None);
        }
        if cursor.payload != payload {
            return Err(QueryError::StateUnavailable(
                "coin queries only support the latest indexed payload".to_string(),
            ));
        }
        resolve_indexed_coin(coin, || async {
            self.databases
                .read()
                .await
                .get(&object_id)
                .await
                .map_err(|err| {
                    QueryError::StateUnavailable(format!("object lookup failed: {err:?}"))
                })
        })
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_coin_edge_result_is_typed_wrong_kind() {
        let err = coin_from_index_miss(Some(Object::Edge(crate::domain::test_edge())))
            .expect_err("edge must not look missing");
        assert!(matches!(
            err,
            QueryError::WrongObjectKind {
                expected: ObjectKind::Coin,
                actual: ObjectKind::Edge,
            }
        ));
    }

    #[test]
    fn get_coin_uses_index_value_without_loading_qmdb() {
        let indexed = Coin {
            owner: SettlementKey::from_bytes([0x42; SettlementKey::LENGTH]),
            value: 17,
        };
        let result = futures::executor::block_on(resolve_indexed_coin(Some(indexed), || async {
            Err(QueryError::StateUnavailable(
                "QMDB must not be loaded for an indexed coin".to_string(),
            ))
        }))
        .expect("indexed coin must win");
        assert_eq!(result, Some(indexed));
    }
}
