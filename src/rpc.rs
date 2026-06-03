//! Local implementation of the light-client query interface.

use crate::{
    app::Mempool,
    execution::store::{UtxoDatabase, get as utxo_get, root as utxo_root},
    indexer::ChainIndexer,
    light_client::{
        ConsensusInfo, FinalizedBlock, FinalizedBlockQuery, LatestBlock, LightClient, OwnerCoins,
        QueryError,
    },
    owner_index::OwnerIndex,
};
use commonware_cryptography::sha256::Digest;
use hellas_kernel::domain::{Address, Coin, ObjectId, Transaction};

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
        let latest = self.get_latest_block().await?;
        let Some(latest) = latest else {
            return Ok(None);
        };
        if latest.payload != payload {
            return Err(QueryError::StateUnavailable(
                "coin queries only support the latest payload".to_string(),
            ));
        }
        Ok(utxo_get(&self.databases, &object_id).await)
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

    async fn get_coins_by_owner(&self, owner: Address) -> Result<Option<OwnerCoins>, QueryError> {
        let latest = self.get_latest_block().await?;
        let Some(latest) = latest else {
            return Ok(None);
        };
        let cursor = self.owner_index.cursor();
        if cursor.payload != latest.payload {
            return Err(QueryError::StateUnavailable(
                "owner index has not reached latest payload".to_string(),
            ));
        }
        Ok(Some(OwnerCoins {
            snapshot: latest,
            coins: self.owner_index.get_coins_by_owner(&owner),
        }))
    }
}
