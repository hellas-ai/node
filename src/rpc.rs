//! Local implementation of the light-client query interface.

use crate::{
    app::{MarshalMailbox, Mempool},
    execution::store::{UtxoDatabase, get as utxo_get, root as utxo_root},
    indexer::Indexer,
};
use commonware_consensus::{Heightable, marshal::Identifier as MarshalIdentifier};
use commonware_cryptography::{Digestible, sha256::Digest};
use hellas_kernel::domain::{Address, Coin, Encode, ObjectId, Transaction};
use hellas_rpc::{LatestBlock, LightClient, QueryError};

/// In-process [`LightClient`] backed by the local application handle.
#[derive(Clone)]
pub struct LocalLightClient {
    databases: UtxoDatabase<commonware_runtime::tokio::Context>,
    indexer: Indexer,
    mempool: Mempool,
    marshal: MarshalMailbox,
    validators: Vec<String>,
}

impl LocalLightClient {
    pub fn new(
        databases: UtxoDatabase<commonware_runtime::tokio::Context>,
        indexer: Indexer,
        mempool: Mempool,
        marshal: MarshalMailbox,
        validators: Vec<String>,
    ) -> Self {
        Self {
            databases,
            indexer,
            mempool,
            marshal,
            validators,
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
        let Some((height, _)) = self.marshal.get_info(&payload).await else {
            return Ok(None);
        };
        Ok(self
            .marshal
            .get_finalization(height)
            .await
            .map(|finalization| finalization.encode().to_vec()))
    }

    async fn get_latest_block(&self) -> Result<Option<LatestBlock>, QueryError> {
        let block = self.marshal.get_block(MarshalIdentifier::Latest).await;
        Ok(block.map(|block| LatestBlock {
            height: block.height().get(),
            payload: block.digest(),
            state_root: block.state_root(),
        }))
    }

    async fn submit_tx(&self, tx: Transaction) -> Result<(), QueryError> {
        self.mempool.submit(tx).await;
        Ok(())
    }

    async fn get_validators(&self) -> Result<Vec<String>, QueryError> {
        Ok(self.validators.clone())
    }

    async fn get_coins_by_owner(&self, owner: Address) -> Result<Vec<(ObjectId, u64)>, QueryError> {
        let latest = self.get_latest_block().await?;
        let Some(latest) = latest else {
            return Ok(Vec::new());
        };
        let cursor = self.indexer.cursor();
        if cursor.payload != latest.payload {
            return Err(QueryError::StateUnavailable(
                "owner index has not reached latest payload".to_string(),
            ));
        }
        Ok(self.indexer.get_coins_by_owner(&owner))
    }
}
