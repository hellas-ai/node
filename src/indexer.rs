use crate::{
    app::{HellasBlock, MarshalMailbox},
    light_client::{FinalizedBlock, FinalizedBlockQuery, LatestBlock, QueryError},
};
use commonware_codec::Encode;
use commonware_consensus::{Heightable, marshal::Identifier as MarshalIdentifier, types::Height};
use commonware_cryptography::{Digestible, sha256::Digest};

#[derive(Clone)]
pub struct ChainIndexer {
    marshal: MarshalMailbox,
}

impl ChainIndexer {
    pub fn new(marshal: MarshalMailbox) -> Self {
        Self { marshal }
    }

    pub async fn get_finalization(&self, payload: Digest) -> Result<Option<Vec<u8>>, QueryError> {
        let Some((height, stored_payload)) = self.marshal.get_info(&payload).await else {
            return Ok(None);
        };
        if stored_payload != payload {
            return Err(QueryError::StateUnavailable(
                "finalization index returned a mismatched payload".to_string(),
            ));
        }
        Ok(self
            .marshal
            .get_finalization(height)
            .await
            .map(|finalization| finalization.encode().to_vec()))
    }

    pub async fn get_latest_block(&self) -> Result<Option<LatestBlock>, QueryError> {
        Ok(self
            .get_finalized_block(FinalizedBlockQuery::Latest)
            .await?
            .map(|block| block.snapshot))
    }

    pub async fn get_finalized_block(
        &self,
        query: FinalizedBlockQuery,
    ) -> Result<Option<FinalizedBlock>, QueryError> {
        let info = match query {
            FinalizedBlockQuery::Latest => self.marshal.get_info(MarshalIdentifier::Latest).await,
            FinalizedBlockQuery::Height(height) => self.marshal.get_info(Height::new(height)).await,
            FinalizedBlockQuery::Payload(payload) => self.marshal.get_info(&payload).await,
        };
        let Some((height, payload)) = info else {
            return Ok(None);
        };
        if let FinalizedBlockQuery::Payload(expected) = query
            && payload != expected
        {
            return Err(QueryError::StateUnavailable(
                "finalized block index returned a mismatched payload".to_string(),
            ));
        }
        self.get_finalized_block_at(height, payload).await
    }

    async fn get_finalized_block_at(
        &self,
        height: Height,
        payload: Digest,
    ) -> Result<Option<FinalizedBlock>, QueryError> {
        let Some(block) = self.marshal.get_block(height).await else {
            return Err(QueryError::StateUnavailable(format!(
                "finalized block is missing at height {}",
                height.get()
            )));
        };
        if block.digest() != payload {
            return Err(QueryError::StateUnavailable(
                "finalized block digest did not match index".to_string(),
            ));
        }
        let Some(finalization) = self.marshal.get_finalization(height).await else {
            return Err(QueryError::StateUnavailable(format!(
                "finalization is missing at height {}",
                height.get()
            )));
        };
        if finalization.proposal.payload != payload {
            return Err(QueryError::StateUnavailable(
                "finalization payload did not match block".to_string(),
            ));
        }
        Ok(Some(finalized_block(block, finalization.encode().to_vec())))
    }
}

fn finalized_block(block: HellasBlock, finalization: Vec<u8>) -> FinalizedBlock {
    FinalizedBlock {
        snapshot: LatestBlock {
            height: block.height().get(),
            payload: block.digest(),
            state_root: block.state_root(),
            finalization,
        },
        block: block.encode().to_vec(),
    }
}
