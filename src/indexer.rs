use crate::{
    app::{HellasBlock, MarshalMailbox},
    config::Config,
    light_client::{FinalizedBlock, FinalizedBlockQuery, LatestBlock, QueryError},
};
use commonware_codec::Encode;
use commonware_consensus::{Heightable, marshal::Identifier as MarshalIdentifier, types::Height};
use commonware_cryptography::{Digestible, certificate::Scheme as _, sha256::Digest};
use commonware_runtime::tokio;
use commonware_storage::archive::immutable;
use commonware_utils::NZU64;
use hellas_kernel::domain::Scheme;
use std::num::NonZeroUsize;

pub type Finalization = commonware_consensus::simplex::types::Finalization<Scheme, Digest>;
pub type FinalizationStore = immutable::Archive<tokio::Context, Digest, Finalization>;
pub type BlockStore = immutable::Archive<tokio::Context, Digest, HellasBlock>;

pub async fn init_finalization_store(
    context: tokio::Context,
    partition_prefix: &str,
    config: &Config,
) -> FinalizationStore {
    let page_cache = config.page_cache(&context);
    immutable::Archive::init(
        context,
        immutable::Config {
            metadata_partition: format!("{partition_prefix}-finalizations-by-height-metadata"),
            freezer_table_partition: format!(
                "{partition_prefix}-finalizations-by-height-freezer-table"
            ),
            freezer_table_initial_size: 64,
            freezer_table_resize_frequency: 10,
            freezer_table_resize_chunk_size: 10,
            freezer_key_partition: format!(
                "{partition_prefix}-finalizations-by-height-freezer-key"
            ),
            freezer_key_page_cache: page_cache,
            freezer_value_partition: format!(
                "{partition_prefix}-finalizations-by-height-freezer-value"
            ),
            freezer_value_target_size: 65536,
            freezer_value_compression: None,
            ordinal_partition: format!("{partition_prefix}-finalizations-by-height-ordinal"),
            items_per_section: NZU64!(256),
            codec_config: Scheme::certificate_codec_config_unbounded(),
            replay_buffer: NonZeroUsize::new(config.replay_buffer).unwrap_or(NonZeroUsize::MIN),
            freezer_key_write_buffer: NonZeroUsize::new(config.write_buffer)
                .unwrap_or(NonZeroUsize::MIN),
            freezer_value_write_buffer: NonZeroUsize::new(config.write_buffer)
                .unwrap_or(NonZeroUsize::MIN),
            ordinal_write_buffer: NonZeroUsize::new(config.write_buffer)
                .unwrap_or(NonZeroUsize::MIN),
        },
    )
    .await
    .expect("failed to initialize finalizations archive")
}

pub async fn init_block_store(
    context: tokio::Context,
    partition_prefix: &str,
    config: &Config,
) -> BlockStore {
    let page_cache = config.page_cache(&context);
    immutable::Archive::init(
        context,
        immutable::Config {
            metadata_partition: format!("{partition_prefix}-finalized-blocks-metadata"),
            freezer_table_partition: format!("{partition_prefix}-finalized-blocks-freezer-table"),
            freezer_table_initial_size: 64,
            freezer_table_resize_frequency: 10,
            freezer_table_resize_chunk_size: 10,
            freezer_key_partition: format!("{partition_prefix}-finalized-blocks-freezer-key"),
            freezer_key_page_cache: page_cache,
            freezer_value_partition: format!("{partition_prefix}-finalized-blocks-freezer-value"),
            freezer_value_target_size: 65536,
            freezer_value_compression: None,
            ordinal_partition: format!("{partition_prefix}-finalized-blocks-ordinal"),
            items_per_section: NZU64!(256),
            codec_config: (),
            replay_buffer: NonZeroUsize::new(config.replay_buffer).unwrap_or(NonZeroUsize::MIN),
            freezer_key_write_buffer: NonZeroUsize::new(config.write_buffer)
                .unwrap_or(NonZeroUsize::MIN),
            freezer_value_write_buffer: NonZeroUsize::new(config.write_buffer)
                .unwrap_or(NonZeroUsize::MIN),
            ordinal_write_buffer: NonZeroUsize::new(config.write_buffer)
                .unwrap_or(NonZeroUsize::MIN),
        },
    )
    .await
    .expect("failed to initialize finalized blocks archive")
}

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
