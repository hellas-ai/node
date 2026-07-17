use crate::domain::{Coin, ObjectId};
use commonware_cryptography::{Sha256, sha256::Digest};
use commonware_glue::stateful::db::{ManagedDb, Shared};
use commonware_parallel::Sequential;
use commonware_runtime::{BufferPooler, Clock, Metrics, Storage, buffer::paged::CacheRef};
use commonware_storage::{
    journal::contiguous::fixed::Config as FixedLogConfig,
    mmr::{self, full::Config as MmrConfig},
    qmdb::{
        any::{FixedConfig, unordered::fixed::Db as AnyFixedDb},
        sync::Target,
    },
    translator::EightCap,
};
use std::num::{NonZeroU16, NonZeroU64, NonZeroUsize};

pub type UtxoDb<E> = AnyFixedDb<mmr::Family, E, ObjectId, Coin, Sha256, EightCap, Sequential>;
pub type UtxoDatabase<E> = Shared<UtxoDb<E>>;
pub type UtxoDbConfig = FixedConfig<EightCap, Sequential>;
pub type UtxoSyncTarget = Target<mmr::Family, Digest>;

#[cfg(feature = "validator")]
pub async fn root<E>(database: &UtxoDatabase<E>) -> Digest
where
    E: Storage + Clock + Metrics + 'static,
{
    database.read().await.root()
}

const ITEMS_PER_BLOB: NonZeroU64 = NonZeroU64::new(256).unwrap();
const WRITE_BUFFER: NonZeroUsize = NonZeroUsize::new(8192).unwrap();

pub const DEFAULT_PAGE_CACHE_SIZE: NonZeroU16 = NonZeroU16::new(4096).unwrap();
pub const DEFAULT_PAGE_CACHE_COUNT: NonZeroUsize = NonZeroUsize::new(1024).unwrap();

pub fn utxo_db_config(
    pooler: &impl BufferPooler,
    partition_prefix: &str,
    page_cache_size: u16,
    page_cache_count: usize,
) -> UtxoDbConfig {
    let page_cache_size = NonZeroU16::new(page_cache_size).unwrap_or(DEFAULT_PAGE_CACHE_SIZE);
    let page_cache_count = NonZeroUsize::new(page_cache_count).unwrap_or(DEFAULT_PAGE_CACHE_COUNT);
    let page_cache = CacheRef::from_pooler(pooler, page_cache_size, page_cache_count);

    FixedConfig {
        merkle_config: MmrConfig {
            journal_partition: format!("{partition_prefix}_utxo_mmr_journal"),
            metadata_partition: format!("{partition_prefix}_utxo_mmr_metadata"),
            items_per_blob: ITEMS_PER_BLOB,
            write_buffer: WRITE_BUFFER,
            strategy: Sequential,
            page_cache: page_cache.clone(),
        },
        journal_config: FixedLogConfig {
            partition: format!("{partition_prefix}_utxo_log_journal"),
            items_per_blob: ITEMS_PER_BLOB,
            page_cache,
            write_buffer: WRITE_BUFFER,
        },
        translator: EightCap,
        init_cache_size: None,
    }
}

pub async fn empty_state<E>(
    context: E,
    partition_prefix: &str,
    page_cache_size: u16,
    page_cache_count: usize,
) -> (Digest, UtxoSyncTarget)
where
    E: Storage + Clock + Metrics + BufferPooler,
{
    let config = utxo_db_config(
        &context,
        &format!("{partition_prefix}_genesis_probe"),
        page_cache_size,
        page_cache_count,
    );
    let db = UtxoDb::init(context, config)
        .await
        .expect("genesis probe database must initialize");
    let state_root = db.root();
    let sync_target = <UtxoDb<E> as ManagedDb<E>>::sync_target(&db);
    (state_root, sync_target)
}
