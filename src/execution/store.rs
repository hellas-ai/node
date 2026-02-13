use hellas_types::{Coin, ObjectId};
use commonware_cryptography::Sha256;
use commonware_runtime::{BufferPooler, buffer::paged::CacheRef};
use commonware_storage::{
    qmdb::current::{FixedConfig, unordered::fixed::Db as CurrentFixedDb},
    translator::EightCap,
};
use std::num::{NonZeroU16, NonZeroU64, NonZeroUsize};

/// Bitmap chunk size for the QMDB Merkle tree.
///
/// Must be a power of 2 and a multiple of the digest size (32).
pub const CHUNK_SIZE: usize = 32;

/// Type alias for the UTXO state database.
///
/// - Keys are `ObjectId` (`sha256::Digest`, 32 bytes)
/// - Values are `Coin` (40 bytes fixed: `PublicKey` 32 + `u64` 8)
/// - `EightCap` compresses 32-byte keys to 8 bytes for index bucketing
pub type UtxoDb<E> = CurrentFixedDb<E, ObjectId, Coin, Sha256, EightCap, CHUNK_SIZE>;

/// Items per blob for journals.
const ITEMS_PER_BLOB: NonZeroU64 = NonZeroU64::new(256).unwrap();

/// Write buffer size for journals.
const WRITE_BUFFER: NonZeroUsize = NonZeroUsize::new(8192).unwrap();

/// Buffer pool page size.
pub const DEFAULT_PAGE_CACHE_SIZE: NonZeroU16 = NonZeroU16::new(4096).unwrap();

/// Buffer pool page count.
pub const DEFAULT_PAGE_CACHE_COUNT: NonZeroUsize = NonZeroUsize::new(1024).unwrap();

/// Build a [FixedConfig] for the UTXO database.
///
/// The `partition_prefix` must be unique per validator instance to avoid
/// storage collisions in tests or multi-process setups.
pub fn utxo_db_config(
    pooler: &impl BufferPooler,
    partition_prefix: &str,
    page_cache_size: u16,
    page_cache_count: usize,
) -> FixedConfig<EightCap> {
    let page_cache_size = NonZeroU16::new(page_cache_size).unwrap_or(DEFAULT_PAGE_CACHE_SIZE);
    let page_cache_count = NonZeroUsize::new(page_cache_count).unwrap_or(DEFAULT_PAGE_CACHE_COUNT);

    FixedConfig {
        mmr_journal_partition: format!("{partition_prefix}_utxo_mmr_journal"),
        mmr_items_per_blob: ITEMS_PER_BLOB,
        mmr_write_buffer: WRITE_BUFFER,
        mmr_metadata_partition: format!("{partition_prefix}_utxo_mmr_metadata"),
        log_journal_partition: format!("{partition_prefix}_utxo_log_journal"),
        log_items_per_blob: ITEMS_PER_BLOB,
        log_write_buffer: WRITE_BUFFER,
        bitmap_metadata_partition: format!("{partition_prefix}_utxo_bitmap_metadata"),
        translator: EightCap,
        thread_pool: None,
        page_cache: CacheRef::from_pooler(pooler, page_cache_size, page_cache_count),
    }
}
