use crate::object::{Coin, ObjectId};
use commonware_cryptography::Sha256;
use commonware_runtime::buffer::PoolRef;
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
const WRITE_BUFFER: NonZeroUsize = NonZeroUsize::new(4096).unwrap();

/// Buffer pool page size.
const BUFFER_PAGE_SIZE: NonZeroU16 = NonZeroU16::new(4096).unwrap();

/// Buffer pool page count.
const BUFFER_PAGE_COUNT: NonZeroUsize = NonZeroUsize::new(1024).unwrap();

/// Build a [FixedConfig] for the UTXO database.
///
/// The `partition_prefix` must be unique per validator instance to avoid
/// storage collisions in tests or multi-process setups.
pub fn utxo_db_config(partition_prefix: &str) -> FixedConfig<EightCap> {
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
        buffer_pool: PoolRef::new(BUFFER_PAGE_SIZE, BUFFER_PAGE_COUNT),
    }
}
