//! Object-store boundary.
//!
//! The store presents a typed transactional view over coin, edge, and
//! registry-chunk slots. Storage representation is left to the
//! implementation; the kernel only ever addresses slots through their
//! typed identifier.
//!
//! Registry chunks share this one store rather than getting their own.
//! They are consensus state, so they have to live under the same
//! authenticated root as coins and edges; a second store beside this one
//! would be state consensus agrees on but does not commit to.
//!
//! # Assumed of the implementation
//!
//! Two premises the kernel takes on faith. They are not properties this
//! crate establishes; they are the contract an implementation must
//! honour, and every correctness argument that reads this store stops
//! applying if one is violated.
//!
//! - **Transactions are atomic.** All writes staged in one [`Batch`]
//!   commit together or none commit at all. The kernel relies on this to
//!   roll back a rejected operation; `models/l1.qnt` captures the same
//!   thing by updating every primed variable inside one `action` block.
//!   Violation: a partially applied operation, which no abstract state
//!   of any model here can represent.
//! - **Slot reads observe the working transaction.** A read through a
//!   [`Batch`] sees that batch's own staged writes and no concurrent
//!   modification from elsewhere. The kernel's two-phase validate-then-
//!   fold depends on it. The abstract models have no concurrency, so
//!   this holds there trivially and is checked nowhere.

use crate::{
    error::{InsertError, KernelResult},
    object::{Coin, Edge},
    primitive::{CoinId, EdgeId},
    registry::{RegistryChunk, RegistryChunkId},
};

/// Storage boundary for on-chain objects.
pub trait Store {
    /// Transaction type used to stage object mutations.
    type Batch<'a>: Batch
    where
        Self: 'a;

    /// Starts a transaction over this object store.
    fn begin(&mut self) -> Self::Batch<'_>;
}

/// Staged object-store transaction.
///
/// Reads observe the working transaction state. Writes are staged against the
/// transaction and become visible to the backing store only on [`Batch::commit`].
/// A dropped (uncommitted) transaction rolls back.
///
pub trait Batch {
    /// Returns the coin stored under `id`, if any.
    fn coin(&self, id: CoinId) -> Option<Coin>;

    /// Inserts `coin` under `id`.
    ///
    /// # Errors
    ///
    /// Returns [`InsertError::Exists`] if `id` is already occupied, or
    /// [`InsertError::Unavailable`] if the store cannot accept `id`.
    fn insert_coin(&mut self, id: CoinId, coin: Coin) -> KernelResult<(), InsertError>;

    /// Removes and returns the coin stored under `id`, if any.
    fn remove_coin(&mut self, id: CoinId) -> Option<Coin>;

    /// Returns the edge stored under `id`, if any.
    fn edge(&self, id: EdgeId) -> Option<Edge>;

    /// Inserts `edge` under `id`.
    ///
    /// # Errors
    ///
    /// Returns [`InsertError::Exists`] if `id` is already occupied, or
    /// [`InsertError::Unavailable`] if the store cannot accept `id`.
    fn insert_edge(&mut self, id: EdgeId, edge: Edge) -> KernelResult<(), InsertError>;

    /// Removes and returns the edge stored under `id`, if any.
    fn remove_edge(&mut self, id: EdgeId) -> Option<Edge>;

    /// Returns the registry chunk stored under `id`, if any.
    fn registry_chunk(&self, id: RegistryChunkId) -> Option<RegistryChunk>;

    /// Inserts `chunk` under `id`.
    ///
    /// Replacing a chunk is a remove followed by an insert, not an
    /// overwrite: the same two steps a coin or edge slot takes, so one
    /// slot rule covers all three object kinds.
    ///
    /// # Errors
    ///
    /// Returns [`InsertError::Exists`] if `id` is already occupied, or
    /// [`InsertError::Unavailable`] if the store cannot accept `id`.
    fn insert_registry_chunk(
        &mut self,
        id: RegistryChunkId,
        chunk: RegistryChunk,
    ) -> KernelResult<(), InsertError>;

    /// Removes and returns the registry chunk stored under `id`, if any.
    fn remove_registry_chunk(&mut self, id: RegistryChunkId) -> Option<RegistryChunk>;

    /// Commits staged mutations to the backing store.
    fn commit(self);
}
