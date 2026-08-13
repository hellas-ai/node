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
//! Abstract counterpart: the store atomicity / read-isolation assumptions
//! in `models/deps/assumptions.qnt`. The Quint model captures atomicity by
//! updating all primed variables in one `action` block; this trait is the
//! Rust contract callers must honor for that abstraction to hold.

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
