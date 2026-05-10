//! Object-store boundary.
//!
//! The store presents a typed transactional view over coin and edge slots.
//! Storage representation is left to the implementation; the kernel only ever
//! addresses slots through their typed identifier.

use crate::{
    error::{InsertError, KernelResult},
    object::{Coin, Edge},
    primitive::{CoinId, EdgeId},
};

/// Storage boundary for on-chain objects.
pub trait Store {
    /// Transaction type used to stage object mutations.
    type Tx<'a>: Tx
    where
        Self: 'a;

    /// Starts a transaction over this object store.
    fn begin(&mut self) -> Self::Tx<'_>;
}

/// Staged object-store transaction.
///
/// Reads observe the working transaction state. Writes are staged against the
/// transaction and become visible to the backing store only on [`Tx::commit`].
/// A dropped (uncommitted) transaction rolls back.
pub trait Tx {
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
    fn edge(&self, _id: EdgeId) -> Option<Edge> {
        None
    }

    /// Inserts `edge` under `id`.
    ///
    /// # Errors
    ///
    /// Returns [`InsertError::Exists`] if `id` is already occupied, or
    /// [`InsertError::Unavailable`] if the store cannot accept `id`.
    fn insert_edge(&mut self, _id: EdgeId, _edge: Edge) -> KernelResult<(), InsertError> {
        Err(InsertError::Unavailable)
    }

    /// Removes and returns the edge stored under `id`, if any.
    fn remove_edge(&mut self, _id: EdgeId) -> Option<Edge> {
        None
    }

    /// Commits staged mutations to the backing store.
    fn commit(self);
}
