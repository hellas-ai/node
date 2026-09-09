//! Synchronous block working set for kernel block application.

use std::collections::HashMap;

use hellas_kernel::{
    Batch, Coin, CoinId, Edge, EdgeId, InsertError, KernelResult, RegistryChunk, RegistryChunkId,
    Store,
};

/// Synchronous staging area for one block's apply pass.
///
/// Holds one entry per `(CoinId | EdgeId | RegistryChunkId)` the block
/// references, with
/// `None` representing "slot is currently empty" (e.g. an output coin id
/// the block will create) and `Some(_)` representing "slot is currently
/// occupied". The kernel reads through [`Batch::coin`] / [`Batch::edge`]
/// and writes through [`Batch::insert_coin`] / [`Batch::remove_coin`]
/// (analogous for edges).
///
/// **Pre-load required.** Inserts and removes only operate on slots
/// declared in advance via [`Self::insert_coin_slot`] /
/// [`Self::insert_edge_slot`] / [`Self::insert_registry_chunk_slot`]. A
/// kernel write to an unknown slot returns [`InsertError::Unavailable`] —
/// the parallel-execution safety property: the host has to surface every
/// id it intends to mutate.
#[derive(Debug, Clone, Default)]
pub struct BlockWorkingSet {
    coins: HashMap<CoinId, Option<Coin>>,
    edges: HashMap<EdgeId, Option<Edge>>,
    registry: HashMap<RegistryChunkId, Option<RegistryChunk>>,
}

impl BlockWorkingSet {
    /// Creates an empty working set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Declares a coin slot. `coin` is `Some(_)` if the slot is currently
    /// occupied in the backing store, `None` if it's empty (e.g. an
    /// output id the block will produce).
    pub fn insert_coin_slot(&mut self, id: CoinId, coin: Option<Coin>) {
        self.coins.insert(id, coin);
    }

    /// Declares an edge slot. Same semantics as [`Self::insert_coin_slot`].
    pub fn insert_edge_slot(&mut self, id: EdgeId, edge: Option<Edge>) {
        self.edges.insert(id, edge);
    }

    /// Declares a registry chunk slot. Same semantics as
    /// [`Self::insert_coin_slot`].
    pub fn insert_registry_chunk_slot(
        &mut self,
        id: RegistryChunkId,
        chunk: Option<RegistryChunk>,
    ) {
        self.registry.insert(id, chunk);
    }

    /// Reads the current coin at `id`, ignoring pre-load tracking.
    #[must_use]
    pub fn coin(&self, id: CoinId) -> Option<Coin> {
        self.coins.get(&id).copied().flatten()
    }

    /// Reads the current edge at `id`.
    #[must_use]
    pub fn edge(&self, id: EdgeId) -> Option<Edge> {
        self.edges.get(&id).copied().flatten()
    }

    /// Reads the current registry chunk at `id`.
    #[must_use]
    pub fn registry_chunk(&self, id: RegistryChunkId) -> Option<RegistryChunk> {
        self.registry.get(&id).copied().flatten()
    }
}

impl Store for BlockWorkingSet {
    type Batch<'a>
        = WorkingBatch<'a>
    where
        Self: 'a;

    fn begin(&mut self) -> Self::Batch<'_> {
        WorkingBatch {
            coins: self.coins.clone(),
            edges: self.edges.clone(),
            registry: self.registry.clone(),
            parent: self,
        }
    }
}

/// Staged transaction over a [`BlockWorkingSet`].
///
/// Reads observe the working copy; writes mutate the working copy;
/// [`Batch::commit`] copies the working copy back into the parent
/// `BlockWorkingSet`. A dropped (uncommitted) batch rolls back.
pub struct WorkingBatch<'a> {
    coins: HashMap<CoinId, Option<Coin>>,
    edges: HashMap<EdgeId, Option<Edge>>,
    registry: HashMap<RegistryChunkId, Option<RegistryChunk>>,
    parent: &'a mut BlockWorkingSet,
}

impl Batch for WorkingBatch<'_> {
    fn coin(&self, id: CoinId) -> Option<Coin> {
        self.coins.get(&id).copied().flatten()
    }

    fn insert_coin(&mut self, id: CoinId, coin: Coin) -> KernelResult<(), InsertError> {
        match self.coins.get(&id) {
            None => Err(InsertError::Unavailable),
            Some(Some(_)) => Err(InsertError::Exists),
            Some(None) => {
                self.coins.insert(id, Some(coin));
                Ok(())
            }
        }
    }

    fn remove_coin(&mut self, id: CoinId) -> Option<Coin> {
        let slot = self.coins.get_mut(&id)?;
        slot.take()
    }

    fn edge(&self, id: EdgeId) -> Option<Edge> {
        self.edges.get(&id).copied().flatten()
    }

    fn insert_edge(&mut self, id: EdgeId, edge: Edge) -> KernelResult<(), InsertError> {
        match self.edges.get(&id) {
            None => Err(InsertError::Unavailable),
            Some(Some(_)) => Err(InsertError::Exists),
            Some(None) => {
                self.edges.insert(id, Some(edge));
                Ok(())
            }
        }
    }

    fn remove_edge(&mut self, id: EdgeId) -> Option<Edge> {
        let slot = self.edges.get_mut(&id)?;
        slot.take()
    }

    fn registry_chunk(&self, id: RegistryChunkId) -> Option<RegistryChunk> {
        self.registry.get(&id).copied().flatten()
    }

    fn insert_registry_chunk(
        &mut self,
        id: RegistryChunkId,
        chunk: RegistryChunk,
    ) -> KernelResult<(), InsertError> {
        match self.registry.get(&id) {
            None => Err(InsertError::Unavailable),
            Some(Some(_)) => Err(InsertError::Exists),
            Some(None) => {
                self.registry.insert(id, Some(chunk));
                Ok(())
            }
        }
    }

    fn remove_registry_chunk(&mut self, id: RegistryChunkId) -> Option<RegistryChunk> {
        let slot = self.registry.get_mut(&id)?;
        slot.take()
    }

    fn commit(self) {
        self.parent.coins = self.coins;
        self.parent.edges = self.edges;
        self.parent.registry = self.registry;
    }
}

#[cfg(test)]
mod tests;
