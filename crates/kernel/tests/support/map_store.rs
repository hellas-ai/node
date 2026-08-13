//! Growing-set test backend for the kernel `Store` trait.
//!
//! `FixedStore` is the no-allocation hot-path backend the kernel ships with;
//! it pre-allocates every coin/edge slot. Real backends grow as state grows:
//! they add slots on `insert` and free them on `remove`. `MapStore` is that
//! shape, backed by `BTreeMap` for determinism. Tests use it to:
//!
//!   - exercise the `Store` trait against a non-bounded backend (catching
//!     any `FixedStore`-specific assumption baked into kernel logic),
//!   - run scenarios that exceed `FixedStore`'s compile-time slot count
//!     (large batches, long-running sequences),
//!   - benchmark the apply path against a backend whose lookup grows with
//!     state size.
//!
//! Kernel hot-path discipline is unaffected: `MapStore` lives in tests, the
//! kernel crate does not depend on it, and `clippy.toml`'s
//! `disallowed-types` ban on `BTreeMap` still applies to `src/`.

use std::collections::BTreeMap;

use hellas_kernel::{
    Batch, Coin, CoinId, Edge, EdgeId, Genesis, InsertError, KernelResult, RegistryChunk,
    RegistryChunkId, Store,
};

/// Two-phase staged transaction: writes go to a side `working` map; on
/// `commit`, the working map is swapped into the parent. A dropped
/// transaction discards staged writes.
#[derive(Debug, Default)]
pub(crate) struct MapStore {
    coins: BTreeMap<CoinId, Coin>,
    edges: BTreeMap<EdgeId, Edge>,
    registry: BTreeMap<RegistryChunkId, RegistryChunk>,
}

impl MapStore {
    /// Empty store; use [`State::genesis`](hellas_kernel::State::genesis) to
    /// seed initial coins.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Direct read of a coin by id (bypasses the transaction layer).
    #[must_use]
    pub(crate) fn coin(&self, id: CoinId) -> Option<Coin> {
        self.coins.get(&id).copied()
    }

    /// Direct read of an edge by id (bypasses the transaction layer).
    #[must_use]
    pub(crate) fn edge(&self, id: EdgeId) -> Option<Edge> {
        self.edges.get(&id).copied()
    }

    /// Direct read of a registry chunk by id (bypasses the transaction
    /// layer).
    #[must_use]
    pub(crate) fn registry_chunk(&self, id: RegistryChunkId) -> Option<RegistryChunk> {
        self.registry.get(&id).copied()
    }
}

impl Store for MapStore {
    type Batch<'a>
        = MapTx<'a>
    where
        Self: 'a;

    fn begin(&mut self) -> Self::Batch<'_> {
        let working = Working {
            coins: self.coins.clone(),
            edges: self.edges.clone(),
            registry: self.registry.clone(),
        };
        MapTx {
            working,
            parent: self,
        }
    }
}

/// Working snapshot held inside a transaction. Cloned from the parent at
/// `begin`; swapped into the parent on `commit`.
#[derive(Debug, Default)]
struct Working {
    coins: BTreeMap<CoinId, Coin>,
    edges: BTreeMap<EdgeId, Edge>,
    registry: BTreeMap<RegistryChunkId, RegistryChunk>,
}

pub(crate) struct MapTx<'a> {
    working: Working,
    parent: &'a mut MapStore,
}

impl Batch for MapTx<'_> {
    fn coin(&self, id: CoinId) -> Option<Coin> {
        self.working.coins.get(&id).copied()
    }

    fn insert_coin(&mut self, id: CoinId, coin: Coin) -> KernelResult<(), InsertError> {
        if self.working.coins.contains_key(&id) {
            return Err(InsertError::Exists);
        }
        self.working.coins.insert(id, coin);
        Ok(())
    }

    fn remove_coin(&mut self, id: CoinId) -> Option<Coin> {
        self.working.coins.remove(&id)
    }

    fn edge(&self, id: EdgeId) -> Option<Edge> {
        self.working.edges.get(&id).copied()
    }

    fn insert_edge(&mut self, id: EdgeId, edge: Edge) -> KernelResult<(), InsertError> {
        if self.working.edges.contains_key(&id) {
            return Err(InsertError::Exists);
        }
        self.working.edges.insert(id, edge);
        Ok(())
    }

    fn remove_edge(&mut self, id: EdgeId) -> Option<Edge> {
        self.working.edges.remove(&id)
    }

    fn registry_chunk(&self, id: RegistryChunkId) -> Option<RegistryChunk> {
        self.working.registry.get(&id).copied()
    }

    fn insert_registry_chunk(
        &mut self,
        id: RegistryChunkId,
        chunk: RegistryChunk,
    ) -> KernelResult<(), InsertError> {
        if self.working.registry.contains_key(&id) {
            return Err(InsertError::Exists);
        }
        self.working.registry.insert(id, chunk);
        Ok(())
    }

    fn remove_registry_chunk(&mut self, id: RegistryChunkId) -> Option<RegistryChunk> {
        self.working.registry.remove(&id)
    }

    fn commit(self) {
        self.parent.coins = self.working.coins;
        self.parent.edges = self.working.edges;
        self.parent.registry = self.working.registry;
    }
}

/// Iterators over the live state. `MapStore` does not implement `Snapshot`
/// because the `Snapshot::View` associated type pins a single compile-time
/// `(C, E)` and the map-backed store has no such bound. Tests that need
/// invariant checks iterate via these methods directly.
impl MapStore {
    pub(crate) fn coins(&self) -> impl Iterator<Item = (CoinId, Coin)> + '_ {
        self.coins.iter().map(|(id, coin)| (*id, *coin))
    }

    pub(crate) fn edges(&self) -> impl Iterator<Item = (EdgeId, Edge)> + '_ {
        self.edges.iter().map(|(id, edge)| (*id, *edge))
    }

    pub(crate) fn coin_count(&self) -> usize {
        self.coins.len()
    }

    pub(crate) fn edge_count(&self) -> usize {
        self.edges.len()
    }

    pub(crate) fn registry_chunks(&self) -> impl Iterator<Item = (RegistryChunkId, RegistryChunk)> {
        self.registry.iter().map(|(id, chunk)| (*id, *chunk))
    }

    pub(crate) fn registry_chunk_count(&self) -> usize {
        self.registry.len()
    }
}

/// Convenience: seed a `MapStore` with the given genesis coins and wrap it
/// as state. Mirrors `support::state` but for the growing backend.
pub(crate) fn map_state<const G: usize>(seeds: [Genesis; G]) -> hellas_kernel::State<MapStore> {
    hellas_kernel::State::genesis(MapStore::new(), &seeds)
        .unwrap_or_else(|_| panic!("genesis rejected map-store seeds"))
}
