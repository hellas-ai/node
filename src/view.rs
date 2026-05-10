//! Allocation-free state snapshots for models and refinement checks.

use crate::{
    object::{Coin, Edge},
    primitive::{CoinId, EdgeId},
};

/// Abstract live-state view over bounded coin and edge sets.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub struct View<const C: usize, const E: usize> {
    coins: [Option<(CoinId, Coin)>; C],
    edges: [Option<(EdgeId, Edge)>; E],
}

impl<const C: usize, const E: usize> View<C, E> {
    /// Creates a compact view from bounded live-object arrays.
    #[must_use]
    pub fn new(coins: [Option<(CoinId, Coin)>; C], edges: [Option<(EdgeId, Edge)>; E]) -> Self {
        Self {
            coins: Self::pack(coins),
            edges: Self::pack(edges),
        }
    }

    /// Iterates over live coins.
    pub fn coins(&self) -> impl Iterator<Item = (CoinId, Coin)> + '_ {
        self.coins.iter().copied().flatten()
    }

    /// Iterates over live edges.
    pub fn edges(&self) -> impl Iterator<Item = (EdgeId, Edge)> + '_ {
        self.edges.iter().copied().flatten()
    }

    /// Returns the live coin stored under `id`, if any.
    #[must_use]
    pub fn coin(&self, id: CoinId) -> Option<Coin> {
        self.coins()
            .find_map(|(coin_id, coin)| (coin_id == id).then_some(coin))
    }

    /// Returns the live edge stored under `id`, if any.
    #[must_use]
    pub fn edge(&self, id: EdgeId) -> Option<Edge> {
        self.edges()
            .find_map(|(edge_id, edge)| (edge_id == id).then_some(edge))
    }

    /// Returns the number of live coins.
    #[must_use]
    pub fn coin_len(&self) -> usize {
        self.coins().count()
    }

    /// Returns the number of live edges.
    #[must_use]
    pub fn edge_len(&self) -> usize {
        self.edges().count()
    }

    fn pack<T: Copy, const N: usize>(items: [Option<T>; N]) -> [Option<T>; N] {
        let mut packed = [None; N];
        for (index, item) in items.into_iter().flatten().enumerate() {
            packed[index] = Some(item);
        }

        packed
    }
}

/// Store extension for producing bounded abstract state views.
pub trait Snapshot<const C: usize, const E: usize> {
    /// Returns the live-state view for this store.
    #[must_use]
    fn view(&self) -> View<C, E>;
}
