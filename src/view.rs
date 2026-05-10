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
            coins: Self::pack_coins(coins),
            edges: Self::pack_edges(edges),
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

    fn pack_coins(items: [Option<(CoinId, Coin)>; C]) -> [Option<(CoinId, Coin)>; C] {
        let mut packed = Self::pack(items);
        Self::sort(&mut packed, |left, right| {
            left.0.as_bytes() > right.0.as_bytes()
        });
        packed
    }

    fn pack_edges(items: [Option<(EdgeId, Edge)>; E]) -> [Option<(EdgeId, Edge)>; E] {
        let mut packed = Self::pack(items);
        Self::sort(&mut packed, |left, right| {
            left.0.as_bytes() > right.0.as_bytes()
        });
        packed
    }

    fn sort<T: Copy, const N: usize>(items: &mut [Option<T>; N], gt: fn(T, T) -> bool) {
        let mut index = 1;
        while index < N {
            let Some(item) = items[index] else {
                return;
            };
            let mut insert = index;
            while insert > 0 {
                let Some(previous) = items[insert - 1] else {
                    break;
                };
                if !gt(previous, item) {
                    break;
                }
                items[insert] = items[insert - 1];
                insert -= 1;
            }
            items[insert] = Some(item);
            index += 1;
        }
    }
}

/// Store extension for producing bounded abstract state views.
///
/// Each store picks its canonical `View` shape via the associated type so
/// callers can write `state.view()` without turbofish.
pub trait Snapshot {
    /// Bounded view shape produced by this store.
    type View;

    /// Returns the live-state view for this store.
    #[must_use]
    fn view(&self) -> Self::View;
}
