//! Allocation-free state snapshots for models and refinement checks.
//!
//! Abstract counterpart: the live `coins` / `edges` / `liveCoins` /
//! `liveEdges` projections in `models/l1.qnt`. ITF replay (`tests/itf.rs`)
//! reads each abstract step and asserts the kernel's [`View`] matches; the
//! model's `valueConserved`, `noNegativeValue`, and shape rules
//! (`models/rules/invariants.qnt`) are checked against this same view.

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
            coins: pack_sorted(coins),
            edges: pack_sorted(edges),
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
}

/// Compacts live entries to the front and sorts them by identifier.
fn pack_sorted<K: Ord + Copy, V: Copy, const N: usize>(
    items: [Option<(K, V)>; N],
) -> [Option<(K, V)>; N] {
    let mut packed = [None; N];
    let mut len = 0;
    for (slot, item) in packed.iter_mut().zip(items.into_iter().flatten()) {
        *slot = Some(item);
        len += 1;
    }
    if let Some(live) = packed.get_mut(..len) {
        live.sort_unstable_by(|left, right| match (left, right) {
            (Some((left_id, _)), Some((right_id, _))) => left_id.cmp(right_id),
            // The packed prefix holds only `Some` entries.
            _ => core::cmp::Ordering::Equal,
        });
    }
    packed
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
