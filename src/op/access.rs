//! Slot access summary used by parallel scheduling.
//!
//! No abstract counterpart — the model evaluates one action at a time and
//! has no notion of parallel scheduling. [`Access`] exists so callers
//! ordering operations into waves can detect read/write conflicts without
//! taking the full apply path; `tests/parallel.rs` checks that disjoint
//! waves produce the same final state as a sequential block.

use super::{EdgeList, MAX_EDGE_INPUTS, MAX_EDGE_OUTPUTS, overlaps};
use crate::{list::List, primitive::CoinId};

/// Deterministic state slots consumed and created by one operation.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub struct Access {
    pub(super) coins: List<CoinId, MAX_EDGE_INPUTS>,
    pub(super) edges: EdgeList,
    pub(super) new_coins: List<CoinId, MAX_EDGE_OUTPUTS>,
    pub(super) new_edges: EdgeList,
}

impl Access {
    /// Returns consumed coin ids.
    #[must_use]
    pub const fn coins(&self) -> &List<CoinId, MAX_EDGE_INPUTS> {
        &self.coins
    }

    /// Returns consumed edge ids.
    #[must_use]
    pub const fn edges(&self) -> &EdgeList {
        &self.edges
    }

    /// Returns created coin ids.
    #[must_use]
    pub const fn new_coins(&self) -> &List<CoinId, MAX_EDGE_OUTPUTS> {
        &self.new_coins
    }

    /// Returns created edge ids.
    #[must_use]
    pub const fn new_edges(&self) -> &EdgeList {
        &self.new_edges
    }

    /// Returns true if two declared access sets touch any common state slot.
    #[must_use]
    pub fn conflicts(&self, other: &Self) -> bool {
        self.coin_conflicts(other) || self.edge_conflicts(other)
    }

    fn coin_conflicts(&self, other: &Self) -> bool {
        overlaps(self.coins(), other.coins())
            || overlaps(self.coins(), other.new_coins())
            || overlaps(self.new_coins(), other.coins())
            || overlaps(self.new_coins(), other.new_coins())
    }

    fn edge_conflicts(&self, other: &Self) -> bool {
        overlaps(self.edges(), other.edges())
            || overlaps(self.edges(), other.new_edges())
            || overlaps(self.new_edges(), other.edges())
            || overlaps(self.new_edges(), other.new_edges())
    }
}
