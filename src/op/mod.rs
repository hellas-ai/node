//! Operation vocabulary, events, and the validate-then-fold transition machinery.

mod access;
mod open;
mod proof;
mod resolve;

pub use self::{
    access::Access,
    open::{Funding, Open},
    proof::{Agreement, Proof, ResolveKind, Seal},
    resolve::{Payout, Resolve},
};

use crate::{
    context::{Context, Cost},
    error::KernelResult,
    event::Change,
    list::List,
    object::Coin,
    primitive::{CoinId, EdgeId},
    store::Tx,
};

const SEAL_LENGTH: usize = 32;

/// Maximum coins that can fund one party in a v1 edge open.
///
/// Four inputs per party covers the expected one-or-two-coin channel open while
/// keeping validation fully bounded. Raising this changes operation shape,
/// resource costs, and model bounds, so it is a chain-version change.
pub const MAX_PARTY_INPUTS: usize = 4;

/// Maximum coins that can fund one v1 edge open.
pub const MAX_EDGE_INPUTS: usize = MAX_PARTY_INPUTS * 2;

/// Maximum coins that can be produced by one v1 edge resolve.
///
/// Four outputs leaves room for maker, taker, and small protocol-defined splits
/// without making every resolve pay for an unbounded payout fanout. Raising this
/// is also a chain-version change.
pub const MAX_EDGE_OUTPUTS: usize = 4;

type PartyCoins = List<CoinId, MAX_PARTY_INPUTS>;
type OpenCoins = List<(CoinId, Coin), MAX_EDGE_INPUTS>;
type Payouts = List<Payout, MAX_EDGE_OUTPUTS>;
type ResolveCoins = List<(CoinId, Coin), MAX_EDGE_OUTPUTS>;
type EdgeList = List<EdgeId, 1>;

/// A protocol operation submitted to the Hellas kernel.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum Op {
    /// Open one edge by locking bounded bilateral funding.
    Open(Open),

    /// Resolve one edge into bounded owner-only coin payouts.
    Resolve(Resolve),
}

impl Op {
    pub(crate) fn apply<T: Tx>(&self, context: Context, tx: &T) -> KernelResult<Change> {
        match self {
            Self::Open(op) => op.apply(context, tx),
            Self::Resolve(op) => op.apply(context, tx),
        }
    }

    /// Returns the deterministic resource cost of this operation.
    #[must_use]
    pub fn cost(&self) -> Cost {
        match self {
            Self::Open(op) => op.cost(),
            Self::Resolve(op) => op.cost(),
        }
    }

    /// Returns the deterministic state access set of this operation.
    #[must_use]
    pub fn access(&self) -> Access {
        match self {
            Self::Open(op) => op.access(),
            Self::Resolve(op) => op.access(),
        }
    }

    /// Returns true if this operation touches any state slot also touched by
    /// `other`.
    #[must_use]
    pub fn conflicts(&self, other: &Self) -> bool {
        self.access().conflicts(&other.access())
    }
}

fn units(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn duplicate<T: Copy + Eq>(items: &[T]) -> Option<T> {
    let mut outer = 0;
    while outer < items.len() {
        let mut inner = outer + 1;
        while inner < items.len() {
            if items[outer] == items[inner] {
                return Some(items[outer]);
            }
            inner += 1;
        }
        outer += 1;
    }

    None
}

fn overlaps<T: Eq, const A: usize, const B: usize>(left: &List<T, A>, right: &List<T, B>) -> bool {
    for item in left.as_slice() {
        for other in right.as_slice() {
            if item == other {
                return true;
            }
        }
    }

    false
}

const fn empty_coins<const N: usize>() -> List<CoinId, N> {
    List::empty(CoinId::ZERO)
}

const fn empty_edges() -> EdgeList {
    List::empty(EdgeId::ZERO)
}

const fn one_edge(id: EdgeId) -> EdgeList {
    List::all([id])
}
