//! Operation vocabulary, events, and the validate-then-fold transition machinery.
//!
//! Abstract counterpart: the actions in `models/l1.qnt` (`openEdge`,
//! `resolveEdge`, `tick`, `idle`) and the `step` relation that dispatches
//! over them. Each concrete [`Op`] variant lines up with one Quint action;
//! `apply` here implements the same validate-then-fold discipline the model
//! captures by primed-variable assignments inside an `action` block.

mod open;
mod proof;
mod resolve;

pub use self::{
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
    primitive::CoinId,
    store::Tx,
    verifier::Verifier,
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

/// A protocol operation submitted to the Hellas kernel.
#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub enum Op {
    /// Open one edge by locking bounded bilateral funding.
    Open(Open),

    /// Resolve one edge into bounded owner-only coin payouts.
    Resolve(Resolve),
}

impl Op {
    pub(crate) fn apply<T: Tx, V: Verifier + ?Sized>(
        &self,
        context: Context,
        verifier: &V,
        tx: &T,
    ) -> KernelResult<Change> {
        match self {
            Self::Open(op) => op.apply(context, tx),
            Self::Resolve(op) => op.apply(context, verifier, tx),
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
}

fn units(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn duplicate<T: Copy + Eq>(items: &[T]) -> Option<T> {
    items
        .iter()
        .enumerate()
        .find_map(|(i, item)| items[i + 1..].contains(item).then_some(*item))
}
