//! Transaction vocabulary, events, and the validate-then-fold transition machinery.
//!
//! Abstract counterpart: the actions in `models/l1.qnt` (`openEdge`,
//! `resolveEdge`, `tick`, `idle`) and the `step` relation that dispatches
//! over them. Each concrete [`Tx`] variant lines up with one Quint action;
//! `apply` here implements the same validate-then-fold discipline the model
//! captures by primed-variable assignments inside an `action` block.

mod funding;
mod payout;
mod proof;

pub use self::{
    funding::Funding,
    payout::Payout,
    proof::{Agreement, Proof, ResolveKind, Seal},
};

use crate::{
    canonical::Encode,
    context::{Context, Cost},
    error::{ApplyError, InvalidOpenReason, InvalidResolveReason, KernelResult},
    event::Change,
    list::List,
    object::{Coin, Edge},
    primitive::{CoinId, EdgeId, ResolveHash, TermsHash},
    store::Batch,
    terms::Terms,
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

/// A protocol transaction submitted to the Hellas kernel.
#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub enum Tx {
    /// Open one edge by locking bounded bilateral funding.
    Open {
        /// Bilateral funding consumed by the open.
        funding: Funding,
        /// Concrete terms committing the produced edge.
        terms: Terms,
    },

    /// Resolve one edge into bounded owner-only coin payouts.
    Resolve {
        /// Edge consumed by the resolve.
        input: EdgeId,
        /// Resolve proof witness.
        proof: Proof,
        /// Coin payouts produced by the resolve.
        outputs: Payouts,
    },
}

impl Tx {
    /// Creates an open transaction from concrete terms.
    #[must_use]
    pub const fn open(funding: Funding, terms: Terms) -> Self {
        Self::Open { funding, terms }
    }

    /// Creates a resolve transaction.
    #[must_use]
    pub const fn resolve(input: EdgeId, proof: Proof, outputs: Payouts) -> Self {
        Self::Resolve {
            input,
            proof,
            outputs,
        }
    }

    /// Predicts the edge id that [`Tx::open`] would produce for `funding` and
    /// `terms`.
    ///
    /// Useful when callers need to know the id before constructing or
    /// applying the transaction.
    #[must_use]
    pub fn edge_id_of(funding: &Funding, terms: &Terms) -> EdgeId {
        edge_id(funding, terms.hash())
    }

    /// Returns the canonical ids of the payout coins a resolve would produce.
    #[must_use]
    pub fn resolve_output_ids(
        edge: EdgeId,
        outputs: &List<Payout, MAX_EDGE_OUTPUTS>,
    ) -> List<CoinId, MAX_EDGE_OUTPUTS> {
        let mut ids = [CoinId::ZERO; MAX_EDGE_OUTPUTS];

        for (index, payout) in outputs.iter().enumerate() {
            ids[index] = payout.id(edge, index);
        }

        List::take(ids, outputs.len())
    }

    /// Returns the commitment signed or proven by a resolve witness.
    #[must_use]
    pub fn payload_hash(
        input: EdgeId,
        kind: ResolveKind,
        terms: TermsHash,
        outputs: &List<Payout, MAX_EDGE_OUTPUTS>,
    ) -> ResolveHash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(crate::domain::RESOLVE);
        input.encode_to(&mut hasher);
        kind.tag().encode_to(&mut hasher);
        terms.encode_to(&mut hasher);
        outputs.encode_to(&mut hasher);
        ResolveHash::from_bytes(*hasher.finalize().as_bytes())
    }

    /// Returns the deterministic resource cost of this transaction.
    #[must_use]
    pub fn cost(&self) -> Cost {
        match self {
            Self::Open { funding, .. } => open_cost(funding),
            Self::Resolve { proof, outputs, .. } => resolve_cost(outputs.len(), proof.kind()),
        }
    }

    pub(crate) fn apply<B: Batch, V: Verifier + ?Sized>(
        &self,
        context: Context,
        verifier: &V,
        batch: &B,
    ) -> KernelResult<Change> {
        match self {
            Self::Open { funding, terms } => apply_open(funding, terms, context, batch),
            Self::Resolve {
                input,
                proof,
                outputs,
            } => apply_resolve(*input, proof, outputs, context, verifier, batch),
        }
    }
}

fn open_cost(funding: &Funding) -> Cost {
    let inputs = units(funding.len());
    Cost::new(1, inputs.saturating_add(1), 0)
}

fn open_reserve_cost() -> Cost {
    resolve_cost(MAX_EDGE_OUTPUTS, ResolveKind::ClaimantWins)
}

/// One slot per payout output plus one for the consumed edge.
fn resolve_cost(outputs: usize, kind: ResolveKind) -> Cost {
    let outputs = units(outputs);
    Cost::new(1, outputs.saturating_add(1), kind.proofs())
}

fn apply_open<B: Batch>(
    funding: &Funding,
    terms: &Terms,
    context: Context,
    batch: &B,
) -> KernelResult<Change> {
    let output = edge_id(funding, terms.hash());

    if let Some(id) = duplicate(open_inputs(funding).as_slice()) {
        return Err(ApplyError::DuplicateInput { id });
    }
    if batch.edge(output).is_some() {
        return Err(ApplyError::EdgeExists { id: output });
    }

    let coins = open_coins(funding, batch)?;
    let open_fee = context
        .fee(open_cost(funding))
        .ok_or_else(|| invalid_open(output, InvalidOpenReason::FeeOverflow))?;
    let reserve = context
        .fee(open_reserve_cost())
        .ok_or_else(|| invalid_open(output, InvalidOpenReason::ReserveOverflow))?;
    let edge = Edge::open(&coins, terms.parties(), terms.hash(), open_fee, reserve)
        .map_err(|reason| invalid_open(output, reason))?;
    Ok(Change::open(&coins, (output, edge)))
}

fn apply_resolve<B: Batch, V: Verifier + ?Sized>(
    input: EdgeId,
    proof: &Proof,
    outputs: &Payouts,
    context: Context,
    verifier: &V,
    batch: &B,
) -> KernelResult<Change> {
    check_resolve_outputs(input, outputs, batch)?;

    let coins = resolve_coins(input, outputs);
    let edge = batch
        .edge(input)
        .ok_or(ApplyError::MissingEdge { id: input })?;
    proof
        .accepts(context, verifier, input, outputs, edge)
        .map_err(|reason| ApplyError::InvalidProof { input, reason })?;
    let fee = context
        .fee(resolve_cost(outputs.len(), proof.kind()))
        .ok_or_else(|| invalid_resolve(input, InvalidResolveReason::FeeOverflow))?;
    edge.resolves(&coins, fee)
        .map_err(|reason| invalid_resolve(input, reason))?;

    Ok(Change::resolve((input, edge), &coins))
}

fn open_inputs(funding: &Funding) -> List<CoinId, MAX_EDGE_INPUTS> {
    let fill = funding.first().unwrap_or(CoinId::ZERO);
    let mut ids = [fill; MAX_EDGE_INPUTS];

    for (index, id) in funding.iter().enumerate() {
        ids[index] = id;
    }

    List::take(ids, funding.len())
}

fn open_coins<B: Batch>(funding: &Funding, batch: &B) -> KernelResult<OpenCoins> {
    let mut coins = [(CoinId::ZERO, Coin::ZERO); MAX_EDGE_INPUTS];
    for (index, id) in funding.iter().enumerate() {
        let coin = batch.coin(id).ok_or(ApplyError::MissingCoin { id })?;
        coins[index] = (id, coin);
    }
    Ok(List::take(coins, funding.len()))
}

fn check_resolve_outputs<B: Batch>(
    input: EdgeId,
    outputs: &Payouts,
    batch: &B,
) -> KernelResult<()> {
    for (index, output) in outputs.iter().enumerate() {
        let id = output.id(input, index);
        if batch.coin(id).is_some() {
            return Err(ApplyError::OutputExists { id });
        }
    }
    Ok(())
}

fn resolve_coins(input: EdgeId, outputs: &Payouts) -> ResolveCoins {
    let mut coins = [(CoinId::ZERO, Coin::ZERO); MAX_EDGE_OUTPUTS];
    for (index, output) in outputs.iter().enumerate() {
        coins[index] = output.coin(input, index);
    }
    List::take(coins, outputs.len())
}

fn edge_id(funding: &Funding, terms_hash: TermsHash) -> EdgeId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(crate::domain::EDGE_OPEN);
    terms_hash.encode_to(&mut hasher);
    funding.maker().encode_to(&mut hasher);
    funding.taker().encode_to(&mut hasher);
    EdgeId::from_bytes(*hasher.finalize().as_bytes())
}

const fn invalid_open(output: EdgeId, reason: InvalidOpenReason) -> ApplyError {
    ApplyError::InvalidOpen { output, reason }
}

const fn invalid_resolve(input: EdgeId, reason: InvalidResolveReason) -> ApplyError {
    ApplyError::InvalidResolve { input, reason }
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
