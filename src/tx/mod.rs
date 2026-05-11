//! Transaction vocabulary, events, and the validate-then-fold transition machinery.
//!
//! Abstract counterpart: the actions in `models/l1.qnt` (`openEdge`,
//! `closeEdge`, `tick`, `idle`) and the `step` relation that dispatches
//! over them. Each concrete [`Tx`] variant lines up with one Quint action;
//! `apply` here implements the same validate-then-fold discipline the model
//! captures by primed-variable assignments inside an `action` block.

mod funding;
mod payout;
mod proof;

pub use self::{
    funding::Funding,
    payout::Payout,
    proof::{CloseKind, Proof, Seal},
};

use crate::{
    canonical::Encode,
    consts::{MAX_EDGE_INPUTS, MAX_EDGE_OUTPUTS, MAX_PARTY_INPUTS},
    context::{Context, Cost},
    error::{ApplyError, InvalidCloseReason, InvalidOpenReason, InvalidProofReason, KernelResult},
    event::Change,
    list::List,
    object::{Coin, Edge},
    primitive::{CloseHash, CoinId, EdgeId, TermsHash},
    store::Batch,
    terms::Terms,
    verifier::{SealPublicInputs, SealVerifier, SigVerifier},
};

type PartyCoins = List<CoinId, MAX_PARTY_INPUTS>;
type OpenCoins = List<(CoinId, Coin), MAX_EDGE_INPUTS>;
type Payouts = List<Payout, MAX_EDGE_OUTPUTS>;
type CloseCoins = List<(CoinId, Coin), MAX_EDGE_OUTPUTS>;

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

    /// Close one edge into bounded owner-only coin payouts.
    Close {
        /// Edge consumed by the close.
        input: EdgeId,
        /// Close proof witness.
        proof: Proof,
        /// Coin payouts produced by the close.
        outputs: Payouts,
    },
}

impl Tx {
    /// Creates an open transaction from concrete terms.
    #[must_use]
    pub const fn open(funding: Funding, terms: Terms) -> Self {
        Self::Open { funding, terms }
    }

    /// Creates a close transaction.
    #[must_use]
    pub const fn close(input: EdgeId, proof: Proof, outputs: Payouts) -> Self {
        Self::Close {
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

    /// Returns the canonical ids of the payout coins a close would produce.
    #[must_use]
    pub fn close_output_ids(
        edge: EdgeId,
        outputs: &List<Payout, MAX_EDGE_OUTPUTS>,
    ) -> List<CoinId, MAX_EDGE_OUTPUTS> {
        let mut ids = [CoinId::ZERO; MAX_EDGE_OUTPUTS];

        for (index, payout) in outputs.iter().enumerate() {
            ids[index] = payout.id(edge, index);
        }

        List::take(ids, outputs.len())
    }

    /// Returns the commitment signed or proven by a close witness.
    #[must_use]
    pub fn payload_hash(
        input: EdgeId,
        kind: CloseKind,
        terms: TermsHash,
        outputs: &List<Payout, MAX_EDGE_OUTPUTS>,
    ) -> CloseHash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(crate::consts::CLOSE);
        input.encode_to(&mut hasher);
        kind.tag().encode_to(&mut hasher);
        terms.encode_to(&mut hasher);
        outputs.encode_to(&mut hasher);
        CloseHash::from_bytes(*hasher.finalize().as_bytes())
    }

    /// Returns the deterministic resource cost of this transaction.
    #[must_use]
    pub fn cost(&self) -> Cost {
        match self {
            Self::Open { funding, .. } => open_cost(funding),
            Self::Close { proof, outputs, .. } => close_cost(outputs.len(), proof.kind()),
        }
    }

    pub(crate) fn apply<B, V>(
        &self,
        context: Context,
        verifier: &V,
        batch: &B,
    ) -> KernelResult<Change>
    where
        B: Batch,
        V: SigVerifier + SealVerifier + ?Sized,
    {
        match self {
            Self::Open { funding, terms } => apply_open(funding, terms, context, batch),
            Self::Close {
                input,
                proof,
                outputs,
            } => apply_close(*input, proof, outputs, context, verifier, batch),
        }
    }
}

fn open_cost(funding: &Funding) -> Cost {
    let inputs = units(funding.len());
    Cost::new(1, inputs.saturating_add(1), 0)
}

fn open_reserve_cost() -> Cost {
    // Reserve covers the worst-case close: the close kind with the most
    // proof units, applied at the maximum payout fanout.
    close_cost(MAX_EDGE_OUTPUTS, CloseKind::Mutual)
}

/// One slot per payout output plus one for the consumed edge.
fn close_cost(outputs: usize, kind: CloseKind) -> Cost {
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

fn apply_close<B, V>(
    input: EdgeId,
    proof: &Proof,
    outputs: &Payouts,
    context: Context,
    verifier: &V,
    batch: &B,
) -> KernelResult<Change>
where
    B: Batch,
    V: SigVerifier + SealVerifier + ?Sized,
{
    check_close_outputs(input, outputs, batch)?;

    let coins = close_coins(input, outputs);
    let edge = batch
        .edge(input)
        .ok_or(ApplyError::MissingEdge { id: input })?;
    check_proof(input, &edge, outputs, proof, context, verifier)
        .map_err(|reason| ApplyError::InvalidProof { input, reason })?;
    let fee = context
        .fee(close_cost(outputs.len(), proof.kind()))
        .ok_or_else(|| invalid_close(input, InvalidCloseReason::FeeOverflow))?;
    edge.closes(&coins, fee)
        .map_err(|reason| invalid_close(input, reason))?;

    Ok(Change::close((input, edge), &coins))
}

/// Dispatches close-proof admissibility per variant. Mutual routes to
/// the signature verifier, Violation routes to the seal verifier, and
/// Timeout is structural — the kernel checks terms-hash binding, height,
/// and payout shape inline because none of those need cryptography.
fn check_proof<V>(
    input: EdgeId,
    edge: &Edge,
    outputs: &Payouts,
    proof: &Proof,
    context: Context,
    verifier: &V,
) -> Result<(), InvalidProofReason>
where
    V: SigVerifier + SealVerifier + ?Sized,
{
    match proof {
        Proof::Mutual { maker, taker } => {
            let hash = Tx::payload_hash(input, CloseKind::Mutual, edge.terms(), outputs);
            let parties = edge.parties();
            if verifier.verify_sig(*maker, parties.maker(), hash)
                && verifier.verify_sig(*taker, parties.taker(), hash)
            {
                Ok(())
            } else {
                Err(InvalidProofReason::BadSignature)
            }
        }
        Proof::Timeout { terms } => {
            if terms.hash() != edge.terms() {
                return Err(InvalidProofReason::TermsMismatch);
            }
            if context.block_height() < terms.timeout() {
                return Err(InvalidProofReason::TimeoutNotReached);
            }
            if outputs != terms.timeout_outputs() {
                return Err(InvalidProofReason::PayoutMismatch);
            }
            Ok(())
        }
        Proof::Violation { terms, seal } => {
            if terms.hash() != edge.terms() {
                return Err(InvalidProofReason::TermsMismatch);
            }
            let public = SealPublicInputs {
                edge_id: input,
                protocol: terms.protocol(),
                terms_hash: terms.hash(),
                payouts: outputs,
            };
            if verifier.verify_seal(*seal, &public) {
                Ok(())
            } else {
                Err(InvalidProofReason::BadSeal)
            }
        }
    }
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

fn check_close_outputs<B: Batch>(
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

fn close_coins(input: EdgeId, outputs: &Payouts) -> CloseCoins {
    let mut coins = [(CoinId::ZERO, Coin::ZERO); MAX_EDGE_OUTPUTS];
    for (index, output) in outputs.iter().enumerate() {
        coins[index] = output.coin(input, index);
    }
    List::take(coins, outputs.len())
}

fn edge_id(funding: &Funding, terms_hash: TermsHash) -> EdgeId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(crate::consts::EDGE_OPEN);
    terms_hash.encode_to(&mut hasher);
    funding.maker().encode_to(&mut hasher);
    funding.taker().encode_to(&mut hasher);
    EdgeId::from_bytes(*hasher.finalize().as_bytes())
}

const fn invalid_open(output: EdgeId, reason: InvalidOpenReason) -> ApplyError {
    ApplyError::InvalidOpen { output, reason }
}

const fn invalid_close(input: EdgeId, reason: InvalidCloseReason) -> ApplyError {
    ApplyError::InvalidClose { input, reason }
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
