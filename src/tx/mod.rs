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
    primitive::{CloseHash, CoinId, EdgeId, Sig, TermsHash},
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
    /// Open one edge by locking bounded bilateral funding under both
    /// parties' authorization.
    Open {
        /// Bilateral funding consumed by the open. Each list's coins
        /// must be owned by the matching party's settlement key from
        /// `terms.parties()`.
        funding: Funding,
        /// Concrete terms committing the produced edge.
        terms: Terms,
        /// Maker's signature over [`Tx::open_hash`]. Required even when
        /// the maker funding list is empty — opening an edge that names
        /// the maker as a party requires the maker's consent.
        maker_sig: Sig,
        /// Taker's signature over [`Tx::open_hash`]. Same authorization
        /// rule as `maker_sig`.
        taker_sig: Sig,
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
    pub const fn open(funding: Funding, terms: Terms, maker_sig: Sig, taker_sig: Sig) -> Self {
        Self::Open {
            funding,
            terms,
            maker_sig,
            taker_sig,
        }
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

    /// Returns the canonical hash both parties must sign to authorize an
    /// open of the edge that `funding` + `terms` would produce.
    ///
    /// Bound to the canonical [`EdgeId`] derived from the open inputs
    /// under a distinct domain separator, so an open signature can never
    /// be replayed as anything else (a close signature, a different
    /// edge's open, etc.).
    #[must_use]
    pub fn open_hash(funding: &Funding, terms: &Terms) -> CloseHash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(crate::consts::OPEN);
        Self::edge_id_of(funding, terms).encode_to(&mut hasher);
        CloseHash::from_bytes(*hasher.finalize().as_bytes())
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
            Self::Open {
                funding,
                terms,
                maker_sig,
                taker_sig,
            } => apply_open(
                funding, terms, *maker_sig, *taker_sig, context, verifier, batch,
            ),
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

fn apply_open<B, V>(
    funding: &Funding,
    terms: &Terms,
    maker_sig: Sig,
    taker_sig: Sig,
    context: Context,
    verifier: &V,
    batch: &B,
) -> KernelResult<Change>
where
    B: Batch,
    V: SigVerifier + ?Sized,
{
    let output = edge_id(funding, terms.hash());

    if let Some(id) = duplicate(open_inputs(funding).as_slice()) {
        return Err(ApplyError::DuplicateInput { id });
    }
    if batch.edge(output).is_some() {
        return Err(ApplyError::EdgeExists { id: output });
    }

    let coins = open_coins(funding, batch)?;
    let parties = terms.parties();
    // Run every cheap structural / arithmetic check before the
    // signature verifier. The verifier is the most expensive piece of
    // the open path (BLAKE3 + two SigVerifier calls, potentially real
    // ECDSA); under DoS pressure we don't want a tx that fails
    // cheaply on owner-match or insufficient funding to also pay for
    // crypto.
    check_funding_ownership(output, &coins, funding.maker_len(), parties)?;
    let open_fee = context
        .fee(open_cost(funding))
        .ok_or_else(|| invalid_open(output, InvalidOpenReason::FeeOverflow))?;
    let reserve = context
        .fee(open_reserve_cost())
        .ok_or_else(|| invalid_open(output, InvalidOpenReason::ReserveOverflow))?;
    let edge = Edge::open(&coins, parties, terms.hash(), open_fee, reserve)
        .map_err(|reason| invalid_open(output, reason))?;
    check_open_signatures(
        output, funding, terms, parties, maker_sig, taker_sig, verifier,
    )?;
    Ok(Change::open(&coins, (output, edge)))
}

/// Every coin in `funding.maker` must be owned by `parties.maker()`;
/// same for the taker. The kernel reads each coin's `owner()` from the
/// staged batch and compares against the matching party's key — the
/// authentication check that complements the open signatures.
fn check_funding_ownership(
    output: EdgeId,
    coins: &OpenCoins,
    maker_len: usize,
    parties: crate::object::Parties,
) -> KernelResult<()> {
    for (index, (_, coin)) in coins.as_slice().iter().enumerate() {
        let expected = if index < maker_len {
            parties.maker()
        } else {
            parties.taker()
        };
        if coin.owner() != expected {
            return Err(invalid_open(output, InvalidOpenReason::FundingUnauthorized));
        }
    }
    Ok(())
}

fn check_open_signatures<V: SigVerifier + ?Sized>(
    output: EdgeId,
    funding: &Funding,
    terms: &Terms,
    parties: crate::object::Parties,
    maker_sig: Sig,
    taker_sig: Sig,
    verifier: &V,
) -> KernelResult<()> {
    let hash = Tx::open_hash(funding, terms);
    if !verifier.verify_sig(maker_sig, parties.maker(), hash)
        || !verifier.verify_sig(taker_sig, parties.taker(), hash)
    {
        return Err(invalid_open(output, InvalidOpenReason::BadSignature));
    }
    Ok(())
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
    // Cheap structural checks first: fee, reserve coverage, value
    // conservation. Verifier comes last because real `SealVerifier`
    // impls may resolve and check expensive ZK artifacts, and we don't
    // want to pay for that on closes that fail trivial checks.
    let fee = context
        .fee(close_cost(outputs.len(), proof.kind()))
        .ok_or_else(|| invalid_close(input, InvalidCloseReason::FeeOverflow))?;
    edge.closes(&coins, fee)
        .map_err(|reason| invalid_close(input, reason))?;
    check_proof(input, &edge, outputs, proof, context, verifier)
        .map_err(|reason| ApplyError::InvalidProof { input, reason })?;

    Ok(Change::close((input, edge), &coins))
}

// Timeout is checked structurally because none of its rules — terms-hash
// binding, height guard, payout shape — need cryptography.
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
            let terms_hash = terms.hash();
            if terms_hash != edge.terms() {
                return Err(InvalidProofReason::TermsMismatch);
            }
            let public = SealPublicInputs {
                edge_id: input,
                protocol: terms.protocol(),
                terms_hash,
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

fn check_close_outputs<B: Batch>(input: EdgeId, outputs: &Payouts, batch: &B) -> KernelResult<()> {
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
