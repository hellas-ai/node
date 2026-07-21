//! Transaction vocabulary, events, and the validate-then-fold transition machinery.
//!
//! Abstract counterpart: the actions in `models/l1.qnt` (`openEdge`,
//! `closeEdge`, `tick`, `idle`) and the `step` relation that dispatches
//! over them. Each concrete [`Tx`] variant lines up with one Quint action;
//! `apply` here implements the same validate-then-fold discipline the model
//! captures by primed-variable assignments inside an `action` block.

mod auth;
mod funding;
mod payout;
mod proof;

use hellas_xet::SingleChunkHasher;

pub use self::{
    auth::{Auth, WebAuthnAssertion, WebAuthnData},
    funding::Funding,
    payout::Payout,
    proof::{CloseKind, CloseKindSet, Proof, Seal},
};

use crate::{
    canonical::{
        Decode, DecodeError, ENVELOPE_SIZE, Encode, Writer, decode_envelope, decode_field,
        encode_envelope, tag,
    },
    consts::{MAX_EDGE_INPUTS, MAX_EDGE_OUTPUTS, MAX_PARTY_INPUTS},
    context::{Context, Cost},
    error::{ApplyError, InvalidCloseReason, InvalidOpenReason, InvalidProofReason, KernelResult},
    event::Change,
    list::List,
    object::{Coin, Edge},
    primitive::{CoinId, EdgeId, PayloadHash, TermsHash},
    store::Batch,
    terms::Terms,
    verifier::{SealPublicInputs, SealVerifier, SigVerifier},
};

const OPEN_TAG: u8 = 0;
const CLOSE_TAG: u8 = 1;

type PartyCoins = List<CoinId, MAX_PARTY_INPUTS>;
type OpenCoins = List<(CoinId, Coin), MAX_EDGE_INPUTS>;
type Payouts = List<Payout, MAX_EDGE_OUTPUTS>;
type CloseCoins = List<(CoinId, Coin), MAX_EDGE_OUTPUTS>;

/// A protocol transaction submitted to the Hellas kernel.
#[allow(
    clippy::large_enum_variant,
    reason = "Opens and mutual closes may carry two inline WebAuthn assertions in this no-alloc kernel"
)]
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
        /// Maker's authorization over [`Tx::open_hash`]. Required even when
        /// the maker funding list is empty — opening an edge that names
        /// the maker as a party requires the maker's consent.
        maker_auth: Auth,
        /// Taker's authorization over [`Tx::open_hash`]. Same
        /// authorization rule as `maker_auth`.
        taker_auth: Auth,
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
    /// Creates an open transaction from concrete terms and party-key
    /// authorization witnesses.
    ///
    /// `maker_auth` and `taker_auth` are checked against the maker/taker keys
    /// committed by `terms.parties()`, even when that party contributes no
    /// funding input.
    #[must_use]
    pub const fn open(funding: Funding, terms: Terms, maker_auth: Auth, taker_auth: Auth) -> Self {
        Self::Open {
            funding,
            terms,
            maker_auth,
            taker_auth,
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

    /// Creates the unilateral timeout close of `edge` under `terms`:
    /// a `Timeout` proof paying the terms' own committed
    /// `timeout_outputs`.
    ///
    /// The only close whose payload is fixed at open, so it is the one
    /// close that needs no negotiation and no signature — either party
    /// may submit it once the committed height has passed.
    #[must_use]
    pub fn timeout_close(edge: EdgeId, terms: &Terms) -> Self {
        Self::close(
            edge,
            Proof::timeout(terms.clone()),
            terms.timeout_outputs().clone(),
        )
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
    pub fn open_hash(funding: &Funding, terms: &Terms) -> PayloadHash {
        let mut hasher = SingleChunkHasher::new();
        hasher.update(crate::consts::OPEN);
        Self::edge_id_of(funding, terms).encode_to(&mut hasher);
        PayloadHash::from_bytes(hasher.finalize().into_bytes())
    }

    /// Returns the canonical ids of the payout coins a close would produce.
    #[must_use]
    pub fn close_output_ids(
        edge: EdgeId,
        outputs: &List<Payout, MAX_EDGE_OUTPUTS>,
    ) -> List<CoinId, MAX_EDGE_OUTPUTS> {
        let mut ids = [CoinId::ZERO; MAX_EDGE_OUTPUTS];

        for (index, (slot, payout)) in ids.iter_mut().zip(outputs).enumerate() {
            *slot = payout.id(edge, index);
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
    ) -> PayloadHash {
        let mut hasher = SingleChunkHasher::new();
        hasher.update(crate::consts::CLOSE);
        input.encode_to(&mut hasher);
        kind.tag().encode_to(&mut hasher);
        terms.encode_to(&mut hasher);
        outputs.encode_to(&mut hasher);
        PayloadHash::from_bytes(hasher.finalize().into_bytes())
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
                maker_auth,
                taker_auth,
            } => apply_open(
                funding, terms, maker_auth, taker_auth, context, verifier, batch,
            ),
            Self::Close {
                input,
                proof,
                outputs,
            } => apply_close(*input, proof, outputs, context, verifier, batch),
        }
    }
}

impl Encode for Tx {
    const MAX_ENCODED_SIZE: usize = {
        let open = Funding::MAX_ENCODED_SIZE + Terms::MAX_ENCODED_SIZE + 2 * Auth::MAX_ENCODED_SIZE;
        let close = EdgeId::MAX_ENCODED_SIZE + Proof::MAX_ENCODED_SIZE + Payouts::MAX_ENCODED_SIZE;
        let max_body = if open > close { open } else { close };
        ENVELOPE_SIZE + u8::MAX_ENCODED_SIZE + max_body
    };

    fn encoded_size(&self) -> usize {
        ENVELOPE_SIZE
            + u8::MAX_ENCODED_SIZE
            + match self {
                Self::Open {
                    funding,
                    terms,
                    maker_auth,
                    taker_auth,
                } => {
                    funding.encoded_size()
                        + terms.encoded_size()
                        + maker_auth.encoded_size()
                        + taker_auth.encoded_size()
                }
                Self::Close {
                    input,
                    proof,
                    outputs,
                } => input.encoded_size() + proof.encoded_size() + outputs.encoded_size(),
            }
    }

    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        encode_envelope(writer, tag::TX);
        match self {
            Self::Open {
                funding,
                terms,
                maker_auth,
                taker_auth,
            } => {
                OPEN_TAG.encode_to(writer);
                funding.encode_to(writer);
                terms.encode_to(writer);
                maker_auth.encode_to(writer);
                taker_auth.encode_to(writer);
            }
            Self::Close {
                input,
                proof,
                outputs,
            } => {
                CLOSE_TAG.encode_to(writer);
                input.encode_to(writer);
                proof.encode_to(writer);
                outputs.encode_to(writer);
            }
        }
    }
}

impl Decode for Tx {
    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        let mut consumed = decode_envelope(buf, tag::TX)?;
        let variant = decode_field::<u8>(buf, &mut consumed)?;
        match variant {
            OPEN_TAG => {
                let funding = decode_field(buf, &mut consumed)?;
                let terms = decode_field(buf, &mut consumed)?;
                let maker_auth = decode_field(buf, &mut consumed)?;
                let taker_auth = decode_field(buf, &mut consumed)?;
                Ok((Self::open(funding, terms, maker_auth, taker_auth), consumed))
            }
            CLOSE_TAG => {
                let input = decode_field(buf, &mut consumed)?;
                let proof = decode_field(buf, &mut consumed)?;
                let outputs = decode_field(buf, &mut consumed)?;
                Ok((Self::close(input, proof, outputs), consumed))
            }
            tag => Err(DecodeError::InvalidTag { tag }),
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
    maker_auth: &Auth,
    taker_auth: &Auth,
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
    // the open path (Xet hash + two SigVerifier calls, potentially real
    // ECDSA); under DoS pressure we don't want a tx that fails
    // cheaply on owner-match or insufficient funding to also pay for
    // crypto.
    check_funding_ownership(output, &coins, funding.maker_len(), parties)?;
    let open_fee = context
        .fee(open_cost(funding))
        .ok_or_else(|| invalid_open(output, InvalidOpenReason::FeeOverflow))?;
    let lifetime_fee =
        open_lifetime_fee(context, terms).map_err(|reason| invalid_open(output, reason))?;
    let reserve = context
        .fee(open_reserve_cost())
        .ok_or_else(|| invalid_open(output, InvalidOpenReason::ReserveOverflow))?;
    let edge = Edge::open(
        &coins,
        parties,
        terms.hash(),
        (open_fee, lifetime_fee, reserve, context.fees()),
        terms.timeout(),
        terms.allowed_closes(),
    )
    .map_err(|reason| invalid_open(output, reason))?;
    check_open_terms(output, &edge, terms)?;
    check_stake_bond_open(output, &edge, terms)?;
    check_open_auth(
        output, funding, terms, parties, maker_auth, taker_auth, verifier,
    )?;
    Ok(Change::open(&coins, (output, edge)))
}

/// Stake-bond opens additionally commit the slash arithmetic. The stake
/// must be the value this open actually locks, and the award must be
/// positive, within the stake, and at least `max_job_price +
/// max_dispute_cost` — otherwise a later slash could not reimburse the
/// client for the worst job this bond admits.
fn check_stake_bond_open(output: EdgeId, edge: &Edge, terms: &Terms) -> KernelResult<()> {
    let Some(bond) = terms.as_stake_bond() else {
        return Ok(());
    };
    if bond.stake != edge.value() {
        return Err(invalid_open(output, InvalidOpenReason::StakeMismatch));
    }
    if bond.award == 0 || bond.award > bond.stake {
        return Err(invalid_open(output, InvalidOpenReason::AwardOutOfRange));
    }
    // A party-controlled treasury would collapse the slash penalty from
    // S to A: the provider would recover S − A through its own key.
    if bond.treasury == bond.parties.maker() || bond.treasury == bond.parties.taker() {
        return Err(invalid_open(output, InvalidOpenReason::TreasuryIsParty));
    }
    // A zero job-price cap covers no job (p_j ≥ 1) and would let the
    // award floor degenerate to A = max_dispute_cost, breaking the
    // strict dispute incentive A > C_disp.
    if bond.max_job_price == 0 {
        return Err(invalid_open(output, InvalidOpenReason::JobPriceCapZero));
    }
    // A zero challenge margin leaves no block between an honest job's
    // terminal deadline and the bond timeout for a challenge to land,
    // so no job could ever be covered (`covered_by` is unsatisfiable).
    if bond.challenge_margin == 0 {
        return Err(invalid_open(output, InvalidOpenReason::ChallengeMarginZero));
    }
    let floor = bond
        .max_job_price
        .checked_add(bond.max_dispute_cost)
        .ok_or_else(|| invalid_open(output, InvalidOpenReason::AwardFloorOverflow))?;
    if bond.award < floor {
        return Err(invalid_open(output, InvalidOpenReason::AwardBelowFloor));
    }
    Ok(())
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

/// Timeout-vs-height rejection happens earlier, in [`open_lifetime_fee`]:
/// a non-future timeout cannot price a lifetime fee. By the time this
/// runs, `terms.timeout() > context.block_height()` already holds.
fn check_open_terms(output: EdgeId, edge: &Edge, terms: &Terms) -> KernelResult<()> {
    let Some(timeout_value) = payout_total(terms.timeout_outputs()) else {
        return Err(invalid_open(output, InvalidOpenReason::TermsPayoutOverflow));
    };
    let timeout_cost = close_cost(terms.timeout_outputs().len(), CloseKind::Timeout);
    let Some(expected_timeout_value) = edge.close_value(timeout_cost) else {
        return Err(invalid_open(output, InvalidOpenReason::ReserveOverflow));
    };
    if timeout_value != expected_timeout_value {
        return Err(invalid_open(output, InvalidOpenReason::TermsValueMismatch));
    }
    Ok(())
}

fn open_lifetime_fee(context: Context, terms: &Terms) -> Result<u64, InvalidOpenReason> {
    let Some(blocks) = terms
        .timeout()
        .get()
        .checked_sub(context.block_height().get())
    else {
        return Err(InvalidOpenReason::TimeoutNotFuture);
    };
    if blocks == 0 {
        return Err(InvalidOpenReason::TimeoutNotFuture);
    }
    context
        .fees()
        .lifetime()
        .checked_mul(blocks)
        .ok_or(InvalidOpenReason::LifetimeFeeOverflow)
}

fn check_open_auth<V: SigVerifier + ?Sized>(
    output: EdgeId,
    funding: &Funding,
    terms: &Terms,
    parties: crate::object::Parties,
    maker_auth: &Auth,
    taker_auth: &Auth,
    verifier: &V,
) -> KernelResult<()> {
    let hash = Tx::open_hash(funding, terms);
    if !verifier.verify_auth(maker_auth, parties.maker(), hash)
        || !verifier.verify_auth(taker_auth, parties.taker(), hash)
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
    if !edge.allows(proof.kind()) {
        return Err(invalid_close(input, InvalidCloseReason::KindForbidden));
    }
    // Cheap structural checks first: output freshness and value conservation.
    // Close has no marginal monetary fee: the reserve was committed when the
    // edge opened, while `Tx::cost()` still counts close resources for block
    // admission. Verifier comes last because real `SealVerifier` impls may
    // resolve and check expensive ZK artifacts, and we don't want to pay for
    // that on closes that fail trivial checks.
    edge.closes(&coins, close_cost(outputs.len(), proof.kind()))
        .map_err(|reason| invalid_close(input, reason))?;
    check_proof(input, &edge, outputs, proof, context, verifier)
        .map_err(|reason| ApplyError::InvalidProof { input, reason })?;

    Ok(Change::close((input, edge), &coins))
}

fn payout_total<const N: usize>(outputs: &List<Payout, N>) -> Option<u64> {
    outputs.checked_sum(|output| output.value())
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
            if context.block_height() >= edge.timeout() {
                return Err(InvalidProofReason::ProofExpired);
            }
            let hash = Tx::payload_hash(input, CloseKind::Mutual, edge.terms(), outputs);
            let parties = edge.parties();
            if verifier.verify_auth(maker, parties.maker(), hash)
                && verifier.verify_auth(taker, parties.taker(), hash)
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
            if context.block_height() < edge.timeout() {
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
            if context.block_height() >= edge.timeout() {
                return Err(InvalidProofReason::ProofExpired);
            }
            check_violation_payouts(terms, outputs)?;
            let public = SealPublicInputs {
                edge_id: input,
                terms,
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

/// A stake-bond violation pays out exactly `[(client, award + surplus),
/// (treasury, stake − award)]`, where client = the bond's taker. The
/// routing is enforced here, structurally, from the terms revealed by
/// the proof — the seal verifier only decides whether the fraud
/// artifact is genuine, and can never redirect the payout. Output 0's
/// value follows from conservation (`Edge::closes` pins the total to
/// `stake + surplus`), so checking output 1's exact value pins both.
fn check_violation_payouts(terms: &Terms, outputs: &Payouts) -> Result<(), InvalidProofReason> {
    let Some(bond) = terms.as_stake_bond() else {
        return Ok(());
    };
    let [client, treasury] = outputs.as_slice() else {
        return Err(InvalidProofReason::PayoutMismatch);
    };
    // Open-time checks guarantee award ≤ stake; a violated subtraction
    // here means the terms did not pass this kernel's open path.
    let Some(remainder) = bond.stake.checked_sub(bond.award) else {
        return Err(InvalidProofReason::PayoutMismatch);
    };
    if client.owner() != bond.parties.taker()
        || treasury.owner() != bond.treasury
        || treasury.value() != remainder
    {
        return Err(InvalidProofReason::PayoutMismatch);
    }
    Ok(())
}

fn open_inputs(funding: &Funding) -> List<CoinId, MAX_EDGE_INPUTS> {
    let mut ids = [CoinId::ZERO; MAX_EDGE_INPUTS];

    for (slot, id) in ids.iter_mut().zip(funding.iter()) {
        *slot = id;
    }

    List::take(ids, funding.len())
}

fn open_coins<B: Batch>(funding: &Funding, batch: &B) -> KernelResult<OpenCoins> {
    let mut coins = [(CoinId::ZERO, Coin::ZERO); MAX_EDGE_INPUTS];
    for (slot, id) in coins.iter_mut().zip(funding.iter()) {
        let coin = batch.coin(id).ok_or(ApplyError::MissingCoin { id })?;
        *slot = (id, coin);
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
    for (index, (slot, output)) in coins.iter_mut().zip(outputs).enumerate() {
        *slot = output.coin(input, index);
    }
    List::take(coins, outputs.len())
}

fn edge_id(funding: &Funding, terms_hash: TermsHash) -> EdgeId {
    let mut hasher = SingleChunkHasher::new();
    hasher.update(crate::consts::EDGE_OPEN);
    terms_hash.encode_to(&mut hasher);
    funding.maker().encode_to(&mut hasher);
    funding.taker().encode_to(&mut hasher);
    EdgeId::from_bytes(hasher.finalize().into_bytes())
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
    let mut rest = items;
    while let Some((head, tail)) = rest.split_first() {
        if tail.contains(head) {
            return Some(*head);
        }
        rest = tail;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `open_reserve_cost` assumes `Mutual` at max fanout is the most
    /// expensive close. If a future `CloseKind` breaks that, already-open
    /// edges become uncloseable (`ReserveTooSmall`); fail here instead.
    #[test]
    fn reserve_covers_every_close_kind_at_every_fanout() {
        let reserve = open_reserve_cost();
        for kind in [CloseKind::Mutual, CloseKind::Timeout, CloseKind::Violation] {
            for outputs in 0..=MAX_EDGE_OUTPUTS {
                assert!(
                    close_cost(outputs, kind).fits(reserve),
                    "close_cost({outputs}, {kind:?}) exceeds the open-time reserve",
                );
            }
        }
    }
}
