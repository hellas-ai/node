//! Staked fraud-game protocol vocabulary (v1: one finite epoch, one
//! challenge-live job at a time).
//!
//! Two long-lived edges per pairing: a payment edge (plain
//! `Terms::basic`, client = maker) advancing an off-chain signed
//! frontier, and a provider-funded stake bond (`Terms::StakeBond`) whose
//! `Violation` close slashes the stake into the committed
//! `[(client, award + surplus), (treasury, stake − award)]` shape — the
//! kernel pins that routing structurally.
//!
//! [`Channel`] is the one off-chain structure for such a pairing, held
//! symmetrically by both parties: the client admits jobs and issues
//! frontier vouchers; the provider admits the same jobs and settles the
//! same vouchers. Every off-chain invariant — admission, serialization
//! through resolution, frontier monotonicity — lives in its methods.
//!
//! This module also defines the job-binding contexts a violation seal
//! must prove itself against, and the dev-only preverified artifact
//! cache the `preverified-seals` verifier consults. The bond `EdgeId`
//! is the epoch identity: it is unforgeable and unique per (funding,
//! terms), so contexts bind it directly instead of carrying a separate
//! epoch counter.

use hellas_kernel::{
    Auth, BlockHeight, CloseKind, EdgeId, Encode, Key, List, MAX_EDGE_OUTPUTS, Parties,
    PayloadHash, Payout, Proof, ProtocolCode, Seal, SealPublicInputs, Secp256k1Signer,
    Secp256k1Verifier, Sig, SigVerifier as _, StakeBondTerms, Terms, TermsHash, Tx as KernelTx,
    Writer as _,
};
#[cfg(feature = "preverified-seals")]
use std::collections::HashMap;
#[cfg(feature = "preverified-seals")]
use std::sync::{Arc, Mutex};

/// Protocol code for the optimistic payment channel (plain `Basic`
/// terms shape; client = maker funds capacity `B`, timeout refunds the
/// client).
pub const PAYMENT_PROTOCOL: ProtocolCode = ProtocolCode::new(2);
/// Protocol code for the provider stake bond.
pub const STAKE_BOND_PROTOCOL: ProtocolCode = ProtocolCode::new(3);

/// Builds the payment-edge terms: a `Basic` edge whose maker is the
/// client, whose taker is the provider, and whose timeout refunds the
/// entire close value to the client (the unilateral fallback when the
/// provider disappears — the client never signs a `Mutual` close, so
/// its own exit is `Timeout`).
///
/// `refund` must equal the edge's close value (locked capacity plus
/// timeout reserve surplus); the kernel rejects the open otherwise.
#[must_use]
pub fn payment_terms(client: Key, provider: Key, timeout: BlockHeight, refund: u64) -> Terms {
    let mut outputs = [Payout::default(); MAX_EDGE_OUTPUTS];
    outputs[0] = Payout::new(client, refund);
    Terms::basic(
        PAYMENT_PROTOCOL,
        Parties::new(client, provider),
        timeout,
        List::take(outputs, 1),
    )
}

/// A client-signed payment frontier: the maker's kernel `Mutual`
/// authorization over one exact two-output close of the payment edge,
/// at cumulative provider earnings `E`.
///
/// Asymmetric by construction — a voucher carries *only* the maker
/// authorization. The provider turns the latest voucher into an
/// executable close by adding its own signature at redemption time;
/// provider authorization never crosses the API boundary in the other
/// direction, so the client's only unilateral exit stays `Timeout` and
/// a stale-frontier race needs a signature the client never saw.
#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub struct MakerVoucher {
    /// The payment edge this voucher closes.
    pub payment_edge: EdgeId,
    /// Commitment to the payment edge's open terms.
    pub terms_hash: TermsHash,
    /// Cumulative provider earnings `E` this frontier settles at. The
    /// monotonicity index — strictly increasing per voucher.
    pub cumulative: u64,
    /// Maker authorization over the canonical kernel `Mutual` payload
    /// hash of the outputs `cumulative` derives — see [`close_outputs`].
    pub client_auth: Auth,
}

/// The canonical two-output close shape: refund to the client,
/// earnings to the provider.
///
/// The single definition of the frontier payload. `SettleRequest`
/// deliberately does not carry outputs — it carries `cumulative` and
/// the provider rebuilds them — so anything that stored them would be
/// a second encoding of a derived value, and a chance for the two to
/// disagree. Returns `None` when `cumulative` exceeds `total`.
#[must_use]
fn close_outputs(
    client: Key,
    provider: Key,
    total: u64,
    cumulative: u64,
) -> Option<List<Payout, MAX_EDGE_OUTPUTS>> {
    let refund = total.checked_sub(cumulative)?;
    let mut slots = [Payout::default(); MAX_EDGE_OUTPUTS];
    slots[0] = Payout::new(client, refund);
    slots[1] = Payout::new(provider, cumulative);
    Some(List::take(slots, 2))
}

impl MakerVoucher {
    /// Client-side issuance: signs the canonical kernel `Mutual` payload
    /// for the frontier at cumulative earnings `cumulative`, where
    /// `total` is the edge's exact close value (capacity plus reserve
    /// surplus). Returns `None` when `cumulative > total`.
    #[must_use]
    pub fn issue(
        client: &Secp256k1Signer,
        provider: Key,
        payment_edge: EdgeId,
        terms_hash: TermsHash,
        total: u64,
        cumulative: u64,
    ) -> Option<Self> {
        let outputs = close_outputs(client.party_key(), provider, total, cumulative)?;
        let hash = KernelTx::payload_hash(payment_edge, CloseKind::Mutual, terms_hash, &outputs);
        Some(Self {
            payment_edge,
            terms_hash,
            cumulative,
            client_auth: Auth::native(client.sign(hash)),
        })
    }

    /// Provider-side redemption: adds the taker authorization and
    /// produces the executable kernel `Mutual` close. This is the only
    /// place provider authorization is created, and it never leaves the
    /// resulting transaction.
    ///
    /// Takes the `channel` because the outputs are derived, not
    /// carried: the voucher commits to `cumulative`, and the pairing
    /// supplies the parties and the capacity that turn it into a
    /// payload. Returns `None` when the voucher does not settle on this
    /// channel's payment edge.
    #[must_use]
    pub fn redeem(&self, channel: &Channel, provider: &Secp256k1Signer) -> Option<KernelTx> {
        let outputs = channel.close_outputs(self.cumulative)?;
        let hash = KernelTx::payload_hash(
            self.payment_edge,
            CloseKind::Mutual,
            self.terms_hash,
            &outputs,
        );
        Some(KernelTx::close(
            self.payment_edge,
            Proof::mutual(self.client_auth.clone(), Auth::native(provider.sign(hash))),
            outputs,
        ))
    }
}

/// Reason a [`Channel::admit`] refused a job.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum AdmitError {
    /// v1 serializes jobs through resolution: the in-flight job has not
    /// settled.
    Busy,
    /// The context names a different bond, payment edge, or terms.
    ForeignJob,
    /// The context's sequence is not the next one in this channel.
    OutOfSequence,
    /// The terminal deadline is not strictly after the observed height.
    DeadlinePassed,
    /// The job fails the bond's committed admission rule (price caps or
    /// the challenge margin against the bond timeout).
    Uncovered,
    /// The provider's redemption margin does not fit before the payment
    /// edge's timeout: an accepted job could strand the frontier behind
    /// the client's unilateral refund.
    RedemptionMarginExceeded,
    /// The frontier plus this job's price exceeds the payment capacity.
    InsufficientCapacity,
}

/// Reason a [`Channel::settle`] refused a voucher.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum SettleError {
    /// No job is awaiting settlement.
    NoActiveJob,
    /// The observed height leaves less than the redemption margin before
    /// the payment timeout, so an accepted frontier could not be
    /// redeemed before the client's unilateral refund — the provider
    /// refuses to treat it as payment.
    TooLateToRedeem,
    /// The voucher names a different payment edge or terms.
    ForeignVoucher,
    /// The voucher does not advance the frontier by exactly the active
    /// job's price into the canonical two-output close shape.
    WrongFrontier,
    /// The maker authorization does not verify over the canonical
    /// mutual-close payload.
    BadAuthorization,
}

/// The one off-chain structure for a two-edge pairing, held
/// symmetrically by both parties.
///
/// A channel pairs the provider-funded stake bond with the
/// client-funded payment edge and carries everything off-chain the
/// pairing needs: the latest client-authorized frontier, the single
/// in-flight job (v1 serializes jobs through resolution), and the
/// strictly-increasing job sequence. The client uses it to refuse
/// uncovered jobs and issue vouchers; the provider uses it to gate
/// admission and settle the same vouchers — one validation path, so
/// the two sides cannot diverge on what is admissible.
///
/// Terms are stored whole; hashes, capacity, and timeouts are derived
/// (`Terms` caches its own hash, so nothing here duplicates a
/// commitment).
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Channel {
    bond_edge: EdgeId,
    bond: Terms,
    payment_edge: EdgeId,
    payment: Terms,
    frontier: Option<MakerVoucher>,
    active: Option<JobAcceptanceContext>,
    sequence: u64,
}

impl Channel {
    /// Pairs a stake bond with a payment edge.
    ///
    /// Returns `None` unless the bond terms are stake-bond shaped, the
    /// payment terms are basic shaped, the parties mirror (bond maker =
    /// payment taker = provider; bond taker = payment maker = client),
    /// and — the routing the kernel does *not* pin at open — each edge's
    /// timeout outputs pay the right party: the payment refund goes
    /// wholly to the client, the bond's stake-return wholly to the
    /// provider. Without this a malicious pairing could route the
    /// client's unilateral refund to the provider, or let the client
    /// drain the stake with a plain bond timeout.
    #[must_use]
    pub fn new(
        bond_edge: EdgeId,
        bond: Terms,
        payment_edge: EdgeId,
        payment: Terms,
    ) -> Option<Self> {
        let policy = bond.as_stake_bond()?;
        if payment.as_stake_bond().is_some() {
            return None;
        }
        let provider = provider_key(&policy.parties);
        let client = client_key(&policy.parties);
        let mirrored = provider == payment.parties().taker() && client == payment.parties().maker();
        if !mirrored {
            return None;
        }
        let refunds_client = paid_solely_to(payment.timeout_outputs(), client);
        let returns_stake = paid_solely_to(bond.timeout_outputs(), provider);
        if !refunds_client || !returns_stake {
            return None;
        }
        Some(Self {
            bond_edge,
            bond,
            payment_edge,
            payment,
            frontier: None,
            active: None,
            sequence: 0,
        })
    }

    /// The bond's committed policy. The constructor guarantees the shape.
    /// Blocks the provider must reserve to get a close transaction
    /// finalized before the payment timeout.
    ///
    /// Read from the bond's committed `challenge_margin` rather than
    /// chosen per-party: it is a margin of the same kind on the same
    /// clock — inclusion plus finality — and it is the only such value
    /// both sides can agree on without another handshake. A
    /// constructor argument here would let two parties run divergent
    /// admission gates, so the client admits a job the provider
    /// refuses, with no on-chain fact to arbitrate. Consensus already
    /// rejects a zero `challenge_margin` at open, so this is non-zero
    /// for any bond that exists. Reserving the full challenge window is
    /// deliberately conservative: a channel that close to expiry has no
    /// remaining useful life anyway.
    /// This pairing's canonical close payload at cumulative earnings
    /// `cumulative`. `None` when `cumulative` exceeds the capacity.
    #[must_use]
    pub fn close_outputs(&self, cumulative: u64) -> Option<List<Payout, MAX_EDGE_OUTPUTS>> {
        close_outputs(self.client(), self.provider(), self.capacity(), cumulative)
    }

    #[must_use]
    pub fn close_margin(&self) -> u64 {
        self.bond_policy().challenge_margin
    }

    #[must_use]
    pub fn bond_policy(&self) -> &StakeBondTerms {
        self.bond
            .as_stake_bond()
            .expect("Channel bond terms are stake-bond shaped by construction")
    }

    /// The client key (payment maker, bond taker, slash beneficiary).
    #[must_use]
    pub fn client(&self) -> Key {
        self.payment.parties().maker()
    }

    /// The provider key (payment taker, bond maker, stake funder).
    #[must_use]
    pub fn provider(&self) -> Key {
        self.payment.parties().taker()
    }

    /// The payment edge's exact close value, committed by its terms.
    #[must_use]
    pub fn capacity(&self) -> u64 {
        self.payment
            .timeout_outputs()
            .as_slice()
            .iter()
            .fold(0_u64, |sum, payout| sum.saturating_add(payout.value()))
    }

    /// Cumulative provider earnings `E` at the latest frontier.
    #[must_use]
    pub fn cumulative(&self) -> u64 {
        self.frontier
            .as_ref()
            .map_or(0, |voucher| voucher.cumulative)
    }

    /// Sequence of the most recently admitted job.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// The in-flight job, if any.
    #[must_use]
    pub const fn active(&self) -> Option<&JobAcceptanceContext> {
        self.active.as_ref()
    }

    /// The latest client-authorized frontier, if any.
    #[must_use]
    pub const fn frontier(&self) -> Option<&MakerVoucher> {
        self.frontier.as_ref()
    }

    /// Builds the acceptance context for the next job in this channel.
    ///
    /// Filling the binding fields from channel state means both parties
    /// derive the identical context from the same request — the wire
    /// carries it only so each side can [`Self::admit`] and sign the
    /// exact same digest.
    #[must_use]
    pub fn job(
        &self,
        request: [u8; 32],
        environment: [u8; 32],
        price: u64,
        terminal_deadline: BlockHeight,
    ) -> JobAcceptanceContext {
        JobAcceptanceContext {
            bond_edge: self.bond_edge,
            bond_terms: self.bond.hash(),
            payment_edge: self.payment_edge,
            sequence: self.sequence.saturating_add(1),
            request,
            environment,
            price,
            terminal_deadline,
        }
    }

    /// The job admission gate, identical on both sides: the client MUST
    /// refuse before signing, the provider MUST refuse before
    /// co-signing. `now` is the highest finalized height the caller has
    /// observed.
    ///
    /// On success the job becomes the channel's single in-flight job
    /// and consumes its sequence number.
    pub fn admit(&mut self, now: BlockHeight, job: JobAcceptanceContext) -> Result<(), AdmitError> {
        if self.active.is_some() {
            return Err(AdmitError::Busy);
        }
        let named = job.bond_edge == self.bond_edge
            && job.bond_terms == self.bond.hash()
            && job.payment_edge == self.payment_edge;
        if !named {
            return Err(AdmitError::ForeignJob);
        }
        if self.sequence.checked_add(1) != Some(job.sequence) {
            return Err(AdmitError::OutOfSequence);
        }
        if job.terminal_deadline.get() <= now.get() {
            return Err(AdmitError::DeadlinePassed);
        }
        if !job.covered_by(self.bond_policy()) {
            return Err(AdmitError::Uncovered);
        }
        let redeemable = job
            .terminal_deadline
            .get()
            .checked_add(self.close_margin())
            .is_some_and(|end| end < self.payment.timeout().get());
        if !redeemable {
            return Err(AdmitError::RedemptionMarginExceeded);
        }
        let funded = self
            .cumulative()
            .checked_add(job.price)
            .is_some_and(|next| next <= self.capacity());
        if !funded {
            return Err(AdmitError::InsufficientCapacity);
        }
        self.sequence = job.sequence;
        self.active = Some(job);
        Ok(())
    }

    /// Releases an admitted job that was never fully accepted (the
    /// counterparty refused to co-sign, so no acceptance can bind
    /// either party). MUST NOT be used once both acceptance signatures
    /// exist — a co-signed job resolves only through
    /// [`Self::issue`]/[`Self::settle`] or the fraud path.
    ///
    /// The rescinded sequence number stays consumed: a half-signed
    /// acceptance digest over it may exist, so it is never reused.
    pub fn rescind(&mut self) -> Option<JobAcceptanceContext> {
        self.active.take()
    }

    /// Releases a job whose committed terminal deadline has passed
    /// without settlement.
    ///
    /// Unlike [`Self::rescind`], this is safe to apply unilaterally:
    /// the deadline is part of the acceptance BOTH parties signed, so
    /// each side computes the same release height from data it already
    /// holds. No coordinating message is needed and the two channels
    /// cannot desync — which is exactly the hazard one-sided `rescind`
    /// carries. The sequence stays consumed, as always.
    ///
    /// This is the provider's escape from a client that takes delivery
    /// and then neither settles nor disputes: without it, one abandoned
    /// job would hold the serialization lock forever.
    pub fn abandon(&mut self, now: BlockHeight) -> Option<JobAcceptanceContext> {
        let expired = self
            .active
            .as_ref()
            .is_some_and(|job| now.get() > job.terminal_deadline.get());
        if expired { self.active.take() } else { None }
    }

    /// True when no further job could be admitted before the payment
    /// timeout, so a frontier worth banking should be redeemed on-chain
    /// now rather than held.
    ///
    /// Derived from the committed margin rather than a chosen policy
    /// constant: once `now + close_margin` reaches the payment timeout,
    /// [`Self::admit`] refuses everything and [`Self::settle`] returns
    /// `TooLateToRedeem`, so the channel has no remaining useful life
    /// and holding the voucher only risks the client's timeout refund
    /// erasing earnings the provider already banked off-chain.
    #[must_use]
    fn redemption_due(&self, now: BlockHeight) -> bool {
        self.frontier.is_some()
            && now
                .get()
                .checked_add(self.close_margin())
                .is_none_or(|end| end >= self.payment.timeout().get())
    }

    /// Builds the channel's CLOSING transaction — exactly once — when
    /// the pairing has reached the end of its life.
    ///
    /// This is not an extra L1 interaction: it *is* the "end the state
    /// channel" half of the design's two on-chain touches. Everything
    /// between the opens and this close is off-chain vouchers.
    ///
    /// Consumes the frontier, which is what makes it single-shot. The
    /// transaction closes the payment edge, so afterwards there is
    /// nothing left to redeem — and a channel that kept handing the
    /// voucher back would resubmit the same close on every block past
    /// the margin, turning one permitted touch into per-block spam.
    pub fn close_on_expiry(
        &mut self,
        now: BlockHeight,
        provider: &Secp256k1Signer,
    ) -> Option<KernelTx> {
        if !self.redemption_due(now) || provider.party_key() != self.provider() {
            return None;
        }
        let voucher = self.frontier.take()?;
        voucher.redeem(self, provider)
    }

    /// Client-side settlement: issues the frontier voucher paying the
    /// in-flight job's price and resolves the job. Returns `None` when
    /// there is no in-flight job or `client` is not the payment maker.
    pub fn issue(&mut self, client: &Secp256k1Signer) -> Option<MakerVoucher> {
        let job = self.active.as_ref()?;
        if client.party_key() != self.client() {
            return None;
        }
        let cumulative = self.cumulative().checked_add(job.price)?;
        let voucher = MakerVoucher::issue(
            client,
            self.provider(),
            self.payment_edge,
            self.payment.hash(),
            self.capacity(),
            cumulative,
        )?;
        self.frontier = Some(voucher.clone());
        self.active = None;
        Some(voucher)
    }

    /// Provider-side settlement: accepts the frontier voucher paying
    /// the in-flight job's price and resolves the job, given the highest
    /// finalized height `now` the provider has observed.
    ///
    /// The voucher must name this payment edge and terms, advance the
    /// frontier by exactly the job's price into the canonical
    /// `[(client, total − E), (provider, E)]` shape, and carry a maker
    /// authorization that verifies over the canonical mutual-close
    /// payload. It is also refused when `now` leaves less than the
    /// redemption margin before the payment timeout: the kernel rejects
    /// a `Mutual` close at `height >= payment_timeout`, so a frontier
    /// accepted too late could be stranded behind the client's timeout
    /// refund. The redemption guarantee binds at *settle* time, not just
    /// at admission — an honest client settles promptly (well inside the
    /// margin), and a client that stalls past it forfeits that job's
    /// payment rather than trapping the provider.
    pub fn settle(&mut self, now: BlockHeight, voucher: MakerVoucher) -> Result<(), SettleError> {
        let Some(job) = self.active.as_ref() else {
            return Err(SettleError::NoActiveJob);
        };
        let redeemable = now
            .get()
            .checked_add(self.close_margin())
            .is_some_and(|end| end < self.payment.timeout().get());
        if !redeemable {
            return Err(SettleError::TooLateToRedeem);
        }
        if voucher.payment_edge != self.payment_edge || voucher.terms_hash != self.payment.hash() {
            return Err(SettleError::ForeignVoucher);
        }
        if self.cumulative().checked_add(job.price) != Some(voucher.cumulative) {
            return Err(SettleError::WrongFrontier);
        }
        // The payload is derived here, not taken from the voucher, so
        // there is nothing to cross-check: a client that signed a
        // different shape fails the authorization check below.
        let Some(outputs) = self.close_outputs(voucher.cumulative) else {
            return Err(SettleError::WrongFrontier);
        };
        let hash = KernelTx::payload_hash(
            self.payment_edge,
            CloseKind::Mutual,
            self.payment.hash(),
            &outputs,
        );
        if !Secp256k1Verifier::new().verify_auth(&voucher.client_auth, self.client(), hash) {
            return Err(SettleError::BadAuthorization);
        }
        self.frontier = Some(voucher);
        self.active = None;
        Ok(())
    }

    /// The client's unilateral exit: a `Timeout` close of the payment
    /// edge into its committed full-refund outputs.
    #[must_use]
    pub fn payment_timeout_close(&self) -> KernelTx {
        KernelTx::close(
            self.payment_edge,
            Proof::timeout(self.payment.clone()),
            self.payment.timeout_outputs().clone(),
        )
    }

    /// The provider's clean epoch end: a `Timeout` close of the bond
    /// into its committed stake-return outputs.
    #[must_use]
    pub fn bond_timeout_close(&self) -> KernelTx {
        KernelTx::close(
            self.bond_edge,
            Proof::timeout(self.bond.clone()),
            self.bond.timeout_outputs().clone(),
        )
    }

    /// The client's fraud exit: a `Violation` close of the bond under
    /// `seal` into the kernel-pinned `[(client, award), (treasury,
    /// stake − award)]` slash shape (the zero-fee shape: reserve
    /// surplus is zero, so the award carries no extra `Q`).
    #[must_use]
    pub fn slash_close(&self, seal: Seal) -> KernelTx {
        let policy = self.bond_policy();
        let mut slots = [Payout::default(); MAX_EDGE_OUTPUTS];
        slots[0] = Payout::new(self.client(), policy.award);
        slots[1] = Payout::new(policy.treasury, policy.stake.saturating_sub(policy.award));
        KernelTx::close(
            self.bond_edge,
            Proof::violation(self.bond.clone(), seal),
            List::take(slots, 2),
        )
    }
}

/// Domain separator for [`JobAcceptanceContext::digest`].
const JOB_ACCEPTANCE_DOMAIN: &[u8] = b"hellas.staked.job_acceptance.v1";
/// Domain separator for [`JobResultContext::digest`].
const JOB_RESULT_DOMAIN: &[u8] = b"hellas.staked.job_result.v1";
/// Domain separator for [`receipt_request_digest`].
const RECEIPT_REQUEST_DOMAIN: &[u8] = b"hellas.staked.receipt_request.v1";
/// Domain separator for [`FraudArtifact::seal`].
const PREVERIFIED_SEAL_DOMAIN: &[u8] = b"hellas.staked.preverified_seal.v1";

/// Job admission facts both parties authenticate *at acceptance* —
/// before any transcript exists. Selects the live bond by exact
/// `EdgeId` + `TermsHash`, so a fraud proof can only ever slash the
/// bond the job was accepted under.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub struct JobAcceptanceContext {
    /// The stake bond this job is covered by.
    pub bond_edge: EdgeId,
    /// Commitment to the bond's open terms.
    pub bond_terms: TermsHash,
    /// The payment channel the job's price settles through.
    pub payment_edge: EdgeId,
    /// Job sequence number within the relationship (v1 serializes jobs
    /// through resolution, so this is strictly increasing).
    pub sequence: u64,
    /// Commitment to the exact request (canonical job terms bytes).
    pub request: [u8; 32],
    /// Commitment to the execution environment / model / runner policy.
    pub environment: [u8; 32],
    /// Job price `p_j`, `1 ≤ p_j ≤ max_job_price` from the bond terms.
    pub price: u64,
    /// Height by which the provider's terminal output must land. Must
    /// leave the challenge window + margins before the bond timeout.
    ///
    /// A NEGOTIATED term, deliberately unbounded above by the protocol.
    /// The client proposes it and the provider only admits by
    /// co-signing, so a provider that dislikes a far-future deadline
    /// simply refuses — a party that habitually proposes absurd ones
    /// finds nobody will sign with it. A protocol-level maximum would
    /// be an invented constant solving a problem the handshake already
    /// solves; a provider wanting its own horizon cap imposes it in its
    /// admission policy, which is what [`Channel::admit`] is.
    pub terminal_deadline: BlockHeight,
}

impl JobAcceptanceContext {
    /// The job admission rule: the client MUST refuse jobs that fail
    /// this before accepting, and the verifier re-checks it before a
    /// slash. The price must sit within the bond's committed cap (and
    /// be at least 1, so a challenge is never value-indifferent), and
    /// the terminal deadline must leave the bond's committed challenge
    /// margin before its timeout — otherwise a stalling provider could
    /// push the challenge window past the bond's expiry and escape into
    /// a stake refund.
    ///
    /// The margin comparison is strict: the kernel rejects a `Violation`
    /// at `block_height >= timeout` (`ProofExpired`), so the last block a
    /// challenge can actually land on is `timeout − 1`. A window ending
    /// exactly at `timeout` is already too late, hence `challenge_end <
    /// timeout`, matching the plan's `terminal_deadline + margins <
    /// bond_timeout`.
    #[must_use]
    pub fn covered_by(&self, bond: &StakeBondTerms) -> bool {
        self.price >= 1
            && self.price <= bond.max_job_price
            && self
                .terminal_deadline
                .get()
                .checked_add(bond.challenge_margin)
                .is_some_and(|challenge_end| challenge_end < bond.timeout.get())
    }

    /// Canonical digest both parties sign at acceptance.
    #[must_use]
    pub fn digest(&self) -> PayloadHash {
        let mut hasher = blake3::Hasher::new();
        hasher.write(JOB_ACCEPTANCE_DOMAIN);
        self.bond_edge.encode_to(&mut hasher);
        self.bond_terms.encode_to(&mut hasher);
        self.payment_edge.encode_to(&mut hasher);
        self.sequence.encode_to(&mut hasher);
        self.request.encode_to(&mut hasher);
        self.environment.encode_to(&mut hasher);
        self.price.encode_to(&mut hasher);
        self.terminal_deadline.encode_to(&mut hasher);
        PayloadHash::from_bytes(*hasher.finalize().as_bytes())
    }
}

/// Terminal facts the provider signs once the job has run: the
/// acceptance it answers and the transcript/output commitment.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub struct JobResultContext {
    /// [`JobAcceptanceContext::digest`] of the accepted job.
    pub acceptance: PayloadHash,
    /// Commitment to the terminal transcript / output.
    pub transcript: [u8; 32],
}

impl JobResultContext {
    /// Canonical digest the provider signs at terminal output.
    #[must_use]
    pub fn digest(&self) -> PayloadHash {
        let mut hasher = blake3::Hasher::new();
        hasher.write(JOB_RESULT_DOMAIN);
        self.acceptance.encode_to(&mut hasher);
        self.transcript.encode_to(&mut hasher);
        PayloadHash::from_bytes(*hasher.finalize().as_bytes())
    }
}

/// Everything a violation seal stands for: a job both parties accepted
/// under a specific bond, a provider-signed terminal result for it, and
/// the signatures binding both to the bond's committed identities.
///
/// v1 stubs the wrongness proof itself (the bisection → atomic-op
/// argument is its own plan); an artifact in the preverified cache is
/// *trusted* to represent proven fraud. What is checked here is the
/// binding: this artifact can slash exactly one bond, for exactly one
/// job, with signatures from exactly the bond's committed parties.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub struct FraudArtifact {
    /// The accepted-job facts.
    pub acceptance: JobAcceptanceContext,
    /// Client (bond taker) signature over the acceptance digest.
    pub client_acceptance_sig: Sig,
    /// Provider (bond maker) signature over the acceptance digest.
    pub provider_acceptance_sig: Sig,
    /// The provider's terminal result.
    pub result: JobResultContext,
    /// Provider signature over the result digest.
    pub provider_result_sig: Sig,
}

impl FraudArtifact {
    /// The seal bytes this artifact justifies: a commitment to both
    /// context digests under a dedicated domain.
    #[must_use]
    pub fn seal(&self) -> Seal {
        let mut hasher = blake3::Hasher::new();
        hasher.write(PREVERIFIED_SEAL_DOMAIN);
        self.acceptance.digest().encode_to(&mut hasher);
        self.result.digest().encode_to(&mut hasher);
        Seal::from_bytes(*hasher.finalize().as_bytes())
    }

    /// Checks that this artifact is bound to the violation close's
    /// public inputs and internally authenticated.
    ///
    /// The payout routing itself is already pinned by the kernel from
    /// the revealed stake-bond terms; this decides only whether the
    /// fraud evidence names this bond, this job, and these parties.
    #[must_use]
    pub fn binds(&self, public: &SealPublicInputs<'_>) -> bool {
        let Some(bond) = public.terms.as_stake_bond() else {
            return false;
        };
        let acceptance_digest = self.acceptance.digest();
        let provider = provider_key(&bond.parties);
        let client = client_key(&bond.parties);
        let sigs = Secp256k1Verifier::new();
        self.acceptance.bond_edge == public.edge_id
            && self.acceptance.bond_terms == public.terms_hash()
            && self.acceptance.covered_by(bond)
            && self.result.acceptance == acceptance_digest
            && sigs.verify_sig(self.client_acceptance_sig, client, acceptance_digest)
            && sigs.verify_sig(self.provider_acceptance_sig, provider, acceptance_digest)
            && sigs.verify_sig(self.provider_result_sig, provider, self.result.digest())
    }
}

/// True when `outputs` is non-empty and every payout pays `key` — the
/// timeout-routing invariant the kernel leaves unpinned (it enforces
/// only the output *sum* at open).
fn paid_solely_to(outputs: &List<Payout, MAX_EDGE_OUTPUTS>, key: Key) -> bool {
    !outputs.as_slice().is_empty() && outputs.as_slice().iter().all(|p| p.owner() == key)
}

/// The payload a client signs to authorize a receipt for the job whose
/// acceptance digest is `acceptance`.
///
/// Deliberately NOT the acceptance digest itself. The client's
/// signature over that digest already travels on the wire inside the
/// run ticket, so verifying it here would authenticate anyone who
/// merely saw the ticket — a proxying gateway, or any peer on the
/// path — which is exactly the party receipt authorization exists to
/// exclude. Domain separation makes the receipt authorization
/// unforgeable from anything the client has already published.
#[must_use]
pub fn receipt_request_digest(acceptance: PayloadHash) -> PayloadHash {
    let mut hasher = blake3::Hasher::new();
    hasher.write(RECEIPT_REQUEST_DOMAIN);
    acceptance.encode_to(&mut hasher);
    PayloadHash::from_bytes(*hasher.finalize().as_bytes())
}

/// The stake-bond party convention: the maker funds the stake.
#[must_use]
fn provider_key(parties: &Parties) -> Key {
    parties.maker()
}

/// The stake-bond party convention: the taker is the client and the
/// committed violation beneficiary.
#[must_use]
fn client_key(parties: &Parties) -> Key {
    parties.taker()
}

/// Dev-only preverified fraud-artifact cache, keyed by seal bytes.
///
/// Populated off the apply critical path (in tests and on dev chains,
/// directly); consulted by the `preverified-seals` verifier during
/// violation closes. Inserting an artifact asserts its fraud claim is
/// true — only the *binding* is re-checked at verify time.
#[derive(Debug, Clone, Default)]
#[cfg(feature = "preverified-seals")]
pub struct PreverifiedSeals {
    inner: Arc<Mutex<HashMap<Seal, FraudArtifact>>>,
}

#[cfg(feature = "preverified-seals")]
impl PreverifiedSeals {
    /// Creates an empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers an artifact and returns the seal that redeems it.
    pub fn insert(&self, artifact: FraudArtifact) -> Seal {
        let seal = artifact.seal();
        self.inner
            .lock()
            .expect("preverified seal cache poisoned")
            .insert(seal, artifact);
        seal
    }

    /// Returns true when `seal` resolves to an artifact bound to
    /// `public`.
    #[must_use]
    pub fn verify(&self, seal: Seal, public: &SealPublicInputs<'_>) -> bool {
        let artifact = self
            .inner
            .lock()
            .expect("preverified seal cache poisoned")
            .get(&seal)
            .copied();
        artifact.is_some_and(|artifact| artifact.seal() == seal && artifact.binds(public))
    }
}

/// The seven symmetric scenarios of the two-edge game, driven purely —
/// heights injected, no chain: honest settle, the two admission
/// refusals (price, deadline), serialization, the fraud exit, and the
/// two timeout exits. Plus the admission/settlement negatives that keep
/// the two sides honest.
#[cfg(test)]
mod channel_tests {
    use super::*;

    const CAPACITY: u64 = 2_000;
    const STAKE: u64 = 1_000;
    const AWARD: u64 = 700;
    const BOND_TIMEOUT: u64 = 200;
    const PAYMENT_TIMEOUT: u64 = 150;
    const CHALLENGE_MARGIN: u64 = 20;

    fn signer(seed: u8) -> Secp256k1Signer {
        let Ok(signer) = Secp256k1Signer::from_secret_scalar([seed; 32]) else {
            panic!("non-zero secret scalar");
        };
        signer
    }

    fn provider() -> Secp256k1Signer {
        signer(1)
    }

    fn client() -> Secp256k1Signer {
        signer(2)
    }

    fn now() -> BlockHeight {
        BlockHeight::new(10)
    }

    fn bond_edge() -> EdgeId {
        EdgeId::from_bytes([1; 32])
    }

    fn payment_edge() -> EdgeId {
        EdgeId::from_bytes([2; 32])
    }

    fn sample_stake_bond() -> StakeBondTerms {
        let provider = provider().party_key();
        let mut outputs = [Payout::default(); MAX_EDGE_OUTPUTS];
        outputs[0] = Payout::new(provider, STAKE);
        StakeBondTerms {
            protocol: STAKE_BOND_PROTOCOL,
            parties: Parties::new(provider, client().party_key()),
            timeout: BlockHeight::new(BOND_TIMEOUT),
            timeout_outputs: List::take(outputs, 1),
            treasury: signer(3).party_key(),
            award: AWARD,
            stake: STAKE,
            max_job_price: 500,
            max_dispute_cost: 200,
            challenge_margin: CHALLENGE_MARGIN,
        }
    }

    fn bond_terms() -> Terms {
        Terms::stake_bond(sample_stake_bond())
    }

    fn payment() -> Terms {
        payment_terms(
            client().party_key(),
            provider().party_key(),
            BlockHeight::new(PAYMENT_TIMEOUT),
            CAPACITY,
        )
    }

    fn channel() -> Channel {
        let Some(channel) = Channel::new(
            bond_edge(),
            bond_terms(),
            payment_edge(),
            payment(),
        ) else {
            panic!("mirrored pairing constructs");
        };
        channel
    }

    fn job(channel: &Channel, price: u64, deadline: u64) -> JobAcceptanceContext {
        channel.job([7; 32], [8; 32], price, BlockHeight::new(deadline))
    }

    // Scenario 1: the honest job, settled symmetrically on both sides.
    #[test]
    fn honest_job_settles_the_frontier_on_both_sides() {
        let mut mine = channel();
        let mut theirs = channel();
        let first = job(&mine, 400, 60);
        assert_eq!(mine.admit(now(), first), Ok(()));
        assert_eq!(theirs.admit(now(), first), Ok(()));
        let Some(voucher) = mine.issue(&client()) else {
            panic!("client issues the frontier");
        };
        assert_eq!(voucher.cumulative, 400);
        assert_eq!(theirs.settle(now(), voucher), Ok(()));
        for side in [&mine, &theirs] {
            assert_eq!(side.cumulative(), 400);
            assert_eq!(side.sequence(), 1);
            assert!(side.active().is_none());
        }

        // The lock is released: the next job runs the same way.
        let second = job(&mine, 500, 70);
        assert_eq!(mine.admit(now(), second), Ok(()));
        assert_eq!(theirs.admit(now(), second), Ok(()));
        let Some(voucher) = mine.issue(&client()) else {
            panic!("second frontier issues");
        };
        assert_eq!(theirs.settle(now(), voucher), Ok(()));
        assert_eq!(theirs.cumulative(), 900);
    }

    // Scenario 2: prices outside the bond's committed cap are refused.
    #[test]
    fn admission_refuses_uncovered_prices() {
        let mut channel = channel();
        for price in [0, 501] {
            let uncovered = job(&channel, price, 60);
            assert_eq!(channel.admit(now(), uncovered), Err(AdmitError::Uncovered));
        }
    }

    // Scenario 3: deadlines that leave no room for the challenge (bond
    // side) or the redemption (payment side) are refused.
    #[test]
    fn admission_refuses_deadlines_outside_the_committed_margins() {
        let mut channel = channel();
        // 180 + 20 = 200 == bond timeout: the challenge cannot land.
        let stalled = job(&channel, 400, 180);
        assert_eq!(channel.admit(now(), stalled), Err(AdmitError::Uncovered));
        // 130 + 20 = 150 == payment timeout: the frontier could be
        // stranded behind the client's unilateral refund.
        let stranded = job(&channel, 400, 130);
        assert_eq!(
            channel.admit(now(), stranded),
            Err(AdmitError::RedemptionMarginExceeded),
        );
        // 129 + 20 = 149 < 150: the last admissible deadline. One
        // committed margin now governs both sides, and the shorter
        // payment timeout makes it bind first.
        let last = job(&channel, 400, 129);
        assert_eq!(channel.admit(now(), last), Ok(()));
    }

    #[test]
    fn admission_refuses_deadlines_at_or_before_the_observed_height() {
        let mut channel = channel();
        let expired = job(&channel, 400, 60);
        assert_eq!(
            channel.admit(BlockHeight::new(60), expired),
            Err(AdmitError::DeadlinePassed),
        );
    }

    // Scenario 4: v1 serializes jobs through resolution.
    #[test]
    fn admission_serializes_jobs_through_resolution() {
        let mut mine = channel();
        let first = job(&mine, 400, 60);
        assert_eq!(mine.admit(now(), first), Ok(()));
        let blocked = job(&mine, 100, 70);
        assert_eq!(mine.admit(now(), blocked), Err(AdmitError::Busy));

        // A never-co-signed offer is rescinded; its sequence stays
        // consumed so a half-signed digest can never collide.
        assert_eq!(mine.rescind(), Some(first));
        let next = job(&mine, 100, 70);
        assert_eq!(next.sequence, 2);
        assert_eq!(mine.admit(now(), next), Ok(()));
    }

    #[test]
    fn admission_refuses_foreign_and_out_of_sequence_contexts() {
        let mut channel = channel();
        let foreign = JobAcceptanceContext {
            bond_edge: EdgeId::from_bytes([9; 32]),
            ..job(&channel, 400, 60)
        };
        assert_eq!(channel.admit(now(), foreign), Err(AdmitError::ForeignJob));
        let skipped = JobAcceptanceContext {
            sequence: 5,
            ..job(&channel, 400, 60)
        };
        assert_eq!(
            channel.admit(now(), skipped),
            Err(AdmitError::OutOfSequence),
        );
    }

    #[test]
    fn admission_refuses_jobs_the_capacity_cannot_fund() {
        let mut mine = channel();
        let mut theirs = channel();
        for deadline in [60, 61, 62, 63] {
            let next = job(&mine, 500, deadline);
            assert_eq!(mine.admit(now(), next), Ok(()));
            assert_eq!(theirs.admit(now(), next), Ok(()));
            let Some(voucher) = mine.issue(&client()) else {
                panic!("frontier issues");
            };
            assert_eq!(theirs.settle(now(), voucher), Ok(()));
        }
        assert_eq!(mine.cumulative(), CAPACITY);
        let unfunded = job(&mine, 1, 70);
        assert_eq!(
            mine.admit(now(), unfunded),
            Err(AdmitError::InsufficientCapacity),
        );
    }

    // Scenario 5: the fraud exit — the artifact binds to this bond and
    // the slash close carries exactly the kernel-pinned payouts.
    #[test]
    fn fraud_artifact_binds_and_the_slash_close_matches_the_pinned_payouts() {
        let mut mine = channel();
        let accepted = job(&mine, 400, 60);
        assert_eq!(mine.admit(now(), accepted), Ok(()));
        let digest = accepted.digest();
        let result = JobResultContext {
            acceptance: digest,
            transcript: [9; 32],
        };
        let artifact = FraudArtifact {
            acceptance: accepted,
            client_acceptance_sig: client().sign(digest),
            provider_acceptance_sig: provider().sign(digest),
            result,
            provider_result_sig: provider().sign(result.digest()),
        };
        let seal = artifact.seal();

        let mut slots = [Payout::default(); MAX_EDGE_OUTPUTS];
        slots[0] = Payout::new(client().party_key(), AWARD);
        slots[1] = Payout::new(signer(3).party_key(), STAKE - AWARD);
        let outputs = List::take(slots, 2);
        let bond = bond_terms();
        assert_eq!(
            mine.slash_close(seal),
            KernelTx::close(
                bond_edge(),
                Proof::violation(bond.clone(), seal),
                outputs.clone()
            ),
        );
        assert!(artifact.binds(&SealPublicInputs {
            edge_id: bond_edge(),
            terms: &bond,
            payouts: &outputs,
        }));
    }

    // Scenario 6: the provider vanishes; the client's refund needs no
    // counterparty.
    #[test]
    fn a_vanished_provider_cannot_stop_the_clients_timeout_refund() {
        let channel = channel();
        assert_eq!(
            channel.payment_timeout_close(),
            KernelTx::close(
                payment_edge(),
                Proof::timeout(payment()),
                payment().timeout_outputs().clone(),
            ),
        );
    }

    // Scenario 7: the clean epoch end returns the stake.
    #[test]
    fn a_clean_epoch_end_returns_the_stake_to_the_provider() {
        let channel = channel();
        assert_eq!(
            channel.bond_timeout_close(),
            KernelTx::close(
                bond_edge(),
                Proof::timeout(bond_terms()),
                bond_terms().timeout_outputs().clone(),
            ),
        );
    }

    #[test]
    fn settlement_refuses_foreign_stale_and_unauthorized_frontiers() {
        let mut theirs = channel();
        let accepted = job(&theirs, 400, 60);
        assert_eq!(theirs.admit(now(), accepted), Ok(()));

        let issue_at = |edge, cumulative| {
            MakerVoucher::issue(
                &client(),
                provider().party_key(),
                edge,
                payment().hash(),
                CAPACITY,
                cumulative,
            )
        };
        let Some(foreign) = issue_at(EdgeId::from_bytes([9; 32]), 400) else {
            panic!("foreign voucher issues");
        };
        assert_eq!(
            theirs.settle(now(), foreign),
            Err(SettleError::ForeignVoucher)
        );

        let Some(short) = issue_at(payment_edge(), 399) else {
            panic!("short voucher issues");
        };
        assert_eq!(theirs.settle(now(), short), Err(SettleError::WrongFrontier));

        let Some(genuine) = issue_at(payment_edge(), 400) else {
            panic!("genuine voucher issues");
        };
        let forged = MakerVoucher {
            client_auth: Auth::native(provider().sign(accepted.digest())),
            ..genuine.clone()
        };
        assert_eq!(
            theirs.settle(now(), forged),
            Err(SettleError::BadAuthorization)
        );

        assert_eq!(theirs.settle(now(), genuine.clone()), Ok(()));
        assert_eq!(theirs.settle(now(), genuine), Err(SettleError::NoActiveJob));
    }

    // The redemption guarantee binds at settle time: a voucher offered
    // too close to the payment timeout to redeem is refused, so the
    // provider is never lured into accepting payment it cannot bank.
    #[test]
    fn settlement_is_refused_once_redemption_no_longer_fits() {
        let mut theirs = channel();
        let accepted = job(&theirs, 400, 60);
        assert_eq!(theirs.admit(now(), accepted), Ok(()));
        let Some(voucher) = MakerVoucher::issue(
            &client(),
            provider().party_key(),
            payment_edge(),
            payment().hash(),
            CAPACITY,
            400,
        ) else {
            panic!("voucher issues");
        };
        // 130 + 20 = 150 == payment timeout: no block left to redeem.
        assert_eq!(
            theirs.settle(BlockHeight::new(130), voucher.clone()),
            Err(SettleError::TooLateToRedeem),
        );
        // 129 + 20 = 149 < 150: the last height a settlement still fits.
        assert_eq!(theirs.settle(BlockHeight::new(129), voucher), Ok(()));
    }

    #[test]
    fn only_the_client_issues_and_only_the_provider_redeems() {
        let mut mine = channel();
        let accepted = job(&mine, 400, 60);
        assert_eq!(mine.admit(now(), accepted), Ok(()));
        assert!(
            mine.issue(&provider()).is_none(),
            "the provider cannot sign the maker frontier",
        );
        let Some(_voucher) = mine.issue(&client()) else {
            panic!("client issues");
        };
        // Past the margin the close is due; only the taker can sign it.
        let due = BlockHeight::new(130);
        assert!(
            mine.close_on_expiry(due, &client()).is_none(),
            "the client cannot redeem the taker close",
        );
        assert!(mine.close_on_expiry(due, &provider()).is_some());
    }

    #[test]
    fn channel_construction_refuses_unmirrored_or_shapeless_pairings() {
        let unmirrored = payment_terms(
            provider().party_key(),
            client().party_key(),
            BlockHeight::new(PAYMENT_TIMEOUT),
            CAPACITY,
        );
        // A payment edge whose timeout refunds the PROVIDER, not the
        // client — the client's unilateral exit would hand capacity away.
        let mut misrouted_payment_outputs = [Payout::default(); MAX_EDGE_OUTPUTS];
        misrouted_payment_outputs[0] = Payout::new(provider().party_key(), CAPACITY);
        let misrouted_payment = Terms::basic(
            PAYMENT_PROTOCOL,
            Parties::new(client().party_key(), provider().party_key()),
            BlockHeight::new(PAYMENT_TIMEOUT),
            List::take(misrouted_payment_outputs, 1),
        );
        // A bond whose timeout returns the stake to the CLIENT — a plain
        // timeout would drain the stake with no fraud proof.
        let mut drained_bond_outputs = [Payout::default(); MAX_EDGE_OUTPUTS];
        drained_bond_outputs[0] = Payout::new(client().party_key(), STAKE);
        let drained_bond = Terms::stake_bond(StakeBondTerms {
            timeout_outputs: List::take(drained_bond_outputs, 1),
            ..sample_stake_bond()
        });
        let cases = [
            // Parties do not mirror across the two edges.
            (bond_terms(), unmirrored),
            // A bond that is not a bond.
            (payment(), payment()),
            // A payment edge that is a bond.
            (bond_terms(), bond_terms()),
            // Timeout outputs routed to the wrong party.
            (bond_terms(), misrouted_payment),
            (drained_bond, payment()),
        ];
        for (bond, payment) in cases {
            assert!(Channel::new(bond_edge(), bond, payment_edge(), payment).is_none());
        }
    }
}

#[cfg(all(test, feature = "preverified-seals"))]
mod tests {
    use super::*;
    use crate::domain::{
        Coin, KERNEL_FEES, Object, SettlementKey, Transaction, coin_object_id, edge_object_id,
        genesis_object_id,
    };
    use crate::execution::store::{UtxoDatabase, utxo_db_config};
    use crate::execution::test_support::run_qmdb;
    use crate::execution::{ChainVerifier, ExecutionError, execute_all};
    use commonware_glue::stateful::db::{DatabaseSet, Unmerkleized as _};
    use hellas_kernel::{
        ApplyError, Auth, BlockHash, BlockHeight, CoinId, Context as KernelContext, Funding,
        InvalidProofReason, List, MAX_EDGE_OUTPUTS, MAX_PARTY_INPUTS, Parties, Payout, Proof,
        Secp256k1Signer, StakeBondTerms, Terms, Tx as KernelTx,
    };

    const STAKE: u64 = 1_000;
    const AWARD: u64 = 700;

    fn context(height: u64) -> KernelContext {
        KernelContext::with_fees(
            BlockHeight::new(height),
            BlockHash::from_bytes([0; BlockHash::LENGTH]),
            KERNEL_FEES,
        )
    }

    fn signer(seed: u8) -> Secp256k1Signer {
        let Ok(signer) = Secp256k1Signer::from_secret_scalar([seed; 32]) else {
            panic!("non-zero secret scalar");
        };
        signer
    }

    const FULL_GAME_CAPACITY: u64 = 2_000;
    const FULL_GAME_STAKE: u64 = 2_000;
    const FULL_GAME_AWARD: u64 = 1_200;

    /// The bond the full-game e2e commits. Shared with the economics
    /// test so that test asserts over the terms actually in use rather
    /// than a copy of them that can silently drift.
    fn full_game_bond_policy() -> StakeBondTerms {
        let provider = signer(12).party_key();
        StakeBondTerms {
            protocol: STAKE_BOND_PROTOCOL,
            parties: Parties::new(provider, signer(11).party_key()),
            timeout: BlockHeight::new(100),
            timeout_outputs: List::take(
                [Payout::new(provider, FULL_GAME_STAKE); MAX_EDGE_OUTPUTS],
                1,
            ),
            treasury: signer(13).party_key(),
            award: FULL_GAME_AWARD,
            stake: FULL_GAME_STAKE,
            max_job_price: 1_000,
            max_dispute_cost: 200,
            challenge_margin: 20,
        }
    }

    /// The bond the preverified-slash e2e commits.
    fn slash_fixture_bond_policy() -> StakeBondTerms {
        let provider = signer(5).party_key();
        StakeBondTerms {
            protocol: STAKE_BOND_PROTOCOL,
            parties: Parties::new(provider, signer(6).party_key()),
            timeout: BlockHeight::new(100),
            timeout_outputs: List::take([Payout::new(provider, STAKE); MAX_EDGE_OUTPUTS], 1),
            treasury: signer(7).party_key(),
            award: AWARD,
            stake: STAKE,
            max_job_price: 500,
            max_dispute_cost: 200,
            challenge_margin: 20,
        }
    }

    /// A channel over the full-game fixture terms, for assertions that
    /// need the real `Channel` closes without a live chain.
    fn full_game_channel() -> Channel {
        let payment = payment_terms(
            signer(11).party_key(),
            signer(12).party_key(),
            BlockHeight::new(100),
            FULL_GAME_CAPACITY,
        );
        let Some(channel) = Channel::new(
            hellas_kernel::EdgeId::from_bytes([0x44; 32]),
            Terms::stake_bond(full_game_bond_policy()),
            hellas_kernel::EdgeId::from_bytes([0x55; 32]),
            payment,
        ) else {
            panic!("full-game fixture terms form a valid pairing");
        };
        channel
    }

    fn two_payouts(first: Payout, second: Payout) -> List<Payout, MAX_EDGE_OUTPUTS> {
        let mut slots = [Payout::default(); MAX_EDGE_OUTPUTS];
        slots[0] = first;
        slots[1] = second;
        List::take(slots, 2)
    }

    fn artifact_for(
        bond_edge: hellas_kernel::EdgeId,
        bond_terms: hellas_kernel::TermsHash,
        provider: &Secp256k1Signer,
        client: &Secp256k1Signer,
    ) -> FraudArtifact {
        let acceptance = JobAcceptanceContext {
            bond_edge,
            bond_terms,
            payment_edge: hellas_kernel::EdgeId::from_bytes([0x33; 32]),
            sequence: 1,
            request: [7; 32],
            environment: [8; 32],
            price: 400,
            terminal_deadline: BlockHeight::new(60),
        };
        let acceptance_digest = acceptance.digest();
        let result = JobResultContext {
            acceptance: acceptance_digest,
            transcript: [9; 32],
        };
        FraudArtifact {
            acceptance,
            client_acceptance_sig: client.sign(acceptance_digest),
            provider_acceptance_sig: provider.sign(acceptance_digest),
            result,
            provider_result_sig: provider.sign(result.digest()),
        }
    }

    /// The committed admission rule: price caps and the challenge
    /// margin against the bond timeout, exactly the inequalities the
    /// plan makes load-bearing against the stall-past-timeout escape.
    #[test]
    fn job_coverage_enforces_price_caps_and_challenge_margin() {
        let provider = signer(5);
        let client = signer(6);
        let bond = StakeBondTerms {
            protocol: STAKE_BOND_PROTOCOL,
            parties: Parties::new(provider.party_key(), client.party_key()),
            timeout: BlockHeight::new(100),
            timeout_outputs: List::take([Payout::default(); MAX_EDGE_OUTPUTS], 0),
            treasury: signer(7).party_key(),
            award: 700,
            stake: 1_000,
            max_job_price: 500,
            max_dispute_cost: 200,
            challenge_margin: 20,
        };
        let base = JobAcceptanceContext {
            bond_edge: hellas_kernel::EdgeId::from_bytes([1; 32]),
            bond_terms: Terms::stake_bond(bond.clone()).hash(),
            payment_edge: hellas_kernel::EdgeId::from_bytes([2; 32]),
            sequence: 1,
            request: [7; 32],
            environment: [8; 32],
            price: 400,
            terminal_deadline: BlockHeight::new(60),
        };

        assert!(base.covered_by(&bond));
        assert!(
            JobAcceptanceContext {
                // 79 + 20 = 99 < 100: the last covered deadline, leaving
                // block 99 as the final slashable challenge block.
                terminal_deadline: BlockHeight::new(79),
                ..base
            }
            .covered_by(&bond),
            "last strictly-under-timeout deadline is covered",
        );
        for uncovered in [
            JobAcceptanceContext { price: 0, ..base },
            JobAcceptanceContext { price: 501, ..base },
            JobAcceptanceContext {
                // 80 + 20 = 100 == timeout: the challenge would have to
                // land at `timeout`, where the kernel already rejects
                // Violation as ProofExpired. Not covered.
                terminal_deadline: BlockHeight::new(80),
                ..base
            },
            JobAcceptanceContext {
                terminal_deadline: BlockHeight::new(81),
                ..base
            },
            JobAcceptanceContext {
                terminal_deadline: BlockHeight::new(u64::MAX),
                ..base
            },
        ] {
            assert!(!uncovered.covered_by(&bond));
        }
    }

    /// Option-1 (stake-only, λ=0) economics, with p_d = p_w = 1. These
    /// are deliberately NOT the paper's `p_d·(P_set + S)` / `λ·P_set`
    /// equations: across two edges the provider always redeems its
    /// payment voucher, so the penalty relative to undetected fraud is
    /// exactly `S`, and the client is made whole from the slash award,
    /// never from clawback.
    /// Option-1 (stake-only, λ = 0) economics, asserted over the terms
    /// the fixtures actually commit and the payouts `slash_close`
    /// actually builds.
    ///
    /// A previous version of this test declared its own literals and
    /// asserted algebraic identities (`(p − c_F − S) − (p − c_H)` vs
    /// `c_H − c_F − S`) that hold for *every* assignment — it read no
    /// production value and would have passed with both fixture bonds
    /// set to economically broken numbers. What follows reads real
    /// terms, quantifies over the whole space of jobs those terms
    /// admit, and derives the settlement delta from the close the
    /// channel emits.
    #[test]
    fn option_one_economics_hold_for_the_committed_bond_shape() {
        for policy in [full_game_bond_policy(), slash_fixture_bond_policy()] {
            // Conditional reimbursement, universally quantified: for
            // EVERY job this bond can admit and every dispute cost it
            // can cover, the award makes the client whole without any
            // clawback of the payment edge. This is exactly what the
            // open-time floor buys, and it fails if the floor is wrong.
            assert!(
                policy.award >= policy.max_job_price + policy.max_dispute_cost,
                "award floor violated by a committed fixture",
            );
            for price in 1..=policy.max_job_price {
                for dispute in [0, policy.max_dispute_cost / 2, policy.max_dispute_cost] {
                    assert!(
                        policy.award >= price + dispute,
                        "award {} cannot make the client whole for p_j={price}, C_disp={dispute}",
                        policy.award,
                    );
                }
            }
            // Strict dispute incentive A > C_disp, for every cost the
            // bond admits — so challenging is never value-indifferent.
            assert!(policy.award > policy.max_dispute_cost);
            // The award is real and bounded by the stake behind it.
            assert!(policy.award > 0 && policy.award <= policy.stake);
        }

        // The settlement delta, read off the close the channel actually
        // builds rather than restated as arithmetic: a proven fraud
        // moves exactly the stake — award to the client, remainder to
        // the treasury — so the provider's loss relative to undetected
        // fraud is exactly S, never p_j + S. Nothing routes back to the
        // provider.
        let channel = full_game_channel();
        let policy = full_game_bond_policy();
        let slash = channel.slash_close(Seal::from_bytes([0; 32]));
        let KernelTx::Close { outputs, .. } = &slash else {
            panic!("slash_close builds a close");
        };
        let moved: u64 = outputs.as_slice().iter().map(|payout| payout.value()).sum();
        assert_eq!(moved, policy.stake, "a slash moves exactly the stake");
        let to_client: u64 = outputs
            .as_slice()
            .iter()
            .filter(|payout| payout.owner() == channel.client())
            .map(|payout| payout.value())
            .sum();
        assert_eq!(to_client, policy.award);
        assert!(
            !outputs
                .as_slice()
                .iter()
                .any(|payout| payout.owner() == channel.provider()),
            "no slash output may route back to the provider",
        );
    }

    /// The full game at consensus execution: both edges open for real
    /// (so every id the contexts bind is a true `edge_id_of`), both
    /// parties drive [`Channel`] through two honest jobs and a frontier
    /// redemption, and then a third, fraudulent job slashes the real
    /// bond into the kernel-pinned payouts — every close built by
    /// `Channel` itself.
    #[test]
    fn the_full_game_plays_out_at_consensus_execution() {
        run_qmdb(|runtime| async move {
            let client = signer(11);
            let provider = signer(12);
            let treasury = signer(13).party_key();
            let terms = payment_terms(
                client.party_key(),
                provider.party_key(),
                BlockHeight::new(100),
                FULL_GAME_CAPACITY,
            );
            let client_coin = CoinId::from_bytes(genesis_object_id(0).0);
            let funding = Funding::new(
                List::take([client_coin; MAX_PARTY_INPUTS], 1),
                List::take([client_coin; MAX_PARTY_INPUTS], 0),
            );
            let open_hash = KernelTx::open_hash(&funding, &terms);
            let payment_open = KernelTx::open(
                funding.clone(),
                terms.clone(),
                Auth::native(client.sign(open_hash)),
                Auth::native(provider.sign(open_hash)),
            );
            let payment_edge = KernelTx::edge_id_of(&funding, &terms);

            // The provider-funded bond, opened on-chain in the same
            // block. Coverage margins: deadline + challenge margin (20)
            // < 100 and deadline + close margin (5) < 100.
            let bond = Terms::stake_bond(full_game_bond_policy());
            let provider_coin = CoinId::from_bytes(genesis_object_id(1).0);
            let bond_funding = Funding::new(
                List::take([provider_coin; MAX_PARTY_INPUTS], 1),
                List::take([provider_coin; MAX_PARTY_INPUTS], 0),
            );
            let bond_open_hash = KernelTx::open_hash(&bond_funding, &bond);
            let bond_open = KernelTx::open(
                bond_funding.clone(),
                bond.clone(),
                Auth::native(provider.sign(bond_open_hash)),
                Auth::native(client.sign(bond_open_hash)),
            );
            let bond_edge = KernelTx::edge_id_of(&bond_funding, &bond);
            let allocations = vec![
                (SettlementKey::from(client.party_key()), FULL_GAME_CAPACITY),
                (SettlementKey::from(provider.party_key()), FULL_GAME_STAKE),
            ];

            let verifier = ChainVerifier::new();
            let config = utxo_db_config(&runtime, "full_game_e2e", 1024, 8);
            let database = <UtxoDatabase<_> as DatabaseSet<_>>::init(runtime, config).await;
            let batches = database.new_batches().await;
            let batches = execute_all(
                context(1),
                &verifier,
                &[
                    Transaction::Kernel(payment_open),
                    Transaction::Kernel(bond_open),
                ],
                &allocations,
                batches,
            )
            .await
            .expect("both edges of the pairing open");
            let merkleized = batches.merkleize().await.expect("opens merkleize");
            database.finalize(merkleized).await;

            let mut mine = Channel::new(bond_edge, bond.clone(), payment_edge, terms.clone()
)
                .expect("mirrored pairing constructs the client channel");
            let mut theirs = Channel::new(bond_edge, bond, payment_edge, terms.clone()
)
                .expect("mirrored pairing constructs the provider channel");

            // Two honest jobs: E = 800, then E = 1_550. Both sides run
            // the same admission; the client issues, the provider
            // settles.
            let now = BlockHeight::new(1);
            let first = mine.job([7; 32], [8; 32], 800, BlockHeight::new(60));
            mine.admit(now, first).expect("client admits the first job");
            theirs
                .admit(now, first)
                .expect("provider admits the first job");
            let voucher = mine.issue(&client).expect("first frontier issues");
            let stale = voucher.clone();
            theirs
                .settle(now, voucher)
                .expect("provider settles the first job");

            let second = mine.job([7; 32], [8; 32], 750, BlockHeight::new(70));
            mine.admit(now, second)
                .expect("client admits the second job");
            theirs
                .admit(now, second)
                .expect("provider admits the second job");
            let voucher = mine.issue(&client).expect("second frontier issues");
            theirs
                .settle(now, voucher)
                .expect("provider settles the second job");
            assert_eq!(theirs.cumulative(), 1_550);
            assert_eq!(
                theirs.settle(now, stale),
                Err(SettleError::NoActiveJob),
                "a settled frontier has nothing further to settle",
            );

            let latest = theirs.frontier().expect("latest frontier").clone();
            let close = latest
                .redeem(&theirs, &provider)
                .expect("provider redeems the latest frontier");
            let batches = execute_all(
                context(2),
                &verifier,
                &[Transaction::Kernel(close)],
                &allocations,
                database.new_batches().await,
            )
            .await
            .expect("latest frontier redeems as a kernel Mutual");

            assert_eq!(
                batches
                    .get(&edge_object_id(payment_edge))
                    .await
                    .expect("edge read"),
                None,
            );
            let outputs = theirs
                .close_outputs(latest.cumulative)
                .expect("the frontier fits the capacity");
            let ids = KernelTx::close_output_ids(payment_edge, &outputs);
            let slots: Vec<_> = ids.as_slice().to_vec();
            assert_eq!(
                batches
                    .get(&coin_object_id(slots[0]))
                    .await
                    .expect("client refund read"),
                Some(Object::Coin(Coin {
                    owner: SettlementKey::from(client.party_key()),
                    value: FULL_GAME_CAPACITY - 1_550,
                })),
            );
            assert_eq!(
                batches
                    .get(&coin_object_id(slots[1]))
                    .await
                    .expect("provider earnings read"),
                Some(Object::Coin(Coin {
                    owner: SettlementKey::from(provider.party_key()),
                    value: 1_550,
                })),
            );
            let merkleized = batches.merkleize().await.expect("redemption merkleizes");
            database.finalize(merkleized).await;

            // The third job is defrauded: the provider signs a bad
            // terminal result (the receipt path, stood in for by its
            // signer here) and never gets a voucher. The client's fraud
            // exit slashes the real bond into the kernel-pinned shape,
            // with every byte of the close built by its own channel.
            let fraud = mine.job([7; 32], [8; 32], 450, BlockHeight::new(75));
            mine.admit(BlockHeight::new(2), fraud)
                .expect("client admits the third job");
            theirs
                .admit(BlockHeight::new(2), fraud)
                .expect("provider admits the third job");
            let digest = fraud.digest();
            let result = JobResultContext {
                acceptance: digest,
                transcript: [9; 32],
            };
            let artifact = FraudArtifact {
                acceptance: fraud,
                client_acceptance_sig: client.sign(digest),
                provider_acceptance_sig: provider.sign(digest),
                result,
                provider_result_sig: provider.sign(result.digest()),
            };
            let seal = verifier.preverified_seals().insert(artifact);
            let slash = mine.slash_close(seal);
            let batches = execute_all(
                context(3),
                &verifier,
                &[Transaction::Kernel(slash.clone())],
                &allocations,
                database.new_batches().await,
            )
            .await
            .expect("the channel-built violation close slashes the bond");

            assert_eq!(
                batches
                    .get(&edge_object_id(bond_edge))
                    .await
                    .expect("bond edge read"),
                None,
            );
            let KernelTx::Close { outputs, .. } = &slash else {
                panic!("slash close is a close");
            };
            let ids = KernelTx::close_output_ids(bond_edge, outputs);
            let slots: Vec<_> = ids.as_slice().to_vec();
            assert_eq!(
                batches
                    .get(&coin_object_id(slots[0]))
                    .await
                    .expect("client award read"),
                Some(Object::Coin(Coin {
                    owner: SettlementKey::from(client.party_key()),
                    value: FULL_GAME_AWARD,
                })),
            );
            assert_eq!(
                batches
                    .get(&coin_object_id(slots[1]))
                    .await
                    .expect("treasury remainder read"),
                Some(Object::Coin(Coin {
                    owner: SettlementKey::from(treasury),
                    value: FULL_GAME_STAKE - FULL_GAME_AWARD,
                })),
            );
        });
    }

    /// Slice-1 e2e fixture: a provider-funded bond opens under real
    /// signatures, a fraud artifact bound to that exact bond and job
    /// slashes it into the committed beneficiary/treasury payouts, and
    /// an artifact bound to a *different* bond edge cannot.
    #[test]
    fn preverified_seal_slashes_only_the_bound_bond_at_consensus_execution() {
        run_qmdb(|runtime| async move {
            let provider = signer(5);
            let client = signer(6);
            let treasury = signer(7).party_key();
            let terms = Terms::stake_bond(slash_fixture_bond_policy());

            let provider_coin = CoinId::from_bytes(genesis_object_id(0).0);
            let funding = Funding::new(
                List::take([provider_coin; MAX_PARTY_INPUTS], 1),
                List::take([provider_coin; MAX_PARTY_INPUTS], 0),
            );
            let open_hash = KernelTx::open_hash(&funding, &terms);
            let open = KernelTx::open(
                funding.clone(),
                terms.clone(),
                Auth::native(provider.sign(open_hash)),
                Auth::native(client.sign(open_hash)),
            );
            let bond_edge = KernelTx::edge_id_of(&funding, &terms);
            let allocations = vec![(SettlementKey::from(provider.party_key()), STAKE)];

            let verifier = ChainVerifier::new();
            let seals = verifier.preverified_seals();

            let config = utxo_db_config(&runtime, "staked_e2e", 1024, 8);
            let database = <UtxoDatabase<_> as DatabaseSet<_>>::init(runtime, config).await;
            let batches = database.new_batches().await;
            let batches = execute_all(
                context(1),
                &verifier,
                &[Transaction::Kernel(open)],
                &allocations,
                batches,
            )
            .await
            .expect("bond opens under the seal-capable dev verifier");
            let merkleized = batches.merkleize().await.expect("open merkleizes");
            database.finalize(merkleized).await;

            let outputs = two_payouts(
                Payout::new(client.party_key(), AWARD),
                Payout::new(treasury, STAKE - AWARD),
            );

            // An artifact naming a different bond edge yields a seal the
            // verifier resolves but refuses to bind here.
            let unbound = artifact_for(
                hellas_kernel::EdgeId::from_bytes([0xee; 32]),
                terms.hash(),
                &provider,
                &client,
            );
            let unbound_seal = seals.insert(unbound);
            let unbound_close = Transaction::Kernel(KernelTx::close(
                bond_edge,
                Proof::violation(terms.clone(), unbound_seal),
                outputs.clone(),
            ));
            let error = execute_all(context(2), &verifier, &[unbound_close], &allocations, {
                database.new_batches().await
            })
            .await
            .err()
            .expect("unbound artifact must not slash");
            assert_eq!(
                error,
                ExecutionError::KernelApply {
                    error: ApplyError::InvalidProof {
                        input: bond_edge,
                        reason: InvalidProofReason::BadSeal,
                    },
                }
            );

            // The bound artifact slashes into exactly the committed shape.
            let artifact = artifact_for(bond_edge, terms.hash(), &provider, &client);
            let seal = seals.insert(artifact);
            let close = Transaction::Kernel(KernelTx::close(
                bond_edge,
                Proof::violation(terms.clone(), seal),
                outputs.clone(),
            ));
            let batches = execute_all(context(2), &verifier, &[close], &allocations, {
                database.new_batches().await
            })
            .await
            .expect("bound artifact slashes the bond");

            assert_eq!(
                batches
                    .get(&edge_object_id(bond_edge))
                    .await
                    .expect("edge read"),
                None,
            );
            let ids = KernelTx::close_output_ids(bond_edge, &outputs);
            let slots: Vec<_> = ids.as_slice().to_vec();
            assert_eq!(
                batches
                    .get(&coin_object_id(slots[0]))
                    .await
                    .expect("client payout read"),
                Some(Object::Coin(Coin {
                    owner: SettlementKey::from(client.party_key()),
                    value: AWARD,
                })),
            );
            assert_eq!(
                batches
                    .get(&coin_object_id(slots[1]))
                    .await
                    .expect("treasury payout read"),
                Some(Object::Coin(Coin {
                    owner: SettlementKey::from(treasury),
                    value: STAKE - AWARD,
                })),
            );
        });
    }
}
