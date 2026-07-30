//! Staked fraud-game protocol vocabulary (v1: one finite epoch, one
//! challenge-live job at a time).
//!
//! Two long-lived edges per relationship: a payment channel (plain
//! `Terms::basic`, client = maker) advancing an off-chain signed
//! frontier, and a provider-funded stake bond (`Terms::StakeBond`) whose
//! `Violation` close slashes the stake into the committed
//! `[(client, award + surplus), (treasury, stake − award)]` shape — the
//! kernel pins that routing structurally.
//!
//! This module defines the job-binding contexts a violation seal must
//! prove itself against, and the dev-only preverified artifact cache the
//! `preverified-seals` verifier consults. The bond `EdgeId` is the epoch
//! identity: it is unforgeable and unique per (funding, terms), so
//! contexts bind it directly instead of carrying a separate epoch
//! counter.

use hellas_kernel::{
    Auth, BlockHeight, CloseKind, EdgeId, Encode, Key, List, MAX_EDGE_OUTPUTS, Parties,
    PayloadHash, Payout, Proof, ProtocolCode, Seal, SealPublicInputs, Secp256k1Signer,
    Secp256k1Verifier, Sig, SigVerifier as _, Terms, TermsHash, Tx as KernelTx, Writer as _,
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Protocol code for the optimistic payment channel (plain `Basic`
/// terms shape; client = maker funds capacity `B`, timeout refunds the
/// client).
pub const PAYMENT_PROTOCOL: ProtocolCode = ProtocolCode::new(2);
/// Protocol code for the provider stake bond.
pub const STAKE_BOND_PROTOCOL: ProtocolCode = ProtocolCode::new(3);

/// Builds the payment-channel terms: a `Basic` edge whose maker is the
/// client, whose taker is the provider, and whose timeout refunds the
/// entire close value to the client (the unilateral fallback when the
/// provider disappears — the client never signs a `Mutual` close, so
/// its own exit is `Timeout`).
///
/// `refund` must equal the edge's close value (locked capacity plus
/// timeout reserve surplus); the kernel rejects the open otherwise.
#[must_use]
pub fn payment_channel_terms(
    client: Key,
    provider: Key,
    timeout: BlockHeight,
    refund: u64,
) -> Terms {
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
    /// The exact close payouts: `[(client, total − E), (provider, E)]`.
    pub outputs: List<Payout, MAX_EDGE_OUTPUTS>,
    /// Maker authorization over the canonical kernel `Mutual` payload
    /// hash of exactly these outputs.
    pub client_auth: Auth,
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
        let refund = total.checked_sub(cumulative)?;
        let mut slots = [Payout::default(); MAX_EDGE_OUTPUTS];
        slots[0] = Payout::new(client.party_key(), refund);
        slots[1] = Payout::new(provider, cumulative);
        let outputs = List::take(slots, 2);
        let hash = KernelTx::payload_hash(payment_edge, CloseKind::Mutual, terms_hash, &outputs);
        Some(Self {
            payment_edge,
            terms_hash,
            cumulative,
            outputs,
            client_auth: Auth::native(client.sign(hash)),
        })
    }

    /// Provider-side redemption: adds the taker authorization and
    /// produces the executable kernel `Mutual` close. This is the only
    /// place provider authorization is created, and it never leaves the
    /// resulting transaction.
    #[must_use]
    pub fn redeem(&self, provider: &Secp256k1Signer) -> KernelTx {
        let hash = KernelTx::payload_hash(
            self.payment_edge,
            CloseKind::Mutual,
            self.terms_hash,
            &self.outputs,
        );
        KernelTx::close(
            self.payment_edge,
            Proof::mutual(self.client_auth.clone(), Auth::native(provider.sign(hash))),
            self.outputs.clone(),
        )
    }
}

/// Provider-side frontier bookkeeping: keeps only the latest voucher
/// and refuses regressions, cross-edge substitutions, and mismatched
/// terms.
#[derive(Debug, Clone, Default)]
pub struct VoucherBook {
    latest: Option<MakerVoucher>,
}

impl VoucherBook {
    /// Creates an empty book.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Accepts `voucher` iff it strictly advances the frontier on the
    /// same edge and terms. Returns false (book unchanged) otherwise.
    pub fn accept(&mut self, voucher: MakerVoucher) -> bool {
        if let Some(latest) = &self.latest {
            let advances = voucher.payment_edge == latest.payment_edge
                && voucher.terms_hash == latest.terms_hash
                && voucher.cumulative > latest.cumulative;
            if !advances {
                return false;
            }
        }
        self.latest = Some(voucher);
        true
    }

    /// The highest-`E` voucher accepted so far.
    #[must_use]
    pub const fn latest(&self) -> Option<&MakerVoucher> {
        self.latest.as_ref()
    }
}

/// Domain separator for [`JobAcceptanceContext::digest`].
const JOB_ACCEPTANCE_DOMAIN: &[u8] = b"hellas.staked.job_acceptance.v1";
/// Domain separator for [`JobResultContext::digest`].
const JOB_RESULT_DOMAIN: &[u8] = b"hellas.staked.job_result.v1";
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
    pub fn covered_by(&self, bond: &hellas_kernel::StakeBondTerms) -> bool {
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

/// The stake-bond party convention: the maker funds the stake.
#[must_use]
pub fn provider_key(parties: &hellas_kernel::Parties) -> Key {
    parties.maker()
}

/// The stake-bond party convention: the taker is the client and the
/// committed violation beneficiary.
#[must_use]
pub fn client_key(parties: &hellas_kernel::Parties) -> Key {
    parties.taker()
}

/// Dev-only preverified fraud-artifact cache, keyed by seal bytes.
///
/// Populated off the apply critical path (in tests and on dev chains,
/// directly); consulted by the `preverified-seals` verifier during
/// violation closes. Inserting an artifact asserts its fraud claim is
/// true — only the *binding* is re-checked at verify time.
#[derive(Debug, Clone, Default)]
pub struct PreverifiedSeals {
    inner: Arc<Mutex<HashMap<Seal, FraudArtifact>>>,
}

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
    #[test]
    fn option_one_economics_hold_for_the_committed_bond_shape() {
        // The shape the e2e fixtures commit.
        let stake = 1_000_u64; // S
        let award = 700_u64; // A
        let max_job_price = 500_u64;
        let max_dispute_cost = 200_u64;
        let price = 400_u64; // p_j of the fixture job
        let dispute_cost = 150_u64; // C_disp ≤ max_dispute_cost
        let honest_cost = 900_u64; // c_H
        let fraud_cost = 100_u64; // c_F

        // Provider IC: S ≥ c_H − c_F (p_j cancels — the provider keeps
        // its payment either way).
        assert!(stake >= honest_cost - fraud_cost);
        // Strict dispute incentive: A > C_disp.
        assert!(award > dispute_cost);
        // Conditional reimbursement: A ≥ p_j + C_disp, guaranteed for
        // every admissible job by the committed open-time floor.
        assert!(award >= max_job_price + max_dispute_cost);
        assert!(price <= max_job_price && dispute_cost <= max_dispute_cost);
        assert!(award >= price + dispute_cost);

        // The many-job cheat, priced honestly: the provider redeems the
        // frontier through job k, defrauds job k+1, still collects p_j,
        // and loses exactly S — never p_j + S. Its marginal payoff for
        // the fraudulent job is (p_j − c_F − S) vs the honest
        // (p_j − c_H); with the IC above, fraud is weakly worse.
        let fraud_payoff = i128::from(price) - i128::from(fraud_cost) - i128::from(stake);
        let honest_payoff = i128::from(price) - i128::from(honest_cost);
        assert_eq!(
            fraud_payoff - honest_payoff,
            i128::from(honest_cost) - i128::from(fraud_cost) - i128::from(stake),
        );
        assert!(fraud_payoff <= honest_payoff);
        // And the settlement delta on proven fraud is +p_j (payment
        // kept) − S (stake lost): p_j − S, matching what the kernel's
        // pinned payouts actually move.
        assert_eq!(
            i128::from(price) - i128::from(stake),
            i128::from(price) - i128::from(award) - i128::from(stake - award),
        );
    }

    /// Slice-1 e2e fixture: the client funds a payment channel, advances
    /// the frontier with asymmetric vouchers, and the provider redeems
    /// exactly the latest one as a kernel `Mutual` at consensus
    /// execution. Stale and cross-frontier vouchers die in the book;
    /// overdrafts cannot even be issued.
    #[test]
    fn provider_redeems_only_the_latest_frontier_at_consensus_execution() {
        const CAPACITY: u64 = 2_000;
        run_qmdb(|runtime| async move {
            let client = signer(11);
            let provider = signer(12);
            let terms = payment_channel_terms(
                client.party_key(),
                provider.party_key(),
                BlockHeight::new(100),
                CAPACITY,
            );
            let client_coin = CoinId::from_bytes(genesis_object_id(0).0);
            let funding = Funding::new(
                List::take([client_coin; MAX_PARTY_INPUTS], 1),
                List::take([client_coin; MAX_PARTY_INPUTS], 0),
            );
            let open_hash = KernelTx::open_hash(&funding, &terms);
            let open = KernelTx::open(
                funding.clone(),
                terms.clone(),
                Auth::native(client.sign(open_hash)),
                Auth::native(provider.sign(open_hash)),
            );
            let payment_edge = KernelTx::edge_id_of(&funding, &terms);
            let allocations = vec![(SettlementKey::from(client.party_key()), CAPACITY)];

            let verifier = ChainVerifier::new();
            let config = utxo_db_config(&runtime, "voucher_e2e", 1024, 8);
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
            .expect("payment channel opens");
            let merkleized = batches.merkleize().await.expect("open merkleizes");
            database.finalize(merkleized).await;

            // Two jobs' worth of frontier: E = 800, then E = 1550. The
            // client only ever signs; the provider only ever accumulates.
            let issue = |cumulative| {
                MakerVoucher::issue(
                    &client,
                    provider.party_key(),
                    payment_edge,
                    terms.hash(),
                    CAPACITY,
                    cumulative,
                )
            };
            let first = issue(800).expect("first frontier");
            let second = issue(1_550).expect("second frontier");
            assert!(issue(CAPACITY + 1).is_none(), "overdraft is unissuable");

            let mut book = VoucherBook::new();
            assert!(book.accept(first.clone()));
            assert!(book.accept(second));
            assert!(!book.accept(first), "stale frontier regression refused");
            let latest = book.latest().expect("latest frontier");
            assert_eq!(latest.cumulative, 1_550);

            let close = latest.redeem(&provider);
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
            let ids = KernelTx::close_output_ids(payment_edge, &latest.outputs);
            let slots: Vec<_> = ids.as_slice().to_vec();
            assert_eq!(
                batches
                    .get(&coin_object_id(slots[0]))
                    .await
                    .expect("client refund read"),
                Some(Object::Coin(Coin {
                    owner: SettlementKey::from(client.party_key()),
                    value: CAPACITY - 1_550,
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
            let parties = Parties::new(provider.party_key(), client.party_key());
            let terms = Terms::stake_bond(StakeBondTerms {
                protocol: STAKE_BOND_PROTOCOL,
                parties,
                timeout: BlockHeight::new(100),
                timeout_outputs: List::take(
                    [Payout::new(provider.party_key(), STAKE); MAX_EDGE_OUTPUTS],
                    1,
                ),
                treasury,
                award: AWARD,
                stake: STAKE,
                max_job_price: 500,
                max_dispute_cost: 200,
                challenge_margin: 20,
            });

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
