//! One channel's durable ledger: what survives a crash, what a restart
//! may still do, and what it may never do twice.
//!
//! Every crash here is a real one: the store is dropped, its files are
//! left exactly as they were, and a new store is opened over them. The
//! assertions are about the second process — never about what the first
//! one intended.

#![cfg(feature = "work")]

use hellas_kernel::{
    BlockHeight, EarnedCertificate, EdgeId, EdgeValues, Encode as _, Fees, List, MAX_EDGE_OUTPUTS,
    NetworkId, Parties, PayloadHash, Payout, Secp256k1Signer, Secp256k1Verifier, Sig, TermsHash,
    WorkPaymentSettlement, WorkPaymentTerms, WorkStakeBondTerms, work_payment_settlement,
};
use hellas_rpc::evaluate::{
    EvaluateOutputTranscriptBuilder, EvaluateStopReason, EvaluateTerminal, EvaluateUsage,
    input_commitment,
};
use hellas_rpc::protocol::artifacts::{
    BoundTermId, InputAddressed as _, OutputAddressed as _, PreparedPaidInputV1, SourceRef,
    TextArtifact, TextExecution, TextPolicy, TokenIds,
};
use hellas_rpc::protocol::work::{
    CreditLedger, PaidChannel, PaidChannelPolicyV1, PaidJobAuthorizationV1, PaidJobResultV1,
    PaidWorkError, PaymentBindingV1, PrivateRecord as _, decode_transcript, encode_transcript,
    next_payment, payment_binding_digest, prepared_input_digest, private_policy_commitment,
    result_digest, terminal_result, work_id,
};
use hellas_rpc::protocol::{ContentId, Digest};
use hellas_rpc::work_store::journal::{Journal, JournalError, JournalId, JournalKind};
use hellas_rpc::work_store::{
    ChannelRecord, ChannelStateError, ChannelStore, CounterpartyLoss, JobEnd, JobPhase, JobState,
    Role, WorkStoreError,
};
use hellas_rpc::{
    Assurance, Evaluate, EvaluateProgramManifest, EvaluateRequest, OutputEventEnvelope,
    ProducerSigningKey, ProgramManifest, PublicKey,
};

// ── Fixture ───────────────────────────────────────────────────────────

const HORIZON: u64 = 500;
const PRICE: u64 = 10;
/// Two jobs' worth of credit, and not three: a limit that is a multiple
/// of the price cannot tell "at the limit" from "one job short of it".
const COMPUTE_LIMIT: u64 = 25;
const DELIVERY_LIMIT: u64 = 25;
const OMISSION_BOND: u64 = 4;
const PAYMENT_VALUE: u64 = 1_000;
const SALT: [u8; 32] = [0x5a; 32];

fn network() -> NetworkId {
    let Some(network) = NetworkId::new("hellas-test") else {
        panic!("a short ascii id is a legal network id");
    };
    network
}

fn client() -> Secp256k1Signer {
    let Ok(signer) = Secp256k1Signer::from_secret_scalar([0x21; 32]) else {
        panic!("a fixed scalar is a key");
    };
    signer
}

fn provider() -> Secp256k1Signer {
    let Ok(signer) = Secp256k1Signer::from_secret_scalar([0x22; 32]) else {
        panic!("a fixed scalar is a key");
    };
    signer
}

fn channel_policy() -> PaidChannelPolicyV1 {
    limits(COMPUTE_LIMIT, DELIVERY_LIMIT)
}

const fn limits(compute: u64, delivery: u64) -> PaidChannelPolicyV1 {
    PaidChannelPolicyV1 {
        compute_credit_limit: compute,
        delivery_credit_limit: delivery,
    }
}

fn bond_terms() -> WorkStakeBondTerms {
    WorkStakeBondTerms {
        parties: Parties::new(provider().party_key(), client().party_key()),
        timeout: BlockHeight::new(HORIZON),
        timeout_outputs: List::take(
            [Payout::new(provider().party_key(), 64); MAX_EDGE_OUTPUTS],
            1,
        ),
        max_job_price: 40,
    }
}

fn terms_for(policy: PaidChannelPolicyV1) -> WorkPaymentTerms {
    WorkPaymentTerms {
        bond_edge: EdgeId::from_bytes([0xb0; 32]),
        bond_terms: bond_terms(),
        private_policy_commitment: private_policy_commitment(network(), &SALT, &policy),
        omit_response_blocks: hellas_kernel::MIN_OMIT_RESPONSE_BLOCKS,
        start_validity_blocks: 8,
        omission_bond: OMISSION_BOND,
    }
}

fn channel_on(payment_edge: EdgeId) -> PaidChannel {
    channel_with(payment_edge, channel_policy())
}

/// A channel whose credit policy is the one it commits to, so a test
/// can move one limit without moving the other.
fn channel_with(payment_edge: EdgeId, policy: PaidChannelPolicyV1) -> PaidChannel {
    match PaidChannel::new(network(), payment_edge, terms_for(policy), &SALT, policy) {
        Ok(channel) => channel,
        Err(error) => panic!("the fixture channel opens: {error}"),
    }
}

fn channel() -> PaidChannel {
    channel_on(EdgeId::from_bytes([0xe1; 32]))
}

fn settlement() -> WorkPaymentSettlement {
    let Some(settlement) =
        work_payment_settlement(EdgeValues::new(PAYMENT_VALUE, 0, Fees::ZERO), OMISSION_BOND)
    else {
        panic!("a funded edge prices both exits");
    };
    settlement
}

fn temp() -> tempfile::TempDir {
    match tempfile::tempdir() {
        Ok(dir) => dir,
        Err(error) => panic!("a temporary directory: {error}"),
    }
}

fn open(root: &std::path::Path, role: Role) -> ChannelStore {
    open_on(root, channel(), role)
}

fn open_on(root: &std::path::Path, channel: PaidChannel, role: Role) -> ChannelStore {
    match ChannelStore::open(root, channel, settlement(), role, &Secp256k1Verifier::new()) {
        Ok(store) => store,
        Err(error) => panic!("the fixture store opens: {error}"),
    }
}

fn payload(digest: Digest) -> PayloadHash {
    PayloadHash::from_bytes(digest.into_bytes())
}

// ── The prepared inputs a job executes from ───────────────────────────

fn manifest() -> ProgramManifest {
    ProgramManifest::Evaluate(EvaluateProgramManifest {
        weights: vec![ContentId::from_bytes([0x11; 32])],
        graph: ContentId::from_bytes([0x12; 32]),
        config: ContentId::from_bytes([0x13; 32]),
        tokenizer: ContentId::from_bytes([0x14; 32]),
        resolved_revision: "main".into(),
        numeric_profile: "f32-cpu".into(),
        backend_profile: "catena-v1".into(),
        build: ContentId::from_bytes([0x15; 32]),
    })
}

fn prompt_tokens() -> TokenIds {
    TokenIds::from([9, 8, 7, 6])
}

fn text_policy() -> TextPolicy {
    TextPolicy::from_u32_stop_tokens(64, [2, 1])
}

fn identity_artifact() -> TextArtifact {
    TextArtifact::identity(
        BoundTermId::from_digest(manifest().content_id().digest()),
        "test-model",
        "main",
        "f32",
    )
}

fn text_execution(nonce: u64) -> TextExecution {
    let _ = nonce;
    TextExecution::new(
        SourceRef::output(identity_artifact().output_id()),
        prompt_tokens().output_id(),
        text_policy().output_id(),
    )
}

/// One job's request. The nonce moves with the proposal nonce, so two
/// jobs on one channel are two different prepared bundles.
fn evaluate_request(nonce: u64) -> EvaluateRequest {
    let mut bytes = [0x77; 32];
    bytes[..8].copy_from_slice(&nonce.to_be_bytes());
    EvaluateRequest {
        text_execution: text_execution(nonce).input_id().digest(),
        runner_public_key: PublicKey::Secp256k1(client().party_key().to_bytes()),
        execution_environment: manifest().content_id(),
        nonce: bytes,
        assurance: Assurance::ProducerSigned,
        retain: true,
    }
}

fn bundle(nonce: u64) -> PreparedPaidInputV1 {
    PreparedPaidInputV1::new(
        &evaluate_request(nonce),
        &manifest(),
        &text_execution(nonce),
        &prompt_tokens(),
        &text_policy(),
        &identity_artifact(),
    )
}

fn bundle_bytes(nonce: u64) -> Vec<u8> {
    match bundle(nonce).encode() {
        Ok(bytes) => bytes,
        Err(error) => panic!("the fixture bundle encodes: {error}"),
    }
}

/// The provider's RPC producer identity: the same scalar its channel
/// party key is.
fn provider_producer() -> ProducerSigningKey {
    match ProducerSigningKey::from_secret_bytes([0x22; 32]) {
        Ok(key) => key,
        Err(error) => panic!("a fixed scalar is a producer key: {error}"),
    }
}

/// One complete signed transcript answering `request` with `answer`.
fn transcript_of(request: &EvaluateRequest, answer: &[u32]) -> Vec<OutputEventEnvelope> {
    let key = provider_producer();
    let mut builder =
        EvaluateOutputTranscriptBuilder::new(input_commitment(request), request.assurance, &key);
    if let Err(error) = builder.push_token_delta(answer.to_vec()) {
        panic!("a non-empty delta pushes: {error}");
    }
    let usage = EvaluateUsage {
        input_units: prompt_tokens().as_slice().len() as u64,
        output_units: answer.len() as u64,
    };
    let billable_units = match usage.billable_units() {
        Ok(units) => units,
        Err(error) => panic!("the fixture usage sums: {error}"),
    };
    match builder.finish(EvaluateTerminal {
        final_position: answer.len() as u64,
        stop_reason: EvaluateStopReason::END_OF_SEQUENCE,
        text_artifact: Digest::from_bytes([0x77; 32]),
        usage,
        billable_units,
    }) {
        Ok(events) => events,
        Err(error) => panic!("the fixture transcript finishes: {error}"),
    }
}

fn spool(transcript: &[OutputEventEnvelope]) -> Vec<u8> {
    match encode_transcript(transcript) {
        Ok(bytes) => bytes,
        Err(error) => panic!("the fixture transcript encodes: {error}"),
    }
}

/// Everything one job's records are built from, at one ledger position.
struct Job {
    authorization: PaidJobAuthorizationV1,
    work_id: Digest,
    result: PaidJobResultV1,
    transcript: Vec<OutputEventEnvelope>,
    binding: PaymentBindingV1,
    certificate: EarnedCertificate,
}

fn job_at(channel: &PaidChannel, nonce: u64, credited: u64) -> Job {
    let authorization = authorization_for(channel, nonce);
    let work_id = work_id(channel, &authorization);
    // The result is derived from a real transcript rather than made up:
    // the store rebuilds it from the stored events, so a hand-written
    // pair of digests is not a result any journal here would take.
    let transcript = transcript_of(&evaluate_request(nonce), &[101, 102, 103]);
    let result = match terminal_result(channel, &authorization, &transcript) {
        Ok(result) => result,
        Err(error) => panic!("the fixture transcript is a terminal: {error}"),
    };
    let (certificate, binding) =
        match next_payment(channel, &authorization, &result, credited, settlement()) {
            Ok(payment) => payment,
            Err(error) => panic!("the fixture payment builds: {error}"),
        };
    Job {
        authorization,
        work_id,
        result,
        transcript,
        binding,
        certificate,
    }
}

fn authorization_for(channel: &PaidChannel, nonce: u64) -> PaidJobAuthorizationV1 {
    let terms = channel.payment_terms();
    PaidJobAuthorizationV1 {
        channel_id: channel.id(),
        bond_edge: terms.bond_edge,
        bond_terms_hash: terms.bond_terms_hash(),
        payment_edge: channel.payment_edge(),
        payment_terms_hash: channel.payment_terms_hash(),
        execution_policy_digest: Digest::from_bytes([0x31; 32]),
        prepared_input_digest: match prepared_input_digest(channel, &bundle(nonce)) {
            Ok(digest) => digest,
            Err(error) => panic!("the fixture bundle hashes: {error}"),
        },
        proposal_nonce: nonce,
        acceptance_deadline: 100,
        request_commitment: Evaluate::commit_request(&evaluate_request(nonce)),
        environment_commitment: manifest().content_id(),
        price: PRICE,
        terminal_deadline: 200,
        payment_deadline: 300,
    }
}

impl Job {
    fn proposed(&self) -> ChannelRecord {
        ChannelRecord::JobProposed {
            authorization: self.authorization,
            client_signature: client().sign(payload(self.work_id)),
            prepared_input: bundle_bytes(self.authorization.proposal_nonce),
        }
    }

    fn accepted(&self) -> ChannelRecord {
        ChannelRecord::JobAccepted {
            provider_signature: provider().sign(payload(self.work_id)),
        }
    }

    fn result_record(&self, channel: &PaidChannel) -> ChannelRecord {
        ChannelRecord::JobResult {
            result: self.result,
            provider_signature: provider().sign(payload(result_digest(channel, &self.result))),
            transcript: spool(&self.transcript),
        }
    }

    fn paid(&self, channel: &PaidChannel) -> ChannelRecord {
        ChannelRecord::CertificateAdmitted {
            certificate: self.certificate,
            binding: self.binding,
            binding_signature: client()
                .sign(payload(payment_binding_digest(channel, &self.binding))),
            certificate_signature: client().sign(self.certificate.digest(channel.network())),
        }
    }
}

/// The provider's whole sequence for one job, in order.
fn provider_sequence(channel: &PaidChannel, job: &Job) -> Vec<ChannelRecord> {
    vec![
        job.proposed(),
        job.accepted(),
        ChannelRecord::JobRunning,
        job.result_record(channel),
        ChannelRecord::PlaintextReleased,
        job.paid(channel),
    ]
}

/// The client's whole sequence for the same job.
///
/// It opens with a cursor because a client records a receipt against a
/// finalized height: the terminal deadline is what a late delivery is
/// late against, and a journal with no processed block cannot say.
fn client_sequence(channel: &PaidChannel, job: &Job) -> Vec<ChannelRecord> {
    vec![
        cursor_at(RECEIPT_HEIGHT),
        job.proposed(),
        job.accepted(),
        job.result_record(channel),
        ChannelRecord::ResultVerified,
        job.paid(channel),
    ]
}

/// A finalized height inside every fixture job's terminal deadline.
const RECEIPT_HEIGHT: u64 = 150;

/// The payload digest of the synthetic block at `height`.
///
/// A cursor is contiguous, so a fixture that moves it has to name a
/// chain rather than repeat one digest: each block's parent is the last
/// block's payload, and the journal refuses anything else.
fn payload_at(height: u64) -> [u8; 32] {
    let mut payload = [0xc0; 32];
    for (slot, byte) in payload.iter_mut().zip(height.to_be_bytes()) {
        *slot = byte;
    }
    payload
}

fn cursor_at(height: u64) -> ChannelRecord {
    ChannelRecord::CursorAdvanced {
        height,
        parent: payload_at(height.saturating_sub(1)),
        payload: payload_at(height),
    }
}

/// Moves one store's cursor to `height`, one block at a time.
fn advance(store: &mut ChannelStore, height: u64) {
    let mut next = store.state().cursor().map_or(height, |(held, _)| held + 1);
    while next <= height {
        commit_all(store, &[cursor_at(next)]);
        next += 1;
    }
}

fn commit_all(store: &mut ChannelStore, records: &[ChannelRecord]) {
    let verifier = Secp256k1Verifier::new();
    for record in records {
        if let Err(error) = store.commit(record.clone(), &verifier) {
            panic!("the fixture record commits: {error}");
        }
    }
}

// ── The happy path ────────────────────────────────────────────────────

/// One paid job moves every ledger exactly once, and leaves nothing
/// reserved behind it.
#[test]
fn one_paid_job_moves_every_ledger_once() {
    let dir = temp();
    let channel = channel();
    let job = job_at(&channel, 1, 0);
    let mut store = open(dir.path(), Role::Provider);

    commit_all(&mut store, &provider_sequence(&channel, &job));

    let state = store.state();
    assert!(state.job().is_none(), "a paid job is closed");
    assert_eq!(state.ledger().credited_cumulative(), PRICE);
    assert!(
        state.ledger().has_paid_for(job.work_id),
        "and it is on the ledger's paid list, forever",
    );
    assert_eq!(state.max_executable_certificate(), PRICE);
    assert_eq!(
        state.compute_outstanding(),
        0,
        "credit is retired on payment"
    );
    assert_eq!(state.delivery_outstanding(), 0);
    assert_eq!(store.loss().compute, 0, "a paid job is not a loss");
    assert_eq!(store.loss().delivery, 0);
}

/// The same sequence on the client, which has a nonce to spend and no
/// credit ledgers of its own.
#[test]
fn the_client_credits_the_same_payment_it_signed() {
    let dir = temp();
    let channel = channel();
    let job = job_at(&channel, 1, 0);
    let mut store = open(dir.path(), Role::Client);

    assert_eq!(store.state().next_proposal_nonce(), 1);
    commit_all(&mut store, &client_sequence(&channel, &job));

    let state = store.state();
    assert_eq!(state.next_proposal_nonce(), 2, "the nonce is burnt");
    assert_eq!(state.ledger().credited_cumulative(), PRICE);
    assert!(state.job().is_none());
}

// ── A result is its transcript's own ──────────────────────────────────

/// A result must be the one its stored transcript produces.
///
/// Two mutations of the same pairing, each varying exactly one side of
/// it. Neither touches a signature: the second is signed correctly over
/// the result it carries, which is the whole point — a provider that
/// signs a result its own events do not summarise is refused by the
/// rebuild and not by a signature check.
#[test]
fn a_result_must_be_the_transcript_it_is_stored_beside() {
    let dir = temp();
    let channel = channel();
    let verifier = Secp256k1Verifier::new();
    let job = job_at(&channel, 1, 0);
    let mut store = open(dir.path(), Role::Provider);
    commit_all(
        &mut store,
        &[job.proposed(), job.accepted(), ChannelRecord::JobRunning],
    );

    // MUTATION: the same signed result, spooled beside a transcript of
    // a different answer to the same request.
    let other_answer = transcript_of(&evaluate_request(1), &[201, 202, 203]);
    let error = store
        .commit(
            ChannelRecord::JobResult {
                result: job.result,
                provider_signature: provider().sign(payload(result_digest(&channel, &job.result))),
                transcript: spool(&other_answer),
            },
            &verifier,
        )
        .expect_err("a result is not another answer's");
    assert!(
        matches!(
            error,
            WorkStoreError::Channel(ChannelStateError::WrongChannel {
                field: "result against its transcript"
            })
        ),
        "unexpected error: {error}"
    );

    // MUTATION: the same transcript, beside a result whose answer digest
    // is one byte other — and correctly signed over that other result.
    let mut altered = job.result;
    let mut digest = altered.canonical_output_digest.into_bytes();
    digest[0] ^= 1;
    altered.canonical_output_digest = Digest::from_bytes(digest);
    let error = store
        .commit(
            ChannelRecord::JobResult {
                result: altered,
                provider_signature: provider().sign(payload(result_digest(&channel, &altered))),
                transcript: spool(&job.transcript),
            },
            &verifier,
        )
        .expect_err("a transcript is not another result's");
    assert!(
        matches!(
            error,
            WorkStoreError::Channel(ChannelStateError::WrongChannel {
                field: "result against its transcript"
            })
        ),
        "unexpected error: {error}"
    );

    // The control: the pair that belongs together is taken, and the
    // stored bytes are the ones offered.
    if let Err(error) = store.commit(job.result_record(&channel), &verifier) {
        panic!("a result and its own transcript record: {error}");
    }
    let Some(open) = store.state().job() else {
        panic!("the job is open");
    };
    assert_eq!(open.phase(), JobPhase::Ready);
    assert_eq!(open.transcript(), spool(&job.transcript));
}

/// A restart finds the exact transcript the result was derived from.
///
/// This is what a spool is for: the process that computed the answer is
/// gone, and the one that comes back can still hand over the bytes it
/// was paid to produce — and can still show they rebuild the result it
/// signed.
#[test]
fn a_restart_finds_the_transcript_the_result_was_derived_from() {
    let dir = temp();
    let channel = channel();
    let job = job_at(&channel, 1, 0);
    {
        let mut store = open(dir.path(), Role::Provider);
        commit_all(&mut store, &provider_sequence(&channel, &job)[..4]);
    }

    let recovered = open(dir.path(), Role::Provider);
    let Some(open) = recovered.state().job() else {
        panic!("the job is still open");
    };
    assert_eq!(open.phase(), JobPhase::Ready);
    assert_eq!(open.transcript(), spool(&job.transcript));

    // And the bytes that came back are the answer, not merely bytes:
    // decoded and rebuilt here, independently of the store that read
    // them, they are the result the provider signed.
    let Ok(events) = decode_transcript(open.transcript(), 1 << 20) else {
        panic!("the recovered spool decodes");
    };
    assert_eq!(events, job.transcript);
    assert_eq!(
        terminal_result(&channel, &job.authorization, &events),
        Ok(job.result)
    );
}

// ── A receipt has a height, and a verdict is a step ───────────────────

/// A client records a receipt at the terminal deadline and not after it.
///
/// One block either side of the deadline the job was signed under, with
/// the cursor as the only thing varied.
#[test]
fn the_terminal_deadline_is_the_last_height_a_receipt_may_be_recorded_at() {
    let channel = channel();
    let job = job_at(&channel, 1, 0);
    let deadline = job.authorization.terminal_deadline;
    for (height, timely) in [(deadline, true), (deadline + 1, false)] {
        let dir = temp();
        let mut store = open(dir.path(), Role::Client);
        commit_all(
            &mut store,
            &[cursor_at(height), job.proposed(), job.accepted()],
        );
        let recorded = store.commit(job.result_record(&channel), &Secp256k1Verifier::new());
        if timely {
            if let Err(error) = recorded {
                panic!("a receipt at {height} is timely: {error}");
            }
            continue;
        }
        let Err(error) = recorded else {
            panic!("a receipt at {height} is late");
        };
        assert!(
            matches!(
                error,
                WorkStoreError::Channel(ChannelStateError::ReceiptLate {
                    height: found,
                    deadline: owed,
                }) if found == height && owed == deadline
            ),
            "unexpected error: {error}"
        );
    }
}

/// A client signs a payment at the payment deadline and not after it.
///
/// One block either side of the deadline the job was signed under, with
/// the cursor as the only thing varied. Past it the provider may end
/// this job as expired and charge its price to this client's loss
/// ledger, and a certificate signed then is money the provider can
/// still close on: the same job, paid for and charged for.
#[test]
fn the_payment_deadline_is_the_last_height_a_payment_may_be_signed_at() {
    let channel = channel();
    let job = job_at(&channel, 1, 0);
    let deadline = job.authorization.payment_deadline;
    for (height, timely) in [(deadline, true), (deadline + 1, false)] {
        let dir = temp();
        let mut store = open(dir.path(), Role::Client);
        let sequence = client_sequence(&channel, &job);
        commit_all(&mut store, &sequence[..5]);
        assert_eq!(
            store.state().job().map(JobState::phase),
            Some(JobPhase::Verified),
        );
        advance(&mut store, height);

        let paid = store.commit(job.paid(&channel), &Secp256k1Verifier::new());
        if timely {
            if let Err(error) = paid {
                panic!("a payment at {height} is timely: {error}");
            }
            assert_eq!(store.state().ledger().credited_cumulative(), PRICE);
            continue;
        }
        let Err(error) = paid else {
            panic!("a payment at {height} is late");
        };
        assert!(
            matches!(
                error,
                WorkStoreError::Channel(ChannelStateError::PaymentLate {
                    height: found,
                    deadline: owed,
                }) if found == height && owed == deadline
            ),
            "unexpected error: {error}"
        );
        assert_eq!(
            store.state().ledger().credited_cumulative(),
            0,
            "a refused payment credits nothing",
        );
    }
}

/// A client with no processed block records no receipt at all.
#[test]
fn a_client_that_has_processed_no_block_records_no_receipt() {
    let dir = temp();
    let channel = channel();
    let job = job_at(&channel, 1, 0);
    let mut store = open(dir.path(), Role::Client);
    commit_all(&mut store, &[job.proposed(), job.accepted()]);
    let error = store
        .commit(job.result_record(&channel), &Secp256k1Verifier::new())
        .expect_err("a receipt needs a height to be timely at");
    assert!(
        matches!(
            error,
            WorkStoreError::Channel(ChannelStateError::NoCursor {
                step: "recording a delivered result"
            })
        ),
        "unexpected error: {error}"
    );
}

/// A verdict is the client's step, and it needs a result to be about.
///
/// This is what keeps [`ChannelRecord::ResultVerified`] worth its tag.
/// Without the phase rule below, a client could record a verdict about
/// an answer that had not arrived, and the payment gate that reads it
/// would be gating on nothing.
#[test]
fn a_verdict_belongs_to_a_client_holding_a_result() {
    let dir = temp();
    let channel = channel();
    let verifier = Secp256k1Verifier::new();
    let job = job_at(&channel, 1, 0);

    // MUTATION: the provider's journal, which has no oracle.
    let mut provider_store = open(dir.path(), Role::Provider);
    commit_all(&mut provider_store, &provider_sequence(&channel, &job)[..4]);
    let error = provider_store
        .commit(ChannelRecord::ResultVerified, &verifier)
        .expect_err("a provider does not check its own answer");
    assert!(
        matches!(
            error,
            WorkStoreError::Channel(ChannelStateError::WrongRole {
                step: "recording an oracle verdict",
                expected: "client"
            })
        ),
        "unexpected error: {error}"
    );

    // MUTATION: a client's journal, one step before the result.
    let other = temp();
    let mut store = open(other.path(), Role::Client);
    let sequence = client_sequence(&channel, &job);
    commit_all(&mut store, &sequence[..3]);
    assert_eq!(
        store.state().job().map(JobState::phase),
        Some(JobPhase::Accepted)
    );
    let error = store
        .commit(ChannelRecord::ResultVerified, &verifier)
        .expect_err("there is nothing yet to have checked");
    assert!(
        matches!(
            error,
            WorkStoreError::Channel(ChannelStateError::WrongPhase {
                step: "recording an oracle verdict",
                phase: "accepted"
            })
        ),
        "unexpected error: {error}"
    );

    // The control: with the result recorded, the same step is taken —
    // and taken again is redundant rather than a second verdict.
    commit_all(&mut store, &sequence[3..5]);
    let before = store.len();
    if let Err(error) = store.commit(ChannelRecord::ResultVerified, &verifier) {
        panic!("a repeated verdict is the same verdict: {error}");
    }
    assert_eq!(store.len(), before, "and it is not written twice");
    assert_eq!(
        store.state().job().map(JobState::phase),
        Some(JobPhase::Verified)
    );
}

/// An unverified result is not paid for, whichever half of the channel
/// is asked.
///
/// The verdict is the only thing varied: the same delivered result, the
/// same signed payment, refused before it and taken after it.
#[test]
fn an_unverified_result_is_not_paid_for() {
    let dir = temp();
    let channel = channel();
    let verifier = Secp256k1Verifier::new();
    let job = job_at(&channel, 1, 0);
    let mut store = open(dir.path(), Role::Client);
    let sequence = client_sequence(&channel, &job);
    commit_all(&mut store, &sequence[..4]);
    assert_eq!(
        store.state().job().map(JobState::phase),
        Some(JobPhase::Ready)
    );

    // MUTATION: the payment offered with the verdict step skipped.
    let error = store
        .commit(job.paid(&channel), &verifier)
        .expect_err("a result nobody checked is not payable");
    assert!(
        matches!(
            error,
            WorkStoreError::Channel(ChannelStateError::WrongPhase {
                step: "crediting a payment",
                phase: "ready"
            })
        ),
        "unexpected error: {error}"
    );
    assert_eq!(store.state().ledger().credited_cumulative(), 0);

    // The control: with the verdict recorded, the same payment is taken.
    commit_all(&mut store, &[ChannelRecord::ResultVerified]);
    if let Err(error) = store.commit(job.paid(&channel), &verifier) {
        panic!("a checked result is paid for: {error}");
    }
    assert_eq!(store.state().ledger().credited_cumulative(), PRICE);
}

// ── The defect this phase exists to prevent ───────────────────────────

/// One job is paid for once: live, and after a restart.
///
/// This is the whole of P3, and it is the construction a review used to
/// break the invoice stack that stood here before: a *truthful* second
/// payment for a job already paid for. Nothing about it is malformed.
/// The work id is the same because the job is the same; the result is
/// the same because the provider signed one; the certificate is the one
/// this ledger's own arithmetic produces at the next cumulative. Read
/// alone it is indistinguishable from a second job, and the only thing
/// that can tell them apart is the record of what has been paid for.
///
/// The refusal is taken twice from the same rule and from two
/// different ledgers: one held in memory since the first payment, and
/// one no process kept — rebuilt by replaying the file a crashed
/// endpoint left behind. Neither of them is asked whether a job is open,
/// which is the point: the nonce rule and the phase rules would also
/// refuse this, and both are facts about the journal rather than about
/// the money. Those are checked below too, as the second and third
/// lines they are.
#[test]
fn one_job_is_paid_for_once_live_and_after_a_restart() {
    let dir = temp();
    let channel = channel();
    let verifier = Secp256k1Verifier::new();
    let first = job_at(&channel, 1, 0);

    {
        let mut store = open(dir.path(), Role::Provider);
        commit_all(&mut store, &provider_sequence(&channel, &first));
    }

    let mut recovered = open(dir.path(), Role::Provider);
    assert_eq!(recovered.state().ledger().credited_cumulative(), PRICE);

    // The second payment: the same job, the same result, at this
    // ledger's own next cumulative.
    let second = job_at(&channel, 1, PRICE);
    assert_eq!(
        second.binding.work_id, first.binding.work_id,
        "the same job, which is what makes this a second payment",
    );
    assert_eq!(second.binding.result_digest, first.binding.result_digest);
    assert_ne!(
        second.certificate, first.certificate,
        "and a fresh certificate, so nothing here is a replay of bytes",
    );
    assert_eq!(second.certificate.earned_cumulative(), 2 * PRICE);

    // Once live, from the ledger this process has held since the first
    // payment.
    let mut live = CreditLedger::new();
    if let Err(error) = live.credit_payment(
        &channel,
        &first.authorization,
        &first.result,
        &first.binding,
        &first.certificate,
        settlement(),
    ) {
        panic!("the first payment credits: {error}");
    }
    assert_eq!(live.credited_cumulative(), PRICE);
    assert!(live.has_paid_for(first.work_id));
    let refused = live.credit_payment(
        &channel,
        &second.authorization,
        &second.result,
        &second.binding,
        &second.certificate,
        settlement(),
    );
    assert_eq!(
        refused,
        Err(PaidWorkError::Duplicate { field: "work_id" }),
        "a job is paid for at most once",
    );
    assert_eq!(
        live.credited_cumulative(),
        PRICE,
        "and the refusal moved nothing",
    );

    // And once from a ledger nothing kept: this one exists only because
    // replaying the file rebuilt it.
    let mut reopened = recovered.state().ledger().clone();
    assert!(
        reopened.has_paid_for(first.work_id),
        "the paid job survives the crash",
    );
    let refused = reopened.credit_payment(
        &channel,
        &second.authorization,
        &second.result,
        &second.binding,
        &second.certificate,
        settlement(),
    );
    assert_eq!(
        refused,
        Err(PaidWorkError::Duplicate { field: "work_id" }),
        "across a restart as well",
    );
    assert_eq!(reopened.credited_cumulative(), PRICE);

    // The second line: the journal will not even re-open the job, since
    // the nonce that names it is spent.
    let error = recovered
        .commit(second.proposed(), &verifier)
        .expect_err("this nonce was already spent");
    assert!(
        matches!(
            error,
            WorkStoreError::Channel(ChannelStateError::Nonce { .. })
        ),
        "unexpected error: {error}"
    );

    // The third line: with a fresh nonce — a genuinely new job, offered
    // the paid job's own signed result and the transcript that produced
    // it — the reproduction rule refuses it before any ledger is asked.
    // Those events answer the first job's request commitment, so no
    // result at all can be rebuilt from them against this
    // authorization.
    let fresh = job_at(&channel, 2, PRICE);
    commit_all(
        &mut recovered,
        &[
            fresh.proposed(),
            fresh.accepted(),
            ChannelRecord::JobRunning,
        ],
    );
    let smuggled = ChannelRecord::JobResult {
        result: first.result,
        provider_signature: provider().sign(payload(result_digest(&channel, &first.result))),
        transcript: spool(&first.transcript),
    };
    let error = recovered
        .commit(smuggled, &verifier)
        .expect_err("a result for another job is not this job's");
    assert!(
        matches!(
            error,
            WorkStoreError::Channel(ChannelStateError::Record(PaidWorkError::Transcript(_)))
        ),
        "unexpected error: {error}"
    );
    assert_eq!(recovered.state().ledger().credited_cumulative(), PRICE);

    // The control: this job's own result and transcript are taken, so
    // what was refused above is the pairing and not the step.
    if let Err(error) = recovered.commit(fresh.result_record(&channel), &verifier) {
        panic!("this job's own result records: {error}");
    }
}

/// Re-sending the retained certificate after a crash is not a second
/// payment.
#[test]
fn re_sending_a_retained_payment_is_idempotent() {
    let dir = temp();
    let channel = channel();
    let job = job_at(&channel, 1, 0);
    {
        let mut store = open(dir.path(), Role::Client);
        commit_all(&mut store, &client_sequence(&channel, &job));
    }

    let mut recovered = open(dir.path(), Role::Client);
    let Some(retained) = recovered.state().last_payment() else {
        panic!("the payment is retained for re-sending");
    };
    assert_eq!(retained.certificate, job.certificate);
    assert_eq!(retained.binding, job.binding);
    // The job it paid for, kept beside the bytes: the payment closed
    // that job, so nothing else on this state can still name it.
    assert_eq!(retained.work_id, job.work_id);

    let before = recovered.len();
    if let Err(error) = recovered.commit(job.paid(&channel), &Secp256k1Verifier::new()) {
        panic!("re-sending the retained payment: {error}");
    }
    assert_eq!(recovered.len(), before, "nothing is written twice");
    assert_eq!(recovered.state().ledger().credited_cumulative(), PRICE);
}

// ── Crash points ──────────────────────────────────────────────────────

/// A crash after every write boundary, and what the next process holds.
///
/// The prefix is committed, the store is dropped without ceremony, and
/// a new one is opened over the same files. What is asserted is the
/// exact state — not that recovery "works".
#[test]
fn every_provider_write_boundary_recovers_to_one_state() {
    let channel = channel();
    let job = job_at(&channel, 1, 0);
    let sequence = provider_sequence(&channel, &job);

    let expected: Vec<(Option<JobPhase>, u64, u64, u64)> = vec![
        // phase, compute reserved, delivery reserved, credited
        (Some(JobPhase::HalfSigned), PRICE, 0, 0),
        (Some(JobPhase::Accepted), PRICE, 0, 0),
        (Some(JobPhase::Running), PRICE, 0, 0),
        (Some(JobPhase::Ready), PRICE, 0, 0),
        (Some(JobPhase::Delivered), PRICE, PRICE, 0),
        (None, 0, 0, PRICE),
    ];

    for (index, (phase, compute, delivery, credited)) in expected.into_iter().enumerate() {
        let dir = temp();
        {
            let mut store = open(dir.path(), Role::Provider);
            commit_all(&mut store, &sequence[..=index]);
        }
        let recovered = open(dir.path(), Role::Provider);
        let state = recovered.state();
        assert_eq!(
            state.job().map(hellas_rpc::work_store::JobState::phase),
            phase,
            "phase after {} records",
            index + 1
        );
        assert_eq!(
            state.compute_outstanding(),
            compute,
            "compute reserved after {} records",
            index + 1
        );
        assert_eq!(
            state.delivery_outstanding(),
            delivery,
            "delivery reserved after {} records",
            index + 1
        );
        assert_eq!(
            state.ledger().credited_cumulative(),
            credited,
            "credited after {} records",
            index + 1
        );
        assert_eq!(recovered.len(), index as u64 + 1);
    }
}

/// A half-signed job holds its reservation across a restart, and the
/// exact bytes the peer may already have.
#[test]
fn a_half_signed_job_keeps_its_reservation_and_its_bytes() {
    let dir = temp();
    let channel = channel();
    let job = job_at(&channel, 1, 0);
    {
        let mut store = open(dir.path(), Role::Provider);
        commit_all(&mut store, &[job.proposed()]);
    }

    let mut recovered = open(dir.path(), Role::Provider);
    let Some(open_job) = recovered.state().job() else {
        panic!("the half-signed job survives");
    };
    assert_eq!(open_job.phase(), JobPhase::HalfSigned);
    assert_eq!(*open_job.authorization(), job.authorization);
    assert_eq!(
        open_job.client_signature(),
        client().sign(payload(job.work_id)),
        "the client's exact signature is retained"
    );
    assert!(open_job.provider_signature().is_none());
    assert_eq!(recovered.state().compute_outstanding(), PRICE);

    // The peer re-sends what it sent before the crash: the same
    // proposal, not a second one.
    let before = recovered.len();
    if let Err(error) = recovered.commit(job.proposed(), &Secp256k1Verifier::new()) {
        panic!("an exact replay commits: {error}");
    }
    assert_eq!(recovered.len(), before);

    // The same nonce with different bytes is not a replay.
    let mut different = job.authorization;
    different.terminal_deadline = 201;
    let error = recovered
        .commit(
            ChannelRecord::JobProposed {
                authorization: different,
                client_signature: client().sign(payload(work_id(&channel, &different))),
                prepared_input: bundle_bytes(different.proposal_nonce),
            },
            &Secp256k1Verifier::new(),
        )
        .expect_err("a second job while one is open");
    assert!(
        matches!(
            error,
            WorkStoreError::Channel(ChannelStateError::WrongPhase { .. })
        ),
        "unexpected error: {error}"
    );
}

/// A crash between the running marker and the result is never resolved
/// by running it again, and never by accepting a result now.
#[test]
fn an_interrupted_invocation_stays_indeterminate() {
    let dir = temp();
    let channel = channel();
    let job = job_at(&channel, 1, 0);
    let verifier = Secp256k1Verifier::new();
    {
        let mut store = open(dir.path(), Role::Provider);
        commit_all(
            &mut store,
            &[job.proposed(), job.accepted(), ChannelRecord::JobRunning],
        );
    }

    let mut recovered = open(dir.path(), Role::Provider);
    assert!(recovered.state().is_indeterminate());
    let error = recovered
        .commit(job.result_record(&channel), &verifier)
        .expect_err("this process did not make that invocation");
    assert!(
        matches!(
            error,
            WorkStoreError::Channel(ChannelStateError::Indeterminate)
        ),
        "unexpected error: {error}"
    );

    // The only way out is an explicit ending, and the compute this
    // provider may have spent is the provider's own to bear: the client
    // ordered a job and was shown nothing, so its credit is untouched
    // and the channel is free to admit the next job.
    if let Err(error) = recovered.commit(
        ChannelRecord::JobEnded {
            reason: JobEnd::Indeterminate,
        },
        &verifier,
    ) {
        panic!("the ending commits: {error}");
    }
    assert!(!recovered.state().is_indeterminate());
    assert_eq!(recovered.state().compute_outstanding(), 0);
    assert_eq!(recovered.loss().compute, 0, "the provider bears this one");
    assert_eq!(recovered.loss().delivery, 0, "nothing was delivered");
}

/// A job the provider's own side failed costs this client nothing, at a
/// phase where the client's own silence would have cost it a price.
///
/// `loss_of`'s first question — whose fault — isolated from its second.
/// Every job here reaches the same phase, `Ready`: the result is signed,
/// so the *phase* half of the rule is satisfied and only the reason is
/// varied. The last one is the control, and it is charged.
///
/// The attack this refuses is a provider that accepts a client's work
/// and fails it, over and over, until that client's identity-wide credit
/// is spent and no honest provider will take it either. Two prices is
/// this channel's whole limit, and after four faults the fifth job is
/// admitted.
#[test]
fn a_provider_fault_is_not_the_clients_debt() {
    let dir = temp();
    let channel = channel_with(EdgeId::from_bytes([0xe6; 32]), limits(2 * PRICE, 2 * PRICE));
    let verifier = Secp256k1Verifier::new();
    let mut store = open_on(dir.path(), channel.clone(), Role::Provider);

    // Four jobs whose results were signed, and whose endings were the
    // provider's own side going wrong.
    for nonce in 1..=4 {
        let reason = if nonce % 2 == 0 {
            JobEnd::Failed
        } else {
            JobEnd::Indeterminate
        };
        let job = job_at(&channel, nonce, 0);
        commit_all(&mut store, &provider_sequence(&channel, &job)[..4]);
        assert_eq!(
            store.state().job().map(JobState::phase),
            Some(JobPhase::Ready),
            "the result is signed before this ending",
        );
        if let Err(error) = store.commit(ChannelRecord::JobEnded { reason }, &verifier) {
            panic!("the ending commits: {error}");
        }
        assert_eq!(store.loss().compute, 0, "ended as {reason}");
        assert_eq!(store.state().compute_outstanding(), 0);
    }

    // The control: the same phase, ended as the client's own silence, is
    // the client's debt — and it is the whole of what this channel then
    // has left.
    let expired = job_at(&channel, 5, 0);
    commit_all(&mut store, &provider_sequence(&channel, &expired)[..4]);
    if let Err(error) = store.commit(
        ChannelRecord::JobEnded {
            reason: JobEnd::Expired,
        },
        &verifier,
    ) {
        panic!("the ending commits: {error}");
    }
    assert_eq!(store.loss().compute, PRICE);
    assert_eq!(store.loss().delivery, 0, "the plaintext never left");
}

/// A job that expired while it was still running costs this client
/// nothing either.
///
/// `loss_of`'s second question, isolated from its first: this ending
/// *is* the one that can charge, and it does not, because the running
/// phase produced no result the client could have paid for. The
/// delivered control for the same reason is
/// `a_delivered_unpaid_job_is_loss_in_both_currencies`.
#[test]
fn a_job_that_expired_before_its_result_is_not_the_clients_debt() {
    let dir = temp();
    let channel = channel();
    let job = job_at(&channel, 1, 0);
    let mut store = open(dir.path(), Role::Provider);
    commit_all(
        &mut store,
        &[job.proposed(), job.accepted(), ChannelRecord::JobRunning],
    );
    if let Err(error) = store.commit(
        ChannelRecord::JobEnded {
            reason: JobEnd::Expired,
        },
        &Secp256k1Verifier::new(),
    ) {
        panic!("the ending commits: {error}");
    }
    assert_eq!(store.loss().compute, 0, "no result was ever signed");
    assert_eq!(store.state().compute_outstanding(), 0);
}

/// A job that never ran costs its counterparty nothing.
#[test]
fn an_expired_half_signed_job_releases_its_reservation_without_loss() {
    let dir = temp();
    let channel = channel();
    let job = job_at(&channel, 1, 0);
    let verifier = Secp256k1Verifier::new();
    let mut store = open(dir.path(), Role::Provider);
    commit_all(&mut store, &[job.proposed()]);
    assert_eq!(store.state().compute_outstanding(), PRICE);

    if let Err(error) = store.commit(
        ChannelRecord::JobEnded {
            reason: JobEnd::Expired,
        },
        &verifier,
    ) {
        panic!("the ending commits: {error}");
    }
    assert_eq!(store.state().compute_outstanding(), 0);
    assert_eq!(store.loss().compute, 0, "no compute was spent");

    // The nonce it burnt is not returned with the reservation.
    let same = job_at(&channel, 1, 0);
    let error = store
        .commit(same.proposed(), &verifier)
        .expect_err("an expired job's nonce stays burnt");
    assert!(
        matches!(
            error,
            WorkStoreError::Channel(ChannelStateError::Nonce { .. })
        ),
        "unexpected error: {error}"
    );
}

/// A delivered job that is never paid for is delivery loss as well as
/// compute loss.
#[test]
fn a_delivered_unpaid_job_is_loss_in_both_currencies() {
    let dir = temp();
    let channel = channel();
    let job = job_at(&channel, 1, 0);
    let mut store = open(dir.path(), Role::Provider);
    commit_all(
        &mut store,
        &provider_sequence(&channel, &job)[..5], // through plaintext release
    );
    if let Err(error) = store.commit(
        ChannelRecord::JobEnded {
            reason: JobEnd::Expired,
        },
        &Secp256k1Verifier::new(),
    ) {
        panic!("the ending commits: {error}");
    }
    assert_eq!(store.loss().compute, PRICE);
    assert_eq!(store.loss().delivery, PRICE);
    assert_eq!(store.state().compute_outstanding(), 0);
    assert_eq!(store.state().delivery_outstanding(), 0);
}

// ── Credit ────────────────────────────────────────────────────────────

/// The compute limit is checked at the boundary, one unit either side.
#[test]
fn compute_credit_bounds_what_may_be_co_signed() {
    let dir = temp();
    let channel = channel();
    let verifier = Secp256k1Verifier::new();
    let mut store = open(dir.path(), Role::Provider);

    // Two jobs fit inside 25; the third does not.
    for nonce in 1..=2 {
        let job = job_at(&channel, nonce, 0);
        commit_all(&mut store, &[job.proposed()]);
        if let Err(error) = store.commit(
            ChannelRecord::JobEnded {
                reason: JobEnd::Expired,
            },
            &verifier,
        ) {
            panic!("the ending commits: {error}");
        }
    }
    // Those two ended before they ran, so nothing is lost and nothing
    // is reserved: the limit is not consumed by a job that never
    // started.
    assert_eq!(store.loss().compute, 0);

    // Now spend the credit for real: two jobs whose results were signed
    // and whose deadlines then passed unpaid.
    for nonce in 3..=4 {
        let job = job_at(&channel, nonce, 0);
        commit_all(&mut store, &provider_sequence(&channel, &job)[..4]);
        if let Err(error) = store.commit(
            ChannelRecord::JobEnded {
                reason: JobEnd::Expired,
            },
            &verifier,
        ) {
            panic!("the ending commits: {error}");
        }
    }
    assert_eq!(store.loss().compute, 2 * PRICE);

    // 20 lost plus 10 more is 30, over the 25 this channel allows.
    let over = job_at(&channel, 5, 0);
    let error = store
        .commit(over.proposed(), &verifier)
        .expect_err("this client has spent its compute credit");
    let WorkStoreError::Channel(ChannelStateError::OverCredit {
        ledger,
        used,
        reserved,
        price,
        limit,
    }) = error
    else {
        panic!("unexpected error: {error}");
    };
    assert_eq!(
        (ledger, used, reserved, price, limit),
        ("compute", 20, 0, PRICE, COMPUTE_LIMIT)
    );
}

/// The delivery limit is checked before the plaintext leaves, and it is
/// the limit that stops it.
///
/// Compute is deliberately given room here: on the fixture channel both
/// limits are equal, so a delivery refusal would be indistinguishable
/// from the compute refusal that reaches the job first.
#[test]
fn delivery_credit_bounds_what_may_be_released() {
    let dir = temp();
    let channel = channel_with(
        EdgeId::from_bytes([0xe3; 32]),
        limits(1_000, DELIVERY_LIMIT),
    );
    let verifier = Secp256k1Verifier::new();
    let mut store = open_on(dir.path(), channel.clone(), Role::Provider);

    // Two delivered-and-unpaid jobs: 20 of the 25 delivery credit gone,
    // while compute has spent 20 of 1000.
    for nonce in 1..=2 {
        let job = job_at(&channel, nonce, 0);
        commit_all(&mut store, &provider_sequence(&channel, &job)[..5]);
        if let Err(error) = store.commit(
            ChannelRecord::JobEnded {
                reason: JobEnd::Expired,
            },
            &verifier,
        ) {
            panic!("the ending commits: {error}");
        }
    }
    assert_eq!(store.loss().delivery, 2 * PRICE);
    assert_eq!(store.loss().compute, 2 * PRICE);

    // The third job is accepted — compute has room — and runs. Only the
    // plaintext is refused.
    let third = job_at(&channel, 3, 0);
    commit_all(&mut store, &provider_sequence(&channel, &third)[..4]);
    let error = store
        .commit(ChannelRecord::PlaintextReleased, &verifier)
        .expect_err("this client has spent its delivery credit");
    let WorkStoreError::Channel(ChannelStateError::OverCredit {
        ledger,
        used,
        reserved,
        price,
        limit,
    }) = error
    else {
        panic!("unexpected error: {error}");
    };
    assert_eq!(
        (ledger, used, reserved, price, limit),
        ("delivery", 2 * PRICE, 0, PRICE, DELIVERY_LIMIT)
    );
    assert_eq!(
        store.state().delivery_outstanding(),
        0,
        "nothing was released"
    );

    // One unit of room is the difference between refusing and
    // releasing: the same job on a channel allowing 30 goes out.
    let roomy = channel_with(EdgeId::from_bytes([0xe4; 32]), limits(1_000, 3 * PRICE));
    let other = temp();
    let mut store = open_on(other.path(), roomy.clone(), Role::Provider);
    for nonce in 1..=2 {
        let job = job_at(&roomy, nonce, 0);
        commit_all(&mut store, &provider_sequence(&roomy, &job)[..5]);
        if let Err(error) = store.commit(
            ChannelRecord::JobEnded {
                reason: JobEnd::Expired,
            },
            &verifier,
        ) {
            panic!("the ending commits: {error}");
        }
    }
    let third = job_at(&roomy, 3, 0);
    commit_all(&mut store, &provider_sequence(&roomy, &third)[..5]);
    assert_eq!(store.state().delivery_outstanding(), PRICE);
}

/// Unresolved loss belongs to the counterparty, not to the channel it
/// was lost on — and it is still spent credit on the next channel.
#[test]
fn loss_outlives_the_channel_it_was_lost_on() {
    let dir = temp();
    let first = channel_on(EdgeId::from_bytes([0xe1; 32]));
    let verifier = Secp256k1Verifier::new();
    {
        let mut store = open_on(dir.path(), first.clone(), Role::Provider);
        for nonce in 1..=2 {
            let job = job_at(&first, nonce, 0);
            commit_all(&mut store, &provider_sequence(&first, &job)[..4]);
            if let Err(error) = store.commit(
                ChannelRecord::JobEnded {
                    reason: JobEnd::Expired,
                },
                &verifier,
            ) {
                panic!("the ending commits: {error}");
            }
        }
        assert_eq!(store.loss().compute, 2 * PRICE);
    }

    // The channel's own journal is deleted, as a rotation would.
    let Ok(entries) = std::fs::read_dir(dir.path()) else {
        panic!("the directory reads");
    };
    for entry in entries.filter_map(Result::ok) {
        if entry.path().to_string_lossy().contains("channel-")
            && let Err(error) = std::fs::remove_file(entry.path())
        {
            panic!("the channel journal is removable: {error}");
        }
    }

    // A fresh payment edge with the same client inherits the loss — and
    // the credit rule spends it: 20 lost plus 10 more is over the 25
    // this client is allowed.
    let second = channel_on(EdgeId::from_bytes([0xe2; 32]));
    let mut store = open_on(dir.path(), second.clone(), Role::Provider);
    assert_eq!(
        store.loss().compute,
        2 * PRICE,
        "a new channel does not reset what this client owes"
    );
    assert_eq!(store.state().ledger().credited_cumulative(), 0);

    let job = job_at(&second, 1, 0);
    let error = store
        .commit(job.proposed(), &verifier)
        .expect_err("this client's credit was spent on another channel");
    let WorkStoreError::Channel(ChannelStateError::OverCredit { used, limit, .. }) = error else {
        panic!("unexpected error: {error}");
    };
    assert_eq!((used, limit), (2 * PRICE, COMPUTE_LIMIT));
}

// ── A journal is read back as the journal it was written as ───────────

/// A journal accepted a record at a time is accepted whole.
///
/// Every prefix of one legal provider journal is reopened over the files
/// the first process left behind, and what the second process holds is
/// compared with what the first one held when it wrote that prefix's
/// last record. Both sequences drive one recorded loss to exactly its
/// limit — compute on the first channel, delivery on the second, since
/// they are two readings of one seed and a fix for either is a fix for
/// both. That is where a replay which re-checked each historical
/// reservation against the *final* loss total would refuse the file it
/// had itself written, record by legal record.
#[test]
fn a_journal_accepted_a_record_at_a_time_reopens_whole() {
    let channel = channel_with(EdgeId::from_bytes([0xe5; 32]), limits(2 * PRICE, 2 * PRICE));
    let verifier = Secp256k1Verifier::new();
    let first = job_at(&channel, 1, 0);
    let second = job_at(&channel, 2, 0);
    let sequence = vec![
        first.proposed(),
        first.accepted(),
        ChannelRecord::JobRunning,
        first.result_record(&channel),
        ChannelRecord::PlaintextReleased,
        // Delivered and never paid for: 10 of the 20 compute and 10 of
        // the 20 delivery this client is allowed.
        ChannelRecord::JobEnded {
            reason: JobEnd::Expired,
        },
        // 10 lost plus 10 more is 20, which is the compute limit and not
        // over it. This is the record the whole test is about.
        second.proposed(),
        second.accepted(),
        ChannelRecord::JobRunning,
        second.result_record(&channel),
        // And now the recorded compute loss *is* the limit.
        ChannelRecord::JobEnded {
            reason: JobEnd::Expired,
        },
    ];
    every_prefix_reopens_as_it_was(&channel, &sequence);

    // The same, with the room in the other currency: two delivered and
    // unpaid jobs put the recorded *delivery* loss exactly on its limit,
    // and the second release is the record checked at the boundary.
    let delivering = channel_with(
        EdgeId::from_bytes([0xea; 32]),
        limits(20 * PRICE, 2 * PRICE),
    );
    let third = job_at(&delivering, 1, 0);
    let fourth = job_at(&delivering, 2, 0);
    let mut delivered = Vec::new();
    for job in [&third, &fourth] {
        delivered.extend(provider_sequence(&delivering, job)[..5].to_vec());
        delivered.push(ChannelRecord::JobEnded {
            reason: JobEnd::Expired,
        });
    }
    every_prefix_reopens_as_it_was(&delivering, &delivered);

    // What the whole journal leaves is a channel with no credit left,
    // which is a refusal the endpoint makes when the next job arrives —
    // not one the file makes when it is opened.
    let dir = temp();
    {
        let mut store = open_on(dir.path(), channel.clone(), Role::Provider);
        commit_all(&mut store, &sequence);
    }
    let mut recovered = open_on(dir.path(), channel.clone(), Role::Provider);
    assert_eq!(recovered.loss().compute, 2 * PRICE, "the limit, exactly");
    let next = job_at(&channel, 3, 0);
    let error = recovered
        .commit(next.proposed(), &verifier)
        .expect_err("this client has spent its compute credit");
    let WorkStoreError::Channel(ChannelStateError::OverCredit {
        ledger,
        used,
        reserved,
        price,
        limit,
    }) = error
    else {
        panic!("unexpected error: {error}");
    };
    assert_eq!(
        (ledger, used, reserved, price, limit),
        ("compute", 2 * PRICE, 0, PRICE, 2 * PRICE)
    );
}

/// Reopens every prefix of one journal, and holds what the second
/// process reads against what the first one held when it wrote that
/// prefix's last record.
fn every_prefix_reopens_as_it_was(channel: &PaidChannel, sequence: &[ChannelRecord]) {
    let verifier = Secp256k1Verifier::new();
    for length in 1..=sequence.len() {
        let dir = temp();
        let (live, live_loss) = {
            let mut store = open_on(dir.path(), channel.clone(), Role::Provider);
            commit_all(&mut store, &sequence[..length]);
            (store.state().clone(), store.loss())
        };

        let recovered = match ChannelStore::open(
            dir.path(),
            channel.clone(),
            settlement(),
            Role::Provider,
            &verifier,
        ) {
            Ok(store) => store,
            Err(error) => panic!("the first {length} records reopen: {error}"),
        };
        assert_eq!(recovered.loss(), live_loss, "loss after {length} records");

        // The running marker is the one field a reopen may move: the
        // process that wrote it made the invocation, and the process
        // that reads it did not. `JobRunning` moves a phase and nothing
        // else, and the prefix one record shorter is compared whole.
        let running = live.job().map(JobState::phase) == Some(JobPhase::Running);
        assert_eq!(
            recovered.state().is_indeterminate(),
            running,
            "the marker after {length} records"
        );
        if running {
            assert_eq!(
                recovered.state().job().map(JobState::phase),
                Some(JobPhase::Running)
            );
            assert_eq!(
                recovered.state().compute_outstanding(),
                live.compute_outstanding()
            );
            assert_eq!(
                recovered.state().delivery_outstanding(),
                live.delivery_outstanding()
            );
        } else {
            assert_eq!(*recovered.state(), live, "state after {length} records");
        }
    }
}

/// The same property when the loss is not this channel's own.
///
/// A client that has defaulted elsewhere for more than this channel's
/// entire limit still has one legal journal here, and it still reads
/// back as itself. What that loss costs it is the next job, not the
/// history of this one.
#[test]
fn a_journal_reopens_when_the_clients_loss_has_passed_this_channels_limit() {
    let dir = temp();
    let verifier = Secp256k1Verifier::new();
    let narrow = channel_with(EdgeId::from_bytes([0xe6; 32]), limits(2 * PRICE, 2 * PRICE));
    let roomy = channel_with(
        EdgeId::from_bytes([0xe7; 32]),
        limits(20 * PRICE, 20 * PRICE),
    );

    // One whole job on the narrow channel, done and paid for while this
    // client owed nothing.
    let paid = job_at(&narrow, 1, 0);
    let live = {
        let mut store = open_on(dir.path(), narrow.clone(), Role::Provider);
        commit_all(&mut store, &provider_sequence(&narrow, &paid));
        store.state().clone()
    };

    // The same client then runs three jobs on the other channel and pays
    // for none. 30 lost is more than the narrow channel's whole 20 of
    // compute credit — and the loss ledger is the client's, not the
    // channel's, so the narrow channel's replay sees all of it.
    {
        let mut store = open_on(dir.path(), roomy.clone(), Role::Provider);
        for nonce in 1..=3 {
            let job = job_at(&roomy, nonce, 0);
            commit_all(&mut store, &provider_sequence(&roomy, &job)[..4]);
            if let Err(error) = store.commit(
                ChannelRecord::JobEnded {
                    reason: JobEnd::Expired,
                },
                &verifier,
            ) {
                panic!("the ending commits: {error}");
            }
        }
        assert_eq!(store.loss().compute, 3 * PRICE);
    }

    let mut recovered = match ChannelStore::open(
        dir.path(),
        narrow.clone(),
        settlement(),
        Role::Provider,
        &verifier,
    ) {
        Ok(store) => store,
        Err(error) => panic!("the narrow channel's journal reopens: {error}"),
    };

    // The loss is the one thing that must have moved: it is what this
    // client owes now, across every channel it has had.
    assert_eq!(recovered.loss().compute, 3 * PRICE);
    assert_eq!(recovered.state().loss().compute, 3 * PRICE);
    let state = recovered.state();
    assert_eq!(state.job(), live.job(), "the job it ended with");
    assert_eq!(state.ledger(), live.ledger(), "what it had credited");
    assert_eq!(
        state.max_executable_certificate(),
        live.max_executable_certificate()
    );
    assert_eq!(state.last_payment(), live.last_payment());
    assert_eq!(state.compute_outstanding(), live.compute_outstanding());
    assert_eq!(state.delivery_outstanding(), live.delivery_outstanding());
    assert_eq!(state.next_proposal_nonce(), live.next_proposal_nonce());
    assert_eq!(state.cursor(), live.cursor());
    assert!(!state.is_indeterminate());

    // And the credit rule the replay stopped applying to history still
    // applies to the next job.
    let next = job_at(&narrow, 2, PRICE);
    let error = recovered
        .commit(next.proposed(), &verifier)
        .expect_err("this client's credit was spent on another channel");
    let WorkStoreError::Channel(ChannelStateError::OverCredit { used, limit, .. }) = error else {
        panic!("unexpected error: {error}");
    };
    assert_eq!((used, limit), (3 * PRICE, 2 * PRICE));
}

/// A reservation the journal's own records forbid is refused on replay.
///
/// The other half of the property above, and what stops the loss replay
/// from being a fold nobody can see: a file that says on its face that
/// 20 was lost and then 10 more was reserved against a limit of 20 is
/// not a file any endpoint here wrote a record at a time, and it is not
/// read back whole. The judgement is made from this journal's own
/// records — never from a total that only existed later.
#[test]
fn replay_refuses_a_reservation_this_journals_own_losses_forbid() {
    let dir = temp();
    let channel = channel_with(EdgeId::from_bytes([0xe8; 32]), limits(2 * PRICE, 2 * PRICE));
    let verifier = Secp256k1Verifier::new();
    {
        let mut store = open_on(dir.path(), channel.clone(), Role::Provider);
        for nonce in 1..=2 {
            let job = job_at(&channel, nonce, 0);
            commit_all(&mut store, &provider_sequence(&channel, &job)[..4]);
            if let Err(error) = store.commit(
                ChannelRecord::JobEnded {
                    reason: JobEnd::Expired,
                },
                &verifier,
            ) {
                panic!("the ending commits: {error}");
            }
        }
        assert_eq!(store.loss().compute, 2 * PRICE, "the limit, exactly");
    }

    // A third proposal, correct in every other way — the client's real
    // signature, this channel's fields, a nonce nothing has spent —
    // written behind the store's back, because no store would take it.
    let third = job_at(&channel, 3, 0);
    {
        let (mut journal, replay) = match Journal::open(
            channel_journal(dir.path()),
            channel_journal_id(dir.path(), Role::Provider),
        ) {
            Ok(opened) => opened,
            Err(error) => panic!("the journal opens: {error}"),
        };
        assert_eq!(replay.records.len(), 10, "two jobs of five records");
        if let Err(error) = journal.append(&third.proposed().encode()) {
            panic!("the record appends: {error}");
        }
    }

    let error = ChannelStore::open(dir.path(), channel, settlement(), Role::Provider, &verifier)
        .expect_err("that reservation was never one this channel could make");
    let WorkStoreError::Channel(ChannelStateError::OverCredit {
        ledger,
        used,
        reserved,
        price,
        limit,
    }) = error
    else {
        panic!("unexpected error: {error}");
    };
    assert_eq!(
        (ledger, used, reserved, price, limit),
        ("compute", 2 * PRICE, 0, PRICE, 2 * PRICE)
    );
}

/// The journal id of the channel file the store wrote, taken from the
/// name it is stored under rather than from a second copy of the key
/// derivation, which could be wrong in the same way twice.
fn channel_journal_id(root: &std::path::Path, role: Role) -> JournalId {
    let path = channel_journal(root);
    let name = path.to_string_lossy().into_owned();
    let Some(hex) = name
        .rsplit_once("channel-")
        .and_then(|(_, rest)| rest.strip_suffix(".journal"))
    else {
        panic!("the channel journal is named channel-<key>.journal");
    };
    let mut key = [0_u8; 32];
    assert_eq!(hex.len(), 2 * key.len(), "the name carries a 32-byte key");
    for (byte, pair) in key.iter_mut().zip(hex.as_bytes().chunks_exact(2)) {
        let Ok(text) = std::str::from_utf8(pair) else {
            panic!("hex is ascii");
        };
        match u8::from_str_radix(text, 16) {
            Ok(value) => *byte = value,
            Err(error) => panic!("the name is hex: {error}"),
        }
    }
    JournalId {
        kind: JournalKind::Channel,
        role,
        key,
    }
}

/// A job whose loss is already on the disk goes no further than its
/// ending.
///
/// Ending a job writes two files, the loss first. The crash between them
/// leaves the loss counted and the job reading as open, and from there
/// the phase rules alone would let it be carried forward and paid for —
/// crediting the client for a job whose price stays in a ledger that
/// never gives anything back. The client would have paid *and* be short
/// of that much credit, for good.
#[test]
fn a_job_whose_loss_is_recorded_takes_no_step_but_its_ending() {
    let channel = channel();
    let verifier = Secp256k1Verifier::new();

    // Both crash points where a loss is already owed: after the result,
    // and after the release. The record offered next is the one the
    // interrupted process would have gone on to write.
    let cases: Vec<(&str, usize, u64, u64)> =
        vec![("ready", 4, PRICE, 0), ("delivered", 5, PRICE, PRICE)];

    for (label, prefix, compute, delivery) in cases {
        let dir = temp();
        let job = job_at(&channel, 1, 0);
        {
            let mut store = open(dir.path(), Role::Provider);
            commit_all(&mut store, &provider_sequence(&channel, &job)[..prefix]);
        }

        // Exactly what the interrupted commit left: the loss fsynced,
        // and no ending in the channel journal to match it.
        {
            let mut ledger = match CounterpartyLoss::open(
                dir.path(),
                network(),
                client().party_key(),
                Role::Provider,
            ) {
                Ok(ledger) => ledger,
                Err(error) => panic!("case {label}: the loss ledger opens: {error}"),
            };
            if let Err(error) = ledger.record(job.work_id, compute, delivery) {
                panic!("case {label}: the loss records: {error}");
            }
        }

        let mut recovered = open(dir.path(), Role::Provider);
        assert_eq!(recovered.loss().compute, compute, "case {label}");
        let Some(open_job) = recovered.state().job() else {
            panic!("case {label}: the job still reads as open");
        };
        assert_eq!(open_job.work_id(), job.work_id);

        let next = provider_sequence(&channel, &job)[prefix].clone();
        let before = recovered.len();
        let error = recovered
            .commit(next, &verifier)
            .expect_err("this job's ending was already decided");
        assert!(
            matches!(
                error,
                WorkStoreError::Channel(ChannelStateError::LossRecorded)
            ),
            "case {label}: unexpected error: {error}"
        );
        assert_eq!(recovered.len(), before, "case {label}: nothing is written");

        // The one step that is left, and the loss it already wrote is
        // counted once.
        if let Err(error) = recovered.commit(
            ChannelRecord::JobEnded {
                reason: JobEnd::Expired,
            },
            &verifier,
        ) {
            panic!("case {label}: the ending re-commits: {error}");
        }
        assert!(recovered.state().job().is_none(), "case {label}");
        assert_eq!(recovered.loss().compute, compute, "case {label}");
        assert_eq!(recovered.loss().delivery, delivery, "case {label}");
        assert_eq!(
            recovered.state().ledger().credited_cumulative(),
            0,
            "case {label}: nothing was paid for"
        );
    }
}

// ── What the store refuses ────────────────────────────────────────────

/// Every signature is checked against the party the channel names, over
/// that record's own digest.
#[test]
fn a_signature_from_the_wrong_party_is_not_evidence() {
    let dir = temp();
    let channel = channel();
    let verifier = Secp256k1Verifier::new();
    let job = job_at(&channel, 1, 0);

    let cases: Vec<(&str, Vec<ChannelRecord>, ChannelRecord)> = vec![
        (
            "the provider signing as the client",
            Vec::new(),
            ChannelRecord::JobProposed {
                authorization: job.authorization,
                client_signature: provider().sign(payload(job.work_id)),
                prepared_input: bundle_bytes(job.authorization.proposal_nonce),
            },
        ),
        (
            "the client signing as the provider",
            vec![job.proposed()],
            ChannelRecord::JobAccepted {
                provider_signature: client().sign(payload(job.work_id)),
            },
        ),
        (
            "a result signed over another digest",
            vec![job.proposed(), job.accepted(), ChannelRecord::JobRunning],
            ChannelRecord::JobResult {
                result: job.result,
                provider_signature: provider().sign(payload(job.work_id)),
                transcript: spool(&job.transcript),
            },
        ),
        (
            "a binding signed over another digest",
            provider_sequence(&channel, &job)[..5].to_vec(),
            ChannelRecord::CertificateAdmitted {
                certificate: job.certificate,
                binding: job.binding,
                binding_signature: client().sign(payload(job.work_id)),
                certificate_signature: client().sign(job.certificate.digest(network())),
            },
        ),
        (
            "a certificate the client did not sign",
            provider_sequence(&channel, &job)[..5].to_vec(),
            ChannelRecord::CertificateAdmitted {
                certificate: job.certificate,
                binding: job.binding,
                binding_signature: client()
                    .sign(payload(payment_binding_digest(&channel, &job.binding))),
                certificate_signature: provider().sign(job.certificate.digest(network())),
            },
        ),
    ];

    for (label, prefix, record) in cases {
        let dir = temp();
        let mut store = open(dir.path(), Role::Provider);
        commit_all(&mut store, &prefix);
        let before = store.len();
        let error = store
            .commit(record, &verifier)
            .expect_err("this signature is not the party's");
        assert!(
            matches!(
                error,
                WorkStoreError::Channel(ChannelStateError::BadSignature { .. })
            ),
            "case {label}: unexpected error: {error}"
        );
        assert_eq!(store.len(), before, "case {label}: nothing is written");
    }
    drop(dir);
}

/// A payment is the one this ledger position admits, or it is not
/// journaled at all.
///
/// Each case moves exactly one field of the honest payment and re-signs
/// whatever the move invalidated, so what refuses it is the arithmetic
/// and not a stale signature. The refusals name the field, which is
/// what makes this six checks rather than one that six inputs happen to
/// trip.
#[test]
fn a_payment_must_be_the_one_this_position_admits() {
    let channel = channel();
    let verifier = Secp256k1Verifier::new();
    let job = job_at(&channel, 1, 0);
    let elsewhere = Digest::from_bytes([0x5e; 32]);
    let other_edge = EdgeId::from_bytes([0x77; 32]);
    let other_terms = TermsHash::from_bytes([0x88; 32]);

    let bindings: Vec<(&str, &str, PaymentBindingV1)> = vec![
        (
            "a work id this journal never opened",
            "binding work_id",
            PaymentBindingV1 {
                work_id: elsewhere,
                ..job.binding
            },
        ),
        (
            "a result this provider never signed",
            "binding result_digest",
            PaymentBindingV1 {
                result_digest: elsewhere,
                ..job.binding
            },
        ),
        (
            "a binding that names some other certificate",
            "binding certificate_digest",
            PaymentBindingV1 {
                certificate_digest: PayloadHash::from_bytes([0x5e; 32]),
                ..job.binding
            },
        ),
    ];
    for (label, field, binding) in bindings {
        let dir = temp();
        let mut store = open(dir.path(), Role::Provider);
        commit_all(&mut store, &provider_sequence(&channel, &job)[..5]);
        let error = store
            .commit(
                ChannelRecord::CertificateAdmitted {
                    certificate: job.certificate,
                    binding,
                    binding_signature: client()
                        .sign(payload(payment_binding_digest(&channel, &binding))),
                    certificate_signature: client().sign(job.certificate.digest(network())),
                },
                &verifier,
            )
            .expect_err("this is not the payment the position admits");
        assert!(
            matches!(
                error,
                WorkStoreError::Channel(ChannelStateError::Record(PaidWorkError::Mismatch {
                    field: found
                })) if found == field
            ),
            "case {label}: unexpected error: {error}"
        );
    }

    let certificates: Vec<(&str, &str, EarnedCertificate)> = vec![
        (
            "an amount this ledger did not arrive at",
            "certificate earned_cumulative",
            EarnedCertificate::new(
                channel.payment_edge(),
                channel.payment_terms_hash(),
                PRICE + 1,
            ),
        ),
        (
            "another edge",
            "certificate payment_edge",
            EarnedCertificate::new(other_edge, channel.payment_terms_hash(), PRICE),
        ),
        (
            "another terms body",
            "certificate payment_terms_hash",
            EarnedCertificate::new(channel.payment_edge(), other_terms, PRICE),
        ),
    ];
    for (label, field, certificate) in certificates {
        let dir = temp();
        let mut store = open(dir.path(), Role::Provider);
        commit_all(&mut store, &provider_sequence(&channel, &job)[..5]);
        // The binding is left as the one this position expects, so the
        // check in front of the certificate passes and what refuses each
        // case is the certificate's own field. It is also the case that
        // check cannot see: an offered certificate that is not the one
        // the binding names.
        let error = store
            .commit(
                ChannelRecord::CertificateAdmitted {
                    certificate,
                    binding: job.binding,
                    binding_signature: client()
                        .sign(payload(payment_binding_digest(&channel, &job.binding))),
                    certificate_signature: client().sign(certificate.digest(network())),
                },
                &verifier,
            )
            .expect_err("this is not the payment the position admits");
        assert!(
            matches!(
                error,
                WorkStoreError::Channel(ChannelStateError::Record(PaidWorkError::Mismatch {
                    field: found
                })) if found == field
            ),
            "case {label}: unexpected error: {error}"
        );
    }
}

/// A record for another channel is not this channel's, whatever it is
/// signed with.
#[test]
fn a_record_for_another_channel_is_refused() {
    let dir = temp();
    let other = channel_on(EdgeId::from_bytes([0xe9; 32]));
    let verifier = Secp256k1Verifier::new();
    let mut store = open(dir.path(), Role::Provider);

    let elsewhere = job_at(&other, 1, 0);
    let error = store
        .commit(elsewhere.proposed(), &verifier)
        .expect_err("that authorization names another channel");
    assert!(
        matches!(
            error,
            WorkStoreError::Channel(ChannelStateError::WrongChannel { .. })
        ),
        "unexpected error: {error}"
    );
}

/// Role-scoped steps belong to one role.
#[test]
fn role_scoped_steps_belong_to_one_role() {
    let dir = temp();
    let channel = channel();
    let verifier = Secp256k1Verifier::new();
    let job = job_at(&channel, 1, 0);

    let mut client_store = open(dir.path(), Role::Client);
    commit_all(&mut client_store, &[job.proposed(), job.accepted()]);
    for record in [ChannelRecord::JobRunning, ChannelRecord::PlaintextReleased] {
        let error = client_store
            .commit(record, &verifier)
            .expect_err("that is a provider's step");
        assert!(
            matches!(
                error,
                WorkStoreError::Channel(ChannelStateError::WrongRole { .. })
            ),
            "unexpected error: {error}"
        );
    }
}

/// A channel spends nonce 1, then nonce 2, and never nonce 1 again.
///
/// One rule, run by both roles: the nonce a proposal carries must be
/// one this journal has not reached, and recording the proposal moves
/// the mark past it. It is the second half of what makes one `work_id`
/// open at most one job in this journal's life.
#[test]
fn a_proposal_nonce_is_spent_once_and_burnt_forever() {
    let dir = temp();
    let channel = channel();
    let verifier = Secp256k1Verifier::new();
    let mut store = open(dir.path(), Role::Client);
    assert_eq!(store.state().next_proposal_nonce(), 1);

    // Nonce 1, spent by the proposal that carries it.
    let first = job_at(&channel, 1, 0);
    commit_all(&mut store, &[first.proposed()]);
    assert_eq!(store.state().next_proposal_nonce(), 2);

    // The identical proposal is the retry after a lost send, and costs
    // nothing.
    let before = store.len();
    commit_all(&mut store, &[first.proposed()]);
    assert_eq!(store.len(), before, "an exact repeat writes nothing");

    // The half-signed job expires; the nonce does not come back.
    if let Err(error) = store.commit(
        ChannelRecord::JobEnded {
            reason: JobEnd::Expired,
        },
        &verifier,
    ) {
        panic!("the ending commits: {error}");
    }
    let error = store
        .commit(first.proposed(), &verifier)
        .expect_err("a spent nonce is not spent again");
    assert!(
        matches!(
            error,
            WorkStoreError::Channel(ChannelStateError::Nonce {
                expected: 2,
                actual: 1
            })
        ),
        "unexpected error: {error}"
    );

    // The next job uses nonce 2.
    let second = job_at(&channel, 2, 0);
    commit_all(&mut store, &[second.proposed()]);
    let Some(open_job) = store.state().job() else {
        panic!("the second job is open");
    };
    assert_eq!(open_job.authorization().proposal_nonce, 2);

    // The same rule on the provider's side, which never chose a nonce
    // and only ever sees the one a client's signature carries. A
    // forward jump is admitted; the number it jumped past is not.
    let other = temp();
    let mut provider_store = open(other.path(), Role::Provider);
    let seventh = job_at(&channel, 7, 0);
    commit_all(&mut provider_store, &[seventh.proposed()]);
    assert_eq!(provider_store.state().next_proposal_nonce(), 8);
    if let Err(error) = provider_store.commit(
        ChannelRecord::JobEnded {
            reason: JobEnd::Expired,
        },
        &verifier,
    ) {
        panic!("the ending commits: {error}");
    }
    let error = provider_store
        .commit(job_at(&channel, 3, 0).proposed(), &verifier)
        .expect_err("a nonce this journal has passed is not admitted");
    assert!(
        matches!(
            error,
            WorkStoreError::Channel(ChannelStateError::Nonce {
                expected: 8,
                actual: 3
            })
        ),
        "unexpected error: {error}"
    );
}

/// The finalized cursor moves to the next block, or it does not move.
///
/// Two rules, varied one at a time against the same held block. A
/// height that is not the next one is a block this endpoint never read;
/// a parent that is not the held payload is a block from a history it
/// never read. Either would let a watcher report progress it has not
/// made, and every deadline in this crate is measured against that
/// progress.
#[test]
fn the_cursor_only_moves_to_the_contiguous_next_block() {
    let dir = temp();
    let verifier = Secp256k1Verifier::new();
    let mut store = open(dir.path(), Role::Provider);
    commit_all(&mut store, &[cursor_at(7)]);
    assert_eq!(store.state().cursor(), Some((7, payload_at(7))));

    // Every height but the next one, with the parent left correct. The
    // repeated height carries a different payload, so it is a second
    // block at height seven rather than the retry answered below.
    for height in [7_u64, 6, 0, 9, 20] {
        let error = store
            .commit(
                ChannelRecord::CursorAdvanced {
                    height,
                    parent: payload_at(7),
                    payload: [0x99; 32],
                },
                &verifier,
            )
            .expect_err("only the next height moves the cursor");
        assert!(
            matches!(
                error,
                WorkStoreError::Channel(ChannelStateError::CursorNotNext {
                    held: 7,
                    actual,
                }) if actual == height
            ),
            "unexpected error at {height}: {error}"
        );
    }

    // The next height, and the only thing varied is the parent.
    let error = store
        .commit(
            ChannelRecord::CursorAdvanced {
                height: 8,
                parent: payload_at(6),
                payload: payload_at(8),
            },
            &verifier,
        )
        .expect_err("a block from another history does not extend this one");
    assert!(
        matches!(
            error,
            WorkStoreError::Channel(ChannelStateError::CursorNotContiguous { height: 8 })
        ),
        "unexpected error: {error}"
    );

    // The same two fields, correct: the cursor moves by exactly one.
    commit_all(&mut store, &[cursor_at(8)]);
    assert_eq!(store.state().cursor(), Some((8, payload_at(8))));

    // The same block again is the same fact.
    let before = store.len();
    commit_all(&mut store, &[cursor_at(8)]);
    assert_eq!(store.len(), before);
}

/// Two processes over one channel: the second fails before it can act.
#[test]
fn a_second_process_cannot_hold_the_same_channel() {
    let dir = temp();
    let held = open(dir.path(), Role::Provider);
    let error = ChannelStore::open(
        dir.path(),
        channel(),
        settlement(),
        Role::Provider,
        &Secp256k1Verifier::new(),
    )
    .expect_err("the journal is already held");
    assert!(
        matches!(error, WorkStoreError::Journal(JournalError::Locked { .. })),
        "unexpected error: {error}"
    );
    drop(held);
    let _ = open(dir.path(), Role::Provider);
}

/// A truncated journal is the state before the interrupted write; a
/// corrupt one is refused outright.
#[test]
fn a_corrupt_channel_journal_is_not_replayed_as_an_earlier_state() {
    let dir = temp();
    let channel = channel();
    let job = job_at(&channel, 1, 0);
    {
        let mut store = open(dir.path(), Role::Provider);
        commit_all(&mut store, &provider_sequence(&channel, &job));
    }
    let path = channel_journal(dir.path());
    let Ok(whole) = std::fs::read(&path) else {
        panic!("the journal reads");
    };

    // The undamaged file first, because a store that always reported a
    // tear would satisfy every assertion below: an operator told this
    // after a clean shutdown learns to ignore it, and then it is worth
    // nothing on the day it is true.
    let clean = open(dir.path(), Role::Provider);
    assert!(
        !clean.recovered_torn_tail(),
        "nothing was interrupted, and the whole sequence is here"
    );
    assert_eq!(clean.len(), provider_sequence(&channel, &job).len() as u64);
    drop(clean);

    // Interrupted inside the payment record: the payment never
    // happened, and the delivered job is still unpaid.
    if let Err(error) = std::fs::write(&path, &whole[..whole.len() - 40]) {
        panic!("the truncated journal writes: {error}");
    }
    let recovered = open(dir.path(), Role::Provider);
    assert_eq!(recovered.state().ledger().credited_cumulative(), 0);
    assert_eq!(
        recovered
            .state()
            .job()
            .map(hellas_rpc::work_store::JobState::phase),
        Some(JobPhase::Delivered)
    );
    drop(recovered);

    // A byte changed inside a complete frame.
    let mut corrupt = whole;
    if let Some(byte) = corrupt.get_mut(80) {
        *byte ^= 0xff;
    }
    if let Err(error) = std::fs::write(&path, &corrupt) {
        panic!("the corrupt journal writes: {error}");
    }
    let error = ChannelStore::open(
        dir.path(),
        channel,
        settlement(),
        Role::Provider,
        &Secp256k1Verifier::new(),
    )
    .expect_err("a corrupt frame is refused");
    assert!(
        matches!(error, WorkStoreError::Journal(JournalError::Corrupt { .. })),
        "unexpected error: {error}"
    );
}

/// A last frame the file ends inside is the write that was
/// interrupted, and only that.
///
/// The two shapes an append can leave the file ending inside: a short
/// prefix of the frame, which a dead process leaves, and a length field
/// that says the frame runs past the end of the file. Neither could
/// have been acknowledged — there is no complete frame there to have
/// acknowledged — so both truncate.
#[test]
fn an_append_the_file_ends_inside_is_removed() {
    let channel = channel();
    let job = job_at(&channel, 1, 0);
    let sequence = provider_sequence(&channel, &job);

    type Tear = fn(&mut Vec<u8>, (usize, usize));
    let damage: Vec<(&'static str, Tear)> = vec![
        (
            "a length field that is not a length",
            |bytes, (start, _)| {
                bytes[start..start + 4].copy_from_slice(&u32::MAX.to_be_bytes());
            },
        ),
        (
            "a frame the file stops nine bytes short of",
            |bytes, (_, end)| {
                bytes.truncate(end - 9);
            },
        ),
        (
            "a frame only its length field reached",
            |bytes, (start, _)| {
                bytes.truncate(start + 4);
            },
        ),
        (
            "a frame not even a whole length field reached",
            |bytes, (start, _)| {
                bytes.truncate(start + 2);
            },
        ),
    ];

    for (label, break_it) in damage {
        let dir = temp();
        let (path, starts) = frames_of(dir.path(), &channel, &sequence);
        let (Some(last), Some(end)) = (
            starts.get(starts.len() - 2).copied(),
            starts.last().copied(),
        ) else {
            panic!("case {label}: the journal has frames");
        };
        let Ok(mut bytes) = std::fs::read(&path) else {
            panic!("case {label}: the journal reads");
        };
        break_it(&mut bytes, (last, end));
        if let Err(error) = std::fs::write(&path, &bytes) {
            panic!("case {label}: the damaged journal writes: {error}");
        }

        let recovered = open(dir.path(), Role::Provider);
        assert!(
            recovered.recovered_torn_tail(),
            "case {label}: the tear is reported"
        );
        assert_eq!(
            recovered.len(),
            sequence.len() as u64 - 1,
            "case {label}: the interrupted record is gone"
        );
        // Which record: the payment. What is left is the state before
        // it, and it is a state this endpoint may still act from.
        assert_eq!(
            recovered
                .state()
                .job()
                .map(hellas_rpc::work_store::JobState::phase),
            Some(JobPhase::Delivered),
            "case {label}"
        );
        assert_eq!(
            recovered.state().ledger().credited_cumulative(),
            0,
            "case {label}"
        );
        // And the bytes are gone, not skipped: the next append lands
        // where the next frame's digest says it does.
        drop(recovered);
        let Ok(after) = std::fs::metadata(&path).map(|meta| meta.len()) else {
            panic!("case {label}: the journal is measurable");
        };
        assert_eq!(after, last as u64, "case {label}: truncated to the frame");
    }
}

/// A frame whose bytes are all there and whose digest is wrong is
/// refused, wherever in the file it is.
///
/// The position is what used to decide this, and it was the wrong
/// question. A frame that is long enough to be complete is a frame this
/// endpoint may have been told it had written — so truncating it drops
/// a record whose signature a peer may already hold, and the endpoint
/// comes back contradicting what it promised. Being unable to open is
/// the failure an operator can see.
///
/// Both positions are checked, and the last frame is the one that
/// matters: it is the only place the old rule differed.
#[test]
fn a_complete_frame_that_does_not_verify_is_refused_wherever_it_is() {
    let channel = channel();
    let job = job_at(&channel, 1, 0);
    let sequence = provider_sequence(&channel, &job);
    // The result record, with three frames still after it; and the
    // last record, with nothing after it at all.
    let last = sequence.len() - 1;

    for (label, break_it) in verifiable_damage() {
        for wounded in [3, last] {
            let dir = temp();
            let (path, starts) = frames_of(dir.path(), &channel, &sequence);
            let Ok(mut bytes) = std::fs::read(&path) else {
                panic!("case {label}: the journal reads");
            };
            break_it(&mut bytes, (starts[wounded], starts[wounded + 1]));
            if let Err(error) = std::fs::write(&path, &bytes) {
                panic!("case {label}: the damaged journal writes: {error}");
            }
            let error = ChannelStore::open(
                dir.path(),
                channel.clone(),
                settlement(),
                Role::Provider,
                &Secp256k1Verifier::new(),
            )
            .expect_err("a whole frame that does not verify is not a tear");
            assert!(
                matches!(error, WorkStoreError::Journal(JournalError::Corrupt { .. })),
                "case {label} at frame {wounded}: unexpected error: {error}"
            );
        }
    }

    // The one exception, and it is the price of reading a file by
    // following its length fields: a length that says the file ends
    // inside this frame cannot be seen past, so nothing after it is
    // found to contradict it. That case truncates, and takes records
    // this endpoint *was* told it had written with it. It is pinned
    // because it is real, not because it is wanted.
    let dir = temp();
    let (path, starts) = frames_of(dir.path(), &channel, &sequence);
    let Ok(mut bytes) = std::fs::read(&path) else {
        panic!("the journal reads");
    };
    unreadable_length(&mut bytes, (starts[3], starts[4]));
    if let Err(error) = std::fs::write(&path, &bytes) {
        panic!("the damaged journal writes: {error}");
    }
    let recovered = open(dir.path(), Role::Provider);
    assert!(recovered.recovered_torn_tail());
    assert_eq!(
        recovered.len(),
        3,
        "everything from the unreadable length onwards is gone"
    );
}

/// A creation interrupted inside the header is written again.
///
/// Nothing can have been recorded under half a header, so there is no
/// state to lose and nobody to disagree with — while refusing it as
/// another endpoint's file leaves a channel that cannot be opened by
/// the endpoint that just created it.
#[test]
fn a_journal_torn_inside_its_header_is_written_again() {
    let dir = temp();
    let channel = channel();
    let job = job_at(&channel, 1, 0);
    {
        let mut store = open(dir.path(), Role::Provider);
        commit_all(&mut store, &[job.proposed()]);
    }
    let path = channel_journal(dir.path());
    let Ok(whole) = std::fs::read(&path) else {
        panic!("the journal reads");
    };
    if let Err(error) = std::fs::write(&path, &whole[..10]) {
        panic!("the torn header writes: {error}");
    }

    let mut recovered = open(dir.path(), Role::Provider);
    assert!(recovered.recovered_torn_tail());
    assert!(recovered.is_empty(), "there was never a record under it");
    assert!(recovered.state().job().is_none());
    // And it is a journal again, not a file that half exists.
    if let Err(error) = recovered.commit(job.proposed(), &Secp256k1Verifier::new()) {
        panic!("the rewritten journal takes a record: {error}");
    }
    drop(recovered);
    assert_eq!(open(dir.path(), Role::Provider).len(), 1);

    // A file that is not a prefix of this header is still another
    // journal, and still refused.
    let mut foreign = whole;
    foreign[3] ^= 0xff;
    if let Err(error) = std::fs::write(&path, &foreign) {
        panic!("the foreign journal writes: {error}");
    }
    let error = ChannelStore::open(
        dir.path(),
        channel,
        settlement(),
        Role::Provider,
        &Secp256k1Verifier::new(),
    )
    .expect_err("that is not this endpoint's journal");
    assert!(
        matches!(
            error,
            WorkStoreError::Journal(JournalError::HeaderMismatch { .. })
        ),
        "unexpected error: {error}"
    );
}

/// What an interruption did to one frame, given where it starts and
/// where it ends.
type Damage = fn(&mut [u8], (usize, usize));

/// The two damages a reader can *see*: the frame is where its length
/// says it is, and it does not verify there.
fn verifiable_damage() -> Vec<(&'static str, Damage)> {
    vec![
        ("a hole punched through it", |bytes, (start, end)| {
            bytes[start + 4..end - Digest::LEN].fill(0);
        }),
        ("a digest its payload never had", |bytes, (_, end)| {
            bytes[end - Digest::LEN..end].fill(0xab);
        }),
    ]
}

/// The damage a reader cannot see past: a length that says the file
/// ends inside this frame.
fn unreadable_length(bytes: &mut [u8], (start, _): (usize, usize)) {
    bytes[start..start + 4].copy_from_slice(&u32::MAX.to_be_bytes());
}

/// Writes one journal a record at a time and returns where each frame
/// begins, measured rather than computed: the file's length before a
/// record is committed is where that record's frame starts.
fn frames_of(
    root: &std::path::Path,
    channel: &PaidChannel,
    records: &[ChannelRecord],
) -> (std::path::PathBuf, Vec<usize>) {
    let verifier = Secp256k1Verifier::new();
    let mut store = open_on(root, channel.clone(), Role::Provider);
    let path = channel_journal(root);
    let mut starts = Vec::new();
    for record in records {
        starts.push(file_len(&path));
        if let Err(error) = store.commit(record.clone(), &verifier) {
            panic!("the fixture record commits: {error}");
        }
    }
    starts.push(file_len(&path));
    (path, starts)
}

fn file_len(path: &std::path::Path) -> usize {
    match std::fs::metadata(path) {
        Ok(meta) => usize::try_from(meta.len()).unwrap_or(usize::MAX),
        Err(error) => panic!("the journal is measurable: {error}"),
    }
}

fn channel_journal(root: &std::path::Path) -> std::path::PathBuf {
    let Ok(entries) = std::fs::read_dir(root) else {
        panic!("the directory reads");
    };
    let Some(path) = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| path.to_string_lossy().contains("channel-"))
    else {
        panic!("the channel journal exists");
    };
    path
}

/// The loss ledger counts one job once, however often it is recorded,
/// and refuses to count it differently.
#[test]
fn one_jobs_loss_is_counted_once() {
    let dir = temp();
    let mut ledger =
        match CounterpartyLoss::open(dir.path(), network(), client().party_key(), Role::Provider) {
            Ok(ledger) => ledger,
            Err(error) => panic!("the loss ledger opens: {error}"),
        };
    let work = Digest::from_bytes([0x44; 32]);
    if let Err(error) = ledger.record(work, PRICE, 0) {
        panic!("the loss records: {error}");
    }
    if let Err(error) = ledger.record(work, PRICE, 0) {
        panic!("the same loss again is the same loss: {error}");
    }
    assert_eq!(ledger.totals().compute, PRICE);

    let error = ledger
        .record(work, PRICE + 1, 0)
        .expect_err("the same job cannot cost two amounts");
    assert!(
        matches!(
            error,
            WorkStoreError::Channel(ChannelStateError::Conflict { .. })
        ),
        "unexpected error: {error}"
    );
    assert_eq!(ledger.totals().compute, PRICE);
}

// ── The record codec ──────────────────────────────────────────────────

/// The codec is exact, and its field order is pinned by bytes rather
/// than by a round trip.
#[test]
fn the_record_codec_is_exact_and_ordered() {
    let channel = channel();
    let job = job_at(&channel, 1, 0);

    let cursor = ChannelRecord::CursorAdvanced {
        height: 0x0102_0304_0506_0708,
        parent: [0xaa; 32],
        payload: [0xab; 32],
    };
    let bytes = cursor.encode();
    // tag || height || parent || payload — the height first and
    // big-endian, and the two digests in that order. A round trip would
    // pass with them transposed; these bytes do not.
    let mut expected = vec![0_u8];
    expected.extend_from_slice(&0x0102_0304_0506_0708_u64.to_be_bytes());
    expected.extend_from_slice(&[0xaa; 32]);
    expected.extend_from_slice(&[0xab; 32]);
    assert_eq!(bytes, expected);
    assert_eq!(ChannelRecord::decode(&bytes), Ok(cursor));

    let start = hellas_kernel::PaymentCloseStart::new(
        channel.payment_edge(),
        hellas_kernel::Terms::work_payment(channel.payment_terms().clone()),
        hellas_kernel::Party::Taker,
        (11, 18),
        None,
        provider().sign(payload(job.work_id)),
    );
    let prepared = ChannelRecord::ClosePrepared {
        start: Box::new(start.clone()),
    };
    let bytes = prepared.encode();
    // tag || the kernel's own encoding of the start, and nothing else:
    // the journal holds the bytes consensus will read, not a second
    // spelling of them.
    let mut expected = vec![9_u8];
    let mut body = vec![0_u8; start.encoded_size()];
    let written = start.write_to(&mut body);
    body.truncate(written);
    expected.extend_from_slice(&body);
    assert_eq!(bytes, expected);
    assert_eq!(ChannelRecord::decode(&bytes), Ok(prepared));

    let opened = ChannelRecord::CloseOpened {
        start_id: hellas_kernel::StartId::from_bytes([0xcd; 32]),
    };
    let bytes = opened.encode();
    let mut expected = vec![10_u8];
    expected.extend_from_slice(&[0xcd; 32]);
    assert_eq!(bytes, expected);
    assert_eq!(ChannelRecord::decode(&bytes), Ok(opened));

    let settled = ChannelRecord::CloseSettled {
        height: 0x1112_1314_1516_1718,
        payload: [0xef; 32],
        provider_payout: 0x2122_2324_2526_2728,
    };
    let bytes = settled.encode();
    // tag || height || payload || provider payout. Two big-endian
    // `u64`s around one digest: a round trip would pass with them
    // exchanged, and these bytes would not.
    let mut expected = vec![11_u8];
    expected.extend_from_slice(&0x1112_1314_1516_1718_u64.to_be_bytes());
    expected.extend_from_slice(&[0xef; 32]);
    expected.extend_from_slice(&0x2122_2324_2526_2728_u64.to_be_bytes());
    assert_eq!(bytes, expected);
    assert_eq!(ChannelRecord::decode(&bytes), Ok(settled));

    // The nested bodies are their own canonical encodings, in the order
    // the record names them.
    let proposed = job.proposed();
    let bytes = proposed.encode();
    let mut expected = vec![1_u8];
    expected.extend_from_slice(&job.authorization.encode());
    expected.extend_from_slice(client().sign(payload(job.work_id)).as_bytes());
    expected.extend_from_slice(&bundle_bytes(1));
    assert_eq!(bytes, expected);
    assert_eq!(ChannelRecord::decode(&bytes), Ok(proposed));

    // The result record: body, then signature, then the transcript as
    // the whole of the rest.
    let recorded = job.result_record(&channel);
    let bytes = recorded.encode();
    let mut expected = vec![4_u8];
    expected.extend_from_slice(&job.result.encode());
    expected.extend_from_slice(
        provider()
            .sign(payload(result_digest(&channel, &job.result)))
            .as_bytes(),
    );
    expected.extend_from_slice(&spool(&job.transcript));
    assert_eq!(bytes, expected);
    assert_eq!(ChannelRecord::decode(&bytes), Ok(recorded));

    // The two records with no body at all are one byte each, and they
    // are not each other's.
    assert_eq!(ChannelRecord::JobRunning.encode(), vec![3_u8]);
    assert_eq!(ChannelRecord::PlaintextReleased.encode(), vec![5_u8]);
    assert_eq!(ChannelRecord::ResultVerified.encode(), vec![6_u8]);
    assert_eq!(ChannelRecord::decode(&[3]), Ok(ChannelRecord::JobRunning));
    assert_eq!(
        ChannelRecord::decode(&[5]),
        Ok(ChannelRecord::PlaintextReleased)
    );
    assert_eq!(
        ChannelRecord::decode(&[6]),
        Ok(ChannelRecord::ResultVerified)
    );

    let paid = job.paid(&channel);
    let bytes = paid.encode();
    let mut expected = vec![7_u8];
    let mut certificate = vec![0_u8; job.certificate.encoded_size()];
    let written = job.certificate.write_to(&mut certificate);
    certificate.truncate(written);
    expected.extend_from_slice(&certificate);
    expected.extend_from_slice(&job.binding.encode());
    expected.extend_from_slice(
        client()
            .sign(payload(payment_binding_digest(&channel, &job.binding)))
            .as_bytes(),
    );
    expected.extend_from_slice(client().sign(job.certificate.digest(network())).as_bytes());
    assert_eq!(bytes, expected);
    assert_eq!(
        bytes.len(),
        1 + EarnedCertificate::ENCODED_SIZE + PaymentBindingV1::ENCODED_SIZE + 2 * Sig::LENGTH
    );
    assert_eq!(ChannelRecord::decode(&bytes), Ok(paid));

    // Swapping the two client signatures is a different record, and a
    // reader that agreed with the layout only by round-tripping could
    // not see it.
    let swapped = ChannelRecord::CertificateAdmitted {
        certificate: job.certificate,
        binding: job.binding,
        binding_signature: client().sign(job.certificate.digest(network())),
        certificate_signature: client()
            .sign(payload(payment_binding_digest(&channel, &job.binding))),
    };
    assert_ne!(swapped.encode(), bytes);

    // Exactness.
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert_eq!(
        ChannelRecord::decode(&trailing),
        Err(ChannelStateError::Malformed)
    );
    assert_eq!(
        ChannelRecord::decode(&bytes[..bytes.len() - 1]),
        Err(ChannelStateError::Malformed)
    );
    assert_eq!(
        ChannelRecord::decode(&[12]),
        Err(ChannelStateError::Malformed)
    );
    assert_eq!(
        ChannelRecord::decode(&[]),
        Err(ChannelStateError::Malformed)
    );
}

/// The credited position survives the restart, and the next payment
/// starts from it.
///
/// The certificate that paid for job one is not a certificate that pays
/// for job two, and the ledger the journal rebuilt is what says so.
#[test]
fn the_next_payment_after_a_restart_starts_from_the_credited_total() {
    let dir = temp();
    let channel = channel();
    let verifier = Secp256k1Verifier::new();
    let first = job_at(&channel, 1, 0);
    {
        let mut store = open(dir.path(), Role::Provider);
        commit_all(&mut store, &provider_sequence(&channel, &first));
    }

    let mut recovered = open(dir.path(), Role::Provider);
    let second = job_at(&channel, 2, PRICE);
    commit_all(&mut recovered, &provider_sequence(&channel, &second)[..5]);

    // A payment for this job at the *old* credited position — the one
    // the first job's certificate settled — is refused on the amount.
    // The first job's own bytes are not offered here: those are the
    // retained payment, and re-sending them is idempotent by design.
    let stale = job_at(&channel, 2, 0);
    assert_eq!(stale.certificate.earned_cumulative(), PRICE);
    let error = recovered
        .commit(stale.paid(&channel), &verifier)
        .expect_err("that amount was already credited");
    assert!(
        matches!(
            error,
            WorkStoreError::Channel(ChannelStateError::Record(PaidWorkError::Mismatch {
                field: "certificate earned_cumulative"
            }))
        ),
        "unexpected error: {error}"
    );

    commit_all(&mut recovered, &[second.paid(&channel)]);
    assert_eq!(recovered.state().ledger().credited_cumulative(), 2 * PRICE);
    assert_eq!(recovered.state().max_executable_certificate(), 2 * PRICE);
    assert!(recovered.state().ledger().has_paid_for(first.work_id));
    assert!(recovered.state().ledger().has_paid_for(second.work_id));
}

/// Signatures are checked when the journal is read back, not only when
/// it is written.
#[test]
fn replay_checks_the_signatures_again() {
    let dir = temp();
    let channel = channel();
    let job = job_at(&channel, 1, 0);
    let forged = ChannelRecord::JobProposed {
        authorization: job.authorization,
        client_signature: provider().sign(payload(job.work_id)),
        prepared_input: bundle_bytes(job.authorization.proposal_nonce),
    };
    {
        let Ok(mut credulous) = ChannelStore::open(
            dir.path(),
            channel.clone(),
            settlement(),
            Role::Provider,
            &AcceptAll,
        ) else {
            panic!("the store opens");
        };
        if let Err(error) = credulous.commit(forged, &AcceptAll) {
            panic!("a credulous verifier accepts it: {error}");
        }
    }
    let error = ChannelStore::open(
        dir.path(),
        channel,
        settlement(),
        Role::Provider,
        &Secp256k1Verifier::new(),
    )
    .expect_err("the client never signed that");
    assert!(
        matches!(
            error,
            WorkStoreError::Channel(ChannelStateError::BadSignature { .. })
        ),
        "unexpected error: {error}"
    );
}

/// A verifier that accepts everything, so a test can write a journal
/// the real verifier will refuse.
struct AcceptAll;

impl hellas_kernel::SigVerifier for AcceptAll {
    fn verify_sig(&self, _sig: Sig, _key: hellas_kernel::Key, _hash: PayloadHash) -> bool {
        true
    }
}

/// A provider records a result only for an invocation it marked.
///
/// The marker is what makes the indeterminate case detectable at all: a
/// result accepted without one is a result whose invocation left no
/// trace, and after a crash there would be nothing to be indeterminate
/// about.
#[test]
fn a_result_needs_the_marker_that_says_the_backend_was_called() {
    let dir = temp();
    let channel = channel();
    let job = job_at(&channel, 1, 0);
    let mut store = open(dir.path(), Role::Provider);
    commit_all(&mut store, &[job.proposed(), job.accepted()]);

    let error = store
        .commit(job.result_record(&channel), &Secp256k1Verifier::new())
        .expect_err("nothing marked this job as invoked");
    assert!(
        matches!(
            error,
            WorkStoreError::Channel(ChannelStateError::WrongPhase { .. })
        ),
        "unexpected error: {error}"
    );
    assert_eq!(
        store
            .state()
            .job()
            .map(hellas_rpc::work_store::JobState::phase),
        Some(JobPhase::Accepted)
    );
}

/// The inputs a job executes from survive the crash, and are the ones
/// the authorization commits to.
///
/// The quote that carried them is transient. Without them a provider
/// that restarted after accepting could not execute the job it
/// accepted; with the wrong ones it would execute a job nobody signed.
#[test]
fn the_retained_dispatch_input_is_the_one_the_authorization_commits_to() {
    let dir = temp();
    let channel = channel();
    let job = job_at(&channel, 1, 0);
    {
        let mut store = open(dir.path(), Role::Provider);
        commit_all(&mut store, &[job.proposed(), job.accepted()]);
    }

    let recovered = open(dir.path(), Role::Provider);
    let Some(open_job) = recovered.state().job() else {
        panic!("the accepted job survives");
    };
    assert_eq!(open_job.prepared_input(), bundle_bytes(1).as_slice());
    // And they are a bundle, not opaque bytes that happen to be stored.
    if let Err(error) = PreparedPaidInputV1::decode(open_job.prepared_input(), 1 << 20) {
        panic!("the retained inputs are a bundle: {error}");
    }

    // MUTATION of exactly one thing: another job's bundle, under this
    // job's authorization and this job's real client signature.
    let other = temp();
    let mut fresh = open(other.path(), Role::Provider);
    let error = fresh
        .commit(
            ChannelRecord::JobProposed {
                authorization: job.authorization,
                client_signature: client().sign(payload(job.work_id)),
                prepared_input: bundle_bytes(2),
            },
            &Secp256k1Verifier::new(),
        )
        .expect_err("those are not the inputs the authorization names");
    assert!(
        matches!(error, WorkStoreError::Channel(ChannelStateError::Record(_))),
        "unexpected error: {error}"
    );
    assert!(fresh.state().job().is_none());

    // And bytes that are not a bundle at all.
    let error = fresh
        .commit(
            ChannelRecord::JobProposed {
                authorization: job.authorization,
                client_signature: client().sign(payload(job.work_id)),
                prepared_input: vec![0xff; 8],
            },
            &Secp256k1Verifier::new(),
        )
        .expect_err("that is not a prepared bundle");
    assert!(
        matches!(error, WorkStoreError::Channel(ChannelStateError::Record(_))),
        "unexpected error: {error}"
    );
}

/// Inputs swapped on the disk fault the journal rather than becoming a
/// job to execute.
///
/// The other half of the property above, and the one that matters to a
/// dispatch: an accepted job is executed from bytes nobody re-verifies
/// at dispatch time, so what makes them the right bytes is that opening
/// the file re-runs the same digest check that admitted them. A store
/// that only checked on commit would hand a restarted provider a job
/// its client never signed, and ask for no new signature to do it.
#[test]
fn inputs_swapped_on_the_disk_are_not_a_job_to_execute() {
    let channel = channel();
    let job = job_at(&channel, 1, 0);

    // Two journals written the same way, behind the store's back
    // because no store would take the second: the same authorization,
    // the same real client signature, and the same real co-signature
    // over the same work id. Only the bundle differs.
    for (bundle_nonce, readable) in [(1_u64, true), (2, false)] {
        let dir = temp();
        {
            // One store, opened and dropped, so the journal exists with
            // the name and header its key fixes.
            drop(open(dir.path(), Role::Provider));
        }
        let path = channel_journal(dir.path());
        if let Err(error) = std::fs::remove_file(&path) {
            panic!("the empty journal is removable: {error}");
        }
        {
            let id = JournalId {
                kind: JournalKind::Channel,
                role: Role::Provider,
                key: channel_key_bytes(&path),
            };
            let (mut journal, _) = match Journal::open(&path, id) {
                Ok(opened) => opened,
                Err(error) => panic!("the journal opens: {error}"),
            };
            for record in [
                ChannelRecord::JobProposed {
                    authorization: job.authorization,
                    client_signature: client().sign(payload(job.work_id)),
                    prepared_input: bundle_bytes(bundle_nonce),
                },
                ChannelRecord::JobAccepted {
                    provider_signature: provider().sign(payload(job.work_id)),
                },
            ] {
                if let Err(error) = journal.append(&record.encode()) {
                    panic!("the record appends: {error}");
                }
            }
        }

        let opened = ChannelStore::open(
            dir.path(),
            channel.clone(),
            settlement(),
            Role::Provider,
            &Secp256k1Verifier::new(),
        );
        if readable {
            match opened {
                Ok(store) => assert!(store.state().job().is_some(), "the job replays"),
                Err(error) => panic!("the journal this route wrote reopens: {error}"),
            }
            continue;
        }
        let Err(error) = opened else {
            panic!("those are not the inputs the authorization names");
        };
        assert!(
            matches!(error, WorkStoreError::Channel(ChannelStateError::Record(_))),
            "unexpected error: {error}"
        );
    }
}

/// The 32-byte key a channel journal's own file name carries.
///
/// Read from the name rather than derived a second time: a second
/// derivation could be wrong in the same way twice.
fn channel_key_bytes(path: &std::path::Path) -> [u8; 32] {
    let name = path.to_string_lossy().into_owned();
    let Some(hex) = name
        .rsplit_once("channel-")
        .and_then(|(_, rest)| rest.strip_suffix(".journal"))
    else {
        panic!("the channel journal is named channel-<key>.journal");
    };
    let mut key = [0_u8; 32];
    assert_eq!(hex.len(), 2 * key.len(), "the name carries a 32-byte key");
    for (byte, pair) in key.iter_mut().zip(hex.as_bytes().chunks_exact(2)) {
        let Ok(text) = std::str::from_utf8(pair) else {
            panic!("hex is ascii");
        };
        match u8::from_str_radix(text, 16) {
            Ok(value) => *byte = value,
            Err(error) => panic!("the name is hex: {error}"),
        }
    }
    key
}

// ── The close cutoff ──────────────────────────────────────────────────

/// A retained close start shuts the channel to new work.
///
/// A close is built from what is held when it is signed, so a job
/// admitted afterwards is a job whose payment that close could not
/// carry. There is no separate rule for certificates: a payment credits
/// the open job, and a close start is refused while there is one, so
/// the two are excluded by the same fact.
#[test]
fn a_retained_close_start_admits_no_further_work() {
    let dir = temp();
    let channel = channel();
    let verifier = Secp256k1Verifier::new();
    let mut store = open(dir.path(), Role::Provider);
    commit_all(&mut store, &[cursor_at(RECEIPT_HEIGHT)]);

    // One paid job, which is the only way this journal comes to hold a
    // certificate at all.
    let paid = job_at(&channel, 1, 0);
    commit_all(&mut store, &provider_sequence(&channel, &paid));
    assert_eq!(store.state().max_executable_certificate(), PRICE);

    let Ok(start) = hellas_rpc::work_close::close_start(
        &channel,
        hellas_kernel::Party::Taker,
        RECEIPT_HEIGHT,
        store.state().executable_certificate(),
        &provider(),
    ) else {
        panic!("a channel with a certificate builds a close start");
    };
    commit_all(
        &mut store,
        &[ChannelRecord::ClosePrepared {
            start: Box::new(start),
        }],
    );
    assert!(store.state().is_closing());

    let next = job_at(&channel, 2, PRICE);
    let error = store
        .commit(next.proposed(), &verifier)
        .expect_err("a job after the cutoff is refused");
    assert!(
        matches!(
            error,
            WorkStoreError::Channel(ChannelStateError::Closing {
                step: "proposing a job"
            })
        ),
        "unexpected error: {error}"
    );
    assert_eq!(
        store.state().max_executable_certificate(),
        PRICE,
        "and it moves nothing",
    );
    assert!(store.state().job().is_none());
}
