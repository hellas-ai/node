//! Spending the certificate: the cursor that makes a deadline mean
//! something, and the close that turns one signed scalar into coins.
//!
//! The job at the top of every fixture here is a real one — proposed,
//! co-signed, computed by a backend, delivered, checked and
//! paid over a live transport — because a close built from a
//! certificate this file invented would prove only that the arithmetic
//! composes. What it settles has to be what the earlier phases produced.
//!
//! What is not re-proved here. That the kernel accepts these bytes and
//! pays out these coins is `hellas-chain`'s
//! `endpoint_built_close_settles_on_a_real_chain`, against real blocks
//! and a real database. These tests are about what the endpoint retains
//! before it sends, what it refuses once it has, and what its watcher
//! does with the blocks that come back.

#![cfg(feature = "work")]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;
use hellas_kernel::{
    BlockHeight, Decode as _, Edge, EdgeId, EdgeValues, Fees, Key, LeaseSlots, List,
    MAX_EDGE_OUTPUTS, NetworkId, Parties, Party, PaymentCloseStart, Payout, PendingSlot,
    RegistryChunk, RegistryNamespace, RegistryRecordTag, Secp256k1Signer, Secp256k1Verifier, Terms,
    TermsHash, WorkPaymentSettlement, WorkPaymentTerms, WorkStakeBondTerms,
    work_payment_settlement,
};
use hellas_rpc::evaluate::{
    EvaluateOutputTranscriptBuilder, EvaluateStopReason, EvaluateTerminal, EvaluateUsage,
    input_commitment,
};
use hellas_rpc::pb::work::{
    AcceptWorkRequest, AcceptWorkResponse, WorkRefusalCode,
    accept_work_response::Outcome as AcceptOutcome,
};
use hellas_rpc::protocol::artifacts::{
    BoundTermId, Canonical as _, InputAddressed as _, OutputAddressed as _, PreparedPaidInputV1,
    SourceRef, TextArtifact, TextExecution, TextPolicy, TokenIds,
};
use hellas_rpc::protocol::work::{
    JobDeadlines, PaidChannelPolicyV1, PaidExecutionPolicyV1, PaidJobAuthorizationV1,
    PrivateRecord as _, generation_policy_digest, identity_source_digest,
    private_policy_commitment, propose_authorization, signing_hash, work_id,
};
use hellas_rpc::protocol::work_setup::{
    ObservedChannel, ReadyChannel, WorkChannelConfig, WorkChannelDescriptor, payment_terms_hash,
};
use hellas_rpc::protocol::{ContentId, Digest};
use hellas_rpc::services::work::{WorkClientImpl, WorkServer};
use hellas_rpc::work::{
    BackendFault, ClientEndpoint, PaidEvaluateBackend, PaymentError, ProviderEndpoint, RunOutcome,
    WorkService, admit_payment, fetch_result, run_accepted_work,
};
use hellas_rpc::work_close::{
    BlockSourceError, CatchUpError, CloseError, FinalizedBlocks, FinalizedWork, close_start,
    observe, start_body_digest,
};
use hellas_rpc::work_store::{
    ChannelRecord, ChannelStore, CloseSettlement, JobPhase, JobState, Role, SetupOrigin,
};
use hellas_rpc::{
    Assurance, EvaluateProgramManifest, EvaluateRequest, OutputEventEnvelope, ProducerSigningKey,
    ProgramManifest, PublicKey,
};
use hellas_wire::mux::{MessagePipe, MuxConfig, MuxTransport, Role as MuxRole};
use hellas_wire::{DefaultClock, Dispatcher, StreamTransport};
use tokio::sync::mpsc;

/// The one proposal nonce every job in this file carries.
const NONCE: u8 = 1;

// ── Fixture ───────────────────────────────────────────────────────────

const HORIZON: u64 = 500;
const PRICE: u64 = 10;
const CREDIT_LIMIT: u64 = 40;
const OMISSION_BOND: u64 = 4;
const PAYMENT_VALUE: u64 = 1_000;
const PAYMENT_RESERVE: u64 = 200;
const STAKE: u64 = 64;
const SALT: [u8; 32] = [0x5a; 32];
const Q: u64 = 999_000;
const COST_CAP: u64 = 1;
/// The finalized block both endpoints have processed through.
const CURSOR: u64 = 10;
/// The prompt this fixture's bundle carries, in tokens.
const PROMPT_TOKENS: u64 = 4;
/// A frame bound no legal delivery here comes close to.
const WIDE_FRAME: u32 = 262_144;

const fn deadlines() -> JobDeadlines {
    JobDeadlines {
        acceptance: 50,
        terminal: 100,
        payment: 200,
    }
}

fn network() -> NetworkId {
    let Some(network) = NetworkId::new("hellas-test") else {
        panic!("a short ascii id is a legal network id");
    };
    network
}

fn client() -> Secp256k1Signer {
    signer(0x21)
}

fn provider() -> Secp256k1Signer {
    signer(0x22)
}

fn signer(byte: u8) -> Secp256k1Signer {
    let Ok(signer) = Secp256k1Signer::from_secret_scalar([byte; 32]) else {
        panic!("a fixed scalar is a key");
    };
    signer
}

fn provider_producer() -> ProducerSigningKey {
    match ProducerSigningKey::from_secret_bytes([0x22; 32]) {
        Ok(key) => key,
        Err(error) => panic!("a fixed scalar is a producer key: {error}"),
    }
}

fn bond_edge() -> EdgeId {
    EdgeId::from_bytes([0x11; EdgeId::LENGTH])
}

fn payment_edge() -> EdgeId {
    EdgeId::from_bytes([0x22; EdgeId::LENGTH])
}

fn channel_policy() -> PaidChannelPolicyV1 {
    PaidChannelPolicyV1 {
        compute_credit_limit: CREDIT_LIMIT,
        delivery_credit_limit: CREDIT_LIMIT,
    }
}

fn bond_terms() -> WorkStakeBondTerms {
    WorkStakeBondTerms {
        parties: Parties::new(provider().party_key(), client().party_key()),
        timeout: BlockHeight::new(HORIZON),
        timeout_outputs: List::take(
            [Payout::new(provider().party_key(), STAKE); MAX_EDGE_OUTPUTS],
            1,
        ),
        max_job_price: 40,
    }
}

fn payment_terms() -> WorkPaymentTerms {
    WorkPaymentTerms {
        bond_edge: bond_edge(),
        bond_terms: bond_terms(),
        private_policy_commitment: private_policy_commitment(network(), &SALT, &channel_policy()),
        omit_response_blocks: hellas_kernel::MIN_OMIT_RESPONSE_BLOCKS,
        start_validity_blocks: 8,
        omission_bond: OMISSION_BOND,
    }
}

/// The execution policy every job here runs under.
fn execution_policy() -> PaidExecutionPolicyV1 {
    PaidExecutionPolicyV1 {
        allowed_environment: manifest().content_id(),
        generation_policy_digest: match generation_policy_digest(&text_policy().canonical_bytes()) {
            Ok(digest) => digest,
            Err(error) => panic!("the fixture policy hashes: {error}"),
        },
        identity_source_digest: match identity_source_digest(&identity_artifact().canonical_bytes())
        {
            Ok(digest) => digest,
            Err(error) => panic!("the fixture identity hashes: {error}"),
        },
        max_prompt_tokens: 512,
        max_new_tokens: 128,
        max_stop_token_ids: 4,
        max_canonical_output_bytes: 65_536,
        max_spool_bytes: 1_048_576,
        max_encoded_result_frame: WIDE_FRAME,
        max_encoded_quote_response: 1_048_576,
        dispatch_margin_blocks: 4,
        delivery_margin_blocks: 2,
        oracle_grace_blocks: 6,
        fixed_price: PRICE,
    }
}

fn payment_values() -> EdgeValues {
    EdgeValues::new(PAYMENT_VALUE, PAYMENT_RESERVE, Fees::new(0, 0, 0, 0))
}

fn descriptor() -> WorkChannelDescriptor {
    let config = WorkChannelConfig {
        network: network(),
        payment_edge: payment_edge(),
        payment_terms: payment_terms(),
        policy_salt: SALT,
        channel_policy: channel_policy(),
        execution_policy: execution_policy(),
        expected_payment_values: payment_values(),
        omission_response_probability: Q,
        omission_response_cost_cap: COST_CAP,
    };
    match WorkChannelDescriptor::open(config) {
        Ok(descriptor) => descriptor,
        Err(error) => panic!("the fixture channel opens: {error}"),
    }
}

/// The channel, ready at the height both endpoints have processed
/// through.
fn ready() -> ReadyChannel {
    let bond = bond_object();
    let payment = payment_object();
    let observed = ObservedChannel {
        height: CURSOR,
        bond: Some(&bond),
        payment: Some(&payment),
        lease: lease_over(bond_edge(), payment_edge()),
        pending: PendingSlot::Absent,
    };
    match descriptor().check_ready(&observed) {
        Ok(ready) => ready,
        Err(error) => panic!("the fixture channel is ready: {error}"),
    }
}

fn settlement() -> WorkPaymentSettlement {
    let Some(settlement) = work_payment_settlement(payment_values(), OMISSION_BOND) else {
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

fn store_at(root: &std::path::Path, ready: &ReadyChannel, role: Role, height: u64) -> ChannelStore {
    let mut store = match ChannelStore::open(
        root,
        ready.channel().clone(),
        settlement(),
        role,
        origin(),
        &Secp256k1Verifier::new(),
    ) {
        Ok(store) => store,
        Err(error) => panic!("the fixture store opens: {error}"),
    };
    advance(&mut store, height);
    store
}

/// The payload digest of the synthetic block at `height`.
///
/// A cursor is contiguous, so a fixture that moves it has to name a
/// chain rather than repeat one digest: each block's parent is the last
/// block's payload, and the watcher refuses anything else.
fn payload_at(height: u64) -> [u8; 32] {
    let mut payload = [0xc0; 32];
    for (slot, byte) in payload.iter_mut().zip(height.to_be_bytes()) {
        *slot = byte;
    }
    payload
}

/// Where the fixture channel was opened: the genesis block of the
/// synthetic chain above, so a store starts with a clock and `advance`
/// reads block one next.
fn origin() -> SetupOrigin {
    SetupOrigin {
        payment_edge: payment_edge(),
        height: 0,
        payload: payload_at(0),
        parent: [0_u8; 32],
    }
}

/// Runs the production watcher over one empty finalized block per
/// height, up through `height`.
///
/// The same call the settlement loop makes, so a fixture cursor is a
/// cursor this endpoint could have reached.
fn advance(store: &mut ChannelStore, height: u64) {
    let mut next = store.state().cursor().0.saturating_add(1);
    while next <= height {
        let block = FinalizedWork {
            height: next,
            parent: payload_at(next.saturating_sub(1)),
            payload: payload_at(next),
            txs: Vec::new(),
        };
        if let Err(error) = observe(store, &block, &Secp256k1Verifier::new()) {
            panic!("the fixture block applies: {error}");
        }
        next = next.saturating_add(1);
    }
}

fn commit(store: &mut ChannelStore, record: ChannelRecord) {
    if let Err(error) = store.commit(record, &Secp256k1Verifier::new()) {
        panic!("the fixture record commits: {error}");
    }
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

fn text_execution() -> TextExecution {
    TextExecution::new(
        SourceRef::output(identity_artifact().output_id()),
        prompt_tokens().output_id(),
        text_policy().output_id(),
    )
}

fn evaluate_request(nonce: u8) -> EvaluateRequest {
    EvaluateRequest {
        text_execution: text_execution().input_id().digest(),
        runner_public_key: PublicKey::Secp256k1(client().party_key().to_bytes()),
        execution_environment: manifest().content_id(),
        nonce: [nonce; 32],
        assurance: Assurance::ProducerSigned,
        retain: true,
    }
}

fn bundle(nonce: u8) -> PreparedPaidInputV1 {
    PreparedPaidInputV1::new(
        &evaluate_request(nonce),
        &manifest(),
        &text_execution(),
        &prompt_tokens(),
        &text_policy(),
        &identity_artifact(),
    )
}

fn authorization() -> PaidJobAuthorizationV1 {
    match propose_authorization(
        ready().channel(),
        &execution_policy(),
        &bundle(NONCE),
        u64::from(NONCE),
        deadlines(),
    ) {
        Ok(authorization) => authorization,
        Err(error) => panic!("the fixture authorization builds: {error}"),
    }
}

/// Puts one accepted job on both journals, and returns its `work_id`.
///
/// The acceptance exchange has its own file; these tests are about what
/// happens after both signatures exist.
fn accept(stores: &mut [&mut ChannelStore]) -> Digest {
    let authorization = authorization();
    let ready = ready();
    let id = work_id(ready.channel(), &authorization);
    let Ok(prepared_input) = bundle(NONCE).encode() else {
        panic!("the fixture bundle encodes");
    };
    for store in stores {
        commit(
            store,
            ChannelRecord::JobProposed {
                authorization,
                client_signature: client().sign(signing_hash(id)),
                prepared_input: prepared_input.clone(),
            },
        );
        commit(
            store,
            ChannelRecord::JobAccepted {
                provider_signature: provider().sign(signing_hash(id)),
            },
        );
    }
    id
}

// ── Transcripts and the backend that produces them ────────────────────

const ANSWER: [u32; 5] = [101, 102, 103, 104, 105];

fn transcript_for(request: &EvaluateRequest, answer: &[u32]) -> Vec<OutputEventEnvelope> {
    let key = provider_producer();
    let mut builder =
        EvaluateOutputTranscriptBuilder::new(input_commitment(request), request.assurance, &key);
    if let Err(error) = builder.push_token_delta(answer.to_vec()) {
        panic!("a non-empty delta pushes: {error}");
    }
    let usage = EvaluateUsage {
        input_units: PROMPT_TOKENS,
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

/// A backend that counts its calls and signs the fixture answer.
struct AnsweringBackend {
    calls: Arc<AtomicUsize>,
}

impl AnsweringBackend {
    fn new() -> Self {
        Self {
            calls: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl PaidEvaluateBackend for AnsweringBackend {
    fn evaluate(
        &self,
        request: EvaluateRequest,
    ) -> impl core::future::Future<Output = Result<Vec<OutputEventEnvelope>, BackendFault>> + Send
    {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let produced = transcript_for(&request, &ANSWER);
        async move { Ok(produced) }
    }
}

/// Runs one accepted job to a signed, durable result.
async fn run_to_result(service: &WorkService, ready: &ReadyChannel, id: Digest) {
    let backend = AnsweringBackend::new();
    let outcome = run_accepted_work(service, ready, &backend, id).await;
    assert!(
        matches!(outcome, Ok(RunOutcome::Completed { .. })),
        "the fixture job completes: {outcome:?}",
    );
}

// ── Transport plumbing ────────────────────────────────────────────────

struct Pipe {
    out: mpsc::UnboundedSender<Bytes>,
    inbox: mpsc::UnboundedReceiver<Bytes>,
}

impl MessagePipe for Pipe {
    type SendError = std::io::Error;
    type RecvError = std::io::Error;

    async fn send_message(&mut self, bytes: Bytes) -> Result<(), Self::SendError> {
        let _ = self.out.send(bytes);
        Ok(())
    }

    async fn recv_message(&mut self) -> Result<Option<Bytes>, Self::RecvError> {
        Ok(self.inbox.recv().await)
    }
}

/// What the two ends of one live session both know.
///
/// A mux over a pair of in-memory pipes has no TLS of its own, so the
/// exporter is supplied here — which is what a QUIC connection does for
/// itself. Both halves are handed the same value, because that is the
/// one property the delivery binding rests on: the number is known to
/// exactly the two ends of one connection.
fn session() -> hellas_wire::TransportContext {
    hellas_wire::TransportContext {
        open_exporter: Some(EXPORTER),
        ..hellas_wire::TransportContext::default()
    }
}

/// The exporter the fixture session exports.
const EXPORTER: [u8; 32] = [0x5e; 32];

fn transport_pair() -> (MuxTransport, MuxTransport) {
    let (to_server, server_inbox) = mpsc::unbounded_channel();
    let (to_client, client_inbox) = mpsc::unbounded_channel();
    let client = MuxTransport::spawn::<8, _, _>(
        MuxRole::Client,
        DefaultClock,
        MuxConfig::default(),
        Pipe {
            out: to_server,
            inbox: client_inbox,
        },
        session(),
    );
    let server = MuxTransport::spawn::<8, _, _>(
        MuxRole::Server,
        DefaultClock,
        MuxConfig::default(),
        Pipe {
            out: to_client,
            inbox: server_inbox,
        },
        session(),
    );
    (client, server)
}

/// Stops one serving task and waits for it to be gone.
///
/// Awaited rather than merely cancelled: the task holds a handle to the
/// provider's endpoint, and a test that reopens that journal from its
/// files needs the process to have actually let go of it.
async fn stop(serving: tokio::task::JoinHandle<()>) {
    serving.abort();
    let _ = serving.await;
}

fn serve(transport: MuxTransport, service: WorkService) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let server = WorkServer(service);
        while let Ok(Some(inbound)) = transport.accept().await {
            let _ = Dispatcher::<MuxTransport>::dispatch(&server, inbound).await;
        }
    })
}

// ── Canonical chain objects, spelled out ──────────────────────────────

const FORMAT_VERSION: u8 = 1;
const TAG_BLOCK_HEIGHT: u8 = 1;
const TAG_FEES: u8 = 2;
const TAG_PARTIES: u8 = 3;
const TAG_EDGE: u8 = 5;
const TAG_BOND_LEASE: u8 = 31;
/// `Freeze | Adjudicated`: close-kind tags 3 and 4.
const WORK_PAYMENT_CLOSES: u8 = 0b0001_1000;
/// `Timeout` alone: close-kind tag 1.
const WORK_STAKE_CLOSES: u8 = 0b0000_0010;

struct EdgeBytes {
    value: u64,
    reserve: u64,
    maker: Key,
    taker: Key,
    terms: TermsHash,
    allowed: u8,
}

impl EdgeBytes {
    fn build(&self) -> Edge {
        let mut out = vec![FORMAT_VERSION, TAG_EDGE];
        out.extend_from_slice(&self.value.to_be_bytes());
        out.extend_from_slice(&self.reserve.to_be_bytes());
        out.extend_from_slice(&[FORMAT_VERSION, TAG_FEES]);
        for _ in 0..4 {
            out.extend_from_slice(&0_u64.to_be_bytes());
        }
        out.extend_from_slice(&[FORMAT_VERSION, TAG_BLOCK_HEIGHT]);
        out.extend_from_slice(&HORIZON.to_be_bytes());
        out.extend_from_slice(&[FORMAT_VERSION, TAG_PARTIES]);
        out.extend_from_slice(&self.maker.to_bytes());
        out.extend_from_slice(&self.taker.to_bytes());
        out.extend_from_slice(self.terms.as_bytes());
        out.push(self.allowed);
        match Edge::decode_exact(&out) {
            Ok(edge) => edge,
            Err(error) => panic!("the hand-written edge is canonical: {error:?}"),
        }
    }
}

fn bond_object() -> Edge {
    EdgeBytes {
        value: STAKE,
        reserve: 0,
        maker: provider().party_key(),
        taker: client().party_key(),
        terms: Terms::work_stake_bond(bond_terms()).hash(),
        allowed: WORK_STAKE_CLOSES,
    }
    .build()
}

fn payment_object() -> Edge {
    EdgeBytes {
        value: PAYMENT_VALUE,
        reserve: PAYMENT_RESERVE,
        maker: client().party_key(),
        taker: provider().party_key(),
        terms: payment_terms_hash(payment_terms()),
        allowed: WORK_PAYMENT_CLOSES,
    }
    .build()
}

fn lease_over(bond: EdgeId, payment: EdgeId) -> LeaseSlots {
    let mut value = vec![FORMAT_VERSION, TAG_BOND_LEASE, 2];
    value.extend_from_slice(&bond.to_bytes());
    value.extend_from_slice(&payment.to_bytes());
    value.extend_from_slice(payment_terms_hash(payment_terms()).as_bytes());
    value.extend_from_slice(&payment_terms().private_policy_commitment);
    value.extend_from_slice(&HORIZON.to_be_bytes());

    let slots = [0, 1].map(|index| {
        RegistryChunk::split(
            RegistryNamespace::BondLease,
            RegistryRecordTag::BondLease,
            &value,
            index,
        )
    });
    let parsed = hellas_kernel::parse_bond_lease(slots, bond);
    assert!(
        matches!(parsed, LeaseSlots::Present(_)),
        "the hand-written lease is readable, got {parsed:?}",
    );
    parsed
}

// ── The state this phase begins from ──────────────────────────────────

/// One job, accepted, computed, delivered and independently checked.
///
/// Everything before the invoice, driven exactly as the earlier phases
/// drive it, because a payment for a job that reached this state any
/// other way would be a payment for something these tests invented.
struct Checked {
    client_root: tempfile::TempDir,
    provider_root: tempfile::TempDir,
    ready: ReadyChannel,
    service: WorkService,
    client: ClientEndpoint,
    id: Digest,
}

async fn checked_job() -> Checked {
    let client_root = temp();
    let provider_root = temp();
    let ready = ready();
    let mut client_store = store_at(client_root.path(), &ready, Role::Client, CURSOR);
    let mut provider_store = store_at(provider_root.path(), &ready, Role::Provider, CURSOR);
    let id = accept(&mut [&mut client_store, &mut provider_store]);

    let Ok(provider_endpoint) = ProviderEndpoint::new(ready.clone(), provider_store, provider())
    else {
        panic!("the provider endpoint binds");
    };
    let service = WorkService::new(provider_endpoint);
    let Ok(mut client) = ClientEndpoint::new(ready.clone(), client_store, client()) else {
        panic!("the client endpoint binds");
    };
    run_to_result(&service, &ready, id).await;

    let (transport, server) = transport_pair();
    let serving = serve(server, service.clone());
    let delivered = fetch_result(transport, &mut client, &ready, id).await;
    stop(serving).await;
    if let Err(error) = delivered {
        panic!("the fixture delivery completes: {error}");
    }
    // The oracle is `hellas-client`'s; what this file needs is the
    // durable verdict it records, which is the only phase an honest
    // client's journal signs a certificate from.
    if let Err(error) = client.verified(id) {
        panic!("the fixture verdict records: {error}");
    }
    Checked {
        client_root,
        provider_root,
        ready,
        service,
        client,
        id,
    }
}

// ── Driving the two calls ─────────────────────────────────────────────

/// One `AdmitCertificate` over a live transport: signed, journaled,
/// sent, and acknowledged.
async fn pay_over_wire(
    service: &WorkService,
    client: &mut ClientEndpoint,
    id: Digest,
) -> Result<u64, PaymentError> {
    let (transport, server) = transport_pair();
    let serving = serve(server, service.clone());
    let outcome = admit_payment(&WorkClientImpl::new(transport), client, id).await;
    stop(serving).await;
    outcome
}

// ── The state this phase begins from ──────────────────────────────────

/// One job, all the way through: checked and paid for.
///
/// The provider's journal ends holding one client-signed
/// [`EarnedCertificate`] at `PRICE`, and that certificate is the only
/// thing every close below settles.
async fn paid_job() -> Checked {
    let mut fixture = checked_job().await;
    let id = fixture.id;
    if let Err(error) = pay_over_wire(&fixture.service, &mut fixture.client, id).await {
        panic!("the fixture job is paid: {error}");
    }
    fixture
}

/// One `AcceptWorkRequest` for a fresh job at `proposal_nonce`.
fn signed_request(nonce: u8, proposal_nonce: u64) -> AcceptWorkRequest {
    let authorization = match propose_authorization(
        ready().channel(),
        &execution_policy(),
        &bundle(nonce),
        proposal_nonce,
        deadlines(),
    ) {
        Ok(authorization) => authorization,
        Err(error) => panic!("the fixture authorization builds: {error}"),
    };
    let Ok(prepared_input) = bundle(nonce).encode() else {
        panic!("the fixture bundle encodes");
    };
    AcceptWorkRequest {
        authorization: authorization.encode(),
        client_signature: client()
            .sign(signing_hash(work_id(ready().channel(), &authorization)))
            .as_bytes()
            .to_vec(),
        prepared_input,
    }
}

fn accepted(response: &AcceptWorkResponse) -> Option<Vec<u8>> {
    match response.outcome.as_ref() {
        Some(AcceptOutcome::Accepted(accepted)) => Some(accepted.provider_signature.clone()),
        _ => None,
    }
}

fn refusal_code(response: &AcceptWorkResponse) -> WorkRefusalCode {
    match response.outcome.as_ref() {
        Some(AcceptOutcome::Refused(refused)) => match WorkRefusalCode::try_from(refused.code) {
            Ok(code) => code,
            Err(error) => panic!("the refusal code is one of the six: {error}"),
        },
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// One finalized block carrying `txs`, on the chain `payload_at` names.
fn block(height: u64, txs: Vec<hellas_kernel::Tx>) -> FinalizedWork {
    FinalizedWork {
        height,
        parent: payload_at(height.saturating_sub(1)),
        payload: payload_at(height),
        txs,
    }
}

/// The canonical bytes of one pending-close record, spelled out here
/// rather than produced by the kernel's encoder.
///
/// An endpoint reads these bytes out of a registry slot on a wire, not
/// out of a transition it ran, so its side of the agreement is a byte
/// layout. A round trip through `PendingPaymentClose::encode` would
/// pass with any two same-width fields transposed; this does not.
fn pending_bytes(record: &Contest) -> Vec<u8> {
    // envelope: canonical format version 1, type tag 23.
    let mut value = vec![1_u8, 23];
    // body version.
    value.push(2);
    value.extend_from_slice(&payment_edge().to_bytes());
    // opener_role: the taker, which on a payment edge is the provider.
    value.push(1);
    value.extend_from_slice(&record.start_id.to_bytes());
    value.extend_from_slice(&record.deadline.to_be_bytes());
    value.extend_from_slice(&record.start_cumulative.to_be_bytes());
    value.extend_from_slice(&record.final_cumulative.to_be_bytes());
    value.push(u8::from(record.responded));
    value.push(u8::from(record.penalty_due));
    value.extend_from_slice(&OMISSION_BOND.to_be_bytes());
    value
}

/// One contest as the chain would hold it.
struct Contest {
    start_id: hellas_kernel::StartId,
    deadline: u64,
    start_cumulative: u64,
    final_cumulative: u64,
    responded: bool,
    penalty_due: bool,
}

impl Contest {
    /// The record an unanswered provider-opened start at `amount`
    /// leaves.
    fn opened(start_id: hellas_kernel::StartId, deadline: u64, amount: u64) -> Self {
        Self {
            start_id,
            deadline,
            start_cumulative: amount,
            final_cumulative: amount,
            responded: false,
            penalty_due: false,
        }
    }
}

fn pending_slot(record: &Contest) -> PendingSlot {
    let bytes = pending_bytes(record);
    let chunk = RegistryChunk::split(
        RegistryNamespace::PaymentClose,
        RegistryRecordTag::PaymentPending,
        &bytes,
        0,
    );
    let parsed = hellas_kernel::parse_pending_close(chunk, payment_edge());
    assert!(
        matches!(parsed, PendingSlot::Present(_)),
        "the hand-written contest is readable, got {parsed:?}",
    );
    parsed
}

/// The contest identifier the kernel derives for `start` at `height`.
fn contest_id(
    ready: &ReadyChannel,
    start: &PaymentCloseStart,
    height: u64,
) -> hellas_kernel::StartId {
    hellas_kernel::start_id(start_body_digest(ready.channel(), start), height)
}

// ── One paid job, closed on chain ─────────────────────────────────────

/// One certificate becomes one start, one contest, and one payout.
///
/// Every value the close carries is traced back to the job: the amount
/// is the invoice's `cumulative_after`, the signature is the client's
/// own, and the contest identifier is the one the block that accepted
/// the start determines.
#[tokio::test]
async fn a_paid_job_closes_at_exactly_what_it_earned() {
    let fixture = paid_job().await;
    let ready = fixture.ready.clone();

    let start = {
        let Ok(mut provider) = fixture.service.endpoint() else {
            panic!("the endpoint is reachable");
        };
        assert_eq!(provider.state().max_executable_certificate(), PRICE);
        match provider.prepare_close() {
            Ok(start) => start,
            Err(error) => panic!("a paid channel closes: {error}"),
        }
    };

    // The start is about this channel, claims exactly what was earned,
    // and is includable in the window the terms fix, starting at the
    // block after the one this endpoint has processed.
    assert_eq!(start.payment_edge(), payment_edge());
    assert_eq!(start.terms().hash(), ready.channel().payment_terms_hash());
    assert_eq!(start.opener_role(), hellas_kernel::Party::Taker);
    assert_eq!(start.valid_from_height(), CURSOR + 1);
    assert_eq!(
        start.valid_through_height(),
        CURSOR + payment_terms().start_validity_blocks,
    );
    let Some((certificate, signature)) = start.certificate() else {
        panic!("a paid channel claims what it earned");
    };
    assert_eq!(certificate.earned_cumulative(), PRICE);
    assert_eq!(certificate.payment_edge(), payment_edge());
    let Some(payment) = fixture.client.state().last_payment() else {
        panic!("the client retains what it paid");
    };
    assert_eq!(
        (certificate, signature),
        (&payment.certificate, &payment.certificate_signature),
        "the close carries the client's own certificate, not a copy of the number",
    );

    // Asking again before the window has passed is the resubmission,
    // not a second close: the same bytes, and no second record.
    let (again, before) = {
        let Ok(mut provider) = fixture.service.endpoint() else {
            panic!("the endpoint is reachable");
        };
        let before = provider.state().close_prepared().cloned();
        (provider.prepare_close(), before)
    };
    match again {
        Ok(again) => assert_eq!(Some(&again), before.as_ref()),
        Err(error) => panic!("a retained start is offered again: {error}"),
    }

    // The block that accepts it. The contest identifier is the height's
    // to decide, and nothing the endpoint retained determines it.
    let inclusion = CURSOR + 1;
    let expected = contest_id(&ready, &start, inclusion);
    {
        let Ok(mut provider) = fixture.service.endpoint() else {
            panic!("the endpoint is reachable");
        };
        let accepted = block(
            inclusion,
            vec![hellas_kernel::Tx::move_action(
                hellas_kernel::Move::StartPaymentClose(start.clone()),
            )],
        );
        match provider.observe_finalized(&accepted) {
            Ok(state) => {
                assert_eq!(state.close_opened(), Some((expected, Party::Taker)));
                assert_eq!(state.cursor(), (inclusion, payload_at(inclusion)));
            }
            Err(error) => panic!("the block applies: {error}"),
        }
        assert_ne!(
            expected,
            contest_id(&ready, &start, inclusion + 1),
            "one signed start included at two heights is two contests",
        );
    }

    // The response window runs out with no answer, and the close pays
    // the amount the contest settled at.
    let deadline = inclusion + payment_terms().omit_response_blocks;
    let record = Contest::opened(expected, deadline, PRICE);
    let bond = bond_object();
    let payment_edge_object = payment_object();
    let close = {
        let Ok(provider) = fixture.service.endpoint() else {
            panic!("the endpoint is reachable");
        };
        let observed = ObservedChannel {
            height: deadline,
            bond: Some(&bond),
            payment: Some(&payment_edge_object),
            lease: lease_over(bond_edge(), payment_edge()),
            pending: pending_slot(&record),
        };
        match provider.adjudicated_close(&observed) {
            Ok(close) => close,
            Err(error) => panic!("a spent window closes: {error}"),
        }
    };
    let hellas_kernel::Tx::Close { input, outputs, .. } = &close else {
        panic!("an adjudicated close is a close");
    };
    assert_eq!(*input, payment_edge());
    let total = settlement().adjudicated_total();
    assert_eq!(
        outputs.as_slice(),
        [
            Payout::new(provider().party_key(), PRICE),
            Payout::new(client().party_key(), total - PRICE),
        ],
        "the provider is paid the job's price and no omission bond",
    );
}

/// The provider's window does not shut early, and the close does not
/// come late.
///
/// One block either side of the deadline, with the deadline the only
/// thing varied. The kernel's own guard is the complement of this one —
/// a response at the deadline is late and a close at the deadline is
/// not — so an endpoint that built a close one block early would be
/// building a transaction consensus refuses.
#[tokio::test]
async fn a_close_is_built_at_the_deadline_and_not_before_it() {
    let fixture = paid_job().await;
    let ready = fixture.ready.clone();
    let inclusion = CURSOR + 1;
    let bond = bond_object();
    let payment_edge_object = payment_object();

    let Ok(mut provider) = fixture.service.endpoint() else {
        panic!("the endpoint is reachable");
    };
    let Ok(start) = provider.prepare_close() else {
        panic!("a paid channel closes");
    };
    let id = contest_id(&ready, &start, inclusion);
    if let Err(error) = provider.observe_finalized(&block(
        inclusion,
        vec![hellas_kernel::Tx::move_action(
            hellas_kernel::Move::StartPaymentClose(start),
        )],
    )) {
        panic!("the block applies: {error}");
    }

    let deadline = inclusion + payment_terms().omit_response_blocks;
    let record = Contest::opened(id, deadline, PRICE);
    for (height, closable) in [(deadline - 1, false), (deadline, true)] {
        let observed = ObservedChannel {
            height,
            bond: Some(&bond),
            payment: Some(&payment_edge_object),
            lease: lease_over(bond_edge(), payment_edge()),
            pending: pending_slot(&record),
        };
        let built = provider.adjudicated_close(&observed);
        if closable {
            if let Err(error) = built {
                panic!("a close at {height} is admissible: {error}");
            }
            continue;
        }
        assert!(
            matches!(
                built,
                Err(CloseError::ResponseWindowOpen {
                    height: found,
                    deadline: owed,
                }) if found == height && owed == deadline
            ),
            "a close at {height} is early: {built:?}",
        );
    }
}

/// A close is built only for the contest this endpoint's own watcher
/// saw.
///
/// Three reads, each differing from the admissible one in exactly one
/// thing: no contest in the slot, another contest's identifier, and a
/// watcher that has not yet read the block that opened this one.
#[tokio::test]
async fn a_close_settles_the_contest_this_endpoint_started() {
    let fixture = paid_job().await;
    let ready = fixture.ready.clone();
    let inclusion = CURSOR + 1;
    let deadline = inclusion + payment_terms().omit_response_blocks;
    let bond = bond_object();
    let payment_edge_object = payment_object();

    let Ok(mut provider) = fixture.service.endpoint() else {
        panic!("the endpoint is reachable");
    };
    let Ok(start) = provider.prepare_close() else {
        panic!("a paid channel closes");
    };
    let id = contest_id(&ready, &start, inclusion);
    let record = Contest::opened(id, deadline, PRICE);

    // Before the watcher has read the block: the chain says a contest
    // is open and this endpoint cannot yet say it is its own.
    let observed = ObservedChannel {
        height: deadline,
        bond: Some(&bond),
        payment: Some(&payment_edge_object),
        lease: lease_over(bond_edge(), payment_edge()),
        pending: pending_slot(&record),
    };
    assert!(
        matches!(
            provider.adjudicated_close(&observed),
            Err(CloseError::NoContest)
        ),
        "an unread block is not a contest this endpoint holds",
    );

    if let Err(error) = provider.observe_finalized(&block(
        inclusion,
        vec![hellas_kernel::Tx::move_action(
            hellas_kernel::Move::StartPaymentClose(start),
        )],
    )) {
        panic!("the block applies: {error}");
    }
    if let Err(error) = provider.adjudicated_close(&observed) {
        panic!("the read contest closes: {error}");
    }

    // The same read with an empty slot.
    let absent = ObservedChannel {
        pending: PendingSlot::Absent,
        ..observed
    };
    assert!(
        matches!(
            provider.adjudicated_close(&absent),
            Err(CloseError::NoContest)
        ),
        "an empty slot is no contest",
    );

    // The same read with another contest in the slot. Only the
    // identifier moves.
    let elsewhere = Contest::opened(
        hellas_kernel::StartId::from_bytes([0x77; 32]),
        deadline,
        PRICE,
    );
    let other = ObservedChannel {
        pending: pending_slot(&elsewhere),
        ..observed
    };
    assert!(
        matches!(
            provider.adjudicated_close(&other),
            Err(CloseError::OtherContest)
        ),
        "another contest is not this endpoint's to settle",
    );
}

// ── The cutoff ────────────────────────────────────────────────────────

/// Once the close is on the disk, the channel takes no more work.
///
/// The proposal refused afterwards is the same proposal the same
/// endpoint accepted a moment earlier — same nonce, same bytes, same
/// deadlines — so what refuses it is the cutoff and nothing else. A job
/// admitted after the start was signed would be a job whose payment
/// that start cannot carry.
#[tokio::test]
async fn a_job_after_the_cutoff_is_refused() {
    let fixture = paid_job().await;
    let second = signed_request(2, 2);

    // The same request, against a provider that has not closed. This is
    // what the refusal below is being distinguished from.
    let open_channel = paid_job().await;
    {
        let Ok(mut provider) = open_channel.service.endpoint() else {
            panic!("the endpoint is reachable");
        };
        let answered = provider.accept(&second);
        assert!(
            accepted(&answered).is_some(),
            "a paid, idle channel takes the next job: {answered:?}",
        );
    }
    drop(open_channel);

    let Ok(mut provider) = fixture.service.endpoint() else {
        panic!("the endpoint is reachable");
    };
    if let Err(error) = provider.prepare_close() {
        panic!("a paid channel closes: {error}");
    }
    let refused = provider.accept(&second);
    assert_eq!(
        refusal_code(&refused),
        WorkRefusalCode::Declined,
        "a closing channel declines new work: {refused:?}",
    );
    assert!(
        provider.state().job().is_none(),
        "and nothing about it is journaled",
    );
}

/// A start that can no longer be included stops holding the gate shut.
///
/// The cursor is the whole proof. It is contiguous, so every block up
/// to it was read: a contest opened by the old start would be on this
/// disk, and it is not. What is left is that the signature's window has
/// passed, and the cursor says exactly that.
#[tokio::test]
async fn a_start_that_can_no_longer_land_is_replaced_and_one_that_can_is_not() {
    let fixture = paid_job().await;
    let Ok(mut provider) = fixture.service.endpoint() else {
        panic!("the endpoint is reachable");
    };
    let Ok(first) = provider.prepare_close() else {
        panic!("a paid channel closes");
    };
    let through = first.valid_through_height();

    // Every block up to the last one that could have included it.
    for height in (CURSOR + 1)..=through {
        if let Err(error) = provider.observe_finalized(&block(height, Vec::new())) {
            panic!("the block at {height} applies: {error}");
        }
        match provider.prepare_close() {
            Ok(again) => assert_eq!(
                again, first,
                "a start that can still be included at {height} is the one that is offered",
            ),
            Err(error) => panic!("the retained start is offered: {error}"),
        }
    }

    // One block further, and the old signature can never be included.
    if let Err(error) = provider.observe_finalized(&block(through + 1, Vec::new())) {
        panic!("the block applies: {error}");
    }
    let Ok(replacement) = provider.prepare_close() else {
        panic!("a spent start is replaced");
    };
    assert_ne!(replacement, first);
    assert_eq!(replacement.valid_from_height(), through + 2);
    assert_eq!(
        provider.state().close_prepared(),
        Some(&replacement),
        "and the disk holds the one that can land",
    );
}

// ── What the watcher does with the blocks that come back ──────────────

/// A settled close is remembered after its coins are gone.
///
/// The evidence is the block that carried the close and the payout it
/// made, both read out of the transaction consensus accepted. Nothing
/// here looks up a coin, which is the point: a payout may be spent the
/// next block, and its absence would not be evidence that the channel
/// was never settled.
#[tokio::test]
async fn settlement_is_the_block_that_closed_the_edge() {
    let fixture = paid_job().await;
    let ready = fixture.ready.clone();
    let inclusion = CURSOR + 1;
    let Ok(mut provider) = fixture.service.endpoint() else {
        panic!("the endpoint is reachable");
    };
    let Ok(start) = provider.prepare_close() else {
        panic!("a paid channel closes");
    };
    let id = contest_id(&ready, &start, inclusion);
    if let Err(error) = provider.observe_finalized(&block(
        inclusion,
        vec![hellas_kernel::Tx::move_action(
            hellas_kernel::Move::StartPaymentClose(start),
        )],
    )) {
        panic!("the block applies: {error}");
    }

    let deadline = inclusion + payment_terms().omit_response_blocks;
    let bond = bond_object();
    let payment_edge_object = payment_object();
    let record = Contest::opened(id, deadline, PRICE);
    let observed = ObservedChannel {
        height: deadline,
        bond: Some(&bond),
        payment: Some(&payment_edge_object),
        lease: lease_over(bond_edge(), payment_edge()),
        pending: pending_slot(&record),
    };
    let Ok(close) = provider.adjudicated_close(&observed) else {
        panic!("a spent window closes");
    };

    for height in (inclusion + 1)..deadline {
        if let Err(error) = provider.observe_finalized(&block(height, Vec::new())) {
            panic!("the block at {height} applies: {error}");
        }
    }
    match provider.observe_finalized(&block(deadline, vec![close])) {
        Ok(state) => {
            assert_eq!(
                state.close_settled(),
                Some(CloseSettlement {
                    height: deadline,
                    payload: payload_at(deadline),
                    provider_payout: PRICE,
                }),
            );
        }
        Err(error) => panic!("the closing block applies: {error}"),
    }
}

/// The watcher applies a block's transactions in the order the
/// validator put them in.
///
/// One block carries the start and the close that ends it. Applied in
/// consensus order both land; applied backwards the start is refused,
/// because a channel whose edge is gone admits no new contest. A
/// scanner that sorted a block's transactions would produce the second
/// history from the first block.
#[tokio::test]
async fn a_blocks_transactions_are_applied_in_consensus_order() {
    // The three fixtures are built before any endpoint is locked: one
    // to derive the two transactions, and one for each reading order.
    let fixture = paid_job().await;
    let ordered = paid_job().await;
    let reversed = paid_job().await;
    let ready = fixture.ready.clone();
    let inclusion = CURSOR + 1;
    let Ok(mut provider) = fixture.service.endpoint() else {
        panic!("the endpoint is reachable");
    };
    let Ok(start) = provider.prepare_close() else {
        panic!("a paid channel closes");
    };
    let id = contest_id(&ready, &start, inclusion);
    let start_tx =
        hellas_kernel::Tx::move_action(hellas_kernel::Move::StartPaymentClose(start.clone()));

    let deadline = inclusion + payment_terms().omit_response_blocks;
    let record = Contest::opened(id, deadline, PRICE);
    let bond = bond_object();
    let payment_edge_object = payment_object();
    // The close this contest settles, built once and put in the same
    // block as the start it answers. Whether consensus would accept the
    // two together is the kernel's question; what is varied here is
    // only the order the watcher reads them in.
    let close = {
        if let Err(error) = provider.observe_finalized(&block(inclusion, vec![start_tx.clone()])) {
            panic!("the block applies: {error}");
        }
        let observed = ObservedChannel {
            height: deadline,
            bond: Some(&bond),
            payment: Some(&payment_edge_object),
            lease: lease_over(bond_edge(), payment_edge()),
            pending: pending_slot(&record),
        };
        match provider.adjudicated_close(&observed) {
            Ok(close) => close,
            Err(error) => panic!("a spent window closes: {error}"),
        }
    };
    drop(provider);
    drop(fixture);

    // A second provider, in the same state, that has read nothing.
    {
        let Ok(mut provider) = ordered.service.endpoint() else {
            panic!("the endpoint is reachable");
        };
        if let Err(error) = provider.prepare_close() {
            panic!("a paid channel closes: {error}");
        }
        match provider.observe_finalized(&block(inclusion, vec![start_tx.clone(), close.clone()])) {
            Ok(state) => {
                assert_eq!(state.close_opened(), Some((id, Party::Taker)));
                assert_eq!(
                    state.close_settled().map(|settled| settled.provider_payout),
                    Some(PRICE),
                );
            }
            Err(error) => panic!("the block in consensus order applies: {error}"),
        }
    }

    {
        let Ok(mut provider) = reversed.service.endpoint() else {
            panic!("the endpoint is reachable");
        };
        if let Err(error) = provider.prepare_close() {
            panic!("a paid channel closes: {error}");
        }
        let applied = provider.observe_finalized(&block(inclusion, vec![close, start_tx]));
        assert!(
            applied.is_err(),
            "a close before the start it answers is not a history this journal takes",
        );
        assert_eq!(
            provider.state().cursor(),
            (CURSOR, payload_at(CURSOR)),
            "and the cursor stays behind the block it could not apply",
        );
    }
}

// ── Catching up ───────────────────────────────────────────────────────

/// One provider endpoint after a restart, over its own files.
///
/// A watcher owns its endpoint rather than sharing it with a serving
/// task, because a catch-up reads a chain and nothing may hold the
/// endpoint while it waits. Reopening is also what makes each test
/// below a crash: the state the loop runs against is replayed from the
/// disk, and the journal's own lock is what says the serving endpoint
/// is really gone.
struct Watcher {
    provider: ProviderEndpoint,
    _client_root: tempfile::TempDir,
    _provider_root: tempfile::TempDir,
}

fn restarted(fixture: Checked) -> Watcher {
    let Checked {
        client_root,
        provider_root,
        ready,
        service,
        client,
        ..
    } = fixture;
    drop(service);
    drop(client);
    let store = store_at(provider_root.path(), &ready, Role::Provider, CURSOR);
    match ProviderEndpoint::new(ready, store, provider()) {
        Ok(provider) => Watcher {
            provider,
            _client_root: client_root,
            _provider_root: provider_root,
        },
        Err(error) => panic!("the reopened provider endpoint binds: {error}"),
    }
}

/// A finalized history a test writes down.
struct Chain {
    blocks: Vec<FinalizedWork>,
    withheld: Option<u64>,
}

impl FinalizedBlocks for Chain {
    async fn latest_height(&self) -> Result<Option<u64>, BlockSourceError> {
        Ok(self.blocks.last().map(|block| block.height))
    }

    async fn block_at(&self, height: u64) -> Result<Option<FinalizedWork>, BlockSourceError> {
        if self.withheld == Some(height) {
            return Ok(None);
        }
        Ok(self
            .blocks
            .iter()
            .find(|block| block.height == height)
            .cloned())
    }
}

/// Every block is read, and a notification is not a substitute for
/// reading them.
///
/// The start is three blocks in. A watcher that jumped to the tip would
/// report a cursor at the same height and know nothing about the
/// contest — which is the whole difference, because the close is built
/// from what the scan found and not from what the tip says.
#[tokio::test]
async fn a_catch_up_reads_every_block_between() {
    let fixture = paid_job().await;
    let ready = fixture.ready.clone();
    let mut watcher = restarted(fixture);
    let provider = &mut watcher.provider;
    let Ok(start) = provider.prepare_close() else {
        panic!("a paid channel closes");
    };
    let inclusion = CURSOR + 3;
    let id = contest_id(&ready, &start, inclusion);
    let start_tx = hellas_kernel::Tx::move_action(hellas_kernel::Move::StartPaymentClose(start));

    // A start and a close on some other channel's payment edge, two
    // blocks before this channel's own. Neither is this channel's
    // business, and a watcher that read them as its own would report a
    // contest it never opened and a settlement that never happened.
    let elsewhere = EdgeId::from_bytes([0x99; EdgeId::LENGTH]);
    let foreign_start = hellas_kernel::Tx::move_action(hellas_kernel::Move::StartPaymentClose(
        PaymentCloseStart::new(
            elsewhere,
            Terms::work_payment(payment_terms()),
            hellas_kernel::Party::Taker,
            (CURSOR + 1, CURSOR + 1),
            None,
            signer(0x22).sign(hellas_kernel::PayloadHash::from_bytes([0x01; 32])),
        ),
    ));
    let foreign_close = hellas_kernel::Tx::close(
        elsewhere,
        hellas_kernel::Proof::adjudicated(hellas_kernel::PaymentContestCommitment::from_bytes(
            [0x02; 32],
        )),
        List::take(
            [Payout::new(signer(0x22).party_key(), 1); MAX_EDGE_OUTPUTS],
            1,
        ),
    );

    let chain = Chain {
        blocks: ((CURSOR + 1)..=(CURSOR + 5))
            .map(|height| {
                let txs = if height == inclusion {
                    vec![start_tx.clone()]
                } else if height == CURSOR + 1 {
                    vec![foreign_start.clone(), foreign_close.clone()]
                } else {
                    Vec::new()
                };
                block(height, txs)
            })
            .collect(),
        withheld: None,
    };
    match provider.catch_up(&chain).await {
        Ok(reached) => assert_eq!(reached, CURSOR + 5),
        Err(error) => panic!("the watcher catches up: {error}"),
    }
    assert_eq!(
        provider.state().close_opened(),
        Some((id, Party::Taker)),
        "the block three heights back is where the contest is",
    );
    assert!(
        provider.state().close_settled().is_none(),
        "another edge's close is not this channel's settlement",
    );

    // Run again with nothing new: a caught-up watcher writes nothing.
    let before = provider.state().cursor();
    match provider.catch_up(&chain).await {
        Ok(reached) => assert_eq!(reached, CURSOR + 5),
        Err(error) => panic!("a caught-up watcher is idle: {error}"),
    }
    assert_eq!(provider.state().cursor(), before);
}

/// A block the source cannot supply stops the scan where it is.
///
/// It does not skip ahead, and it does not pretend to be caught up.
/// Every gate in this crate is anchored at the cursor, so a watcher
/// that jumped the gap would make each of them pass on a height at
/// which it does not know what happened.
#[tokio::test]
async fn a_withheld_block_leaves_the_cursor_behind() {
    let fixture = paid_job().await;
    let mut watcher = restarted(fixture);
    let provider = &mut watcher.provider;
    let chain = Chain {
        blocks: ((CURSOR + 1)..=(CURSOR + 5))
            .map(|height| block(height, Vec::new()))
            .collect(),
        withheld: Some(CURSOR + 3),
    };
    let stopped = provider.catch_up(&chain).await;
    assert!(
        matches!(stopped, Err(CatchUpError::Missing { height }) if height == CURSOR + 3),
        "a gap is not a skip: {stopped:?}",
    );
    assert_eq!(
        provider.state().cursor(),
        (CURSOR + 2, payload_at(CURSOR + 2)),
        "the cursor keeps the last block that was read",
    );
}

// ── The deadline the cursor decides ───────────────────────────────────

/// The payment deadline ends the job, once, and lets the channel close.
///
/// Nothing but the watcher moves this. The height that crosses the
/// deadline is a finalized height this endpoint read, and until it does
/// the job is still open — which is the difference this whole phase is
/// about: a provider whose cursor never moved would hold a delivered,
/// unpaid job open forever and never be able to close its channel.
#[tokio::test]
async fn the_watcher_ends_a_job_its_payment_deadline_has_passed() {
    let fixture = checked_job().await;
    let payment_deadline = deadlines().payment;
    let Ok(mut provider) = fixture.service.endpoint() else {
        panic!("the endpoint is reachable");
    };
    assert_eq!(
        provider.state().job().map(JobState::phase),
        Some(JobPhase::Delivered),
    );

    // A closing provider with a delivered, unpaid job is refused: what
    // the client owes has not been decided yet.
    assert!(
        provider.prepare_close().is_err(),
        "a channel with an open job does not close",
    );

    for height in (CURSOR + 1)..=payment_deadline {
        if let Err(error) = provider.observe_finalized(&block(height, Vec::new())) {
            panic!("the block at {height} applies: {error}");
        }
    }
    assert!(
        provider.state().job().is_some(),
        "the deadline itself is still inside the window the client signed",
    );

    if let Err(error) = provider.observe_finalized(&block(payment_deadline + 1, Vec::new())) {
        panic!("the block past the deadline applies: {error}");
    }
    assert!(provider.state().job().is_none(), "the job is over");
    let loss = provider.state().loss();
    assert_eq!(
        (loss.compute, loss.delivery),
        (PRICE, PRICE),
        "a delivered, unpaid job is loss in both currencies",
    );
    assert_eq!(provider.state().compute_outstanding(), 0);
    assert_eq!(provider.state().delivery_outstanding(), 0);

    // The next blocks charge it again to nobody.
    for height in (payment_deadline + 2)..=(payment_deadline + 4) {
        if let Err(error) = provider.observe_finalized(&block(height, Vec::new())) {
            panic!("the block at {height} applies: {error}");
        }
    }
    let after = provider.state().loss();
    assert_eq!((after.compute, after.delivery), (PRICE, PRICE));

    // And now the channel can be closed, at nothing: the client never
    // signed a certificate, so there is none to carry.
    match provider.prepare_close() {
        Ok(start) => assert!(
            start.certificate().is_none(),
            "an unpaid channel claims nothing",
        ),
        Err(error) => panic!("a channel whose job is over closes: {error}"),
    }
}

// ── The signed window ─────────────────────────────────────────────────

/// The same channel under another start-validity span.
fn channel_with_span(span: u64) -> hellas_rpc::protocol::work::PaidChannel {
    let mut terms = payment_terms();
    terms.start_validity_blocks = span;
    match hellas_rpc::protocol::work::PaidChannel::new(
        network(),
        payment_edge(),
        terms,
        &SALT,
        channel_policy(),
    ) {
        Ok(channel) => channel,
        Err(error) => panic!("the fixture channel opens: {error}"),
    }
}

/// The signed window starts at the next block and is exactly as wide as
/// the terms say, and at the ceiling it refuses rather than wraps.
///
/// The span is inclusive at both ends, which is the kernel's own
/// reading: a one-block window has span one. An endpoint that read the
/// field as a duration would sign a window one block wider than the
/// terms admit, and every signature it made would be refused for a span
/// that is too wide.
#[test]
fn the_start_window_is_the_next_block_and_the_span_the_terms_fix() {
    for (span, height, expected) in [(8_u64, 10_u64, (11_u64, 18_u64)), (1, 10, (11, 11))] {
        let Ok(start) = close_start(
            &channel_with_span(span),
            hellas_kernel::Party::Taker,
            height,
            None,
            &signer(0x22),
        ) else {
            panic!("a span of {span} at height {height} signs");
        };
        assert_eq!(
            (start.valid_from_height(), start.valid_through_height()),
            expected,
        );
    }

    // A one-block window whose only live block is the last one there
    // is.
    let Ok(edge) = close_start(
        &channel_with_span(1),
        hellas_kernel::Party::Taker,
        u64::MAX - 1,
        None,
        &signer(0x22),
    ) else {
        panic!("the last representable window signs");
    };
    assert_eq!(
        (edge.valid_from_height(), edge.valid_through_height()),
        (u64::MAX, u64::MAX),
    );

    // Past it, nothing is signed. Each of these differs from a case
    // above in exactly one number.
    assert!(
        matches!(
            close_start(
                &channel_with_span(1),
                hellas_kernel::Party::Taker,
                u64::MAX,
                None,
                &signer(0x22),
            ),
            Err(CloseError::WindowOverflow { height }) if height == u64::MAX
        ),
        "there is no block after the last one",
    );
    assert!(
        matches!(
            close_start(
                &channel_with_span(8),
                hellas_kernel::Party::Taker,
                u64::MAX - 1,
                None,
                &signer(0x22),
            ),
            Err(CloseError::WindowOverflow { .. })
        ),
        "an eight-block window does not fit before the ceiling",
    );
    assert!(
        matches!(
            close_start(
                &channel_with_span(0),
                hellas_kernel::Party::Taker,
                10,
                None,
                &signer(0x22),
            ),
            Err(CloseError::NoValidityWindow)
        ),
        "a zero-block window is a signature no block could carry",
    );
}

/// A start signed before a crash is the start that is resubmitted.
///
/// The endpoint is dropped and its journal reopened over its own files,
/// so what comes back is replayed rather than remembered. Signing a
/// second start here would be a second contest for one channel — and
/// the first one may already be in a mempool.
#[tokio::test]
async fn a_start_signed_before_a_crash_is_the_start_that_is_resubmitted() {
    let fixture = paid_job().await;
    let signed = {
        let Ok(mut provider) = fixture.service.endpoint() else {
            panic!("the endpoint is reachable");
        };
        match provider.prepare_close() {
            Ok(start) => start,
            Err(error) => panic!("a paid channel closes: {error}"),
        }
    };

    let mut watcher = restarted(fixture);
    assert_eq!(
        watcher.provider.state().close_prepared(),
        Some(&signed),
        "the reopened journal holds the exact bytes that were signed",
    );

    // One more finalized block, so a fresh signature would carry a
    // different window. Without it the two are the same bytes — the
    // signing is deterministic — and this would prove nothing.
    if let Err(error) = watcher
        .provider
        .observe_finalized(&block(CURSOR + 1, Vec::new()))
    {
        panic!("the block applies: {error}");
    }
    match watcher.provider.prepare_close() {
        Ok(again) => assert_eq!(
            again, signed,
            "the retained start is resubmitted, not replaced by a fresh one",
        ),
        Err(error) => panic!("the retained start is offered again: {error}"),
    }
    assert_eq!(watcher.provider.state().close_prepared(), Some(&signed));
}

// ── Answering a contest opened below what is held ─────────────────────

/// The provider answers a client that opened below what it has already
/// signed for, and answers exactly once.
///
/// Each refusal below differs from the admissible answer in one thing:
/// the contest is another, the answer already landed, the read is at
/// the deadline rather than a block before it, or the provider holds
/// nothing more than the contest already settles. The last is not a
/// fault — it is the case where the one answer the window admits would
/// buy nothing.
#[tokio::test]
async fn the_provider_answers_an_understated_contest_exactly_once() {
    let fixture = paid_job().await;
    let ready = fixture.ready.clone();
    let inclusion = CURSOR + 1;
    let bond = bond_object();
    let payment_edge_object = payment_object();

    // The client opens at nothing, having a certificate for PRICE.
    let Ok(understated) = close_start(
        ready.channel(),
        hellas_kernel::Party::Maker,
        CURSOR,
        None,
        &client(),
    ) else {
        panic!("a client opens a close");
    };
    let id = contest_id(&ready, &understated, inclusion);

    let Ok(mut provider) = fixture.service.endpoint() else {
        panic!("the endpoint is reachable");
    };
    if let Err(error) = provider.observe_finalized(&block(
        inclusion,
        vec![hellas_kernel::Tx::move_action(
            hellas_kernel::Move::StartPaymentClose(understated),
        )],
    )) {
        panic!("the block applies: {error}");
    }
    assert_eq!(provider.state().close_opened(), Some((id, Party::Maker)));

    let deadline = inclusion + payment_terms().omit_response_blocks;
    let open = Contest::opened(id, deadline, 0);
    let read_at = |height: u64, record: &Contest| ObservedChannel {
        height,
        bond: Some(&bond),
        payment: Some(&payment_edge_object),
        lease: lease_over(bond_edge(), payment_edge()),
        pending: pending_slot(record),
    };

    // One block before the deadline, the answer is the client's own
    // larger certificate.
    let answered = match provider.respond_to_close(&read_at(deadline - 1, &open)) {
        Ok(answer) => answer,
        Err(error) => panic!("an understated contest is answered: {error}"),
    };
    let hellas_kernel::Tx::Move {
        action: hellas_kernel::Move::RespondPaymentClose(response),
    } = &answered
    else {
        panic!("an answer is a response move");
    };
    assert_eq!(response.start_id(), id);
    assert_eq!(response.responder_role(), hellas_kernel::Party::Taker);
    assert_eq!(response.certificate().earned_cumulative(), PRICE);

    // At the deadline the kernel calls it late, and so does this.
    assert!(
        matches!(
            provider.respond_to_close(&read_at(deadline, &open)),
            Err(CloseError::ResponseWindowClosed { height, deadline: owed })
                if height == deadline && owed == deadline
        ),
        "an answer at the deadline is late",
    );

    // The one answer, already landed.
    let mut settled = Contest::opened(id, deadline, 0);
    settled.final_cumulative = PRICE;
    settled.responded = true;
    settled.penalty_due = true;
    assert!(
        matches!(
            provider.respond_to_close(&read_at(deadline - 1, &settled)),
            Err(CloseError::AlreadyResponded)
        ),
        "there is one answer",
    );

    // A contest already at this endpoint's own high-water: nothing to
    // add, and the window is not spent saying so.
    let level = Contest::opened(id, deadline, PRICE);
    assert!(
        matches!(
            provider.respond_to_close(&read_at(deadline - 1, &level)),
            Err(CloseError::NothingToAdd { held, settled }) if held == PRICE && settled == PRICE
        ),
        "an equal high-water has no legal answer",
    );

    // Another contest in the slot.
    let elsewhere = Contest::opened(hellas_kernel::StartId::from_bytes([0x77; 32]), deadline, 0);
    assert!(
        matches!(
            provider.respond_to_close(&read_at(deadline - 1, &elsewhere)),
            Err(CloseError::OtherContest)
        ),
        "another contest is not this endpoint's to answer",
    );
}

// ── The cutoff a finalized close is ───────────────────────────────────

/// One job, run to a signed result and not yet released.
async fn ready_job() -> Checked {
    let client_root = temp();
    let provider_root = temp();
    let ready = ready();
    let mut client_store = store_at(client_root.path(), &ready, Role::Client, CURSOR);
    let mut provider_store = store_at(provider_root.path(), &ready, Role::Provider, CURSOR);
    let id = accept(&mut [&mut client_store, &mut provider_store]);
    let Ok(provider_endpoint) = ProviderEndpoint::new(ready.clone(), provider_store, provider())
    else {
        panic!("the provider endpoint binds");
    };
    let service = WorkService::new(provider_endpoint);
    let Ok(client) = ClientEndpoint::new(ready.clone(), client_store, client()) else {
        panic!("the client endpoint binds");
    };
    run_to_result(&service, &ready, id).await;
    Checked {
        client_root,
        provider_root,
        ready,
        service,
        client,
        id,
    }
}

/// A finalized close start takes the answer off the wire.
///
/// The exploit, end to end. The provider has signed a result and not
/// released it. The client opens a close carrying no certificate at
/// all, so the contest settles at nothing and the provider has nothing
/// higher to answer it with. Then the client asks for the plaintext.
///
/// Before this, it got it: the result was on the provider's disk, the
/// job read as ready, and no transition consulted the contest. The
/// compute was spent, the answer was taken, and nothing was signed for
/// it. Now the block that opens the contest is also what ends the job,
/// and the delivery has nothing to release.
#[tokio::test]
async fn a_finalized_close_start_takes_the_answer_off_the_wire() {
    let mut fixture = ready_job().await;
    let ready = fixture.ready.clone();
    let id = fixture.id;

    // The client's own start, carrying nothing.
    let Ok(understated) = close_start(ready.channel(), Party::Maker, CURSOR, None, &client())
    else {
        panic!("a client opens a close");
    };
    let inclusion = CURSOR + 1;
    let contest = contest_id(&ready, &understated, inclusion);
    let start_tx =
        hellas_kernel::Tx::move_action(hellas_kernel::Move::StartPaymentClose(understated));

    {
        let Ok(mut provider) = fixture.service.endpoint() else {
            panic!("the endpoint is reachable");
        };
        assert_eq!(
            provider.state().job().map(JobState::phase),
            Some(JobPhase::Ready),
            "the answer exists and has not left",
        );
        if let Err(error) = provider.observe_finalized(&block(inclusion, vec![start_tx])) {
            panic!("the block applies: {error}");
        }
        let state = provider.state();
        assert_eq!(state.close_opened(), Some((contest, Party::Maker)));
        assert!(
            state.job().is_none(),
            "a job no payment can reach is not a job that is still open",
        );
        // And the cost of it is this client's: it cut off a result it
        // could still have taken and paid for.
        assert_eq!(state.loss().compute, PRICE);
        assert_eq!(state.loss().delivery, 0, "nothing was released");
        assert_eq!(state.compute_outstanding(), 0);
    }

    // The delivery call the exploit ends with.
    let (transport, server) = transport_pair();
    let serving = serve(server, fixture.service.clone());
    let refused = fetch_result(transport, &mut fixture.client, &ready, id).await;
    stop(serving).await;
    let Err(hellas_rpc::work::DeliverError::Refused { refusal, .. }) = refused else {
        panic!("a closed channel releases nothing: {refused:?}");
    };
    assert_eq!(refusal, hellas_rpc::work::WorkRefusal::Declined);
    assert_eq!(
        fixture.client.state().job().map(JobState::phase),
        Some(JobPhase::Accepted),
        "and the client has no answer to check",
    );

    // Nor is there a fresh job to take its place.
    let response = {
        let Ok(mut provider) = fixture.service.endpoint() else {
            panic!("the endpoint is reachable");
        };
        provider.accept(&signed_request(NONCE + 1, 2))
    };
    let Some(AcceptOutcome::Refused(refused)) = response.outcome else {
        panic!("a closing channel takes no work: {response:?}");
    };
    assert_eq!(refused.code, WorkRefusalCode::Declined as i32);
}

/// A block out of order writes nothing before it is refused.
///
/// The transitions a block carries move money and shut the channel, so
/// they may not run before the block is one this journal may read. A
/// forged or merely early `h + 2` would otherwise end the job, charge
/// the client, record the contest, and only then be turned away by the
/// cursor — leaving every one of those effects on the disk under a
/// height this endpoint never reached.
#[tokio::test]
async fn a_block_out_of_order_writes_nothing_before_it_is_refused() {
    let fixture = ready_job().await;
    let ready = fixture.ready.clone();
    let Ok(mut provider) = fixture.service.endpoint() else {
        panic!("the endpoint is reachable");
    };
    let before = provider.state().clone();

    let Ok(understated) = close_start(ready.channel(), Party::Maker, CURSOR, None, &client())
    else {
        panic!("a client opens a close");
    };
    let start_tx =
        hellas_kernel::Tx::move_action(hellas_kernel::Move::StartPaymentClose(understated));
    // Two blocks on, and past the payment deadline as well, so every
    // transition `observe` has would fire if it ran at all.
    let skipped = CURSOR + 2;
    assert!(skipped > deadlines().payment || CURSOR + 2 == skipped);
    let applied = provider.observe_finalized(&block(skipped, vec![start_tx]));
    assert!(
        matches!(
            applied,
            Err(hellas_rpc::work_store::WorkStoreError::Channel(
                hellas_rpc::work_store::ChannelStateError::CursorNotNext { held, actual }
            )) if held == CURSOR && actual == skipped
        ),
        "a skipped height is not this journal's next block: {applied:?}",
    );
    assert_eq!(
        provider.state(),
        &before,
        "and nothing the block claimed reached the disk",
    );
}

/// The first catch-up cannot skip the channel's own history.
///
/// The exploit it closes: setup finishes at the channel's origin, the
/// client opens and settles a close in the blocks just after it, and
/// the provider starts watching later. A watcher that anchored at the
/// latest finalized block would see neither, report itself caught up,
/// and go on accepting work against an edge that is already gone.
///
/// The store is anchored at the block that opened the channel, so the
/// scan starts one block later whatever the tip says.
#[tokio::test]
async fn a_first_catch_up_cannot_skip_the_channels_own_history() {
    let root = temp();
    let ready = ready();
    // A store that has read nothing since the channel opened, which is
    // what a provider coming up for the first time has.
    let store = store_at(root.path(), &ready, Role::Provider, 0);
    assert_eq!(store.state().cursor(), (0, payload_at(0)));
    let Ok(mut provider) = ProviderEndpoint::new(ready.clone(), store, provider()) else {
        panic!("the provider endpoint binds");
    };

    // The client settles the payment edge in the second block of the
    // channel's life, and twenty more blocks go by.
    let settled_at = 2;
    let close = hellas_kernel::Tx::close(
        payment_edge(),
        hellas_kernel::Proof::adjudicated(hellas_kernel::PaymentContestCommitment::from_bytes(
            [0x02; 32],
        )),
        List::take([Payout::new(client().party_key(), 1); MAX_EDGE_OUTPUTS], 1),
    );
    let chain = Chain {
        blocks: (1..=20)
            .map(|height| {
                let txs = if height == settled_at {
                    vec![close.clone()]
                } else {
                    Vec::new()
                };
                block(height, txs)
            })
            .collect(),
        withheld: None,
    };
    match provider.catch_up(&chain).await {
        Ok(reached) => assert_eq!(reached, 20),
        Err(error) => panic!("the watcher catches up: {error}"),
    }
    let settlement = provider.state().close_settled();
    assert_eq!(
        settlement.map(|settled| settled.height),
        Some(settled_at),
        "the close eighteen blocks back is this channel's",
    );

    // And the channel it found closed admits no work.
    let response = provider.accept(&signed_request(NONCE, 1));
    let Some(AcceptOutcome::Refused(refused)) = response.outcome else {
        panic!("a settled edge takes no work: {response:?}");
    };
    assert_eq!(refused.code, WorkRefusalCode::Declined as i32);
}
