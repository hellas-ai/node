//! Invoicing one checked job and paying for it: what each endpoint
//! prices for itself, what is on the disk before either of them speaks,
//! and what a certificate the ledger cannot explain does.
//!
//! Both calls run over a real multiplexed transport, so the requests are
//! framed, routed by method id, decoded and answered rather than handed
//! to a function. Every crash is a real one: the endpoints are dropped
//! and their stores reopened over their own files.
//!
//! What is not re-proved here. The transition rules themselves belong to
//! the journal and are pinned in `work_store_channel.rs` — that a client
//! invoices only what its oracle checked, that a payment past its
//! deadline is refused, that a paid job is not billed again after a
//! restart. The record arithmetic belongs to `paid_work_vectors.rs`.
//! These tests are about the two endpoints and the wire between them.

#![cfg(feature = "work")]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;
use hellas_kernel::{
    BlockHeight, Decode as _, EarnedCertificate, Edge, EdgeId, EdgeValues, Encode as _, Fees, Key,
    LeaseSlots, List, MAX_EDGE_OUTPUTS, NetworkId, Parties, Payout, PendingSlot, RegistryChunk,
    RegistryNamespace, RegistryRecordTag, Secp256k1Signer, Secp256k1Verifier, Terms, TermsHash,
    WorkPaymentSettlement, WorkPaymentTerms, WorkStakeBondTerms, work_payment_settlement,
};
use hellas_rpc::evaluate::{
    EvaluateOutputTranscriptBuilder, EvaluateStopReason, EvaluateTerminal, EvaluateUsage,
    input_commitment,
};
use hellas_rpc::pb::work::{
    AdmitCertificateRequest, AdmitCertificateResponse, RequestInvoiceRequest, WorkInvoiced,
    WorkPaid, WorkRefusalCode, admit_certificate_response::Outcome as AdmitOutcome,
    request_invoice_response::Outcome as InvoiceOutcome,
};
use hellas_rpc::protocol::artifacts::{
    BoundTermId, Canonical as _, InputAddressed as _, OutputAddressed as _, PreparedPaidInputV1,
    SourceRef, TextArtifact, TextExecution, TextPolicy, TokenIds,
};
use hellas_rpc::protocol::work::{
    CertificateAllocationV1, InvoiceEntryV1, JobDeadlines, PaidChannel, PaidChannelPolicyV1,
    PaidExecutionPolicyV1, PaidJobAuthorizationV1, PrivateRecord as _, allocation_digest,
    generation_policy_digest, identity_source_digest, invoice_digest, invoice_entries_root,
    private_policy_commitment, propose_authorization, signing_hash, work_id,
};
use hellas_rpc::protocol::work_setup::{
    ObservedChannel, ReadyChannel, WorkChannelConfig, WorkChannelDescriptor, payment_terms_hash,
};
use hellas_rpc::protocol::{ContentId, Digest};
use hellas_rpc::services::work::{WorkClientImpl, WorkServer};
use hellas_rpc::work::{
    BackendFault, ClientEndpoint, PaidEvaluateBackend, PaymentError, ProviderEndpoint, RunError,
    RunOutcome, WorkRefusal, WorkService, admit_payment, fetch_result, request_invoice,
    run_accepted_work,
};
use hellas_rpc::work_close::{FinalizedWork, observe};
use hellas_rpc::work_store::{
    ChannelRecord, ChannelStateError, ChannelStore, JobEnd, JobPhase, JobState, Role,
    WorkStoreError,
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

/// Runs the production watcher over one empty finalized block per
/// height, up through `height`.
///
/// The same call the settlement loop makes, so a fixture cursor is a
/// cursor this endpoint could have reached.
fn advance(store: &mut ChannelStore, height: u64) {
    let mut next = store.state().cursor().map_or(height, |(held, _)| held + 1);
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
        if store.state().role() == Role::Client {
            commit(
                store,
                ChannelRecord::NonceReserved {
                    nonce: NONCE.into(),
                },
            );
        }
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
        None,
    );
    let server = MuxTransport::spawn::<8, _, _>(
        MuxRole::Server,
        DefaultClock,
        MuxConfig::default(),
        Pipe {
            out: to_client,
            inbox: server_inbox,
        },
        None,
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
    // client's journal will invoice from.
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

/// One `RequestInvoice` over a live transport, journaled on both sides.
async fn invoice_over_wire(
    service: &WorkService,
    client: &mut ClientEndpoint,
    id: Digest,
) -> Result<InvoiceEntryV1, PaymentError> {
    let (transport, server) = transport_pair();
    let serving = serve(server, service.clone());
    let outcome = request_invoice(&WorkClientImpl::new(transport), client, id).await;
    stop(serving).await;
    outcome
}

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

/// The provider's invoice for one job, taken off the wire and not
/// recorded by any client.
async fn invoice_response(service: &WorkService, id: Digest) -> WorkInvoiced {
    let (transport, server) = transport_pair();
    let serving = serve(server, service.clone());
    let response = WorkClientImpl::new(transport)
        .request_invoice(RequestInvoiceRequest {
            work_id: id.as_bytes().to_vec(),
        })
        .await;
    stop(serving).await;
    match response.map(|response| response.outcome) {
        Ok(Some(InvoiceOutcome::Invoiced(invoiced))) => invoiced,
        other => panic!("expected an invoice, got {other:?}"),
    }
}

/// The provider's answer to one payment, whatever it is.
async fn admit_response(
    service: &WorkService,
    request: AdmitCertificateRequest,
) -> AdmitCertificateResponse {
    let (transport, server) = transport_pair();
    let serving = serve(server, service.clone());
    let response = WorkClientImpl::new(transport)
        .admit_certificate(request)
        .await;
    stop(serving).await;
    match response {
        Ok(response) => response,
        Err(status) => panic!("the call completes: {status}"),
    }
}

fn refusal_of(response: &AdmitCertificateResponse) -> WorkRefusalCode {
    match &response.outcome {
        Some(AdmitOutcome::Refused(refused)) => match WorkRefusalCode::try_from(refused.code) {
            Ok(code) => code,
            Err(error) => panic!("the refusal code is one of the six: {error}"),
        },
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// One invoice entry as a provider would offer it, signed by `signer`.
fn offered(
    channel: &PaidChannel,
    entry: &InvoiceEntryV1,
    signer: &Secp256k1Signer,
) -> WorkInvoiced {
    WorkInvoiced {
        entry: entry.encode(),
        provider_signature: signature_over(signer, signing_hash(invoice_digest(channel, entry))),
    }
}

fn signature_over(signer: &Secp256k1Signer, hash: hellas_kernel::PayloadHash) -> Vec<u8> {
    signer.sign(hash).as_bytes().to_vec()
}

fn certificate_bytes(certificate: &EarnedCertificate) -> Vec<u8> {
    let mut buf = vec![0_u8; certificate.encoded_size()];
    let written = certificate.write_to(&mut buf);
    buf.truncate(written);
    buf
}

// ── One job, invoiced and paid ────────────────────────────────────────

/// One checked answer becomes one invoice and one certificate, and both
/// endpoints end at the same number.
///
/// The record counts at the end are what say nothing was written twice:
/// the calls were each made a second time, and the journals a process
/// that saw none of it reopens are the same length as before.
#[tokio::test]
async fn one_invoice_and_one_certificate_pay_for_one_job() {
    let mut fixture = checked_job().await;
    let id = fixture.id;

    let entry = match invoice_over_wire(&fixture.service, &mut fixture.client, id).await {
        Ok(entry) => entry,
        Err(error) => panic!("the checked job is invoiced: {error}"),
    };
    assert_eq!(entry.invoice_seq, 1, "the first invoice is sequence one");
    assert_eq!(entry.work_id, id);
    assert_eq!(entry.price, PRICE);
    assert_eq!(entry.cumulative_before, 0);
    assert_eq!(entry.cumulative_after, PRICE);
    assert_eq!(
        fixture.client.state().job().map(JobState::phase),
        Some(JobPhase::Invoiced),
    );

    // One job has one invoice: asking again is the lost-response retry,
    // and it returns the same entry rather than a second sequence.
    match invoice_over_wire(&fixture.service, &mut fixture.client, id).await {
        Ok(again) => assert_eq!(again, entry),
        Err(error) => panic!("a repeated invoice is the same invoice: {error}"),
    }

    let credited = match pay_over_wire(&fixture.service, &mut fixture.client, id).await {
        Ok(credited) => credited,
        Err(error) => panic!("the invoiced job is paid: {error}"),
    };
    assert_eq!(credited, PRICE);

    let state = fixture.client.state();
    assert!(state.job().is_none(), "the payment closes the job");
    assert_eq!(state.ledger().credited_invoice_high_water(), PRICE);
    assert_eq!(state.ledger().next_invoice_seq(), 2);
    let Some(payment) = state.last_payment() else {
        panic!("the payment is retained for re-sending");
    };
    assert_eq!(payment.work_id, id);
    assert_eq!(
        payment.certificate.earned_cumulative(),
        entry.cumulative_after
    );
    assert_eq!(payment.allocation.first_invoice_seq, entry.invoice_seq);
    assert_eq!(payment.allocation.last_invoice_seq, entry.invoice_seq);

    {
        let Ok(provider) = fixture.service.endpoint() else {
            panic!("the endpoint is reachable");
        };
        let state = provider.state();
        assert!(state.job().is_none());
        assert_eq!(state.ledger().credited_invoice_high_water(), PRICE);
        assert_eq!(state.max_executable_certificate(), PRICE);
        assert_eq!(
            state.compute_outstanding(),
            0,
            "the admitted certificate retires the compute credit",
        );
        assert_eq!(state.delivery_outstanding(), 0, "and the delivery credit");
    }

    // The acknowledgement lost to a crash: the same bytes again, and
    // the same answer.
    match pay_over_wire(&fixture.service, &mut fixture.client, id).await {
        Ok(again) => assert_eq!(again, PRICE),
        Err(error) => panic!("a re-sent payment is acknowledged: {error}"),
    }

    // The retained payment answers for the job it paid for and no
    // other: a channel with a payment on its disk has not thereby paid
    // for everything.
    let elsewhere = fixture.client.pay(Digest::from_bytes([0xaa; 32]));
    assert!(
        matches!(elsewhere, Err(PaymentError::NoSuchJob)),
        "another job's payment is not this one's: {elsewhere:?}",
    );

    drop(fixture.client);
    drop(fixture.service);
    let client_store = store_at(
        fixture.client_root.path(),
        &fixture.ready,
        Role::Client,
        CURSOR,
    );
    let provider_store = store_at(
        fixture.provider_root.path(),
        &fixture.ready,
        Role::Provider,
        CURSOR,
    );
    // Client: cursor, nonce, proposal, acceptance, result, verdict,
    // invoice, payment. Provider: cursor, proposal, acceptance, running
    // marker, result, release, invoice, payment.
    for (store, role) in [(&client_store, "client"), (&provider_store, "provider")] {
        assert_eq!(store.len(), 8, "the {role} journal wrote each step once");
        let state = store.state();
        assert!(state.job().is_none(), "the {role} job is closed");
        assert_eq!(state.ledger().credited_invoice_high_water(), PRICE);
        assert_eq!(state.ledger().next_invoice_seq(), 2);
        assert_eq!(state.max_executable_certificate(), PRICE);
    }
    assert_eq!(provider_store.state().compute_outstanding(), 0);
    assert_eq!(provider_store.state().delivery_outstanding(), 0);
    assert_eq!(
        client_store.state().last_payment().map(|p| p.work_id),
        Some(id)
    );
}

// ── What the client will be billed ────────────────────────────────────

/// A client pays the entry its own ledger arrives at, and no other.
///
/// Each offer below moves exactly one field of the honest entry and is
/// re-signed by the provider, so what refuses it is the arithmetic and
/// not the signature — and the last one moves no field and changes only
/// the signer, so the signature rule is shown to be there too.
#[tokio::test]
async fn the_client_prices_the_invoice_itself() {
    let mut fixture = checked_job().await;
    let id = fixture.id;
    let channel = fixture.ready.channel().clone();
    let honest = invoice_response(&fixture.service, id).await;
    let Ok(entry) = InvoiceEntryV1::decode(&honest.entry) else {
        panic!("the provider's own entry decodes");
    };

    let elsewhere = Digest::from_bytes([0x5e; 32]);
    let mutations = [
        (
            "price",
            InvoiceEntryV1 {
                price: PRICE + 1,
                ..entry
            },
        ),
        (
            "invoice_seq",
            InvoiceEntryV1 {
                invoice_seq: 2,
                ..entry
            },
        ),
        (
            "cumulative_before",
            InvoiceEntryV1 {
                cumulative_before: 1,
                ..entry
            },
        ),
        (
            "cumulative_after",
            InvoiceEntryV1 {
                cumulative_after: PRICE + 1,
                ..entry
            },
        ),
        (
            "work_id",
            InvoiceEntryV1 {
                work_id: elsewhere,
                ..entry
            },
        ),
        (
            "result_digest",
            InvoiceEntryV1 {
                result_digest: elsewhere,
                ..entry
            },
        ),
        (
            "channel_id",
            InvoiceEntryV1 {
                channel_id: elsewhere,
                ..entry
            },
        ),
    ];
    for (field, mutated) in mutations {
        assert_ne!(mutated, entry, "{field} is the one thing varied");
        let refused = fixture
            .client
            .invoiced(id, &offered(&channel, &mutated, &provider()));
        let Err(PaymentError::Store(WorkStoreError::Channel(error))) = refused else {
            panic!("an entry whose {field} this client did not arrive at: {refused:?}");
        };
        assert!(
            matches!(
                error,
                ChannelStateError::WrongChannel {
                    field: "invoice entry"
                }
            ),
            "unexpected error for {field}: {error}",
        );
        assert_eq!(
            fixture.client.state().job().map(JobState::phase),
            Some(JobPhase::Verified),
            "a refused invoice records nothing",
        );
    }

    // The honest entry, signed by the wrong party.
    let refused = fixture
        .client
        .invoiced(id, &offered(&channel, &entry, &client()));
    let Err(PaymentError::Store(WorkStoreError::Channel(ChannelStateError::BadSignature {
        slot: "invoice",
        party: "the provider",
    }))) = refused
    else {
        panic!("an entry the provider did not sign: {refused:?}");
    };

    // The control: the provider's own bytes, taken.
    match fixture.client.invoiced(id, &honest) {
        Ok(taken) => assert_eq!(taken, entry),
        Err(error) => panic!("the provider's own invoice is taken: {error}"),
    }
    assert_eq!(
        fixture.client.state().job().map(JobState::phase),
        Some(JobPhase::Invoiced),
    );
}

/// An acknowledgement is only this payment's if it names this
/// payment's amount.
///
/// The number is the one thing varied: the same durable certificate,
/// and three answers about what it bought.
#[tokio::test]
async fn an_acknowledgement_must_name_the_amount_that_was_signed() {
    let mut fixture = checked_job().await;
    let id = fixture.id;
    if let Err(error) = invoice_over_wire(&fixture.service, &mut fixture.client, id).await {
        panic!("the checked job is invoiced: {error}");
    }
    match pay_over_wire(&fixture.service, &mut fixture.client, id).await {
        Ok(credited) => assert_eq!(credited, PRICE),
        Err(error) => panic!("the invoiced job is paid: {error}"),
    }

    for credited_cumulative in [PRICE - 1, PRICE, PRICE + 1] {
        let response = AdmitCertificateResponse {
            outcome: Some(AdmitOutcome::Paid(WorkPaid {
                credited_cumulative,
            })),
        };
        let read = fixture.client.acknowledged(id, &response);
        if credited_cumulative == PRICE {
            assert_eq!(read.ok(), Some(PRICE), "the amount that was signed");
            continue;
        }
        let Err(PaymentError::Acknowledged { signed, credited }) = read else {
            panic!("an acknowledgement of {credited_cumulative}: {read:?}");
        };
        assert_eq!(signed, PRICE);
        assert_eq!(credited, credited_cumulative);
    }
}

/// A job with no result yet has no invoice, and the provider says so
/// as a wait rather than a refusal.
///
/// The control is `one_invoice_and_one_certificate_pay_for_one_job`:
/// the same call, on the same channel, once a result has been computed
/// and released.
#[tokio::test]
async fn an_uncomputed_job_has_no_invoice_yet() {
    let provider_root = temp();
    let ready = ready();
    let mut provider_store = store_at(provider_root.path(), &ready, Role::Provider, CURSOR);
    let id = accept(&mut [&mut provider_store]);
    let Ok(endpoint) = ProviderEndpoint::new(ready.clone(), provider_store, provider()) else {
        panic!("the provider endpoint binds");
    };
    let service = WorkService::new(endpoint);

    let (transport, server) = transport_pair();
    let serving = serve(server, service.clone());
    let response = WorkClientImpl::new(transport)
        .request_invoice(RequestInvoiceRequest {
            work_id: id.as_bytes().to_vec(),
        })
        .await;
    stop(serving).await;
    let Ok(response) = response else {
        panic!("the call completes: {response:?}");
    };
    match response.outcome {
        Some(InvoiceOutcome::Refused(refused)) => assert_eq!(
            WorkRefusalCode::try_from(refused.code),
            Ok(WorkRefusalCode::NotReady),
        ),
        other => panic!("expected a wait, got {other:?}"),
    }
    let Ok(provider) = service.endpoint() else {
        panic!("the endpoint is reachable");
    };
    assert_eq!(
        provider.state().job().map(JobState::phase),
        Some(JobPhase::Accepted),
        "and nothing was invoiced",
    );
}

/// A job nobody has invoiced has nothing to pay for.
#[tokio::test]
async fn an_uninvoiced_job_is_not_paid() {
    let mut fixture = checked_job().await;
    let paid = fixture.client.pay(fixture.id);
    let Err(PaymentError::Unbilled { phase }) = paid else {
        panic!("a checked job with no invoice: {paid:?}");
    };
    assert_eq!(phase, JobPhase::Verified);
    assert!(
        fixture.client.state().last_payment().is_none(),
        "and nothing was signed",
    );
}

// ── Money the ledger cannot explain ───────────────────────────────────

/// A certificate whose allocation is wrong is kept and credits nothing,
/// and the allocation that is right still closes the gap afterwards.
///
/// Only the private evidence is varied: the same certificate bytes, the
/// same client signature over them, and an allocation naming a sequence
/// this channel never invoiced — signed by the client, so what refuses
/// it is the ledger and not the signature.
#[tokio::test]
async fn a_certificate_its_allocation_cannot_explain_is_kept_as_evidence() {
    let mut fixture = checked_job().await;
    let id = fixture.id;
    let channel = fixture.ready.channel().clone();
    if let Err(error) = invoice_over_wire(&fixture.service, &mut fixture.client, id).await {
        panic!("the checked job is invoiced: {error}");
    }
    let honest = match fixture.client.pay(id) {
        Ok(request) => request,
        Err(error) => panic!("the client signs its payment: {error}"),
    };

    let Ok(allocation) = CertificateAllocationV1::decode(&honest.allocation) else {
        panic!("the client's own allocation decodes");
    };
    let corrupted = CertificateAllocationV1 {
        first_invoice_seq: 2,
        last_invoice_seq: 2,
        ..allocation
    };
    let response = admit_response(
        &fixture.service,
        AdmitCertificateRequest {
            allocation: corrupted.encode(),
            allocation_signature: signature_over(
                &client(),
                signing_hash(allocation_digest(&channel, &corrupted)),
            ),
            ..honest.clone()
        },
    )
    .await;
    assert_eq!(refusal_of(&response), WorkRefusalCode::Invalid);
    {
        let Ok(provider) = fixture.service.endpoint() else {
            panic!("the endpoint is reachable");
        };
        let state = provider.state();
        assert_eq!(
            state.max_executable_certificate(),
            PRICE,
            "the money the client signed for is kept",
        );
        assert_eq!(
            state.ledger().credited_invoice_high_water(),
            0,
            "and it buys nothing",
        );
        assert_eq!(
            state.delivery_outstanding(),
            PRICE,
            "so no credit is retired",
        );
        assert_eq!(state.unallocated_gap(), Some(PRICE));
        assert_eq!(
            state.job().map(JobState::phase),
            Some(JobPhase::Invoiced),
            "and the job is still unpaid",
        );
    }

    // The same certificate with the allocation the client actually
    // signed: credited once, and the credit retired once.
    match pay_over_wire(&fixture.service, &mut fixture.client, id).await {
        Ok(credited) => assert_eq!(credited, PRICE),
        Err(error) => panic!("the durable allocation reconciles: {error}"),
    }
    let Ok(provider) = fixture.service.endpoint() else {
        panic!("the endpoint is reachable");
    };
    let state = provider.state();
    assert_eq!(state.ledger().credited_invoice_high_water(), PRICE);
    assert_eq!(state.unallocated_gap(), None);
    assert_eq!(state.compute_outstanding(), 0);
    assert_eq!(state.delivery_outstanding(), 0);
}

/// A certificate above the invoiced prefix is close evidence and
/// nothing else: no job is marked paid, and no credit is released.
#[tokio::test]
async fn a_certificate_above_the_invoiced_prefix_pays_no_job() {
    let mut fixture = checked_job().await;
    let id = fixture.id;
    let channel = fixture.ready.channel().clone();
    let entry = match invoice_over_wire(&fixture.service, &mut fixture.client, id).await {
        Ok(entry) => entry,
        Err(error) => panic!("the checked job is invoiced: {error}"),
    };

    // Correctly signed, and for one more than this channel has ever
    // invoiced. The amount is the only thing varied.
    let larger = EarnedCertificate::new(
        channel.payment_edge(),
        channel.payment_terms_hash(),
        entry.cumulative_after + 1,
    );
    let Ok(invoice_entries_root) = invoice_entries_root(&channel, &[entry]) else {
        panic!("one entry has a root");
    };
    let allocation = CertificateAllocationV1 {
        channel_id: channel.id(),
        certificate_digest: larger.digest(channel.network()),
        first_invoice_seq: entry.invoice_seq,
        last_invoice_seq: entry.invoice_seq,
        invoice_entries_root,
    };
    let response = admit_response(
        &fixture.service,
        AdmitCertificateRequest {
            certificate: certificate_bytes(&larger),
            allocation: allocation.encode(),
            allocation_signature: signature_over(
                &client(),
                signing_hash(allocation_digest(&channel, &allocation)),
            ),
            certificate_signature: signature_over(&client(), larger.digest(channel.network())),
        },
    )
    .await;
    assert_eq!(refusal_of(&response), WorkRefusalCode::Invalid);
    {
        let Ok(provider) = fixture.service.endpoint() else {
            panic!("the endpoint is reachable");
        };
        let state = provider.state();
        assert_eq!(
            state.max_executable_certificate(),
            PRICE + 1,
            "a close may name it",
        );
        assert_eq!(state.ledger().credited_invoice_high_water(), 0);
        assert_eq!(
            state.delivery_outstanding(),
            PRICE,
            "and it releases nothing"
        );
        assert_eq!(state.job().map(JobState::phase), Some(JobPhase::Invoiced));
    }

    // The job's own payment still credits its own prefix. What the
    // client signed above it stays unexplained, and while it does this
    // channel takes no new work.
    match pay_over_wire(&fixture.service, &mut fixture.client, id).await {
        Ok(credited) => assert_eq!(credited, PRICE),
        Err(error) => panic!("the invoiced prefix is still paid: {error}"),
    }
    let Ok(provider) = fixture.service.endpoint() else {
        panic!("the endpoint is reachable");
    };
    assert_eq!(provider.state().max_executable_certificate(), PRICE + 1);
    assert_eq!(provider.state().unallocated_gap(), Some(1));
}

/// A payment is exactly the bytes the service defines, and no other
/// spelling of them.
///
/// Each request below is the honest one with one field mis-encoded, and
/// none of the three reaches a rule about money: nothing is credited,
/// and nothing is kept as evidence either.
#[tokio::test]
async fn a_payment_is_exactly_the_bytes_the_service_defines() {
    let mut fixture = checked_job().await;
    let id = fixture.id;
    if let Err(error) = invoice_over_wire(&fixture.service, &mut fixture.client, id).await {
        panic!("the checked job is invoiced: {error}");
    }
    let honest = match fixture.client.pay(id) {
        Ok(request) => request,
        Err(error) => panic!("the client signs its payment: {error}"),
    };

    let mut trailing = honest.certificate.clone();
    trailing.push(0);
    let mut truncated = honest.allocation.clone();
    truncated.pop();
    let mut short = honest.allocation_signature.clone();
    short.pop();
    let mutations = [
        (
            "a trailing byte on the certificate",
            AdmitCertificateRequest {
                certificate: trailing,
                ..honest.clone()
            },
        ),
        (
            "a truncated allocation",
            AdmitCertificateRequest {
                allocation: truncated,
                ..honest.clone()
            },
        ),
        (
            "a 63-byte allocation signature",
            AdmitCertificateRequest {
                allocation_signature: short,
                ..honest.clone()
            },
        ),
    ];
    for (what, request) in mutations {
        let response = admit_response(&fixture.service, request).await;
        assert_eq!(refusal_of(&response), WorkRefusalCode::Invalid, "{what}");
        let Ok(provider) = fixture.service.endpoint() else {
            panic!("the endpoint is reachable");
        };
        let state = provider.state();
        assert_eq!(
            state.ledger().credited_invoice_high_water(),
            0,
            "{what} credits nothing",
        );
        assert_eq!(
            state.max_executable_certificate(),
            0,
            "{what} is not evidence either",
        );
    }

    // The control: the same request, whole.
    let response = admit_response(&fixture.service, honest).await;
    assert!(
        matches!(response.outcome, Some(AdmitOutcome::Paid(_))),
        "the whole request is paid: {response:?}",
    );
}

// ── Payment against default ───────────────────────────────────────────

/// A job written off and a job paid for are the same job, and exactly
/// one of the two happens.
///
/// Both orders, over the one file that decides them. Ending first: the
/// price is on this client's identity-wide loss ledger, which nothing
/// takes back, so the payment is refused *and not banked* — a provider
/// that kept both would charge the client twice for one job, and the
/// cost of the race falls on the endpoint whose default caused it.
/// Paying first: the payment closes the job, and there is nothing left
/// to end.
#[tokio::test]
async fn a_defaulted_job_is_not_paid_for_as_well() {
    let mut fixture = checked_job().await;
    let id = fixture.id;
    if let Err(error) = invoice_over_wire(&fixture.service, &mut fixture.client, id).await {
        panic!("the checked job is invoiced: {error}");
    }
    {
        let Ok(mut provider) = fixture.service.endpoint() else {
            panic!("the endpoint is reachable");
        };
        if let Err(error) = provider.end_run(id, JobEnd::Expired) {
            panic!("the provider defaults the job: {error}");
        }
        assert_eq!(provider.state().loss().compute, PRICE);
        assert_eq!(provider.state().loss().delivery, PRICE);
    }

    let paid = pay_over_wire(&fixture.service, &mut fixture.client, id).await;
    let Err(PaymentError::Refused { refusal, .. }) = paid else {
        panic!("a defaulted job takes no payment: {paid:?}");
    };
    assert_eq!(refusal, WorkRefusal::Declined);
    {
        let Ok(provider) = fixture.service.endpoint() else {
            panic!("the endpoint is reachable");
        };
        let state = provider.state();
        assert_eq!(state.ledger().credited_invoice_high_water(), 0);
        assert_eq!(
            state.max_executable_certificate(),
            0,
            "a job already written off is not banked as well",
        );
        assert_eq!(state.loss().compute, PRICE, "and the write-off stands");
    }
    assert_eq!(
        fixture
            .client
            .state()
            .ledger()
            .credited_invoice_high_water(),
        PRICE,
        "the client holds a payment no provider will take",
    );

    // The other order.
    let mut fixture = checked_job().await;
    let id = fixture.id;
    if let Err(error) = invoice_over_wire(&fixture.service, &mut fixture.client, id).await {
        panic!("the checked job is invoiced: {error}");
    }
    match pay_over_wire(&fixture.service, &mut fixture.client, id).await {
        Ok(credited) => assert_eq!(credited, PRICE),
        Err(error) => panic!("the invoiced job is paid: {error}"),
    }
    let Ok(mut provider) = fixture.service.endpoint() else {
        panic!("the endpoint is reachable");
    };
    let ended = provider.end_run(id, JobEnd::Expired);
    assert!(
        matches!(ended, Err(RunError::NoSuchJob)),
        "a paid job is closed: {ended:?}",
    );
    assert_eq!(provider.state().loss().compute, 0, "and cost nothing");
    assert_eq!(
        provider.state().ledger().credited_invoice_high_water(),
        PRICE
    );
}
