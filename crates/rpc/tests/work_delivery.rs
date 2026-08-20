//! Delivering one job's answer: what leaves the provider, what it costs
//! the moment it does, and what the client will take.
//!
//! The happy path runs over a real multiplexed transport, so the request
//! is framed, routed by method id, decoded, and answered rather than
//! handed to a function. Every crash is a real one: the store is dropped
//! and reopened over its own files.

#![cfg(feature = "work")]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;
use hellas_kernel::{
    BlockHeight, Decode as _, Edge, EdgeId, EdgeValues, Fees, Key, LeaseSlots, List,
    MAX_EDGE_OUTPUTS, NetworkId, Parties, Payout, PendingSlot, RegistryChunk, RegistryNamespace,
    RegistryRecordTag, Secp256k1Signer, Secp256k1Verifier, Terms, TermsHash, WorkPaymentSettlement,
    WorkPaymentTerms, WorkStakeBondTerms, work_payment_settlement,
};
use hellas_rpc::evaluate::{
    EvaluateOutputTranscriptBuilder, EvaluateStopReason, EvaluateTerminal, EvaluateUsage,
    input_commitment,
};
use hellas_rpc::pb::work::{
    DeliverResultRequest, DeliverResultResponse, WorkDelivered, WorkRefusalCode,
    deliver_result_response::Outcome,
};
use hellas_rpc::protocol::artifacts::{
    BoundTermId, Canonical as _, InputAddressed as _, OutputAddressed as _, PreparedPaidInputV1,
    SourceRef, TextArtifact, TextExecution, TextPolicy, TokenIds,
};
use hellas_rpc::protocol::work::{
    JobDeadlines, PaidChannelPolicyV1, PaidExecutionPolicyV1, PaidJobAuthorizationV1,
    PrivateRecord as _, encode_transcript, generation_policy_digest, identity_source_digest,
    private_policy_commitment, propose_authorization, signing_hash, terminal_result, work_id,
};
use hellas_rpc::protocol::work_setup::{
    ObservedChannel, ReadyChannel, WorkChannelConfig, WorkChannelDescriptor, WorkSetupError,
    payment_terms_hash,
};
use hellas_rpc::protocol::{ContentId, Digest};
use hellas_rpc::services::work::{WorkClientImpl, WorkServer};
use hellas_rpc::work::{
    BackendFault, ClientEndpoint, DeliverError, PaidEvaluateBackend, ProviderEndpoint, RunOutcome,
    WorkService, fetch_result, run_accepted_work,
};
use hellas_rpc::work_store::{ChannelRecord, ChannelStore, JobPhase, JobState, Role};
use hellas_rpc::{
    Assurance, EvaluateProgramManifest, EvaluateRequest, OutputEventEnvelope, ProducerSigningKey,
    ProgramManifest, PublicKey,
};
use hellas_wire::mux::{MessagePipe, MuxConfig, MuxTransport, Role as MuxRole};
use hellas_wire::{DefaultClock, Dispatcher, StreamTransport};
use tokio::sync::mpsc;

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
const CURSOR_PAYLOAD: [u8; 32] = [0xc0; 32];
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

/// The last height at which the signed delivery margin still fits
/// before the terminal deadline.
const LAST_RELEASE: u64 = deadlines().terminal - 2;

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

/// The execution policy, with the one bound a test varies as its
/// argument.
fn policy_with(max_encoded_result_frame: u32) -> PaidExecutionPolicyV1 {
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
        max_encoded_result_frame,
        max_encoded_quote_response: 1_048_576,
        dispatch_margin_blocks: 4,
        delivery_margin_blocks: 2,
        oracle_grace_blocks: 6,
        fixed_price: PRICE,
    }
}

fn execution_policy() -> PaidExecutionPolicyV1 {
    policy_with(WIDE_FRAME)
}

fn payment_values() -> EdgeValues {
    EdgeValues::new(PAYMENT_VALUE, PAYMENT_RESERVE, Fees::new(0, 0, 0, 0))
}

fn descriptor_with(policy: PaidExecutionPolicyV1) -> WorkChannelDescriptor {
    let config = WorkChannelConfig {
        network: network(),
        payment_edge: payment_edge(),
        payment_terms: payment_terms(),
        policy_salt: SALT,
        channel_policy: channel_policy(),
        execution_policy: policy,
        expected_payment_values: payment_values(),
        omission_response_probability: Q,
        omission_response_cost_cap: COST_CAP,
    };
    match WorkChannelDescriptor::open(config) {
        Ok(descriptor) => descriptor,
        Err(error) => panic!("the fixture channel opens: {error}"),
    }
}

fn ready_of(descriptor: &WorkChannelDescriptor, height: u64) -> ReadyChannel {
    let bond = bond_object();
    let payment = payment_object();
    let observed = ObservedChannel {
        height,
        bond: Some(&bond),
        payment: Some(&payment),
        lease: lease_over(bond_edge(), payment_edge()),
        pending: PendingSlot::Absent,
    };
    match descriptor.check_ready(&observed) {
        Ok(ready) => ready,
        Err(error) => panic!("the fixture channel is ready: {error}"),
    }
}

fn ready_at(height: u64) -> ReadyChannel {
    ready_of(&descriptor_with(execution_policy()), height)
}

fn ready() -> ReadyChannel {
    ready_at(CURSOR)
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
    if store.state().cursor().is_none() {
        commit(
            &mut store,
            ChannelRecord::CursorAdvanced {
                height,
                payload: CURSOR_PAYLOAD,
            },
        );
    }
    store
}

/// Moves one store's finalized cursor forward, as a running P8a
/// catch-up will.
fn advance(store: &mut ChannelStore, height: u64) {
    if store.state().cursor() == Some((height, CURSOR_PAYLOAD)) {
        return;
    }
    commit(
        store,
        ChannelRecord::CursorAdvanced {
            height,
            payload: CURSOR_PAYLOAD,
        },
    );
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

fn authorization(policy: &PaidExecutionPolicyV1, nonce: u8) -> PaidJobAuthorizationV1 {
    match propose_authorization(
        ready_of(&descriptor_with(*policy), CURSOR).channel(),
        policy,
        &bundle(nonce),
        u64::from(nonce),
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
fn accept(
    policy: &PaidExecutionPolicyV1,
    stores: &mut [&mut ChannelStore],
    nonce: u8,
) -> (Digest, PaidJobAuthorizationV1) {
    let authorization = authorization(policy, nonce);
    let ready = ready_of(&descriptor_with(*policy), CURSOR);
    let id = work_id(ready.channel(), &authorization);
    let Ok(prepared_input) = bundle(nonce).encode() else {
        panic!("the fixture bundle encodes");
    };
    for store in stores {
        if store.state().role() == Role::Client {
            commit(
                store,
                ChannelRecord::NonceReserved {
                    nonce: nonce.into(),
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
    (id, authorization)
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

fn serve(transport: MuxTransport, service: WorkService) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let server = WorkServer(service);
        while let Ok(Some(inbound)) = transport.accept().await {
            let _ = Dispatcher::<MuxTransport>::dispatch(&server, inbound).await;
        }
    })
}

fn refusal_code(response: &DeliverResultResponse) -> WorkRefusalCode {
    match &response.outcome {
        Some(Outcome::Refused(refused)) => match WorkRefusalCode::try_from(refused.code) {
            Ok(code) => code,
            Err(error) => panic!("the refusal code is one of the six: {error}"),
        },
        other => panic!("expected a refusal, got {other:?}"),
    }
}

// ── One answer, over the wire, debited once ───────────────────────────

/// One job's answer crosses a real transport, lands on the client's
/// disk, and costs the provider exactly one job's delivery credit
/// however many times it is fetched.
#[tokio::test]
async fn one_answer_crosses_the_wire_and_is_debited_once() {
    let client_root = temp();
    let provider_root = temp();
    let ready = ready();
    let mut client_store = store_at(client_root.path(), &ready, Role::Client, CURSOR);
    let mut provider_store = store_at(provider_root.path(), &ready, Role::Provider, CURSOR);
    let (id, authorization) = accept(
        &execution_policy(),
        &mut [&mut client_store, &mut provider_store],
        1,
    );

    let Ok(provider_endpoint) = ProviderEndpoint::new(ready.clone(), provider_store, provider())
    else {
        panic!("the provider endpoint binds");
    };
    let service = WorkService::new(provider_endpoint);
    run_to_result(&service, &ready, id).await;

    let (transport, server_transport) = transport_pair();
    let serving = serve(server_transport, service.clone());
    let Ok(mut endpoint) = ClientEndpoint::new(ready.clone(), client_store, client()) else {
        panic!("the client endpoint binds");
    };

    let delivered = match fetch_result(transport, &mut endpoint, &ready, id).await {
        Ok(delivery) => delivery,
        Err(error) => panic!("the fixture delivery completes: {error}"),
    };

    // The answer the client holds is the answer the provider computed,
    // rebuilt here from the delivered events rather than trusted.
    let Ok(events) = hellas_rpc::protocol::work::decode_transcript(&delivered.transcript, 1 << 20)
    else {
        panic!("the delivered transcript decodes");
    };
    assert_eq!(
        terminal_result(ready.channel(), &authorization, &events),
        Ok(delivered.result),
    );
    assert_eq!(delivered.result.work_id, id);

    // One debit on the provider's side, and the client is at Ready with
    // no verdict yet.
    {
        let Ok(provider) = service.endpoint() else {
            panic!("the endpoint is reachable");
        };
        assert_eq!(provider.state().delivery_outstanding(), PRICE);
        assert_eq!(
            provider.state().job().map(JobState::phase),
            Some(JobPhase::Delivered)
        );
    }
    assert_eq!(
        endpoint.state().job().map(JobState::phase),
        Some(JobPhase::Ready)
    );

    // The retry a client makes when its response was lost: the same
    // bytes, and no second debit.
    let (transport, second) = transport_pair();
    let serving_again = serve(second, service.clone());
    let again = match fetch_result(transport, &mut endpoint, &ready, id).await {
        Ok(delivery) => delivery,
        Err(error) => panic!("a replayed delivery completes: {error}"),
    };
    assert_eq!(again, delivered, "the same answer came back");
    let Ok(provider) = service.endpoint() else {
        panic!("the endpoint is reachable");
    };
    assert_eq!(
        provider.state().delivery_outstanding(),
        PRICE,
        "a replay reuses the debit it already made",
    );
    drop(provider);

    // The verdict is the client's own step, and it moves the phase.
    if let Err(error) = endpoint.verified(id) {
        panic!("the client records its verdict: {error}");
    }
    assert_eq!(
        endpoint.state().job().map(JobState::phase),
        Some(JobPhase::Verified)
    );

    serving.abort();
    serving_again.abort();
    drop(endpoint);
    drop(service);

    // And it is all on the disk: reopened from the files, the client's
    // journal still holds the result and the transcript it came with.
    let recovered = store_at(client_root.path(), &ready, Role::Client, CURSOR);
    let Some(job) = recovered.state().job() else {
        panic!("the job is still open");
    };
    assert_eq!(job.phase(), JobPhase::Verified);
    assert_eq!(
        job.result().map(|(result, _)| *result),
        Some(delivered.result)
    );
    assert_eq!(job.transcript(), delivered.transcript);
}

// ── The gate in front of the first byte ───────────────────────────────

/// A release whose measured margin no longer fits before the terminal
/// deadline sends nothing and debits nothing.
///
/// One block either side of the boundary the signed policy measures,
/// with the provider's processed height as the only thing varied.
#[tokio::test]
async fn the_last_height_the_delivery_margin_fits_is_the_last_that_may_release() {
    for (height, may_release) in [(LAST_RELEASE, true), (LAST_RELEASE + 1, false)] {
        // The job is accepted and run early, because the dispatch gate
        // has its own margin; only the release height is varied.
        let provider_root = temp();
        let early = ready_at(CURSOR);
        let mut provider_store = store_at(provider_root.path(), &early, Role::Provider, CURSOR);
        let (id, _) = accept(&execution_policy(), &mut [&mut provider_store], 1);
        let Ok(endpoint) = ProviderEndpoint::new(early.clone(), provider_store, provider()) else {
            panic!("the provider endpoint binds");
        };
        let service = WorkService::new(endpoint);
        run_to_result(&service, &early, id).await;
        drop(service);

        let ready = ready_at(height);
        let mut provider_store = store_at(provider_root.path(), &ready, Role::Provider, height);
        advance(&mut provider_store, height);
        let Ok(mut endpoint) = ProviderEndpoint::new(ready.clone(), provider_store, provider())
        else {
            panic!("the provider endpoint binds at the release height");
        };
        let released = endpoint.deliver(id, &ready);
        if may_release {
            if let Err(error) = released {
                panic!("at {height} the margin still fits: {error}");
            }
            assert_eq!(endpoint.state().delivery_outstanding(), PRICE);
            continue;
        }
        let Err(DeliverError::Setup(WorkSetupError::DeliveryUnreachable { terminal, .. })) =
            released
        else {
            panic!("at {height} the margin does not fit: {released:?}");
        };
        assert_eq!(terminal, deadlines().terminal);
        assert_eq!(
            endpoint.state().delivery_outstanding(),
            0,
            "nothing left, so nothing was debited",
        );
        assert_eq!(
            endpoint.state().job().map(JobState::phase),
            Some(JobPhase::Ready),
            "and nothing was marked released",
        );
    }
}

/// A job with no signed result has no answer to release.
#[tokio::test]
async fn a_job_with_no_result_releases_nothing() {
    let provider_root = temp();
    let ready = ready();
    let mut provider_store = store_at(provider_root.path(), &ready, Role::Provider, CURSOR);
    let (id, _) = accept(&execution_policy(), &mut [&mut provider_store], 1);
    let Ok(endpoint) = ProviderEndpoint::new(ready.clone(), provider_store, provider()) else {
        panic!("the provider endpoint binds");
    };
    let service = WorkService::new(endpoint);

    let (transport, server_transport) = transport_pair();
    let serving = serve(server_transport, service.clone());
    let response = match WorkClientImpl::new(transport)
        .deliver_result(DeliverResultRequest {
            work_id: id.as_bytes().to_vec(),
        })
        .await
    {
        Ok(response) => response,
        Err(status) => panic!("the call completes: {status}"),
    };
    serving.abort();
    assert_eq!(refusal_code(&response), WorkRefusalCode::Declined);

    {
        let Ok(endpoint) = service.endpoint() else {
            panic!("the endpoint is reachable");
        };
        assert_eq!(endpoint.state().delivery_outstanding(), 0);
    }

    // The control: the same request, once the job has a result.
    run_to_result(&service, &ready, id).await;
    let (transport, server_transport) = transport_pair();
    let serving = serve(server_transport, service.clone());
    let response = match WorkClientImpl::new(transport)
        .deliver_result(DeliverResultRequest {
            work_id: id.as_bytes().to_vec(),
        })
        .await
    {
        Ok(response) => response,
        Err(status) => panic!("the call completes: {status}"),
    };
    serving.abort();
    assert!(
        matches!(response.outcome, Some(Outcome::Delivered(_))),
        "a finished job delivers: {response:?}",
    );
}

/// A `work_id` that is not this channel's open job is refused, and a
/// `work_id` that is not 32 bytes never reaches a journal.
#[tokio::test]
async fn a_delivery_named_for_another_job_finds_nothing() {
    let provider_root = temp();
    let ready = ready();
    let mut provider_store = store_at(provider_root.path(), &ready, Role::Provider, CURSOR);
    let (id, _) = accept(&execution_policy(), &mut [&mut provider_store], 1);
    let Ok(endpoint) = ProviderEndpoint::new(ready.clone(), provider_store, provider()) else {
        panic!("the provider endpoint binds");
    };
    let service = WorkService::new(endpoint);
    run_to_result(&service, &ready, id).await;

    let other = work_id(ready.channel(), &authorization(&execution_policy(), 2));
    assert_ne!(other, id);
    for (name, work_id) in [
        ("another job", other.as_bytes().to_vec()),
        ("a truncated id", other.as_bytes()[..31].to_vec()),
    ] {
        let (transport, server_transport) = transport_pair();
        let serving = serve(server_transport, service.clone());
        let response = match WorkClientImpl::new(transport)
            .deliver_result(DeliverResultRequest { work_id })
            .await
        {
            Ok(response) => response,
            Err(status) => panic!("the call for {name} completes: {status}"),
        };
        serving.abort();
        assert!(
            matches!(response.outcome, Some(Outcome::Refused(_))),
            "{name} is refused: {response:?}",
        );
    }

    let Ok(endpoint) = service.endpoint() else {
        panic!("the endpoint is reachable");
    };
    assert_eq!(endpoint.state().delivery_outstanding(), 0);
    assert_eq!(
        endpoint.state().job().map(JobState::phase),
        Some(JobPhase::Ready),
    );
}

// ── What the client will take ─────────────────────────────────────────

/// The client refuses a delivery larger than the frame it signed a
/// bound for.
///
/// The bound is the only thing varied: the same job, the same answer,
/// under two channels that differ in `max_encoded_result_frame` alone.
#[tokio::test]
async fn a_client_refuses_a_frame_over_the_bound_it_signed() {
    // Measure the legal delivery first, then re-run the whole exchange
    // under a policy whose bound is one byte below it.
    let generous = delivered_frame_len(WIDE_FRAME).await;
    let tight = u32::try_from(generous - 1).unwrap_or(u32::MAX);

    let client_root = temp();
    let provider_root = temp();
    let policy = policy_with(tight);
    let descriptor = descriptor_with(policy);
    let ready = ready_of(&descriptor, CURSOR);
    let mut client_store = store_at(client_root.path(), &ready, Role::Client, CURSOR);
    let mut provider_store = store_at(provider_root.path(), &ready, Role::Provider, CURSOR);
    let (id, _) = accept(&policy, &mut [&mut client_store, &mut provider_store], 1);
    let Ok(provider_endpoint) = ProviderEndpoint::new(ready.clone(), provider_store, provider())
    else {
        panic!("the provider endpoint binds");
    };
    let service = WorkService::new(provider_endpoint);
    run_to_result(&service, &ready, id).await;

    let (transport, server_transport) = transport_pair();
    let serving = serve(server_transport, service.clone());
    let Ok(mut endpoint) = ClientEndpoint::new(ready.clone(), client_store, client()) else {
        panic!("the client endpoint binds");
    };
    let refused = fetch_result(transport, &mut endpoint, &ready, id).await;
    serving.abort();

    let Err(DeliverError::OverFrame { actual, limit }) = refused else {
        panic!("an oversized frame is refused: {refused:?}");
    };
    assert_eq!(actual, generous);
    assert_eq!(limit, u64::from(tight));
    assert_eq!(
        endpoint.state().job().map(JobState::phase),
        Some(JobPhase::Accepted),
        "nothing was recorded",
    );
}

/// Returns the encoded length of one legal delivery under `frame`.
async fn delivered_frame_len(frame: u32) -> u64 {
    use prost::Message as _;

    let provider_root = temp();
    let policy = policy_with(frame);
    let ready = ready_of(&descriptor_with(policy), CURSOR);
    let mut provider_store = store_at(provider_root.path(), &ready, Role::Provider, CURSOR);
    let (id, _) = accept(&policy, &mut [&mut provider_store], 1);
    let Ok(endpoint) = ProviderEndpoint::new(ready.clone(), provider_store, provider()) else {
        panic!("the provider endpoint binds");
    };
    let service = WorkService::new(endpoint);
    run_to_result(&service, &ready, id).await;
    let Ok(mut endpoint) = service.endpoint() else {
        panic!("the endpoint is reachable");
    };
    let Ok(delivery) = endpoint.deliver(id, &ready) else {
        panic!("the fixture delivery is released");
    };
    WorkDelivered {
        result: delivery.result.encode(),
        provider_signature: delivery.signature.as_bytes().to_vec(),
        transcript: delivery.transcript,
    }
    .encoded_len() as u64
}

/// A transcript swapped in transit is not recorded, however well the
/// result beside it is signed.
///
/// This is the tamper the client's own rebuild exists for: the provider
/// signed the result honestly, and something between the two endpoints
/// replaced the events it summarises.
#[tokio::test]
async fn a_transcript_swapped_in_transit_is_not_recorded() {
    let client_root = temp();
    let provider_root = temp();
    let ready = ready();
    let mut client_store = store_at(client_root.path(), &ready, Role::Client, CURSOR);
    let mut provider_store = store_at(provider_root.path(), &ready, Role::Provider, CURSOR);
    let (id, _) = accept(
        &execution_policy(),
        &mut [&mut client_store, &mut provider_store],
        1,
    );
    let Ok(provider_endpoint) = ProviderEndpoint::new(ready.clone(), provider_store, provider())
    else {
        panic!("the provider endpoint binds");
    };
    let service = WorkService::new(provider_endpoint);
    run_to_result(&service, &ready, id).await;
    let Ok(mut provider) = service.endpoint() else {
        panic!("the endpoint is reachable");
    };
    let Ok(delivery) = provider.deliver(id, &ready) else {
        panic!("the fixture delivery is released");
    };
    drop(provider);

    let Ok(mut endpoint) = ClientEndpoint::new(ready.clone(), client_store, client()) else {
        panic!("the client endpoint binds");
    };
    let honest = WorkDelivered {
        result: delivery.result.encode(),
        provider_signature: delivery.signature.as_bytes().to_vec(),
        transcript: delivery.transcript.clone(),
    };

    // MUTATION: the same signed result, beside a valid signed transcript
    // of a different answer to the same request.
    let Ok(other) = encode_transcript(&transcript_for(&evaluate_request(1), &[7, 7, 7])) else {
        panic!("the other transcript encodes");
    };
    assert_ne!(other, delivery.transcript);
    let tampered = WorkDelivered {
        transcript: other,
        ..honest.clone()
    };
    let refused = endpoint.receive(id, &ready, &tampered);
    assert!(
        matches!(refused, Err(DeliverError::Store(_))),
        "a swapped transcript is refused: {refused:?}",
    );
    assert_eq!(
        endpoint.state().job().map(JobState::phase),
        Some(JobPhase::Accepted),
        "nothing was recorded",
    );

    // The control: the untampered delivery is taken.
    if let Err(error) = endpoint.receive(id, &ready, &honest) {
        panic!("the honest delivery records: {error}");
    }
    assert_eq!(
        endpoint.state().job().map(JobState::phase),
        Some(JobPhase::Ready),
    );
}

/// A client that has not caught up to its own readiness records no
/// receipt.
#[tokio::test]
async fn a_client_behind_its_readiness_records_no_receipt() {
    let client_root = temp();
    let provider_root = temp();
    let ready = ready();
    let mut client_store = store_at(client_root.path(), &ready, Role::Client, CURSOR);
    let mut provider_store = store_at(provider_root.path(), &ready, Role::Provider, CURSOR);
    let (id, _) = accept(
        &execution_policy(),
        &mut [&mut client_store, &mut provider_store],
        1,
    );
    let Ok(provider_endpoint) = ProviderEndpoint::new(ready.clone(), provider_store, provider())
    else {
        panic!("the provider endpoint binds");
    };
    let service = WorkService::new(provider_endpoint);
    run_to_result(&service, &ready, id).await;
    let Ok(mut provider) = service.endpoint() else {
        panic!("the endpoint is reachable");
    };
    let Ok(delivery) = provider.deliver(id, &ready) else {
        panic!("the fixture delivery is released");
    };
    drop(provider);

    let delivered = WorkDelivered {
        result: delivery.result.encode(),
        provider_signature: delivery.signature.as_bytes().to_vec(),
        transcript: delivery.transcript,
    };
    let Ok(mut endpoint) = ClientEndpoint::new(ready.clone(), client_store, client()) else {
        panic!("the client endpoint binds");
    };

    // MUTATION: a readiness decided at a later block than this endpoint
    // has processed. The blocks between are where a contest it must not
    // build evidence over would appear.
    let ahead = ready_at(CURSOR + 1);
    let refused = endpoint.receive(id, &ahead, &delivered);
    assert!(
        matches!(
            refused,
            Err(DeliverError::Setup(WorkSetupError::CursorBehind {
                cursor: CURSOR,
                height: 11
            }))
        ),
        "unexpected answer: {refused:?}",
    );

    // The control: the readiness this endpoint has caught up to.
    if let Err(error) = endpoint.receive(id, &ready, &delivered) {
        panic!("a caught-up client records the receipt: {error}");
    }
}

/// A verdict names the job the client holds, and nothing else.
#[tokio::test]
async fn a_verdict_names_the_job_the_client_holds() {
    let client_root = temp();
    let ready = ready();
    let mut client_store = store_at(client_root.path(), &ready, Role::Client, CURSOR);
    let (id, _) = accept(&execution_policy(), &mut [&mut client_store], 1);
    let Ok(mut endpoint) = ClientEndpoint::new(ready.clone(), client_store, client()) else {
        panic!("the client endpoint binds");
    };

    let other = work_id(ready.channel(), &authorization(&execution_policy(), 2));
    assert_ne!(other, id);
    assert!(
        matches!(endpoint.verified(other), Err(DeliverError::NoSuchJob)),
        "a verdict about another job is not this job's",
    );

    // And a verdict about a job with no result at all is refused by the
    // journal rather than recorded.
    let refused = endpoint.verified(id);
    assert!(
        matches!(refused, Err(DeliverError::Store(_))),
        "unexpected answer: {refused:?}",
    );
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
