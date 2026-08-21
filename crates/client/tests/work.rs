//! One paid job, end to end, from the client's side: proposed,
//! computed by a real provider endpoint, delivered, checked by an
//! engine that never speaks to the provider, and paid for.
//!
//! Both endpoints are real and hold real journals, and the exchange runs
//! over a real multiplexed transport, framed and routed by method id.
//! The one double is the reexecution engine, because this repository has
//! no second implementation of the model to plug in — so what these
//! tests establish is the orchestration around the check and the
//! consequences of its verdict, not that any particular model
//! reproduces.

#![cfg(feature = "work")]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;
use hellas_client::work::invoice::pay_for_checked_result;
use hellas_client::work::oracle::{OracleFault, Reexecuted, Reexecution, ReexecutionRequest};
use hellas_client::work::{CheckedResult, CollectError, CollectOutcome, collect_checked_result};
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
use hellas_rpc::protocol::artifacts::{
    BoundTermId, Canonical as _, InputAddressed as _, OutputAddressed as _, PreparedPaidInputV1,
    SourceRef, TextArtifact, TextExecution, TextExecutionId, TextPolicy, TokenIds, completed_text,
};
use hellas_rpc::protocol::work::{
    JobDeadlines, PaidChannelPolicyV1, PaidExecutionPolicyV1, PaidJobAuthorizationV1,
    generation_policy_digest, identity_source_digest, private_policy_commitment,
    propose_authorization, signing_hash, work_id,
};
use hellas_rpc::protocol::work_setup::{
    ObservedChannel, ReadyChannel, WorkChannelConfig, WorkChannelDescriptor, payment_terms_hash,
};
use hellas_rpc::protocol::{ContentId, Digest};
use hellas_rpc::services::work::{WorkClientImpl, WorkServer};
use hellas_rpc::work::{
    BackendFault, ClientEndpoint, PaidEvaluateBackend, ProviderEndpoint, RunOutcome, WorkService,
    request_invoice, run_accepted_work,
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
        max_encoded_result_frame: 262_144,
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

fn ready() -> ReadyChannel {
    ready_of(&descriptor_with(execution_policy()), CURSOR)
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

/// The prompt every job here runs on. It is the whole input, because
/// this profile starts from an identity artifact.
const PROMPT: [u32; 4] = [9, 8, 7, 6];

fn prompt_tokens() -> TokenIds {
    TokenIds::from(PROMPT.to_vec())
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
    // The artifact a provider's own store records for this execution.
    // A placeholder would do for the tests that never reexecute; here
    // it would make an honest provider look wrong, because the answer
    // digest binds this field and the oracle derives it.
    let text_artifact = completed_text(
        TextExecutionId::from_digest(request.text_execution),
        &PROMPT,
        answer,
    )
    .artifact
    .output_id()
    .digest();
    match builder.finish(EvaluateTerminal {
        final_position: answer.len() as u64,
        stop_reason: EvaluateStopReason::END_OF_SEQUENCE,
        text_artifact,
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

// ── The reexecution engine double ─────────────────────────────────────

/// An engine that answers with fixed tokens, or refuses.
///
/// It is handed a question derived from the accepted bundle and has no
/// other input, which is the property that makes it stand in for an
/// independent implementation at all: nothing it can see comes from the
/// provider's answer.
struct FixedEngine {
    answer: Result<Reexecuted, OracleFault>,
}

impl FixedEngine {
    fn answering(tokens: &[u32]) -> Self {
        Self {
            answer: Ok(Reexecuted {
                output_token_ids: tokens.to_vec(),
                stop_reason: EvaluateStopReason::END_OF_SEQUENCE,
            }),
        }
    }

    fn agreeing() -> Self {
        Self::answering(&ANSWER)
    }

    fn failing(reason: &str) -> Self {
        Self {
            answer: Err(OracleFault::Engine(reason.to_string())),
        }
    }
}

impl Reexecution for FixedEngine {
    fn reexecute(&self, _request: &ReexecutionRequest) -> Result<Reexecuted, OracleFault> {
        self.answer.clone()
    }
}

// ── The whole path ────────────────────────────────────────────────────

/// One job, proposed and computed and delivered and checked, and a
/// client journal that ends in the phase an invoice may be asked from.
#[tokio::test]
async fn a_checked_answer_is_the_only_thing_that_reaches_the_verified_phase() {
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
    let Ok(mut endpoint) = ClientEndpoint::new(ready.clone(), client_store, client()) else {
        panic!("the client endpoint binds");
    };
    let engine = FixedEngine::agreeing();

    // Before the provider has run anything, asking is a wait rather than
    // a failure, and nothing is recorded.
    let (transport, server) = transport_pair();
    let serving = serve(server, service.clone());
    let waiting = collect_checked_result(transport, &mut endpoint, &ready, &engine, id).await;
    serving.abort();
    assert!(
        matches!(waiting, Ok(CollectOutcome::NotReady { .. })),
        "unexpected outcome: {waiting:?}",
    );
    assert_eq!(
        endpoint.state().job().map(JobState::phase),
        Some(JobPhase::Accepted),
    );

    run_to_result(&service, &ready, id).await;

    let (transport, server) = transport_pair();
    let serving = serve(server, service.clone());
    let collected = collect_checked_result(transport, &mut endpoint, &ready, &engine, id).await;
    serving.abort();
    let Ok(CollectOutcome::Checked(CheckedResult { result, transcript })) = collected else {
        panic!("the checked answer is collected: {collected:?}");
    };
    assert_eq!(result.work_id, id);
    assert!(!transcript.is_empty());
    assert_eq!(
        endpoint.state().job().map(JobState::phase),
        Some(JobPhase::Verified),
    );

    // A second call is the same call: the provider answers from its
    // spool at no second delivery debit, and the verdict is the same
    // verdict.
    let (transport, server) = transport_pair();
    let serving = serve(server, service.clone());
    let again = collect_checked_result(transport, &mut endpoint, &ready, &engine, id).await;
    serving.abort();
    assert!(
        matches!(again, Ok(CollectOutcome::Checked(_))),
        "unexpected outcome: {again:?}",
    );
    {
        let Ok(provider) = service.endpoint() else {
            panic!("the endpoint is reachable");
        };
        assert_eq!(provider.state().delivery_outstanding(), PRICE);
    }

    // And it is on the disk: reopened from the files by a process that
    // saw none of this, the job is still checked.
    drop(endpoint);
    drop(service);
    let recovered = store_at(client_root.path(), &ready, Role::Client, CURSOR);
    let Some(job) = recovered.state().job() else {
        panic!("the job is still open");
    };
    assert_eq!(job.phase(), JobPhase::Verified);
    assert_eq!(job.result().map(|(result, _)| *result), Some(result));
}

/// The whole of the client's side: a checked answer becomes a payment
/// the provider has admitted.
///
/// What each side ends holding is asserted from its own journal, and
/// the client's is asserted from a reopened file — a process that saw
/// none of this and knows only what reached the disk.
#[tokio::test]
async fn a_checked_answer_becomes_a_payment_the_provider_admitted() {
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
    let Ok(mut endpoint) = ClientEndpoint::new(ready.clone(), client_store, client()) else {
        panic!("the client endpoint binds");
    };
    let engine = FixedEngine::agreeing();
    run_to_result(&service, &ready, id).await;

    let (transport, server) = transport_pair();
    let serving = serve(server, service.clone());
    let collected = collect_checked_result(transport, &mut endpoint, &ready, &engine, id).await;
    serving.abort();
    assert!(
        matches!(collected, Ok(CollectOutcome::Checked(_))),
        "the answer is checked: {collected:?}",
    );

    let (transport, server) = transport_pair();
    let serving = serve(server, service.clone());
    let credited = pay_for_checked_result(transport, &mut endpoint, id).await;
    serving.abort();
    let Ok(credited) = credited else {
        panic!("the checked answer is paid for: {credited:?}");
    };
    assert_eq!(credited, PRICE, "one job at its authorized price");

    // The provider has the certificate and has let the job's credit go,
    // in that order and in one record.
    {
        let Ok(provider) = service.endpoint() else {
            panic!("the endpoint is reachable");
        };
        let state = provider.state();
        assert_eq!(state.ledger().credited_invoice_high_water(), PRICE);
        assert_eq!(state.max_executable_certificate(), PRICE);
        assert_eq!(state.compute_outstanding(), 0);
        assert_eq!(state.delivery_outstanding(), 0);
        assert!(state.job().is_none(), "the job is closed by its payment");
    }

    drop(endpoint);
    drop(service);
    let recovered = store_at(client_root.path(), &ready, Role::Client, CURSOR);
    let state = recovered.state();
    assert!(state.job().is_none());
    assert_eq!(state.ledger().credited_invoice_high_water(), PRICE);
    assert_eq!(state.ledger().next_invoice_seq(), 2);
    let Some(payment) = state.last_payment() else {
        panic!("the payment is on the disk");
    };
    assert_eq!(payment.work_id, id);
    assert_eq!(payment.certificate.earned_cumulative(), PRICE);
}

/// A payment signed before a crash is re-sent after it, and credited
/// once.
///
/// The client dies between fsyncing its certificate and sending it —
/// the one window where its journal holds a payment no provider has
/// seen. What comes back is not a second signature: it is the same
/// bytes, off the disk of a process that never made them.
#[tokio::test]
async fn a_payment_signed_before_a_crash_is_re_sent_after_it() {
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
    let Ok(mut endpoint) = ClientEndpoint::new(ready.clone(), client_store, client()) else {
        panic!("the client endpoint binds");
    };
    run_to_result(&service, &ready, id).await;

    let (transport, server) = transport_pair();
    let serving = serve(server, service.clone());
    let collected = collect_checked_result(
        transport,
        &mut endpoint,
        &ready,
        &FixedEngine::agreeing(),
        id,
    )
    .await;
    serving.abort();
    assert!(
        matches!(collected, Ok(CollectOutcome::Checked(_))),
        "the answer is checked: {collected:?}",
    );

    // Invoiced and signed, and then the process is gone before a byte
    // of the certificate leaves it.
    let (transport, server) = transport_pair();
    let serving = serve(server, service.clone());
    let invoiced = request_invoice(&WorkClientImpl::new(transport), &mut endpoint, id).await;
    serving.abort();
    if let Err(error) = invoiced {
        panic!("the checked job is invoiced: {error}");
    }
    let signed = endpoint.pay(id);
    assert!(signed.is_ok(), "the client signs its payment: {signed:?}");
    drop(endpoint);
    {
        let Ok(provider) = service.endpoint() else {
            panic!("the endpoint is reachable");
        };
        assert_eq!(
            provider.state().ledger().credited_invoice_high_water(),
            0,
            "and the provider has seen nothing",
        );
    }

    let recovered = store_at(client_root.path(), &ready, Role::Client, CURSOR);
    let Ok(mut endpoint) = ClientEndpoint::new(ready.clone(), recovered, client()) else {
        panic!("the client endpoint rebinds");
    };
    let (transport, server) = transport_pair();
    let serving = serve(server, service.clone());
    let credited = pay_for_checked_result(transport, &mut endpoint, id).await;
    serving.abort();
    assert_eq!(credited.ok(), Some(PRICE));

    let Ok(provider) = service.endpoint() else {
        panic!("the endpoint is reachable");
    };
    assert_eq!(
        provider.state().ledger().credited_invoice_high_water(),
        PRICE
    );
    assert_eq!(provider.state().compute_outstanding(), 0);
    assert_eq!(provider.state().delivery_outstanding(), 0);
}

/// An unchecked answer is not paid for, and asking to pay for one
/// signs nothing.
///
/// The verdict is the only thing varied: the same delivered result,
/// refused before it and paid after it.
#[tokio::test]
async fn an_unchecked_answer_is_not_paid_for() {
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
    let Ok(mut endpoint) = ClientEndpoint::new(ready.clone(), client_store, client()) else {
        panic!("the client endpoint binds");
    };
    run_to_result(&service, &ready, id).await;

    // The result is fetched and journaled, and no oracle has run.
    let (transport, server) = transport_pair();
    let serving = serve(server, service.clone());
    // One token of the provider's answer, changed: the engine's verdict
    // is the only thing this test varies.
    let mut other = ANSWER;
    other[2] = 999;
    let refuted = collect_checked_result(
        transport,
        &mut endpoint,
        &ready,
        &FixedEngine::answering(&other),
        id,
    )
    .await;
    serving.abort();
    assert!(
        matches!(refuted, Err(CollectError::Refuted(_))),
        "the engine refuses the answer: {refuted:?}",
    );
    assert_eq!(
        endpoint.state().job().map(JobState::phase),
        Some(JobPhase::Ready),
        "and the job is not in a phase an invoice may be asked from",
    );

    let (transport, server) = transport_pair();
    let serving = serve(server, service.clone());
    let paid = pay_for_checked_result(transport, &mut endpoint, id).await;
    serving.abort();
    assert!(
        paid.is_err(),
        "an unchecked answer is not paid for: {paid:?}"
    );
    assert!(
        endpoint.state().last_payment().is_none(),
        "and nothing was signed",
    );
    {
        let Ok(provider) = service.endpoint() else {
            panic!("the endpoint is reachable");
        };
        assert_eq!(provider.state().ledger().credited_invoice_high_water(), 0);
    }

    // The control: the same delivered result, checked, is paid for.
    let (transport, server) = transport_pair();
    let serving = serve(server, service.clone());
    let checked = collect_checked_result(
        transport,
        &mut endpoint,
        &ready,
        &FixedEngine::agreeing(),
        id,
    )
    .await;
    serving.abort();
    assert!(
        matches!(checked, Ok(CollectOutcome::Checked(_))),
        "the same answer, checked: {checked:?}",
    );
    let (transport, server) = transport_pair();
    let serving = serve(server, service.clone());
    let credited = pay_for_checked_result(transport, &mut endpoint, id).await;
    serving.abort();
    assert_eq!(credited.ok(), Some(PRICE));
}

/// An answer the client's own engine does not reproduce is refused, and
/// stays refused across a restart.
///
/// The provider here is honest in every checkable way: its result is
/// signed over its own transcript, its transcript is signed under the
/// channel's provider key, and its delivery is timely. The only thing
/// wrong with it is the answer, and nothing but reexecution can say so.
#[tokio::test]
async fn an_answer_the_engine_does_not_reproduce_never_becomes_payable() {
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
    let Ok(mut endpoint) = ClientEndpoint::new(ready.clone(), client_store, client()) else {
        panic!("the client endpoint binds");
    };

    // MUTATION: the engine's answer differs from the provider's in one
    // token. Everything else about the exchange is unchanged.
    let mut other = ANSWER;
    other[2] = 999;
    let engine = FixedEngine::answering(&other);

    let (transport, server) = transport_pair();
    let serving = serve(server, service.clone());
    let refused = collect_checked_result(transport, &mut endpoint, &ready, &engine, id).await;
    serving.abort();
    assert!(
        matches!(refused, Err(CollectError::Refuted(OracleFault::Mismatch))),
        "unexpected outcome: {refused:?}",
    );

    // The delivered result is kept as evidence, and is not checked.
    assert_eq!(
        endpoint.state().job().map(JobState::phase),
        Some(JobPhase::Ready),
    );
    drop(endpoint);
    let recovered = store_at(client_root.path(), &ready, Role::Client, CURSOR);
    assert_eq!(
        recovered.state().job().map(JobState::phase),
        Some(JobPhase::Ready),
        "a restart does not turn an unchecked result into a checked one",
    );

    // The control: the same delivery, checked by an engine that agrees,
    // reaches the verified phase. Only the engine's answer is varied.
    let Ok(mut endpoint) = ClientEndpoint::new(ready.clone(), recovered, client()) else {
        panic!("the client endpoint binds");
    };
    let (transport, server) = transport_pair();
    let serving = serve(server, service.clone());
    let checked = collect_checked_result(
        transport,
        &mut endpoint,
        &ready,
        &FixedEngine::agreeing(),
        id,
    )
    .await;
    serving.abort();
    assert!(
        matches!(checked, Ok(CollectOutcome::Checked(_))),
        "unexpected outcome: {checked:?}",
    );
    assert_eq!(
        endpoint.state().job().map(JobState::phase),
        Some(JobPhase::Verified),
    );
}

/// An engine that cannot run says so, and its silence is not a verdict
/// either way.
#[tokio::test]
async fn an_engine_that_cannot_run_records_no_verdict() {
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
    let Ok(mut endpoint) = ClientEndpoint::new(ready.clone(), client_store, client()) else {
        panic!("the client endpoint binds");
    };

    let engine = FixedEngine::failing("the weights did not load");
    let (transport, server) = transport_pair();
    let serving = serve(server, service.clone());
    let unchecked = collect_checked_result(transport, &mut endpoint, &ready, &engine, id).await;
    serving.abort();

    let Err(CollectError::Unchecked(OracleFault::Engine(reason))) = unchecked else {
        panic!("an engine fault is reported as one: {unchecked:?}");
    };
    assert!(reason.contains("the weights did not load"), "{reason}");
    assert_eq!(
        endpoint.state().job().map(JobState::phase),
        Some(JobPhase::Ready),
        "a check that did not happen is not a check that passed",
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
