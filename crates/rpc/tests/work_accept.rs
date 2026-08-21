//! The bilateral acceptance exchange: what each side has on its disk
//! before it releases a signature, and what it answers when it will not.
//!
//! Every crash here is a real one — the store is dropped and reopened
//! over its own files — and the happy path runs over a real multiplexed
//! transport, so the request is framed, routed by method id, decoded,
//! and answered rather than handed to a function.

#![cfg(feature = "work")]

use bytes::Bytes;
use hellas_kernel::{
    BlockHeight, Decode as _, Edge, EdgeId, EdgeValues, Fees, Key, LeaseSlots, List,
    MAX_EDGE_OUTPUTS, NetworkId, Parties, PayloadHash, Payout, PendingSlot, RegistryChunk,
    RegistryNamespace, RegistryRecordTag, Secp256k1Signer, Secp256k1Verifier, Sig,
    SigVerifier as _, Terms, TermsHash, WorkPaymentSettlement, WorkPaymentTerms,
    WorkStakeBondTerms, work_payment_settlement,
};
use hellas_rpc::pb::work::{
    AcceptWorkRequest, AcceptWorkResponse, WorkAccepted, WorkRefusalCode, WorkRefused,
    accept_work_response::Outcome,
};
use hellas_rpc::protocol::artifacts::{
    BoundTermId, Canonical as _, InputAddressed as _, OutputAddressed as _, PreparedPaidInputV1,
    SourceRef, TextArtifact, TextExecution, TextPolicy, TokenIds,
};
use hellas_rpc::protocol::work::{
    JobDeadlines, PaidChannel, PaidChannelPolicyV1, PaidExecutionPolicyV1, PaidJobAuthorizationV1,
    PrivateRecord as _, execution_policy_digest, generation_policy_digest, identity_source_digest,
    prepared_input_digest, private_policy_commitment, propose_authorization, signing_hash, work_id,
};
use hellas_rpc::protocol::work_setup::{
    ObservedChannel, ReadyChannel, WorkChannelConfig, WorkChannelDescriptor, payment_terms_hash,
};
use hellas_rpc::protocol::{ContentId, Digest};
use hellas_rpc::services::work::{Work, WorkServer};
use hellas_rpc::work::{
    ClientEndpoint, EndpointError, JobProposal, ProposeError, ProviderEndpoint, WorkRefusal,
    WorkService, propose_work,
};
use hellas_rpc::work_close::{FinalizedWork, observe};
use hellas_rpc::work_store::{
    ChannelRecord, ChannelState, ChannelStore, JobEnd, JobPhase, JobState, Role,
};
use hellas_rpc::{
    Assurance, Evaluate, EvaluateProgramManifest, EvaluateRequest, ProgramManifest, PublicKey,
};
use hellas_wire::mux::{MessagePipe, MuxConfig, MuxTransport, Role as MuxRole};
use hellas_wire::{DefaultClock, Dispatcher, ServiceMarker, StreamTransport};
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

/// A third party with no role on this channel.
fn stranger() -> Secp256k1Signer {
    signer(0x23)
}

fn signer(byte: u8) -> Secp256k1Signer {
    let Ok(signer) = Secp256k1Signer::from_secret_scalar([byte; 32]) else {
        panic!("a fixed scalar is a key");
    };
    signer
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

fn store(root: &std::path::Path, role: Role) -> ChannelStore {
    store_with(root, role, settlement())
}

fn store_with(
    root: &std::path::Path,
    role: Role,
    settlement: WorkPaymentSettlement,
) -> ChannelStore {
    match ChannelStore::open(
        root,
        ready().channel().clone(),
        settlement,
        role,
        &Secp256k1Verifier::new(),
    ) {
        Ok(store) => store,
        Err(error) => panic!("the fixture store opens: {error}"),
    }
}

/// A store that has processed one finalized block, which is what lets
/// either endpoint measure a deadline.
fn store_at_cursor(root: &std::path::Path, role: Role) -> ChannelStore {
    at_height(store(root, role), CURSOR)
}

fn at_height(mut store: ChannelStore, height: u64) -> ChannelStore {
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

fn client_endpoint(root: &std::path::Path) -> ClientEndpoint {
    match ClientEndpoint::new(ready(), store_at_cursor(root, Role::Client), client()) {
        Ok(endpoint) => endpoint,
        Err(error) => panic!("the fixture client endpoint binds: {error}"),
    }
}

fn provider_endpoint(root: &std::path::Path) -> ProviderEndpoint {
    match ProviderEndpoint::new(ready(), store_at_cursor(root, Role::Provider), provider()) {
        Ok(endpoint) => endpoint,
        Err(error) => panic!("the fixture provider endpoint binds: {error}"),
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

/// One job's request. The nonce byte makes two proposals two different
/// bundles, and therefore two different jobs.
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

fn bundle_bytes(nonce: u8) -> Vec<u8> {
    match bundle(nonce).encode() {
        Ok(bytes) => bytes,
        Err(error) => panic!("the fixture bundle encodes: {error}"),
    }
}

const fn deadlines() -> JobDeadlines {
    JobDeadlines {
        acceptance: 50,
        terminal: 100,
        payment: 200,
    }
}

fn proposal(nonce: u8) -> JobProposal {
    JobProposal {
        prepared_input: bundle(nonce),
        deadlines: deadlines(),
    }
}

/// The authorization the client would build for one proposal at one
/// nonce, computed here rather than taken from the endpoint.
fn authorization(nonce: u8, proposal_nonce: u64) -> PaidJobAuthorizationV1 {
    match propose_authorization(
        ready().channel(),
        &execution_policy(),
        &bundle(nonce),
        proposal_nonce,
        deadlines(),
    ) {
        Ok(authorization) => authorization,
        Err(error) => panic!("the fixture authorization builds: {error}"),
    }
}

/// A request built by hand rather than by the client endpoint, so a
/// provider test can vary exactly one field of it.
fn request(authorization: &PaidJobAuthorizationV1, signature: Sig, nonce: u8) -> AcceptWorkRequest {
    AcceptWorkRequest {
        authorization: authorization.encode(),
        client_signature: signature.as_bytes().to_vec(),
        prepared_input: bundle_bytes(nonce),
    }
}

fn signed_request(nonce: u8, proposal_nonce: u64) -> AcceptWorkRequest {
    signed_request_with(nonce, proposal_nonce, deadlines())
}

fn signed_request_with(
    nonce: u8,
    proposal_nonce: u64,
    deadlines: JobDeadlines,
) -> AcceptWorkRequest {
    let authorization = match propose_authorization(
        ready().channel(),
        &execution_policy(),
        &bundle(nonce),
        proposal_nonce,
        deadlines,
    ) {
        Ok(authorization) => authorization,
        Err(error) => panic!("the fixture authorization builds: {error}"),
    };
    let signature = client().sign(signing_hash(work_id(ready().channel(), &authorization)));
    request(&authorization, signature, nonce)
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

// ── Reading answers ───────────────────────────────────────────────────

fn accepted_signature(response: &AcceptWorkResponse) -> Sig {
    match response.outcome.as_ref() {
        Some(Outcome::Accepted(accepted)) => {
            let Ok(bytes) = <[u8; Sig::LENGTH]>::try_from(&accepted.provider_signature[..]) else {
                panic!("an accepted signature is 64 bytes");
            };
            Sig::from_bytes(bytes)
        }
        other => panic!("expected an acceptance, got {other:?}"),
    }
}

fn refusal_code(response: &AcceptWorkResponse) -> WorkRefusalCode {
    match response.outcome.as_ref() {
        Some(Outcome::Refused(refused)) => match WorkRefusalCode::try_from(refused.code) {
            Ok(code) => code,
            Err(_) => panic!("a refusal names a defined code, got {}", refused.code),
        },
        other => panic!("expected a refusal, got {other:?}"),
    }
}

fn refusal_text(response: &AcceptWorkResponse) -> String {
    match response.outcome.as_ref() {
        Some(Outcome::Refused(refused)) => refused.reason.clone(),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

// ── An in-memory pipe pair, so the wire is a real wire ────────────────

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

/// Serves one provider endpoint over one transport until the caller
/// drops the returned handle.
fn serve(transport: MuxTransport, service: WorkService) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let server = WorkServer(service);
        while let Ok(Some(inbound)) = transport.accept().await {
            let _ = Dispatcher::<MuxTransport>::dispatch(&server, inbound).await;
        }
    })
}

// ── The exchange, over a real transport ───────────────────────────────

#[tokio::test]
async fn an_accepted_exchange_leaves_both_signatures_on_both_disks() {
    let client_root = temp();
    let provider_root = temp();
    let service = WorkService::new(provider_endpoint(provider_root.path()));
    let (client_transport, server_transport) = transport_pair();
    let serving = serve(server_transport, service.clone());

    let mut endpoint = client_endpoint(client_root.path());
    let accepted = propose_work(client_transport, &mut endpoint, &proposal(1)).await;
    let Ok(work_id) = accepted else {
        panic!("the fixture exchange completes: {accepted:?}");
    };

    // Both endpoints let go of their journals before anything reopens
    // them: the exclusive lock is the store's, and a live server still
    // holds one.
    drop(endpoint);
    serving.abort();
    let _ = serving.await;
    drop(service);

    // Reopened from the files, not read from the objects that wrote
    // them: what is on the disk is the only thing a restart has.
    let client_store = store(client_root.path(), Role::Client);
    let provider_store = store(provider_root.path(), Role::Provider);
    for (side, state) in [
        ("client", client_store.state()),
        ("provider", provider_store.state()),
    ] {
        let Some(job) = state.job() else {
            panic!("the {side} journal holds the accepted job");
        };
        assert_eq!(job.work_id(), work_id, "{side} names the same job");
        assert_eq!(job.phase(), JobPhase::Accepted, "{side} is accepted");
        assert!(
            job.provider_signature().is_some(),
            "{side} holds the co-signature",
        );
    }
    // The provider reserved this job's compute the moment it took the
    // proposal, not when it dispatches.
    assert_eq!(provider_store.state().compute_outstanding(), PRICE);
    assert_eq!(client_store.state().next_proposal_nonce(), 2);
}

#[tokio::test]
async fn the_service_answers_a_refusal_over_the_same_wire() {
    let provider_root = temp();
    // A provider that has processed no block cannot measure a deadline.
    let endpoint = match ProviderEndpoint::new(
        ready(),
        store(provider_root.path(), Role::Provider),
        provider(),
    ) {
        Ok(endpoint) => endpoint,
        Err(error) => panic!("the endpoint binds: {error}"),
    };
    let service = WorkService::new(endpoint);
    let (client_transport, server_transport) = transport_pair();
    let serving = serve(server_transport, service);

    let client = hellas_rpc::services::work::WorkClientImpl::new(client_transport);
    let response = match client.accept_work(signed_request(1, 1)).await {
        Ok(response) => response,
        Err(status) => panic!("the call completes: {status}"),
    };
    serving.abort();
    assert_eq!(refusal_code(&response), WorkRefusalCode::NotReady);
}

#[test]
fn the_service_catalogue_names_the_work_service_and_nothing_settled() {
    let names: Vec<&str> = hellas_rpc::services::KNOWN_SERVICES
        .iter()
        .map(|service| service.name)
        .collect();
    assert!(
        names.contains(&"hellas.work.v1.Work"),
        "the work service is catalogued, got {names:?}",
    );
    assert_eq!(<Work as ServiceMarker>::ALPN, "/hellas.work.v1.Work/2.0");
    for dead in ["Receipt", "Settle", "JobAcceptance"] {
        assert!(
            !names.iter().any(|name| name.contains(dead)),
            "the single-edge protocol's {dead} is gone, got {names:?}",
        );
    }
}

// ── What the client puts on its disk, and when ────────────────────────

#[test]
fn a_client_journals_its_signature_before_the_request_leaves() {
    let root = temp();
    let mut endpoint = client_endpoint(root.path());
    let Ok(request) = endpoint.propose(&proposal(1)) else {
        panic!("the fixture proposal is accepted by its own rules");
    };
    drop(endpoint);

    let reopened = store(root.path(), Role::Client);
    let Some(job) = reopened.state().job() else {
        panic!("the journal holds the proposal the caller was handed");
    };
    assert_eq!(job.phase(), JobPhase::HalfSigned);
    assert_eq!(
        job.client_signature().as_bytes().to_vec(),
        request.client_signature,
        "the signature on the disk is the signature on the wire",
    );
    assert_eq!(job.authorization().encode(), request.authorization);
    assert_eq!(job.prepared_input(), request.prepared_input);
}

#[test]
fn a_proposal_refused_before_signing_spends_no_nonce() {
    let root = temp();
    let mut endpoint = client_endpoint(root.path());
    // Terminal deadline inside the measured dispatch and delivery
    // margins: legal, ordered, and unreachable.
    let unreachable = JobProposal {
        prepared_input: bundle(1),
        deadlines: JobDeadlines {
            acceptance: 11,
            terminal: 12,
            payment: 30,
        },
    };
    let refused = endpoint.propose(&unreachable);
    assert!(
        matches!(refused, Err(ProposeError::Setup(_))),
        "an unreachable terminal deadline is refused, got {refused:?}",
    );
    assert_eq!(endpoint.state().next_proposal_nonce(), 1);
    assert!(endpoint.state().job().is_none());
    drop(endpoint);
    assert!(store(root.path(), Role::Client).state().job().is_none());
}

#[test]
fn a_repeat_proposal_returns_the_retained_request() {
    let root = temp();
    let mut endpoint = client_endpoint(root.path());
    let Ok(first) = endpoint.propose(&proposal(1)) else {
        panic!("the first proposal is built");
    };
    let before = endpoint.state().next_proposal_nonce();
    let Ok(second) = endpoint.propose(&proposal(1)) else {
        panic!("the same proposal is retained, not rebuilt");
    };
    assert_eq!(first, second, "the retained bytes come back unchanged");
    assert_eq!(
        endpoint.state().next_proposal_nonce(),
        before,
        "a retry spends no second nonce",
    );
}

#[test]
fn a_different_proposal_while_one_is_outstanding_conflicts() {
    let root = temp();
    let mut endpoint = client_endpoint(root.path());
    let Ok(_) = endpoint.propose(&proposal(1)) else {
        panic!("the first proposal is built");
    };
    let conflict = endpoint.propose(&proposal(2));
    assert!(
        matches!(conflict, Err(ProposeError::Conflict)),
        "a second job is a conflict, not a queue, got {conflict:?}",
    );
}

#[test]
fn a_client_with_no_finalized_block_signs_nothing() {
    let root = temp();
    let Ok(mut endpoint) = ClientEndpoint::new(ready(), store(root.path(), Role::Client), client())
    else {
        panic!("the endpoint binds");
    };
    let refused = endpoint.propose(&proposal(1));
    assert!(
        matches!(refused, Err(ProposeError::NoCursor)),
        "no cursor, no signature, got {refused:?}",
    );
}

#[test]
fn an_acceptance_with_no_proposal_has_nothing_to_answer() {
    let root = temp();
    let mut endpoint = client_endpoint(root.path());
    let authorization = authorization(1, 1);
    let signature = provider().sign(signing_hash(work_id(ready().channel(), &authorization)));
    let response = accepted_response(signature);
    let refused = endpoint.accepted(&response);
    assert!(
        matches!(refused, Err(ProposeError::NoOpenJob)),
        "an acceptance answers a proposal or nothing, got {refused:?}",
    );
}

#[test]
fn a_co_signature_from_another_key_is_not_an_acceptance() {
    let root = temp();
    let mut endpoint = client_endpoint(root.path());
    let Ok(_) = endpoint.propose(&proposal(1)) else {
        panic!("the proposal is built");
    };
    let authorization = authorization(1, 1);
    let forged = stranger().sign(signing_hash(work_id(ready().channel(), &authorization)));
    let refused = endpoint.accepted(&accepted_response(forged));
    assert!(
        matches!(refused, Err(ProposeError::Store(_))),
        "only the provider's key accepts, got {refused:?}",
    );
    assert_eq!(
        phase_of(endpoint.state()),
        Some(JobPhase::HalfSigned),
        "a forged co-signature moves nothing",
    );
}

#[test]
fn a_refusal_is_read_back_as_the_refusal_it_names() {
    let root = temp();
    let mut endpoint = client_endpoint(root.path());
    let Ok(_) = endpoint.propose(&proposal(1)) else {
        panic!("the proposal is built");
    };
    let response = AcceptWorkResponse {
        outcome: Some(Outcome::Refused(WorkRefused {
            code: WorkRefusalCode::Declined as i32,
            reason: "no".into(),
        })),
    };
    let refused = endpoint.accepted(&response);
    assert!(
        matches!(
            refused,
            Err(ProposeError::Refused {
                refusal: WorkRefusal::Declined,
                ..
            })
        ),
        "the client reads the code the provider sent, got {refused:?}",
    );
}

#[test]
fn a_response_this_service_does_not_define_is_malformed() {
    let root = temp();
    let mut endpoint = client_endpoint(root.path());
    let Ok(_) = endpoint.propose(&proposal(1)) else {
        panic!("the proposal is built");
    };
    for (what, response) in [
        ("no outcome", AcceptWorkResponse { outcome: None }),
        (
            "unspecified refusal",
            AcceptWorkResponse {
                outcome: Some(Outcome::Refused(WorkRefused {
                    code: WorkRefusalCode::Unspecified as i32,
                    reason: String::new(),
                })),
            },
        ),
        (
            "unassigned refusal",
            AcceptWorkResponse {
                outcome: Some(Outcome::Refused(WorkRefused {
                    code: 99,
                    reason: String::new(),
                })),
            },
        ),
        (
            "short signature",
            AcceptWorkResponse {
                outcome: Some(Outcome::Accepted(WorkAccepted {
                    provider_signature: vec![0; Sig::LENGTH - 1],
                })),
            },
        ),
    ] {
        let refused = endpoint.accepted(&response);
        assert!(
            matches!(refused, Err(ProposeError::Malformed(_))),
            "{what} is malformed, got {refused:?}",
        );
    }
}

fn accepted_response(signature: Sig) -> AcceptWorkResponse {
    AcceptWorkResponse {
        outcome: Some(Outcome::Accepted(WorkAccepted {
            provider_signature: signature.as_bytes().to_vec(),
        })),
    }
}

fn phase_of(state: &ChannelState) -> Option<JobPhase> {
    state.job().map(JobState::phase)
}

// ── What the provider puts on its disk, and when ──────────────────────

#[test]
fn the_co_signature_is_on_the_disk_before_it_is_answered() {
    let root = temp();
    let mut endpoint = provider_endpoint(root.path());
    let response = endpoint.accept(&signed_request(1, 1));
    let signature = accepted_signature(&response);
    drop(endpoint);

    let reopened = store(root.path(), Role::Provider);
    let Some(job) = reopened.state().job() else {
        panic!("the journal holds the job it answered for");
    };
    assert_eq!(job.phase(), JobPhase::Accepted);
    assert_eq!(job.provider_signature(), Some(signature));
}

#[test]
fn nothing_is_journaled_for_a_proposal_that_is_refused() {
    let root = temp();
    let mut endpoint = provider_endpoint(root.path());
    let before = endpoint.state().job().is_none();
    // Another channel's authorization: the channel id is the first
    // thing `check_authorization` compares.
    let mut foreign = authorization(1, 1);
    foreign.channel_id = Digest::from_bytes([0x00; 32]);
    let signature = client().sign(signing_hash(work_id(ready().channel(), &foreign)));
    let response = endpoint.accept(&request(&foreign, signature, 1));

    assert_eq!(refusal_code(&response), WorkRefusalCode::Invalid);
    assert!(before && endpoint.state().job().is_none());
    assert_eq!(endpoint.state().compute_outstanding(), 0);
    drop(endpoint);
    assert!(store(root.path(), Role::Provider).state().job().is_none());
}

/// A proposal the journal's own rules would take, refused by the rules
/// that run before it.
///
/// `apply_proposed` checks the channel, the bundle digest, the client
/// signature, and the nonce. It does not check the price, the policy
/// digest, or the deadline order, because nothing in a journal knows
/// what a policy fixed. So this is the case that separates the two: with
/// the acceptance checks removed, these bytes are journaled, credited,
/// and co-signed.
#[test]
fn a_price_the_policy_does_not_fix_is_refused_before_anything_is_journaled() {
    let root = temp();
    let mut endpoint = provider_endpoint(root.path());
    let mut overpriced = authorization(1, 1);
    overpriced.price = PRICE + 1;
    let signature = client().sign(signing_hash(work_id(ready().channel(), &overpriced)));
    let response = endpoint.accept(&request(&overpriced, signature, 1));

    assert_eq!(
        refusal_code(&response),
        WorkRefusalCode::Invalid,
        "{}",
        refusal_text(&response),
    );
    assert!(endpoint.state().job().is_none());
    assert_eq!(endpoint.state().compute_outstanding(), 0);
    drop(endpoint);
    assert!(store(root.path(), Role::Provider).state().job().is_none());
}

#[test]
fn a_retry_returns_the_retained_co_signature() {
    let root = temp();
    let mut endpoint = provider_endpoint(root.path());
    let first = accepted_signature(&endpoint.accept(&signed_request(1, 1)));
    let second = accepted_signature(&endpoint.accept(&signed_request(1, 1)));
    assert_eq!(first, second);
    assert_eq!(
        endpoint.state().compute_outstanding(),
        PRICE,
        "one job's credit, however many times it is asked for",
    );
}

#[test]
fn a_retry_after_the_deadline_still_returns_the_retained_signature() {
    let root = temp();
    let mut endpoint = provider_endpoint(root.path());
    let first = accepted_signature(&endpoint.accept(&signed_request(1, 1)));
    drop(endpoint);

    // The same provider, now well past the acceptance deadline.
    let late = at_height(
        store(root.path(), Role::Provider),
        deadlines().acceptance + 1,
    );
    let Ok(mut endpoint) = ProviderEndpoint::new(ready(), late, provider()) else {
        panic!("the endpoint binds");
    };
    let again = endpoint.accept(&signed_request(1, 1));
    assert_eq!(
        accepted_signature(&again),
        first,
        "an answer already given is not unsaid by a passing height",
    );
}

#[test]
fn a_crash_between_the_two_commits_co_signs_on_retry() {
    let root = temp();
    // A provider that journaled the proposal and died before signing.
    let mut store = store_at_cursor(root.path(), Role::Provider);
    let authorization = authorization(1, 1);
    let signature = client().sign(signing_hash(work_id(ready().channel(), &authorization)));
    if let Err(error) = store.commit(
        ChannelRecord::JobProposed {
            authorization,
            client_signature: signature,
            prepared_input: bundle_bytes(1),
        },
        &Secp256k1Verifier::new(),
    ) {
        panic!("the proposal is journaled: {error}");
    }
    drop(store);

    let mut endpoint = provider_endpoint(root.path());
    assert_eq!(
        phase_of(endpoint.state()),
        Some(JobPhase::HalfSigned),
        "the reopened provider is half-signed",
    );
    let response = endpoint.accept(&request(&authorization, signature, 1));
    assert_eq!(phase_of(endpoint.state()), Some(JobPhase::Accepted),);
    accepted_signature(&response);
    assert_eq!(
        endpoint.state().compute_outstanding(),
        PRICE,
        "the credit the first process reserved is not reserved again",
    );
}

// ── The six refusals, one at a time ───────────────────────────────────

#[test]
fn a_provider_with_no_finalized_block_is_not_ready() {
    let root = temp();
    let Ok(mut endpoint) =
        ProviderEndpoint::new(ready(), store(root.path(), Role::Provider), provider())
    else {
        panic!("the endpoint binds");
    };
    let response = endpoint.accept(&signed_request(1, 1));
    assert_eq!(refusal_code(&response), WorkRefusalCode::NotReady);
    assert!(WorkRefusal::NotReady.is_retryable());
}

#[test]
fn an_authorization_past_its_acceptance_deadline_expires() {
    let root = temp();
    let late = at_height(
        store(root.path(), Role::Provider),
        deadlines().acceptance + 1,
    );
    let Ok(mut endpoint) = ProviderEndpoint::new(ready(), late, provider()) else {
        panic!("the endpoint binds");
    };
    let response = endpoint.accept(&signed_request(1, 1));
    assert_eq!(refusal_code(&response), WorkRefusalCode::Expired);
    assert!(!WorkRefusal::Expired.is_retryable());
}

#[test]
fn a_bundle_that_is_not_the_committed_one_is_invalid() {
    let root = temp();
    let mut endpoint = provider_endpoint(root.path());
    // The authorization commits to bundle 1; the request carries 2.
    let authorization = authorization(1, 1);
    let signature = client().sign(signing_hash(work_id(ready().channel(), &authorization)));
    let response = endpoint.accept(&request(&authorization, signature, 2));
    assert_eq!(refusal_code(&response), WorkRefusalCode::Invalid);
    assert!(endpoint.state().job().is_none());
}

/// A bundle that hashes to its own authorization and still breaks the
/// policy the channel signed.
///
/// The digest binding is not the same rule as the envelope: a client is
/// free to commit to whatever it likes, and what makes a proposal
/// runnable is that the committed graph fits inside the bounds both
/// parties fixed. Nothing in a journal can see that.
fn overlong_bundle() -> PreparedPaidInputV1 {
    // The channel allows 128 new tokens; this asks for 129.
    let policy = TextPolicy::from_u32_stop_tokens(129, [2, 1]);
    let execution = TextExecution::new(
        SourceRef::output(identity_artifact().output_id()),
        prompt_tokens().output_id(),
        policy.output_id(),
    );
    let mut request = evaluate_request(1);
    request.text_execution = execution.input_id().digest();
    PreparedPaidInputV1::new(
        &request,
        &manifest(),
        &execution,
        &prompt_tokens(),
        &policy,
        &identity_artifact(),
    )
}

/// A bundle whose runner is not the channel's client, likewise
/// self-consistent and likewise not runnable here.
fn foreign_runner_bundle() -> PreparedPaidInputV1 {
    let mut request = evaluate_request(1);
    request.runner_public_key = PublicKey::Secp256k1(stranger().party_key().to_bytes());
    PreparedPaidInputV1::new(
        &request,
        &manifest(),
        &text_execution(),
        &prompt_tokens(),
        &text_policy(),
        &identity_artifact(),
    )
}

#[test]
fn a_bundle_the_policy_does_not_allow_is_refused_though_its_digest_matches() {
    let root = temp();
    let mut endpoint = provider_endpoint(root.path());
    for (what, bundle) in [
        ("a generation policy over the envelope", overlong_bundle()),
        ("a runner that is not the client", foreign_runner_bundle()),
    ] {
        let authorization = match propose_authorization(
            ready().channel(),
            &execution_policy(),
            &bundle,
            1,
            deadlines(),
        ) {
            Ok(authorization) => authorization,
            Err(error) => panic!("{what} still builds an authorization: {error}"),
        };
        let signature = client().sign(signing_hash(work_id(ready().channel(), &authorization)));
        let Ok(bytes) = bundle.encode() else {
            panic!("{what} encodes");
        };
        let response = endpoint.accept(&AcceptWorkRequest {
            authorization: authorization.encode(),
            client_signature: signature.as_bytes().to_vec(),
            prepared_input: bytes,
        });

        assert_eq!(
            refusal_code(&response),
            WorkRefusalCode::Invalid,
            "{what}: {}",
            refusal_text(&response),
        );
        assert!(endpoint.state().job().is_none(), "{what} reserved nothing");
    }
}

#[test]
fn a_forged_client_signature_is_invalid() {
    let root = temp();
    let mut endpoint = provider_endpoint(root.path());
    let authorization = authorization(1, 1);
    let forged = stranger().sign(signing_hash(work_id(ready().channel(), &authorization)));
    let response = endpoint.accept(&request(&authorization, forged, 1));
    assert_eq!(refusal_code(&response), WorkRefusalCode::Invalid);
    assert!(
        endpoint.state().job().is_none(),
        "a proposal nobody signed reserves nothing",
    );
}

/// A signature is exactly 64 bytes, and a longer field is not one.
///
/// The load-bearing case is the last: the real signature with a byte
/// after it. A field of the wrong length full of *garbage* is refused by
/// the verifier however the length is read, so on its own it proves
/// nothing about the length rule — it is here as the neighbour that a
/// reader who truncates would also refuse.
#[test]
fn a_signature_of_any_other_length_is_not_a_signature() {
    let root = temp();
    let mut endpoint = provider_endpoint(root.path());
    let valid = signed_request(1, 1).client_signature;

    let mut cases: Vec<(String, Vec<u8>)> = [Sig::LENGTH - 1, Sig::LENGTH + 1, 0]
        .into_iter()
        .map(|length| (format!("{length} garbage bytes"), vec![0x11; length]))
        .collect();
    cases.push((
        "the signature with a byte after it".to_owned(),
        valid.iter().copied().chain([0x00]).collect(),
    ));
    cases.push((
        "the signature one byte short".to_owned(),
        valid[..Sig::LENGTH - 1].to_vec(),
    ));

    for (what, client_signature) in cases {
        let mut request = signed_request(1, 1);
        request.client_signature = client_signature;
        let response = endpoint.accept(&request);
        assert_eq!(
            refusal_code(&response),
            WorkRefusalCode::Invalid,
            "{what} is refused",
        );
        assert!(endpoint.state().job().is_none(), "{what} reserved nothing");
    }
}

/// The two refusals the measured margins produce, and the reason they
/// are not the same answer.
///
/// A terminal deadline this height can no longer reach is a fact about
/// the height, and no later one recovers it. A payment deadline too
/// close to its terminal is a fact about two carried numbers and no
/// height at all, so it is wrong rather than late.
#[test]
fn the_measured_margins_separate_a_late_job_from_a_malformed_one() {
    let root = temp();
    let mut endpoint = provider_endpoint(root.path());
    for (what, deadlines, expected) in [
        (
            "a terminal deadline inside the dispatch and delivery margins",
            JobDeadlines {
                acceptance: 12,
                terminal: 13,
                payment: 100,
            },
            WorkRefusalCode::Expired,
        ),
        (
            "a payment deadline under the measured oracle grace",
            JobDeadlines {
                acceptance: 50,
                terminal: 100,
                payment: 103,
            },
            WorkRefusalCode::Invalid,
        ),
    ] {
        let response = endpoint.accept(&signed_request_with(1, 1, deadlines));
        assert_eq!(
            refusal_code(&response),
            expected,
            "{what}: {}",
            refusal_text(&response),
        );
        assert!(endpoint.state().job().is_none(), "{what} reserved nothing",);
    }
}

#[test]
fn bytes_that_are_not_an_authorization_are_invalid() {
    let root = temp();
    let mut endpoint = provider_endpoint(root.path());
    let mut truncated = signed_request(1, 1);
    truncated.authorization.pop();
    assert_eq!(
        refusal_code(&endpoint.accept(&truncated)),
        WorkRefusalCode::Invalid,
    );

    let mut retagged = signed_request(1, 1);
    retagged.authorization[1] = 0xfe;
    assert_eq!(
        refusal_code(&endpoint.accept(&retagged)),
        WorkRefusalCode::Invalid,
    );
}

#[test]
fn a_job_already_in_flight_declines_the_next_one() {
    let root = temp();
    let mut endpoint = provider_endpoint(root.path());
    accepted_signature(&endpoint.accept(&signed_request(1, 1)));
    let response = endpoint.accept(&signed_request(2, 2));
    assert_eq!(refusal_code(&response), WorkRefusalCode::Declined);
    assert_eq!(
        endpoint.state().compute_outstanding(),
        PRICE,
        "the refused job reserved nothing",
    );
}

#[test]
fn an_unallocated_certificate_declines_new_work() {
    let root = temp();
    let mut store = store_at_cursor(root.path(), Role::Provider);
    // A valid client certificate larger than anything this ledger has
    // credited: money the provider holds and cannot say what for.
    let certificate = hellas_kernel::EarnedCertificate::new(
        ready().channel().payment_edge(),
        ready().channel().payment_terms_hash(),
        1,
    );
    let signature = client().sign(certificate.digest(network()));
    if let Err(error) = store.commit(
        ChannelRecord::CertificateGift {
            certificate,
            certificate_signature: signature,
        },
        &Secp256k1Verifier::new(),
    ) {
        panic!("a gift is journaled: {error}");
    }
    let Ok(mut endpoint) = ProviderEndpoint::new(ready(), store, provider()) else {
        panic!("the endpoint binds");
    };
    assert_eq!(endpoint.state().unallocated_gap(), Some(1));
    let response = endpoint.accept(&signed_request(1, 1));
    assert_eq!(refusal_code(&response), WorkRefusalCode::Declined);
}

#[test]
fn a_nonce_this_channel_has_already_seen_is_a_conflict() {
    let root = temp();
    let mut endpoint = provider_endpoint(root.path());
    accepted_signature(&endpoint.accept(&signed_request(1, 1)));
    drop(endpoint);

    // The job ends unpaid, releasing its credit and never its nonce.
    let mut ending = store(root.path(), Role::Provider);
    if let Err(error) = ending.commit(
        ChannelRecord::JobEnded {
            reason: JobEnd::Expired,
        },
        &Secp256k1Verifier::new(),
    ) {
        panic!("the job ends: {error}");
    }
    drop(ending);

    let mut endpoint = provider_endpoint(root.path());
    assert_eq!(endpoint.state().compute_outstanding(), 0);
    // A different job — a different bundle — at the nonce the ended job
    // already spent.
    let response = endpoint.accept(&signed_request(2, 1));
    assert_eq!(
        refusal_code(&response),
        WorkRefusalCode::Conflict,
        "a burnt nonce stays burnt: {}",
        refusal_text(&response),
    );
}

#[test]
fn a_poisoned_endpoint_is_unavailable() {
    let root = temp();
    let service = WorkService::new(provider_endpoint(root.path()));
    let poisoner = service.clone();
    let panicked = std::thread::spawn(move || {
        let _guard = poisoner.endpoint();
        panic!("poison the endpoint");
    })
    .join();
    assert!(panicked.is_err(), "the helper thread panicked on purpose");
    assert!(matches!(service.endpoint(), Err(EndpointError::Poisoned)));
}

// ── Binding an endpoint to its own half of its own channel ────────────

/// A nonce spent by a process that did not come back is not spent again.
#[test]
fn a_nonce_burnt_by_a_crash_is_not_used_again() {
    let root = temp();
    // The client reserved nonce 1 and died before it built a proposal.
    let mut store = store_at_cursor(root.path(), Role::Client);
    if let Err(error) = store.commit(
        ChannelRecord::NonceReserved { nonce: 1 },
        &Secp256k1Verifier::new(),
    ) {
        panic!("a nonce is reserved: {error}");
    }
    drop(store);

    let mut endpoint = client_endpoint(root.path());
    let Ok(request) = endpoint.propose(&proposal(1)) else {
        panic!("the next proposal is built");
    };
    let Ok(built) = PaidJobAuthorizationV1::decode(&request.authorization) else {
        panic!("the request carries an authorization");
    };
    assert_eq!(
        built.proposal_nonce, 2,
        "the burnt nonce is not offered a second time",
    );
}

#[test]
fn an_endpoint_needs_its_own_store_settlement_role_and_key() {
    let root = temp();
    let wrong_role = ProviderEndpoint::new(ready(), store(root.path(), Role::Client), provider());
    assert!(
        matches!(wrong_role, Err(EndpointError::WrongRole { .. })),
        "a client journal is not a provider endpoint, got {wrong_role:?}",
    );

    let other = temp();
    let wrong_key = ProviderEndpoint::new(ready(), store(other.path(), Role::Provider), client());
    assert!(
        matches!(wrong_key, Err(EndpointError::WrongKey { .. })),
        "the client's key does not co-sign as the provider, got {wrong_key:?}",
    );

    let third = temp();
    let Some(thin) = work_payment_settlement(
        EdgeValues::new(PAYMENT_VALUE - 1, PAYMENT_RESERVE, Fees::new(0, 0, 0, 0)),
        OMISSION_BOND,
    ) else {
        panic!("a funded edge prices both exits");
    };
    let wrong_settlement = ProviderEndpoint::new(
        ready(),
        store_with(third.path(), Role::Provider, thin),
        provider(),
    );
    assert!(
        matches!(wrong_settlement, Err(EndpointError::WrongSettlement)),
        "a store bounded by other funding is not this channel's, got {wrong_settlement:?}",
    );

    let fourth = temp();
    let Ok(elsewhere) = PaidChannel::new(
        network(),
        EdgeId::from_bytes([0x99; EdgeId::LENGTH]),
        payment_terms(),
        &SALT,
        channel_policy(),
    ) else {
        panic!("a second payment edge is a second channel");
    };
    let Ok(other_store) = ChannelStore::open(
        fourth.path(),
        elsewhere,
        settlement(),
        Role::Provider,
        &Secp256k1Verifier::new(),
    ) else {
        panic!("the other channel's store opens");
    };
    let wrong_channel = ProviderEndpoint::new(ready(), other_store, provider());
    assert!(
        matches!(wrong_channel, Err(EndpointError::WrongChannel)),
        "another channel's journal is not this channel's, got {wrong_channel:?}",
    );

    let fifth = temp();
    let ok = ClientEndpoint::new(ready(), store(fifth.path(), Role::Client), client());
    assert!(ok.is_ok(), "the matching triple binds: {ok:?}");
}

// ── What the authorization derives ────────────────────────────────────

#[test]
fn the_authorization_derives_every_field_it_does_not_choose() {
    let channel = ready().channel().clone();
    let policy = execution_policy();
    let built = authorization(7, 3);
    let request = evaluate_request(7);

    // Each field against an independently computed value, not against
    // a second call to the same constructor: a swap of two fields of
    // the same width survives a round trip and does not survive this.
    assert_eq!(built.channel_id, channel.id());
    assert_eq!(built.bond_edge, bond_edge());
    assert_eq!(built.bond_terms_hash, payment_terms().bond_terms_hash());
    assert_eq!(built.payment_edge, payment_edge());
    assert_eq!(
        built.payment_terms_hash,
        payment_terms_hash(payment_terms()),
    );
    assert_eq!(
        built.execution_policy_digest,
        execution_policy_digest(&channel, &policy),
    );
    assert_eq!(
        built.prepared_input_digest,
        match prepared_input_digest(&channel, &bundle(7)) {
            Ok(digest) => digest,
            Err(error) => panic!("the bundle hashes: {error}"),
        },
    );
    assert_eq!(built.proposal_nonce, 3);
    assert_eq!(built.acceptance_deadline, deadlines().acceptance);
    assert_eq!(built.request_commitment, Evaluate::commit_request(&request));
    assert_eq!(built.environment_commitment, manifest().content_id());
    assert_eq!(built.price, policy.fixed_price);
    assert_eq!(built.terminal_deadline, deadlines().terminal);
    assert_eq!(built.payment_deadline, deadlines().payment);

    // The three deadlines are distinct, so the three assertions above
    // are three assertions and not one repeated.
    assert!(
        deadlines().acceptance != deadlines().terminal
            && deadlines().terminal != deadlines().payment,
    );
}

#[test]
fn the_wire_carries_the_authorization_the_signature_covers() {
    let root = temp();
    let mut endpoint = client_endpoint(root.path());
    let Ok(request) = endpoint.propose(&proposal(1)) else {
        panic!("the proposal is built");
    };
    let authorization = authorization(1, 1);
    assert_eq!(
        request.authorization,
        authorization.encode(),
        "the wire field is the canonical record, not a re-spelling",
    );
    assert_eq!(
        request.authorization.get(..2),
        Some(&[1_u8, 2_u8][..]),
        "format version 1, private record tag 2",
    );
    assert_eq!(request.prepared_input, bundle_bytes(1));

    let expected = client().sign(signing_hash(work_id(ready().channel(), &authorization)));
    assert_eq!(request.client_signature, expected.as_bytes().to_vec());
    assert!(
        Secp256k1Verifier::new().verify_sig(
            expected,
            client().party_key(),
            PayloadHash::from_bytes(work_id(ready().channel(), &authorization).into_bytes(),),
        ),
        "the signature on the wire verifies over the work id",
    );
}
