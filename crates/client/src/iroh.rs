use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use async_stream::try_stream;
use futures::{Stream, StreamExt};
use hellas_attestation::{
    AnchorTime, AppleCredential, ApplePolicy, AssertionCounterStore, RegisteredAppleCredential,
    apple_app_attest_root_ca, apple_app_id_hash, register_apple, verify_apple_assertion,
};
use hellas_rpc::pb::courtesy::{QuoteResponse, QuoteTokensRequest, evaluate_start};
use hellas_rpc::pb::execute::{OpenRequest, OpenResponse, Ticket, open_response};
use hellas_rpc::pb::fetch::FetchRequest;
use hellas_rpc::protocol::artifacts::{
    BoundTermId, InputAddressed, OutputAddressed, SourceRef, TextArtifact, TextArtifactId,
    TextExecution, TextExecutionId, TextPolicy, TokenIds,
};
use hellas_rpc::provenance::ExecutionProvenance;
use hellas_rpc::services::courtesy::{Courtesy, Open as CourtesyOpen, QuoteTokens};
use hellas_rpc::services::execute::{Execute, ExecuteClientImpl};
use hellas_rpc::services::fetch::{Fetch, FetchClientImpl, Open as FetchOpen};
use hellas_rpc::{
    AppleAppAttestEnrollment, Assurance, ContentId, Digest, Evaluate, EvaluateProgramManifest,
    EvaluateRequest, ExecutionPackageId, InputCommitment, MAX_STOP_TOKEN_IDS, PlatformCredential,
    PlatformEnrollment, ProducerSigningKey, ProgramManifest, ProviderEnrollmentBundle, PublicKey,
    RootKind,
};
use hellas_wire::iroh::IrohTransport;
use hellas_wire::iroh::swarm::{DhtBackend, MdnsBackend, PeerExchangeBackend, ServiceRegistry};
use hellas_wire::{
    Metadata, MethodMarker, PeerIdentity, ServiceMarker, StreamTransport, WireStatus,
};
use iroh_mdns_address_lookup::MdnsAddressLookup;

use crate::error::ClientContext;
use crate::{
    ClientError, ClientResult, ExecutionRuntime, FetchChunkVerifier, FetchExecutionEvent,
    ProducerTrust, signed_run_ticket_request, validate_fetch_ticket, verified_fetch_input,
    verify_fetch_work_event,
};

#[derive(Clone)]
pub struct AppleAppAttestTrust {
    pub app_id: String,
    pub allowed_cd_hashes: Vec<[u8; 32]>,
    pub counter_store: Arc<dyn AssertionCounterStore + Send + Sync>,
    credential: Arc<Mutex<Option<RegisteredAppleCredential>>>,
}

impl AppleAppAttestTrust {
    pub fn new(
        app_id: impl Into<String>,
        allowed_cd_hashes: Vec<[u8; 32]>,
        counter_store: Arc<dyn AssertionCounterStore + Send + Sync>,
    ) -> Self {
        Self {
            app_id: app_id.into(),
            allowed_cd_hashes,
            counter_store,
            credential: Arc::new(Mutex::new(None)),
        }
    }

    fn registered_credential(
        &self,
        enrollment: &AppleAppAttestEnrollment,
    ) -> ClientResult<RegisteredAppleCredential> {
        let mut registered = self.credential.lock().map_err(|_| {
            ClientError::protocol("provider App Attest enrollment credential cache is unavailable")
        })?;
        let credential = AppleCredential {
            attestation: enrollment.attestation_object.clone(),
            client_data_hash: enrollment.client_data_hash,
        };
        if let Some(existing) = registered.as_ref() {
            if existing.id != credential.content_id() {
                return Err(ClientError::protocol(
                    "provider App Attest enrollment changed after registration",
                ));
            }
            return Ok(existing.clone());
        }
        let verified = register_apple(
            &credential,
            apple_app_id_hash(&self.app_id),
            apple_app_attest_root_ca(),
            AnchorTime(enrollment.validation_time),
        )
        .map_err(|source| {
            ClientError::source("provider App Attest enrollment registration failed", source)
        })?;
        *registered = Some(verified.clone());
        Ok(verified)
    }
}

impl std::fmt::Debug for AppleAppAttestTrust {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AppleAppAttestTrust")
            .field("app_id", &self.app_id)
            .field("allowed_cd_hashes", &self.allowed_cd_hashes)
            .field("counter_store", &"<injected>")
            .field("credential", &"<verified requester-side>")
            .finish()
    }
}

impl PartialEq for AppleAppAttestTrust {
    fn eq(&self, other: &Self) -> bool {
        self.app_id == other.app_id
            && self.allowed_cd_hashes == other.allowed_cd_hashes
            && Arc::ptr_eq(&self.counter_store, &other.counter_store)
            && Arc::ptr_eq(&self.credential, &other.credential)
    }
}

impl Eq for AppleAppAttestTrust {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderTrustAnchor {
    pub expected_genesis: ContentId,
    pub required_assurance: Assurance,
    pub apple_app_attest: Option<AppleAppAttestTrust>,
}

/// Remote execution route carrying the out-of-band provider trust anchor even
/// while discovery is selecting an address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExecutionRoute {
    Local,
    RemoteDirect(RemoteNodeTarget),
    RemoteDiscovery {
        retries: usize,
        provider_trust: ProviderTrustAnchor,
    },
}

/// A remote dial target: the canonical iroh identity plus optional dial hints.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoteNodeTarget {
    pub addr: ::iroh::EndpointAddr,
    pub provider_trust: ProviderTrustAnchor,
}

impl RemoteNodeTarget {
    pub fn node_id(&self) -> ::iroh::EndpointId {
        self.addr.id
    }

    pub fn direct(node_id: ::iroh::EndpointId, provider_trust: ProviderTrustAnchor) -> Self {
        Self {
            addr: ::iroh::EndpointAddr::from(node_id),
            provider_trust,
        }
    }
}

impl ExecutionRoute {
    /// Build a remote route from a peer id and optional direct-address hints.
    pub fn remote(
        node_id: Option<::iroh::EndpointId>,
        node_addrs: Vec<SocketAddr>,
        retries: usize,
        provider_trust: ProviderTrustAnchor,
    ) -> Self {
        match node_id {
            Some(node_id) => Self::RemoteDirect(RemoteNodeTarget {
                addr: ::iroh::EndpointAddr::from_parts(
                    node_id,
                    node_addrs.into_iter().map(::iroh::TransportAddr::Ip),
                ),
                provider_trust,
            }),
            None => Self::RemoteDiscovery {
                retries,
                provider_trust,
            },
        }
    }
}

/// Bound endpoint plus the per-service registry and connection pools built on it.
#[derive(Clone)]
pub struct RemoteRpc {
    endpoint: ::iroh::Endpoint,
    registry: ServiceRegistry,
}

/// Client discovery registry and its peer-exchange ingestion handle.
pub struct ClientDiscovery {
    pub registry: ServiceRegistry,
    pub peer_exchange: PeerExchangeBackend,
}

impl<L> ExecutionRuntime<L> {
    /// Bind a remote-capable runtime keyed by `secret_key`.
    pub async fn remote(secret_key: ::iroh::SecretKey) -> ClientResult<Self> {
        Self::default().with_remote(secret_key).await
    }

    /// Add a bound iroh endpoint and service registry to this runtime.
    pub async fn with_remote(mut self, secret_key: ::iroh::SecretKey) -> ClientResult<Self> {
        let endpoint = ::iroh::Endpoint::builder(::iroh::endpoint::presets::N0)
            .secret_key(secret_key)
            .bind()
            .await
            .client_context("failed to bind iroh endpoint for ExecutionRuntime")?;
        let discovery = build_client_registry(&endpoint).map_err(|source| {
            ClientError::protocol(format!("failed to configure service discovery: {source:#}"))
        })?;
        self.remote = Some(RemoteRpc {
            endpoint,
            registry: discovery.registry,
        });
        Ok(self)
    }

    /// Gracefully close the client endpoint after a finite remote operation.
    /// Long-lived callers such as the HTTP gateway keep their runtime instead.
    pub async fn close_remote(&self) {
        if let Some(remote) = &self.remote {
            remote.endpoint.close().await;
        }
    }

    /// Access the discovery registry configured for remote dispatch.
    pub fn remote_registry(&self) -> ClientResult<&ServiceRegistry> {
        self.remote
            .as_ref()
            .map(|remote| &remote.registry)
            .ok_or_else(remote_unavailable)
    }

    /// Dial one service through its shared connection pool.
    pub async fn remote_transport<S: ServiceMarker>(
        &self,
        target: &RemoteNodeTarget,
    ) -> ClientResult<IrohTransport> {
        let registry = self.remote_registry()?;
        registry
            .pool::<S>()
            .transport(target.addr.clone())
            .await
            .map_err(|source| {
                ClientError::source(
                    format!("failed to dial {} on {}", S::ALPN, target.node_id()),
                    source,
                )
            })
    }
}

fn remote_unavailable() -> ClientError {
    ClientError::protocol(
        "remote dispatch on a local-only runtime; construct via ExecutionRuntime::remote(...)",
    )
}

/// Build the native discovery registry shared by clients and the monitor.
pub fn build_client_registry(endpoint: &::iroh::Endpoint) -> ClientResult<ClientDiscovery> {
    let mdns = MdnsAddressLookup::builder()
        .advertise(false)
        .build(endpoint.id())
        .client_context("failed to start mDNS discovery")?;
    endpoint
        .address_lookup()
        .client_context("iroh endpoint has no address lookup registry")?
        .add(mdns.clone());

    let dht = DhtBackend::new(endpoint).client_context("failed to start DHT discovery")?;
    let peer_exchange = PeerExchangeBackend::new();

    let mut registry = ServiceRegistry::new(endpoint);
    registry.add(MdnsBackend::new(mdns));
    registry.add(dht);
    registry.add(peer_exchange.clone());

    Ok(ClientDiscovery {
        registry,
        peer_exchange,
    })
}

async fn confidential_open<M>(
    transport: &IrohTransport,
    trust: &ProviderTrustAnchor,
) -> ClientResult<()>
where
    M: MethodMarker<Request = OpenRequest, Response = OpenResponse>,
{
    let context = transport.context();
    let exporter = context.open_exporter.ok_or_else(|| {
        ClientError::protocol("live QUIC connection did not expose a confidential-open exporter")
    })?;
    let peer = context.peer.ok_or_else(|| {
        ClientError::protocol("live QUIC connection did not expose its remote peer identity")
    })?;
    let nonce: [u8; 32] = rand::random();
    let response = hellas_rpc::call::unary::<_, M>(
        transport,
        OpenRequest {
            nonce: nonce.to_vec(),
        },
        Metadata::new(),
    )
    .await
    .map_err(|status| ClientError::wire("provider declined confidential open", status))?;
    verify_open_response(
        trust,
        &exporter,
        &nonce,
        <M::Service as ServiceMarker>::ALPN.as_bytes(),
        peer,
        response,
    )
}

fn verify_open_response(
    trust: &ProviderTrustAnchor,
    exporter: &[u8; 32],
    nonce: &[u8; 32],
    alpn: &[u8],
    peer: PeerIdentity,
    response: OpenResponse,
) -> ClientResult<()> {
    // The out-of-band pin is the trust anchor. Check it before interpreting
    // any attacker-controlled genesis fields or proof bytes.
    let actual_genesis = ContentId::hash(&response.provider_genesis);
    if actual_genesis != trust.expected_genesis {
        return Err(ClientError::protocol(format!(
            "provider genesis pin mismatch: expected {}, got {}",
            trust.expected_genesis, actual_genesis
        )));
    }

    let bundle = ProviderEnrollmentBundle::from_canonical_bytes(&response.provider_genesis)
        .map_err(|source| {
            ClientError::source("provider returned invalid enrollment bundle", source)
        })?;
    let genesis = &bundle.genesis;
    if trust.required_assurance == Assurance::AppleAppAttest
        && genesis.statement.root_kind != RootKind::SecureEnclave
    {
        return Err(ClientError::protocol(
            "Apple App Attest assurance requires a Secure Enclave provider root",
        ));
    }
    if genesis.statement.transport_public_key != PublicKey::Ed25519(peer.0) {
        return Err(ClientError::protocol(format!(
            "provider transport key mismatch: pinned genesis names {:?}, live QUIC peer is {peer:#}",
            genesis.statement.transport_public_key
        )));
    }
    let binding = hellas_rpc::open_proof_binding(
        exporter,
        nonce,
        &genesis.statement.producer_public_key,
        actual_genesis,
        alpn,
    );

    match genesis.statement.root_kind {
        RootKind::Software => {
            if !matches!(bundle.platform, PlatformEnrollment::Absent) {
                return Err(ClientError::protocol(
                    "software provider has unexpected platform enrollment",
                ));
            }
            let signature = match response.proof {
                Some(open_response::Proof::ProducerSignature(signature)) => signature,
                _ => {
                    return Err(ClientError::protocol(
                        "software provider open response is missing its producer signature",
                    ));
                }
            };
            let signature =
                hellas_rpc::run_ticket::signature_from_pb(signature).map_err(|source| {
                    ClientError::source("provider open signature is malformed", source)
                })?;
            hellas_rpc::signature::verify_digest_signature(
                &genesis.statement.producer_public_key,
                &signature,
                binding,
            )
            .map_err(|source| {
                ClientError::source("provider open signature verification failed", source)
            })
        }
        RootKind::SecureEnclave => {
            let PlatformEnrollment::AppleAppAttest(enrollment) = &bundle.platform else {
                return Err(ClientError::protocol(
                    "Secure Enclave provider bundle has no Apple App Attest enrollment",
                ));
            };
            let assertion = match response.proof {
                Some(open_response::Proof::AppleAppAttestAssertion(assertion)) => assertion,
                _ => {
                    return Err(ClientError::protocol(
                        "Apple provider open response is missing its App Attest assertion",
                    ));
                }
            };
            let apple = trust.apple_app_attest.as_ref().ok_or_else(|| {
                ClientError::protocol(
                    "pinned Apple provider requires an App Attest app identity and CDhash allowlist",
                )
            })?;
            let credential = apple.registered_credential(enrollment)?;
            if genesis.statement.platform_credential
                != PlatformCredential::Registered(credential.id)
                || genesis.statement.root_public_key != PublicKey::P256(credential.public_key)
            {
                return Err(ClientError::protocol(
                    "Apple provider genesis does not match its chain-verified credential",
                ));
            }
            let claims = verify_apple_assertion(
                &assertion,
                binding.as_bytes(),
                &credential,
                &ApplePolicy {
                    expected_rp_id_hash: apple_app_id_hash(&apple.app_id),
                    allowed_cd_hashes: apple.allowed_cd_hashes.clone(),
                },
            )
            .map_err(|source| {
                ClientError::source(
                    "provider App Attest open assertion verification failed",
                    source,
                )
            })?;
            apple
                .counter_store
                .advance(&credential.public_key, claims.counter)
                .map_err(|source| {
                    ClientError::source(
                        "provider App Attest open assertion counter advancement failed",
                        source,
                    )
                })
        }
        RootKind::Tpm20 => Err(ClientError::protocol(
            "TPM confidential open verification is not implemented",
        )),
    }
}

fn validate_provider_trust_assurance(
    trust: &ProviderTrustAnchor,
    requested: Assurance,
) -> ClientResult<()> {
    if trust.required_assurance == requested {
        Ok(())
    } else {
        Err(ClientError::protocol(format!(
            "provider trust anchor requires {:?}, but the request asks for {:?}",
            trust.required_assurance, requested
        )))
    }
}

/// A token quote checked against the caller's request rather than trusted as
/// an interpretation supplied by the provider.
#[derive(Debug)]
pub struct ValidatedEvaluateQuote {
    pub ticket: Ticket,
    pub producer_key: PublicKey,
    pub text_execution: TextExecutionId,
}

/// Validate every deterministic field of a token quote and bind its ticket to
/// the returned canonical Evaluate request.
///
/// The provider chooses only the nonce. Package aliases are deliberately not
/// trusted: `request.execution_package` is the caller's exact Catena pin.
pub fn validate_evaluate_quote_response(
    request: &QuoteTokensRequest,
    response: QuoteResponse,
    expected_provider_genesis: Option<ContentId>,
) -> ClientResult<ValidatedEvaluateQuote> {
    if request.prompt_token_ids.is_empty() {
        return Err(ClientError::protocol(
            "token quote prompt_token_ids must not be empty",
        ));
    }
    if request.stop_token_ids.len() > MAX_STOP_TOKEN_IDS {
        return Err(ClientError::protocol(format!(
            "token quote has {} stop IDs, over the limit of {MAX_STOP_TOKEN_IDS}",
            request.stop_token_ids.len()
        )));
    }
    let prompt_tokens = u32::try_from(request.prompt_token_ids.len())
        .map_err(|_| ClientError::protocol("token quote prompt count exceeds u32"))?;
    if response.prompt_tokens != prompt_tokens {
        return Err(ClientError::protocol(format!(
            "provider reported {} prompt tokens for a {prompt_tokens}-token quote",
            response.prompt_tokens
        )));
    }

    let execution_package = ExecutionPackageId::from_bytes(fixed_quote_field(
        "execution_package",
        &request.execution_package,
    )?);
    let manifest = ProgramManifest::Evaluate(EvaluateProgramManifest { execution_package });
    let execution_environment = manifest.content_id();
    let from = match request.start.as_ref().and_then(|start| start.kind.as_ref()) {
        Some(evaluate_start::Kind::Genesis(_)) => {
            let identity = TextArtifact::identity(
                BoundTermId::from_digest(execution_environment.digest()),
                execution_package,
            );
            SourceRef::output(identity.output_id())
        }
        Some(evaluate_start::Kind::Artifact(artifact)) => {
            let digest = Digest::from_bytes(fixed_quote_field("artifact", &artifact.artifact)?);
            SourceRef::output(TextArtifactId::from_digest(digest))
        }
        None => {
            return Err(ClientError::protocol(
                "token quote is missing its evaluate start",
            ));
        }
    };
    let prompt_tokens = TokenIds::from_u32s(request.prompt_token_ids.iter().copied());
    let max_new_tokens = request
        .max_new_tokens
        .unwrap_or(hellas_rpc::DEFAULT_MAX_NEW_TOKENS);
    if max_new_tokens == 0 {
        return Err(ClientError::protocol(
            "token quote max_new_tokens must be greater than zero",
        ));
    }
    let policy =
        TextPolicy::from_u32_stop_tokens(max_new_tokens, request.stop_token_ids.iter().copied());
    let text_execution = TextExecution::new(from, prompt_tokens.output_id(), policy.output_id());

    let evaluate_pb = response
        .evaluate_request
        .ok_or_else(|| ClientError::protocol("quote_tokens response missing evaluate_request"))?;
    let evaluate_request = EvaluateRequest {
        text_execution: Digest::from_bytes(fixed_quote_field(
            "evaluate_request.text_execution",
            &evaluate_pb.text_execution,
        )?),
        runner_public_key: hellas_rpc::run_ticket::public_key_from_pb(
            evaluate_pb.runner_public_key.ok_or_else(|| {
                ClientError::protocol("evaluate request missing runner_public_key")
            })?,
        )
        .map_err(|source| ClientError::source("invalid evaluate runner_public_key", source))?,
        execution_environment: ContentId::from_bytes(fixed_quote_field(
            "evaluate_request.execution_environment",
            &evaluate_pb.execution_environment,
        )?),
        nonce: fixed_quote_field("evaluate_request.nonce", &evaluate_pb.nonce)?,
        assurance: hellas_rpc::run_ticket::assurance_from_pb(evaluate_pb.assurance)
            .map_err(|source| ClientError::source("invalid evaluate request assurance", source))?,
        retain: evaluate_pb.retain.unwrap_or(true),
    };
    let requested_runner = request
        .runner_public_key
        .clone()
        .ok_or_else(|| ClientError::protocol("token quote is missing runner_public_key"))
        .and_then(|key| {
            hellas_rpc::run_ticket::public_key_from_pb(key).map_err(|source| {
                ClientError::source("invalid requested runner_public_key", source)
            })
        })?;

    let text_execution = text_execution.input_id();
    if evaluate_request.text_execution != text_execution.digest()
        || evaluate_request.execution_environment != execution_environment
        || evaluate_request.runner_public_key != requested_runner
        || evaluate_request.assurance.to_byte() as i32 != request.assurance
        || evaluate_request.retain != request.retain.unwrap_or(true)
    {
        return Err(ClientError::protocol(
            "provider's evaluate request does not match the token quote",
        ));
    }

    let ticket = response
        .ticket
        .ok_or_else(|| ClientError::protocol("quote_tokens response missing ticket"))?;
    let terms = hellas_rpc::run_ticket::job_terms_from_pb(&ticket)
        .map_err(|source| ClientError::source("invalid evaluate ticket terms", source))?;
    let expected_request = Evaluate::commit_request(&evaluate_request);
    if terms.request != expected_request {
        return Err(ClientError::protocol(
            "evaluate ticket is not bound to the returned evaluate request",
        ));
    }
    if terms.assurance != evaluate_request.assurance {
        return Err(ClientError::protocol(
            "evaluate ticket assurance does not match the committed request",
        ));
    }
    if let Some(expected) = expected_provider_genesis
        && terms.provider_genesis != expected
    {
        return Err(ClientError::protocol(format!(
            "evaluate ticket provider genesis mismatch: expected {expected}, got {}",
            terms.provider_genesis
        )));
    }
    let enrollment = ProviderEnrollmentBundle::from_canonical_bytes(&ticket.provider_genesis)
        .map_err(|source| ClientError::source("invalid evaluate provider enrollment", source))?;

    Ok(ValidatedEvaluateQuote {
        ticket,
        producer_key: enrollment.genesis.statement.producer_public_key,
        text_execution,
    })
}

fn fixed_quote_field<const N: usize>(field: &str, bytes: &[u8]) -> ClientResult<[u8; N]> {
    bytes.try_into().map_err(|_| {
        ClientError::protocol(format!("{field} must be {N} bytes, got {}", bytes.len()))
    })
}

/// Bind unauthenticated transport metadata to the request commitment carried
/// by the already-validated ticket before exposing it as provenance.
pub fn validate_evaluate_quote_provenance(
    ticket: &Ticket,
    provenance: ExecutionProvenance,
) -> ClientResult<ExecutionProvenance> {
    let expected =
        fixed_quote_field::<32>("ticket.request_commitment", &ticket.request_commitment)?;
    if provenance.commitment_id != expected {
        return Err(ClientError::protocol(
            "evaluate quote provenance does not match the ticket request commitment",
        ));
    }
    Ok(provenance)
}

/// Open and quote prepared tokens on a specific peer.
///
/// The returned transport is the exact Open-bound Courtesy connection. The
/// caller must run the ticket on it rather than dialing a transferable Execute
/// leg whose connection was never attested.
pub async fn quote_tokens<L>(
    runtime: &ExecutionRuntime<L>,
    target: &RemoteNodeTarget,
    quote_req: &QuoteTokensRequest,
) -> ClientResult<(
    IrohTransport,
    Ticket,
    ExecutionProvenance,
    PublicKey,
    TextExecutionId,
)> {
    let requested_assurance = hellas_rpc::run_ticket::assurance_from_pb(quote_req.assurance)
        .map_err(|source| ClientError::source("invalid requested assurance", source))?;
    validate_provider_trust_assurance(&target.provider_trust, requested_assurance)?;
    let transport = runtime.remote_transport::<Courtesy>(target).await?;
    confidential_open::<CourtesyOpen>(&transport, &target.provider_trust).await?;
    let with_trailer = hellas_rpc::call::unary_with_trailer::<_, QuoteTokens>(
        &transport,
        quote_req.clone(),
        Metadata::new(),
    )
    .await
    .map_err(|status| {
        ClientError::wire(
            format!("node {} declined quote_tokens", target.node_id()),
            status,
        )
    })?;
    let validated = validate_evaluate_quote_response(
        quote_req,
        with_trailer.response,
        Some(target.provider_trust.expected_genesis),
    )?;
    let provenance = hellas_rpc::provenance::read_provenance_metadata(&with_trailer.metadata)
        .map_err(|source| {
            ClientError::source(
                format!(
                    "node {} response missing provenance metadata",
                    target.node_id()
                ),
                source,
            )
        })?;
    let provenance = validate_evaluate_quote_provenance(&validated.ticket, provenance)?;
    Ok((
        transport,
        validated.ticket,
        provenance,
        validated.producer_key,
        validated.text_execution,
    ))
}

/// Discover Courtesy peers until one returns a valid quote, retaining that
/// peer's Open-bound connection for RunTicket.
pub async fn discover_and_quote(
    registry: &ServiceRegistry,
    quote_req: &QuoteTokensRequest,
    retries: usize,
    provider_trust: &ProviderTrustAnchor,
) -> ClientResult<(
    IrohTransport,
    Ticket,
    ExecutionProvenance,
    PublicKey,
    TextExecutionId,
)> {
    let requested_assurance = hellas_rpc::run_ticket::assurance_from_pb(quote_req.assurance)
        .map_err(|source| ClientError::source("invalid requested assurance", source))?;
    validate_provider_trust_assurance(provider_trust, requested_assurance)?;
    let mut stream = Box::pin(registry.discover::<Courtesy>());
    let pool = registry.pool::<Courtesy>();
    let mut last_error: Option<ClientError> = None;
    let mut attempts = 0usize;
    let max_attempts = retries.saturating_add(1);

    while let Some(peer) = stream.next().await {
        let peer = match peer {
            Ok(peer) => peer,
            Err(error) => {
                last_error = Some(ClientError::source("discovery feed error", error));
                continue;
            }
        };
        let peer_id = peer.id();
        attempts += 1;

        let transport = match pool.transport(peer_id).await {
            Ok(transport) => transport,
            Err(error) => {
                last_error = Some(ClientError::source(
                    format!("failed to dial Courtesy on {peer_id}"),
                    error,
                ));
                if attempts >= max_attempts {
                    break;
                }
                continue;
            }
        };

        if let Err(error) = confidential_open::<CourtesyOpen>(&transport, provider_trust).await {
            last_error = Some(error);
            if attempts >= max_attempts {
                break;
            }
            continue;
        }

        let with_trailer = match hellas_rpc::call::unary_with_trailer::<_, QuoteTokens>(
            &transport,
            quote_req.clone(),
            Metadata::new(),
        )
        .await
        {
            Ok(response) => response,
            Err(status) => {
                last_error = Some(ClientError::wire(
                    format!("node {peer_id} declined quote_tokens"),
                    status,
                ));
                if attempts >= max_attempts {
                    break;
                }
                continue;
            }
        };

        let validated = match validate_evaluate_quote_response(
            quote_req,
            with_trailer.response,
            Some(provider_trust.expected_genesis),
        ) {
            Ok(validated) => validated,
            Err(error) => {
                last_error = Some(error);
                if attempts >= max_attempts {
                    break;
                }
                continue;
            }
        };

        let provenance =
            match hellas_rpc::provenance::read_provenance_metadata(&with_trailer.metadata) {
                Ok(provenance) => provenance,
                Err(error) => {
                    last_error = Some(ClientError::source(
                        format!("peer {peer_id} response missing provenance metadata"),
                        error,
                    ));
                    if attempts >= max_attempts {
                        break;
                    }
                    continue;
                }
            };
        let provenance = match validate_evaluate_quote_provenance(&validated.ticket, provenance) {
            Ok(provenance) => provenance,
            Err(error) => {
                last_error = Some(error);
                if attempts >= max_attempts {
                    break;
                }
                continue;
            }
        };

        return Ok((
            transport,
            validated.ticket,
            provenance,
            validated.producer_key,
            validated.text_execution,
        ));
    }

    Err(last_error.unwrap_or_else(|| {
        ClientError::protocol(
            "discovery stream exhausted without a successful quote (no peers found)",
        )
    }))
}

/// Create and validate a fetch ticket on a specific peer.
pub async fn fetch_quote<L>(
    runtime: &ExecutionRuntime<L>,
    target: &RemoteNodeTarget,
    request: FetchRequest,
    input_commitment: InputCommitment,
    assurance: Assurance,
) -> ClientResult<Ticket> {
    validate_provider_trust_assurance(&target.provider_trust, assurance)?;
    let transport = runtime.remote_transport::<Fetch>(target).await?;
    confidential_open::<FetchOpen>(&transport, &target.provider_trust).await?;
    let client = FetchClientImpl::new(transport);
    let ticket = client.create_ticket(request).await.map_err(|status| {
        ClientError::wire(
            format!("node {} declined fetch create_ticket", target.node_id()),
            status,
        )
    })?;
    validate_fetch_ticket(ticket, input_commitment, assurance)
}

/// Discover Fetch peers until one returns a valid ticket.
pub async fn discover_and_fetch_quote(
    registry: &ServiceRegistry,
    request: &FetchRequest,
    input_commitment: InputCommitment,
    assurance: Assurance,
    retries: usize,
    provider_trust: &ProviderTrustAnchor,
) -> ClientResult<(RemoteNodeTarget, Ticket)> {
    validate_provider_trust_assurance(provider_trust, assurance)?;
    let mut stream = Box::pin(registry.discover::<Fetch>());
    let pool = registry.pool::<Fetch>();
    let mut last_error: Option<ClientError> = None;
    let mut attempts = 0usize;
    let max_attempts = retries.saturating_add(1);

    while let Some(peer) = stream.next().await {
        let peer = match peer {
            Ok(peer) => peer,
            Err(error) => {
                last_error = Some(ClientError::source("discovery feed error", error));
                continue;
            }
        };
        let peer_id = peer.id();
        attempts += 1;

        let transport = match pool.transport(peer_id).await {
            Ok(transport) => transport,
            Err(error) => {
                last_error = Some(ClientError::source(
                    format!("failed to dial Fetch on {peer_id}"),
                    error,
                ));
                if attempts >= max_attempts {
                    break;
                }
                continue;
            }
        };

        if let Err(error) = confidential_open::<FetchOpen>(&transport, provider_trust).await {
            last_error = Some(error);
            if attempts >= max_attempts {
                break;
            }
            continue;
        }

        let client = FetchClientImpl::new(transport);
        match client.create_ticket(request.clone()).await {
            Ok(ticket) => {
                let ticket = validate_fetch_ticket(ticket, input_commitment, assurance)?;
                return Ok((
                    RemoteNodeTarget::direct(peer_id, provider_trust.clone()),
                    ticket,
                ));
            }
            Err(status) => {
                last_error = Some(ClientError::wire(
                    format!("node {peer_id} declined fetch create_ticket"),
                    status,
                ));
                if attempts >= max_attempts {
                    break;
                }
            }
        }
    }

    Err(last_error.unwrap_or_else(|| {
        ClientError::protocol("discovery stream exhausted without a successful fetch quote")
    }))
}

pub fn fetch_execution_stream<L: Send + Sync>(
    runtime: ExecutionRuntime<L>,
    request: FetchRequest,
    route: ExecutionRoute,
    trust: ProducerTrust,
    runner_key: Arc<ProducerSigningKey>,
) -> impl Stream<Item = ClientResult<FetchExecutionEvent>> + Send {
    try_stream! {
        let verified_input = verified_fetch_input(&request)?;
        let input_commitment = verified_input.input_commitment;
        let assurance = verified_input.assurance;
        match route {
            ExecutionRoute::Local => Err(ClientError::protocol(
                "local fetch execution requires an embedded executor",
            ))?,
            ExecutionRoute::RemoteDirect(target) => {
                let ticket = fetch_quote(
                    &runtime,
                    &target,
                    request,
                    input_commitment,
                    assurance,
                )
                .await?;
                let execute_transport = execute_transport(&runtime, &target).await?;
                let inner = execute_fetch_stream(
                    execute_transport,
                    ticket,
                    input_commitment,
                    assurance,
                    trust,
                    runner_key.clone(),
                );
                futures::pin_mut!(inner);
                while let Some(event) = inner.next().await {
                    yield event?;
                }
            }
            ExecutionRoute::RemoteDiscovery {
                retries,
                provider_trust,
            } => {
                let (target, ticket) =
                    discover_and_fetch_quote(
                        runtime.remote_registry()?,
                        &request,
                        input_commitment,
                        assurance,
                        retries,
                        &provider_trust,
                    )
                    .await?;
                let execute_transport = execute_transport(&runtime, &target).await?;
                let inner = execute_fetch_stream(
                    execute_transport,
                    ticket,
                    input_commitment,
                    assurance,
                    trust,
                    runner_key.clone(),
                );
                futures::pin_mut!(inner);
                while let Some(event) = inner.next().await {
                    yield event?;
                }
            }
        }
    }
}

/// Run a fetch ticket over an already-dialed Execute transport.
pub fn execute_fetch_stream(
    transport: IrohTransport,
    ticket: Ticket,
    input_commitment: InputCommitment,
    assurance: Assurance,
    trust: ProducerTrust,
    runner_key: Arc<ProducerSigningKey>,
) -> impl Stream<Item = ClientResult<FetchExecutionEvent>> + Send {
    try_stream! {
        let client = ExecuteClientImpl::new(transport);
        let run_ticket = signed_run_ticket_request(ticket, runner_key.as_ref())?;
        let mut wire = client
            .run_ticket(run_ticket)
            .await
            .map_err(|status| ClientError::wire("failed to start remote fetch execute stream", status))?;
        let mut terminal = None;
        let mut verifier = FetchChunkVerifier::new(input_commitment, assurance, trust);
        while let Some(item) = wire.next().await {
            if terminal.is_some() {
                Err(ClientError::protocol(
                    "remote fetch execute stream emitted an event after its terminal outcome"
                ))?;
            }
            let event = verify_fetch_work_event(
                &mut verifier,
                item.map_err(|status: WireStatus| {
                    ClientError::wire("remote fetch execute stream failed", status)
                })?,
                input_commitment,
            )?;
            match event {
                FetchExecutionEvent::Chunk {
                    position,
                    output_event,
                    event,
                } => {
                    yield FetchExecutionEvent::Chunk {
                        position,
                        output_event,
                        event,
                    };
                }
                FetchExecutionEvent::Done(outcome) => {
                    terminal = Some(outcome);
                }
            }
        }
        wire.finish()
            .map_err(|status| ClientError::wire("remote fetch execute stream trailer", status))?;
        let terminal = terminal.ok_or_else(|| {
            ClientError::protocol("remote fetch execute stream ended Ok but emitted no Done event")
        })?;
        yield FetchExecutionEvent::Done(terminal);
        drop(client);
    }
}

/// Dial the Execute service for a selected peer.
pub async fn execute_transport<L>(
    runtime: &ExecutionRuntime<L>,
    target: &RemoteNodeTarget,
) -> ClientResult<IrohTransport> {
    runtime.remote_transport::<Execute>(target).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use hellas_rpc::pb::courtesy::{EvaluateGenesisStart, EvaluateStart};
    use hellas_rpc::protocol::artifacts::{
        BoundTermId, InputAddressed, OutputAddressed, SourceRef, TextArtifact, TextExecution,
        TextPolicy, TokenIds,
    };
    use hellas_rpc::{
        Digest, ProviderEnrollmentBundle, ProviderGenesisStatement, RootProof,
        SignedProviderGenesis, pb::execute::open_response, run_ticket::signature_to_pb,
    };
    use p256::ecdsa::signature::Signer as _;
    use p256::ecdsa::{Signature as P256Signature, SigningKey as P256SigningKey};
    use serde::Serialize;
    use serde_bytes::ByteBuf;
    use sha2::{Digest as _, Sha256};
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    const ALPN: &[u8] = b"/hellas.courtesy.v1.Courtesy/2.0";
    const ENROLLED_PEER: PeerIdentity = PeerIdentity([3; 32]);
    const OTHER_PEER: PeerIdentity = PeerIdentity([7; 32]);

    fn signed_open_response(
        exporter: &[u8; 32],
        nonce: &[u8; 32],
    ) -> (ProviderTrustAnchor, OpenResponse) {
        let root = ProducerSigningKey::from_secret_bytes([1; 32]).unwrap();
        let producer = ProducerSigningKey::from_secret_bytes([2; 32]).unwrap();
        let statement = ProviderGenesisStatement {
            root_kind: RootKind::Software,
            root_public_key: root.public_key(),
            producer_public_key: producer.public_key(),
            transport_public_key: PublicKey::Ed25519(ENROLLED_PEER.0),
            platform_credential: PlatformCredential::Absent,
            installation_nonce: [4; 32],
        };
        let genesis = SignedProviderGenesis {
            root_proof: RootProof::Software(
                root.sign_digest(Digest::hash(&statement.canonical_bytes()))
                    .unwrap(),
            ),
            statement,
        };
        let bundle = ProviderEnrollmentBundle {
            genesis,
            platform: PlatformEnrollment::Absent,
        };
        let provider_genesis = bundle.canonical_bytes();
        let expected_genesis = ContentId::hash(&provider_genesis);
        let binding = hellas_rpc::open_proof_binding(
            exporter,
            nonce,
            &bundle.genesis.statement.producer_public_key,
            expected_genesis,
            ALPN,
        );
        let signature = producer.sign_digest(binding).unwrap();
        (
            ProviderTrustAnchor {
                expected_genesis,
                required_assurance: Assurance::ProducerSigned,
                apple_app_attest: None,
            },
            OpenResponse {
                provider_genesis,
                proof: Some(open_response::Proof::ProducerSignature(signature_to_pb(
                    &signature,
                ))),
            },
        )
    }

    fn valid_token_quote() -> (
        QuoteTokensRequest,
        QuoteResponse,
        ProviderTrustAnchor,
        PublicKey,
    ) {
        let (trust, open) = signed_open_response(&[8; 32], &[9; 32]);
        let enrollment =
            ProviderEnrollmentBundle::from_canonical_bytes(&open.provider_genesis).unwrap();
        let producer_key = enrollment.genesis.statement.producer_public_key;
        let runner = ProducerSigningKey::from_secret_bytes([5; 32]).unwrap();
        let execution_package = ExecutionPackageId::from_bytes([6; 32]);
        let request = QuoteTokensRequest {
            package: "smollm2-135m".to_string(),
            execution_package: execution_package.as_bytes().to_vec(),
            prompt_token_ids: vec![1, 2, 3],
            max_new_tokens: Some(4),
            stop_token_ids: vec![9, 7, 9],
            start: Some(EvaluateStart {
                kind: Some(evaluate_start::Kind::Genesis(EvaluateGenesisStart {})),
            }),
            runner_public_key: Some(hellas_rpc::run_ticket::public_key_to_pb(
                &runner.public_key(),
            )),
            assurance: Assurance::ProducerSigned.to_byte().into(),
            retain: Some(true),
        };
        let execution_environment =
            ProgramManifest::Evaluate(EvaluateProgramManifest { execution_package }).content_id();
        let identity = TextArtifact::identity(
            BoundTermId::from_digest(execution_environment.digest()),
            execution_package,
        );
        let prompt = TokenIds::from([1, 2, 3]);
        let policy = TextPolicy::from_u32_stop_tokens(4, [9, 7, 9]);
        let text_execution = TextExecution::new(
            SourceRef::output(identity.output_id()),
            prompt.output_id(),
            policy.output_id(),
        );
        let evaluate_request = EvaluateRequest {
            text_execution: text_execution.input_id().digest(),
            runner_public_key: runner.public_key(),
            execution_environment,
            nonce: [4; 32],
            assurance: Assurance::ProducerSigned,
            retain: true,
        };
        let terms = hellas_rpc::JobTerms {
            request: Evaluate::commit_request(&evaluate_request),
            provider_genesis: trust.expected_genesis,
            assurance: Assurance::ProducerSigned,
            amount: 1000,
            ttl_ms: 30_000,
        };
        let ticket = hellas_rpc::run_ticket::ticket_to_pb(terms, open.provider_genesis).unwrap();
        let response = QuoteResponse {
            ticket: Some(ticket),
            prompt_tokens: 3,
            evaluate_request: Some(hellas_rpc::pb::evaluate::EvaluateRequest {
                text_execution: evaluate_request.text_execution.as_bytes().to_vec(),
                runner_public_key: Some(hellas_rpc::run_ticket::public_key_to_pb(
                    &evaluate_request.runner_public_key,
                )),
                execution_environment: evaluate_request.execution_environment.as_bytes().to_vec(),
                nonce: evaluate_request.nonce.to_vec(),
                assurance: evaluate_request.assurance.to_byte().into(),
                retain: Some(evaluate_request.retain),
            }),
        };
        (request, response, trust, producer_key)
    }

    #[test]
    fn token_quote_binds_exact_package_request_ticket_and_producer() {
        let (request, response, trust, producer_key) = valid_token_quote();
        let validated =
            validate_evaluate_quote_response(&request, response, Some(trust.expected_genesis))
                .unwrap();
        assert_eq!(validated.producer_key, producer_key);
    }

    #[test]
    fn token_quote_rejects_a_provider_substituting_another_package() {
        let (mut request, response, trust, _) = valid_token_quote();
        request.execution_package = vec![42; 32];
        let error =
            validate_evaluate_quote_response(&request, response, Some(trust.expected_genesis))
                .unwrap_err();
        assert!(error.to_string().contains("does not match the token quote"));
    }

    #[test]
    fn token_quote_provenance_must_name_the_ticket_commitment() {
        let (_, response, _, _) = valid_token_quote();
        let ticket = response.ticket.unwrap();
        let commitment_id: [u8; 32] = ticket.request_commitment.as_slice().try_into().unwrap();
        let valid = ExecutionProvenance { commitment_id };
        assert_eq!(
            validate_evaluate_quote_provenance(&ticket, valid.clone()).unwrap(),
            valid
        );

        let error = validate_evaluate_quote_provenance(
            &ticket,
            ExecutionProvenance {
                commitment_id: [42; 32],
            },
        )
        .unwrap_err();
        assert!(error.to_string().contains("does not match"), "{error}");
    }

    #[test]
    fn token_quote_rejects_a_ticket_for_another_request() {
        let (request, mut response, trust, _) = valid_token_quote();
        response.ticket.as_mut().unwrap().request_commitment = vec![0; 32];
        let error =
            validate_evaluate_quote_response(&request, response, Some(trust.expected_genesis))
                .unwrap_err();
        assert!(error.to_string().contains("not bound"));
    }

    #[derive(Default)]
    struct TestCounterStore {
        counters: Mutex<BTreeMap<[u8; 33], u32>>,
    }

    impl AssertionCounterStore for TestCounterStore {
        fn advance(
            &self,
            public_key: &[u8; 33],
            counter: u32,
        ) -> Result<(), hellas_attestation::AttestationError> {
            let mut counters = self
                .counters
                .lock()
                .map_err(|_| hellas_attestation::AttestationError::State)?;
            let previous = counters.get(public_key).copied().unwrap_or(0);
            if counter <= previous {
                return Err(hellas_attestation::AttestationError::Counter);
            }
            counters.insert(*public_key, counter);
            Ok(())
        }
    }

    fn apple_assertion(
        signing_key: &P256SigningKey,
        rp_id_hash: [u8; 32],
        cd_hash: [u8; 32],
        counter: u32,
        client_data_hash: &[u8; 32],
    ) -> Vec<u8> {
        let mut extensions = BTreeMap::new();
        extensions.insert(
            "apple_cd_hash_hash_01".to_owned(),
            ByteBuf::from(cd_hash.to_vec()),
        );
        extensions.insert("apple_cd_hash_type_01".to_owned(), ByteBuf::from(vec![2]));
        extensions.insert(
            "apple_validation_category_01".to_owned(),
            ByteBuf::from(vec![6, 0, 0, 0]),
        );
        let mut extension_bytes = Vec::new();
        ciborium::into_writer(&extensions, &mut extension_bytes).unwrap();

        let mut authenticator_data = Vec::new();
        authenticator_data.extend_from_slice(&rp_id_hash);
        authenticator_data.push(0x40);
        authenticator_data.extend_from_slice(&counter.to_be_bytes());
        authenticator_data.extend_from_slice(&extension_bytes);
        let digest = Sha256::digest([authenticator_data.as_slice(), client_data_hash].concat());
        let signature: P256Signature = signing_key.sign(&digest);

        #[derive(Serialize)]
        struct Assertion {
            #[serde(rename = "authenticatorData")]
            authenticator_data: ByteBuf,
            signature: ByteBuf,
        }

        let mut encoded = Vec::new();
        ciborium::into_writer(
            &Assertion {
                authenticator_data: ByteBuf::from(authenticator_data),
                signature: ByteBuf::from(signature.to_der().as_bytes().to_vec()),
            },
            &mut encoded,
        )
        .unwrap();
        encoded
    }

    fn apple_open_response(
        exporter: &[u8; 32],
        nonce: &[u8; 32],
        counter: u32,
        counter_store: Arc<TestCounterStore>,
    ) -> (ProviderTrustAnchor, OpenResponse, [u8; 33]) {
        let signing_key = P256SigningKey::from_bytes((&[7; 32]).into()).unwrap();
        let public_key = signing_key
            .verifying_key()
            .to_sec1_point(true)
            .as_bytes()
            .try_into()
            .unwrap();
        let cd_hash = [8; 32];
        let enrollment = AppleAppAttestEnrollment {
            attestation_object: vec![1],
            client_data_hash: [2; 32],
            validation_time: 3,
        };
        let credential_id = AppleCredential {
            attestation: enrollment.attestation_object.clone(),
            client_data_hash: enrollment.client_data_hash,
        }
        .content_id();
        let producer = ProducerSigningKey::from_secret_bytes([2; 32]).unwrap();
        let statement = ProviderGenesisStatement {
            root_kind: RootKind::SecureEnclave,
            root_public_key: PublicKey::P256(public_key),
            producer_public_key: producer.public_key(),
            transport_public_key: PublicKey::Ed25519(ENROLLED_PEER.0),
            platform_credential: PlatformCredential::Registered(credential_id),
            installation_nonce: [4; 32],
        };
        let genesis = SignedProviderGenesis {
            root_proof: RootProof::AppleAppAttest(Vec::new()),
            statement,
        };
        let bundle = ProviderEnrollmentBundle {
            genesis,
            platform: PlatformEnrollment::AppleAppAttest(enrollment),
        };
        let provider_genesis = bundle.canonical_bytes();
        let expected_genesis = ContentId::hash(&provider_genesis);
        let binding = hellas_rpc::open_proof_binding(
            exporter,
            nonce,
            &bundle.genesis.statement.producer_public_key,
            expected_genesis,
            ALPN,
        );
        let apple = AppleAppAttestTrust::new("TESTTEAM.example.app", vec![cd_hash], counter_store);
        *apple.credential.lock().unwrap() = Some(RegisteredAppleCredential {
            id: credential_id,
            public_key,
        });
        (
            ProviderTrustAnchor {
                expected_genesis,
                required_assurance: Assurance::AppleAppAttest,
                apple_app_attest: Some(apple),
            },
            OpenResponse {
                provider_genesis,
                proof: Some(open_response::Proof::AppleAppAttestAssertion(
                    apple_assertion(
                        &signing_key,
                        apple_app_id_hash("TESTTEAM.example.app"),
                        cd_hash,
                        counter,
                        binding.as_bytes(),
                    ),
                )),
            },
            public_key,
        )
    }

    #[test]
    fn producer_signed_open_happy_path_verifies() {
        let exporter = [5; 32];
        let nonce = [6; 32];
        let (trust, response) = signed_open_response(&exporter, &nonce);
        verify_open_response(&trust, &exporter, &nonce, ALPN, ENROLLED_PEER, response).unwrap();
    }

    #[test]
    fn apple_assurance_rejects_software_root_downgrade() {
        let exporter = [5; 32];
        let nonce = [6; 32];
        let (mut trust, response) = signed_open_response(&exporter, &nonce);
        trust.required_assurance = Assurance::AppleAppAttest;

        let error = verify_open_response(&trust, &exporter, &nonce, ALPN, ENROLLED_PEER, response)
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("requires a Secure Enclave provider root")
        );
    }

    #[test]
    fn request_assurance_must_match_trust_anchor_policy() {
        let (trust, _) = signed_open_response(&[5; 32], &[6; 32]);
        let error =
            validate_provider_trust_assurance(&trust, Assurance::AppleAppAttest).unwrap_err();
        assert!(error.to_string().contains("trust anchor requires"));
    }

    #[test]
    fn apple_enrollment_is_registered_once_per_trust_anchor() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../attestation/tests/fixtures/real-app-attest.json"
        ))
        .unwrap();
        let artifacts = &fixture["artifacts"];
        let attestation_object = STANDARD
            .decode(artifacts["attestationObjectBase64"].as_str().unwrap())
            .unwrap();
        let client_data_hash: [u8; 32] =
            hex::decode(artifacts["attestationClientDataHashHex"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
        let counters = Arc::new(TestCounterStore::default());
        let apple =
            AppleAppAttestTrust::new("2F53L9ZR3N.ai.hellas.app-attest-spike", vec![], counters);
        let enrollment = AppleAppAttestEnrollment {
            attestation_object,
            client_data_hash,
            validation_time: 1_784_384_387,
        };

        let first = apple.registered_credential(&enrollment).unwrap();
        let second = apple
            .registered_credential(&AppleAppAttestEnrollment {
                validation_time: 0,
                ..enrollment
            })
            .unwrap();

        assert_eq!(first, second);
    }

    #[test]
    fn apple_open_rejects_genesis_key_that_differs_from_registered_credential() {
        let exporter = [5; 32];
        let nonce = [6; 32];
        let counters = Arc::new(TestCounterStore::default());
        let (mut trust, mut response, _) = apple_open_response(&exporter, &nonce, 2, counters);
        let mut bundle =
            ProviderEnrollmentBundle::from_canonical_bytes(&response.provider_genesis).unwrap();
        bundle.genesis.statement.root_public_key = PublicKey::P256([4; 33]);
        response.provider_genesis = bundle.canonical_bytes();
        trust.expected_genesis = ContentId::hash(&response.provider_genesis);

        let error = verify_open_response(&trust, &exporter, &nonce, ALPN, ENROLLED_PEER, response)
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("does not match its chain-verified credential")
        );
    }

    #[test]
    fn proof_for_different_exporter_is_rejected() {
        let nonce = [6; 32];
        let (trust, response) = signed_open_response(&[5; 32], &nonce);
        assert!(
            verify_open_response(&trust, &[7; 32], &nonce, ALPN, ENROLLED_PEER, response).is_err()
        );
    }

    #[test]
    fn pin_mismatch_aborts_before_prompt_send() {
        let exporter = [5; 32];
        let nonce = [6; 32];
        let (mut trust, response) = signed_open_response(&exporter, &nonce);
        trust.expected_genesis = ContentId::from_bytes([9; 32]);
        let mut prompt_sent = false;

        let result = (|| -> ClientResult<()> {
            verify_open_response(&trust, &exporter, &nonce, ALPN, ENROLLED_PEER, response)?;
            prompt_sent = true;
            Ok(())
        })();

        assert!(result.is_err());
        assert!(!prompt_sent);
    }

    #[test]
    fn live_peer_mismatch_aborts_before_prompt_send() {
        let exporter = [5; 32];
        let nonce = [6; 32];
        let (trust, response) = signed_open_response(&exporter, &nonce);
        let mut prompt_sent = false;

        let result = (|| -> ClientResult<()> {
            verify_open_response(&trust, &exporter, &nonce, ALPN, OTHER_PEER, response)?;
            prompt_sent = true;
            Ok(())
        })();

        let error = result.unwrap_err();
        assert!(
            error
                .to_string()
                .contains("provider transport key mismatch")
        );
        assert!(!prompt_sent);
    }

    #[test]
    fn live_apple_open_advances_counter_and_rejects_lower_replay() {
        let exporter = [5; 32];
        let nonce = [6; 32];
        let counters = Arc::new(TestCounterStore::default());
        let (trust, response, public_key) =
            apple_open_response(&exporter, &nonce, 2, counters.clone());

        verify_open_response(&trust, &exporter, &nonce, ALPN, ENROLLED_PEER, response).unwrap();
        assert_eq!(counters.counters.lock().unwrap().get(&public_key), Some(&2));

        let (trust, replay, _) = apple_open_response(&exporter, &nonce, 1, counters.clone());
        let error = verify_open_response(&trust, &exporter, &nonce, ALPN, ENROLLED_PEER, replay)
            .unwrap_err();
        let ClientError::Source { context, source } = error else {
            panic!("expected counter source error");
        };
        assert_eq!(
            context,
            "provider App Attest open assertion counter advancement failed"
        );
        assert_eq!(
            source.downcast_ref::<hellas_attestation::AttestationError>(),
            Some(&hellas_attestation::AttestationError::Counter)
        );
        assert_eq!(counters.counters.lock().unwrap().get(&public_key), Some(&2));
    }
}
