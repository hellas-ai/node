use std::net::SocketAddr;
use std::sync::Arc;

use async_stream::try_stream;
use futures::{Stream, StreamExt};
use hellas_rpc::InputCommitment;
use hellas_rpc::pb::courtesy::QuotePreparedTextRequest;
use hellas_rpc::pb::execute::Ticket;
use hellas_rpc::pb::fetch::FetchRequest;
use hellas_rpc::provenance::ExecutionProvenance;
use hellas_rpc::services::courtesy::{Courtesy, QuotePreparedText};
use hellas_rpc::services::execute::{Execute, ExecuteClientImpl};
use hellas_rpc::services::fetch::{Fetch, FetchClientImpl};
use hellas_wire::iroh::IrohTransport;
use hellas_wire::iroh::swarm::{DhtBackend, MdnsBackend, PeerExchangeBackend, ServiceRegistry};
use hellas_wire::{Metadata, ServiceMarker, WireStatus};
use iroh_mdns_address_lookup::MdnsAddressLookup;

use crate::error::ClientContext;
use crate::{
    ClientError, ClientResult, ExecutionRuntime, FetchChunkVerifier, FetchExecutionEvent,
    ProducerTrust, Route, signed_run_ticket_request, validate_fetch_ticket,
    verify_fetch_work_event,
};

pub type ExecutionRoute = Route<RemoteNodeTarget>;

/// A remote dial target: the canonical iroh identity plus optional dial hints.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoteNodeTarget {
    pub addr: ::iroh::EndpointAddr,
}

impl RemoteNodeTarget {
    pub fn node_id(&self) -> ::iroh::EndpointId {
        self.addr.id
    }
}

impl From<::iroh::EndpointId> for RemoteNodeTarget {
    fn from(node_id: ::iroh::EndpointId) -> Self {
        Self {
            addr: ::iroh::EndpointAddr::from(node_id),
        }
    }
}

impl Route<RemoteNodeTarget> {
    /// Build a remote route from a peer id and optional direct-address hints.
    pub fn remote(
        node_id: Option<::iroh::EndpointId>,
        node_addrs: Vec<SocketAddr>,
        retries: usize,
    ) -> Self {
        match node_id {
            Some(node_id) => Self::RemoteDirect(RemoteNodeTarget {
                addr: ::iroh::EndpointAddr::from_parts(
                    node_id,
                    node_addrs.into_iter().map(::iroh::TransportAddr::Ip),
                ),
            }),
            None => Self::RemoteDiscovery { retries },
        }
    }
}

/// Bound endpoint plus the per-service registry and connection pools built on it.
#[derive(Clone)]
pub struct RemoteRpc {
    _endpoint: ::iroh::Endpoint,
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
            _endpoint: endpoint,
            registry: discovery.registry,
        });
        Ok(self)
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

/// Quote prepared text on a specific peer and return its ticket and provenance.
pub async fn quote_prepared_text<L>(
    runtime: &ExecutionRuntime<L>,
    target: &RemoteNodeTarget,
    quote_req: &QuotePreparedTextRequest,
) -> ClientResult<(Ticket, ExecutionProvenance)> {
    let transport = runtime.remote_transport::<Courtesy>(target).await?;
    let with_trailer = hellas_rpc::call::unary_with_trailer::<_, QuotePreparedText>(
        &transport,
        quote_req.clone(),
        Metadata::new(),
    )
    .await
    .map_err(|status| {
        ClientError::wire(
            format!("node {} declined quote_prepared_text", target.node_id()),
            status,
        )
    })?;
    let ticket = with_trailer.response.ticket.ok_or_else(|| {
        ClientError::protocol(format!(
            "quote_prepared_text response from {} missing ticket",
            target.node_id()
        ))
    })?;
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
    Ok((ticket, provenance))
}

/// Discover Courtesy peers until one returns a valid quote.
pub async fn discover_and_quote(
    registry: &ServiceRegistry,
    quote_req: &QuotePreparedTextRequest,
    retries: usize,
) -> ClientResult<(RemoteNodeTarget, Ticket, ExecutionProvenance)> {
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

        let with_trailer = match hellas_rpc::call::unary_with_trailer::<_, QuotePreparedText>(
            &transport,
            quote_req.clone(),
            Metadata::new(),
        )
        .await
        {
            Ok(response) => response,
            Err(status) => {
                last_error = Some(ClientError::wire(
                    format!("node {peer_id} declined quote_prepared_text"),
                    status,
                ));
                if attempts >= max_attempts {
                    break;
                }
                continue;
            }
        };

        let Some(ticket) = with_trailer.response.ticket else {
            last_error = Some(ClientError::protocol(format!(
                "quote_prepared_text response from {peer_id} missing ticket"
            )));
            if attempts >= max_attempts {
                break;
            }
            continue;
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

        return Ok((RemoteNodeTarget::from(peer_id), ticket, provenance));
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
) -> ClientResult<Ticket> {
    let transport = runtime.remote_transport::<Fetch>(target).await?;
    let client = FetchClientImpl::new(transport);
    let ticket = client.create_ticket(request).await.map_err(|status| {
        ClientError::wire(
            format!("node {} declined fetch create_ticket", target.node_id()),
            status,
        )
    })?;
    validate_fetch_ticket(ticket, input_commitment)
}

/// Discover Fetch peers until one returns a valid ticket.
pub async fn discover_and_fetch_quote(
    registry: &ServiceRegistry,
    request: &FetchRequest,
    input_commitment: InputCommitment,
    retries: usize,
) -> ClientResult<(RemoteNodeTarget, Ticket)> {
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

        let client = FetchClientImpl::new(transport);
        match client.create_ticket(request.clone()).await {
            Ok(ticket) => {
                let ticket = validate_fetch_ticket(ticket, input_commitment)?;
                return Ok((RemoteNodeTarget::from(peer_id), ticket));
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

/// Run a fetch ticket over an already-dialed Execute transport.
pub fn execute_fetch_stream(
    transport: IrohTransport,
    ticket: Ticket,
    input_commitment: InputCommitment,
    trust: ProducerTrust,
    runner_key: Arc<hellas_rpc::ProducerSigningKey>,
) -> impl Stream<Item = ClientResult<FetchExecutionEvent>> + Send {
    try_stream! {
        let client = ExecuteClientImpl::new(transport);
        let run_ticket = signed_run_ticket_request(ticket, runner_key.as_ref())?;
        let mut wire = client
            .run_ticket(run_ticket)
            .await
            .map_err(|status| ClientError::wire("failed to start remote fetch execute stream", status))?;
        let mut got_terminal = false;
        let mut verifier = FetchChunkVerifier::new(input_commitment, trust);
        while let Some(item) = wire.next().await {
            let event = verify_fetch_work_event(
                &mut verifier,
                item.map_err(|status: WireStatus| {
                    ClientError::wire("remote fetch execute stream failed", status)
                })?,
                input_commitment,
            )?;
            let is_done = matches!(event, FetchExecutionEvent::Done(_));
            yield event;
            if is_done {
                got_terminal = true;
                break;
            }
        }
        wire.finish()
            .map_err(|status| ClientError::wire("remote fetch execute stream trailer", status))?;
        if !got_terminal {
            Err(ClientError::protocol(
                "remote fetch execute stream ended Ok but emitted no Done event"
            ))?;
        }
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
