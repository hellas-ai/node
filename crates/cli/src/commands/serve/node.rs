//! Node server bootstrap.
//!
//! Binds an iroh `Endpoint` with all service ALPNs, runs the executor,
//! and spawns a per-connection accept loop that routes each inbound
//! stream to the right service's dispatcher (selected by ALPN).
//!
//! Peers can reach this node by direct address. Registry publishing is
//! owned by the service-discovery path and is not started from this
//! bootstrap.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
#[cfg(feature = "evaluate")]
use hellas_executor::ArtifactStoreConfig;
use hellas_executor::{
    Executor, ExecutorMetrics, ExecutorSpawnConfig, FetchAccessPolicy, FetchQuotaStoreBackend,
    FetchRouteRegistry, FetchTranscriptStoreBackend,
};
use hellas_rpc::Dtype;
use hellas_rpc::pb::work::{
    AcceptWorkRequest, AcceptWorkResponse, AdmitCertificateRequest, AdmitCertificateResponse,
    DeliverResultRequest, DeliverResultResponse, ExchangeSetupRequest, ExchangeSetupResponse,
    WorkRefusalCode, WorkRefused, accept_work_response, admit_certificate_response,
    deliver_result_response, exchange_setup_response,
};
use hellas_rpc::peers::{PeerDirectory, PeerId, PeerManager};
use hellas_rpc::policy::ExecutePolicy;
use hellas_rpc::serve::AccountingDispatcher;
use hellas_rpc::services::node::{Node, NodeServer};
use hellas_rpc::services::work::{Work, WorkHandler, WorkServer};
use hellas_rpc::services::work_setup::{WorkSetup, WorkSetupHandler, WorkSetupServer};
use hellas_rpc::{Assurance, ProducerSigningKey};
use hellas_wire::iroh::IrohTransport;
use hellas_wire::{Dispatcher, ServiceMarker, StreamTransport, TransportContext, WireStatus};
use iroh::{Endpoint, EndpointId, SecretKey, endpoint::Connection, endpoint::presets};
use tokio::task::JoinHandle;
use tracing::warn;

use super::node_handler::NodeHandlerImpl;
use crate::commands::discovery::{DiscoveryAdvertiser, served_alpns, start_server_advertising};

pub(super) struct NodeHandle {
    node_id: EndpointId,
    accept_task: Option<JoinHandle<()>>,
    endpoint: Endpoint,
    discovery: Option<DiscoveryAdvertiser>,
}

impl NodeHandle {
    pub(super) fn node_id(&self) -> EndpointId {
        self.node_id
    }

    #[cfg(feature = "otel")]
    pub(super) fn iroh_metrics(&self) -> iroh::metrics::EndpointMetrics {
        self.endpoint.metrics().clone()
    }

    pub(super) async fn shutdown(mut self) -> anyhow::Result<()> {
        if let Some(handle) = self.accept_task.take() {
            handle.abort();
            let _ = handle.await;
        }
        if let Some(discovery) = self.discovery.take() {
            discovery.shutdown().await;
        }
        self.endpoint.close().await;
        Ok(())
    }
}

pub(super) struct NodeConfig {
    pub(super) port: Option<u16>,
    pub(super) execute_policy: ExecutePolicy,
    pub(super) queue_size: usize,
    pub(super) preload_models: Vec<String>,
    pub(super) build: String,
    pub(super) graffiti: Vec<u8>,
    pub(super) supported_dtypes: Vec<Dtype>,
    pub(super) fetch_access_policy: FetchAccessPolicy,
    pub(super) artifact_store_path: PathBuf,
    pub(super) fetch_routes: FetchRouteRegistry,
    pub(super) fetch_max_in_flight: usize,
    pub(super) fetch_queue_size: usize,
    pub(super) work_configured: bool,
    pub(super) secret_key: SecretKey,
    pub(super) producer_key: ProducerSigningKey,
    pub(super) provider_genesis: Vec<u8>,
    pub(super) assurance: Assurance,
    pub(super) metrics: Arc<ExecutorMetrics>,
    #[cfg(feature = "evaluate")]
    pub(super) artifact_store: ArtifactStoreConfig,
}

pub(super) async fn spawn_node(config: NodeConfig) -> anyhow::Result<NodeHandle> {
    let fetch_store =
        FetchTranscriptStoreBackend::fs(config.artifact_store_path.join("fetch-transcripts"));
    let fetch_access_policy = config
        .fetch_access_policy
        .with_store(FetchQuotaStoreBackend::fs(
            config.artifact_store_path.join("fetch-quota"),
        ));
    let handle = Executor::spawn_configured(ExecutorSpawnConfig {
        execute_policy: config.execute_policy,
        queue_capacity: config.queue_size,
        supported_dtypes: config.supported_dtypes,
        metrics: config.metrics.clone(),
        producer_key: Arc::new(config.producer_key),
        provider_genesis: Arc::new(config.provider_genesis),
        assurance: config.assurance,
        fetch_access_policy,
        fetch_routes: config.fetch_routes,
        fetch_max_in_flight: config.fetch_max_in_flight,
        fetch_queue_capacity: config.fetch_queue_size,
        fetch_store,
        #[cfg(feature = "evaluate")]
        artifact_store: config.artifact_store,
    })
    .await
    .context("failed to spawn executor")?;
    for model in &config.preload_models {
        handle
            .materialize_model(model.clone())
            .await
            .with_context(|| format!("failed to make model {model} available"))?;
    }

    let alpns = served_alpns(config.work_configured);
    let mut builder = Endpoint::builder(presets::N0)
        .secret_key(config.secret_key)
        .alpns(alpns.clone());
    if let Some(port) = config.port {
        builder = builder
            .bind_addr(format!("0.0.0.0:{port}").parse::<std::net::SocketAddr>()?)
            .map_err(|e| anyhow::anyhow!("invalid bind address: {e}"))?;
    }
    let endpoint = builder
        .bind()
        .await
        .context("failed to bind iroh endpoint")?;
    let node_id = endpoint.id();
    let discovery = start_server_advertising(&endpoint, &alpns)
        .context("failed to start service discovery advertising")?;

    // -- Construct a shared peer directory.
    //
    // The directory records inbound service observations and is shared
    // across the dispatch path.
    //
    // Deferred until a concrete abuse scenario warrants it: an
    // `AdmittingDispatcher<S>` that looks up per-method policy before
    // forwarding to the generated dispatcher and records inbound request
    // observations in the directory.
    let local_peer = PeerId::from_bytes(*node_id.as_bytes());
    // Seed the directory with this crate's generated service catalogue so
    // ALPN/FQN service-filter queries resolve (p2p ships no service names).
    let directory = Arc::new(PeerDirectory::with_config(
        local_peer,
        hellas_rpc::peer_directory_config(),
    ));

    // -- Build the Node handler with the operator-supplied build hash
    //    and graffiti so introspection (`hellas rpc`) returns real data.
    //    `NodeHandlerImpl: Clone` (its fields are Arc/Copy), so we
    //    clone per-connection rather than wrap in Arc<dyn>.
    let node_handler =
        NodeHandlerImpl::new(node_id, config.build, config.graffiti, directory.clone());

    // -- Accept loop: one task per inbound Connection; per-Connection
    //    dispatch routed by ALPN to the matching service handler.
    let work_configured = config.work_configured;
    let accept_endpoint = endpoint.clone();
    let accept_task = tokio::spawn(async move {
        loop {
            let incoming = match accept_endpoint.accept().await {
                Some(inc) => inc,
                None => break, // endpoint closed
            };
            let accepting = match incoming.accept() {
                Ok(a) => a,
                Err(e) => {
                    warn!("incoming accept failed: {e}");
                    continue;
                }
            };
            let node_handler_for_conn = node_handler.clone();
            let manager_for_conn = directory.manager();
            tokio::spawn(async move {
                let conn = match accepting.await {
                    Ok(c) => c,
                    Err(e) => {
                        warn!("connection handshake failed: {e}");
                        return;
                    }
                };
                let alpn = conn.alpn().to_vec();
                if let Err(e) = serve_connection(
                    alpn,
                    conn,
                    node_handler_for_conn,
                    manager_for_conn,
                    work_configured,
                )
                .await
                {
                    warn!("serve_connection error: {e}");
                }
            });
        }
    });

    Ok(NodeHandle {
        node_id,
        accept_task: Some(accept_task),
        endpoint,
        discovery: Some(discovery),
    })
}

/// Per-connection serve: each inbound substream is dispatched to the
/// service selected by the connection's negotiated ALPN.
async fn serve_connection(
    alpn: Vec<u8>,
    conn: Connection,
    node_handler: NodeHandlerImpl,
    manager: PeerManager,
    work_configured: bool,
) -> anyhow::Result<()> {
    let transport = IrohTransport::new(conn);

    // Every generated `XServer` is wrapped in `AccountingDispatcher`
    // so per-peer counters (`total_requests`, `last_seen_ms`, RTT
    // EMA) are populated for every inbound. That's the producer side
    // of the data that `PeerDirectory::ranked_known_peers` consumes
    // when surfacing `Node/get_known_peers`; without this wrapper
    // the directory the node hands out is always empty.
    if alpn == <Node as ServiceMarker>::ALPN.as_bytes() {
        let server = AccountingDispatcher::new(NodeServer(node_handler), manager);
        serve_loop(&transport, &server).await
    } else if work_configured && alpn == <WorkSetup as ServiceMarker>::ALPN.as_bytes() {
        let server = AccountingDispatcher::new(WorkSetupServer(UnmountedWork), manager);
        serve_loop(&transport, &server).await
    } else if work_configured && alpn == <Work as ServiceMarker>::ALPN.as_bytes() {
        let server = AccountingDispatcher::new(WorkServer(UnmountedWork), manager);
        serve_loop(&transport, &server).await
    } else {
        warn!("Unknown ALPN: {:?}", String::from_utf8_lossy(&alpn));
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
struct UnmountedWork;

fn not_ready() -> WorkRefused {
    WorkRefused {
        code: WorkRefusalCode::NotReady as i32,
        reason: "work state is not mounted".to_string(),
    }
}

impl WorkSetupHandler for UnmountedWork {
    fn exchange_setup(
        &self,
        _request: ExchangeSetupRequest,
        _context: TransportContext,
    ) -> impl core::future::Future<
        Output = Result<
            impl Into<hellas_rpc::call::WithTrailer<ExchangeSetupResponse>> + Send,
            WireStatus,
        >,
    > + Send {
        core::future::ready(Ok(ExchangeSetupResponse {
            outcome: Some(exchange_setup_response::Outcome::Refused(not_ready())),
        }))
    }
}

impl WorkHandler for UnmountedWork {
    fn accept_work(
        &self,
        _request: AcceptWorkRequest,
        _context: TransportContext,
    ) -> impl core::future::Future<
        Output = Result<
            impl Into<hellas_rpc::call::WithTrailer<AcceptWorkResponse>> + Send,
            WireStatus,
        >,
    > + Send {
        core::future::ready(Ok(AcceptWorkResponse {
            outcome: Some(accept_work_response::Outcome::Refused(not_ready())),
        }))
    }

    fn deliver_result(
        &self,
        _request: DeliverResultRequest,
        _context: TransportContext,
    ) -> impl core::future::Future<
        Output = Result<
            impl Into<hellas_rpc::call::WithTrailer<DeliverResultResponse>> + Send,
            WireStatus,
        >,
    > + Send {
        core::future::ready(Ok(DeliverResultResponse {
            outcome: Some(deliver_result_response::Outcome::Refused(not_ready())),
        }))
    }

    fn admit_certificate(
        &self,
        _request: AdmitCertificateRequest,
        _context: TransportContext,
    ) -> impl core::future::Future<
        Output = Result<
            impl Into<hellas_rpc::call::WithTrailer<AdmitCertificateResponse>> + Send,
            WireStatus,
        >,
    > + Send {
        core::future::ready(Ok(AdmitCertificateResponse {
            outcome: Some(admit_certificate_response::Outcome::Refused(not_ready())),
        }))
    }
}

async fn serve_loop<S>(transport: &IrohTransport, server: &S) -> anyhow::Result<()>
where
    S: Dispatcher<IrohTransport> + Send + Sync,
    S::Error: Send + Sync + 'static,
{
    while let Ok(Some(inbound)) = transport.accept().await {
        if server.dispatch(inbound).await.is_err() {
            // RPC errors can be derived from request content. Keep the trace
            // useful without copying prompt or token material into logs.
            warn!("dispatch error; request details suppressed");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use hellas_rpc::call::WithTrailer;
    use hellas_rpc::work::WorkRefusal;

    use super::*;

    fn assert_retryable_not_ready(refusal: WorkRefused) {
        assert_eq!(refusal.code, WorkRefusalCode::NotReady as i32);
        assert!(WorkRefusal::NotReady.is_retryable());
        assert!(refusal.reason.len() <= 64);
    }

    #[tokio::test]
    async fn unmounted_work_refuses_every_method_as_bounded_retryable_not_ready() {
        let setup: WithTrailer<ExchangeSetupResponse> = UnmountedWork
            .exchange_setup(ExchangeSetupRequest::default(), TransportContext::default())
            .await
            .unwrap()
            .into();
        let Some(exchange_setup_response::Outcome::Refused(refusal)) = setup.response.outcome
        else {
            panic!("unmounted WorkSetup must refuse")
        };
        assert_retryable_not_ready(refusal);

        let accept: WithTrailer<AcceptWorkResponse> = UnmountedWork
            .accept_work(AcceptWorkRequest::default(), TransportContext::default())
            .await
            .unwrap()
            .into();
        let Some(accept_work_response::Outcome::Refused(refusal)) = accept.response.outcome else {
            panic!("unmounted Work must refuse acceptance")
        };
        assert_retryable_not_ready(refusal);

        let delivery: WithTrailer<DeliverResultResponse> = UnmountedWork
            .deliver_result(DeliverResultRequest::default(), TransportContext::default())
            .await
            .unwrap()
            .into();
        let Some(deliver_result_response::Outcome::Refused(refusal)) = delivery.response.outcome
        else {
            panic!("unmounted Work must refuse delivery")
        };
        assert_retryable_not_ready(refusal);

        let payment: WithTrailer<AdmitCertificateResponse> = UnmountedWork
            .admit_certificate(
                AdmitCertificateRequest::default(),
                TransportContext::default(),
            )
            .await
            .unwrap()
            .into();
        let Some(admit_certificate_response::Outcome::Refused(refusal)) = payment.response.outcome
        else {
            panic!("unmounted Work must refuse payment")
        };
        assert_retryable_not_ready(refusal);
    }
}
