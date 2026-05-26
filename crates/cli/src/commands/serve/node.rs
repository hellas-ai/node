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
use catgrad::prelude::Dtype;
use hellas_core::ProducerSigningKey;
use hellas_executor::{
    ArtifactStoreConfig, CourtesyServer, Executor, ExecuteServer, ExecutorMetrics,
    OpaqueServer, SymbolicServer,
};
use hellas_rpc::peers::{PeerDirectory, PeerId, PeerManager};
use hellas_rpc::policy::{DownloadPolicy, ExecutePolicy};
use hellas_rpc::serve::AccountingDispatcher;
use hellas_rpc::services::courtesy::Courtesy;
use hellas_rpc::services::execute::Execute;
use hellas_rpc::services::node::{Node, NodeServer};
use hellas_rpc::services::opaque::Opaque;
use hellas_rpc::services::symbolic::Symbolic;
use hellas_wire::iroh::IrohTransport;
use hellas_wire::{Dispatcher, ServiceMarker, StreamTransport};
use iroh::{endpoint::Connection, endpoint::presets, Endpoint, EndpointId, SecretKey};
use tokio::task::JoinHandle;
use tracing::warn;

use super::node_handler::NodeHandlerImpl;

pub(super) struct NodeHandle {
    node_id: EndpointId,
    accept_task: Option<JoinHandle<()>>,
    endpoint: Endpoint,
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
        self.endpoint.close().await;
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn spawn_node(
    port: Option<u16>,
    download_policy: DownloadPolicy,
    execute_policy: ExecutePolicy,
    queue_size: usize,
    preload_weights: Vec<String>,
    build: String,
    graffiti: Vec<u8>,
    supported_dtypes: Vec<Dtype>,
    artifact_store_path: PathBuf,
    secret_key: SecretKey,
    producer_key: ProducerSigningKey,
    metrics: Arc<ExecutorMetrics>,
) -> anyhow::Result<NodeHandle> {
    // -- Spawn the executor (the local handler that backs all four RPC services).
    let handle = Executor::spawn_with_metrics_and_producer_key_and_artifact_store(
        download_policy,
        execute_policy,
        queue_size,
        supported_dtypes,
        metrics.clone(),
        Arc::new(producer_key),
        ArtifactStoreConfig::Fs(artifact_store_path),
    )
    .await
    .context("failed to spawn executor")?;
    // `preload_weights` is accepted for CLI compatibility; model loading is
    // demand-driven by the executor. `build` and `graffiti` are surfaced via
    // the Node service's GetNodeInfoResponse below.
    let _ = preload_weights;

    // -- Bind iroh Endpoint with one ALPN per service we serve.
    let alpns: Vec<Vec<u8>> = vec![
        <Execute as ServiceMarker>::ALPN.as_bytes().to_vec(),
        <Symbolic as ServiceMarker>::ALPN.as_bytes().to_vec(),
        <Opaque as ServiceMarker>::ALPN.as_bytes().to_vec(),
        <Courtesy as ServiceMarker>::ALPN.as_bytes().to_vec(),
        <Node as ServiceMarker>::ALPN.as_bytes().to_vec(),
    ];

    let mut builder = Endpoint::builder(presets::N0)
        .secret_key(secret_key)
        .alpns(alpns);
    if let Some(port) = port {
        builder = builder
            .bind_addr(format!("0.0.0.0:{port}").parse::<std::net::SocketAddr>()?)
            .map_err(|e| anyhow::anyhow!("invalid bind address: {e}"))?;
    }
    let endpoint = builder
        .bind()
        .await
        .context("failed to bind iroh endpoint")?;
    let node_id = endpoint.id();

    // -- Construct a shared peer directory.
    //
    // The directory records inbound service observations and is shared
    // across the dispatch path.
    //
    // Deferred until a concrete abuse scenario warrants it: an
    // `AdmittingDispatcher<S>` that, before forwarding to the
    // generated dispatcher, looks up `policy_for(inbound.method_id)`
    // via `KNOWN_RATE_LIMITED_METHODS` and calls
    // `directory.observe_inbound_request(...)`. The plan in
    // `/home/grw/.claude/plans/recursive-mixing-neumann.md` Phase F
    // is the implementation sketch when needed.
    let local_peer = PeerId::from_bytes(*node_id.as_bytes());
    let directory = Arc::new(PeerDirectory::new(local_peer));

    // -- Build the Node handler with the operator-supplied build hash
    //    and graffiti so introspection (`hellas rpc`) returns real data.
    //    `NodeHandlerImpl: Clone` (its fields are Arc/Copy), so we
    //    clone per-connection rather than wrap in Arc<dyn>.
    let node_handler = NodeHandlerImpl::new(node_id, build, graffiti, directory.clone());

    // -- Accept loop: one task per inbound Connection; per-Connection
    //    dispatch routed by ALPN to the matching service handler.
    let accept_handle = handle.clone();
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
            let handle_for_conn = accept_handle.clone();
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
                    handle_for_conn,
                    node_handler_for_conn,
                    manager_for_conn,
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
    })
}

/// Per-connection serve: each inbound substream becomes an `Inbound`
/// dispatched to the right `XServer<ExecutorHandle>` based on the
/// connection's negotiated ALPN.
async fn serve_connection(
    alpn: Vec<u8>,
    conn: Connection,
    handle: hellas_executor::ExecutorHandle,
    node_handler: NodeHandlerImpl,
    manager: PeerManager,
) -> anyhow::Result<()> {
    let transport = IrohTransport::new(conn);

    // Every generated `XServer` is wrapped in `AccountingDispatcher`
    // so per-peer counters (`total_requests`, `last_seen_ms`, RTT
    // EMA) are populated for every inbound. That's the producer side
    // of the data that `PeerDirectory::ranked_known_peers` consumes
    // when surfacing `Node/get_known_peers`; without this wrapper
    // the directory the node hands out is always empty.
    if alpn == <Execute as ServiceMarker>::ALPN.as_bytes() {
        let server = AccountingDispatcher::new(ExecuteServer(handle), manager);
        serve_loop(&transport, &server).await
    } else if alpn == <Symbolic as ServiceMarker>::ALPN.as_bytes() {
        let server = AccountingDispatcher::new(SymbolicServer(handle), manager);
        serve_loop(&transport, &server).await
    } else if alpn == <Opaque as ServiceMarker>::ALPN.as_bytes() {
        let server = AccountingDispatcher::new(OpaqueServer(handle), manager);
        serve_loop(&transport, &server).await
    } else if alpn == <Courtesy as ServiceMarker>::ALPN.as_bytes() {
        let server = AccountingDispatcher::new(CourtesyServer(handle), manager);
        serve_loop(&transport, &server).await
    } else if alpn == <Node as ServiceMarker>::ALPN.as_bytes() {
        let server = AccountingDispatcher::new(NodeServer(node_handler), manager);
        serve_loop(&transport, &server).await
    } else {
        warn!("Unknown ALPN: {:?}", String::from_utf8_lossy(&alpn));
        Ok(())
    }
}

async fn serve_loop<S>(
    transport: &IrohTransport,
    server: &S,
) -> anyhow::Result<()>
where
    S: Dispatcher<IrohTransport> + Send + Sync,
    S::Error: Send + Sync + 'static,
{
    while let Ok(Some(inbound)) = transport.accept().await {
        if let Err(e) = server.dispatch(inbound).await {
            warn!("dispatch error: {e}");
        }
    }
    Ok(())
}
