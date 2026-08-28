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
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Context;
use hellas_chain::client::VerifiedRemoteLightClient;
use hellas_chain::work_blocks::advance_paid_work_clock;
use hellas_chain::{
    ConsensusInfo, ConsensusVerifier, FinalizedWorkView, WorkBlocks, WorkChannelQuery,
};
#[cfg(feature = "evaluate")]
use hellas_executor::ArtifactStoreConfig;
use hellas_executor::{
    Executor, ExecutorMetrics, ExecutorSpawnConfig, FetchAccessPolicy, FetchQuotaStoreBackend,
    FetchRouteRegistry, FetchTranscriptStoreBackend,
};
use hellas_kernel::{EdgeId, NetworkId, Secp256k1Signer, Secp256k1Verifier};
use hellas_rpc::Dtype;
use hellas_rpc::pb::work::{
    AcceptWorkRequest, AcceptWorkResponse, AdmitCertificateRequest, AdmitCertificateResponse,
    DeliverResultRequest, DeliverResultResponse, ExchangeSetupRequest, ExchangeSetupResponse,
    WorkRefusalCode, WorkRefused, accept_work_response, admit_certificate_response,
    deliver_result_response, exchange_setup_response,
};
use hellas_rpc::peers::{PeerDirectory, PeerId, PeerManager};
use hellas_rpc::policy::ExecutePolicy;
use hellas_rpc::protocol::work_setup::{ProviderChannelPolicy, WorkChannelDescriptor};
use hellas_rpc::serve::AccountingDispatcher;
use hellas_rpc::services::node::{Node, NodeServer};
use hellas_rpc::services::work::{Work, WorkHandler, WorkServer};
use hellas_rpc::services::work_setup::{WorkSetup, WorkSetupHandler, WorkSetupServer};
use hellas_rpc::work::{CloseEndpoint, WorkService};
use hellas_rpc::work_close::{FinalizedBlocks, TxSink};
use hellas_rpc::work_handshake::{PaymentAdmission, SetupEndpoint, SetupService};
use hellas_rpc::work_open::{
    SetupAdvance, SetupDriveError, SetupProgress, SetupView, advance_setup,
};
use hellas_rpc::work_store::{ChannelStore, Role, SetupStore, discover_setups};
use hellas_rpc::{Assurance, ProducerSigningKey};
use hellas_wire::iroh::IrohTransport;
use hellas_wire::{Dispatcher, ServiceMarker, StreamTransport, TransportContext, WireStatus};
use iroh::{Endpoint, EndpointId, SecretKey, endpoint::Connection, endpoint::presets};
use tokio::sync::{Mutex as AsyncMutex, oneshot};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use super::node_handler::NodeHandlerImpl;
use crate::commands::discovery::{DiscoveryAdvertiser, served_alpns, start_server_advertising};

type ProductionWorkSource = WorkBlocks<VerifiedRemoteLightClient>;

pub(super) struct NodeHandle {
    node_id: EndpointId,
    accept_task: Option<JoinHandle<()>>,
    endpoint: Endpoint,
    discovery: Option<DiscoveryAdvertiser>,
    work: Option<WorkWatcher>,
}

/// The clock over this node's paid-work journals, and the way to stop
/// it.
///
/// Stopped rather than aborted: every journal this task holds is closed
/// when the task returns, and a shutdown that aborted it would drop
/// those files at whatever point the runtime chose. Nothing here is
/// racing a torn write — a journal append is synchronous and fsynced
/// inside its own borrow, and there is no await inside one — but a
/// runner told to stop between two steps is what leaves the operator a
/// process that owns nothing.
struct WorkWatcher {
    stop: oneshot::Sender<()>,
    task: JoinHandle<()>,
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
        // The clock first, and joined rather than aborted: its journals
        // are released when its task returns, and a node that closed its
        // endpoint while a step was still writing would be a node whose
        // files outlive it.
        if let Some(watcher) = self.work.take() {
            let _ = watcher.stop.send(());
            let _ = watcher.task.await;
        }
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
    /// What the clock over this node's paid-work journals is built
    /// from, or `None` when no work configuration was loaded. Its
    /// presence is still what advertises the two work ALPNs.
    pub(super) work: Option<WorkRunnerConfig>,
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

    let alpns = served_alpns(config.work.is_some());
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

    // -- The clock. Spawned only when a work configuration was loaded,
    //    and given the same mount slot the accept loop reads: the runner
    //    publishes the channel it is handed, and `Work` is answered from
    //    it from that moment on.
    let work_mount: MountedWork<ProductionWorkSource> = MountedWork::default();
    let setup_mount = MountedSetup::default();
    let work = config.work.map(|work| {
        let poll = work.poll;
        let runner = WorkRunner::discover(work, work_mount.clone(), setup_mount.clone());
        let (stop, stopped) = oneshot::channel();
        let task = tokio::spawn(async move {
            match runner {
                Ok(runner) => runner.run(stopped).await,
                // §4's rule, at the one place it could still refuse to
                // start: a root that cannot be enumerated is an operator
                // error, and a node that exited over it would be a node
                // answering no contest at all.
                Err(error) => warn!(%error, "the paid-work journals could not be enumerated"),
            }
        });
        info!(poll_ms = poll.as_millis(), "the paid-work clock is running");
        WorkWatcher { stop, task }
    });
    let serves_work = work.is_some().then(|| work_mount.clone());
    let serves_setup = work.is_some().then(|| setup_mount.clone());

    // -- Accept loop: one task per inbound Connection; per-Connection
    //    dispatch routed by ALPN to the matching service handler.
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
            let work_for_conn = serves_work.clone();
            let setup_for_conn = serves_setup.clone();
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
                    setup_for_conn,
                    work_for_conn,
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
        work,
    })
}

/// Per-connection serve: each inbound substream is dispatched to the
/// service selected by the connection's negotiated ALPN.
async fn serve_connection<S>(
    alpn: Vec<u8>,
    conn: Connection,
    node_handler: NodeHandlerImpl,
    manager: PeerManager,
    setup: Option<MountedSetup>,
    work: Option<MountedWork<S>>,
) -> anyhow::Result<()>
where
    S: FinalizedBlocks + FinalizedWorkView + Sync,
{
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
    } else if let Some(setup) =
        setup.filter(|_| alpn == <WorkSetup as ServiceMarker>::ALPN.as_bytes())
    {
        match setup.service() {
            Some(mounted) => {
                let server = AccountingDispatcher::new(WorkSetupServer(mounted), manager);
                serve_loop(&transport, &server).await
            }
            None => {
                let server = AccountingDispatcher::new(WorkSetupServer(UnmountedWork), manager);
                serve_loop(&transport, &server).await
            }
        }
    } else if let Some(work) = work.filter(|_| alpn == <Work as ServiceMarker>::ALPN.as_bytes()) {
        // The mounted channel answers for itself. Until the runner has
        // been handed one there is no channel to answer from, and this
        // is still the bounded retryable `NotReady` §3 left here.
        match work.handler() {
            Some(mounted) => {
                let server = AccountingDispatcher::new(WorkServer(mounted), manager);
                serve_loop(&transport, &server).await
            }
            None => {
                let server = AccountingDispatcher::new(WorkServer(UnmountedWork), manager);
                serve_loop(&transport, &server).await
            }
        }
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

// ── The clock ─────────────────────────────────────────────────────────
//
// Everything below is a runner and nothing below is a decision. It
// builds no transaction, fixes no deadline, chooses no settlement,
// judges no duty due, and does not decide whether admission is on: each
// of those is a library edge it calls on a cadence, and the cadence is
// the whole of what this file adds. What it owns is *when* — and the
// journals, which is why it hands them to nobody.

/// What the clock over one node's paid-work journals is built from.
///
/// Every field is something the serve path has already loaded and
/// checked. The admission most of all: [`PaymentAdmission`] is
/// `PaidWorkDuties::payment_admission`'s answer to §4's evidence rule,
/// carried here rather than asked again, so there is no second place a
/// node could decide whether it countersigns new paid work.
pub(super) struct WorkRunnerConfig {
    /// The network the journals are keyed and the signatures bound to.
    pub(super) network: NetworkId,
    /// The threshold identity finalized blocks must authenticate under.
    pub(super) threshold_identity: Vec<u8>,
    /// The configured root the setup journals live under.
    pub(super) journal_root: PathBuf,
    /// The validator RPCs a read and a submission go to.
    pub(super) validators: Vec<String>,
    /// How often the clock ticks.
    pub(super) poll: Duration,
    /// The key every settlement this node signs is signed with.
    pub(super) settlement_key: Secp256k1Signer,
    /// What a setup endpoint over this node's evidence countersigns, or
    /// `None` when there is no evidence to build one over at all.
    pub(super) admission: Option<PaymentAdmission>,
}

/// The channel this node answers `Work` from, once the runner has been
/// handed one.
///
/// Written by the runner and read by the accept loop. What crosses is a
/// clone of a handler whose mutable pieces are themselves behind `Arc`s,
/// so the lock is held for a clone and never across a request: the
/// dispatch path never waits while holding the mount, and the clock never
/// waits on a request.
#[derive(Clone)]
pub(super) struct MountedWork<S>(Arc<Mutex<Option<MountedWorkService<S>>>>);

impl<S> Default for MountedWork<S> {
    fn default() -> Self {
        Self(Arc::new(Mutex::new(None)))
    }
}

/// One mounted channel's served handler.
///
/// `source` is replaceable because the runner redials a failed validator.
/// The request path copies the current source under the plain mutex and
/// drops that guard before its coherent read awaits. `accepting` spans the
/// complete fresh-read-to-signature sequence, so two acceptance attempts
/// cannot each refresh and then race to consume the same channel credit.
#[derive(Clone)]
struct MountedWorkService<S> {
    bond_edge: EdgeId,
    service: WorkService,
    descriptor: Option<WorkChannelDescriptor>,
    source: Arc<Mutex<S>>,
    accepting: Arc<AsyncMutex<()>>,
}

impl<S> MountedWorkService<S>
where
    S: FinalizedBlocks + FinalizedWorkView + Sync,
{
    /// Re-establishes admission from one fresh coherent read.
    ///
    /// The service is the exact clone the runner drives. Its cursor is
    /// checked after readiness, and that same service receives the fresh
    /// decision before the raw handler is reached. A missing policy,
    /// failed read, failed predicate, lagging cursor, or endpoint failure
    /// therefore leaves the request on the retryable `NotReady` side.
    async fn refresh_admission(&self) -> anyhow::Result<()> {
        let Some(descriptor) = self.descriptor.as_ref() else {
            anyhow::bail!("this channel has no measured admission policy");
        };
        let query = WorkChannelQuery {
            bond_edge: descriptor.bond_edge(),
            payment_edge: descriptor.channel().payment_edge(),
            funding: Default::default(),
        };
        // A `std::sync::MutexGuard` is deliberately confined to this
        // block. Holding the source-slot guard across the read would make
        // this handler's future non-`Send` and is not a valid dispatch.
        let source = {
            let held = self
                .source
                .lock()
                .map_err(|_| anyhow::anyhow!("the finalized source lock is poisoned"))?;
            held.clone()
        };
        let Some(snapshot) = source
            .work_channel_snapshot(query.clone())
            .await
            .context("the fresh coherent channel read failed")?
        else {
            anyhow::bail!("no finalized channel snapshot is available");
        };
        if snapshot.query() != &query {
            anyhow::bail!("the finalized source answered for another channel");
        }
        let ready = descriptor
            .check_ready(&snapshot.observed_channel())
            .context("the fresh channel snapshot is not ready")?;
        let cursor = self
            .service
            .with_state(|state| state.cursor().0)
            .context("the mounted channel cursor is unavailable")?;
        ready
            .check_caught_up(cursor)
            .context("the mounted channel has not caught up to the fresh snapshot")?;
        self.service
            .admit_new_work(ready)
            .context("the driven work service refused its fresh readiness")
    }
}

impl<S> WorkHandler for MountedWorkService<S>
where
    S: FinalizedBlocks + FinalizedWorkView + Sync,
{
    fn accept_work(
        &self,
        request: AcceptWorkRequest,
        _context: TransportContext,
    ) -> impl core::future::Future<
        Output = Result<
            impl Into<hellas_rpc::call::WithTrailer<AcceptWorkResponse>> + Send,
            WireStatus,
        >,
    > + Send {
        async move {
            let _accepting = self.accepting.lock().await;
            if let Err(error) = self.refresh_admission().await {
                debug!(%error, "an acceptance attempt found no fresh channel readiness");
                return Ok(AcceptWorkResponse {
                    outcome: Some(accept_work_response::Outcome::Refused(WorkRefused {
                        code: WorkRefusalCode::NotReady as i32,
                        reason: "fresh channel readiness is unavailable".to_string(),
                    })),
                });
            }
            Ok(self.service.accept(&request))
        }
    }

    fn deliver_result(
        &self,
        request: DeliverResultRequest,
        context: TransportContext,
    ) -> impl core::future::Future<
        Output = Result<
            impl Into<hellas_rpc::call::WithTrailer<DeliverResultResponse>> + Send,
            WireStatus,
        >,
    > + Send {
        self.service.deliver_result(request, context)
    }

    fn admit_certificate(
        &self,
        request: AdmitCertificateRequest,
        context: TransportContext,
    ) -> impl core::future::Future<
        Output = Result<
            impl Into<hellas_rpc::call::WithTrailer<AdmitCertificateResponse>> + Send,
            WireStatus,
        >,
    > + Send {
        self.service.admit_certificate(request, context)
    }
}

impl<S: Clone> MountedWork<S> {
    /// Serves `Work` from `service` from now on, and says whether it
    /// took the slot.
    ///
    /// The first mount wins. One endpoint answers for one channel alone
    /// — an authorization naming another is refused by the endpoint and
    /// never routed — so a second mounted channel is still driven and is
    /// not served, and the operator is told which.
    fn mount(
        &self,
        bond_edge: EdgeId,
        service: &WorkService,
        descriptor: Option<WorkChannelDescriptor>,
        source: &S,
    ) -> bool {
        match self.0.lock() {
            Ok(mut held) if held.is_none() => {
                *held = Some(MountedWorkService {
                    bond_edge,
                    service: service.clone(),
                    descriptor,
                    source: Arc::new(Mutex::new(source.clone())),
                    accepting: Arc::new(AsyncMutex::new(())),
                });
                true
            }
            _ => false,
        }
    }

    /// The mounted channel's served handler, when the runner has mounted
    /// one.
    fn handler(&self) -> Option<MountedWorkService<S>> {
        self.0.lock().ok().and_then(|held| held.clone())
    }

    /// The exact mounted service, for the clock and its state checks.
    fn service(&self) -> Option<WorkService> {
        self.handler().map(|mounted| mounted.service)
    }

    /// Replaces the finalized source for the matching driven channel.
    ///
    /// A reconnect reaches handlers already cloned by live connections,
    /// because they share this inner source slot. Neither mount lock is
    /// held across a source request.
    fn refresh_source(&self, bond_edge: EdgeId, source: &S) {
        let source_slot = self.0.lock().ok().and_then(|held| {
            held.as_ref()
                .filter(|mounted| mounted.bond_edge == bond_edge)
                .map(|mounted| Arc::clone(&mounted.source))
        });
        if let Some(source_slot) = source_slot {
            if let Ok(mut held) = source_slot.lock() {
                *held = source.clone();
            }
        }
    }

    /// Stops serving `Work` from every channel.
    ///
    /// The clock's last act. A channel nobody is advancing is not a
    /// channel to answer from — its journal is closed the moment the
    /// runner drops it, and a handler still holding it open would be the
    /// one thing keeping the files this process no longer owns.
    fn clear_all(&self) {
        if let Ok(mut held) = self.0.lock() {
            *held = None;
        }
    }
}

/// The one provider setup this node answers `WorkSetup` from.
///
/// Written by discovery and read by the accept loop, beside
/// [`MountedWork`]. The clone in this slot is the exact [`SetupService`]
/// stored in [`Driven::Setup`], so serving and driving share one exclusive
/// journal rather than attempting to reopen it.
#[derive(Clone, Debug, Default)]
pub(super) struct MountedSetup(Arc<Mutex<Option<MountedSetupService>>>);

#[derive(Clone, Debug)]
struct MountedSetupService {
    bond_edge: EdgeId,
    service: SetupService,
}

impl MountedSetup {
    /// Serves one setup, only while the slot is empty.
    fn mount(&self, bond_edge: EdgeId, service: &SetupService) -> bool {
        match self.0.lock() {
            Ok(mut held) if held.is_none() => {
                *held = Some(MountedSetupService {
                    bond_edge,
                    service: service.clone(),
                });
                true
            }
            _ => false,
        }
    }

    /// The exact setup service discovery mounted, cloned without holding
    /// the slot across dispatch.
    fn service(&self) -> Option<SetupService> {
        self.0
            .lock()
            .ok()
            .and_then(|held| held.as_ref().map(|mounted| mounted.service.clone()))
    }

    /// Stops serving only the setup that made this transition.
    fn clear(&self, bond_edge: EdgeId) {
        if let Ok(mut held) = self.0.lock() {
            if held
                .as_ref()
                .is_some_and(|mounted| mounted.bond_edge == bond_edge)
            {
                *held = None;
            }
        }
    }

    /// Stops serving every setup during runner shutdown.
    fn clear_all(&self) {
        if let Ok(mut held) = self.0.lock() {
            *held = None;
        }
    }
}

/// One journal, and what the clock drives it as.
///
/// Two live states and one transition between them: a setup is driven
/// until it hands back the channel it mounted, and from then on the
/// channel is what is driven. Nothing here re-derives a mount —
/// [`SetupAdvance::mounted`] is the only way a [`ChannelStore`] reaches
/// this file, and the setup is not driven again afterwards, because a
/// second step would open a second journal on the same file.
enum Driven {
    /// This node holds an admission, so the journal is driven behind the
    /// setup service that answers for it. Only an `Admits` policy is
    /// retained: it is the provider authority from which the full channel
    /// descriptor is rebuilt after the setup reveals its actual terms.
    Setup {
        service: SetupService,
        policy: Option<ProviderChannelPolicy>,
    },
    /// §4's missing, changed or unconfigured evidence: there is no
    /// admission and therefore no setup endpoint to build. Recovery is
    /// not disabled by any of those, so the journal itself is driven —
    /// history, mount and close duty are the driver's, and none of them
    /// countersigns anything.
    Recovery(Box<SetupStore>),
    /// The channel this setup mounted, close-only until a readiness
    /// decision is made for it.
    Channel(WorkService),
    /// The setup ended, or its mount was refused. Nothing left to
    /// drive.
    Done,
}

impl Driven {
    /// Takes one step of the setup this journal holds, or `None` when
    /// this journal is past its setup.
    async fn advance<S>(&mut self, source: &S) -> Option<Result<SetupAdvance, SetupDriveError>>
    where
        S: SetupView + FinalizedBlocks + TxSink + Sync + ?Sized,
    {
        match self {
            Self::Setup { service, .. } => {
                Some(service.advance_setup(source, source, source).await)
            }
            Self::Recovery(store) => Some(
                advance_setup(
                    source,
                    source,
                    source,
                    store.as_mut(),
                    &Secp256k1Verifier::new(),
                )
                .await,
            ),
            Self::Channel(_) | Self::Done => None,
        }
    }
}

/// One setup journal on a clock.
struct SetupClock {
    /// The bond this journal stakes, so a log line names which one.
    bond_edge: EdgeId,
    /// What is being driven for it.
    driven: Driven,
}

impl SetupClock {
    /// Takes this journal's one step, and says whether the chain
    /// answered.
    ///
    /// A source failure is the only outcome the caller acts on: a
    /// validator that stopped answering is dialled again rather than
    /// asked forever. Everything else is this journal's own business and
    /// is logged where it happens.
    async fn tick<S>(
        &mut self,
        source: &S,
        signer: &Secp256k1Signer,
        work_mount: &MountedWork<S>,
        setup_mount: &MountedSetup,
    ) -> bool
    where
        S: SetupView + FinalizedBlocks + FinalizedWorkView + TxSink + Sync,
    {
        let bond = hex::encode(self.bond_edge.to_bytes());
        let mut answered = true;
        if let Some(step) = self.driven.advance(source).await {
            match step {
                Ok(SetupAdvance { progress, mounted }) => {
                    if let Some(store) = mounted {
                        let policy = match &self.driven {
                            Driven::Setup { policy, .. } => policy.clone(),
                            Driven::Recovery(_) | Driven::Channel(_) | Driven::Done => None,
                        };
                        setup_mount.clear(self.bond_edge);
                        self.take_mount(store, signer, policy.as_ref(), source, work_mount, &bond);
                    } else if matches!(
                        progress,
                        SetupProgress::Aborted(_) | SetupProgress::Faulted(_)
                    ) {
                        warn!(bond, ?progress, "this setup ended with no channel to drive");
                        self.driven = Driven::Done;
                    } else {
                        debug!(bond, ?progress, "the setup advanced");
                    }
                }
                Err(error) => {
                    answered = !matches!(error, SetupDriveError::Source(_));
                    warn!(bond, %error, "this setup did not advance");
                }
            }
        }
        if let Driven::Channel(service) = &self.driven {
            work_mount.refresh_source(self.bond_edge, source);
            match advance_paid_work_clock(service, source).await {
                Ok(progress) => debug!(bond, ?progress, "the channel advanced"),
                Err(error) => {
                    answered &= !error.source_failed();
                    warn!(bond, %error, "this channel's close did not advance");
                }
            }
        }
        answered
    }

    /// Mounts the store the driver handed back.
    ///
    /// Handed back, never reopened: the journal is exclusive, so a
    /// second `ChannelStore::open` on the same file is a refusal rather
    /// than a second view, and the settlement and origin this one
    /// carries are the ones the completing read established.
    fn take_mount<S: Clone>(
        &mut self,
        store: ChannelStore,
        signer: &Secp256k1Signer,
        policy: Option<&ProviderChannelPolicy>,
        source: &S,
        mount: &MountedWork<S>,
        bond: &str,
    ) {
        // The setup's retained policy supplies the provider-controlled
        // fields, while the mounted channel supplies the payment edge and
        // complete terms the two parties actually signed. This is a full
        // descriptor reconstruction, not a mount-time readiness cache.
        let descriptor = policy.and_then(|policy| {
            let channel = store.state().channel();
            match policy.admit(
                channel.payment_edge(),
                channel.payment_terms().clone(),
            ) {
                Ok(descriptor) => Some(descriptor),
                Err(error) => {
                    warn!(bond, %error, "the mounted channel no longer satisfies its admission policy");
                    None
                }
            }
        });
        match CloseEndpoint::new(store, signer.clone()) {
            Ok(close) => {
                let service = WorkService::close_only(close);
                if mount.mount(self.bond_edge, &service, descriptor, source) {
                    info!(
                        bond,
                        "this node now answers Work from the channel it mounted"
                    );
                } else {
                    warn!(
                        bond,
                        "a channel is already served; this one is driven and not served",
                    );
                }
                self.driven = Driven::Channel(service);
            }
            // The journal and the key are not both the provider's view
            // of one channel. Nothing this runner can do about it, and
            // dropping the mount is what stops it being reopened every
            // tick.
            Err(error) => {
                warn!(bond, %error, "the mounted channel is not this node's to close");
                self.driven = Driven::Done;
            }
        }
    }
}

/// The clock, over every paid-work journal this node owns.
pub(super) struct WorkRunner<S> {
    clocks: Vec<SetupClock>,
    signer: Secp256k1Signer,
    work_mount: MountedWork<S>,
    setup_mount: MountedSetup,
    poll: Duration,
    validators: Vec<String>,
    consensus_verifier: ConsensusVerifier,
}

impl<S> WorkRunner<S>
where
    S: SetupView + FinalizedBlocks + FinalizedWorkView + TxSink + Sync,
{
    /// Opens every setup journal under the configured root.
    ///
    /// The root and the network are the whole of what a restarting node
    /// is told; the bond each journal is about and the role it was
    /// written at come out of the files, which is what `discover_setups`
    /// is for. A journal that cannot be named is reported and not
    /// skipped silently: a file this node cannot open may be a channel
    /// it still owes a close.
    ///
    /// # Errors
    ///
    /// When the root itself cannot be enumerated.
    /// `WorkSetup` has no selector in its empty first request, so exactly
    /// one discovered provider journal is the only unambiguous offer. If
    /// there are several, all are still driven for recovery and close
    /// duty, but none is served as an arbitrary answer to that request.
    pub(super) fn discover(
        config: WorkRunnerConfig,
        work_mount: MountedWork<S>,
        setup_mount: MountedSetup,
    ) -> anyhow::Result<Self> {
        let consensus_verifier = ConsensusVerifier::new(&ConsensusInfo {
            validators: config.validators.clone(),
            threshold_identity: config.threshold_identity,
            network_id: config.network.as_str().to_owned(),
        })
        .context("the configured threshold identity is not usable")?;
        let settlement_verifier = Secp256k1Verifier::new();
        let found = discover_setups(&config.journal_root, config.network).with_context(|| {
            format!(
                "failed to enumerate the work journals under {}",
                config.journal_root.display(),
            )
        })?;
        for unnamed in &found.unidentified {
            warn!(
                path = %unnamed.path.display(),
                reason = %unnamed.reason,
                "a setup journal under the work root could not be named",
            );
        }
        let provider_setups = found
            .setups
            .iter()
            .filter(|setup| setup.role == Role::Provider)
            .count();
        let setup_is_unambiguous = provider_setups == 1;
        if provider_setups > 1 {
            warn!(
                provider_setups,
                "more than one provider setup journal was discovered; WorkSetup is not served",
            );
        }
        let mut clocks = Vec::with_capacity(found.setups.len());
        for setup in found.setups {
            let bond = hex::encode(setup.bond_edge.to_bytes());
            // A close capability binds the provider half, and this
            // process holds the provider's key. A client journal beside
            // this node's own is another party's, and this runner has
            // nothing to sign for it.
            if setup.role != Role::Provider {
                warn!(
                    bond,
                    "a setup journal under the work root is not this node's half"
                );
                continue;
            }
            let store = match SetupStore::open(
                &config.journal_root,
                config.network,
                setup.bond_edge,
                setup.role,
                &settlement_verifier,
            ) {
                Ok(store) => store,
                Err(error) => {
                    warn!(bond, %error, "a discovered setup journal did not open");
                    continue;
                }
            };
            let driven = match config.admission.clone() {
                Some(admission) => {
                    let policy = match &admission {
                        PaymentAdmission::Admits(policy) => Some(policy.as_ref().clone()),
                        PaymentAdmission::Proposes(_) => None,
                    };
                    let service = SetupService::new(SetupEndpoint::new(
                        store,
                        config.settlement_key.clone(),
                        admission,
                    ));
                    if setup_is_unambiguous {
                        if setup_mount.mount(setup.bond_edge, &service) {
                            info!(
                                bond,
                                "this node now answers WorkSetup from its driven setup"
                            );
                        } else {
                            warn!(bond, "the unambiguous provider setup could not be mounted");
                        }
                    }
                    Driven::Setup { service, policy }
                }
                None => Driven::Recovery(Box::new(store)),
            };
            clocks.push(SetupClock {
                bond_edge: setup.bond_edge,
                driven,
            });
        }
        Ok(Self {
            clocks,
            signer: config.settlement_key,
            work_mount,
            setup_mount,
            poll: config.poll,
            validators: config.validators,
            consensus_verifier,
        })
    }

    /// Takes one step of every journal, and says whether the chain
    /// answered all of them.
    async fn tick(&mut self, source: &S) -> bool {
        let mut answered = true;
        for clock in &mut self.clocks {
            answered &= clock
                .tick(source, &self.signer, &self.work_mount, &self.setup_mount)
                .await;
        }
        answered
    }

    /// The loop, over whatever chain `dial` produces.
    ///
    /// One tick of every journal per period, and a chain that stopped
    /// answering is dialled again rather than asked forever. The whole
    /// of the cadence is here, and none of the decisions are.
    async fn run_over<D, F>(mut self, mut stop: oneshot::Receiver<()>, dial: D)
    where
        D: Fn() -> F,
        F: core::future::Future<Output = Option<S>>,
    {
        if self.clocks.is_empty() {
            info!("no provider setup journal under the work root; the clock has nothing to drive");
            self.work_mount.clear_all();
            self.setup_mount.clear_all();
            return;
        }
        let mut chain = None;
        loop {
            tokio::select! {
                _ = &mut stop => break,
                () = tokio::time::sleep(self.poll) => {}
            }
            let Some(source) = chain.take() else {
                chain = dial().await;
                continue;
            };
            if self.tick(&source).await {
                chain = Some(source);
            }
        }
        self.work_mount.clear_all();
        self.setup_mount.clear_all();
        info!("the paid-work clock stopped, and its journals are closed");
    }
}

impl WorkRunner<ProductionWorkSource> {
    /// Ticks until told to stop, over the validators the configuration
    /// names.
    async fn run(self, stop: oneshot::Receiver<()>) {
        let validators = self.validators.clone();
        let verifier = self.consensus_verifier.clone();
        self.run_over(stop, move || {
            let validators = validators.clone();
            let verifier = verifier.clone();
            async move { connect_chain(&validators, verifier).await }
        })
        .await;
    }
}

/// Dials the configured validators in order and reads and submits
/// through the first that answers.
///
/// One endpoint for both directions. §1's concurrent fan-out to all six
/// is a submission strategy with an outcome rule, and neither exists in
/// this tree yet; inventing one here would be the runner deciding what
/// a submission means.
async fn connect_chain(
    validators: &[String],
    verifier: ConsensusVerifier,
) -> Option<ProductionWorkSource> {
    for url in validators {
        match VerifiedRemoteLightClient::connect(url.clone(), verifier.clone()).await {
            Ok(client) => {
                info!(validator = %url, "the paid-work clock reads and submits here");
                return Some(WorkBlocks::new(client));
            }
            Err(error) => warn!(validator = %url, %error, "a configured validator did not answer"),
        }
    }
    None
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
    use std::collections::BTreeSet;
    use std::path::Path;

    use hellas_chain::{LatestBlock, QueryError, WorkChannelQuery, WorkChannelSnapshot};
    use hellas_kernel::{
        Auth, BlockHeight, BufferWriter, CoinId, Decode as _, Edge, EdgeValues, Encode as _, Fees,
        Funding, LeaseSlots, List, MAX_EDGE_OUTPUTS, MAX_PARTY_INPUTS, MIN_OMIT_RESPONSE_BLOCKS,
        Move, Parties, Party, Payout, PendingPaymentClose, Proof, RegistryChunk, RegistryNamespace,
        RegistryRecordTag, StartId, Terms, Tx, WorkPaymentSettlement, WorkPaymentTerms,
        WorkStakeBondTerms, Writer as _,
    };
    use hellas_rpc::call::WithTrailer;
    use hellas_rpc::evaluate::{
        EvaluateOutputTranscriptBuilder, EvaluateStopReason, EvaluateTerminal, EvaluateUsage,
        input_commitment,
    };
    use hellas_rpc::protocol::artifacts::{
        BoundTermId, InputAddressed as _, OutputAddressed as _, PreparedPaidInputV1, SourceRef,
        TextArtifact, TextExecution, TextPolicy, TokenIds,
    };
    use hellas_rpc::protocol::mount::{MountBudget, MountFloor};
    use hellas_rpc::protocol::work::{
        JobDeadlines, PaidChannelPolicyV1, PaidExecutionPolicyV1, PaidJobAuthorizationV1,
        encode_transcript, next_payment, payment_binding_digest, private_policy_commitment,
        propose_authorization, result_digest, signing_hash, terminal_result, work_id,
    };
    use hellas_rpc::protocol::work_bundle::WorkChannelSetupBundleV1;
    use hellas_rpc::protocol::work_setup::{OmissionMeasurements, ProviderChannelPolicy};
    use hellas_rpc::protocol::{ContentId, Digest};
    use hellas_rpc::work::WorkRefusal;
    use hellas_rpc::work_close::{BlockSourceError, FinalizedWork};
    use hellas_rpc::work_open::{FinalizedSetup, SetupQuery};
    use hellas_rpc::work_store::{
        ChannelRecord, SetupEnd, SetupOrigin, SetupRecord, TerminalOutcome,
    };
    use hellas_rpc::{
        Assurance, EvaluateProgramManifest, EvaluateRequest, OutputEventEnvelope,
        ProducerSigningKey, ProgramManifest, PublicKey, SubmitTxOutcome,
    };
    use tokio::sync::Semaphore;

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

    // ── The clock's fixture ───────────────────────────────────────────
    //
    // Real journals under a real root, replayed by their own stores, and
    // a chain a test writes down. Nothing here is a double for a journal
    // or for the kernel: what is stood in for is consensus, which is one
    // finalized read and one sink that keeps what it was handed.

    const SALT: [u8; 32] = [0x5a; 32];
    const OMISSION_BOND: u64 = 4;
    const PAYMENT_VALUE: u64 = 1_000;
    const PAYMENT_RESERVE: u64 = 200;
    /// The finalized block this channel's payment Open landed in, and so
    /// the cursor every mount of it starts at.
    const ORIGIN: u64 = 44;
    /// Height at which the fixture contest's response window shuts. Above
    /// the origin, which is what makes the answer below a timely one.
    const RESPONSE_DEADLINE: u64 = 60;
    /// The immutable history floor both journals are armed at.
    const FLOOR: u64 = 7;

    fn network() -> NetworkId {
        let Some(network) = NetworkId::new("hellas-devnet") else {
            panic!("a short ascii id is a network id");
        };
        network
    }

    /// A threshold identity consensus accepts: the compressed BLS12-381 G1
    /// generator used by the configuration loader's fixture too.
    fn threshold_identity() -> Vec<u8> {
        vec![
            0x97, 0xf1, 0xd3, 0xa7, 0x31, 0x97, 0xd7, 0x94, 0x26, 0x95, 0x63, 0x8c, 0x4f, 0xa9,
            0xac, 0x0f, 0xc3, 0x68, 0x8c, 0x4f, 0x97, 0x74, 0xb9, 0x05, 0xa1, 0x4e, 0x3a, 0x3f,
            0x17, 0x1b, 0xac, 0x58, 0x6c, 0x55, 0xe8, 0x3f, 0xf9, 0x7a, 0x1a, 0xef, 0xfb, 0x3a,
            0xf0, 0x0a, 0xdb, 0x22, 0xc6, 0xbb,
        ]
    }

    fn signer(byte: u8) -> Secp256k1Signer {
        let Ok(signer) = Secp256k1Signer::from_secret_scalar([byte; 32]) else {
            panic!("a fixed scalar is a key");
        };
        signer
    }

    fn client() -> Secp256k1Signer {
        signer(0x21)
    }

    fn provider() -> Secp256k1Signer {
        signer(0x22)
    }

    /// The provider's RPC producer identity: the same scalar its channel
    /// party key is.
    fn provider_producer() -> ProducerSigningKey {
        let Ok(key) = ProducerSigningKey::from_secret_bytes([0x22; 32]) else {
            panic!("a fixed scalar is a producer key");
        };
        key
    }

    fn temp() -> tempfile::TempDir {
        match tempfile::tempdir() {
            Ok(dir) => dir,
            Err(error) => panic!("a temporary directory: {error}"),
        }
    }

    fn coins(ids: &[u8]) -> List<CoinId, MAX_PARTY_INPUTS> {
        let mut slots = [CoinId::from_bytes([0; CoinId::LENGTH]); MAX_PARTY_INPUTS];
        for (slot, id) in slots.iter_mut().zip(ids) {
            *slot = CoinId::from_bytes([*id; CoinId::LENGTH]);
        }
        List::take(slots, ids.len())
    }

    fn bond_terms() -> WorkStakeBondTerms {
        WorkStakeBondTerms {
            parties: Parties::new(provider().party_key(), client().party_key()),
            timeout: BlockHeight::new(500),
            timeout_outputs: List::take(
                [Payout::new(provider().party_key(), 64); MAX_EDGE_OUTPUTS],
                1,
            ),
            max_job_price: 40,
        }
    }

    fn bond_funding() -> Funding {
        Funding::new(coins(&[0xa1]), coins(&[]))
    }

    fn payment_funding() -> Funding {
        Funding::new(coins(&[0xb1]), coins(&[]))
    }

    fn channel_policy() -> PaidChannelPolicyV1 {
        PaidChannelPolicyV1 {
            compute_credit_limit: 40,
            delivery_credit_limit: 40,
        }
    }

    fn execution_policy() -> PaidExecutionPolicyV1 {
        PaidExecutionPolicyV1 {
            allowed_environment: manifest().content_id(),
            generation_policy_digest: Digest::from_bytes([0x32; 32]),
            identity_source_digest: Digest::from_bytes([0x33; 32]),
            max_prompt_tokens: 512,
            max_new_tokens: 128,
            max_stop_token_ids: 4,
            max_spool_bytes: 1_048_576,
            max_encoded_result_frame: 262_144,
            max_encoded_quote_response: 1_048_576,
            dispatch_margin_blocks: 4,
            delivery_margin_blocks: 2,
            oracle_grace_blocks: 6,
            fixed_price: 10,
        }
    }

    fn payment_terms() -> WorkPaymentTerms {
        WorkPaymentTerms {
            bond_edge: bond_edge(),
            bond_terms: bond_terms(),
            private_policy_commitment: private_policy_commitment(
                network(),
                &SALT,
                &channel_policy(),
            ),
            omit_response_blocks: MIN_OMIT_RESPONSE_BLOCKS,
            start_validity_blocks: 8,
            omission_bond: OMISSION_BOND,
        }
    }

    /// The policy a measured artifact would make, built here directly.
    ///
    /// Which of §4's evidence cases produces which admission is
    /// `work_config`'s to decide and its tests' to check; what the runner
    /// is handed is one of the three values below, and this is them.
    /// The floor these fixtures run under: a budget in which no wait
    /// takes any time, so §4's `S` and `R` are zero, its response-window
    /// floor is the kernel's own `MIN_OMIT_RESPONSE_BLOCKS`, and `T` is
    /// four. What each test below observes is therefore its own gate and
    /// never this one.
    fn floor() -> MountFloor {
        let instant = MountBudget {
            fsync_tail_ms: 0,
            rotation_tail_ms: 0,
            response_build_ms: 0,
            one_block_fetch_ms: 0,
            fresh_tip_ms: 0,
            close_prepared_fsync_ms: 0,
            rpc_ms: 0,
            response_worker_ms: 0,
            general_worker_ms: 0,
            validation_ms: 0,
            restart_replay_ms_at_cap: 0,
            restart_downtime_ms: 0,
            lower_tail_block_ms: 1,
            general_inclusion_blocks: 0,
        };
        match instant.floor() {
            Ok(floor) => floor,
            Err(error) => panic!("a one-millisecond block prices every wait: {error}"),
        }
    }

    fn provider_policy() -> ProviderChannelPolicy {
        ProviderChannelPolicy {
            network: network(),
            policy_salt: SALT,
            channel_policy: channel_policy(),
            execution_policy: execution_policy(),
            expected_payment_values: EdgeValues::new(PAYMENT_VALUE, PAYMENT_RESERVE, Fees::ZERO),
            omission: OmissionMeasurements {
                response_probability: 999_000,
                response_blocks: MIN_OMIT_RESPONSE_BLOCKS,
                response_cost_cap: 1,
            },
            floor: floor(),
        }
    }

    fn admits() -> PaymentAdmission {
        PaymentAdmission::Admits(Box::new(provider_policy()))
    }

    fn proposes() -> PaymentAdmission {
        PaymentAdmission::Proposes(Box::new(provider_policy()))
    }

    // ── The handshake this journal retains ────────────────────────────

    fn proposed() -> WorkChannelSetupBundleV1 {
        let hash = Tx::open_hash(
            network(),
            &bond_funding(),
            &Terms::work_stake_bond(bond_terms()),
        );
        match WorkChannelSetupBundleV1::propose_bond(
            network(),
            bond_funding(),
            bond_terms(),
            Auth::native(provider().sign(hash)),
        ) {
            Ok(bundle) => bundle,
            Err(error) => panic!("the fixture bond proposes: {error}"),
        }
    }

    fn countersigned(bundle: WorkChannelSetupBundleV1) -> WorkChannelSetupBundleV1 {
        let bond_hash = bundle.bond_open_hash();
        let payment_hash = Tx::open_hash(
            network(),
            &payment_funding(),
            &Terms::work_payment(payment_terms()),
        );
        match bundle.countersign_bond_and_propose_payment(
            Auth::native(client().sign(bond_hash)),
            payment_funding(),
            payment_terms(),
            Auth::native(client().sign(payment_hash)),
        ) {
            Ok(bundle) => bundle,
            Err(error) => panic!("the fixture payment proposes: {error}"),
        }
    }

    fn completed(bundle: WorkChannelSetupBundleV1) -> WorkChannelSetupBundleV1 {
        let Some(hash) = bundle.payment_open_hash() else {
            panic!("a proposed payment has an open hash");
        };
        match bundle.countersign_payment(Auth::native(provider().sign(hash))) {
            Ok(bundle) => bundle,
            Err(error) => panic!("the fixture payment countersigns: {error}"),
        }
    }

    fn bond_edge() -> EdgeId {
        Tx::edge_id_of(&bond_funding(), &Terms::work_stake_bond(bond_terms()))
    }

    fn payment_edge() -> EdgeId {
        Tx::edge_id_of(&payment_funding(), &Terms::work_payment(payment_terms()))
    }

    /// The channel the retained descriptor names, which is the one the
    /// runner's mount must open.
    fn descriptor() -> hellas_rpc::protocol::work_setup::CloseDescriptor {
        match provider_policy().describe_close(payment_edge(), payment_terms()) {
            Ok(descriptor) => descriptor,
            Err(error) => panic!("the fixture close descriptor opens: {error}"),
        }
    }

    fn settlement() -> WorkPaymentSettlement {
        match descriptor().expected_settlement() {
            Ok(settlement) => settlement,
            Err(error) => panic!("the fixture edge prices both exits: {error}"),
        }
    }

    /// The payload digest of the synthetic block at `height`.
    fn payload_at(height: u64) -> [u8; 32] {
        let mut payload = [0xc0; 32];
        for (slot, byte) in payload.iter_mut().zip(height.to_be_bytes()) {
            *slot = byte;
        }
        payload
    }

    fn origin() -> SetupOrigin {
        SetupOrigin {
            payment_edge: payment_edge(),
            height: ORIGIN,
            payload: payload_at(ORIGIN),
            parent: payload_at(ORIGIN - 1),
        }
    }

    /// A provider's setup journal, complete and recording where its
    /// channel begins — which is exactly what a restarting node finds.
    fn write_setup_journal(root: &Path) {
        let verifier = Secp256k1Verifier::new();
        let mut store =
            match SetupStore::open(root, network(), bond_edge(), Role::Provider, &verifier) {
                Ok(store) => store,
                Err(error) => panic!("the fixture setup journal opens: {error}"),
            };
        let one = proposed();
        let two = countersigned(one.clone());
        let three = completed(two.clone());
        let Some(terms) = three.payment_terms().cloned() else {
            panic!("a countersigned payment has terms");
        };
        let Some(edge) = three.payment_edge() else {
            panic!("a countersigned payment has an edge");
        };
        let close_descriptor = match provider_policy().describe_close(edge, terms) {
            Ok(descriptor) => descriptor,
            Err(error) => panic!("the fixture close descriptor opens: {error}"),
        };
        for record in [
            SetupRecord::ScanArmed {
                height: FLOOR,
                payload: payload_at(FLOOR),
            },
            SetupRecord::Bundle {
                bundle: one.encode(),
            },
            SetupRecord::Bundle {
                bundle: two.encode(),
            },
            SetupRecord::ArmedBundle {
                bundle: three.encode(),
                close_descriptor: Box::new(close_descriptor),
            },
            SetupRecord::Complete {
                payment_edge: edge,
                origin_height: ORIGIN,
                origin_payload: payload_at(ORIGIN),
                origin_parent: payload_at(ORIGIN - 1),
            },
        ] {
            if let Err(error) = store.commit(record, &verifier) {
                panic!("the fixture setup record commits: {error}");
            }
        }
    }

    /// Reopens the channel journal the mount opens, under exactly the
    /// channel, settlement, role and origin the descriptor fixes.
    fn open_channel(root: &Path) -> ChannelStore {
        match ChannelStore::open(
            root,
            descriptor().channel().clone(),
            settlement(),
            Role::Provider,
            origin(),
            &Secp256k1Verifier::new(),
        ) {
            Ok(store) => store,
            Err(error) => panic!("the fixture channel journal opens: {error}"),
        }
    }

    // ── One job, paid for, and then contested ─────────────────────────

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

    fn evaluate_request() -> EvaluateRequest {
        EvaluateRequest {
            text_execution: text_execution().input_id().digest(),
            runner_public_key: PublicKey::Secp256k1(client().party_key().to_bytes()),
            execution_environment: manifest().content_id(),
            nonce: [0x9e; 32],
            assurance: Assurance::ProducerSigned,
            retain: true,
        }
    }

    fn bundle() -> PreparedPaidInputV1 {
        PreparedPaidInputV1::new(
            &evaluate_request(),
            &manifest(),
            &text_execution(),
            &prompt_tokens(),
            &text_policy(),
            &identity_artifact(),
        )
    }

    fn deadlines() -> JobDeadlines {
        JobDeadlines {
            acceptance: 50,
            terminal: 100,
            payment: 200,
        }
    }

    fn authorization() -> PaidJobAuthorizationV1 {
        match propose_authorization(
            descriptor().channel(),
            &execution_policy(),
            &bundle(),
            1,
            deadlines(),
        ) {
            Ok(authorization) => authorization,
            Err(error) => panic!("the fixture authorization builds: {error}"),
        }
    }

    /// One complete signed transcript for the fixture request.
    fn answer_transcript() -> Vec<OutputEventEnvelope> {
        let request = evaluate_request();
        let producer = provider_producer();
        let mut builder = EvaluateOutputTranscriptBuilder::new(
            input_commitment(&request),
            request.assurance,
            &producer,
        );
        let answer = vec![101_u32, 102, 103, 104, 105];
        if let Err(error) = builder.push_token_delta(answer.clone()) {
            panic!("a non-empty delta pushes: {error}");
        }
        let usage = EvaluateUsage {
            input_units: 4,
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

    fn commit(store: &mut ChannelStore, record: ChannelRecord) {
        if let Err(error) = store.commit(record, &Secp256k1Verifier::new()) {
            panic!("the fixture channel record commits: {error}");
        }
    }

    /// The channel journal a restarted provider finds: one job it
    /// delivered and holds a signed certificate for, and a finalized
    /// contest opened below that certificate.
    ///
    /// It is written and closed here, so the runner opens it exactly as
    /// a restart does — through the mount the setup driver hands back.
    fn write_contested_channel(root: &Path) -> StartId {
        let channel = descriptor().channel().clone();
        let mut store = open_channel(root);
        let job = authorization();
        let id = work_id(&channel, &job);
        commit(
            &mut store,
            ChannelRecord::JobProposed {
                authorization: job,
                client_signature: client().sign(signing_hash(id)),
                prepared_input: match bundle().encode() {
                    Ok(bytes) => bytes,
                    Err(error) => panic!("the fixture bundle encodes: {error}"),
                },
            },
        );
        commit(
            &mut store,
            ChannelRecord::JobAccepted {
                provider_signature: provider().sign(signing_hash(id)),
            },
        );
        commit(&mut store, ChannelRecord::JobRunning);
        let transcript = answer_transcript();
        let result = match terminal_result(&channel, &job, &transcript) {
            Ok(result) => result,
            Err(error) => panic!("the fixture result derives: {error}"),
        };
        commit(
            &mut store,
            ChannelRecord::JobResult {
                result,
                provider_signature: provider().sign(signing_hash(result_digest(&channel, &result))),
                transcript: match encode_transcript(&transcript) {
                    Ok(bytes) => bytes,
                    Err(error) => panic!("the fixture transcript encodes: {error}"),
                },
            },
        );
        commit(&mut store, ChannelRecord::PlaintextReleased);
        let (certificate, binding) = match next_payment(&channel, &job, &result, 0, settlement()) {
            Ok(paid) => paid,
            Err(error) => panic!("the fixture payment builds: {error}"),
        };
        commit(
            &mut store,
            ChannelRecord::JobTerminated {
                outcome: TerminalOutcome::Certified {
                    certificate,
                    binding,
                    binding_signature: client()
                        .sign(signing_hash(payment_binding_digest(&channel, &binding))),
                    certificate_signature: client().sign(certificate.digest(network())),
                },
            },
        );
        let start_id = StartId::from_bytes([0x7c; 32]);
        commit(
            &mut store,
            ChannelRecord::CloseOpened {
                start_id,
                opener: Party::Maker,
                response_deadline: RESPONSE_DEADLINE,
                claimed: 0,
            },
        );
        start_id
    }

    /// The coherent finalized view the clock asks this fixture chain for.
    fn channel_snapshot(
        height: u64,
        bond: Option<Edge>,
        pending: Option<RegistryChunk>,
    ) -> WorkChannelSnapshot {
        WorkChannelSnapshot::new(
            WorkChannelQuery {
                bond_edge: bond_edge(),
                payment_edge: payment_edge(),
                funding: BTreeSet::new(),
            },
            LatestBlock {
                height,
                payload: hellas_chain::domain::Digest::from(payload_at(height)),
                state_root: hellas_chain::domain::Digest::from([0xd0; 32]),
                finalization: Vec::new(),
            },
            bond,
            None,
            [None, None],
            pending,
            BTreeSet::new(),
        )
    }

    /// Canonical pending-close bytes for the fixture contest.
    ///
    /// Written field by field because the kernel deliberately exposes the
    /// consensus record for reading, not for callers to manufacture. The
    /// decode at the end proves this literal is its canonical shape.
    fn pending_contest(responded: bool) -> RegistryChunk {
        let mut value = Vec::with_capacity(PendingPaymentClose::ENCODED_SIZE);
        value.extend_from_slice(&[1, 23, 2]); // envelope and work-close version
        value.extend_from_slice(payment_edge().as_bytes());
        value.push(Party::Maker.tag());
        value.extend_from_slice(&[0x7c; StartId::LENGTH]);
        value.extend_from_slice(&RESPONSE_DEADLINE.to_be_bytes());
        value.extend_from_slice(&0_u64.to_be_bytes());
        let final_cumulative = if responded {
            execution_policy().fixed_price
        } else {
            0
        };
        value.extend_from_slice(&final_cumulative.to_be_bytes());
        value.push(u8::from(responded));
        value.push(u8::from(responded));
        value.extend_from_slice(&OMISSION_BOND.to_be_bytes());
        assert_eq!(value.len(), PendingPaymentClose::ENCODED_SIZE);
        let record = match PendingPaymentClose::decode_exact(&value) {
            Ok(record) => record,
            Err(error) => panic!("the fixture pending-close bytes decode: {error:?}"),
        };
        assert_eq!(record.responded(), responded);
        match RegistryChunk::split(
            RegistryNamespace::PaymentClose,
            RegistryRecordTag::PaymentPending,
            &value,
            0,
        ) {
            Some(chunk) => chunk,
            None => panic!("one pending close fits one registry chunk"),
        }
    }

    /// One readable live edge under the fixture bond's committed terms.
    fn live_bond() -> Edge {
        let terms = Terms::work_stake_bond(bond_terms());
        let mut encoded = vec![0_u8; Edge::MAX_ENCODED_SIZE];
        let written = {
            let mut writer = BufferWriter::new(&mut encoded);
            writer.write(&[1, 5]); // canonical Edge envelope
            64_u64.encode_to(&mut writer);
            0_u64.encode_to(&mut writer);
            Fees::ZERO.encode_to(&mut writer);
            terms.timeout().encode_to(&mut writer);
            terms.parties().encode_to(&mut writer);
            terms.hash().encode_to(&mut writer);
            terms.allowed_closes().encode_to(&mut writer);
            writer.position()
        };
        match Edge::decode_exact(&encoded[..written]) {
            Ok(edge) => edge,
            Err(error) => panic!("the fixture live bond decodes: {error:?}"),
        }
    }

    // ── The chain a test writes down ──────────────────────────────────

    /// One coherent finalized read, a tip that never moves, and a sink
    /// that keeps what it was handed.
    #[derive(Clone)]
    struct TestChain(Arc<ChainState>);

    struct ChainState {
        /// Everything a driver submitted, in the order it did.
        submitted: Mutex<Vec<Tx>>,
        /// The one coherent finalized channel read this chain answers with.
        snapshot: Mutex<WorkChannelSnapshot>,
        /// One permit added as `latest_height` is entered.
        entered: Semaphore,
        /// One permit the test adds to let `latest_height` out again.
        release: Semaphore,
        /// Whether `latest_height` waits at all.
        slow: bool,
    }

    impl TestChain {
        fn new() -> Self {
            Self::with(false)
        }

        /// A chain whose block read blocks until the test releases it.
        fn slow() -> Self {
            Self::with(true)
        }

        fn with(slow: bool) -> Self {
            Self(Arc::new(ChainState {
                submitted: Mutex::new(Vec::new()),
                snapshot: Mutex::new(channel_snapshot(ORIGIN, None, None)),
                entered: Semaphore::new(0),
                release: Semaphore::new(0),
                slow,
            }))
        }

        fn submitted(&self) -> Vec<Tx> {
            match self.0.submitted.lock() {
                Ok(held) => held.clone(),
                Err(error) => panic!("the fixture sink is reachable: {error}"),
            }
        }

        fn set_snapshot(&self, snapshot: WorkChannelSnapshot) {
            match self.0.snapshot.lock() {
                Ok(mut held) => *held = snapshot,
                Err(error) => panic!("the fixture snapshot is reachable: {error}"),
            }
        }

        /// Waits until a caller is inside the block read.
        async fn wait_for_read(&self) {
            match self.0.entered.acquire().await {
                Ok(permit) => permit.forget(),
                Err(error) => panic!("the fixture chain is open: {error}"),
            }
        }

        fn release(&self) {
            self.0.release.add_permits(1);
        }
    }

    impl SetupView for TestChain {
        async fn finalized_setup(
            &self,
            _query: SetupQuery,
        ) -> Result<Option<FinalizedSetup>, BlockSourceError> {
            // Both edges consumed and no funding left live. A completed
            // setup reads its edge only to price the settlement, and an
            // absent one is what makes the mount fall back to the
            // descriptor's expectation — the same one this fixture's
            // journal was written under.
            Ok(Some(FinalizedSetup {
                height: ORIGIN,
                bond: None,
                payment: None,
                lease: LeaseSlots::Absent,
                live_funding: BTreeSet::new(),
            }))
        }
    }

    impl FinalizedWorkView for TestChain {
        async fn work_channel_snapshot(
            &self,
            query: WorkChannelQuery,
        ) -> Result<Option<WorkChannelSnapshot>, QueryError> {
            let snapshot = match self.0.snapshot.lock() {
                Ok(held) => held.clone(),
                Err(error) => {
                    return Err(QueryError::StateUnavailable(format!(
                        "the fixture snapshot lock failed: {error}",
                    )));
                }
            };
            if snapshot.query() != &query {
                return Err(QueryError::StateUnavailable(
                    "the fixture was asked for another work channel".to_string(),
                ));
            }
            Ok(Some(snapshot))
        }
    }

    impl FinalizedBlocks for TestChain {
        async fn latest_height(&self) -> Result<Option<u64>, BlockSourceError> {
            if self.0.slow {
                self.0.entered.add_permits(1);
                match self.0.release.acquire().await {
                    Ok(permit) => permit.forget(),
                    Err(error) => panic!("the fixture chain is open: {error}"),
                }
            }
            Ok(Some(ORIGIN))
        }

        async fn block_at(&self, _height: u64) -> Result<Option<FinalizedWork>, BlockSourceError> {
            Ok(None)
        }
    }

    impl TxSink for TestChain {
        async fn submit(&self, tx: Tx) -> Result<SubmitTxOutcome, BlockSourceError> {
            match self.0.submitted.lock() {
                Ok(mut held) => held.push(tx),
                Err(error) => panic!("the fixture sink is reachable: {error}"),
            }
            Ok(SubmitTxOutcome::Enqueued)
        }
    }

    /// The runner a node starts with: the configured root, the stored
    /// identity, and whichever of §4's three admissions this node's
    /// evidence produced.
    fn runner(
        root: &Path,
        admission: Option<PaymentAdmission>,
        mount: &MountedWork<TestChain>,
    ) -> WorkRunner<TestChain> {
        match WorkRunner::discover(
            WorkRunnerConfig {
                network: network(),
                threshold_identity: threshold_identity(),
                journal_root: root.to_path_buf(),
                validators: Vec::new(),
                poll: Duration::from_millis(1),
                settlement_key: provider(),
                admission,
            },
            mount.clone(),
            MountedSetup::default(),
        ) {
            Ok(runner) => runner,
            Err(error) => panic!("the configured root enumerates: {error}"),
        }
    }

    /// The one contest this fixture's sink was handed an answer to.
    fn responded(chain: &TestChain) -> StartId {
        let submitted = chain.submitted();
        let [
            Tx::Move {
                action: Move::RespondPaymentClose(response),
            },
        ] = submitted.as_slice()
        else {
            panic!("the clock submits exactly one contest answer: {submitted:?}");
        };
        response.start_id()
    }

    fn adjudicated_payment_closes(chain: &TestChain) -> usize {
        chain
            .submitted()
            .iter()
            .filter(|tx| {
                matches!(
                    tx,
                    Tx::Close {
                        input,
                        proof: Proof::Adjudicated { .. },
                        ..
                    } if *input == payment_edge()
                )
            })
            .count()
    }

    /// A restart with an open contest is answered by the clock, before
    /// the deadline, without a single library call from this file.
    ///
    /// Nothing in the runner names a contest, builds a response, or reads
    /// a deadline: the journal on the disk holds the contest and the
    /// certificate, and one tick is the whole of what this file adds.
    #[tokio::test]
    async fn a_restart_with_an_open_contest_is_answered_on_the_clock() {
        let dir = temp();
        write_setup_journal(dir.path());
        let start_id = write_contested_channel(dir.path());
        let mount = MountedWork::default();
        let mut runner = runner(dir.path(), Some(admits()), &mount);
        let chain = TestChain::new();

        assert!(
            mount.service().is_none(),
            "nothing is mounted before the first tick",
        );
        assert!(chain.submitted().is_empty(), "and nothing is submitted");

        assert!(runner.tick(&chain).await, "the fixture chain answers");

        assert_eq!(responded(&chain), start_id);
        let Some(service) = mount.service() else {
            panic!("the tick that answered the contest mounted its channel")
        };
        let cursor = match service.with_state(|state| state.cursor().0) {
            Ok(cursor) => cursor,
            Err(error) => panic!("the mounted channel is readable: {error}"),
        };
        assert!(
            cursor < RESPONSE_DEADLINE,
            "the answer was submitted at {cursor}, past the deadline {RESPONSE_DEADLINE}",
        );
        let responded = match service.with_state(|state| state.close_responded()) {
            Ok(responded) => responded,
            Err(error) => panic!("the mounted channel is readable: {error}"),
        };
        assert_eq!(
            responded.map(|contest| contest.start_id),
            Some(start_id),
            "the answer is on the disk before it reaches a sink",
        );
    }

    #[tokio::test]
    async fn the_paid_work_clock_submits_adjudication_when_consensus_makes_it_due_and_not_before() {
        let dir = temp();
        write_setup_journal(dir.path());
        let start_id = write_contested_channel(dir.path());
        let mount = MountedWork::default();
        let mut runner = runner(dir.path(), Some(admits()), &mount);
        let chain = TestChain::new();
        chain.set_snapshot(channel_snapshot(ORIGIN, None, Some(pending_contest(false))));

        assert!(runner.tick(&chain).await, "the first coherent read answers");
        assert_eq!(
            adjudicated_payment_closes(&chain),
            0,
            "an unresponded contest below its deadline is not final",
        );
        let Some(service) = mount.service() else {
            panic!("the first tick mounts the contested channel")
        };
        assert_eq!(
            service
                .with_state(|state| state.close_responded().map(|held| held.start_id))
                .unwrap_or_else(|error| panic!("the mounted channel is readable: {error}")),
            Some(start_id),
            "the response is chosen and fsynced locally",
        );

        assert!(
            runner.tick(&chain).await,
            "the second coherent read answers"
        );
        assert_eq!(
            adjudicated_payment_closes(&chain),
            0,
            "a local CloseResponded is not consensus response evidence",
        );

        chain.set_snapshot(channel_snapshot(ORIGIN, None, Some(pending_contest(true))));
        assert!(runner.tick(&chain).await, "the responded read answers");
        assert_eq!(
            adjudicated_payment_closes(&chain),
            1,
            "consensus response makes exactly one adjudicated payment close due",
        );
    }

    #[tokio::test]
    async fn the_paid_work_clock_returns_the_completed_bond_at_its_horizon() {
        let dir = temp();
        write_setup_journal(dir.path());
        let mount = MountedWork::default();
        let mut runner = runner(dir.path(), Some(admits()), &mount);
        let chain = TestChain::new();
        chain.set_snapshot(channel_snapshot(
            bond_terms().timeout.get(),
            Some(live_bond()),
            None,
        ));

        assert!(runner.tick(&chain).await, "the horizon read answers");
        let submitted = chain.submitted();
        let timeouts = submitted
            .iter()
            .filter(|tx| {
                matches!(
                    tx,
                    Tx::Close {
                        input,
                        proof: Proof::Timeout { .. },
                        ..
                    } if *input == bond_edge()
                )
            })
            .count();
        assert_eq!(
            timeouts, 1,
            "the live completed bond is returned by one deterministic timeout",
        );
        assert_eq!(submitted.len(), 1, "no other transaction is submitted");
    }

    /// §4's rule, driven: evidence that is `assumed` or absent turns
    /// admission off and leaves every contest answered.
    ///
    /// The two cases are the two admissions `payment_admission` returns
    /// for them — `Proposes`, which countersigns nothing, and `None`,
    /// which is no setup endpoint at all. Both still reach the mount and
    /// both still answer, and neither admits a job.
    #[tokio::test]
    async fn unmeasured_evidence_answers_the_contest_and_admits_no_work() {
        for admission in [Some(proposes()), None] {
            let dir = temp();
            write_setup_journal(dir.path());
            let start_id = write_contested_channel(dir.path());
            let mount = MountedWork::default();
            let mut runner = runner(dir.path(), admission.clone(), &mount);
            let chain = TestChain::new();

            assert!(runner.tick(&chain).await, "the fixture chain answers");

            assert_eq!(
                responded(&chain),
                start_id,
                "unmeasured evidence still answers a contest: {admission:?}",
            );
            let Some(service) = mount.service() else {
                panic!("unmeasured evidence still mounts its channel: {admission:?}")
            };
            let Some(accept_work_response::Outcome::Refused(refusal)) =
                service.accept(&AcceptWorkRequest::default()).outcome
            else {
                panic!("a channel with no readiness decision refuses new work")
            };
            assert_eq!(
                refusal.code,
                WorkRefusalCode::NotReady as i32,
                "unmeasured evidence admits no new work: {admission:?}",
            );
        }
    }

    /// The runner mounts what it is handed, and `Work` answers from it.
    ///
    /// The discriminator is deliberately not the refusal code of
    /// `accept_work`, which a close-only mount also refuses as
    /// `NotReady`: it is `admit_certificate`, which the mounted service
    /// answers from its own channel's state and the unmounted one cannot
    /// answer at all.
    #[tokio::test]
    async fn the_clock_serves_work_from_the_channel_it_was_handed() {
        let dir = temp();
        write_setup_journal(dir.path());
        let mount = MountedWork::default();
        let mut runner = runner(dir.path(), Some(admits()), &mount);
        let chain = TestChain::new();

        let unmounted: WithTrailer<AdmitCertificateResponse> = UnmountedWork
            .admit_certificate(
                AdmitCertificateRequest::default(),
                TransportContext::default(),
            )
            .await
            .unwrap_or_else(|error| panic!("the unmounted handler answers: {error}"))
            .into();
        let Some(admit_certificate_response::Outcome::Refused(before)) = unmounted.response.outcome
        else {
            panic!("an unmounted Work refuses payment")
        };
        assert_eq!(before.code, WorkRefusalCode::NotReady as i32);

        assert!(runner.tick(&chain).await, "the fixture chain answers");

        let Some(service) = mount.service() else {
            panic!("the driver handed back a channel and the runner published it")
        };
        let edge = match service.with_state(|state| state.channel().payment_edge()) {
            Ok(edge) => edge,
            Err(error) => panic!("the mounted channel is readable: {error}"),
        };
        assert_eq!(
            edge,
            payment_edge(),
            "the mount is the channel the setup journal names",
        );
        let mounted: WithTrailer<AdmitCertificateResponse> = service
            .admit_certificate(
                AdmitCertificateRequest::default(),
                TransportContext::default(),
            )
            .await
            .unwrap_or_else(|error| panic!("the mounted handler answers: {error}"))
            .into();
        let Some(admit_certificate_response::Outcome::Refused(after)) = mounted.response.outcome
        else {
            panic!("a mounted Work refuses a payment naming no job of its own")
        };
        assert_ne!(
            after.code,
            WorkRefusalCode::NotReady as i32,
            "a mounted channel answers from its own state, not from `NotReady`: {}",
            after.reason,
        );

        // And the setup is not driven again, so no second journal is
        // opened on the file the first mount holds.
        let [clock] = runner.clocks.as_slice() else {
            panic!("one setup journal was written and one is driven")
        };
        assert!(matches!(clock.driven, Driven::Channel(_)));
        assert!(
            runner.tick(&chain).await,
            "a second tick drives the channel"
        );
        assert!(chain.submitted().is_empty(), "and it has nothing to submit");
    }

    /// A request is answered while the clock waits on a slow chain.
    ///
    /// The mutation this fails against is the one §5 names: a driver
    /// that held the endpoint across the source's wait. It would not
    /// compile in a spawned task if it held a `MutexGuard`, and it
    /// would deadlock here if it held anything else.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_clock_does_not_starve_the_request_path() {
        let dir = temp();
        write_setup_journal(dir.path());
        let mount = MountedWork::default();
        let mut runner = runner(dir.path(), Some(admits()), &mount);
        let chain = TestChain::slow();

        let ticking = {
            let chain = chain.clone();
            tokio::spawn(async move { runner.tick(&chain).await })
        };
        chain.wait_for_read().await;

        // The dispatch path's own two steps, both taken while the clock
        // is inside the chain read: resolve the handler for this ALPN,
        // and answer with it.
        let dispatch = mount.clone();
        let answered = tokio::time::timeout(
            Duration::from_secs(5),
            tokio::task::spawn_blocking(move || {
                dispatch
                    .service()
                    .map(|service| service.accept(&AcceptWorkRequest::default()))
            }),
        )
        .await;
        match answered {
            Ok(Ok(Some(_))) => {}
            Ok(Ok(None)) => panic!("the channel is mounted before the chain is read"),
            Ok(Err(error)) => panic!("the request path is reachable: {error}"),
            Err(_) => panic!("an inbound request waited on the clock's chain read"),
        }

        chain.release();
        if let Err(error) = ticking.await {
            panic!("the tick finishes once the chain answers: {error}");
        }
    }

    /// Told to stop, the clock stops between two steps and leaves both
    /// journals openable and replayable.
    #[tokio::test]
    async fn a_clean_shutdown_leaves_a_replayable_journal() {
        let dir = temp();
        write_setup_journal(dir.path());
        let start_id = write_contested_channel(dir.path());
        let mount = MountedWork::default();
        let runner = runner(dir.path(), Some(admits()), &mount);
        let chain = TestChain::new();
        let (stop, stopped) = oneshot::channel();
        let task = {
            let chain = chain.clone();
            tokio::spawn(async move {
                runner
                    .run_over(stopped, move || {
                        let chain = chain.clone();
                        async move { Some(chain) }
                    })
                    .await;
            })
        };

        // The loop is running and has answered the contest at least
        // once, so both journals are open and held.
        for _ in 0..2_000_u32 {
            if !chain.submitted().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        assert_eq!(responded(&chain), start_id, "the loop answered the contest");

        if stop.send(()).is_err() {
            panic!("the runner is still listening for its stop signal");
        }
        if let Err(error) = task.await {
            panic!("the runner stops when it is told to: {error}");
        }

        // A channel nobody advances is a channel this node no longer
        // answers from, and the files go with it.
        assert!(
            mount.service().is_none(),
            "a stopped clock serves no channel",
        );

        // Both files are released, and both replay to what the clock
        // left in them.
        let setup = match SetupStore::open(
            dir.path(),
            network(),
            bond_edge(),
            Role::Provider,
            &Secp256k1Verifier::new(),
        ) {
            Ok(store) => store,
            Err(error) => panic!("the setup journal reopens after a clean stop: {error}"),
        };
        assert_eq!(setup.state().end(), Some(SetupEnd::Complete));
        assert!(!setup.recovered_torn_tail(), "the setup journal is whole");

        let channel = open_channel(dir.path());
        assert!(
            !channel.recovered_torn_tail(),
            "the channel journal is whole"
        );
        assert_eq!(
            channel.state().close_responded().map(|held| held.start_id),
            Some(start_id),
            "the answer the clock fixed replays",
        );
    }
}
