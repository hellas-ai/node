//! Node server bootstrap.
//!
//! NOTE (hellas-wire v2 cutover): the body of `spawn_node` currently
//! returns `unimplemented!()`. The legacy implementation depended on
//! `tonic-iroh-transport::{TransportBuilder, swarm::{ServiceRegistry,
//! DhtBackend, MdnsBackend}}` plus the per-service `ManagedServer`
//! wrappers, none of which have been ported to `hellas-wire` /
//! `hellas-rpc` yet. The `NodeHandle` public surface and the
//! `spawn_node` signature are preserved so the binary still
//! type-checks. See `HELLAS_WIRE_CUTOVER_FINDINGS.md` finding #5.

use catgrad::prelude::Dtype;
use hellas_core::ProducerSigningKey;
use hellas_executor::ExecutorMetrics;
use hellas_rpc::policy::{DownloadPolicy, ExecutePolicy};
use iroh::EndpointId;
use std::path::PathBuf;
use std::sync::Arc;

pub(super) struct NodeHandle {
    node_id: EndpointId,
}

impl NodeHandle {
    pub(super) fn node_id(&self) -> EndpointId {
        self.node_id
    }

    /// Snapshot of iroh's internal metrics. The returned `EndpointMetrics`
    /// contains `Arc`s into the live metric storage, so values continue to
    /// update as iroh records them.
    #[cfg(feature = "otel")]
    pub(super) fn iroh_metrics(&self) -> iroh::metrics::EndpointMetrics {
        unimplemented!("iroh metrics pending discovery/pool port — see CUTOVER_FINDINGS.md")
    }

    pub(super) async fn shutdown(self) -> anyhow::Result<()> {
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn spawn_node(
    _port: Option<u16>,
    _download_policy: DownloadPolicy,
    _execute_policy: ExecutePolicy,
    _queue_size: usize,
    _preload_weights: Vec<String>,
    _build: String,
    _graffiti: Vec<u8>,
    _supported_dtypes: Vec<Dtype>,
    _artifact_store_path: PathBuf,
    _secret_key: iroh::SecretKey,
    _producer_key: ProducerSigningKey,
    _metrics: Arc<ExecutorMetrics>,
) -> anyhow::Result<NodeHandle> {
    unimplemented!(
        "node server pending hellas-wire discovery/pool port — see CUTOVER_FINDINGS.md"
    )
}
