#[macro_use]
extern crate tracing;

mod access;
mod anthropic;
mod backend;
mod dispatch;
mod execution;
mod fetch_backend;
mod metrics;
mod openai;
mod plain;
mod provenance_layer;
mod proxy;
mod responses;
mod state;
mod wrap;

use anyhow::{Context, bail};
use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use futures::Stream;
use hellas_rpc::{Dtype, ProducerSigningKey};
use iroh::{EndpointId, SecretKey};
use serde::Serialize;
use serde_json::{Map as JsonMap, Value as JsonValue, json};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use self::state::GatewayState;

pub use execution::{
    CliRuntime, ExecutionEvent, ExecutionRequest, ExecutionRequestOptions, ExecutionStrategy,
    Outcome, PreparedExecution, StopReason,
};

const DEFAULT_HTTP_PORT: u16 = 8080;

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

pub struct GatewayOptions {
    pub host: String,
    pub port: Option<u16>,
    pub node_id: Option<EndpointId>,
    pub node_addrs: Vec<SocketAddr>,
    #[cfg(feature = "evaluate")]
    pub local: bool,
    #[cfg(feature = "evaluate")]
    pub verify_local: bool,
    pub verify: Option<EndpointId>,
    #[cfg(feature = "evaluate")]
    pub queue_size: usize,
    pub retries: usize,
    pub default_max_tokens: u32,
    pub force_model: Option<String>,
    pub metrics_port: Option<u16>,
    pub dtype: Dtype,
    pub responses_backend: ResponsesBackend,
    pub responses_proxy_url: String,
    pub responses_proxy_api_key_env: String,
    pub responses_fetch_route_service: String,
    pub responses_fetch_route_method: String,
    pub responses_fetch_execution_environment: Option<hellas_rpc::ContentId>,
    pub responses_fetch_request_overrides: JsonMap<String, JsonValue>,
    pub trusted_producer_public_keys: Vec<hellas_rpc::PublicKey>,
    /// The out-of-band anchor every remote route is verified against.
    /// `None` is the absence of a *route*, never a route dialled without
    /// an anchor: each remote constructor takes an anchor by value, so a
    /// gateway given none has no remote route to run and says so.
    pub provider_trust: Option<hellas_client::ProviderTrustAnchor>,
    pub producer_key: ProducerSigningKey,
    #[cfg(feature = "evaluate")]
    pub provider_genesis: Vec<u8>,
    pub assurance: hellas_rpc::Assurance,
    pub secret_key: SecretKey,
    pub wrap: Option<String>,
    pub wrap_args: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResponsesBackend {
    Hellas,
    Proxy,
    Fetch,
}

pub async fn run(options: GatewayOptions) -> anyhow::Result<()> {
    let state = Arc::new(GatewayState::from_options(&options).await?);

    // Every route below reaches an executor, so every route below is
    // behind this run's credential. The layer goes on last, which in axum
    // puts it outermost: a request without the credential is answered
    // before a handler, the provenance layer, or the executor sees it.
    let bearer = Arc::new(access::Bearer::generate());
    let app = Router::new()
        .route("/v1/chat/completions", post(openai::handle))
        .route("/v1/responses", post(responses::handle))
        .route("/v1/messages", post(anthropic::handle))
        .route("/v1/completions", post(plain::handle))
        .with_state(state.clone())
        .layer(provenance_layer::ProvenanceLayer)
        .layer(access::BearerLayer::new(bearer.clone()));

    let listener = bind_gateway(&options.host, options.port).await?;
    let bound_addr = listener
        .local_addr()
        .context("listener has no local address")?;
    info!("gateway listening on {bound_addr}");
    bearer.announce();

    if let Some(metrics_port) = options.metrics_port {
        let registry = Arc::new(prometheus_client::registry::Registry::default());
        let bundle = crate::metrics::MetricsBundle::new(registry);
        crate::metrics::spawn_metrics_server(
            metrics_port,
            bundle,
            access::BearerLayer::new(bearer.clone()),
        );
    }

    #[cfg(feature = "evaluate")]
    if state.local {
        info!(
            "local catgrad execution, queue size: {}",
            options.queue_size
        );
    } else if state.verify_local {
        info!(
            "local catgrad verification, queue size: {}",
            options.queue_size
        );
    } else if let Some(verify_node) = state.verify_node_id.as_ref() {
        info!("Verifying primary node against remote shadow node {verify_node}");
    }
    #[cfg(not(feature = "evaluate"))]
    if let Some(verify_node) = state.verify_node_id.as_ref() {
        info!("Verifying primary node against remote shadow node {verify_node}");
    }

    info!("timeout: {}s", state.inference_timeout.as_secs());
    if let Some(model) = state.force_model.as_deref() {
        info!("Forcing request model override to `{model}`");
    }

    let wrap_child = if let Some(cmd) = options.wrap.as_deref() {
        // The listener is loopback by construction, so the address we
        // bound is the address the wrapped command can dial.
        let base = format!("http://{bound_addr}");
        info!("wrapping `{cmd}` with gateway base {base}");
        Some(wrap::spawn(
            cmd,
            &options.wrap_args,
            &base,
            &bearer.child_credential(),
        )?)
    } else {
        None
    };

    let shutdown = Arc::new(tokio::sync::Notify::new());
    let server_shutdown = shutdown.clone();
    let server = std::future::IntoFuture::into_future(
        axum::serve(listener, app).with_graceful_shutdown(async move {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = server_shutdown.notified() => {}
            }
        }),
    );

    match wrap_child {
        Some(mut child) => {
            tokio::pin!(server);
            tokio::select! {
                res = &mut server => {
                    // Gateway stopped (ctrl-c or error); kill_on_drop tears the
                    // wrapped child down too.
                    res.context("gateway server failed")?;
                }
                status = child.wait() => {
                    let status = status.context("waiting on wrapped child failed")?;
                    shutdown.notify_one();
                    server.await.context("gateway server failed")?;
                    if !status.success() {
                        bail!("wrapped command exited with status {status}");
                    }
                }
            }
        }
        None => {
            server.await.context("gateway server failed")?;
        }
    }

    Ok(())
}

/// Bind the gateway listener. The host is resolved and required to be
/// loopback before anything is bound — these routes reach the executor,
/// so the listener does not come up on an address other machines can
/// dial. With `--port`, fail loud on conflict (the user asked for that
/// exact port). Without it, try 8080 first and fall back to an
/// OS-assigned port on EADDRINUSE so a stray dev gateway doesn't block a
/// fresh one.
async fn bind_gateway(host: &str, port: Option<u16>) -> anyhow::Result<tokio::net::TcpListener> {
    if let Some(p) = port {
        let addr = access::loopback_addr(host, p).await?;
        return tokio::net::TcpListener::bind(addr)
            .await
            .with_context(|| format!("failed to bind gateway on {addr}"));
    }
    let preferred = access::loopback_addr(host, DEFAULT_HTTP_PORT).await?;
    match tokio::net::TcpListener::bind(preferred).await {
        Ok(listener) => Ok(listener),
        Err(err) if err.kind() == std::io::ErrorKind::AddrInUse => {
            let fallback = SocketAddr::new(preferred.ip(), 0);
            info!("failed to bind {preferred}; attempting to bind {fallback}");
            tokio::net::TcpListener::bind(fallback)
                .await
                .with_context(|| format!("failed to bind gateway on {fallback}"))
        }
        Err(err) => Err(err).with_context(|| format!("failed to bind gateway on {preferred}")),
    }
}

fn json_error(status: StatusCode, message: impl Into<String>) -> Response {
    (
        status,
        Json(json!({ "error": { "message": message.into() } })),
    )
        .into_response()
}

/// Wrap an event stream as an SSE response. The stream IS the producer —
/// no spawn, no channel. When axum drops the response body the stream is
/// dropped, propagating drop-cancellation through every layer (decoder,
/// inference, broadcast subscriber, executor's per-running cancel token).
fn sse_response<S>(stream: S) -> Response
where
    S: Stream<Item = Result<Event, Infallible>> + Send + 'static,
{
    Sse::new(stream)
        .keep_alive(KeepAlive::default())
        .into_response()
}

fn sse_data<T: Serialize>(payload: &T) -> Event {
    let data = serde_json::to_string(payload).unwrap_or_else(|_| "{}".to_string());
    Event::default().data(data)
}

fn sse_event_data<T: Serialize>(event: &str, payload: &T) -> Event {
    let data = serde_json::to_string(payload).unwrap_or_else(|_| "{}".to_string());
    Event::default().event(event).data(data)
}

fn next_id(prefix: &str) -> String {
    let n = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    format!("{prefix}-{n}")
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

/// How many seconds remain until `deadline`, clamped to at least one
/// second so timeout error messages don't report `0s`.
fn timeout_secs_until(deadline: tokio::time::Instant) -> u64 {
    deadline
        .saturating_duration_since(tokio::time::Instant::now())
        .as_secs()
        .max(1)
}
