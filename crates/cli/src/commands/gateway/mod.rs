mod anthropic;
mod openai;
mod pi;
mod plain;
mod provenance_layer;
mod state;

use crate::commands::CliResult;
use anyhow::{Context, anyhow, bail};
use axum::body::Bytes;
use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use catgrad::cid::Cid;
use catgrad::prelude::Dtype;
use catgrad_llm::runtime::TextReceipt;
use hellas_rpc::provenance::{ExecutionProvenance, encode_hex};
use futures::Stream;
use serde::Serialize;
use serde_json::json;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tonic_iroh_transport::iroh::{EndpointId, SecretKey};

use self::state::{GatewayState, HttpError};

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

pub struct GatewayOptions {
    pub host: String,
    pub port: u16,
    pub node_id: Option<EndpointId>,
    pub node_addrs: Vec<SocketAddr>,
    #[cfg(feature = "hellas-executor")]
    pub local: bool,
    #[cfg(feature = "hellas-executor")]
    pub verify_local: bool,
    pub verify: Option<EndpointId>,
    #[cfg(feature = "hellas-executor")]
    pub queue_size: usize,
    pub retries: usize,
    pub default_max_tokens: u32,
    pub force_model: Option<String>,
    pub metrics_port: Option<u16>,
    pub dtype: Dtype,
    pub secret_key: SecretKey,
    pub pi: bool,
    pub pi_bin: String,
    pub pi_api: String,
    pub pi_log: Option<std::path::PathBuf>,
    pub pi_args: Vec<String>,
}

pub async fn run(options: GatewayOptions) -> CliResult<()> {
    let state = Arc::new(GatewayState::from_options(&options)?);

    let app = Router::new()
        .route("/v1/chat/completions", post(openai::handle))
        .route("/v1/messages", post(anthropic::handle))
        .route("/v1/completions", post(plain::handle))
        .with_state(state.clone())
        .layer(provenance_layer::ProvenanceLayer);

    let addr = format!("{}:{}", options.host, options.port);
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .with_context(|| format!("failed to bind gateway on {addr}"))?;
    let bound_addr = listener
        .local_addr()
        .context("listener has no local address")?;

    if let Some(metrics_port) = options.metrics_port {
        let registry = Arc::new(prometheus_client::registry::Registry::default());
        crate::metrics::spawn_metrics_server(metrics_port, registry);
    }

    #[cfg(feature = "hellas-executor")]
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
    #[cfg(not(feature = "hellas-executor"))]
    if let Some(verify_node) = state.verify_node_id.as_ref() {
        info!("Verifying primary node against remote shadow node {verify_node}");
    }

    info!("timeout: {}s", state.inference_timeout.as_secs());
    if let Some(model) = state.force_model.as_deref() {
        info!("Forcing request model override to `{model}`");
    }

    let pi_handle = if options.pi {
        let model = options.force_model.as_deref().ok_or_else(|| {
            anyhow!("--pi requires --force-model so pi can advertise a concrete model id")
        })?;
        let host = if options.host == "0.0.0.0" || options.host == "::" {
            "127.0.0.1"
        } else {
            options.host.as_str()
        };
        // openai SDKs append /chat/completions to baseUrl, so we need /v1 in
        // the URL. anthropic SDKs append /v1/messages themselves, so baseUrl
        // stays at the host root.
        let path = match options.pi_api.as_str() {
            "openai-completions" => "/v1",
            "anthropic-messages" => "",
            other => bail!("unsupported --pi-api: {other}"),
        };
        let base_url = format!("http://{host}:{}{path}", bound_addr.port());
        info!("spawning pi with provider baseUrl {base_url} (api={})", options.pi_api);
        if let Some(path) = options.pi_log.as_deref() {
            info!("pi stdout/stderr -> {}", path.display());
        }
        Some(pi::spawn(
            &base_url,
            model,
            &options.pi_api,
            &options.pi_bin,
            &options.pi_args,
            options.pi_log.as_deref(),
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

    match pi_handle {
        Some(mut handle) => {
            tokio::pin!(server);
            tokio::select! {
                res = &mut server => {
                    // Gateway stopped (ctrl-c or error); pi dies via kill_on_drop.
                    res.context("gateway server failed")?;
                }
                status = handle.child.wait() => {
                    let status = status.context("waiting on pi failed")?;
                    shutdown.notify_one();
                    server.await.context("gateway server failed")?;
                    if !status.success() {
                        bail!("pi exited with status {status}");
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

fn parse_json_body<T: serde::de::DeserializeOwned>(
    body: &Bytes,
    protocol: &str,
) -> Result<T, HttpError> {
    catgrad_llm::utils::from_json_slice::<T>(body).map_err(|err| HttpError {
        status: StatusCode::BAD_REQUEST,
        message: format!("Invalid {protocol} request: {err}"),
    })
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

/// Initial in-band SSE event carrying the request commitment CID.
/// Browser `EventSource` consumers pick this up via
/// `addEventListener("hellas-provenance", …)` since they can't read
/// HTTP response headers.
fn provenance_sse_event(prov: &ExecutionProvenance) -> Event {
    sse_event_data(
        "hellas-provenance",
        &json!({ "commitment_id": encode_hex(&prov.commitment_id) }),
    )
}

/// Terminal in-band SSE event carrying the execution receipt CID. Emitted
/// once per successful run, immediately before the protocol's terminal
/// frame (`[DONE]` / `message_stop`). Skipped on `Outcome::Failed` since
/// no verifiable receipt was produced.
fn receipt_sse_event(cid: &Cid<TextReceipt>) -> Event {
    sse_event_data("hellas-receipt", &json!({ "receipt_id": cid.to_string() }))
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
