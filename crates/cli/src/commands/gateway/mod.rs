mod anthropic;
mod openai;
mod plain;
mod state;

use crate::commands::CliResult;
use anyhow::Context;
use axum::body::Bytes;
use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde::Serialize;
use serde_json::json;
use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use tokio_stream::wrappers::UnboundedReceiverStream;
use tonic_iroh_transport::iroh::{EndpointId, SecretKey};

use self::state::{GatewayState, HttpError};

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

pub struct GatewayOptions {
    pub host: String,
    pub port: u16,
    pub node_id: Option<EndpointId>,
    pub node_addrs: Vec<SocketAddr>,
    pub local: bool,
    pub verify_local: bool,
    pub verify: Option<EndpointId>,
    pub queue_size: usize,
    pub retries: usize,
    pub default_max_tokens: u32,
    pub force_model: Option<String>,
    pub metrics_port: Option<u16>,
    pub secret_key: SecretKey,
}

type SseSender = mpsc::UnboundedSender<Result<Event, Infallible>>;

pub async fn run(options: GatewayOptions) -> CliResult<()> {
    let state = Arc::new(GatewayState::from_options(&options)?);

    let app = Router::new()
        .route("/v1/chat/completions", post(openai::handle))
        .route("/v1/messages", post(anthropic::handle))
        .route("/v1/completions", post(plain::handle))
        .with_state(state.clone());

    let addr = format!("{}:{}", options.host, options.port);
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .with_context(|| format!("failed to bind gateway on {addr}"))?;

    if let Some(metrics_port) = options.metrics_port {
        let registry = Arc::new(prometheus_client::registry::Registry::default());
        crate::metrics::spawn_metrics_server(metrics_port, registry);
    }

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

    info!("timeout: {}s", state.inference_timeout.as_secs());
    if let Some(model) = state.force_model.as_deref() {
        info!("Forcing request model override to `{model}`");
    }

    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .context("gateway server failed")?;

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

fn sse_response<F, Fut>(task: F) -> Response
where
    F: FnOnce(SseSender) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(task(tx));
    Sse::new(UnboundedReceiverStream::new(rx))
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
