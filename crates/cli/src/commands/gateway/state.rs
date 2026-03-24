use super::{GatewayOptions, json_error};
use crate::execution::{
    ExecutionOutput, ExecutionRequest, ExecutionRoute, ExecutionRuntime, ExecutionStrategy,
    RemoteNodeTarget,
};
use crate::text_output::TextOutputDecoder;
use anyhow::Context;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use catgrad_llm::PreparedPrompt;
use catgrad_llm::PromptRequest;
use catgrad_llm::types::{anthropic, openai, plain};
use hellas_executor::{DownloadPolicy, ExecutePolicy, Executor, ModelAssets};
use std::collections::HashMap;
use std::error::Error as StdError;
use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tokio::time::{Duration, timeout};
use tonic_iroh_transport::iroh::EndpointId;

const DEFAULT_INFERENCE_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Clone)]
pub(super) struct GatewayState {
    pub(super) node_id: Option<EndpointId>,
    pub(super) node_addrs: Vec<SocketAddr>,
    pub(super) local: bool,
    pub(super) verify_local: bool,
    pub(super) verify_node_id: Option<EndpointId>,
    pub(super) retries: usize,
    default_max_tokens: u32,
    pub(super) force_model: Option<String>,
    pub(super) inference_timeout: Duration,
    runtime: ExecutionRuntime,
    model_cache: Arc<RwLock<HashMap<String, Arc<ModelAssets>>>>,
    model_load_locks: Arc<Mutex<HashMap<String, Arc<Mutex<()>>>>>,
}

pub(super) struct PreparedGeneration {
    pub(super) model: String,
    pub(super) request: ExecutionRequest,
    pub(super) prompt_tokens: u32,
    pub(super) stop_token_ids: Vec<i32>,
    assets: Arc<ModelAssets>,
    inference_timeout: Duration,
}

pub(super) enum GenerationError {
    Timeout(Duration),
    Failed(anyhow::Error),
}

pub(super) struct HttpError {
    pub(super) status: StatusCode,
    pub(super) message: String,
}

impl GatewayState {
    pub(super) fn from_options(options: &GatewayOptions) -> anyhow::Result<Self> {
        let runtime = if options.local || options.verify_local {
            ExecutionRuntime::with_local_executor(
                Executor::spawn(
                    DownloadPolicy::Eager,
                    ExecutePolicy::Eager,
                    options.queue_size,
                )
                .context("failed to initialize local execution backend")?,
            )
        } else {
            ExecutionRuntime::default()
        };

        Ok(Self {
            node_id: options.node_id,
            node_addrs: options.node_addrs.clone(),
            local: options.local,
            verify_local: options.verify_local,
            verify_node_id: options.verify,
            retries: options.retries,
            default_max_tokens: options.default_max_tokens,
            force_model: options.force_model.clone(),
            inference_timeout: DEFAULT_INFERENCE_TIMEOUT,
            runtime,
            model_cache: Arc::new(RwLock::new(HashMap::new())),
            model_load_locks: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    fn resolve_model(&self, request_model: &str) -> String {
        self.force_model
            .clone()
            .unwrap_or_else(|| request_model.to_string())
    }

    fn execution_route(&self) -> ExecutionRoute {
        if self.local {
            ExecutionRoute::Local
        } else {
            ExecutionRoute::remote(self.node_id, self.node_addrs.clone(), self.retries)
        }
    }

    fn execution_strategy(&self) -> ExecutionStrategy {
        let primary = self.execution_route();
        if self.verify_local {
            return ExecutionStrategy::Verify {
                primary,
                shadow: ExecutionRoute::Local,
            };
        }

        if let Some(node_id) = self.verify_node_id.clone() {
            return ExecutionStrategy::Verify {
                primary,
                shadow: ExecutionRoute::RemoteDirect(RemoteNodeTarget {
                    node_id,
                    node_addrs: Vec::new(),
                }),
            };
        }

        ExecutionStrategy::Run(primary)
    }

    async fn model_assets(&self, model: &str) -> anyhow::Result<Arc<ModelAssets>> {
        {
            let cache = self.model_cache.read().await;
            if let Some(assets) = cache.get(model) {
                return Ok(assets.clone());
            }
        }

        let load_lock = {
            let mut locks = self.model_load_locks.lock().await;
            locks
                .entry(model.to_string())
                .or_insert_with(|| Arc::new(Mutex::new(())))
                .clone()
        };
        let _load_guard = load_lock.lock().await;

        {
            let cache = self.model_cache.read().await;
            if let Some(assets) = cache.get(model) {
                return Ok(assets.clone());
            }
        }

        let model_name = model.to_string();
        let assets = tokio::task::spawn_blocking(move || ModelAssets::load(&model_name))
            .await
            .context("local model loader panicked")??;

        let assets = Arc::new(assets);
        let mut cache = self.model_cache.write().await;
        cache.insert(model.to_string(), assets.clone());
        Ok(assets)
    }

    async fn prepare_generation<F, E>(
        &self,
        request_model: &str,
        max_tokens: u32,
        prepare_error: &str,
        prepare: F,
    ) -> Result<PreparedGeneration, HttpError>
    where
        F: FnOnce(&ModelAssets) -> Result<PreparedPrompt, E>,
        E: StdError + Send + Sync + 'static,
    {
        let model = self.resolve_model(request_model);
        let assets = self.model_assets(&model).await.map_err(|err| HttpError {
            status: StatusCode::BAD_REQUEST,
            message: format!("Failed to load local model assets for `{model}`: {err}"),
        })?;
        let prepared_prompt = prepare(assets.as_ref()).map_err(|err| HttpError {
            status: StatusCode::BAD_REQUEST,
            message: format!("{prepare_error}: {}", format_error_causes(&err)),
        })?;
        let prompt_tokens = prepared_prompt.input_ids.len() as u32;
        let stop_token_ids = prepared_prompt.stop_token_ids.clone();
        let request = ExecutionRequest::new(
            self.runtime.clone(),
            assets.clone(),
            prepared_prompt,
            max_tokens,
            self.execution_strategy(),
        )
        .map_err(|err| HttpError {
            status: StatusCode::BAD_REQUEST,
            message: format!("Failed to build execution request: {err}"),
        })?;

        Ok(PreparedGeneration {
            model,
            assets,
            request,
            prompt_tokens,
            stop_token_ids,
            inference_timeout: self.inference_timeout,
        })
    }

    pub(super) async fn prepare_openai(
        &self,
        req: &openai::ChatCompletionRequest,
    ) -> Result<PreparedGeneration, HttpError> {
        let max_tokens = req.max_tokens.unwrap_or(self.default_max_tokens);
        let prompt_request = PromptRequest::try_from(req).map_err(|err| HttpError {
            status: StatusCode::BAD_REQUEST,
            message: format!("Failed to normalize chat request: {err}"),
        })?;
        self.prepare_generation(
            &req.model,
            max_tokens,
            "Failed to prepare chat request",
            move |assets| assets.prepare_request(&prompt_request),
        )
        .await
    }

    pub(super) async fn prepare_anthropic(
        &self,
        req: &anthropic::MessageRequest,
    ) -> Result<PreparedGeneration, HttpError> {
        let prompt_request = PromptRequest::try_from(req).map_err(|err| HttpError {
            status: StatusCode::BAD_REQUEST,
            message: format!("Failed to normalize chat request: {err}"),
        })?;
        self.prepare_generation(
            &req.model,
            req.max_tokens,
            "Failed to prepare chat request",
            move |assets| assets.prepare_request(&prompt_request),
        )
        .await
    }

    pub(super) async fn prepare_plain(
        &self,
        req: &plain::CompletionRequest,
    ) -> Result<PreparedGeneration, HttpError> {
        let max_tokens = req.max_tokens.unwrap_or(self.default_max_tokens);
        let prompt_request = PromptRequest::try_from(req).map_err(|err| HttpError {
            status: StatusCode::BAD_REQUEST,
            message: format!("Failed to normalize completion request: {err}"),
        })?;
        self.prepare_generation(
            &req.model,
            max_tokens,
            "Failed to prepare completion prompt",
            move |assets| assets.prepare_request(&prompt_request),
        )
        .await
    }
}

fn format_error_causes(err: &(dyn StdError + 'static)) -> String {
    let mut parts = Vec::new();
    let mut current = err.source().unwrap_or(err);
    parts.push(current.to_string());
    while let Some(source) = current.source() {
        parts.push(source.to_string());
        current = source;
    }
    parts.join(": ")
}

impl PreparedGeneration {
    async fn run<F>(&self, mut on_output: F) -> Result<ExecutionOutput, GenerationError>
    where
        F: FnMut(&[u8]) -> anyhow::Result<()> + Send,
    {
        let output = timeout(self.inference_timeout, self.request.run(&mut on_output))
            .await
            .map_err(|_| GenerationError::Timeout(self.inference_timeout))??;
        Ok(output)
    }

    pub(super) async fn run_to_text(&self) -> Result<(ExecutionOutput, String), GenerationError> {
        let output = self.run(|_| Ok(())).await?;
        let text = TextOutputDecoder::decode_output(self.assets.as_ref(), &output)?;
        Ok((output, text))
    }

    pub(super) async fn stream_text<F>(
        &self,
        mut on_text: F,
    ) -> Result<ExecutionOutput, GenerationError>
    where
        F: FnMut(&str) -> anyhow::Result<()> + Send,
    {
        let mut decoder = TextOutputDecoder::new(self.assets.clone(), &self.stop_token_ids);
        self.run(|output| {
            let delta = decoder.push_output(output)?;
            if delta.is_empty() {
                return Ok(());
            }
            on_text(&delta)
        })
        .await
    }
}

impl fmt::Display for GenerationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GenerationError::Timeout(duration) => {
                write!(f, "inference timed out after {}s", duration.as_secs())
            }
            GenerationError::Failed(err) => write!(f, "{err}"),
        }
    }
}

impl From<anyhow::Error> for GenerationError {
    fn from(err: anyhow::Error) -> Self {
        GenerationError::Failed(err)
    }
}

impl IntoResponse for GenerationError {
    fn into_response(self) -> Response {
        let status = match self {
            GenerationError::Timeout(_) => StatusCode::GATEWAY_TIMEOUT,
            GenerationError::Failed(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        match &self {
            GenerationError::Timeout(duration) => {
                warn!(
                    timeout_secs = duration.as_secs(),
                    "gateway inference timed out"
                );
            }
            GenerationError::Failed(err) => {
                error!(error = %err, "gateway inference failed");
            }
        }
        json_error(status, format!("Inference error: {self}"))
    }
}

impl IntoResponse for HttpError {
    fn into_response(self) -> Response {
        if self.status.is_server_error() {
            error!(
                status = %self.status,
                message = %self.message,
                "gateway request failed"
            );
        } else {
            warn!(
                status = %self.status,
                message = %self.message,
                "gateway request rejected"
            );
        }
        json_error(self.status, self.message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn endpoint(byte: u8) -> EndpointId {
        match byte {
            1 => EndpointId::from_str(
                "bb18ebc065d836ecc7e1f33972d2c17eac9894cd33ce4916f66cb1165ccc7550",
            )
            .expect("valid endpoint id"),
            2 => EndpointId::from_str(
                "edfadcefb3917925de1111087f11925542c97e14ab00cf42b9447f7567a25b62",
            )
            .expect("valid endpoint id"),
            _ => panic!("unknown test endpoint"),
        }
    }

    fn state(local: bool, verify_local: bool, verify_node_id: Option<EndpointId>) -> GatewayState {
        GatewayState {
            node_id: Some(endpoint(1)),
            node_addrs: Vec::new(),
            local,
            verify_local,
            verify_node_id,
            retries: 2,
            default_max_tokens: 128,
            force_model: None,
            inference_timeout: DEFAULT_INFERENCE_TIMEOUT,
            runtime: ExecutionRuntime::default(),
            model_cache: Arc::default(),
            model_load_locks: Arc::default(),
        }
    }

    #[test]
    fn execution_strategy_uses_local_shadow_for_verify_local() {
        let state = state(false, true, None);
        assert_eq!(
            state.execution_strategy(),
            ExecutionStrategy::Verify {
                primary: ExecutionRoute::RemoteDirect(RemoteNodeTarget {
                    node_id: endpoint(1),
                    node_addrs: Vec::new(),
                }),
                shadow: ExecutionRoute::Local,
            }
        );
    }

    #[test]
    fn execution_strategy_uses_remote_shadow_for_verify_node() {
        let verify_node = endpoint(2);
        let state = state(false, false, Some(verify_node));
        assert_eq!(
            state.execution_strategy(),
            ExecutionStrategy::Verify {
                primary: ExecutionRoute::RemoteDirect(RemoteNodeTarget {
                    node_id: endpoint(1),
                    node_addrs: Vec::new(),
                }),
                shadow: ExecutionRoute::RemoteDirect(RemoteNodeTarget {
                    node_id: endpoint(2),
                    node_addrs: Vec::new(),
                }),
            }
        );
    }

    #[test]
    fn execution_strategy_uses_local_run_when_local_is_enabled() {
        let state = state(true, false, None);
        assert_eq!(
            state.execution_strategy(),
            ExecutionStrategy::Run(ExecutionRoute::Local)
        );
    }
}
