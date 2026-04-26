use crate::inputs::{EnsureDisposition, HuggingFaceLocator, Status, is_cached_locally};
use crate::state::{QuotePlan, QuoteRecord};
use catgrad::prelude::Dtype;
use catgrad_llm::runtime::TextPolicy;
use catgrad_llm::types;
use hellas_rpc::ExecutorError;
use hellas_rpc::model::ModelAssets;
use hellas_rpc::pb::hellas::{
    GetQuoteRequest, GetQuoteResponse, ListModelsResponse, ModelInfo, ModelStatus,
    QuoteChatPromptRequest, QuoteChatPromptResponse, QuotePromptRequest, QuotePromptResponse,
};
use hellas_rpc::provenance::ExecutionProvenance;
use hellas_rpc::spec::ModelSpec;
use std::str::FromStr;
use std::time::{Duration, Instant};

use super::Executor;
use crate::executor::QuoteOutcome;

const STATIC_QUOTE_AMOUNT: u64 = 1000;
const QUOTE_TTL: Duration = Duration::from_secs(30);

/// Lower-case `Dtype` rendering used in wire fields so callers don't pay
/// the `Debug` impl's upper-case quirk (`F32` etc.).
fn dtype_to_wire(dtype: Dtype) -> String {
    match dtype {
        Dtype::F32 => "f32".to_string(),
        Dtype::F16 => "f16".to_string(),
        Dtype::BF16 => "bf16".to_string(),
        Dtype::U32 => "u32".to_string(),
    }
}

impl Executor {
    /// Resolve a client-supplied dtype preference list against this
    /// executor's `supported_dtypes`. The first entry of `prefs` that this
    /// executor supports wins. An empty `prefs` list lets the executor
    /// fall back to its preferred dtype. If `prefs` is non-empty and none
    /// of its entries are supported, the request is refused with
    /// `DtypeNotSupported`.
    ///
    /// Each entry must be `"f32"`, `"f16"`, or `"bf16"`. `"u32"` and
    /// unknown strings produce `InvalidQuoteRequest`.
    pub(super) fn resolve_accept_dtypes(&self, prefs: &[String]) -> Result<Dtype, ExecutorError> {
        if prefs.is_empty() {
            return Ok(self.preferred_dtype());
        }
        let mut parsed = Vec::with_capacity(prefs.len());
        for raw in prefs {
            let dtype = Dtype::from_str(raw).map_err(|e| {
                ExecutorError::InvalidQuoteRequest(format!("invalid dtype `{raw}`: {e}"))
            })?;
            if matches!(dtype, Dtype::U32) {
                return Err(ExecutorError::InvalidQuoteRequest(
                    "model dtype must be f32, f16, or bf16".to_string(),
                ));
            }
            parsed.push(dtype);
        }
        for dtype in &parsed {
            if self.supported_dtypes.contains(dtype) {
                return Ok(*dtype);
            }
        }
        Err(ExecutorError::DtypeNotSupported {
            request: parsed[0],
            supported: self.supported_dtypes.clone(),
        })
    }
}

impl Executor {
    pub(super) async fn handle_preload(&mut self, model: String) -> Result<(), ExecutorError> {
        let spec = ModelSpec::parse(&model).map_err(hellas_rpc::ModelAssetsError::from)?;
        let locator = HuggingFaceLocator::from_spec(spec, self.preferred_dtype());
        self.programs.ensure_preloaded(locator.clone()).await?;
        info!(
            model = %locator.model_id,
            requested_revision = %locator.revision,
            "preloaded weights"
        );
        Ok(())
    }

    pub(super) async fn handle_quote(
        &mut self,
        request: GetQuoteRequest,
    ) -> Result<QuoteOutcome<GetQuoteResponse>, ExecutorError> {
        let total_start = Instant::now();
        self.store.prune_expired_quotes(Instant::now());
        let plan_start = Instant::now();
        let plan = QuotePlan::from_quote_request(request, &self.supported_dtypes)?;
        let plan_parse_ms = plan_start.elapsed().as_millis();
        let program_id = plan.program.id();
        if !self.execute_policy.allows_execute(
            &program_id.to_string(),
            Some(plan.weights_key.model_id.as_str()),
        ) {
            return Err(ExecutorError::PolicyDenied(format!(
                "execute policy denied program {} for model {}",
                program_id, plan.weights_key.model_id
            )));
        }

        let ensure_start = Instant::now();
        self.ensure_quote_weights_ready(&plan.weights_key).await?;
        let ensure_weights_ms = ensure_start.elapsed().as_millis();
        let bind_start = Instant::now();
        let execution = self
            .programs
            .bound_program(&plan.weights_key, &plan.program)
            .await?;
        let bind_program_ms = bind_start.elapsed().as_millis();
        // Build the request commitment: a `Cid<TextExecution>` over
        // (program, parameter tensor CIDs, prompt tokens, policy), hashed
        // via canonical DAG-CBOR. The same 32 bytes serve two roles:
        //   - audit anchor — the executor is committing to having run
        //     exactly these inputs and no others.
        //   - exact-replay cache key — two requests with the same
        //     commitment hash are byte-identical and skip the model.
        let policy = TextPolicy::new(
            plan.invocation.max_new_tokens,
            plan.invocation.stop_token_ids.clone(),
        );
        // Cold-start: anchor on the bound program's genesis receipt.
        // Anchored execution (later phase) will read this from the
        // request wire field instead.
        let initial_receipt_id = execution.genesis_receipt_id();
        let commitment_id = execution
            .build_text_execution(initial_receipt_id, &plan.invocation, &policy)?
            .id();
        let cache_start = Instant::now();
        let start = execution.execution_start(commitment_id, initial_receipt_id)?;
        let cache_lookup_ms = cache_start.elapsed().as_millis();

        let model_id = plan.weights_key.model_id.clone();
        let requested_revision = plan.weights_key.revision.clone();
        let prompt_tokens = plan.invocation.input_ids.len();
        let max_new_tokens = plan.invocation.max_new_tokens;
        let cached_output_tokens = start.cached.as_ref().map_or(0, |c| c.output_tokens.len());
        let quote_id = self.store.create_quote(QuoteRecord {
            invocation: plan.invocation,
            execution,
            start,
            expires_at: Instant::now() + QUOTE_TTL,
            model_id: model_id.clone(),
        });

        info!(
            %quote_id,
            %program_id,
            %commitment_id,
            amount = STATIC_QUOTE_AMOUNT,
            model = model_id,
            requested_revision,
            prompt_tokens,
            cached_output_tokens,
            max_new_tokens,
            "quoted program execution"
        );
        debug!(
            %quote_id,
            %program_id,
            prompt_tokens,
            cached_output_tokens,
            plan_parse_ms,
            ensure_weights_ms,
            bind_program_ms,
            cache_lookup_ms,
            total_ms = total_start.elapsed().as_millis(),
            "quote phase timings"
        );

        Ok(QuoteOutcome {
            response: GetQuoteResponse {
                quote_id,
                amount: STATIC_QUOTE_AMOUNT,
                ttl_ms: QUOTE_TTL.as_millis() as u64,
            },
            provenance: ExecutionProvenance {
                commitment_id: *commitment_id.as_bytes(),
            },
        })
    }

    pub(super) async fn handle_quote_prompt(
        &mut self,
        request: QuotePromptRequest,
    ) -> Result<QuoteOutcome<QuotePromptResponse>, ExecutorError> {
        let dtype = self.resolve_accept_dtypes(&request.accept_dtypes)?;
        let assets = load_assets(
            &request.huggingface_model_id,
            &request.huggingface_revision,
            dtype,
        )?;
        let prepared = assets.prepare_plain(&request.prompt)?;
        let prompt_tokens = prepared.input_ids.len() as u32;
        let full_request = assets.build_quote_request(&prepared, request.max_new_tokens)?;
        let inner = self.handle_quote(full_request).await?;

        Ok(QuoteOutcome {
            response: QuotePromptResponse {
                quote_id: inner.response.quote_id,
                amount: inner.response.amount,
                ttl_ms: inner.response.ttl_ms,
                prompt_tokens,
                dtype: dtype_to_wire(dtype),
            },
            provenance: inner.provenance,
        })
    }

    pub(super) async fn handle_quote_chat_prompt(
        &mut self,
        request: QuoteChatPromptRequest,
    ) -> Result<QuoteOutcome<QuoteChatPromptResponse>, ExecutorError> {
        let dtype = self.resolve_accept_dtypes(&request.accept_dtypes)?;
        let assets = load_assets(
            &request.huggingface_model_id,
            &request.huggingface_revision,
            dtype,
        )?;

        // Build ChatInput from proto messages + system_prompt.
        let mut messages: Vec<types::Message> = Vec::new();
        if !request.system_prompt.is_empty() {
            messages.push(types::Message::openai(types::openai::ChatMessage::system(
                &request.system_prompt,
            )));
        }
        for m in &request.messages {
            let msg = match m.role.as_str() {
                "assistant" => types::openai::ChatMessage::assistant(&m.content),
                _ => types::openai::ChatMessage::user(&m.content),
            };
            messages.push(types::Message::openai(msg));
        }
        let prepared = assets.prepare_chat(&messages)?;
        let prompt_tokens = prepared.input_ids.len() as u32;
        let full_request = assets.build_quote_request(&prepared, request.max_new_tokens)?;
        let inner = self.handle_quote(full_request).await?;

        Ok(QuoteOutcome {
            response: QuoteChatPromptResponse {
                quote_id: inner.response.quote_id,
                amount: inner.response.amount,
                ttl_ms: inner.response.ttl_ms,
                prompt_tokens,
                dtype: dtype_to_wire(dtype),
            },
            provenance: inner.provenance,
        })
    }

    pub(super) async fn handle_list_models(&self) -> ListModelsResponse {
        let entries = self.programs.list_models().await;
        let models = entries
            .into_iter()
            .map(|(locator, status)| {
                let (proto_status, error) = match status {
                    Status::Queued => (ModelStatus::Queued, String::new()),
                    Status::Loading => (ModelStatus::Loading, String::new()),
                    Status::Ready => (ModelStatus::Ready, String::new()),
                    Status::Failed(err) => (ModelStatus::Failed, err),
                };
                ModelInfo {
                    model_id: locator.model_id,
                    revision: locator.revision,
                    status: proto_status.into(),
                    error,
                }
            })
            .collect();
        ListModelsResponse { models }
    }

    async fn ensure_quote_weights_ready(
        &self,
        locator: &HuggingFaceLocator,
    ) -> Result<(), ExecutorError> {
        match self.programs.ensure_ready(locator.clone()).await {
            EnsureDisposition::Ready => Ok(()),
            EnsureDisposition::Queued | EnsureDisposition::InFlight => {
                if !is_cached_locally(locator) {
                    return Err(ExecutorError::WeightsNotReady(locator.to_string()));
                }
                self.programs
                    .ensure_ready_wait(locator.clone(), tokio::time::Duration::from_secs(2))
                    .await
            }
            EnsureDisposition::Failed(error) => Err(ExecutorError::WeightsError(error)),
        }
    }
}

/// Load `ModelAssets` for a `(model_id, revision)` pair, using the same
/// `id[@revision]` parser the quote path uses. An empty revision means
/// "default" (resolved by `ModelSpec::parse`).
fn load_assets(
    model_id: &str,
    revision: &str,
    dtype: Dtype,
) -> Result<ModelAssets, hellas_rpc::ModelAssetsError> {
    let spec = if revision.is_empty() {
        model_id.to_string()
    } else {
        format!("{model_id}@{revision}")
    };
    ModelAssets::load(&spec, dtype)
}

