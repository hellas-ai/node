use crate::ExecutorError;
use crate::model::{ModelAssets, ModelSpec};
use crate::state::{QuotePlan, QuoteRecord};
use crate::weights::{EnsureDisposition, EntryStatusSnapshot, WeightsLocator, has_cached_weights};
use catgrad_llm::types;
use catgrad_llm::utils::ChatInput;
use hellas_rpc::pb::hellas::{
    GetQuoteRequest, GetQuoteResponse, ListModelsResponse, ModelInfo, ModelStatus,
    QuoteChatPromptRequest, QuoteChatPromptResponse, QuotePromptRequest, QuotePromptResponse,
};
use std::time::{Duration, Instant};

use super::{Executor, weights_not_ready_error};

const STATIC_QUOTE_AMOUNT: u64 = 1000;
const QUOTE_TTL: Duration = Duration::from_secs(30);

impl Executor {
    pub(super) async fn handle_preload(&mut self, model: String) -> Result<(), ExecutorError> {
        let spec = ModelSpec::parse(&model)?;
        let locator: WeightsLocator = spec.into();
        self.runtime_manager
            .ensure_preloaded(locator.clone())
            .await
            .map_err(|error| super::map_weights_error(&locator, error))?;
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
    ) -> Result<GetQuoteResponse, ExecutorError> {
        let total_start = Instant::now();
        self.store.prune_expired_quotes(Instant::now());
        let plan_start = Instant::now();
        let plan = QuotePlan::from_quote_request(request)?;
        let plan_parse_ms = plan_start.elapsed().as_millis();
        let program_id = crate::weights::spec_cache_key(&plan.program);
        if !self
            .execute_policy
            .allows_execute(&program_id, Some(plan.weights_key.model_id.as_str()))
        {
            return Err(ExecutorError::PolicyDenied(format!(
                "execute policy denied program {program_id} for model {}",
                plan.weights_key.model_id
            )));
        }

        let ensure_start = Instant::now();
        self.ensure_quote_weights_ready(&plan.weights_key).await?;
        let ensure_weights_ms = ensure_start.elapsed().as_millis();
        let bind_start = Instant::now();
        let execution = self
            .runtime_manager
            .bound_program(&plan.weights_key, &plan.program)
            .await?;
        let bind_program_ms = bind_start.elapsed().as_millis();
        let cache_start = Instant::now();
        let start = execution.execution_start(&plan.invocation);
        let cache_lookup_ms = cache_start.elapsed().as_millis();

        let model_id = plan.weights_key.model_id.clone();
        let requested_revision = plan.weights_key.revision.clone();
        let prompt_tokens = plan.invocation.input_ids.len();
        let max_new_tokens = plan.invocation.max_new_tokens;
        let cached_prompt_tokens = start.transcript.len();
        let cached_output_tokens = start
            .cached_output_tokens
            .as_ref()
            .map_or(0, |tokens| tokens.len());
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
            amount = STATIC_QUOTE_AMOUNT,
            model = model_id,
            requested_revision,
            prompt_tokens,
            cached_prompt_tokens,
            cached_output_tokens,
            max_new_tokens,
            "quoted program execution"
        );
        debug!(
            %quote_id,
            %program_id,
            prompt_tokens,
            cached_prompt_tokens,
            cached_output_tokens,
            plan_parse_ms,
            ensure_weights_ms,
            bind_program_ms,
            cache_lookup_ms,
            total_ms = total_start.elapsed().as_millis(),
            "quote phase timings"
        );

        Ok(GetQuoteResponse {
            quote_id,
            amount: STATIC_QUOTE_AMOUNT,
            ttl_ms: QUOTE_TTL.as_millis() as u64,
        })
    }

    pub(super) async fn handle_quote_prompt(
        &mut self,
        request: QuotePromptRequest,
    ) -> Result<QuotePromptResponse, ExecutorError> {
        let model_spec = format!(
            "{}{}",
            request.huggingface_model_id,
            if request.huggingface_revision.is_empty() {
                String::new()
            } else {
                format!("@{}", request.huggingface_revision)
            }
        );
        let assets = ModelAssets::load(&model_spec)?;
        let prepared = assets.prepare_plain(&request.prompt)?;
        let prompt_tokens = prepared.input_ids.len() as u32;
        let full_request = assets.build_quote_request(&prepared, request.max_new_tokens)?;
        let quote_response = self.handle_quote(full_request).await?;

        Ok(QuotePromptResponse {
            quote_id: quote_response.quote_id,
            amount: quote_response.amount,
            ttl_ms: quote_response.ttl_ms,
            prompt_tokens,
        })
    }

    pub(super) async fn handle_quote_chat_prompt(
        &mut self,
        request: QuoteChatPromptRequest,
    ) -> Result<QuoteChatPromptResponse, ExecutorError> {
        let model_spec = format!(
            "{}{}",
            request.huggingface_model_id,
            if request.huggingface_revision.is_empty() {
                String::new()
            } else {
                format!("@{}", request.huggingface_revision)
            }
        );
        let assets = ModelAssets::load(&model_spec)?;

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
        let chat_input = ChatInput {
            messages,
            enable_thinking: false,
            has_image: false,
        };

        let prepared = assets.prepare_chat(&chat_input)?;
        let prompt_tokens = prepared.input_ids.len() as u32;
        let full_request = assets.build_quote_request(&prepared, request.max_new_tokens)?;
        let quote_response = self.handle_quote(full_request).await?;

        Ok(QuoteChatPromptResponse {
            quote_id: quote_response.quote_id,
            amount: quote_response.amount,
            ttl_ms: quote_response.ttl_ms,
            prompt_tokens,
        })
    }

    pub(super) async fn handle_list_models(&self) -> ListModelsResponse {
        let entries = self.runtime_manager.list_models().await;
        let models = entries
            .into_iter()
            .map(|(locator, status)| {
                let (proto_status, error) = match status {
                    EntryStatusSnapshot::Queued => (ModelStatus::Queued, String::new()),
                    EntryStatusSnapshot::Loading => (ModelStatus::Loading, String::new()),
                    EntryStatusSnapshot::Ready => (ModelStatus::Ready, String::new()),
                    EntryStatusSnapshot::Failed(err) => (ModelStatus::Failed, err),
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
        locator: &crate::weights::WeightsLocator,
    ) -> Result<(), ExecutorError> {
        match self.runtime_manager.ensure_ready(locator.clone()).await {
            EnsureDisposition::Ready => Ok(()),
            EnsureDisposition::Queued | EnsureDisposition::InFlight => {
                if !has_cached_weights(locator) {
                    return Err(weights_not_ready_error(locator));
                }

                self.runtime_manager
                    .ensure_ready_wait(locator.clone(), tokio::time::Duration::from_secs(2))
                    .await
                    .map_err(|error| super::map_weights_error(locator, error))
            }
            EnsureDisposition::Failed(error) => Err(ExecutorError::WeightsError(error)),
        }
    }
}
