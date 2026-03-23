use crate::ExecutorError;
use crate::model::ModelSpec;
use crate::state::{QuotePlan, QuoteRecord};
use crate::weights::PrefixState;
use crate::weights::{EnsureDisposition, WeightsLocator, has_cached_weights};
use hellas_rpc::pb::hellas::{GetQuoteRequest, GetQuoteResponse};
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
        let program_id = plan.program.id().to_string();
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
        let program = self
            .runtime_manager
            .bound_program(&plan.weights_key, &plan.program)
            .await?;
        let bind_program_ms = bind_start.elapsed().as_millis();
        let prefix_start = Instant::now();
        let prefix_match = program.lookup_prefix(&plan.invocation.input_ids);
        let prefix_lookup_ms = prefix_start.elapsed().as_millis();
        let (start_snapshot, start_prefix_len, start_prefix_hash, start_next_token) =
            match prefix_match {
                Some(prefix_match) => (
                    prefix_match.snapshot,
                    prefix_match.prefix_len,
                    prefix_match.prefix_hash,
                    Some(prefix_match.next_token),
                ),
                None => (
                    program.empty_snapshot(),
                    0,
                    PrefixState::seed().hash(),
                    None,
                ),
            };

        let model_id = plan.weights_key.model_id.clone();
        let requested_revision = plan.weights_key.revision.clone();
        let prompt_tokens = plan.invocation.input_ids.len();
        let max_new_tokens = plan.invocation.max_new_tokens;
        let cached_prompt_tokens = start_prefix_len;
        let quote_id = self.store.create_quote(QuoteRecord {
            invocation: plan.invocation,
            program,
            start_snapshot,
            start_prefix_len,
            start_prefix_hash,
            start_next_token,
            expires_at: Instant::now() + QUOTE_TTL,
        });

        info!(
            %quote_id,
            %program_id,
            amount = STATIC_QUOTE_AMOUNT,
            model = model_id,
            requested_revision,
            prompt_tokens,
            cached_prompt_tokens,
            max_new_tokens,
            "quoted program execution"
        );
        debug!(
            %quote_id,
            %program_id,
            prompt_tokens,
            cached_prompt_tokens,
            plan_parse_ms,
            ensure_weights_ms,
            bind_program_ms,
            prefix_lookup_ms,
            total_ms = total_start.elapsed().as_millis(),
            "quote phase timings"
        );

        Ok(GetQuoteResponse {
            quote_id,
            amount: STATIC_QUOTE_AMOUNT,
            ttl_ms: QUOTE_TTL.as_millis() as u64,
        })
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
