use crate::state::{ExecutionPlan, QuoteRecord};
use crate::weights::PrefixState;
use crate::weights::{has_cached_weights, EnsureDisposition};
use crate::ExecutorError;
use hellas_rpc::pb::hellas::{GetQuoteRequest, GetQuoteResponse};
use std::time::{Duration, Instant};

use super::{weights_not_ready_error, Executor};

const STATIC_QUOTE_AMOUNT: u64 = 1000;
const QUOTE_TTL: Duration = Duration::from_secs(30);

impl Executor {
    pub(super) async fn handle_quote(
        &mut self,
        request: GetQuoteRequest,
    ) -> Result<GetQuoteResponse, ExecutorError> {
        self.store.prune_expired_quotes(Instant::now());
        let (plan, program_id) = ExecutionPlan::from_quote_request(request)?;
        if !self
            .execute_policy
            .allows_execute(&program_id, Some(plan.weights_key.model_id.as_str()))
        {
            return Err(ExecutorError::PolicyDenied(format!(
                "execute policy denied program {program_id} for model {}",
                plan.weights_key.model_id
            )));
        }

        self.ensure_quote_weights_ready(&plan).await?;
        let program = self
            .weights
            .bound_program(&plan.weights_key, &plan.program)
            .await?;
        let prefix_match = program.lookup_prefix(&plan.input_ids);
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
        let prompt_tokens = plan.input_ids.len();
        let max_new_tokens = plan.max_new_tokens;
        let cached_prompt_tokens = start_prefix_len;
        let quote_id = self.store.create_quote(QuoteRecord {
            plan,
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

        Ok(GetQuoteResponse {
            quote_id,
            amount: STATIC_QUOTE_AMOUNT,
            ttl_ms: QUOTE_TTL.as_millis() as u64,
        })
    }

    async fn ensure_quote_weights_ready(&self, plan: &ExecutionPlan) -> Result<(), ExecutorError> {
        let locator = &plan.weights_key;
        match self.weights.ensure_ready(locator.clone()).await {
            EnsureDisposition::Ready => Ok(()),
            EnsureDisposition::Queued | EnsureDisposition::InFlight => {
                if !has_cached_weights(locator) {
                    return Err(weights_not_ready_error(locator));
                }

                self.weights
                    .ensure_ready_wait(locator.clone(), tokio::time::Duration::from_secs(2))
                    .await
                    .map_err(|error| super::map_weights_error(locator, error))
            }
            EnsureDisposition::Failed(error) => Err(ExecutorError::WeightsError(error)),
        }
    }
}
