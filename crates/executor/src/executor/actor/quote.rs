use crate::state::ExecutionPlan;
use crate::weights::{has_cached_weights, EnsureDisposition};
use crate::ExecutorError;
use hellas_rpc::pb::hellas::{GetQuoteRequest, GetQuoteResponse};

use super::{weights_not_ready_error, Executor};

const STATIC_QUOTE_AMOUNT: u64 = 1000;

impl Executor {
    pub(super) async fn handle_quote(
        &mut self,
        request: GetQuoteRequest,
    ) -> Result<GetQuoteResponse, ExecutorError> {
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
        let _ = self
            .weights
            .bound_program(&plan.weights_key, &plan.program)
            .await?;

        let model_id = plan.weights_key.model_id.clone();
        let requested_revision = plan.weights_key.revision.clone();
        let prompt_tokens = plan.input_ids.len();
        let max_new_tokens = plan.max_new_tokens;
        let quote_id = self.store.create_quote(plan);

        info!(
            %quote_id,
            %program_id,
            amount = STATIC_QUOTE_AMOUNT,
            model = model_id,
            requested_revision,
            prompt_tokens,
            max_new_tokens,
            "quoted program execution"
        );

        Ok(GetQuoteResponse {
            quote_id,
            amount: STATIC_QUOTE_AMOUNT,
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
