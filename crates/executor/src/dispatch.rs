use hellas_rpc::pb::hellas::{ExecuteRequest, ExecuteResponse};

use crate::execute_worker::{ExecuteJob, ExecuteWorkerError};
use crate::state::ExecutionStatus;
use crate::weights::WeightsError;
use crate::{Executor, ExecutorError};

impl Executor {
    pub(super) async fn handle_execute(
        &mut self,
        request: ExecuteRequest,
    ) -> Result<ExecuteResponse, ExecutorError> {
        let quote_id = request.quote_id;
        let plan = self.state.get_quote(&quote_id)?.plan.clone();

        let bundle = match plan.weights_hint.clone() {
            Some(key) => Some(self.weights.bundle(&key).await.map_err(|e| match e {
                WeightsError::NotReady => ExecutorError::WeightsNotReady(key.model_id.0.clone()),
                WeightsError::Failed(msg) => ExecutorError::WeightsError(msg),
                other => ExecutorError::WeightsError(other.to_string()),
            })?),
            None => None,
        };

        let reservation = self.execute_worker.reserve().map_err(|e| match e {
            ExecuteWorkerError::Busy => ExecutorError::Busy,
            ExecuteWorkerError::Stopped => ExecutorError::ChannelClosed,
        })?;

        let execution_id = self.state.create_execution(quote_id.clone())?;
        self.state
            .set_status(&execution_id, ExecutionStatus::Running)?;

        info!(
            %execution_id,
            %quote_id,
            input_len = plan.input.len(),
            "starting execution"
        );

        reservation
            .enqueue(ExecuteJob {
                execution_id: execution_id.clone(),
                plan,
                bundle,
            })
            .map_err(|e| match e {
                ExecuteWorkerError::Busy => ExecutorError::Busy,
                ExecuteWorkerError::Stopped => ExecutorError::ChannelClosed,
            })?;

        Ok(ExecuteResponse {
            execution_id,
            quote_id,
        })
    }
}
