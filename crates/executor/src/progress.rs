use hellas_rpc::pb::hellas::ExecuteProgress;
use tokio::sync::mpsc;

use crate::state::ExecutionStatus;
use crate::{Executor, ExecutorError};

impl Executor {
    pub(super) fn handle_subscribe(
        &mut self,
        execution_id: String,
    ) -> Result<(ExecuteProgress, mpsc::UnboundedReceiver<ExecuteProgress>), ExecutorError> {
        // Validate existence and grab current snapshot
        let status = *self.state.get_status(&execution_id)?;
        let progress = self.state.get_progress(&execution_id).unwrap_or(0);

        let (tx, rx) = mpsc::unbounded_channel();

        // Only keep watchers alive when more updates are expected
        if !matches!(status, ExecutionStatus::Completed | ExecutionStatus::Failed) {
            self.watchers.entry(execution_id).or_default().push(tx);
        }

        Ok((
            ExecuteProgress {
                status: status.as_str().to_string(),
                progress,
                chunk: Vec::new(),
                decoded: None,
            },
            rx,
        ))
    }

    pub(super) fn handle_complete(
        &mut self,
        execution_id: String,
        result: Option<Vec<u8>>,
        decoded: Option<String>,
        success: bool,
    ) {
        let status = if success {
            ExecutionStatus::Completed
        } else {
            ExecutionStatus::Failed
        };
        info!(
            %execution_id,
            success,
            decoded_len = decoded.as_ref().map(|s| s.len()).unwrap_or(0),
            "execution finished"
        );
        if let Err(e) = self.state.set_status(&execution_id, status) {
            warn!("failed to set status for {execution_id}: {e}");
            return;
        }
        if let Some(result) = result {
            if let Err(e) = self.state.set_result(&execution_id, result, decoded) {
                warn!("failed to set result for {execution_id}: {e}");
            }
        }
        self.send_status(&execution_id, status);
    }

    pub(super) fn send_progress(
        &mut self,
        execution_id: &str,
        status: ExecutionStatus,
        progress: u64,
        chunk: Vec<u8>,
        decoded: Option<String>,
    ) {
        if let Some(watchers) = self.watchers.get_mut(execution_id) {
            watchers.retain(|tx| {
                tx.send(ExecuteProgress {
                    status: status.as_str().to_string(),
                    progress,
                    chunk: chunk.clone(),
                    decoded: decoded.clone(),
                })
                .is_ok()
            });

            if matches!(status, ExecutionStatus::Completed | ExecutionStatus::Failed) {
                self.watchers.remove(execution_id);
            }
        }
    }

    pub(super) fn send_status(&mut self, execution_id: &str, status: ExecutionStatus) {
        let progress = self.state.get_progress(execution_id).unwrap_or(0);
        self.send_progress(execution_id, status, progress, Vec::new(), None);
    }
}
