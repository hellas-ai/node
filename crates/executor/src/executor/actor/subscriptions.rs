use crate::state::ExecutionStatus;
use hellas_rpc::pb::hellas::{ExecuteProgress, ExecuteSnapshot, ExecuteStatusResponse};

use super::super::stream::SubscriptionSet;
use super::super::{LocalExecutionStream, spawn_closed_monitor};
use super::Executor;

impl Executor {
    pub(super) fn handle_subscribe(
        &mut self,
        execution_id: String,
    ) -> Result<LocalExecutionStream, crate::ExecutorError> {
        let snapshot = self.stream_snapshot(&execution_id)?;

        if matches!(
            ExecutionStatus::try_from(snapshot.status),
            Ok(ExecutionStatus::Completed | ExecutionStatus::Failed)
        ) {
            return Ok(LocalExecutionStream::new(snapshot, None));
        }

        let subscriptions = self
            .subscriptions
            .entry(execution_id.clone())
            .or_insert_with(SubscriptionSet::new);
        let updates = subscriptions.updates.subscribe();

        if !subscriptions.closed_monitor_running {
            subscriptions.closed_monitor_running = true;
            spawn_closed_monitor(
                execution_id,
                subscriptions.updates.clone(),
                self.notify_tx.clone(),
            );
        }

        Ok(LocalExecutionStream::new(snapshot, Some(updates)))
    }

    pub(super) fn send_progress(
        &mut self,
        execution_id: &str,
        status: ExecutionStatus,
        progress: u64,
        output_chunk: Vec<u8>,
        error: Option<String>,
    ) {
        let Some(subscriptions) = self.subscriptions.get(execution_id) else {
            return;
        };

        let _ = subscriptions.updates.send(ExecuteProgress {
            status: status as i32,
            progress,
            output_chunk,
            error: error.unwrap_or_default(),
        });
    }

    pub(super) fn send_status(
        &mut self,
        execution_id: &str,
        status: ExecutionStatus,
        error: Option<String>,
    ) {
        let progress = self.store.progress(execution_id).unwrap_or(0);
        self.send_progress(execution_id, status, progress, Vec::new(), error);
    }

    pub(super) fn handle_subscriptions_closed(&mut self, execution_id: &str) {
        let should_remove = match self.subscriptions.get_mut(execution_id) {
            Some(subscriptions) => {
                if subscriptions.updates.receiver_count() == 0 {
                    subscriptions.closed_monitor_running = false;
                    true
                } else {
                    subscriptions.closed_monitor_running = true;
                    spawn_closed_monitor(
                        execution_id.to_string(),
                        subscriptions.updates.clone(),
                        self.notify_tx.clone(),
                    );
                    false
                }
            }
            None => false,
        };

        if should_remove {
            self.subscriptions.remove(execution_id);

            if matches!(
                self.store.status(execution_id),
                Ok(ExecutionStatus::Pending)
            ) {
                self.cancel_pending_execution(execution_id);
            }
        }
    }

    pub(super) fn status_response(
        &self,
        execution_id: &str,
    ) -> Result<ExecuteStatusResponse, crate::ExecutorError> {
        let (status, progress) = self.store.status_snapshot(execution_id)?;
        Ok(ExecuteStatusResponse {
            status: status as i32,
            progress,
        })
    }

    fn stream_snapshot(&self, execution_id: &str) -> Result<ExecuteSnapshot, crate::ExecutorError> {
        Ok(self.store.snapshot(execution_id)?.into())
    }
}

impl From<crate::state::ExecutionSnapshot> for ExecuteSnapshot {
    fn from(snapshot: crate::state::ExecutionSnapshot) -> Self {
        Self {
            status: snapshot.status as i32,
            progress: snapshot.progress,
            output: snapshot.output,
            error: snapshot.error.unwrap_or_default(),
        }
    }
}
