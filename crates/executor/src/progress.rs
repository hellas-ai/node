use hellas_rpc::pb::hellas::ExecuteProgress;
use tokio::sync::mpsc;

use crate::state::ExecutionStatus;
use crate::{Executor, ExecutorError, LocalExecuteStream, Watcher, WatcherRegistration};

impl Executor {
    pub(super) fn handle_subscribe(
        &mut self,
        execution_id: String,
    ) -> Result<(ExecuteProgress, LocalExecuteStream), ExecutorError> {
        // New subscribers receive the full buffered output so they can catch up
        // even if execution progress raced ahead before the stream was attached.
        let execution = self.state.get_execution(&execution_id)?;
        let status = execution.status;
        let progress = execution.progress;
        let chunk = execution.result.clone().unwrap_or_default();

        let (tx, rx) = mpsc::unbounded_channel();
        let mut watcher_registration = None;

        // Only keep watchers alive when more updates are expected
        if !matches!(status, ExecutionStatus::Completed | ExecutionStatus::Failed) {
            let watcher_id = self.next_watcher_id;
            self.next_watcher_id += 1;
            self.watchers
                .entry(execution_id.clone())
                .or_default()
                .push(Watcher {
                    id: watcher_id,
                    tx: tx.clone(),
                });
            watcher_registration = Some(WatcherRegistration {
                execution_id,
                watcher_id,
                notify_tx: self.watcher_notify_tx.clone(),
            });
        }

        Ok((
            ExecuteProgress {
                status: status as i32,
                progress,
                chunk,
            },
            LocalExecuteStream::new(rx, watcher_registration),
        ))
    }

    pub(super) fn handle_complete(
        &mut self,
        execution_id: String,
        result: Option<Vec<u8>>,
        status: ExecutionStatus,
    ) {
        let success = matches!(status, ExecutionStatus::Completed);
        info!(
            %execution_id,
            success,
            "execution finished"
        );
        if let Err(e) = self.state.set_status(&execution_id, status) {
            warn!("failed to set status for {execution_id}: {e}");
        }
        if let Some(result) = result {
            if let Err(e) = self.state.set_result(&execution_id, result) {
                warn!("failed to set result for {execution_id}: {e}");
            }
        } else if success && self.state.get_result(&execution_id).is_err() {
            if let Err(e) = self.state.set_result(&execution_id, Vec::new()) {
                warn!("failed to set default result for {execution_id}: {e}");
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
    ) {
        if let Some(watchers) = self.watchers.get_mut(execution_id) {
            watchers.retain(|watcher| {
                watcher
                    .tx
                    .send(ExecuteProgress {
                        status: status as i32,
                        progress,
                        chunk: chunk.clone(),
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
        self.send_progress(execution_id, status, progress, Vec::new());
    }

    pub(super) fn handle_watcher_closed(&mut self, execution_id: String, watcher_id: u64) {
        let mut remove_watchers = false;
        if let Some(watchers) = self.watchers.get_mut(&execution_id) {
            watchers.retain(|watcher| watcher.id != watcher_id && !watcher.tx.is_closed());
            remove_watchers = watchers.is_empty();
        }

        if remove_watchers {
            self.watchers.remove(&execution_id);

            if matches!(
                self.state.get_status(&execution_id),
                Ok(ExecutionStatus::Pending)
            ) {
                self.cancel_pending_execution(&execution_id);
            }
        }
    }
}
