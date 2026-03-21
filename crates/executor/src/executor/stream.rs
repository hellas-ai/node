use crate::state::ExecutionStatus;
use hellas_rpc::pb::hellas::{
    execute_stream_event, ExecuteProgress, ExecuteSnapshot, ExecuteStreamEvent,
};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::sync::{broadcast, mpsc};
use tokio_stream::wrappers::{errors::BroadcastStreamRecvError, BroadcastStream};
use tokio_stream::Stream;
use tonic::{Status, Status as TonicStatus};

use super::ExecutorMessage;

const EXECUTION_STREAM_BUFFER_CAPACITY: usize = 4096;

pub(super) struct SubscriptionSet {
    pub(super) updates: broadcast::Sender<ExecuteProgress>,
    pub(super) closed_monitor_running: bool,
}

impl SubscriptionSet {
    pub(super) fn new() -> Self {
        let (updates, _rx) = broadcast::channel(EXECUTION_STREAM_BUFFER_CAPACITY);
        Self {
            updates,
            closed_monitor_running: false,
        }
    }
}

pub(crate) struct LocalExecutionStream {
    initial: Option<ExecuteStreamEvent>,
    updates: Option<BroadcastStream<ExecuteProgress>>,
}

impl LocalExecutionStream {
    pub(super) fn new(
        snapshot: ExecuteSnapshot,
        updates: Option<broadcast::Receiver<ExecuteProgress>>,
    ) -> Self {
        let updates = if matches!(
            ExecutionStatus::try_from(snapshot.status),
            Ok(ExecutionStatus::Completed | ExecutionStatus::Failed)
        ) {
            None
        } else {
            updates
        };

        Self {
            initial: Some(ExecuteStreamEvent {
                event: Some(execute_stream_event::Event::Snapshot(snapshot)),
            }),
            updates: updates.map(BroadcastStream::new),
        }
    }
}

impl Stream for LocalExecutionStream {
    type Item = Result<ExecuteStreamEvent, TonicStatus>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if let Some(initial) = self.initial.take() {
            return Poll::Ready(Some(Ok(initial)));
        }

        let poll = match self.updates.as_mut() {
            Some(updates) => Pin::new(updates).poll_next(cx),
            None => return Poll::Ready(None),
        };

        match poll {
            Poll::Ready(Some(Ok(progress))) => {
                if matches!(
                    ExecutionStatus::try_from(progress.status),
                    Ok(ExecutionStatus::Completed | ExecutionStatus::Failed)
                ) {
                    self.updates = None;
                }
                Poll::Ready(Some(Ok(ExecuteStreamEvent {
                    event: Some(execute_stream_event::Event::Progress(progress)),
                })))
            }
            Poll::Ready(Some(Err(BroadcastStreamRecvError::Lagged(skipped)))) => {
                Poll::Ready(Some(Err(Status::resource_exhausted(format!(
                    "execution stream lagged by {skipped} updates"
                )))))
            }
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

pub(crate) fn spawn_closed_monitor(
    execution_id: String,
    updates: broadcast::Sender<ExecuteProgress>,
    notify_tx: mpsc::WeakUnboundedSender<ExecutorMessage>,
) {
    tokio::spawn(async move {
        updates.closed().await;
        let Some(notify_tx) = notify_tx.upgrade() else {
            return;
        };
        let _ = notify_tx.send(ExecutorMessage::SubscriptionsClosed { execution_id });
    });
}
