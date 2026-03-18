#[macro_use]
extern crate tracing;

mod backend;
pub mod catgrad_support;
mod dispatch;
mod error;
mod execute_worker;
pub mod model;
pub mod policy;
mod progress;
mod quote;
mod state;
mod weights;

pub use error::ExecutorError;
pub use hellas_rpc::pb::hellas::execute_server::ExecuteServer;
pub use model::ModelAssets;
pub use policy::{DownloadPolicy, ExecutePolicy};

use execute_worker::ExecuteWorker;
use hellas_rpc::driver::{ExecuteDriver, ExecuteProgressStream};
use state::{ExecutionStatus, ExecutorState};
use weights::WeightsManager;

use hellas_rpc::pb::hellas::execute_server::Execute;
use hellas_rpc::pb::hellas::{
    ExecuteProgress, ExecuteRequest, ExecuteResponse, ExecuteResultRequest, ExecuteResultResponse,
    ExecuteStatusRequest, ExecuteStatusResponse, GetQuoteRequest, GetQuoteResponse,
};
use std::collections::{HashMap, VecDeque};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::sync::{mpsc, oneshot};
use tokio_stream::wrappers::UnboundedReceiverStream;
use tokio_stream::{Stream, StreamExt};
use tonic::Status as TonicStatus;
use tonic::{Request, Response, Status};

pub(crate) const DEFAULT_MAX_SEQ: u32 = 16;
pub const DEFAULT_EXECUTION_QUEUE_CAPACITY: usize = 8;

enum ExecutorMessage {
    Quote {
        request: GetQuoteRequest,
        reply: oneshot::Sender<Result<GetQuoteResponse, ExecutorError>>,
    },
    Subscribe {
        execution_id: String,
        reply: oneshot::Sender<Result<(ExecuteProgress, LocalExecuteStream), ExecutorError>>,
    },
    Execute {
        request: ExecuteRequest,
        reply: oneshot::Sender<Result<ExecuteResponse, ExecutorError>>,
    },
    Status {
        request: ExecuteStatusRequest,
        reply: oneshot::Sender<Result<ExecuteStatusResponse, ExecutorError>>,
    },
    Result {
        request: ExecuteResultRequest,
        reply: oneshot::Sender<Result<ExecuteResultResponse, ExecutorError>>,
    },
    Progress {
        execution_id: String,
        chunk: Vec<u8>,
        progress: u64,
    },
    Complete {
        execution_id: String,
        result: Option<Vec<u8>>,
        status: ExecutionStatus,
    },
    WatcherClosed {
        execution_id: String,
        watcher_id: u64,
    },
}

struct Watcher {
    id: u64,
    tx: mpsc::UnboundedSender<ExecuteProgress>,
}

struct WatcherRegistration {
    execution_id: String,
    watcher_id: u64,
    notify_tx: mpsc::WeakUnboundedSender<ExecutorMessage>,
}

pub struct LocalExecuteStream {
    rx: UnboundedReceiverStream<ExecuteProgress>,
    watcher: Option<WatcherRegistration>,
}

impl LocalExecuteStream {
    fn new(
        rx: mpsc::UnboundedReceiver<ExecuteProgress>,
        watcher: Option<WatcherRegistration>,
    ) -> Self {
        Self {
            rx: UnboundedReceiverStream::new(rx),
            watcher,
        }
    }
}

impl Stream for LocalExecuteStream {
    type Item = Result<ExecuteProgress, Status>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.rx)
            .poll_next(cx)
            .map(|next| next.map(Ok))
    }
}

impl Drop for LocalExecuteStream {
    fn drop(&mut self) {
        let Some(watcher) = self.watcher.take() else {
            return;
        };
        let Some(notify_tx) = watcher.notify_tx.upgrade() else {
            return;
        };
        let _ = notify_tx.send(ExecutorMessage::WatcherClosed {
            execution_id: watcher.execution_id,
            watcher_id: watcher.watcher_id,
        });
    }
}

pub struct Executor {
    watcher_notify_tx: mpsc::WeakUnboundedSender<ExecutorMessage>,
    rx: mpsc::UnboundedReceiver<ExecutorMessage>,
    state: ExecutorState,
    watchers: HashMap<String, Vec<Watcher>>,
    pending_executions: VecDeque<execute_worker::ExecuteJob>,
    next_watcher_id: u64,
    queue_capacity: usize,
    weights: WeightsManager,
    execute_worker: ExecuteWorker,
    execute_policy: policy::ExecutePolicy,
}

impl Executor {
    pub fn spawn(
        download_policy: policy::DownloadPolicy,
        execute_policy: policy::ExecutePolicy,
        queue_capacity: usize,
    ) -> Result<ExecutorHandle, ExecutorError> {
        let (tx, rx) = mpsc::unbounded_channel();
        crate::backend::create_backend()?;
        let weights = WeightsManager::spawn(download_policy);
        let execute_worker = ExecuteWorker::spawn(tx.clone());
        let executor = Self {
            watcher_notify_tx: tx.downgrade(),
            rx,
            state: ExecutorState::new(),
            watchers: HashMap::new(),
            pending_executions: VecDeque::new(),
            next_watcher_id: 0,
            queue_capacity,
            weights,
            execute_worker,
            execute_policy,
        };
        tokio::spawn(executor.run());
        Ok(ExecutorHandle { tx })
    }

    async fn run(mut self) {
        while let Some(msg) = self.rx.recv().await {
            match msg {
                ExecutorMessage::Quote { request, reply } => {
                    let _ = reply.send(self.handle_quote(request).await);
                }
                ExecutorMessage::Subscribe {
                    execution_id,
                    reply,
                } => {
                    let _ = reply.send(self.handle_subscribe(execution_id));
                }
                ExecutorMessage::Execute { request, reply } => {
                    let _ = reply.send(self.handle_execute(request).await);
                }
                ExecutorMessage::Status { request, reply } => {
                    let _ = reply.send(self.handle_status(request));
                }
                ExecutorMessage::Result { request, reply } => {
                    let _ = reply.send(self.handle_result(request));
                }
                ExecutorMessage::Progress {
                    execution_id,
                    chunk,
                    progress,
                } => {
                    let _ = self
                        .state
                        .append_output_chunk(&execution_id, &chunk, progress);
                    self.send_progress(&execution_id, ExecutionStatus::Running, progress, chunk);
                }
                ExecutorMessage::Complete {
                    execution_id,
                    result,
                    status,
                } => {
                    self.handle_complete(execution_id, result, status);
                    self.dispatch_next_execution();
                }
                ExecutorMessage::WatcherClosed {
                    execution_id,
                    watcher_id,
                } => {
                    self.handle_watcher_closed(execution_id, watcher_id);
                }
            }
        }
    }

    fn handle_status(
        &self,
        request: ExecuteStatusRequest,
    ) -> Result<ExecuteStatusResponse, ExecutorError> {
        let status = self.state.get_status(&request.execution_id)?;
        let progress = self.state.get_progress(&request.execution_id).unwrap_or(0);
        let result_bytes = self
            .state
            .get_result(&request.execution_id)
            .map(|s| s.to_vec())
            .unwrap_or_default();
        Ok(ExecuteStatusResponse {
            status: *status as i32,
            progress,
            result: result_bytes,
        })
    }

    fn handle_result(
        &self,
        request: ExecuteResultRequest,
    ) -> Result<ExecuteResultResponse, ExecutorError> {
        let result = self.state.get_result(&request.execution_id)?;
        Ok(ExecuteResultResponse {
            result: result.to_vec(),
        })
    }
}

#[derive(Clone)]
pub struct ExecutorHandle {
    tx: mpsc::UnboundedSender<ExecutorMessage>,
}

impl ExecutorHandle {
    async fn send<T>(
        &self,
        make_msg: impl FnOnce(oneshot::Sender<Result<T, ExecutorError>>) -> ExecutorMessage,
    ) -> Result<T, ExecutorError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(make_msg(reply_tx))
            .map_err(|_| ExecutorError::ChannelClosed)?;
        reply_rx.await.map_err(|_| ExecutorError::ChannelClosed)?
    }

    pub async fn quote_local(
        &self,
        request: GetQuoteRequest,
    ) -> Result<GetQuoteResponse, ExecutorError> {
        self.send(|reply| ExecutorMessage::Quote { request, reply })
            .await
    }

    pub async fn execute_local(
        &self,
        request: ExecuteRequest,
    ) -> Result<ExecuteResponse, ExecutorError> {
        self.send(|reply| ExecutorMessage::Execute { request, reply })
            .await
    }

    pub async fn status_local(
        &self,
        request: ExecuteStatusRequest,
    ) -> Result<ExecuteStatusResponse, ExecutorError> {
        self.send(|reply| ExecutorMessage::Status { request, reply })
            .await
    }

    pub async fn result_local(
        &self,
        request: ExecuteResultRequest,
    ) -> Result<ExecuteResultResponse, ExecutorError> {
        self.send(|reply| ExecutorMessage::Result { request, reply })
            .await
    }

    pub async fn subscribe_local(
        &self,
        execution_id: String,
    ) -> Result<(ExecuteProgress, LocalExecuteStream), ExecutorError> {
        self.send(|reply| ExecutorMessage::Subscribe {
            execution_id,
            reply,
        })
        .await
    }
}

#[tonic::async_trait]
impl Execute for ExecutorHandle {
    async fn get_quote(
        &self,
        request: Request<GetQuoteRequest>,
    ) -> Result<Response<GetQuoteResponse>, Status> {
        Ok(Response::new(self.quote_local(request.into_inner()).await?))
    }

    async fn execute(
        &self,
        request: Request<ExecuteRequest>,
    ) -> Result<Response<ExecuteResponse>, Status> {
        Ok(Response::new(
            self.execute_local(request.into_inner()).await?,
        ))
    }

    async fn execute_status(
        &self,
        request: Request<ExecuteStatusRequest>,
    ) -> Result<Response<ExecuteStatusResponse>, Status> {
        Ok(Response::new(
            self.status_local(request.into_inner()).await?,
        ))
    }

    type ExecuteStreamStream =
        Pin<Box<dyn tokio_stream::Stream<Item = Result<ExecuteProgress, TonicStatus>> + Send>>;

    async fn execute_stream(
        &self,
        request: Request<ExecuteStatusRequest>,
    ) -> Result<Response<Self::ExecuteStreamStream>, Status> {
        let exec_id = request.into_inner().execution_id;
        let (initial, updates) = self.subscribe_local(exec_id).await?;
        let initial_stream = tokio_stream::once(Ok::<_, TonicStatus>(initial));
        let stream = initial_stream.chain(updates);
        Ok(Response::new(Box::pin(stream) as Self::ExecuteStreamStream))
    }

    async fn execute_result(
        &self,
        request: Request<ExecuteResultRequest>,
    ) -> Result<Response<ExecuteResultResponse>, Status> {
        Ok(Response::new(
            self.result_local(request.into_inner()).await?,
        ))
    }
}

#[tonic::async_trait]
impl ExecuteDriver for ExecutorHandle {
    async fn get_quote(&mut self, request: GetQuoteRequest) -> Result<GetQuoteResponse, Status> {
        self.quote_local(request).await.map_err(Into::into)
    }

    async fn execute_streaming(
        &mut self,
        request: ExecuteRequest,
    ) -> Result<ExecuteProgressStream, Status> {
        let execution = self.execute_local(request).await?;
        let (initial, updates) = self.subscribe_local(execution.execution_id).await?;
        let initial_stream = tokio_stream::once(Ok::<_, Status>(initial));
        Ok(Box::pin(initial_stream.chain(updates)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::ExecutionPlan;
    use crate::weights::WeightsLocator;
    use hellas_rpc::encode_token_ids;
    use hellas_rpc::pb::hellas::ExecutionStatus as RpcExecutionStatus;
    use tokio_stream::StreamExt;

    fn stub_execution_plan() -> ExecutionPlan {
        ExecutionPlan {
            graph: Vec::new(),
            model_config_json: b"{}".to_vec(),
            weights_key: WeightsLocator {
                model_id: "test-model".to_string(),
                revision: "deadbeef".to_string(),
            },
            input: Vec::new(),
            prompt_tokens: 0,
            max_new_tokens: DEFAULT_MAX_SEQ,
            stop_token_ids: Vec::new(),
        }
    }

    #[tokio::test]
    async fn quote_rejects_missing_model_id() {
        let handle = Executor::spawn(
            DownloadPolicy::default(),
            ExecutePolicy::default(),
            DEFAULT_EXECUTION_QUEUE_CAPACITY,
        )
        .expect("executor should start");

        let err = handle
            .quote_local(GetQuoteRequest {
                graph: b"test-graph".to_vec(),
                model_config_json: b"{}".to_vec(),
                ..Default::default()
            })
            .await
            .expect_err("quote should fail");
        assert!(matches!(err, ExecutorError::InvalidQuoteRequest(_)));
    }

    #[tokio::test]
    async fn execute_with_invalid_quote_fails() {
        let handle = Executor::spawn(
            DownloadPolicy::default(),
            ExecutePolicy::default(),
            DEFAULT_EXECUTION_QUEUE_CAPACITY,
        )
        .expect("executor should start");

        let result = handle
            .execute_local(ExecuteRequest {
                quote_id: "invalid-quote".to_string(),
                stream_batch_size: None,
            })
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn result_before_completion_reports_unavailable() {
        let (_tx, rx) = mpsc::unbounded_channel();
        let mut executor = Executor {
            watcher_notify_tx: mpsc::unbounded_channel::<ExecutorMessage>().0.downgrade(),
            rx,
            state: ExecutorState::new(),
            watchers: HashMap::new(),
            pending_executions: VecDeque::new(),
            next_watcher_id: 0,
            queue_capacity: DEFAULT_EXECUTION_QUEUE_CAPACITY,
            weights: WeightsManager::spawn(DownloadPolicy::default()),
            execute_worker: ExecuteWorker::stopped(),
            execute_policy: ExecutePolicy::default(),
        };

        let quote_id = executor.state.create_quote(stub_execution_plan());
        let execution_id = executor
            .state
            .create_execution(quote_id)
            .expect("execution should be created");

        let err = executor
            .handle_result(ExecuteResultRequest {
                execution_id: execution_id.clone(),
            })
            .expect_err("result should not be available yet");
        assert!(matches!(
            err,
            ExecutorError::State(state::StateError::ResultNotAvailable(id)) if id == execution_id
        ));
    }

    #[tokio::test]
    async fn subscribe_sends_snapshot_immediately() {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut executor = Executor {
            watcher_notify_tx: tx.downgrade(),
            rx,
            state: ExecutorState::new(),
            watchers: HashMap::new(),
            pending_executions: VecDeque::new(),
            next_watcher_id: 0,
            queue_capacity: DEFAULT_EXECUTION_QUEUE_CAPACITY,
            weights: WeightsManager::spawn(DownloadPolicy::default()),
            execute_worker: ExecuteWorker::stopped(),
            execute_policy: ExecutePolicy::default(),
        };

        let quote_id = executor.state.create_quote(stub_execution_plan());
        let execution_id = executor
            .state
            .create_execution(quote_id)
            .expect("execution should be created");
        executor
            .state
            .set_status(&execution_id, ExecutionStatus::Running)
            .unwrap();

        let (initial, mut updates) = executor
            .handle_subscribe(execution_id.clone())
            .expect("subscribe should succeed");

        assert_eq!(initial.status, RpcExecutionStatus::Running as i32);
        assert_eq!(initial.progress, 0);
        assert!(initial.chunk.is_empty());

        executor.send_status(&execution_id, ExecutionStatus::Completed);
        let completed = updates
            .next()
            .await
            .expect("should receive completion")
            .expect("completion should be valid");
        assert_eq!(completed.status, RpcExecutionStatus::Completed as i32);
        assert_eq!(completed.progress, 0);
        assert!(completed.chunk.is_empty());
        assert!(updates.next().await.is_none());
    }

    #[tokio::test]
    async fn subscribe_after_completion_receives_buffered_result() {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut executor = Executor {
            watcher_notify_tx: tx.downgrade(),
            rx,
            state: ExecutorState::new(),
            watchers: HashMap::new(),
            pending_executions: VecDeque::new(),
            next_watcher_id: 0,
            queue_capacity: DEFAULT_EXECUTION_QUEUE_CAPACITY,
            weights: WeightsManager::spawn(DownloadPolicy::default()),
            execute_worker: ExecuteWorker::stopped(),
            execute_policy: ExecutePolicy::default(),
        };

        let quote_id = executor.state.create_quote(stub_execution_plan());
        let execution_id = executor
            .state
            .create_execution(quote_id)
            .expect("execution should be created");
        let chunk = encode_token_ids(&[42]);
        executor
            .state
            .append_output_chunk(&execution_id, &chunk, 1)
            .unwrap();
        executor
            .state
            .set_status(&execution_id, ExecutionStatus::Completed)
            .unwrap();

        let (initial, mut updates) = executor
            .handle_subscribe(execution_id)
            .expect("subscribe should succeed");

        assert_eq!(initial.status, RpcExecutionStatus::Completed as i32);
        assert_eq!(initial.progress, 1);
        assert_eq!(initial.chunk, chunk);
        assert!(updates.next().await.is_none());
    }

    #[tokio::test]
    async fn subscribe_midstream_receives_buffered_result_and_future_updates() {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut executor = Executor {
            watcher_notify_tx: tx.downgrade(),
            rx,
            state: ExecutorState::new(),
            watchers: HashMap::new(),
            pending_executions: VecDeque::new(),
            next_watcher_id: 0,
            queue_capacity: DEFAULT_EXECUTION_QUEUE_CAPACITY,
            weights: WeightsManager::spawn(DownloadPolicy::default()),
            execute_worker: ExecuteWorker::stopped(),
            execute_policy: ExecutePolicy::default(),
        };

        let quote_id = executor.state.create_quote(stub_execution_plan());
        let execution_id = executor
            .state
            .create_execution(quote_id)
            .expect("execution should be created");
        let first_chunk = encode_token_ids(&[11]);
        executor
            .state
            .append_output_chunk(&execution_id, &first_chunk, 1)
            .unwrap();
        executor
            .state
            .set_status(&execution_id, ExecutionStatus::Running)
            .unwrap();

        let (initial, mut updates) = executor
            .handle_subscribe(execution_id.clone())
            .expect("subscribe should succeed");

        assert_eq!(initial.status, RpcExecutionStatus::Running as i32);
        assert_eq!(initial.progress, 1);
        assert_eq!(initial.chunk, first_chunk);

        let second_chunk = encode_token_ids(&[22]);
        executor.send_progress(
            &execution_id,
            ExecutionStatus::Running,
            2,
            second_chunk.clone(),
        );
        let update = updates
            .next()
            .await
            .expect("should receive progress")
            .expect("progress should be valid");
        assert_eq!(update.status, RpcExecutionStatus::Running as i32);
        assert_eq!(update.progress, 2);
        assert_eq!(update.chunk, second_chunk);
    }

    #[tokio::test]
    async fn dropped_subscription_notifies_executor() {
        let (notify_tx, mut notify_rx) = mpsc::unbounded_channel();
        let (_tx, rx) = mpsc::unbounded_channel();
        let mut executor = Executor {
            watcher_notify_tx: notify_tx.downgrade(),
            rx,
            state: ExecutorState::new(),
            watchers: HashMap::new(),
            pending_executions: VecDeque::new(),
            next_watcher_id: 0,
            queue_capacity: DEFAULT_EXECUTION_QUEUE_CAPACITY,
            weights: WeightsManager::spawn(DownloadPolicy::default()),
            execute_worker: ExecuteWorker::stopped(),
            execute_policy: ExecutePolicy::default(),
        };

        let quote_id = executor.state.create_quote(stub_execution_plan());
        let execution_id = executor
            .state
            .create_execution(quote_id)
            .expect("execution should be created");
        executor
            .state
            .set_status(&execution_id, ExecutionStatus::Pending)
            .unwrap();

        let (_initial, updates) = executor
            .handle_subscribe(execution_id.clone())
            .expect("subscribe should succeed");
        drop(updates);

        match notify_rx.recv().await {
            Some(ExecutorMessage::WatcherClosed {
                execution_id: closed_execution_id,
                watcher_id,
            }) => {
                assert_eq!(closed_execution_id, execution_id);
                assert_eq!(watcher_id, 0);
            }
            _ => panic!("unexpected executor message"),
        }
    }
}
