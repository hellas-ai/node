#[macro_use]
extern crate tracing;

mod backend;
pub mod catgrad_support;
mod dispatch;
mod error;
mod execute_worker;
pub mod policy;
mod progress;
mod quote;
mod state;
mod weights;

pub use error::ExecutorError;
pub use hellas_rpc::pb::hellas::execute_server::ExecuteServer;
pub use policy::{DownloadPolicy, ExecutePolicy};

use execute_worker::ExecuteWorker;
use state::{ExecutionStatus, ExecutorState, StateError};
use weights::WeightsManager;

use hellas_rpc::pb::hellas::execute_server::Execute;
use hellas_rpc::pb::hellas::{
    ExecuteProgress, ExecuteRequest, ExecuteResponse, ExecuteResultRequest, ExecuteResultResponse,
    ExecuteStatusRequest, ExecuteStatusResponse, GetGraphRequest, GetGraphResponse,
    GetQuoteRequest, GetQuoteResponse,
};
use std::collections::HashMap;
use std::pin::Pin;
use tokio::sync::{mpsc, oneshot};
use tokio_stream::StreamExt;
use tonic::Status as TonicStatus;
use tonic::{Request, Response, Status};

pub(crate) const DEFAULT_MAX_SEQ: u32 = 16;

enum ExecutorMessage {
    Quote {
        request: GetQuoteRequest,
        reply: oneshot::Sender<Result<GetQuoteResponse, ExecutorError>>,
    },
    Graph {
        request: GetGraphRequest,
        reply: oneshot::Sender<Result<GetGraphResponse, ExecutorError>>,
    },
    Subscribe {
        execution_id: String,
        reply: oneshot::Sender<
            Result<(ExecuteProgress, mpsc::UnboundedReceiver<ExecuteProgress>), ExecutorError>,
        >,
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
        decoded_chunk: Option<String>,
        progress: u64,
    },
    Complete {
        execution_id: String,
        result: Option<Vec<u8>>,
        decoded: Option<String>,
        status: ExecutionStatus,
    },
}

pub struct Executor {
    rx: mpsc::UnboundedReceiver<ExecutorMessage>,
    state: ExecutorState,
    watchers: HashMap<String, Vec<mpsc::UnboundedSender<ExecuteProgress>>>,
    weights: WeightsManager,
    execute_worker: ExecuteWorker,
    execute_policy: policy::ExecutePolicy,
}

impl Executor {
    pub fn spawn(
        download_policy: policy::DownloadPolicy,
        execute_policy: policy::ExecutePolicy,
    ) -> ExecutorHandle {
        let (tx, rx) = mpsc::unbounded_channel();
        let _ = crate::backend::create_backend();
        let weights = WeightsManager::spawn(download_policy);
        let execute_worker = ExecuteWorker::spawn(tx.clone());
        let executor = Self {
            rx,
            state: ExecutorState::new(),
            watchers: HashMap::new(),
            weights,
            execute_worker,
            execute_policy,
        };
        tokio::spawn(executor.run());
        ExecutorHandle { tx }
    }

    async fn run(mut self) {
        while let Some(msg) = self.rx.recv().await {
            match msg {
                ExecutorMessage::Quote { request, reply } => {
                    let _ = reply.send(self.handle_quote(request).await);
                }
                ExecutorMessage::Graph { request, reply } => {
                    let _ = reply.send(self.handle_graph(request));
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
                    decoded_chunk,
                    progress,
                } => {
                    let _ = self.state.append_output_chunk(
                        &execution_id,
                        &chunk,
                        decoded_chunk.as_deref(),
                        progress,
                    );
                    self.send_progress(
                        &execution_id,
                        ExecutionStatus::Running,
                        progress,
                        chunk,
                        decoded_chunk,
                    );
                }
                ExecutorMessage::Complete {
                    execution_id,
                    result,
                    decoded,
                    status,
                } => {
                    self.handle_complete(execution_id, result, decoded, status);
                }
            }
        }
    }

    fn handle_graph(&self, request: GetGraphRequest) -> Result<GetGraphResponse, ExecutorError> {
        let graph = self
            .state
            .get_graph(&request.graph_id)
            .cloned()
            .ok_or_else(|| ExecutorError::State(StateError::QuoteNotFound(request.graph_id)))?;
        Ok(GetGraphResponse { graph })
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
        let decoded = self
            .state
            .get_decoded(&request.execution_id)?
            .map(|s| s.to_string());
        Ok(ExecuteStatusResponse {
            status: *status as i32,
            progress,
            result: result_bytes,
            decoded,
        })
    }

    fn handle_result(
        &self,
        request: ExecuteResultRequest,
    ) -> Result<ExecuteResultResponse, ExecutorError> {
        let result = self.state.get_result(&request.execution_id)?;
        let decoded = self
            .state
            .get_decoded(&request.execution_id)?
            .unwrap_or_default();
        Ok(ExecuteResultResponse {
            result: result.to_vec(),
            decoded: decoded.to_string(),
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

    async fn quote(&self, request: GetQuoteRequest) -> Result<GetQuoteResponse, ExecutorError> {
        self.send(|reply| ExecutorMessage::Quote { request, reply })
            .await
    }

    async fn graph(&self, request: GetGraphRequest) -> Result<GetGraphResponse, ExecutorError> {
        self.send(|reply| ExecutorMessage::Graph { request, reply })
            .await
    }

    async fn execute(&self, request: ExecuteRequest) -> Result<ExecuteResponse, ExecutorError> {
        self.send(|reply| ExecutorMessage::Execute { request, reply })
            .await
    }

    async fn status(
        &self,
        request: ExecuteStatusRequest,
    ) -> Result<ExecuteStatusResponse, ExecutorError> {
        self.send(|reply| ExecutorMessage::Status { request, reply })
            .await
    }

    async fn result(
        &self,
        request: ExecuteResultRequest,
    ) -> Result<ExecuteResultResponse, ExecutorError> {
        self.send(|reply| ExecutorMessage::Result { request, reply })
            .await
    }

    async fn subscribe(
        &self,
        execution_id: String,
    ) -> Result<(ExecuteProgress, mpsc::UnboundedReceiver<ExecuteProgress>), ExecutorError> {
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
        Ok(Response::new(self.quote(request.into_inner()).await?))
    }

    async fn get_graph(
        &self,
        request: Request<GetGraphRequest>,
    ) -> Result<Response<GetGraphResponse>, Status> {
        Ok(Response::new(self.graph(request.into_inner()).await?))
    }

    async fn execute(
        &self,
        request: Request<ExecuteRequest>,
    ) -> Result<Response<ExecuteResponse>, Status> {
        Ok(Response::new(self.execute(request.into_inner()).await?))
    }

    async fn execute_status(
        &self,
        request: Request<ExecuteStatusRequest>,
    ) -> Result<Response<ExecuteStatusResponse>, Status> {
        Ok(Response::new(self.status(request.into_inner()).await?))
    }

    type ExecuteStreamStream =
        Pin<Box<dyn tokio_stream::Stream<Item = Result<ExecuteProgress, TonicStatus>> + Send>>;

    async fn execute_stream(
        &self,
        request: Request<ExecuteStatusRequest>,
    ) -> Result<Response<Self::ExecuteStreamStream>, Status> {
        let exec_id = request.into_inner().execution_id;
        let (initial, rx) = self.subscribe(exec_id).await?;
        let initial_stream = tokio_stream::once(Ok::<_, TonicStatus>(initial));
        let updates =
            tokio_stream::wrappers::UnboundedReceiverStream::new(rx).map(Ok::<_, TonicStatus>);
        let stream = initial_stream.chain(updates);
        Ok(Response::new(Box::pin(stream) as Self::ExecuteStreamStream))
    }

    async fn execute_result(
        &self,
        request: Request<ExecuteResultRequest>,
    ) -> Result<Response<ExecuteResultResponse>, Status> {
        Ok(Response::new(self.result(request.into_inner()).await?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::ExecutionPlan;
    use hellas_rpc::pb::hellas::{get_quote_request, ExecutionStatus as RpcExecutionStatus};

    #[tokio::test]
    async fn quote_and_execute() {
        let handle =
            Executor::spawn(DownloadPolicy::default(), ExecutePolicy::default());

        // Get quote
        let quote = handle
            .quote(GetQuoteRequest {
                payload: Some(get_quote_request::Payload::Graph(b"test-graph".to_vec())),
            })
            .await
            .expect("should return quote");
        assert!(quote.quote_id.starts_with("quote-"));

        // Execute with quote
        let exec = handle
            .execute(ExecuteRequest {
                quote_id: quote.quote_id.clone(),
            })
            .await
            .expect("should return execution");
        assert!(exec.execution_id.starts_with("exec-"));
        assert_eq!(exec.quote_id, quote.quote_id);
    }

    #[tokio::test]
    async fn execute_with_invalid_quote_fails() {
        let handle =
            Executor::spawn(DownloadPolicy::default(), ExecutePolicy::default());

        let result = handle
            .execute(ExecuteRequest {
                quote_id: "invalid-quote".to_string(),
            })
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn subscribe_sends_snapshot_immediately() {
        let (tx, rx) = mpsc::unbounded_channel();
        let tx2 = tx.clone();
        let mut executor = Executor {
            rx,
            state: ExecutorState::new(),
            watchers: HashMap::new(),
            weights: WeightsManager::spawn(DownloadPolicy::default()),
            execute_worker: ExecuteWorker::spawn(tx2),
            execute_policy: ExecutePolicy::default(),
        };

        let quote_id = executor.state.create_quote(
            "graph-0".to_string(),
            ExecutionPlan {
                graph: Vec::new(),
                weights_hint: None,
                input: String::new(),
                max_seq: DEFAULT_MAX_SEQ,
            },
        );
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
        assert!(initial.decoded.is_none());

        executor.send_status(&execution_id, ExecutionStatus::Completed);
        let completed = updates.recv().await.expect("should receive completion");
        assert_eq!(completed.status, RpcExecutionStatus::Completed as i32);
        assert_eq!(completed.progress, 0);
        assert!(completed.chunk.is_empty());
        assert!(completed.decoded.is_none());
        assert!(updates.recv().await.is_none());
    }
}
