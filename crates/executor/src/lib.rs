#[macro_use]
extern crate tracing;

pub mod catgrad_support;
mod error;
mod execute_worker;
mod state;
mod weights;

pub use error::ExecutorError;
pub use hellas_rpc::pb::hellas::execute_server::ExecuteServer;

use execute_worker::{ExecuteJob, ExecuteWorker, ExecuteWorkerError};
use state::{ExecutionPlan, ExecutionStatus, ExecutorState, StateError};
use weights::{default_ref_cached, EnsureDisposition, ModelId, WeightsManager};

use hellas_rpc::pb::hellas::execute_server::Execute;
use hellas_rpc::pb::hellas::{
    get_quote_request, ExecuteProgress, ExecuteRequest, ExecuteResponse, ExecuteResultRequest,
    ExecuteResultResponse, ExecuteStatusRequest, ExecuteStatusResponse, GetGraphRequest,
    GetGraphResponse, GetQuoteRequest, GetQuoteResponse, WeightsHint as RpcWeightsHint,
};
use std::collections::HashMap;
use std::pin::Pin;
use tokio::sync::{mpsc, oneshot};
use tokio_stream::StreamExt;
use tonic::Status as TonicStatus;
use tonic::{Request, Response, Status};

const DEFAULT_MAX_SEQ: u32 = 16;

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
        success: bool,
    },
}

pub struct Executor {
    rx: mpsc::UnboundedReceiver<ExecutorMessage>,
    state: ExecutorState,
    watchers: HashMap<String, Vec<mpsc::UnboundedSender<ExecuteProgress>>>,
    weights: WeightsManager,
    execute_worker: ExecuteWorker,
}

impl Executor {
    pub fn spawn() -> ExecutorHandle {
        let (tx, rx) = mpsc::unbounded_channel();
        let weights = WeightsManager::spawn();
        let execute_worker = ExecuteWorker::spawn(tx.clone());
        let executor = Self {
            rx,
            state: ExecutorState::new(),
            watchers: HashMap::new(),
            weights,
            execute_worker,
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
                    success,
                } => {
                    self.handle_complete(execution_id, result, decoded, success);
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

    fn handle_subscribe(
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

    async fn handle_quote(
        &mut self,
        request: GetQuoteRequest,
    ) -> Result<GetQuoteResponse, ExecutorError> {
        let payload = request.payload.ok_or(ExecutorError::MissingPayload)?;

        enum QuoteKind {
            Graph,
            Llm { model_id: String, max_seq: u32 },
        }

        let (graph, input, weights_hint, max_seq, kind) = match payload {
            get_quote_request::Payload::Graph(graph) => (
                graph,
                String::new(),
                None,
                DEFAULT_MAX_SEQ,
                QuoteKind::Graph,
            ),
            get_quote_request::Payload::LlmPrompt(llm) => {
                let max_seq = if llm.max_seq == 0 {
                    DEFAULT_MAX_SEQ
                } else {
                    llm.max_seq
                };

                let model_id = llm.huggingface_model_id.clone();
                let model_id_typed = ModelId(model_id.clone());
                let disposition = self
                    .weights
                    .ensure_default_ready(model_id_typed.clone())
                    .await;

                let key = match disposition {
                    EnsureDisposition::Ready(key) => key,
                    EnsureDisposition::Queued | EnsureDisposition::InFlight => {
                        if default_ref_cached(&model_id) {
                            let key = self
                                .weights
                                .ensure_default_ready_wait(
                                    model_id_typed,
                                    tokio::time::Duration::from_secs(2),
                                )
                                .await
                                .map_err(|e| match e {
                                    weights::WeightsError::NotReady => {
                                        ExecutorError::WeightsNotReady(model_id.clone())
                                    }
                                    other => ExecutorError::WeightsError(other.to_string()),
                                })?;
                            key
                        } else {
                            return Err(ExecutorError::WeightsNotReady(model_id));
                        }
                    }
                    EnsureDisposition::Failed(err) => {
                        return Err(ExecutorError::WeightsError(err));
                    }
                };

                let bundle = self
                    .weights
                    .bundle(&key)
                    .await
                    .map_err(|e| ExecutorError::WeightsError(e.to_string()))?;

                let (graph_bytes, templated_input) = catgrad_support::build_graph_from_llm_prompt(
                    bundle.as_ref(),
                    &llm.prompt,
                    max_seq,
                )?;

                (
                    graph_bytes,
                    templated_input,
                    Some(key),
                    max_seq,
                    QuoteKind::Llm { model_id, max_seq },
                )
            }
        };

        let plan = ExecutionPlan {
            graph: graph.clone(),
            weights_hint: weights_hint.clone(),
            input: input.clone(),
            max_seq,
        };
        let graph_id = format!("{:x}", simple_hash(&graph));
        let amount = 1000; // stub
        let quote_id = self.state.create_quote(graph_id.clone(), plan);

        match kind {
            QuoteKind::Graph => {
                info!(%quote_id, %graph_id, amount, "quoted raw graph");
            }
            QuoteKind::Llm { model_id, max_seq } => {
                info!(
                    %quote_id,
                    %graph_id,
                    amount,
                    model = model_id,
                    max_seq,
                    input_len = input.len(),
                    "quoted llm prompt"
                );
            }
        }

        Ok(GetQuoteResponse {
            quote_id,
            graph_id,
            amount,
            input,
            resolved_weights: weights_hint.map(|hint| RpcWeightsHint {
                huggingface_model_id: hint.model_id.0,
                revision: hint.revision.0,
            }),
        })
    }

    async fn handle_execute(
        &mut self,
        request: ExecuteRequest,
    ) -> Result<ExecuteResponse, ExecutorError> {
        let quote_id = String::from_utf8_lossy(&request.quote_id).to_string();
        let plan = self.state.get_quote(&quote_id)?.plan.clone();

        if self.execute_worker.is_busy() {
            return Err(ExecutorError::Busy);
        }

        let bundle = match plan.weights_hint.clone() {
            Some(key) => Some(self.weights.bundle(&key).await.map_err(|e| match e {
                weights::WeightsError::NotReady => {
                    ExecutorError::WeightsNotReady(key.model_id.0.clone())
                }
                weights::WeightsError::Failed(msg) => ExecutorError::WeightsError(msg),
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

    fn handle_complete(
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
            status: status.as_str().to_string(),
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

    fn send_progress(
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

    fn send_status(&mut self, execution_id: &str, status: ExecutionStatus) {
        let progress = self.state.get_progress(execution_id).unwrap_or(0);
        self.send_progress(execution_id, status, progress, Vec::new(), None);
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

fn simple_hash(data: &[u8]) -> u64 {
    let mut hash: u64 = 0;
    for (i, &byte) in data.iter().enumerate() {
        hash = hash.wrapping_add((byte as u64).wrapping_mul(31_u64.wrapping_pow(i as u32)));
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn quote_and_execute() {
        let handle = Executor::spawn();

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
                quote_id: quote.quote_id.as_bytes().to_vec(),
            })
            .await
            .expect("should return execution");
        assert!(exec.execution_id.starts_with("exec-"));
        assert_eq!(exec.quote_id, quote.quote_id);
    }

    #[tokio::test]
    async fn execute_with_invalid_quote_fails() {
        let handle = Executor::spawn();

        let result = handle
            .execute(ExecuteRequest {
                quote_id: b"invalid-quote".to_vec(),
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
            weights: WeightsManager::spawn(),
            execute_worker: ExecuteWorker::spawn(tx2),
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

        assert_eq!(initial.status, "running");
        assert_eq!(initial.progress, 0);
        assert!(initial.chunk.is_empty());
        assert!(initial.decoded.is_none());

        executor.send_status(&execution_id, ExecutionStatus::Completed);
        let completed = updates.recv().await.expect("should receive completion");
        assert_eq!(completed.status, "completed");
        assert_eq!(completed.progress, 0);
        assert!(completed.chunk.is_empty());
        assert!(completed.decoded.is_none());
        assert!(updates.recv().await.is_none());
    }
}
