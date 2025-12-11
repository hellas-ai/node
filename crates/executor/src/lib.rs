#[macro_use]
extern crate tracing;

pub mod catgrad_support;
mod error;
mod state;

pub use error::ExecutorError;
pub use hellas_rpc::pb::hellas::execute_server::ExecuteServer;

use ::catgrad::category::lang::TypedTerm;
use state::{ExecutionPlan, ExecutionStatus, ExecutorState, StateError, WeightsHint};

use hellas_rpc::pb::hellas::execute_server::Execute;
use hellas_rpc::pb::hellas::{
    get_quote_request, ExecuteRequest, ExecuteResponse, ExecuteResultRequest,
    ExecuteResultResponse, ExecuteStatusDiff, ExecuteStatusRequest, ExecuteStatusResponse,
    GetGraphRequest, GetGraphResponse, GetQuoteRequest, GetQuoteResponse, LlmpQuoteRequest,
    WeightsHint as RpcWeightsHint,
};
use tokio::sync::{mpsc, oneshot};
use tonic::{Request, Response, Status};
use tonic::Status as TonicStatus;
use std::pin::Pin;
use tokio_stream::StreamExt;

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
        reply: oneshot::Sender<Result<mpsc::UnboundedReceiver<ExecuteStatusDiff>, ExecutorError>>,
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
        result: String,
        decoded: Option<String>,
    },
    Complete {
        execution_id: String,
        result: String,
        decoded: Option<String>,
        success: bool,
    },
}

pub struct Executor {
    tx: mpsc::UnboundedSender<ExecutorMessage>,
    rx: mpsc::UnboundedReceiver<ExecutorMessage>,
    state: ExecutorState,
    watchers: std::collections::HashMap<String, Vec<mpsc::UnboundedSender<ExecuteStatusDiff>>>,
}

impl Executor {
    pub fn spawn() -> ExecutorHandle {
        let (tx, rx) = mpsc::unbounded_channel();
        let executor = Self {
            tx: tx.clone(),
            rx,
            state: ExecutorState::new(),
            watchers: std::collections::HashMap::new(),
        };
        tokio::spawn(executor.run());
        ExecutorHandle { tx }
    }

    async fn run(mut self) {
        while let Some(msg) = self.rx.recv().await {
            match msg {
                ExecutorMessage::Quote { request, reply } => {
                    let _ = reply.send(self.handle_quote(request));
                }
                ExecutorMessage::Graph { request, reply } => {
                    let _ = reply.send(self.handle_graph(request));
                }
                ExecutorMessage::Subscribe { execution_id, reply } => {
                    let _ = reply.send(self.handle_subscribe(execution_id));
                }
                ExecutorMessage::Execute { request, reply } => {
                    let _ = reply.send(self.handle_execute(request));
                }
                ExecutorMessage::Status { request, reply } => {
                    let _ = reply.send(self.handle_status(request));
                }
                ExecutorMessage::Result { request, reply } => {
                    let _ = reply.send(self.handle_result(request));
                }
                ExecutorMessage::Progress {
                    execution_id,
                    result,
                    decoded,
                } => {
                    let _ = self.state.set_result(&execution_id, result, decoded);
                    self.send_diff(&execution_id, ExecutionStatus::Running);
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
    ) -> Result<mpsc::UnboundedReceiver<ExecuteStatusDiff>, ExecutorError> {
        // Validate existence and grab current snapshot
        let status = self.state.get_status(&execution_id)?;
        let result = self
            .state
            .get_result(&execution_id)
            .map(|s| s.as_bytes().to_vec())
            .unwrap_or_default();
        let decoded = self
            .state
            .get_decoded(&execution_id)?
            .unwrap_or_default()
            .to_string();

        let (tx, rx) = mpsc::unbounded_channel();
        // Send initial snapshot
        let initial = ExecuteStatusDiff {
            status: status.as_str().to_string(),
            result,
            decoded,
        };
        let _ = tx.send(initial);

        self.watchers
            .entry(execution_id)
            .or_default()
            .push(tx);

        Ok(rx)
    }

    fn handle_quote(
        &mut self,
        request: GetQuoteRequest,
    ) -> Result<GetQuoteResponse, ExecutorError> {
        let (graph, input, weights_hint, max_seq, is_llm) = match request
            .payload
            .as_ref()
            .ok_or_else(|| ExecutorError::Execution("quote payload missing".into()))?
        {
            get_quote_request::Payload::Graph(graph) => {
                serde_json::from_slice::<TypedTerm>(graph)
                    .map_err(ExecutorError::InvalidGraph)?;
                (
                    graph.clone(),
                    String::new(),
                    None,
                    DEFAULT_MAX_SEQ,
                    false,
                )
            }
            get_quote_request::Payload::LlmPrompt(LlmpQuoteRequest {
                huggingface_model_id,
                revision,
                prompt,
                max_seq,
            }) => {
                let max_seq = if *max_seq == 0 { DEFAULT_MAX_SEQ } else { *max_seq };
                let revision = if revision.is_empty() {
                    None
                } else {
                    Some(revision.clone())
                };

                let (graph_bytes, templated_input) = catgrad_support::build_graph_from_llm_prompt(
                    huggingface_model_id,
                    prompt,
                    max_seq,
                    revision.as_deref(),
                )
                .map_err(|e| ExecutorError::Execution(e.to_string()))?;

                let weights_hint = Some(WeightsHint {
                    huggingface_model_id: huggingface_model_id.clone(),
                    revision,
                });

                (
                    graph_bytes,
                    templated_input,
                    weights_hint,
                    max_seq,
                    true,
                )
            }
        };

        let plan = ExecutionPlan {
            graph: graph.clone(),
            weights_hint: weights_hint.clone(),
            input: input.clone(),
            max_seq,
            is_llm,
        };
        let graph_id = format!("{:x}", simple_hash(&graph));
        let amount = 1000; // stub
        let quote_id = self.state.create_quote(graph_id.clone(), amount, plan);

        match request.payload.as_ref().unwrap() {
            get_quote_request::Payload::Graph(_) => {
                info!(%quote_id, %graph_id, amount, "quoted raw graph");
            }
            get_quote_request::Payload::LlmPrompt(llm) => {
                info!(
                    %quote_id,
                    %graph_id,
                    amount,
                    model = llm.huggingface_model_id,
                    revision = llm.revision,
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
                huggingface_model_id: hint.huggingface_model_id,
                revision: hint.revision.unwrap_or_default(),
            }),
        })
    }

    fn handle_execute(
        &mut self,
        request: ExecuteRequest,
    ) -> Result<ExecuteResponse, ExecutorError> {
        let quote_id = String::from_utf8_lossy(&request.quote_id).to_string();
        let execution_id = self.state.create_execution(quote_id.clone())?;
        let plan = self.state.get_quote(&quote_id)?.plan.clone();
        self.state
            .set_status(&execution_id, ExecutionStatus::Running)?;

        info!(
            %execution_id,
            %quote_id,
            is_llm = plan.is_llm,
            input_len = plan.input.len(),
            "starting execution"
        );

        let tx = self.tx.clone();
        let exec_id = execution_id.clone();
        tokio::spawn(async move {
            let (result, decoded, success) =
                match execute_plan(&exec_id, plan, tx.clone()).await {
                    Ok((result, decoded)) => (result, decoded, true),
                    Err(err) => (err.to_string(), None, false),
                };
            if let Err(e) = tx.send(ExecutorMessage::Complete {
                execution_id: exec_id.clone(),
                result,
                decoded,
                success,
            }) {
                warn!("failed to send completion for {exec_id}: {e}");
            }
        });

        Ok(ExecuteResponse {
            execution_id,
            quote_id,
        })
    }

    fn handle_complete(
        &mut self,
        execution_id: String,
        result: String,
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
        if let Err(e) = self.state.set_result(&execution_id, result, decoded) {
            warn!("failed to set result for {execution_id}: {e}");
        }
        self.send_diff(&execution_id, status);
    }

    fn handle_status(
        &self,
        request: ExecuteStatusRequest,
    ) -> Result<ExecuteStatusResponse, ExecutorError> {
        let status = self.state.get_status(&request.execution_id)?;
        let result_bytes = self
            .state
            .get_result(&request.execution_id)
            .map(|s| s.as_bytes().to_vec())
            .unwrap_or_default();
        let decoded = self
            .state
            .get_decoded(&request.execution_id)?
            .unwrap_or_default()
            .to_string();
        Ok(ExecuteStatusResponse {
            status: status.as_str().to_string(),
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
            result: result.to_string(),
            decoded: decoded.to_string(),
        })
    }

    fn send_diff(&mut self, execution_id: &str, status: ExecutionStatus) {
        if let Some(watchers) = self.watchers.get_mut(execution_id) {
            let result = self
                .state
                .get_result(execution_id)
                .map(|s| s.as_bytes().to_vec())
                .unwrap_or_default();
            let decoded = self
                .state
                .get_decoded(execution_id)
                .unwrap_or(None)
                .unwrap_or_default()
                .to_string();

            watchers.retain(|tx| tx.send(ExecuteStatusDiff {
                status: status.as_str().to_string(),
                result: result.clone(),
                decoded: decoded.clone(),
            })
            .is_ok());

            if matches!(status, ExecutionStatus::Completed | ExecutionStatus::Failed) {
                self.watchers.remove(execution_id);
            }
        }
    }
}

async fn execute_plan(
    execution_id: &str,
    plan: ExecutionPlan,
    tx: mpsc::UnboundedSender<ExecutorMessage>,
) -> Result<(String, Option<String>), ExecutorError> {
    let term: TypedTerm =
        serde_json::from_slice(&plan.graph).map_err(ExecutorError::InvalidGraph)?;

    let prompt = plan.input.clone();

    let model_id = plan
        .weights_hint
        .as_ref()
        .map(|hint| hint.huggingface_model_id.clone())
        .ok_or_else(|| ExecutorError::Execution("weights hint missing model id".into()))?;

    let mut last = String::new();
    let revision = plan
        .weights_hint
        .as_ref()
        .and_then(|hint| hint.revision.as_deref());

    catgrad_support::run_graph_streaming(
        &model_id,
        &prompt,
        &term,
        plan.max_seq,
        revision,
        |partial, _done| {
            last = partial.to_string();
            let _ = tx.send(ExecutorMessage::Progress {
                execution_id: execution_id.to_string(),
                result: partial.to_string(),
                decoded: plan.is_llm.then(|| partial.to_string()),
            });
        },
    )
    .map_err(|e| ExecutorError::Execution(e.to_string()))?;

    let decoded = plan.is_llm.then(|| last.clone());
    Ok((last, decoded))
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
    ) -> Result<mpsc::UnboundedReceiver<ExecuteStatusDiff>, ExecutorError> {
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
        Pin<Box<dyn tokio_stream::Stream<Item = Result<ExecuteStatusDiff, TonicStatus>> + Send>>;

    async fn execute_stream(
        &self,
        request: Request<ExecuteStatusRequest>,
    ) -> Result<Response<Self::ExecuteStreamStream>, Status> {
        let exec_id = request.into_inner().execution_id;
        let rx = self.subscribe(exec_id).await?;
        let stream = tokio_stream::wrappers::UnboundedReceiverStream::new(rx).map(Ok);
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
                payload: Some(get_quote_request::Payload::Graph(
                    b"test-graph".to_vec(),
                )),
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
}
