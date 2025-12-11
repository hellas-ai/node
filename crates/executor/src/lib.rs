#[macro_use]
extern crate tracing;

mod error;
mod state;

pub use error::ExecutorError;
pub use hellas_rpc::pb::hellas::execute_server::ExecuteServer;

use state::ExecutorState;

use hellas_rpc::pb::hellas::execute_server::Execute;
use hellas_rpc::pb::hellas::{
    ExecuteRequest, ExecuteResponse, ExecuteResultRequest, ExecuteResultResponse,
    ExecuteStatusRequest, ExecuteStatusResponse, GetQuoteRequest, GetQuoteResponse,
};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tonic::{Request, Response, Status};

enum ExecutorMessage {
    Quote {
        request: GetQuoteRequest,
        reply: oneshot::Sender<Result<GetQuoteResponse, ExecutorError>>,
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
    Complete {
        execution_id: String,
        result: String,
    },
}

pub struct Executor {
    tx: mpsc::UnboundedSender<ExecutorMessage>,
    rx: mpsc::UnboundedReceiver<ExecutorMessage>,
    state: ExecutorState,
}

impl Executor {
    pub fn spawn() -> ExecutorHandle {
        let (tx, rx) = mpsc::unbounded_channel();
        let executor = Self {
            tx: tx.clone(),
            rx,
            state: ExecutorState::new(),
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
                ExecutorMessage::Execute { request, reply } => {
                    let _ = reply.send(self.handle_execute(request));
                }
                ExecutorMessage::Status { request, reply } => {
                    let _ = reply.send(self.handle_status(request));
                }
                ExecutorMessage::Result { request, reply } => {
                    let _ = reply.send(self.handle_result(request));
                }
                ExecutorMessage::Complete { execution_id, result } => {
                    self.handle_complete(execution_id, result);
                }
            }
        }
    }

    fn handle_quote(&mut self, request: GetQuoteRequest) -> Result<GetQuoteResponse, ExecutorError> {
        let graph_id = format!("{:x}", simple_hash(&request.graph));
        let amount = 1000; // stub
        let quote_id = self.state.create_quote(graph_id.clone(), amount);

        Ok(GetQuoteResponse {
            quote_id,
            graph_id,
            amount,
        })
    }

    fn handle_execute(&mut self, request: ExecuteRequest) -> Result<ExecuteResponse, ExecutorError> {
        let quote_id = String::from_utf8_lossy(&request.quote_id).to_string();
        let execution_id = self.state.create_execution(quote_id.clone())?;

        // Spawn timer to complete after 3s
        let tx = self.tx.clone();
        let exec_id = execution_id.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(3)).await;
            if let Err(e) = tx.send(ExecutorMessage::Complete {
                execution_id: exec_id.clone(),
                result: "done".to_string(),
            }) {
                warn!("failed to send completion for {exec_id}: {e}");
            }
        });

        Ok(ExecuteResponse {
            execution_id,
            quote_id,
        })
    }

    fn handle_complete(&mut self, execution_id: String, result: String) {
        if let Err(e) = self.state.set_status(&execution_id, state::ExecutionStatus::Completed) {
            warn!("failed to set status for {execution_id}: {e}");
            return;
        }
        if let Err(e) = self.state.set_result(&execution_id, result) {
            warn!("failed to set result for {execution_id}: {e}");
        }
    }

    fn handle_status(
        &self,
        request: ExecuteStatusRequest,
    ) -> Result<ExecuteStatusResponse, ExecutorError> {
        let status = self.state.get_status(&request.execution_id)?;
        Ok(ExecuteStatusResponse {
            status: status.as_str().to_string(),
        })
    }

    fn handle_result(
        &self,
        request: ExecuteResultRequest,
    ) -> Result<ExecuteResultResponse, ExecutorError> {
        let result = self.state.get_result(&request.execution_id)?;
        Ok(ExecuteResultResponse {
            result: result.to_string(),
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
}

#[tonic::async_trait]
impl Execute for ExecutorHandle {
    async fn get_quote(
        &self,
        request: Request<GetQuoteRequest>,
    ) -> Result<Response<GetQuoteResponse>, Status> {
        Ok(Response::new(self.quote(request.into_inner()).await?))
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
                graph: b"test-graph".to_vec(),
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
