mod error;

pub use error::ExecutorError;
pub use hellas_rpc::pb::hellas::quote_server::QuoteServer;

use hellas_rpc::pb::hellas::quote_server::Quote;
use hellas_rpc::pb::hellas::{GetQuoteRequest, GetQuoteResponse};
use tokio::sync::{mpsc, oneshot};
use tonic::{Request, Response, Status};

struct ExecutorMessage {
    request: GetQuoteRequest,
    reply: oneshot::Sender<Result<GetQuoteResponse, ExecutorError>>,
}

pub struct Executor {
    rx: mpsc::UnboundedReceiver<ExecutorMessage>,
}

impl Executor {
    pub fn spawn() -> ExecutorHandle {
        let (tx, rx) = mpsc::unbounded_channel();
        let executor = Self { rx };
        tokio::spawn(executor.run());
        ExecutorHandle { tx }
    }

    async fn run(mut self) {
        while let Some(msg) = self.rx.recv().await {
            let response = self.handle_quote(msg.request);
            let _ = msg.reply.send(response);
        }
    }

    fn handle_quote(&self, request: GetQuoteRequest) -> Result<GetQuoteResponse, ExecutorError> {
        let graph_id = format!("{:x}", simple_hash(&request.graph));
        let quote_id = format!("quote-{graph_id}-{}", random_suffix());

        Ok(GetQuoteResponse {
            quote_id,
            graph_id,
            amount: 1000,
        })
    }
}

#[derive(Clone)]
pub struct ExecutorHandle {
    tx: mpsc::UnboundedSender<ExecutorMessage>,
}

impl ExecutorHandle {
    async fn get_quote(
        &self,
        request: GetQuoteRequest,
    ) -> Result<GetQuoteResponse, ExecutorError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(ExecutorMessage {
                request,
                reply: reply_tx,
            })
            .map_err(|_| ExecutorError::ChannelClosed)?;
        reply_rx.await.map_err(|_| ExecutorError::ChannelClosed)?
    }
}

#[tonic::async_trait]
impl Quote for ExecutorHandle {
    async fn get_quote(
        &self,
        request: Request<GetQuoteRequest>,
    ) -> Result<Response<GetQuoteResponse>, Status> {
        Ok(Response::new(self.get_quote(request.into_inner()).await?))
    }
}

fn simple_hash(data: &[u8]) -> u64 {
    let mut hash: u64 = 0;
    for (i, &byte) in data.iter().enumerate() {
        hash = hash.wrapping_add((byte as u64).wrapping_mul(31_u64.wrapping_pow(i as u32)));
    }
    hash
}

fn random_suffix() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn get_quote_returns_response() {
        let handle = Executor::spawn();
        let response = handle.get_quote(GetQuoteRequest { graph: vec![1, 2, 3] }).await;

        let response = response.expect("should return quote");
        assert!(response.quote_id.starts_with("quote-"));
        assert!(!response.graph_id.is_empty());
        assert_eq!(response.amount, 1000);
    }
}
