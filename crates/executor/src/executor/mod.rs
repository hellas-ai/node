mod actor;
mod handle;
mod stream;

use crate::ExecutorError;
use crate::state::ExecutionStatus;
use hellas_rpc::pb::hellas::{
    ExecuteRequest, ExecuteResponse, ExecuteResultRequest, ExecuteResultResponse,
    ExecuteStatusRequest, ExecuteStatusResponse, GetModelStatsRequest, GetModelStatsResponse,
    GetQuoteRequest, GetQuoteResponse, GetStatsResponse, ListModelsResponse,
    QuoteChatPromptRequest, QuoteChatPromptResponse, QuotePromptRequest, QuotePromptResponse,
};
use tokio::sync::{mpsc, oneshot};

pub use actor::Executor;
pub(crate) use stream::{LocalExecutionStream, spawn_closed_monitor};

pub(crate) enum ExecutorMessage {
    Quote {
        request: GetQuoteRequest,
        reply: oneshot::Sender<Result<GetQuoteResponse, ExecutorError>>,
    },
    QuotePrompt {
        request: QuotePromptRequest,
        reply: oneshot::Sender<Result<QuotePromptResponse, ExecutorError>>,
    },
    QuoteChatPrompt {
        request: QuoteChatPromptRequest,
        reply: oneshot::Sender<Result<QuoteChatPromptResponse, ExecutorError>>,
    },
    Preload {
        model: String,
        reply: oneshot::Sender<Result<(), ExecutorError>>,
    },
    Subscribe {
        execution_id: String,
        reply: oneshot::Sender<Result<LocalExecutionStream, ExecutorError>>,
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
        output_chunk: Vec<u8>,
        progress: u64,
    },
    Complete {
        execution_id: String,
        output: Option<Vec<u8>>,
        status: ExecutionStatus,
        error: Option<String>,
    },
    SubscriptionsClosed {
        execution_id: String,
    },
    ListModels {
        reply: oneshot::Sender<Result<ListModelsResponse, ExecutorError>>,
    },
    GetStats {
        reply: oneshot::Sender<Result<GetStatsResponse, ExecutorError>>,
    },
    GetModelStats {
        request: GetModelStatsRequest,
        reply: oneshot::Sender<Result<GetModelStatsResponse, ExecutorError>>,
    },
}

#[derive(Clone)]
pub struct ExecutorHandle {
    pub(super) tx: mpsc::UnboundedSender<ExecutorMessage>,
}
