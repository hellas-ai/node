mod actor;
mod handle;
mod stream;

use crate::state::ExecutionStatus;
use crate::ExecutorError;
use hellas_rpc::pb::hellas::{
    ExecuteRequest, ExecuteResponse, ExecuteResultRequest, ExecuteResultResponse,
    ExecuteStatusRequest, ExecuteStatusResponse, GetQuoteRequest, GetQuoteResponse,
};
use tokio::sync::{mpsc, oneshot};

pub use actor::Executor;
pub(crate) use stream::{spawn_closed_monitor, LocalExecutionStream};

pub const DEFAULT_EXECUTION_QUEUE_CAPACITY: usize = 8;

pub(crate) enum ExecutorMessage {
    Quote {
        request: GetQuoteRequest,
        reply: oneshot::Sender<Result<GetQuoteResponse, ExecutorError>>,
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
    },
    SubscriptionsClosed {
        execution_id: String,
    },
}

#[derive(Clone)]
pub struct ExecutorHandle {
    pub(super) tx: mpsc::UnboundedSender<ExecutorMessage>,
}
