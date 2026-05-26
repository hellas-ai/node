mod actor;
mod handle;

use hellas_rpc::ExecutorError;
use hellas_rpc::pb::hellas::{
    ExecuteRequest, ExecuteStreamEvent, GetModelStatsRequest, GetModelStatsResponse,
    GetQuoteRequest, GetQuoteResponse, GetStatsResponse, ListModelsResponse,
    QuoteChatPromptRequest, QuoteChatPromptResponse, QuotePromptRequest, QuotePromptResponse,
};
use hellas_rpc::provenance::ExecutionProvenance;
use tokio::sync::{mpsc, oneshot};
use tonic::Status;

pub use actor::Executor;

/// Per-execution receiver returned to the streaming `Execute` consumer.
/// Dropping it closes the matching sender held by the worker, which the
/// worker observes on its next chunk send and converts into a cancel.
pub(crate) type ExecuteEventReceiver = mpsc::Receiver<Result<ExecuteStreamEvent, Status>>;

/// Quote response paired with the provenance the executor committed to.
/// `provenance` is the same value the executor logs at quote/accept time;
/// callers (the tonic Execute impl) attach it to outgoing Response
/// metadata so gateways/clients can correlate the wire response with the
/// commitment that produced it.
#[derive(Debug)]
pub struct QuoteOutcome<R> {
    pub response: R,
    pub provenance: ExecutionProvenance,
}

/// Streaming execution paired with the provenance committed to at
/// quote-acceptance time. The receipt commitment is terminal and travels
/// via the stream's final event.
#[derive(Debug)]
pub struct ExecuteOutcome {
    pub provenance: ExecutionProvenance,
    pub events: ExecuteEventReceiver,
}

pub(crate) enum ExecutorMessage {
    Quote {
        request: GetQuoteRequest,
        reply: oneshot::Sender<Result<QuoteOutcome<GetQuoteResponse>, ExecutorError>>,
    },
    QuotePrompt {
        request: QuotePromptRequest,
        reply: oneshot::Sender<Result<QuoteOutcome<QuotePromptResponse>, ExecutorError>>,
    },
    QuoteChatPrompt {
        request: QuoteChatPromptRequest,
        reply: oneshot::Sender<Result<QuoteOutcome<QuoteChatPromptResponse>, ExecutorError>>,
    },
    Preload {
        model: String,
        reply: oneshot::Sender<Result<(), ExecutorError>>,
    },
    /// Single streaming entry point: validate the quote, accept the job
    /// (queueing if the worker is busy), and return a Receiver wired to
    /// the worker's per-execution sender.
    Execute {
        request: ExecuteRequest,
        reply: oneshot::Sender<Result<ExecuteOutcome, ExecutorError>>,
    },
    /// Worker → actor: this execution finished (or was cancelled).
    /// Sole purpose is advancing the pending queue.
    WorkerIdle,
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
