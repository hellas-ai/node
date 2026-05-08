mod actor;
mod handle;

use hellas_pb::courtesy::{
    GetArtifactRequest, GetArtifactResponse, GetModelStatsRequest, GetModelStatsResponse,
    GetStatsResponse, ListModelsResponse, PutArtifactRequest, PutArtifactResponse,
    QuoteChatPromptRequest, QuoteChatPromptResponse, QuotePreparedTextRequest,
    QuotePreparedTextResponse, QuotePromptRequest, QuotePromptResponse,
};
use hellas_pb::hellas::{RunTicketRequest, Ticket, WorkEvent};
use hellas_pb::opaque::OpaqueRequest as PbOpaqueRequest;
use hellas_pb::symbolic::SymbolicRequest as PbSymbolicRequest;
use hellas_rpc::ExecutorError;
use hellas_rpc::provenance::ExecutionProvenance;
use tokio::sync::{mpsc, oneshot};
use tonic::Status;

use crate::worker::WorkerCompletion;
pub use actor::Executor;

/// Per-execution receiver returned to the streaming `Execute` consumer.
/// Dropping it closes the matching sender held by the worker, which the
/// worker observes on its next chunk send and converts into a cancel.
pub(crate) type ExecuteEventReceiver = mpsc::Receiver<Result<WorkEvent, Status>>;

/// Quote response paired with the provenance the executor committed to.
/// `provenance` is the same value the executor logs at quote/accept time;
/// callers (the tonic Execute impl) attach it to outgoing Response
/// metadata so gateways/clients can correlate the wire response with the
/// commitment that produced it.
#[derive(Debug)]
pub struct TicketOutcome<R> {
    pub response: R,
    pub provenance: ExecutionProvenance,
}

/// Streaming execution paired with the provenance committed to at
/// quote-acceptance time. The producer receipt is terminal and travels via
/// the final `WorkFinished.receipt` event — it's not part of
/// `ExecutionProvenance`.
#[derive(Debug)]
pub struct ExecuteOutcome {
    pub provenance: ExecutionProvenance,
    pub events: ExecuteEventReceiver,
}

pub(crate) enum ExecutorMessage {
    QuoteSymbolic {
        request: PbSymbolicRequest,
        reply: oneshot::Sender<Result<TicketOutcome<Ticket>, ExecutorError>>,
    },
    QuoteOpaque {
        request: PbOpaqueRequest,
        reply: oneshot::Sender<Result<TicketOutcome<Ticket>, ExecutorError>>,
    },
    QuotePrompt {
        request: QuotePromptRequest,
        reply: oneshot::Sender<Result<TicketOutcome<QuotePromptResponse>, ExecutorError>>,
    },
    QuotePreparedText {
        request: QuotePreparedTextRequest,
        reply: oneshot::Sender<Result<TicketOutcome<QuotePreparedTextResponse>, ExecutorError>>,
    },
    QuoteChatPrompt {
        request: QuoteChatPromptRequest,
        reply: oneshot::Sender<Result<TicketOutcome<QuoteChatPromptResponse>, ExecutorError>>,
    },
    PutArtifact {
        request: PutArtifactRequest,
        reply: oneshot::Sender<Result<PutArtifactResponse, ExecutorError>>,
    },
    GetArtifact {
        request: GetArtifactRequest,
        reply: oneshot::Sender<Result<GetArtifactResponse, ExecutorError>>,
    },
    Preload {
        model: String,
        reply: oneshot::Sender<Result<(), ExecutorError>>,
    },
    /// Single streaming entry point: validate the quote, accept the job
    /// (queueing if the worker is busy), and return a Receiver wired to
    /// the worker's per-execution sender.
    Execute {
        request: RunTicketRequest,
        reply: oneshot::Sender<Result<ExecuteOutcome, ExecutorError>>,
    },
    /// Worker → actor: this execution finished (or failed). The actor records
    /// terminal artifacts, signs the receipt, sends the final event, and
    /// advances the pending queue.
    WorkerFinished(WorkerCompletion),
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
