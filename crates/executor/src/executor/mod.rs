mod actor;
mod handle;

use crate::ExecutorError;
#[cfg(feature = "evaluate")]
use hellas_rpc::Dtype;
use hellas_rpc::pb::courtesy::{
    GetArtifactRequest, GetArtifactResponse, GetModelStatsRequest, GetModelStatsResponse,
    GetStatsResponse, ListModelsResponse, PutArtifactRequest, PutArtifactResponse,
    QuoteChatPromptRequest, QuoteChatPromptResponse, QuotePreparedTextRequest,
    QuotePreparedTextResponse, QuotePromptRequest, QuotePromptResponse,
};
use hellas_rpc::pb::evaluate::EvaluateRequest as PbEvaluateRequest;
use hellas_rpc::pb::execute::{RunTicketRequest, Ticket, WorkEvent};
use hellas_rpc::pb::fetch::FetchRequest as PbFetchRequest;
use hellas_rpc::provenance::ExecutionProvenance;
use hellas_rpc::{Assurance, InputCommitment, OutputEventEnvelope, ProducerSigningKey};
use hellas_wire::WireStatus;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};

use crate::fetch_policy::FetchQuotaReservation;
use crate::fetch_projection::FetchProjector;
use crate::fetch_provider::{FetchProvider, FetchProviderError, FetchProviderRequest};
pub use actor::{Executor, ExecutorSpawnConfig};

#[derive(Clone)]
pub(crate) struct ProviderContext {
    pub producer_key: Arc<ProducerSigningKey>,
    pub genesis: Arc<Vec<u8>>,
    pub assurance: Assurance,
}

/// Per-execution receiver returned to the streaming `Execute` consumer.
/// Dropping it closes the matching sender held by the worker, which the
/// worker observes on its next chunk send and converts into a cancel.
pub(crate) type ExecuteEventReceiver = mpsc::Receiver<Result<WorkEvent, WireStatus>>;

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
/// quote-acceptance time. Scheme results are carried by signed terminal
/// output events in the stream, not by `ExecutionProvenance`.
#[derive(Debug)]
pub struct ExecuteOutcome {
    pub provenance: ExecutionProvenance,
    pub events: ExecuteEventReceiver,
}

pub(crate) enum ExecutorMessage {
    QuoteEvaluate {
        request: PbEvaluateRequest,
        reply: oneshot::Sender<Result<TicketOutcome<Ticket>, ExecutorError>>,
    },
    QuoteFetch {
        request: PbFetchRequest,
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
    MaterializeModel {
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
    #[cfg(feature = "evaluate")]
    SchemeFinished(Box<dyn crate::scheme::SchemeCompletion>),
    FetchFinished(FetchCompletion),
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

pub(crate) struct FetchCompletion {
    pub input_commitment: InputCommitment,
    pub request_commitment_id: [u8; 32],
    pub quota_reservation: Option<FetchQuotaReservation>,
    pub execution_id: String,
    pub model_id: String,
    pub sender: ExecuteEventReceiverSender,
    pub result: Result<FetchProviderRun, FetchProviderFailure>,
}

pub(crate) type ExecuteEventReceiverSender = mpsc::Sender<Result<WorkEvent, WireStatus>>;

pub(crate) struct FetchProviderRun {
    pub output_events: Vec<OutputEventEnvelope>,
}

pub(crate) struct FetchProviderFailure {
    pub position: u64,
    pub error: FetchProviderError,
}

pub(crate) struct PendingFetch {
    pub request: FetchProviderRequest,
    pub provider: Arc<dyn FetchProvider>,
    pub projector: Box<dyn FetchProjector>,
    pub quota_reservation: Option<FetchQuotaReservation>,
    pub input_commitment: InputCommitment,
    pub assurance: Assurance,
    pub request_commitment_id: [u8; 32],
    pub execution_id: String,
    pub model_id: String,
    pub sender: ExecuteEventReceiverSender,
}

#[derive(Clone)]
pub struct ExecutorHandle {
    pub(super) tx: mpsc::UnboundedSender<ExecutorMessage>,
    #[cfg(feature = "evaluate")]
    pub(super) preferred_dtype: Dtype,
}
