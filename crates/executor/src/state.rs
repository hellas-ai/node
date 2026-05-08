use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use crate::DEFAULT_MAX_SEQ;
use crate::inputs::HuggingFaceLocator;
use crate::programs::{ExecutionContext, ExecutionStart};
use catgrad::cid::Cid;
use catgrad::prelude::Dtype;
use catgrad::runtime::Program;
use catgrad_llm::runtime::{TextExecution, TextReceipt};
use hellas_core::{
    Digest, JsonBytes, OpaqueRequest, RequestCommitment, SymbolicGenesisRequest, SymbolicPolicy,
    SymbolicRequest, SymbolicStepRequest,
};
use hellas_pb::courtesy::{
    QuotePreparedTextRequest, SymbolicStart as PbSymbolicStart, symbolic_start,
};
use hellas_pb::hellas::{
    FinishStatus as PbFinishStatus, ReceiptEnvelope as PbReceiptEnvelope, WorkEvent as PbWorkEvent,
    WorkFailed as PbWorkFailed, WorkFinished as PbWorkFinished, work_event,
};
use hellas_pb::symbolic::{
    SymbolicGenesisExecution as PbSymbolicGenesisExecution, SymbolicRequest as PbSymbolicRequest,
    SymbolicStepExecution as PbSymbolicStepExecution, symbolic_request,
};
use hellas_rpc::ExecutorError;
use hellas_rpc::encode_token_ids;
use hellas_rpc::model::ModelAssets;
use hellas_rpc::spec::DEFAULT_MODEL_REVISION;
use std::str::FromStr;
use uuid::Uuid;

pub use hellas_rpc::error::StateError;

// =====================================================================
// Courtesy ticket validation: turn an incoming Hugging Face text request into
// the typed inputs the executor needs (program, weights locator, invocation).
// =====================================================================

#[derive(Clone)]
pub struct Invocation {
    pub input_ids: Vec<u32>,
    pub max_new_tokens: u32,
    pub stop_token_ids: Vec<i32>,
}

pub(crate) struct QuotePlan {
    pub program: Program,
    pub weights_key: HuggingFaceLocator,
    pub invocation: Invocation,
    pub initial_receipt_id: Option<Cid<TextReceipt>>,
}

impl QuotePlan {
    pub(crate) fn from_prepared_text_request(
        request: QuotePreparedTextRequest,
        supported_dtypes: &[Dtype],
    ) -> Result<Self, ExecutorError> {
        let model_id = request.huggingface_model_id.trim();
        if model_id.is_empty() {
            return Err(ExecutorError::InvalidQuoteRequest(
                "missing huggingface_model_id".to_string(),
            ));
        }

        let requested_revision = request.huggingface_revision.trim();
        let requested_revision = if requested_revision.is_empty() {
            DEFAULT_MODEL_REVISION
        } else {
            requested_revision
        }
        .to_string();

        let request_dtype = resolve_accept_dtypes(&request.accept_dtypes, supported_dtypes)?;

        let max_new_tokens = if request.max_new_tokens == 0 {
            DEFAULT_MAX_SEQ
        } else {
            request.max_new_tokens
        };

        let input_ids = request.prompt_token_ids.clone();
        if input_ids.is_empty() {
            return Err(ExecutorError::InvalidTokenPayload(
                "prompt is empty after decoding".to_string(),
            ));
        }
        let stop_token_ids = request
            .stop_token_ids
            .iter()
            .copied()
            .map(|token| {
                i32::try_from(token).map_err(|_| {
                    ExecutorError::InvalidTokenPayload(format!(
                        "stop token id {token} exceeds i32 range"
                    ))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let expected_max_sequence_length = input_ids.len().saturating_add(max_new_tokens as usize);
        let assets = ModelAssets::load(&model_spec(model_id, &requested_revision), request_dtype)?;
        let program_bytes =
            assets.build_program_bytes_for_sequence(expected_max_sequence_length)?;
        let program: Program = serde_json::from_slice(&program_bytes)
            .map_err(|e| ExecutorError::InvalidQuoteRequest(format!("invalid program: {e}")))?;
        if program.max_sequence_length() != expected_max_sequence_length {
            return Err(ExecutorError::InvalidQuoteRequest(format!(
                "program max_sequence_length mismatch: request implies {expected_max_sequence_length}, program declares {}",
                program.max_sequence_length()
            )));
        }
        let initial_receipt_id = parse_symbolic_start(request.start)?;

        Ok(Self {
            program,
            weights_key: HuggingFaceLocator::new(
                model_id.to_string(),
                requested_revision,
                request_dtype,
            ),
            invocation: Invocation {
                input_ids,
                max_new_tokens,
                stop_token_ids,
            },
            initial_receipt_id,
        })
    }
}

fn resolve_accept_dtypes(
    prefs: &[String],
    supported_dtypes: &[Dtype],
) -> Result<Dtype, ExecutorError> {
    if supported_dtypes.is_empty() {
        return Err(ExecutorError::InvalidQuoteRequest(
            "executor must support at least one dtype".to_string(),
        ));
    }
    if prefs.is_empty() {
        return Ok(supported_dtypes[0]);
    }
    let mut parsed = Vec::with_capacity(prefs.len());
    for raw in prefs {
        let dtype = Dtype::from_str(raw).map_err(|e| {
            ExecutorError::InvalidQuoteRequest(format!("invalid dtype `{raw}`: {e}"))
        })?;
        if matches!(dtype, Dtype::U32) {
            return Err(ExecutorError::InvalidQuoteRequest(
                "model dtype must be f32, f16, or bf16".to_string(),
            ));
        }
        parsed.push(dtype);
    }
    for dtype in &parsed {
        if supported_dtypes.contains(dtype) {
            return Ok(*dtype);
        }
    }
    Err(ExecutorError::DtypeNotSupported {
        request: parsed[0],
        supported: supported_dtypes.to_vec(),
    })
}

pub(crate) fn symbolic_request_from_text_execution(execution: &TextExecution) -> SymbolicRequest {
    match execution {
        TextExecution::Genesis { binding } => SymbolicRequest::Genesis(SymbolicGenesisRequest {
            binding_cid: Digest::from_bytes(*binding.as_bytes()),
        }),
        TextExecution::Step {
            binding,
            previous,
            input_tokens,
            policy,
        } => SymbolicRequest::Step(SymbolicStepRequest {
            binding_cid: Digest::from_bytes(*binding.as_bytes()),
            previous_execution_cid: Digest::from_bytes(*previous.as_bytes()),
            input_tokens_cid: Digest::from_bytes(*input_tokens.as_bytes()),
            policy: SymbolicPolicy::new(policy.max_new_tokens(), policy.stop_token_ids().to_vec()),
        }),
    }
}

pub(crate) fn symbolic_request_to_pb(request: &SymbolicRequest) -> PbSymbolicRequest {
    let execution = match request {
        SymbolicRequest::Genesis(genesis) => {
            symbolic_request::Execution::Genesis(PbSymbolicGenesisExecution {
                binding_cid: genesis.binding_cid.as_bytes().to_vec(),
            })
        }
        SymbolicRequest::Step(step) => symbolic_request::Execution::Step(PbSymbolicStepExecution {
            binding_cid: step.binding_cid.as_bytes().to_vec(),
            previous_execution_cid: step.previous_execution_cid.as_bytes().to_vec(),
            input_tokens_cid: step.input_tokens_cid.as_bytes().to_vec(),
            max_new_tokens: step.policy.max_new_tokens,
            stop_token_ids: step.policy.stop_token_ids.clone(),
        }),
    };
    PbSymbolicRequest {
        execution: Some(execution),
    }
}

pub(crate) fn symbolic_request_from_pb(
    request: PbSymbolicRequest,
) -> Result<SymbolicRequest, ExecutorError> {
    match request.execution {
        Some(symbolic_request::Execution::Genesis(genesis)) => {
            Ok(SymbolicRequest::Genesis(SymbolicGenesisRequest {
                binding_cid: Digest::from_bytes(bytes32(&genesis.binding_cid, "binding_cid")?),
            }))
        }
        Some(symbolic_request::Execution::Step(step)) => {
            Ok(SymbolicRequest::Step(SymbolicStepRequest {
                binding_cid: Digest::from_bytes(bytes32(&step.binding_cid, "binding_cid")?),
                previous_execution_cid: Digest::from_bytes(bytes32(
                    &step.previous_execution_cid,
                    "previous_execution_cid",
                )?),
                input_tokens_cid: Digest::from_bytes(bytes32(
                    &step.input_tokens_cid,
                    "input_tokens_cid",
                )?),
                policy: SymbolicPolicy::new(step.max_new_tokens, step.stop_token_ids),
            }))
        }
        None => Err(ExecutorError::InvalidQuoteRequest(
            "missing symbolic execution".to_string(),
        )),
    }
}

fn parse_symbolic_start(
    start: Option<PbSymbolicStart>,
) -> Result<Option<Cid<TextReceipt>>, ExecutorError> {
    let start = start
        .and_then(|start| start.kind)
        .ok_or_else(|| ExecutorError::InvalidQuoteRequest("missing symbolic start".to_string()))?;
    match start {
        symbolic_start::Kind::Genesis(_) => Ok(None),
        symbolic_start::Kind::Receipt(receipt) => {
            let bytes = bytes32(&receipt.receipt_cid, "receipt_cid")?;
            Ok(Some(Cid::from_bytes(bytes)))
        }
    }
}

fn bytes32(bytes: &[u8], field: &str) -> Result<[u8; 32], ExecutorError> {
    bytes.try_into().map_err(|_| {
        ExecutorError::InvalidQuoteRequest(format!("{field} must be 32 bytes, got {}", bytes.len()))
    })
}

fn hex32(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn model_spec(model_id: &str, revision: &str) -> String {
    if revision.is_empty() {
        model_id.to_string()
    } else {
        format!("{model_id}@{revision}")
    }
}

// =====================================================================
// In-memory store of issued quotes. Quotes are short-lived
// (TTL ~30s); after the matching `Execute` consumes one it's removed.
// Executions themselves are not tracked — the streaming `Execute` RPC
// owns everything needed for the request lifecycle.
// =====================================================================

#[derive(Clone)]
pub struct QuoteRecord {
    pub request_commitment: RequestCommitment,
    pub expires_at: Instant,
    pub model_id: String,
    pub kind: QuoteKind,
}

#[derive(Clone)]
pub enum QuoteKind {
    Symbolic {
        symbolic_request: SymbolicRequest,
        invocation: Invocation,
        execution: Arc<ExecutionContext>,
        start: ExecutionStart,
    },
    Opaque {
        request: OpaqueRequest,
        output: JsonBytes,
    },
}

#[derive(Default)]
pub struct ExecutorState {
    quotes: HashMap<[u8; 32], QuoteRecord>,
}

impl ExecutorState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn create_quote(&mut self, quote: QuoteRecord) -> [u8; 32] {
        let key = *quote.request_commitment.0.as_bytes();
        self.quotes.insert(key, quote);
        key
    }

    pub fn get_quote(
        &self,
        request_commitment: &[u8],
        now: Instant,
    ) -> Result<&QuoteRecord, StateError> {
        let key: [u8; 32] = request_commitment.try_into().map_err(|_| {
            StateError::QuoteNotFound(format!(
                "invalid request_commitment length {}",
                request_commitment.len()
            ))
        })?;
        let quote = self
            .quotes
            .get(&key)
            .ok_or_else(|| StateError::QuoteNotFound(hex32(&key)))?;
        if quote.expires_at <= now {
            return Err(StateError::QuoteExpired(hex32(&key)));
        }
        Ok(quote)
    }

    pub fn remove_quote(&mut self, request_commitment: &[u8]) -> Option<QuoteRecord> {
        let key: [u8; 32] = request_commitment.try_into().ok()?;
        self.quotes.remove(&key)
    }

    pub fn prune_expired_quotes(&mut self, now: Instant) -> usize {
        let before = self.quotes.len();
        self.quotes.retain(|_, quote| quote.expires_at > now);
        before - self.quotes.len()
    }
}

/// Mint a fresh execution id. Not registered anywhere — under the unified
/// streaming `Execute` RPC the id only matters for logging/tracing within
/// the lifetime of one request, never for cross-RPC lookup.
pub fn new_execution_id() -> String {
    make_id("exec")
}

fn make_id(prefix: &str) -> String {
    format!("{prefix}-{}", Uuid::new_v4().simple())
}

// =====================================================================
// Termination — the worker's authoritative result for one execution.
// Mirrors the wire `Outcome` shape but keeps the receipt CID typed and
// the stop reason native.
// =====================================================================

/// Why the runner stopped emitting tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopReason {
    EndOfSequence,
    MaxNewTokens,
    Cancelled,
}

impl StopReason {
    pub fn to_pb(self) -> PbFinishStatus {
        match self {
            Self::EndOfSequence => PbFinishStatus::EndOfSequence,
            Self::MaxNewTokens => PbFinishStatus::MaxOutput,
            Self::Cancelled => PbFinishStatus::Cancelled,
        }
    }
}

#[derive(Debug, Clone)]
pub enum Termination {
    Completed {
        stop_reason: StopReason,
        output_tokens: Vec<u32>,
        receipt_dag_cbor: Vec<u8>,
    },
    Failed {
        position: u64,
        error: String,
    },
}

impl Termination {
    pub fn position(&self) -> u64 {
        match self {
            Self::Completed { output_tokens, .. } => output_tokens.len() as u64,
            Self::Failed { position, .. } => *position,
        }
    }

    pub fn is_completed(&self) -> bool {
        matches!(self, Self::Completed { .. })
    }

    pub fn into_pb(self) -> PbWorkEvent {
        let kind = match self {
            Self::Completed {
                stop_reason,
                output_tokens,
                receipt_dag_cbor,
            } => work_event::Kind::Finished(PbWorkFinished {
                total_units: output_tokens.len() as u64,
                status: stop_reason.to_pb() as i32,
                output: encode_token_ids(&output_tokens),
                receipt: Some(PbReceiptEnvelope {
                    dag_cbor: receipt_dag_cbor,
                }),
            }),
            Self::Failed { position, error } => {
                work_event::Kind::Failed(PbWorkFailed { position, error })
            }
        };
        PbWorkEvent { kind: Some(kind) }
    }
}
