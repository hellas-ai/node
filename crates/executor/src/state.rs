use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use crate::DEFAULT_MAX_SEQ;
use crate::inputs::HuggingFaceLocator;
use crate::programs::{ExecutionContext, ExecutionStart};
use catgrad::prelude::Dtype;
use hellas_core::protocol::Call;
use hellas_rpc::ExecutorError;
use hellas_rpc::decode_token_ids;
use hellas_rpc::pb::hellas::{
    self as pb, Completed as PbCompleted, Failed as PbFailed, GetQuoteRequest,
    Outcome as PbOutcome, StopReason as PbStopReason,
};
use hellas_rpc::spec::DEFAULT_MODEL_REVISION;
use hellas_runtime::cid::Cid;
use hellas_runtime::graph::Program;
use hellas_runtime::runtime::TextReceipt;
use uuid::Uuid;

pub use hellas_rpc::error::StateError;

// =====================================================================
// Quote validation: turn an incoming `GetQuoteRequest` into the typed
// inputs the executor needs (program, weights locator, invocation).
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
}

impl QuotePlan {
    pub(crate) fn from_quote_request(
        request: GetQuoteRequest,
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

        if request.program.is_empty() {
            return Err(ExecutorError::InvalidQuoteRequest(
                "missing program bytes".to_string(),
            ));
        }

        let max_new_tokens = if request.max_new_tokens == 0 {
            DEFAULT_MAX_SEQ
        } else {
            request.max_new_tokens
        };
        let program: Program = serde_json::from_slice(&request.program)
            .map_err(|e| ExecutorError::InvalidQuoteRequest(format!("invalid program: {e}")))?;

        // Detect requests whose program was built for a dtype this executor
        // doesn't accept. Every shipped text model tags `empty_state_type`
        // entries with the model's dtype, so we read the first state tensor's
        // dtype as the program's dtype. Programs with no state (vision-only
        // graphs, not part of node's text path today) are accepted: there's
        // nothing to mismatch on.
        let program_dtype = program.empty_state_type().first().map(|&(dtype, _)| dtype);
        if let Some(program_dtype) = program_dtype
            && !supported_dtypes.contains(&program_dtype)
        {
            return Err(ExecutorError::DtypeNotSupported {
                request: program_dtype,
                supported: supported_dtypes.to_vec(),
            });
        }
        // The cache is scoped per-(model, revision, dtype) via HuggingFaceLocator,
        // so a multi-dtype executor holds an independent bundle for each
        // dtype it has been asked to serve. Use the program's actual dtype
        // here, not the executor's preferred default.
        let request_dtype = program_dtype.unwrap_or_else(|| supported_dtypes[0]);

        let input_ids = decode_token_ids(&request.input)?;
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
        let expected_prompt_tokens = usize::try_from(request.prompt_tokens).unwrap_or(usize::MAX);
        if input_ids.len() != expected_prompt_tokens {
            return Err(ExecutorError::InvalidTokenPayload(format!(
                "prompt token count mismatch: request says {}, input decodes to {}",
                request.prompt_tokens,
                input_ids.len()
            )));
        }
        let expected_max_sequence_length = input_ids.len().saturating_add(max_new_tokens as usize);
        if program.max_sequence_length() != expected_max_sequence_length {
            return Err(ExecutorError::InvalidQuoteRequest(format!(
                "program max_sequence_length mismatch: request implies {expected_max_sequence_length}, program declares {}",
                program.max_sequence_length()
            )));
        }

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
        })
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
    pub invocation: Invocation,
    pub execution: Arc<ExecutionContext>,
    pub start: ExecutionStart,
    pub expires_at: Instant,
    pub model_id: String,
    /// Catnix projection of this quote's request, captured at quote time
    /// so the completion path can build a matching `TextRunOutput` and
    /// signed `Receipt` without re-projecting.
    ///
    /// `None` when projection failed. For CatgradText, `Call::payload`
    /// is the canonical `catnix::Term` bytes for this quote.
    pub catnix_call: Option<Call>,
}

#[derive(Default)]
pub struct ExecutorState {
    quotes: HashMap<String, QuoteRecord>,
}

impl ExecutorState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn create_quote(&mut self, quote: QuoteRecord) -> String {
        let quote_id = make_id("quote");
        self.quotes.insert(quote_id.clone(), quote);
        quote_id
    }

    pub fn get_quote(&self, quote_id: &str, now: Instant) -> Result<&QuoteRecord, StateError> {
        let quote = self
            .quotes
            .get(quote_id)
            .ok_or_else(|| StateError::QuoteNotFound(quote_id.to_string()))?;
        if quote.expires_at <= now {
            return Err(StateError::QuoteExpired(quote_id.to_string()));
        }
        Ok(quote)
    }

    pub fn remove_quote(&mut self, quote_id: &str) -> Option<QuoteRecord> {
        self.quotes.remove(quote_id)
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
    pub fn to_pb(self) -> PbStopReason {
        match self {
            Self::EndOfSequence => PbStopReason::EndOfSequence,
            Self::MaxNewTokens => PbStopReason::MaxNewTokens,
            Self::Cancelled => PbStopReason::Cancelled,
        }
    }
}

#[derive(Debug, Clone)]
pub enum Termination {
    Completed {
        total_tokens: u64,
        stop_reason: StopReason,
        receipt_cid: Cid<TextReceipt>,
        /// Catnix receipt commitment: BLAKE3 of the signed `Claim`
        /// body. `None` when no catnix Call was captured for the quote
        /// or result projection/signing failed.
        catnix_receipt_commitment: Option<[u8; 32]>,
    },
    Failed {
        position: u64,
        error: String,
    },
}

impl Termination {
    pub fn position(&self) -> u64 {
        match self {
            Self::Completed { total_tokens, .. } => *total_tokens,
            Self::Failed { position, .. } => *position,
        }
    }

    pub fn is_completed(&self) -> bool {
        matches!(self, Self::Completed { .. })
    }

    pub fn into_pb(self) -> PbOutcome {
        let kind = match self {
            Self::Completed {
                total_tokens,
                stop_reason,
                receipt_cid,
                catnix_receipt_commitment,
            } => pb::outcome::Kind::Completed(PbCompleted {
                total_tokens,
                stop_reason: stop_reason.to_pb() as i32,
                receipt_cid: receipt_cid.as_bytes().to_vec(),
                catnix_receipt_commitment: catnix_receipt_commitment
                    .map(|c| c.to_vec())
                    .unwrap_or_default(),
            }),
            Self::Failed { position, error } => {
                pb::outcome::Kind::Failed(PbFailed { position, error })
            }
        };
        PbOutcome { kind: Some(kind) }
    }
}
