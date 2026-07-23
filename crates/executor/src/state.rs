use std::collections::HashMap;
#[cfg(feature = "evaluate")]
use std::str::FromStr;
use std::time::{Duration, Instant};

#[cfg(feature = "evaluate")]
use crate::DEFAULT_MAX_SEQ;
use crate::ExecutorError;
use crate::fetch_provider::FetchProviderRequest;
#[cfg(feature = "evaluate")]
use hellas_rpc::Dtype;
#[cfg(feature = "evaluate")]
use hellas_rpc::pb::courtesy::{
    EvaluateStart as PbEvaluateStart, QuotePreparedTextRequest, evaluate_start,
};
#[cfg(feature = "evaluate")]
use hellas_rpc::pb::evaluate::EvaluateRequest as PbEvaluateRequest;
#[cfg(feature = "evaluate")]
use hellas_rpc::pb::execute::{
    WorkEvent as PbWorkEvent, WorkFailed as PbWorkFailed, WorkFinished as PbWorkFinished,
    work_event,
};
use hellas_rpc::run_ticket::ticket_to_pb;
#[cfg(feature = "evaluate")]
use hellas_rpc::run_ticket::{public_key_from_pb, public_key_to_pb};
#[cfg(feature = "evaluate")]
use hellas_rpc::spec::DEFAULT_MODEL_REVISION;
#[cfg(feature = "evaluate")]
use hellas_rpc::stream::output_event_to_pb;
use hellas_rpc::{Assurance, ContentId, Digest, JobTerms, PublicKey, RequestCommitment};
use hellas_rpc::{EvaluateRequest, OutputEventEnvelope, Retention};
use uuid::Uuid;

pub use crate::StateError;

pub(crate) const QUOTE_AMOUNT: u64 = 1000;
pub(crate) const QUOTE_TTL: Duration = Duration::from_secs(30);

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ArtifactStoreConfig {
    Memory,
    Fs(std::path::PathBuf),
}

impl ArtifactStoreConfig {
    pub fn memory() -> Self {
        Self::Memory
    }

    pub fn fs(path: impl Into<std::path::PathBuf>) -> Self {
        Self::Fs(path.into())
    }
}

#[cfg(feature = "evaluate")]
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct ModelLocator {
    pub model_id: String,
    pub revision: String,
    pub dtype: Dtype,
}

#[cfg(feature = "evaluate")]
impl ModelLocator {
    pub(crate) fn spec(&self) -> String {
        model_spec(&self.model_id, &self.revision)
    }
}

#[cfg(feature = "evaluate")]
#[derive(Clone, Debug)]
pub struct Invocation {
    pub input_ids: Vec<u32>,
    pub max_new_tokens: u32,
    pub stop_token_ids: Vec<i32>,
}

#[cfg(feature = "evaluate")]
pub(crate) struct QuotePlan {
    pub locator: ModelLocator,
    pub execution_environment: ContentId,
    pub invocation: Invocation,
    pub initial_artifact_id: Option<Digest>,
    pub runner_public_key: PublicKey,
    pub assurance: Assurance,
    pub retention: Retention,
}

#[cfg(feature = "evaluate")]
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

        let revision = request.huggingface_revision.trim();
        let revision = if revision.is_empty() {
            DEFAULT_MODEL_REVISION
        } else {
            revision
        }
        .to_string();

        let dtype = resolve_accept_dtypes(&request.accept_dtypes, supported_dtypes)?;
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
        let initial_artifact_id = parse_evaluate_start(request.start)?;
        let runner_public_key = request
            .runner_public_key
            .ok_or_else(|| {
                ExecutorError::InvalidQuoteRequest("missing runner_public_key".to_string())
            })
            .and_then(|key| {
                public_key_from_pb(key).map_err(|err| {
                    ExecutorError::InvalidQuoteRequest(format!("invalid runner_public_key: {err}"))
                })
            })?;
        let assurance = hellas_rpc::run_ticket::assurance_from_pb(request.assurance)
            .map_err(|err| ExecutorError::InvalidQuoteRequest(err.to_string()))?;
        let retention = Retention::from_retain(request.retain.unwrap_or(true));

        let locator = ModelLocator {
            model_id: model_id.to_string(),
            revision,
            dtype,
        };
        let backend = if cfg!(any(feature = "candle-cuda", feature = "candle-metal")) {
            "accelerated"
        } else {
            "cpu"
        };
        let execution_environment = hellas_rpc::ProgramManifest::Evaluate(
            hellas_models::program_manifest(&locator.spec(), locator.dtype, backend)?,
        )
        .content_id();
        Ok(Self {
            locator,
            execution_environment,
            invocation: Invocation {
                input_ids,
                max_new_tokens,
                stop_token_ids,
            },
            initial_artifact_id,
            runner_public_key,
            assurance,
            retention,
        })
    }
}

#[cfg(feature = "evaluate")]
pub(crate) fn resolve_accept_dtypes(
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
        if !dtype.is_model_dtype() {
            return Err(ExecutorError::InvalidQuoteRequest(
                "model dtype must be f32, f16, bf16, or f8".to_string(),
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

#[cfg(feature = "evaluate")]
pub(crate) fn evaluate_request_to_pb(request: &EvaluateRequest) -> PbEvaluateRequest {
    PbEvaluateRequest {
        text_execution: request.text_execution.as_bytes().to_vec(),
        runner_public_key: Some(public_key_to_pb(&request.runner_public_key)),
        execution_environment: request.execution_environment.as_bytes().to_vec(),
        nonce: request.nonce.to_vec(),
        assurance: request.assurance.to_byte().into(),
        retain: Some(request.retain),
    }
}

#[cfg(feature = "evaluate")]
pub(crate) fn evaluate_request_from_pb(
    request: PbEvaluateRequest,
) -> Result<EvaluateRequest, ExecutorError> {
    Ok(EvaluateRequest {
        text_execution: Digest::from_bytes(bytes32(&request.text_execution, "text_execution")?),
        runner_public_key: request
            .runner_public_key
            .ok_or_else(|| {
                ExecutorError::InvalidQuoteRequest("missing runner_public_key".to_string())
            })
            .and_then(|key| {
                public_key_from_pb(key).map_err(|err| {
                    ExecutorError::InvalidQuoteRequest(format!("invalid runner_public_key: {err}"))
                })
            })?,
        execution_environment: ContentId::from_slice(&request.execution_environment).map_err(
            |_| {
                ExecutorError::InvalidQuoteRequest(format!(
                    "execution_environment must be 32 bytes, got {}",
                    request.execution_environment.len()
                ))
            },
        )?,
        nonce: bytes32(&request.nonce, "nonce")?,
        assurance: hellas_rpc::run_ticket::assurance_from_pb(request.assurance)
            .map_err(|err| ExecutorError::InvalidQuoteRequest(err.to_string()))?,
        retain: request.retain.unwrap_or(true),
    })
}

#[cfg(feature = "evaluate")]
fn parse_evaluate_start(start: Option<PbEvaluateStart>) -> Result<Option<Digest>, ExecutorError> {
    let start = start
        .and_then(|start| start.kind)
        .ok_or_else(|| ExecutorError::InvalidQuoteRequest("missing evaluate start".to_string()))?;
    match start {
        evaluate_start::Kind::Genesis(_) => Ok(None),
        evaluate_start::Kind::Artifact(artifact) => Ok(Some(Digest::from_bytes(bytes32(
            &artifact.artifact,
            "artifact",
        )?))),
    }
}

#[cfg(feature = "evaluate")]
fn bytes32(bytes: &[u8], field: &str) -> Result<[u8; 32], ExecutorError> {
    bytes.try_into().map_err(|_| {
        ExecutorError::InvalidQuoteRequest(format!("{field} must be 32 bytes, got {}", bytes.len()))
    })
}

fn hex32(bytes: &[u8; 32]) -> String {
    Digest::from_bytes(*bytes).to_string()
}

#[cfg(feature = "evaluate")]
pub(crate) fn model_spec(model_id: &str, revision: &str) -> String {
    if revision.is_empty() {
        model_id.to_string()
    } else {
        format!("{model_id}@{revision}")
    }
}

#[cfg(feature = "evaluate")]
#[derive(Clone, Debug)]
pub(crate) enum LocalModelStatus {
    Ready,
    Failed(String),
}

#[derive(Clone)]
pub struct QuoteRecord {
    pub terms: JobTerms,
    pub expires_at: Instant,
    pub model_id: String,
    pub runner_public_key: PublicKey,
    pub kind: QuoteKind,
}

pub(crate) fn quote_ticket(
    request: RequestCommitment,
    provider_genesis: &[u8],
    assurance: Assurance,
) -> Result<(JobTerms, hellas_rpc::pb::execute::Ticket), ExecutorError> {
    let terms = JobTerms {
        request,
        provider_genesis: ContentId::hash(provider_genesis),
        assurance,
        amount: QUOTE_AMOUNT,
        ttl_ms: QUOTE_TTL.as_millis() as u64,
    };
    let ticket = ticket_to_pb(terms.clone(), provider_genesis.to_vec())
        .map_err(|error| ExecutorError::InvalidQuoteRequest(error.to_string()))?;
    Ok((terms, ticket))
}

pub(crate) fn validate_job_terms(
    terms: &JobTerms,
    provider_genesis: &[u8],
    assurance: Assurance,
) -> Result<(), ExecutorError> {
    if terms.provider_genesis != ContentId::hash(provider_genesis)
        || terms.assurance != assurance
        || terms.amount != QUOTE_AMOUNT
        || terms.ttl_ms != QUOTE_TTL.as_millis() as u64
    {
        return Err(ExecutorError::InvalidQuoteRequest(
            "run ticket terms do not match provider quote terms".into(),
        ));
    }
    Ok(())
}

#[derive(Clone)]
pub enum QuoteKind {
    #[cfg(feature = "evaluate")]
    Scheme(Box<dyn crate::scheme::SchemeJob>),
    Fetch {
        request: FetchProviderRequest,
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
        let key = *quote.terms.request.as_bytes();
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

pub fn new_execution_id() -> String {
    make_id("exec")
}

fn make_id(prefix: &str) -> String {
    format!("{prefix}-{}", Uuid::new_v4().simple())
}

#[cfg(feature = "evaluate")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopReason {
    EndOfSequence,
    MaxNewTokens,
    Cancelled,
}

#[cfg(feature = "evaluate")]
#[derive(Debug, Clone)]
pub enum Termination {
    Completed {
        output_events: Vec<OutputEventEnvelope>,
    },
    Failed {
        position: u64,
        error: String,
    },
}

#[cfg(feature = "evaluate")]
impl Termination {
    pub fn into_pb(self) -> PbWorkEvent {
        let kind = match self {
            Self::Completed { output_events } => work_event::Kind::Finished(PbWorkFinished {
                output_events: output_events.iter().map(output_event_to_pb).collect(),
                assurance_evidence: Vec::new(),
            }),
            Self::Failed { position, error } => {
                work_event::Kind::Failed(PbWorkFailed { position, error })
            }
        };
        PbWorkEvent { kind: Some(kind) }
    }
}
