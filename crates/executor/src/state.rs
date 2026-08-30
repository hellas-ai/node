use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::ExecutorError;
use crate::fetch_provider::FetchProviderRequest;
#[cfg(feature = "evaluate")]
use hellas_rpc::pb::courtesy::{
    EvaluateStart as PbEvaluateStart, QuoteTokensRequest, evaluate_start,
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
use hellas_rpc::stream::output_event_to_pb;
use hellas_rpc::{Assurance, ContentId, Digest, JobTerms, PublicKey, RequestCommitment};
#[cfg(feature = "evaluate")]
use hellas_rpc::{
    DEFAULT_MAX_NEW_TOKENS, EvaluateProgramManifest, EvaluateRequest, ExecutionPackageId,
    MAX_STOP_TOKEN_IDS, OutputEventEnvelope, ProgramManifest, Retention, normalize_stop_token_ids,
};
use uuid::Uuid;

pub use crate::StateError;

pub(crate) const QUOTE_AMOUNT: u64 = 1000;
pub(crate) const QUOTE_TTL: Duration = Duration::from_secs(30);
pub(crate) const MAX_OUTSTANDING_QUOTES: usize = 1024;

#[cfg(feature = "evaluate")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LoadedPackage {
    pub execution_package: ExecutionPackageId,
    pub vocabulary_size: u64,
    pub maximum_capacity: u64,
}

#[cfg(feature = "evaluate")]
impl LoadedPackage {
    pub(crate) fn validate_invocation(self, invocation: &Invocation) -> Result<(), ExecutorError> {
        validate_invocation(invocation, self.vocabulary_size, self.maximum_capacity)
    }
}

#[cfg(feature = "evaluate")]
#[derive(Clone, Debug)]
pub struct Invocation {
    pub input_ids: Vec<u32>,
    pub max_new_tokens: u32,
    pub stop_token_ids: Vec<u32>,
}

#[cfg(feature = "evaluate")]
pub(crate) struct QuotePlan {
    pub execution_package: ExecutionPackageId,
    pub vocabulary_size: u64,
    pub maximum_capacity: u64,
    pub execution_environment: ContentId,
    pub invocation: Invocation,
    pub initial_artifact_id: Option<Digest>,
    pub runner_public_key: PublicKey,
    pub assurance: Assurance,
    pub retention: Retention,
}

#[cfg(feature = "evaluate")]
impl QuotePlan {
    pub(crate) fn validate_invocation(&self, invocation: &Invocation) -> Result<(), ExecutorError> {
        validate_invocation(invocation, self.vocabulary_size, self.maximum_capacity)
    }

    /// The Hellas content ID binding the exact verified Catena execution
    /// package. This is pure and cheap: package bytes were verified once by
    /// the owner-only loading path, never while handling an RPC.
    pub(crate) fn execution_environment(execution_package: ExecutionPackageId) -> ContentId {
        ProgramManifest::Evaluate(EvaluateProgramManifest { execution_package }).content_id()
    }

    /// Builds a token-native quote after the peer-supplied package alias has
    /// already been resolved through the executor's loaded-package registry.
    pub(crate) fn from_tokens_request(
        request: QuoteTokensRequest,
        package: LoadedPackage,
    ) -> Result<Self, ExecutorError> {
        let requested_package = ExecutionPackageId::from_bytes(bytes32(
            &request.execution_package,
            "execution_package",
        )?);
        if requested_package != package.execution_package {
            return Err(ExecutorError::InvalidQuoteRequest(format!(
                "package alias resolved to {}, but caller pinned {requested_package}",
                package.execution_package
            )));
        }
        let max_new_tokens = request.max_new_tokens.unwrap_or(DEFAULT_MAX_NEW_TOKENS);

        if request.stop_token_ids.len() > MAX_STOP_TOKEN_IDS {
            return Err(ExecutorError::InvalidTokenPayload(format!(
                "stop_token_ids contains {} entries, over the limit of {MAX_STOP_TOKEN_IDS}",
                request.stop_token_ids.len()
            )));
        }
        let input_ids = request.prompt_token_ids;
        let mut stop_token_ids = request.stop_token_ids;
        normalize_stop_token_ids(&mut stop_token_ids);
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
        let execution_environment = Self::execution_environment(package.execution_package);
        let plan = Self {
            execution_package: package.execution_package,
            vocabulary_size: package.vocabulary_size,
            maximum_capacity: package.maximum_capacity,
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
        };
        plan.validate_invocation(&plan.invocation)?;
        Ok(plan)
    }
}

#[cfg(feature = "evaluate")]
fn validate_invocation(
    invocation: &Invocation,
    vocabulary_size: u64,
    maximum_capacity: u64,
) -> Result<(), ExecutorError> {
    if invocation.input_ids.is_empty() {
        return Err(ExecutorError::InvalidTokenPayload(
            "input token IDs must not be empty".to_string(),
        ));
    }
    if invocation.max_new_tokens == 0 {
        return Err(ExecutorError::InvalidTokenPayload(
            "max_new_tokens must be greater than zero".to_string(),
        ));
    }
    if invocation.stop_token_ids.len() > MAX_STOP_TOKEN_IDS {
        return Err(ExecutorError::InvalidTokenPayload(format!(
            "stop token IDs contains {} entries, over the limit of {MAX_STOP_TOKEN_IDS}",
            invocation.stop_token_ids.len()
        )));
    }
    for (field, tokens) in [
        ("input token IDs", invocation.input_ids.as_slice()),
        ("stop token IDs", invocation.stop_token_ids.as_slice()),
    ] {
        if let Some(token) = tokens
            .iter()
            .copied()
            .find(|&token| u64::from(token) >= vocabulary_size)
        {
            return Err(ExecutorError::InvalidTokenPayload(format!(
                "{field} contain token {token}, but package vocabulary size is {}",
                vocabulary_size
            )));
        }
    }
    let total_tokens = u64::try_from(invocation.input_ids.len())
        .unwrap_or(u64::MAX)
        .saturating_add(u64::from(invocation.max_new_tokens));
    if total_tokens > maximum_capacity {
        return Err(ExecutorError::InvalidTokenPayload(format!(
            "prompt plus max_new_tokens is {total_tokens} tokens, but package capacity is {}",
            maximum_capacity
        )));
    }
    Ok(())
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

/// Decodes a fixed-width byte field, naming it in the failure.
///
/// The crate's one copy of this: `state` and `evaluate` wrap it in
/// their own error type rather than restating the conversion.
#[cfg(feature = "evaluate")]
pub(crate) fn fixed<const N: usize>(field: &str, bytes: &[u8]) -> Result<[u8; N], String> {
    bytes
        .try_into()
        .map_err(|_| format!("{field} must be {N} bytes, got {}", bytes.len()))
}

#[cfg(feature = "evaluate")]
fn bytes32(bytes: &[u8], field: &str) -> Result<[u8; 32], ExecutorError> {
    fixed(field, bytes).map_err(ExecutorError::InvalidQuoteRequest)
}

fn hex32(bytes: &[u8; 32]) -> String {
    Digest::from_bytes(*bytes).to_string()
}

#[cfg(feature = "evaluate")]
#[derive(Clone, Debug)]
pub(crate) enum LocalPackageStatus {
    Ready(LoadedPackage),
    Failed(String),
}

#[derive(Clone)]
pub struct QuoteRecord {
    pub terms: JobTerms,
    pub expires_at: Instant,
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
    Evaluate(Box<crate::evaluate::EvaluateJob>),
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

    pub fn create_quote(&mut self, quote: QuoteRecord) -> Result<[u8; 32], ExecutorError> {
        let key = *quote.terms.request.as_bytes();
        if !self.quotes.contains_key(&key) && self.quotes.len() >= MAX_OUTSTANDING_QUOTES {
            return Err(ExecutorError::QueueFull {
                capacity: MAX_OUTSTANDING_QUOTES,
            });
        }
        self.quotes.insert(key, quote);
        Ok(key)
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
    StopToken,
    MaxNewTokens,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn quote(index: u32) -> QuoteRecord {
        let mut bytes = [0_u8; 32];
        bytes[..4].copy_from_slice(&index.to_be_bytes());
        let digest = Digest::from_bytes(bytes);
        let input = hellas_rpc::InputCommitment::from_digest(digest);
        QuoteRecord {
            terms: JobTerms {
                request: RequestCommitment::from_digest(digest),
                provider_genesis: ContentId::from_bytes([1; 32]),
                assurance: Assurance::ProducerSigned,
                amount: QUOTE_AMOUNT,
                ttl_ms: QUOTE_TTL.as_millis() as u64,
            },
            expires_at: Instant::now() + QUOTE_TTL,
            runner_public_key: hellas_rpc::ProducerSigningKey::from_secret_bytes([2; 32])
                .unwrap()
                .public_key(),
            kind: QuoteKind::Fetch {
                request: FetchProviderRequest::new(
                    "test",
                    "run",
                    hellas_rpc::JsonBytes::new(Vec::new()),
                    input,
                ),
            },
        }
    }

    #[test]
    fn outstanding_quotes_are_bounded_without_evicting_live_tickets() {
        let mut state = ExecutorState::new();
        for index in 0..MAX_OUTSTANDING_QUOTES as u32 {
            state.create_quote(quote(index)).unwrap();
        }
        let Err(error) = state.create_quote(quote(MAX_OUTSTANDING_QUOTES as u32)) else {
            panic!("a quote over the bound must be refused");
        };
        assert!(matches!(
            error,
            ExecutorError::QueueFull {
                capacity: MAX_OUTSTANDING_QUOTES
            }
        ));

        // Repeating an existing deterministic commitment is replacement, not
        // attacker-controlled cardinality growth.
        state.create_quote(quote(0)).unwrap();
    }
}
