use std::collections::HashMap;
#[cfg(feature = "evaluate")]
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::ExecutorError;
use crate::fetch_provider::FetchCall;
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
    DEFAULT_MAX_NEW_TOKENS, EvaluateRequest, MAX_STOP_TOKEN_IDS, OutputEventEnvelope, Retention,
    normalize_stop_token_ids,
};
use uuid::Uuid;

pub use crate::StateError;

pub(crate) const QUOTE_AMOUNT: u64 = 1000;
pub(crate) const QUOTE_TTL: Duration = Duration::from_secs(30);
pub(crate) const MAX_OUTSTANDING_QUOTES: usize = 1024;
/// Quotes are unauthenticated preparation and may carry large prompt bodies.
/// Bound their conservative logical retained heap independently of entry
/// count: fixed quote values and their directly owned allocations are charged,
/// while shared environment metadata is deliberately charged once per quote.
/// The entry cap separately bounds hash-table and allocator bookkeeping.
pub(crate) const MAX_OUTSTANDING_QUOTE_BYTES: usize = 128 * 1024 * 1024;

#[cfg(feature = "evaluate")]
#[derive(Clone, Debug)]
pub struct Invocation {
    pub input_ids: Vec<u32>,
    pub max_new_tokens: u32,
    pub stop_token_ids: Vec<u32>,
}

#[cfg(feature = "evaluate")]
pub(crate) struct QuotePlan {
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
    /// Builds a token-native quote from a locally bound canonical environment.
    pub(crate) fn from_tokens_request(
        request: QuoteTokensRequest,
        environment: &crate::CausalLmEnvironmentSource,
    ) -> Result<Self, ExecutorError> {
        let manifest_id = environment.manifest_id();
        let metadata = environment.environment();
        let requested_manifest_id = ContentId::hash(&request.program_manifest);
        if requested_manifest_id != manifest_id {
            return Err(ExecutorError::InvalidQuoteRequest(format!(
                "loaded environment is {}, but caller pinned {}",
                manifest_id, requested_manifest_id
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
        let retention = Retention::from_retain(request.retain.unwrap_or(false));
        let plan = Self {
            vocabulary_size: metadata.vocabulary_size(),
            maximum_capacity: metadata.maximum_capacity(),
            execution_environment: manifest_id,
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
        validate_invocation(
            &plan.invocation,
            plan.vocabulary_size,
            plan.maximum_capacity,
        )?;
        Ok(plan)
    }
}

#[cfg(feature = "evaluate")]
pub(crate) fn validate_invocation(
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
                "{field} contain token {token}, but environment vocabulary size is {}",
                vocabulary_size
            )));
        }
    }
    let total_tokens = u64::try_from(invocation.input_ids.len())
        .unwrap_or(u64::MAX)
        .saturating_add(u64::from(invocation.max_new_tokens));
    if total_tokens > maximum_capacity {
        return Err(ExecutorError::InvalidTokenPayload(format!(
            "prompt plus max_new_tokens is {total_tokens} tokens, but environment capacity is {}",
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
        retain: request.retain.unwrap_or(false),
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
        call: FetchCall,
    },
}

impl QuoteRecord {
    pub(crate) fn retained_heap_bytes(&self) -> Option<usize> {
        let variable = match &self.kind {
            #[cfg(feature = "evaluate")]
            QuoteKind::Evaluate(job) => job.retained_heap_bytes()?,
            QuoteKind::Fetch { call } => call
                .service
                .capacity()
                .checked_add(call.method.capacity())?
                .checked_add(call.body.retained_heap_bytes())?,
        };
        std::mem::size_of::<QuoteRecord>().checked_add(variable)
    }
}

#[derive(Default)]
pub struct ExecutorState {
    quotes: HashMap<[u8; 32], QuoteRecord>,
    quote_bytes: usize,
}

impl ExecutorState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn create_quote(&mut self, quote: QuoteRecord) -> Result<[u8; 32], ExecutorError> {
        self.create_quote_with_limits(quote, MAX_OUTSTANDING_QUOTES, MAX_OUTSTANDING_QUOTE_BYTES)
    }

    fn create_quote_with_limits(
        &mut self,
        quote: QuoteRecord,
        entry_capacity: usize,
        byte_capacity: usize,
    ) -> Result<[u8; 32], ExecutorError> {
        let key = *quote.terms.request.as_bytes();
        if !self.quotes.contains_key(&key) && self.quotes.len() >= entry_capacity {
            return Err(ExecutorError::QueueFull {
                capacity: entry_capacity,
            });
        }
        let retained_bytes = quote.retained_heap_bytes().ok_or_else(|| {
            ExecutorError::ResourceExhausted(
                "outstanding quote logical retained-heap accounting overflowed".to_string(),
            )
        })?;
        let replaced_bytes = self
            .quotes
            .get(&key)
            .and_then(QuoteRecord::retained_heap_bytes)
            .unwrap_or(0);
        let next_bytes = self
            .quote_bytes
            .checked_sub(replaced_bytes)
            .and_then(|bytes| bytes.checked_add(retained_bytes))
            .filter(|bytes| *bytes <= byte_capacity)
            .ok_or_else(|| {
                ExecutorError::ResourceExhausted(format!(
                    "outstanding quote logical retained-heap capacity of {byte_capacity} bytes is exhausted"
                ))
            })?;
        self.quotes.insert(key, quote);
        self.quote_bytes = next_bytes;
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
        let quote = self.quotes.remove(&key)?;
        self.quote_bytes = quote
            .retained_heap_bytes()
            .and_then(|removed| self.quote_bytes.checked_sub(removed))
            // Stored quotes are immutable and were accounted before insert.
            // Fail closed on an impossible internal mismatch.
            .unwrap_or(usize::MAX);
        Some(quote)
    }

    pub fn prune_expired_quotes(&mut self, now: Instant) -> usize {
        let expired = self
            .quotes
            .iter()
            .filter_map(|(key, quote)| (quote.expires_at <= now).then_some(*key))
            .collect::<Vec<_>>();
        for key in &expired {
            let _ = self.remove_quote(key);
        }
        expired.len()
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
    StopToken(u32),
    MaxNewTokens,
}

#[cfg(feature = "evaluate")]
#[derive(Debug, Clone)]
pub enum Termination {
    Completed {
        streamed_prefix: Arc<[OutputEventEnvelope]>,
        terminal_output_event: Box<OutputEventEnvelope>,
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
            Self::Completed {
                terminal_output_event,
                ..
            } => work_event::Kind::Finished(PbWorkFinished {
                terminal_output_event: Some(output_event_to_pb(terminal_output_event.as_ref())),
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
        quote_with_body(index, Vec::new())
    }

    fn quote_with_body(index: u32, body: Vec<u8>) -> QuoteRecord {
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
                call: FetchCall::new("test", "run", hellas_rpc::JsonBytes::new(body), input),
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

    #[test]
    fn outstanding_quote_heap_is_bounded_and_replacements_are_accounted() {
        let first = quote_with_body(1, vec![1; 64]);
        let per_quote = first.retained_heap_bytes().unwrap();
        let empty_quote = quote_with_body(1, Vec::new())
            .retained_heap_bytes()
            .unwrap();
        let two_full_quotes = per_quote.checked_mul(2).unwrap();
        let byte_capacity = two_full_quotes.checked_add(empty_quote).unwrap();
        let mut state = ExecutorState::new();

        state
            .create_quote_with_limits(first, 10, byte_capacity)
            .unwrap();
        state
            .create_quote_with_limits(quote_with_body(2, vec![2; 64]), 10, byte_capacity)
            .unwrap();
        assert_eq!(state.quote_bytes, two_full_quotes);

        let error = state
            .create_quote_with_limits(quote_with_body(3, vec![3; 64]), 10, byte_capacity)
            .unwrap_err();
        assert!(matches!(error, ExecutorError::ResourceExhausted(_)));

        state
            .create_quote_with_limits(quote_with_body(1, Vec::new()), 10, byte_capacity)
            .unwrap();
        state
            .create_quote_with_limits(quote_with_body(3, vec![3; 64]), 10, byte_capacity)
            .unwrap();
        assert!(state.quote_bytes <= byte_capacity);
    }

    #[test]
    fn fetch_quote_heap_accounting_uses_owned_buffer_capacity() {
        let mut body = Vec::with_capacity(4_096);
        body.extend_from_slice(b"{}");
        let body_capacity = body.capacity();
        let quote = quote_with_body(9, body);
        let call = match &quote.kind {
            #[cfg(feature = "evaluate")]
            QuoteKind::Evaluate(_) => unreachable!("fixture is a Fetch quote"),
            QuoteKind::Fetch { call } => call,
        };
        let expected = std::mem::size_of::<QuoteRecord>()
            + call.service.capacity()
            + call.method.capacity()
            + body_capacity;

        assert_eq!(quote.retained_heap_bytes(), Some(expected));
        assert!(body_capacity > call.body.as_bytes().len());
    }

    #[test]
    fn removing_and_pruning_quotes_release_heap_accounting() {
        let now = Instant::now();
        let mut expired = quote_with_body(1, vec![1; 64]);
        expired.expires_at = now;
        let live = quote_with_body(2, vec![2; 64]);
        let live_key = *live.terms.request.as_bytes();
        let live_bytes = live.retained_heap_bytes().unwrap();
        let mut state = ExecutorState::new();
        state.create_quote(expired).unwrap();
        state.create_quote(live).unwrap();

        assert_eq!(state.prune_expired_quotes(now), 1);
        assert_eq!(state.quote_bytes, live_bytes);
        assert!(state.remove_quote(&live_key).is_some());
        assert_eq!(state.quote_bytes, 0);
    }
}
