use crate::artifacts::{
    ArtifactId, ArtifactResolver, ProgramBindingArtifact, TensorArtifact,
    decode_program_binding_artifact, decode_tensor_artifact,
};
use crate::backend::ExecBackend;
use crate::inputs::{EnsureDisposition, HuggingFaceLocator, Status, is_cached_locally};
use crate::programs::ExecutionContext;
use crate::state::{
    Invocation, QuoteKind, QuotePlan, QuoteRecord, symbolic_request_from_pb,
    symbolic_request_from_text_execution, symbolic_request_to_pb,
};
use catgrad::category::core::Shape;
use catgrad::cid::{Cid, tensor_dag_cbor_bytes};
use catgrad::interpreter::{self, TaggedTensor};
use catgrad::path::Path;
use catgrad::prelude::Dtype;
use catgrad::runtime::{Program, ProgramBinding};
use catgrad_llm::runtime::{TextExecution, TextPolicy, TextReceipt};
use catgrad_llm::types;
use hellas_core::{
    CommitmentScheme, Digest, JsonBytes, Opaque, OpaqueRequest, RequestCommitment, Symbolic,
    SymbolicRequest, SymbolicStepRequest,
};
use hellas_pb::hellas::{
    CreateTicketRequest, ListModelsResponse, ModelInfo, ModelStatus, QuoteChatPromptRequest,
    QuoteChatPromptResponse, QuotePreparedTextRequest, QuotePreparedTextResponse,
    QuotePromptRequest, QuotePromptResponse, Ticket, work_request,
};
use hellas_rpc::ExecutorError;
use hellas_rpc::model::ModelAssets;
use hellas_rpc::provenance::ExecutionProvenance;
use hellas_rpc::spec::ModelSpec;
use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::Executor;
use crate::executor::TicketOutcome;

const STATIC_QUOTE_AMOUNT: u64 = 1000;
const QUOTE_TTL: Duration = Duration::from_secs(30);

/// Lower-case `Dtype` rendering used in wire fields so callers don't pay
/// the `Debug` impl's upper-case quirk (`F32` etc.).
fn dtype_to_wire(dtype: Dtype) -> String {
    match dtype {
        Dtype::F32 => "f32".to_string(),
        Dtype::F16 => "f16".to_string(),
        Dtype::BF16 => "bf16".to_string(),
        Dtype::U32 => "u32".to_string(),
    }
}

impl Executor {
    /// Resolve a client-supplied dtype preference list against this
    /// executor's `supported_dtypes`. The first entry of `prefs` that this
    /// executor supports wins. An empty `prefs` list lets the executor
    /// fall back to its preferred dtype. If `prefs` is non-empty and none
    /// of its entries are supported, the request is refused with
    /// `DtypeNotSupported`.
    ///
    /// Each entry must be `"f32"`, `"f16"`, or `"bf16"`. `"u32"` and
    /// unknown strings produce `InvalidQuoteRequest`.
    pub(super) fn resolve_accept_dtypes(&self, prefs: &[String]) -> Result<Dtype, ExecutorError> {
        if prefs.is_empty() {
            return Ok(self.preferred_dtype());
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
            if self.supported_dtypes.contains(dtype) {
                return Ok(*dtype);
            }
        }
        Err(ExecutorError::DtypeNotSupported {
            request: parsed[0],
            supported: self.supported_dtypes.clone(),
        })
    }
}

impl Executor {
    pub(super) async fn handle_preload(&mut self, model: String) -> Result<(), ExecutorError> {
        let spec = ModelSpec::parse(&model).map_err(hellas_rpc::ModelAssetsError::from)?;
        let locator = HuggingFaceLocator::from_spec(spec, self.preferred_dtype());
        self.programs.ensure_preloaded(locator.clone()).await?;
        info!(
            model = %locator.model_id,
            requested_revision = %locator.revision,
            "preloaded weights"
        );
        Ok(())
    }

    pub(super) async fn handle_quote(
        &mut self,
        request: CreateTicketRequest,
    ) -> Result<TicketOutcome<Ticket>, ExecutorError> {
        match work_request_from_ticket_request(request)? {
            TicketWorkRequest::Symbolic(symbolic) => {
                let symbolic = symbolic_request_from_pb(symbolic)?;
                let missing = self.missing_for_symbolic_quote(&symbolic)?;
                if !missing.is_empty() {
                    return Err(ExecutorError::InvalidQuoteRequest(format!(
                        "missing symbolic artifacts: {}",
                        format_missing_artifacts(&missing)
                    )));
                }
                self.quote_cid_only_symbolic(symbolic)
            }
            TicketWorkRequest::Opaque(opaque) => self.quote_opaque(opaque),
        }
    }

    pub(super) async fn handle_quote_prepared_text(
        &mut self,
        request: QuotePreparedTextRequest,
    ) -> Result<TicketOutcome<QuotePreparedTextResponse>, ExecutorError> {
        let total_start = Instant::now();
        self.store.prune_expired_quotes(Instant::now());
        let plan_start = Instant::now();
        let plan = QuotePlan::from_prepared_text_request(request, &self.supported_dtypes)?;
        let plan_parse_ms = plan_start.elapsed().as_millis();
        let program_id = plan.program.id();
        if !self.execute_policy.allows_execute(
            &program_id.to_string(),
            Some(plan.weights_key.model_id.as_str()),
        ) {
            return Err(ExecutorError::PolicyDenied(format!(
                "execute policy denied program {} for model {}",
                program_id, plan.weights_key.model_id
            )));
        }

        let ensure_start = Instant::now();
        self.ensure_quote_weights_ready(&plan.weights_key).await?;
        let ensure_weights_ms = ensure_start.elapsed().as_millis();
        let bind_start = Instant::now();
        let execution = self
            .programs
            .bound_program(&plan.weights_key, &plan.program)
            .await?;
        self.symbolic_contexts
            .entry(execution.bound_program().program_binding_id())
            .or_insert_with(|| Arc::clone(&execution));
        let bind_program_ms = bind_start.elapsed().as_millis();
        // Build the request commitment: the `Cid<TextExecution>` over
        // (program, parameter tensor CIDs, prompt tokens, policy). The same
        // 32-byte content address serves two roles:
        //   - audit anchor — the executor is committing to having run
        //     exactly these inputs and no others.
        //   - exact-replay cache key — two requests with the same
        //     commitment hash are byte-identical and skip the model.
        let policy = TextPolicy::new(
            plan.invocation.max_new_tokens,
            plan.invocation.stop_token_ids.clone(),
        );
        // Cold-start: anchor on the bound program's genesis receipt.
        // Anchored execution (later phase) will read this from the
        // request wire field instead.
        let initial_receipt_id = plan
            .initial_receipt_id
            .unwrap_or_else(|| execution.genesis_receipt_id());
        let text_execution =
            execution.build_text_execution(initial_receipt_id, &plan.invocation, &policy)?;
        let commitment_id = text_execution.id();
        let symbolic_request = symbolic_request_from_text_execution(&text_execution);
        let symbolic_request_pb = symbolic_request_to_pb(&symbolic_request);
        let request_commitment = RequestCommitment(Symbolic::commit_request(&symbolic_request));
        let cache_start = Instant::now();
        let start = execution.execution_start(commitment_id, initial_receipt_id)?;
        let cache_lookup_ms = cache_start.elapsed().as_millis();
        remember_prepared_text_artifacts(
            &self.artifacts,
            execution.bound_program().program_binding(),
            &plan.program,
            &plan.invocation.input_ids,
            &text_execution,
            start.initial_state.receipt(),
        )?;

        let model_id = plan.weights_key.model_id.clone();
        let requested_revision = plan.weights_key.revision.clone();
        let prompt_tokens = plan.invocation.input_ids.len();
        let max_new_tokens = plan.invocation.max_new_tokens;
        let cached_output_tokens = start.cached.as_ref().map_or(0, |c| c.output_tokens.len());
        let request_commitment = self.store.create_quote(QuoteRecord {
            request_commitment,
            expires_at: Instant::now() + QUOTE_TTL,
            model_id: model_id.clone(),
            kind: QuoteKind::Symbolic {
                symbolic_request,
                invocation: plan.invocation,
                execution,
                start,
            },
        });

        info!(
            request_commitment = %format_request_commitment(&request_commitment),
            %program_id,
            %commitment_id,
            amount = STATIC_QUOTE_AMOUNT,
            model = model_id,
            requested_revision,
            prompt_tokens,
            cached_output_tokens,
            max_new_tokens,
            "quoted program execution"
        );
        debug!(
            request_commitment = %format_request_commitment(&request_commitment),
            %program_id,
            prompt_tokens,
            cached_output_tokens,
            plan_parse_ms,
            ensure_weights_ms,
            bind_program_ms,
            cache_lookup_ms,
            total_ms = total_start.elapsed().as_millis(),
            "quote phase timings"
        );

        Ok(TicketOutcome {
            response: QuotePreparedTextResponse {
                ticket: Some(Ticket {
                    request_commitment: request_commitment.to_vec(),
                    amount: STATIC_QUOTE_AMOUNT,
                    ttl_ms: QUOTE_TTL.as_millis() as u64,
                }),
                prompt_tokens: prompt_tokens as u32,
                dtype: dtype_to_wire(plan.weights_key.dtype),
                symbolic_request: Some(symbolic_request_pb),
            },
            provenance: ExecutionProvenance {
                commitment_id: *commitment_id.as_bytes(),
            },
        })
    }

    pub(super) async fn handle_quote_prompt(
        &mut self,
        request: QuotePromptRequest,
    ) -> Result<TicketOutcome<QuotePromptResponse>, ExecutorError> {
        let dtype = self.resolve_accept_dtypes(&request.accept_dtypes)?;
        let assets = load_assets(
            &request.huggingface_model_id,
            &request.huggingface_revision,
            dtype,
        )?;
        let prepared = assets.prepare_plain(&request.prompt)?;
        let prompt_tokens = prepared.input_ids.len() as u32;
        let mut prepared_request =
            assets.build_quote_prepared_text_request(&prepared, request.max_new_tokens)?;
        prepared_request.accept_dtypes = vec![dtype_to_wire(dtype)];
        let inner = self.handle_quote_prepared_text(prepared_request).await?;

        Ok(TicketOutcome {
            response: QuotePromptResponse {
                ticket: inner.response.ticket,
                prompt_tokens,
                dtype: inner.response.dtype,
                symbolic_request: inner.response.symbolic_request,
            },
            provenance: inner.provenance,
        })
    }

    pub(super) async fn handle_quote_chat_prompt(
        &mut self,
        request: QuoteChatPromptRequest,
    ) -> Result<TicketOutcome<QuoteChatPromptResponse>, ExecutorError> {
        let dtype = self.resolve_accept_dtypes(&request.accept_dtypes)?;
        let assets = load_assets(
            &request.huggingface_model_id,
            &request.huggingface_revision,
            dtype,
        )?;

        // Build ChatInput from proto messages + system_prompt.
        let mut messages: Vec<types::Message> = Vec::new();
        if !request.system_prompt.is_empty() {
            messages.push(types::Message::openai(types::openai::ChatMessage::system(
                &request.system_prompt,
            )));
        }
        for m in &request.messages {
            let msg = match m.role.as_str() {
                "assistant" => types::openai::ChatMessage::assistant(&m.content),
                _ => types::openai::ChatMessage::user(&m.content),
            };
            messages.push(types::Message::openai(msg));
        }
        let prepared = assets.prepare_chat(&messages)?;
        let prompt_tokens = prepared.input_ids.len() as u32;
        let mut prepared_request =
            assets.build_quote_prepared_text_request(&prepared, request.max_new_tokens)?;
        prepared_request.accept_dtypes = vec![dtype_to_wire(dtype)];
        let inner = self.handle_quote_prepared_text(prepared_request).await?;

        Ok(TicketOutcome {
            response: QuoteChatPromptResponse {
                ticket: inner.response.ticket,
                prompt_tokens,
                dtype: inner.response.dtype,
                symbolic_request: inner.response.symbolic_request,
            },
            provenance: inner.provenance,
        })
    }

    pub(super) async fn handle_list_models(&self) -> ListModelsResponse {
        let entries = self.programs.list_models().await;
        let models = entries
            .into_iter()
            .map(|(locator, status)| {
                let (proto_status, error) = match status {
                    Status::Queued => (ModelStatus::Queued, String::new()),
                    Status::Loading => (ModelStatus::Loading, String::new()),
                    Status::Ready => (ModelStatus::Ready, String::new()),
                    Status::Failed(err) => (ModelStatus::Failed, err),
                };
                ModelInfo {
                    model_id: locator.model_id,
                    revision: locator.revision,
                    status: proto_status.into(),
                    error,
                }
            })
            .collect();
        ListModelsResponse { models }
    }

    fn quote_cid_only_symbolic(
        &mut self,
        symbolic_request: SymbolicRequest,
    ) -> Result<TicketOutcome<Ticket>, ExecutorError> {
        self.store.prune_expired_quotes(Instant::now());
        let SymbolicRequest::Step(step) = symbolic_request.clone() else {
            return Err(ExecutorError::InvalidQuoteRequest(
                "symbolic genesis requests are state anchors, not executable work".to_string(),
            ));
        };

        let request_commitment = RequestCommitment(Symbolic::commit_request(&symbolic_request));
        let commitment_id = Cid::<TextExecution>::from_bytes(*request_commitment.0.as_bytes());
        let execution = self.execution_context_for_binding(step.binding_cid)?;
        let invocation = invocation_from_symbolic_step(&self.artifacts, &step)?;
        let previous_execution =
            Cid::<TextExecution>::from_bytes(*step.previous_execution_cid.as_bytes());
        let start = execution.execution_start_after(commitment_id, previous_execution)?;

        let model_id = format!("symbolic:{}", ArtifactId::from_digest(step.binding_cid));
        let prompt_tokens = invocation.input_ids.len();
        let max_new_tokens = invocation.max_new_tokens;
        let cached_output_tokens = start.cached.as_ref().map_or(0, |c| c.output_tokens.len());
        let request_commitment_bytes = self.store.create_quote(QuoteRecord {
            request_commitment,
            expires_at: Instant::now() + QUOTE_TTL,
            model_id,
            kind: QuoteKind::Symbolic {
                symbolic_request,
                invocation,
                execution,
                start,
            },
        });

        info!(
            request_commitment = %format_request_commitment(&request_commitment_bytes),
            commitment_id = %commitment_id,
            prompt_tokens,
            cached_output_tokens,
            max_new_tokens,
            amount = STATIC_QUOTE_AMOUNT,
            "quoted CID-only symbolic execution"
        );

        Ok(TicketOutcome {
            response: Ticket {
                request_commitment: request_commitment_bytes.to_vec(),
                amount: STATIC_QUOTE_AMOUNT,
                ttl_ms: QUOTE_TTL.as_millis() as u64,
            },
            provenance: ExecutionProvenance {
                commitment_id: *commitment_id.as_bytes(),
            },
        })
    }

    fn quote_opaque(
        &mut self,
        request: hellas_pb::hellas::OpaqueWorkRequest,
    ) -> Result<TicketOutcome<Ticket>, ExecutorError> {
        self.store.prune_expired_quotes(Instant::now());

        let service = request.service.trim().to_string();
        if service.is_empty() {
            return Err(ExecutorError::InvalidQuoteRequest(
                "opaque service must not be empty".to_string(),
            ));
        }
        let method = request.method.trim().to_string();
        if method.is_empty() {
            return Err(ExecutorError::InvalidQuoteRequest(
                "opaque method must not be empty".to_string(),
            ));
        }
        serde_json::from_slice::<serde_json::Value>(&request.payload).map_err(|err| {
            ExecutorError::InvalidQuoteRequest(format!("opaque payload must be UTF-8 JSON: {err}"))
        })?;

        let opaque_request = OpaqueRequest {
            service: service.clone(),
            method: method.clone(),
            payload: JsonBytes::new(request.payload),
        };
        let output = opaque_request.payload.clone();
        let request_commitment = RequestCommitment(Opaque::commit_request(&opaque_request));
        let request_commitment_bytes = self.store.create_quote(QuoteRecord {
            request_commitment,
            expires_at: Instant::now() + QUOTE_TTL,
            model_id: format!("opaque:{service}/{method}"),
            kind: QuoteKind::Opaque {
                request: opaque_request,
                output,
            },
        });

        info!(
            request_commitment = %format_request_commitment(&request_commitment_bytes),
            service,
            method,
            amount = STATIC_QUOTE_AMOUNT,
            "quoted opaque execution"
        );

        Ok(TicketOutcome {
            response: Ticket {
                request_commitment: request_commitment_bytes.to_vec(),
                amount: STATIC_QUOTE_AMOUNT,
                ttl_ms: QUOTE_TTL.as_millis() as u64,
            },
            provenance: ExecutionProvenance {
                commitment_id: request_commitment_bytes,
            },
        })
    }

    fn missing_for_symbolic_quote(
        &self,
        request: &SymbolicRequest,
    ) -> Result<Vec<ArtifactId>, ExecutorError> {
        let mut required = BTreeSet::new();
        let SymbolicRequest::Step(step) = request else {
            return Ok(Vec::new());
        };

        required.insert(ArtifactId::from_digest(step.input_tokens_cid));

        let binding_id = Cid::<ProgramBinding>::from_bytes(*step.binding_cid.as_bytes());
        if !self.symbolic_contexts.contains_key(&binding_id) {
            let binding_artifact_id = ArtifactId::from_digest(step.binding_cid);
            required.insert(binding_artifact_id);
            match self.artifacts.resolve(binding_artifact_id) {
                Ok(binding_artifact) => {
                    let binding = decode_program_binding_artifact(&binding_artifact)
                        .map_err(|err| ExecutorError::InvalidQuoteRequest(err.to_string()))?;
                    required.insert(binding.program);
                    required.extend(binding.parameters.values().copied());
                }
                Err(crate::artifacts::ArtifactError::Missing { .. }) => {}
                Err(err) => return Err(ExecutorError::InvalidQuoteRequest(err.to_string())),
            }
        }

        let mut missing = Vec::new();
        for id in required {
            if !self
                .artifacts
                .contains(id)
                .map_err(|err| ExecutorError::InvalidQuoteRequest(err.to_string()))?
            {
                missing.push(id);
            }
        }
        Ok(missing)
    }

    fn execution_context_for_binding(
        &mut self,
        binding_digest: Digest,
    ) -> Result<Arc<ExecutionContext>, ExecutorError> {
        let binding_id = Cid::<ProgramBinding>::from_bytes(*binding_digest.as_bytes());
        if let Some(context) = self.symbolic_contexts.get(&binding_id) {
            return Ok(Arc::clone(context));
        }

        let binding_artifact = self
            .artifacts
            .resolve(ArtifactId::from_digest(binding_digest))
            .map_err(|err| ExecutorError::InvalidQuoteRequest(err.to_string()))?;
        let binding = decode_program_binding_artifact(&binding_artifact)
            .map_err(|err| ExecutorError::InvalidQuoteRequest(err.to_string()))?;
        let context =
            build_execution_context_from_artifacts(&self.artifacts, binding_digest, binding)?;
        self.symbolic_contexts
            .insert(binding_id, Arc::clone(&context));
        Ok(context)
    }

    async fn ensure_quote_weights_ready(
        &self,
        locator: &HuggingFaceLocator,
    ) -> Result<(), ExecutorError> {
        match self.programs.ensure_ready(locator.clone()).await {
            EnsureDisposition::Ready => Ok(()),
            EnsureDisposition::Queued | EnsureDisposition::InFlight => {
                if !is_cached_locally(locator) {
                    return Err(ExecutorError::WeightsNotReady(locator.to_string()));
                }
                self.programs
                    .ensure_ready_wait(locator.clone(), tokio::time::Duration::from_secs(2))
                    .await
            }
            EnsureDisposition::Failed(error) => Err(ExecutorError::WeightsError(error)),
        }
    }
}

fn build_execution_context_from_artifacts(
    artifacts: &crate::artifacts::InMemoryArtifactStore,
    binding_digest: Digest,
    binding: ProgramBindingArtifact,
) -> Result<Arc<ExecutionContext>, ExecutorError> {
    let program_artifact = artifacts
        .resolve(binding.program)
        .map_err(|err| ExecutorError::InvalidQuoteRequest(err.to_string()))?;
    let program: Program =
        serde_ipld_dagcbor::from_slice(program_artifact.bytes()).map_err(|err| {
            ExecutorError::InvalidQuoteRequest(format!("invalid program artifact: {err}"))
        })?;
    let expected_program_id = Cid::<Program>::from_bytes(*binding.program.as_bytes());
    if program.id() != expected_program_id {
        return Err(ExecutorError::InvalidQuoteRequest(format!(
            "program artifact {} decoded to program {}",
            binding.program,
            program.id()
        )));
    }

    let backend = crate::backend::create_backend()?;
    let mut parameters = BTreeMap::new();
    for (path_text, tensor_id) in binding.parameters {
        let path = path_from_binding(&path_text)?;
        let tensor_artifact = artifacts
            .resolve(tensor_id)
            .map_err(|err| ExecutorError::InvalidQuoteRequest(err.to_string()))?;
        let tensor = decode_tensor_artifact(&tensor_artifact)
            .map_err(|err| ExecutorError::InvalidQuoteRequest(err.to_string()))
            .and_then(validate_tensor_payload_size)?;
        parameters.insert(path, materialize_tensor(&backend, tensor)?);
    }

    let bound = catgrad::runtime::BoundProgram::bind(
        &interpreter::Parameters::from(parameters),
        &backend,
        program,
    )
    .map_err(catgrad_llm::LLMError::from)?;
    let bound_id = bound.program_binding_id();
    let expected_binding = Cid::<ProgramBinding>::from_bytes(*binding_digest.as_bytes());
    if bound_id != expected_binding {
        return Err(ExecutorError::InvalidQuoteRequest(format!(
            "materialized binding mismatch: request names {expected_binding}, reconstructed {bound_id}"
        )));
    }
    Ok(Arc::new(ExecutionContext::new(Arc::new(bound))?))
}

fn invocation_from_symbolic_step(
    artifacts: &crate::artifacts::InMemoryArtifactStore,
    step: &SymbolicStepRequest,
) -> Result<Invocation, ExecutorError> {
    let input_artifact = artifacts
        .resolve(ArtifactId::from_digest(step.input_tokens_cid))
        .map_err(|err| ExecutorError::InvalidQuoteRequest(err.to_string()))?;
    let tensor = decode_tensor_artifact(&input_artifact)
        .map_err(|err| ExecutorError::InvalidQuoteRequest(err.to_string()))
        .and_then(validate_tensor_payload_size)?;
    let input_ids = tensor_to_u32_values(&tensor)?;
    if tensor.shape.0.len() != 2 || tensor.shape.0[0] != 1 || tensor.shape.0[1] != input_ids.len() {
        return Err(ExecutorError::InvalidQuoteRequest(format!(
            "input_tokens_cid must decode to a u32 tensor with shape [1, n], got {:?}",
            tensor.shape
        )));
    }
    if input_ids.is_empty() {
        return Err(ExecutorError::InvalidQuoteRequest(
            "input token tensor must not be empty".to_string(),
        ));
    }
    Ok(Invocation {
        input_ids,
        max_new_tokens: step.policy.max_new_tokens,
        stop_token_ids: step.policy.stop_token_ids.clone(),
    })
}

fn path_from_binding(path: &str) -> Result<Path, ExecutorError> {
    if path.is_empty() {
        return Ok(Path::empty());
    }
    Path::new(path.split('.')).map_err(|err| {
        ExecutorError::InvalidQuoteRequest(format!("invalid parameter path {path:?}: {:?}", err))
    })
}

fn validate_tensor_payload_size(tensor: TensorArtifact) -> Result<TensorArtifact, ExecutorError> {
    let elem_bytes = dtype_element_bytes(tensor.dtype);
    let expected = checked_shape_size(&tensor.shape)?
        .checked_mul(elem_bytes)
        .ok_or_else(|| {
            ExecutorError::InvalidQuoteRequest("tensor byte length overflow".to_string())
        })?;
    if tensor.data.len() != expected {
        return Err(ExecutorError::InvalidQuoteRequest(format!(
            "tensor payload has {} bytes, expected {} for {:?} {:?}",
            tensor.data.len(),
            expected,
            tensor.dtype,
            tensor.shape
        )));
    }
    Ok(tensor)
}

fn materialize_tensor(
    backend: &ExecBackend,
    tensor: TensorArtifact,
) -> Result<TaggedTensor<ExecBackend>, ExecutorError> {
    match tensor.dtype {
        Dtype::F32 => TaggedTensor::from_vec(backend, read_f32_le(&tensor.data)?, tensor.shape),
        Dtype::F16 => TaggedTensor::from_vec(backend, read_f16_le(&tensor.data)?, tensor.shape),
        Dtype::BF16 => TaggedTensor::from_vec(backend, read_bf16_le(&tensor.data)?, tensor.shape),
        Dtype::U32 => TaggedTensor::from_vec(backend, read_u32_le(&tensor.data)?, tensor.shape),
    }
    .map_err(|err| ExecutorError::WeightsError(format!("failed to materialize tensor: {err:?}")))
}

fn tensor_to_u32_values(tensor: &TensorArtifact) -> Result<Vec<u32>, ExecutorError> {
    if tensor.dtype != Dtype::U32 {
        return Err(ExecutorError::InvalidQuoteRequest(format!(
            "expected u32 token tensor, got {:?}",
            tensor.dtype
        )));
    }
    read_u32_le(&tensor.data)
}

const fn dtype_element_bytes(dtype: Dtype) -> usize {
    match dtype {
        Dtype::F32 | Dtype::U32 => 4,
        Dtype::F16 | Dtype::BF16 => 2,
    }
}

fn checked_shape_size(shape: &Shape) -> Result<usize, ExecutorError> {
    shape.0.iter().try_fold(1usize, |acc, dim| {
        acc.checked_mul(*dim).ok_or_else(|| {
            ExecutorError::InvalidQuoteRequest(format!("tensor shape {:?} overflows usize", shape))
        })
    })
}

fn read_f32_le(bytes: &[u8]) -> Result<Vec<f32>, ExecutorError> {
    read_u32_le(bytes).map(|values| values.into_iter().map(f32::from_bits).collect())
}

fn read_f16_le(bytes: &[u8]) -> Result<Vec<half::f16>, ExecutorError> {
    read_u16_le(bytes).map(|values| values.into_iter().map(half::f16::from_bits).collect())
}

fn read_bf16_le(bytes: &[u8]) -> Result<Vec<half::bf16>, ExecutorError> {
    read_u16_le(bytes).map(|values| values.into_iter().map(half::bf16::from_bits).collect())
}

fn read_u32_le(bytes: &[u8]) -> Result<Vec<u32>, ExecutorError> {
    if !bytes.len().is_multiple_of(4) {
        return Err(ExecutorError::InvalidQuoteRequest(format!(
            "u32 tensor payload length {} is not divisible by 4",
            bytes.len()
        )));
    }
    Ok(bytes
        .chunks_exact(4)
        .map(|chunk| u32::from_le_bytes(chunk.try_into().expect("chunk size checked")))
        .collect())
}

fn read_u16_le(bytes: &[u8]) -> Result<Vec<u16>, ExecutorError> {
    if !bytes.len().is_multiple_of(2) {
        return Err(ExecutorError::InvalidQuoteRequest(format!(
            "u16 tensor payload length {} is not divisible by 2",
            bytes.len()
        )));
    }
    Ok(bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes(chunk.try_into().expect("chunk size checked")))
        .collect())
}

enum TicketWorkRequest {
    Symbolic(hellas_pb::hellas::SymbolicWorkRequest),
    Opaque(hellas_pb::hellas::OpaqueWorkRequest),
}

fn work_request_from_ticket_request(
    request: CreateTicketRequest,
) -> Result<TicketWorkRequest, ExecutorError> {
    match request.request.and_then(|request| request.kind) {
        Some(work_request::Kind::Symbolic(symbolic)) => Ok(TicketWorkRequest::Symbolic(symbolic)),
        Some(work_request::Kind::Opaque(opaque)) => Ok(TicketWorkRequest::Opaque(opaque)),
        None => Err(ExecutorError::InvalidQuoteRequest(
            "missing work request".to_string(),
        )),
    }
}

fn format_request_commitment(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn format_missing_artifacts(ids: &[crate::artifacts::ArtifactId]) -> String {
    const MAX_IDS: usize = 8;
    let mut rendered = ids
        .iter()
        .take(MAX_IDS)
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    if ids.len() > MAX_IDS {
        use std::fmt::Write as _;
        let _ = write!(rendered, " and {} more", ids.len() - MAX_IDS);
    }
    rendered
}

fn remember_prepared_text_artifacts(
    artifacts: &crate::artifacts::InMemoryArtifactStore,
    binding: &ProgramBinding,
    program: &Program,
    input_ids: &[u32],
    text_execution: &TextExecution,
    initial_receipt: &TextReceipt,
) -> Result<(), ExecutorError> {
    artifacts
        .insert_verified_bytes(
            ArtifactId::from_digest(hellas_core::Digest::from_bytes(*binding.id().as_bytes())),
            binding.to_dag_cbor_bytes(),
        )
        .map_err(|err| ExecutorError::InvalidQuoteRequest(err.to_string()))?;

    let program_bytes = program.to_dag_cbor_bytes().map_err(|err| {
        ExecutorError::InvalidQuoteRequest(format!("program encoding failed: {err}"))
    })?;
    artifacts
        .insert_verified_bytes(
            ArtifactId::from_digest(hellas_core::Digest::from_bytes(*program.id().as_bytes())),
            program_bytes,
        )
        .map_err(|err| ExecutorError::InvalidQuoteRequest(err.to_string()))?;

    let input_bytes = u32_tensor_dag_cbor_bytes(input_ids);
    if let TextExecution::Step { input_tokens, .. } = text_execution {
        artifacts
            .insert_verified_bytes(
                ArtifactId::from_digest(hellas_core::Digest::from_bytes(*input_tokens.as_bytes())),
                input_bytes,
            )
            .map_err(|err| ExecutorError::InvalidQuoteRequest(err.to_string()))?;
    }

    artifacts
        .insert_verified_bytes(
            ArtifactId::from_digest(hellas_core::Digest::from_bytes(
                *text_execution.id().as_bytes(),
            )),
            text_execution.to_dag_cbor_bytes(),
        )
        .map_err(|err| ExecutorError::InvalidQuoteRequest(err.to_string()))?;

    artifacts
        .insert_verified_bytes(
            ArtifactId::from_digest(hellas_core::Digest::from_bytes(
                *initial_receipt.id().as_bytes(),
            )),
            initial_receipt.to_dag_cbor_bytes(),
        )
        .map_err(|err| ExecutorError::InvalidQuoteRequest(err.to_string()))?;

    Ok(())
}

fn u32_tensor_dag_cbor_bytes(values: &[u32]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(std::mem::size_of_val(values));
    for value in values {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    tensor_dag_cbor_bytes(Dtype::U32, &Shape(vec![1, values.len()]), &bytes)
}

/// Load `ModelAssets` for a `(model_id, revision)` pair, using the same
/// `id[@revision]` parser the quote path uses. An empty revision means
/// "default" (resolved by `ModelSpec::parse`).
fn load_assets(
    model_id: &str,
    revision: &str,
    dtype: Dtype,
) -> Result<ModelAssets, hellas_rpc::ModelAssetsError> {
    let spec = if revision.is_empty() {
        model_id.to_string()
    } else {
        format!("{model_id}@{revision}")
    };
    ModelAssets::load(&spec, dtype)
}
