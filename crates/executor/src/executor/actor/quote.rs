use crate::executor::TicketOutcome;
use crate::fetch_provider::FetchProviderRequest;
use crate::state::{
    LocalModelStatus, ModelLocator, QuoteKind, QuotePlan, QuoteRecord, evaluate_request_from_pb,
    evaluate_request_to_pb, model_spec, resolve_accept_dtypes,
};
use catgrad::prelude::Dtype;
use chatgrad::types;
use hellas_rpc::ExecutorError;
use hellas_rpc::fetch::verify_input_events;
use hellas_rpc::model::ModelAssets;
use hellas_rpc::pb::courtesy::{
    GetArtifactRequest, GetArtifactResponse, ListModelsResponse, ModelInfo, ModelStatus,
    PutArtifactRequest, PutArtifactResponse, QuoteChatPromptRequest, QuoteChatPromptResponse,
    QuotePreparedTextRequest, QuotePreparedTextResponse, QuotePromptRequest, QuotePromptResponse,
};
use hellas_rpc::pb::evaluate::EvaluateRequest as PbEvaluateRequest;
use hellas_rpc::pb::execute::{PublicKey as PbPublicKey, Ticket};
use hellas_rpc::pb::fetch::FetchRequest as PbFetchRequest;
use hellas_rpc::provenance::ExecutionProvenance;
use hellas_rpc::run_ticket::public_key_from_pb;
use hellas_rpc::spec::ModelSpec;
use hellas_rpc::stream::input_event_from_pb;
use hellas_rpc::{CommitmentScheme, Digest, Evaluate, PublicKey, RequestCommitment};
use std::time::{Duration, Instant};

use super::Executor;

const STATIC_QUOTE_AMOUNT: u64 = 1000;
const QUOTE_TTL: Duration = Duration::from_secs(30);

fn dtype_to_wire(dtype: Dtype) -> String {
    match dtype {
        Dtype::F32 => "f32".to_string(),
        Dtype::F16 => "f16".to_string(),
        Dtype::BF16 => "bf16".to_string(),
        Dtype::F8 => "f8".to_string(),
        Dtype::U32 => "u32".to_string(),
    }
}

fn parse_runner_public_key(key: Option<PbPublicKey>) -> Result<PublicKey, ExecutorError> {
    key.ok_or_else(|| ExecutorError::InvalidQuoteRequest("missing runner_public_key".to_string()))
        .and_then(|key| {
            public_key_from_pb(key).map_err(|err| {
                ExecutorError::InvalidQuoteRequest(format!("invalid runner_public_key: {err}"))
            })
        })
}

impl Executor {
    pub(super) fn resolve_accept_dtypes(&self, prefs: &[String]) -> Result<Dtype, ExecutorError> {
        resolve_accept_dtypes(prefs, &self.supported_dtypes)
    }

    pub(super) async fn handle_load_model_metadata(
        &mut self,
        model: String,
    ) -> Result<(), ExecutorError> {
        let spec = ModelSpec::parse(&model).map_err(hellas_rpc::ModelAssetsError::from)?;
        let locator = ModelLocator {
            model_id: spec.id,
            revision: spec.revision,
            dtype: self.preferred_dtype(),
        };
        let key = locator.clone();
        match ModelAssets::load(&locator.spec(), locator.dtype) {
            Ok(_) => {
                self.models.insert(key.clone(), LocalModelStatus::Ready);
                info!(
                    model = %key.model_id,
                    requested_revision = %key.revision,
                    dtype = %dtype_to_wire(key.dtype),
                    "loaded model metadata"
                );
                Ok(())
            }
            Err(err) => {
                self.models
                    .insert(key.clone(), LocalModelStatus::Failed(err.to_string()));
                Err(err.into())
            }
        }
    }

    pub(super) async fn handle_quote_evaluate(
        &mut self,
        request: PbEvaluateRequest,
    ) -> Result<TicketOutcome<Ticket>, ExecutorError> {
        self.store.prune_expired_quotes(Instant::now());
        let evaluate_request = evaluate_request_from_pb(request)?;
        let resolved = self
            .artifacts
            .resolve_evaluate_request(evaluate_request.clone())
            .await?;
        if !self.supported_dtypes.contains(&resolved.locator.dtype) {
            return Err(ExecutorError::DtypeNotSupported {
                request: resolved.locator.dtype,
                supported: self.supported_dtypes.clone(),
            });
        }
        if !self.execute_policy.allows_execute(
            &resolved.locator.spec(),
            Some(resolved.locator.model_id.as_str()),
        ) {
            return Err(ExecutorError::PolicyDenied(format!(
                "execute policy denied model {}",
                resolved.locator.spec()
            )));
        }
        let request_commitment = Evaluate::commit_request(&evaluate_request);
        let request_commitment_bytes = self.store.create_quote(QuoteRecord {
            request_commitment,
            expires_at: Instant::now() + QUOTE_TTL,
            model_id: resolved.locator.spec(),
            runner_public_key: evaluate_request.runner_public_key,
            kind: QuoteKind::Evaluate {
                evaluate_request,
                locator: resolved.locator,
                invocation: resolved.invocation,
            },
        });

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

    pub(super) async fn handle_quote_fetch(
        &mut self,
        request: PbFetchRequest,
    ) -> Result<TicketOutcome<Ticket>, ExecutorError> {
        self.store.prune_expired_quotes(Instant::now());

        let input = request
            .input
            .into_iter()
            .map(input_event_from_pb)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| {
                ExecutorError::InvalidQuoteRequest(format!(
                    "fetch input event decode failed: {err}"
                ))
            })?;
        let hellas_rpc::fetch::FetchInput {
            service,
            method,
            body,
            caller_key,
            ..
        } = verify_input_events(&input).map_err(|err| {
            ExecutorError::InvalidQuoteRequest(format!(
                "fetch input transcript verification failed: {err}"
            ))
        })?;
        let route = crate::fetch_policy::FetchRoute::new(service.clone(), method.clone());
        if !self.fetch_routes.contains(&route) {
            return Err(super::execution::no_fetch_route_error(&route));
        }
        let (quote, _) = self
            .fetch_state
            .quote_input(input)
            .map_err(super::execution::fetch_execute_error)?;
        let provider_request = FetchProviderRequest::new(
            service.clone(),
            method.clone(),
            body,
            quote.input_commitment,
        );

        let request_commitment = RequestCommitment::from_digest(quote.input_commitment.digest());
        let request_commitment_bytes = self.store.create_quote(QuoteRecord {
            request_commitment,
            expires_at: Instant::now() + QUOTE_TTL,
            model_id: format!("fetch:{service}/{method}"),
            runner_public_key: caller_key,
            kind: QuoteKind::Fetch {
                request: provider_request,
            },
        });

        info!(
            request_commitment = %format_request_commitment(&request_commitment_bytes),
            service,
            method,
            amount = STATIC_QUOTE_AMOUNT,
            "quoted fetch execution"
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

    pub(super) async fn handle_quote_prepared_text(
        &mut self,
        request: QuotePreparedTextRequest,
    ) -> Result<TicketOutcome<QuotePreparedTextResponse>, ExecutorError> {
        let total_start = Instant::now();
        self.store.prune_expired_quotes(Instant::now());
        let plan = QuotePlan::from_prepared_text_request(request, &self.supported_dtypes)?;

        if !self
            .execute_policy
            .allows_execute(&plan.locator.spec(), Some(plan.locator.model_id.as_str()))
        {
            return Err(ExecutorError::PolicyDenied(format!(
                "execute policy denied model {}",
                plan.locator.spec()
            )));
        }

        let resolved = self.artifacts.record_prepared_text(&plan).await?;
        let evaluate_request = resolved.evaluate_request.clone();
        let evaluate_request_pb = evaluate_request_to_pb(&evaluate_request);
        let request_commitment = Evaluate::commit_request(&evaluate_request);
        let commitment_id = request_commitment.digest();
        let request_commitment_bytes = self.store.create_quote(QuoteRecord {
            request_commitment,
            expires_at: Instant::now() + QUOTE_TTL,
            model_id: plan.locator.spec(),
            runner_public_key: evaluate_request.runner_public_key,
            kind: QuoteKind::Evaluate {
                evaluate_request,
                locator: resolved.locator,
                invocation: resolved.invocation,
            },
        });

        info!(
            request_commitment = %format_request_commitment(&request_commitment_bytes),
            commitment_id = %commitment_id,
            model = %plan.locator.model_id,
            requested_revision = %plan.locator.revision,
            dtype = %dtype_to_wire(plan.locator.dtype),
            prompt_tokens = plan.invocation.input_ids.len(),
            max_new_tokens = plan.invocation.max_new_tokens,
            amount = STATIC_QUOTE_AMOUNT,
            total_ms = total_start.elapsed().as_millis(),
            "quoted prepared evaluate text execution"
        );

        Ok(TicketOutcome {
            response: QuotePreparedTextResponse {
                ticket: Some(Ticket {
                    request_commitment: request_commitment_bytes.to_vec(),
                    amount: STATIC_QUOTE_AMOUNT,
                    ttl_ms: QUOTE_TTL.as_millis() as u64,
                }),
                prompt_tokens: plan.invocation.input_ids.len() as u32,
                dtype: dtype_to_wire(plan.locator.dtype),
                evaluate_request: Some(evaluate_request_pb),
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
        let runner_public_key = parse_runner_public_key(request.runner_public_key)?;
        let mut prepared_request = assets.build_quote_prepared_text_request(
            &prepared,
            request.max_new_tokens,
            &runner_public_key,
        )?;
        prepared_request.accept_dtypes = vec![dtype_to_wire(dtype)];
        let inner = self.handle_quote_prepared_text(prepared_request).await?;

        Ok(TicketOutcome {
            response: QuotePromptResponse {
                ticket: inner.response.ticket,
                prompt_tokens,
                dtype: inner.response.dtype,
                evaluate_request: inner.response.evaluate_request,
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
        let runner_public_key = parse_runner_public_key(request.runner_public_key)?;
        let mut prepared_request = assets.build_quote_prepared_text_request(
            &prepared,
            request.max_new_tokens,
            &runner_public_key,
        )?;
        prepared_request.accept_dtypes = vec![dtype_to_wire(dtype)];
        let inner = self.handle_quote_prepared_text(prepared_request).await?;

        Ok(TicketOutcome {
            response: QuoteChatPromptResponse {
                ticket: inner.response.ticket,
                prompt_tokens,
                dtype: inner.response.dtype,
                evaluate_request: inner.response.evaluate_request,
            },
            provenance: inner.provenance,
        })
    }

    pub(super) async fn handle_put_artifact(
        &mut self,
        request: PutArtifactRequest,
    ) -> Result<PutArtifactResponse, ExecutorError> {
        let digest = self
            .artifacts
            .publish_canonical_bytes(request.canonical_artifact)
            .await?;
        Ok(PutArtifactResponse {
            digest: digest.as_bytes().to_vec(),
        })
    }

    pub(super) async fn handle_get_artifact(
        &mut self,
        request: GetArtifactRequest,
    ) -> Result<GetArtifactResponse, ExecutorError> {
        let canonical_artifact = self
            .artifacts
            .get_canonical_bytes(digest_from_slice(&request.digest, "digest")?)
            .await?;
        Ok(GetArtifactResponse { canonical_artifact })
    }

    pub(super) async fn handle_list_models(&self) -> ListModelsResponse {
        let models = self
            .models
            .iter()
            .map(|(locator, status)| {
                let (proto_status, error) = match status {
                    LocalModelStatus::Ready => (ModelStatus::Ready, String::new()),
                    LocalModelStatus::Failed(err) => (ModelStatus::Failed, err.clone()),
                };
                ModelInfo {
                    model_id: locator.model_id.clone(),
                    revision: locator.revision.clone(),
                    status: proto_status.into(),
                    error,
                }
            })
            .collect();
        ListModelsResponse { models }
    }
}

fn digest_from_slice(bytes: &[u8], field: &str) -> Result<Digest, ExecutorError> {
    Digest::from_slice(bytes).map_err(|_| {
        ExecutorError::InvalidQuoteRequest(format!("{field} must be 32 bytes, got {}", bytes.len()))
    })
}

fn format_request_commitment(bytes: &[u8; 32]) -> String {
    Digest::from_bytes(*bytes).to_string()
}

fn load_assets(
    model_id: &str,
    revision: &str,
    dtype: Dtype,
) -> Result<ModelAssets, hellas_rpc::ModelAssetsError> {
    ModelAssets::load(&model_spec(model_id, revision), dtype)
}
