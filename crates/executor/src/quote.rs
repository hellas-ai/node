use hellas_rpc::pb::hellas::{
    get_quote_request, GetQuoteRequest, GetQuoteResponse, WeightsHint as RpcWeightsHint,
};

use crate::catgrad_support;
use crate::state::ExecutionPlan;
use crate::weights::{default_ref_cached, EnsureDisposition, ModelId, WeightsError};
use crate::{Executor, ExecutorError, DEFAULT_MAX_SEQ};

enum QuoteKind {
    Graph,
    Llm { model_id: String, max_seq: u32 },
}

impl Executor {
    pub(super) async fn handle_quote(
        &mut self,
        request: GetQuoteRequest,
    ) -> Result<GetQuoteResponse, ExecutorError> {
        let payload = request.payload.ok_or(ExecutorError::MissingPayload)?;

        let (graph, input, weights_hint, max_seq, kind) = match payload {
            get_quote_request::Payload::Graph(graph) => (
                graph,
                String::new(),
                None,
                DEFAULT_MAX_SEQ,
                QuoteKind::Graph,
            ),
            get_quote_request::Payload::LlmPrompt(llm) => {
                let max_seq = if llm.max_seq == 0 {
                    DEFAULT_MAX_SEQ
                } else {
                    llm.max_seq
                };

                let model_id = llm.huggingface_model_id.clone();
                let model_id_typed = ModelId(model_id.clone());
                let disposition = self
                    .weights
                    .ensure_default_ready(model_id_typed.clone())
                    .await;

                let key = match disposition {
                    EnsureDisposition::Ready(key) => key,
                    EnsureDisposition::Queued | EnsureDisposition::InFlight => {
                        if default_ref_cached(&model_id) {
                            self.weights
                                .ensure_default_ready_wait(
                                    model_id_typed,
                                    tokio::time::Duration::from_secs(2),
                                )
                                .await
                                .map_err(|e| match e {
                                    WeightsError::NotReady => {
                                        ExecutorError::WeightsNotReady(model_id.clone())
                                    }
                                    other => ExecutorError::WeightsError(other.to_string()),
                                })?
                        } else {
                            return Err(ExecutorError::WeightsNotReady(model_id));
                        }
                    }
                    EnsureDisposition::Failed(err) => {
                        return Err(ExecutorError::WeightsError(err));
                    }
                };

                let bundle = self
                    .weights
                    .bundle(&key)
                    .await
                    .map_err(|e| ExecutorError::WeightsError(e.to_string()))?;

                let (graph_bytes, templated_input) = catgrad_support::build_graph_from_llm_prompt(
                    bundle.as_ref(),
                    &llm.prompt,
                    max_seq,
                )?;

                (
                    graph_bytes,
                    templated_input,
                    Some(key),
                    max_seq,
                    QuoteKind::Llm { model_id, max_seq },
                )
            }
        };

        let plan = ExecutionPlan {
            graph: graph.clone(),
            weights_hint: weights_hint.clone(),
            input: input.clone(),
            max_seq,
        };
        let graph_id = format!("{:x}", simple_hash(&graph));
        let amount = 1000; // stub
        let quote_id = self.state.create_quote(graph_id.clone(), plan);

        match kind {
            QuoteKind::Graph => {
                info!(%quote_id, %graph_id, amount, "quoted raw graph");
            }
            QuoteKind::Llm { model_id, max_seq } => {
                info!(
                    %quote_id,
                    %graph_id,
                    amount,
                    model = model_id,
                    max_seq,
                    input_len = input.len(),
                    "quoted llm prompt"
                );
            }
        }

        Ok(GetQuoteResponse {
            quote_id,
            graph_id,
            amount,
            input,
            resolved_weights: weights_hint.map(|hint| RpcWeightsHint {
                huggingface_model_id: hint.model_id.0,
                revision: hint.revision.0,
            }),
        })
    }
}

fn simple_hash(data: &[u8]) -> u64 {
    let mut hash: u64 = 0;
    for (i, &byte) in data.iter().enumerate() {
        hash = hash.wrapping_add((byte as u64).wrapping_mul(31_u64.wrapping_pow(i as u32)));
    }
    hash
}
