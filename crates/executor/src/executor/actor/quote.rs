use std::time::{Duration, Instant};

use crate::ExecutorError;
use hellas_rpc::fetch::verify_input_events;
use hellas_rpc::pb::execute::Ticket;
use hellas_rpc::pb::fetch::FetchRequest as PbFetchRequest;
use hellas_rpc::provenance::ExecutionProvenance;
use hellas_rpc::stream::input_event_from_pb;
use hellas_rpc::{Digest, RequestCommitment};

use crate::executor::TicketOutcome;
use crate::fetch_provider::FetchProviderRequest;
use crate::state::{QuoteKind, QuoteRecord};

use super::Executor;

const STATIC_QUOTE_AMOUNT: u64 = 1000;
const QUOTE_TTL: Duration = Duration::from_secs(30);

impl Executor {
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
}

fn format_request_commitment(bytes: &[u8; 32]) -> String {
    Digest::from_bytes(*bytes).to_string()
}
