use std::time::Instant;

use crate::ExecutorError;
use hellas_rpc::fetch::validate_input_event_pb_shape;
use hellas_rpc::pb::execute::Ticket;
use hellas_rpc::pb::fetch::FetchRequest as PbFetchRequest;
use hellas_rpc::provenance::ExecutionProvenance;
use hellas_rpc::stream::input_event_from_pb;
use hellas_rpc::{Digest, InputCommitment, RequestCommitment};

use crate::executor::TicketOutcome;
use crate::fetch::{FetchStateMachine, FetchTranscriptStore};
use crate::fetch_provider::FetchCall;
use crate::state::{ExecutorState, QUOTE_AMOUNT, QUOTE_TTL, QuoteKind, QuoteRecord, quote_ticket};

use super::Executor;

impl Executor {
    pub(super) async fn handle_quote_fetch(
        &mut self,
        request: PbFetchRequest,
    ) -> Result<TicketOutcome<Ticket>, ExecutorError> {
        validate_input_event_pb_shape(&request.input).map_err(|err| {
            ExecutorError::InvalidQuoteRequest(format!(
                "fetch protobuf input shape rejected: {err}"
            ))
        })?;
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
        let verified_input = self
            .fetch_state
            .verify_authorized_input(input)
            .map_err(super::execution::fetch_execute_error)?;
        let verified = verified_input.input();
        let service = verified.service.clone();
        let method = verified.method.clone();
        let execution_environment = verified.execution_environment;
        let body = verified.body.clone();
        let caller_key = verified.caller_key;
        let assurance = verified.assurance;
        let input_commitment = verified.input_commitment;
        if assurance != self.provider.assurance {
            return Err(ExecutorError::InvalidQuoteRequest(
                "request assurance does not match provider assurance".into(),
            ));
        }
        let route = crate::fetch_policy::FetchRoute::new(service.clone(), method.clone());
        let entry = self
            .fetch_routes
            .entry(&route)
            .ok_or_else(|| super::execution::no_fetch_route_error(&route))?;
        if execution_environment != entry.execution_environment() {
            return Err(ExecutorError::InvalidQuoteRequest(
                "fetch execution environment does not match route manifest".into(),
            ));
        }
        let call = FetchCall::new(service.clone(), method.clone(), body, input_commitment);
        // The selected trusted adaptor owns request validation and canonical
        // provider-wire construction. Exercise it before issuing a ticket so
        // an unsupported request can never occupy quote state.
        entry.adaptor_factory.create(&call).map_err(|err| {
            ExecutorError::InvalidQuoteRequest(format!("fetch adaptor rejected request: {err}"))
        })?;

        let request_commitment = RequestCommitment::from_digest(input_commitment.digest());
        let (terms, ticket) = quote_ticket(
            request_commitment,
            self.provider.genesis.as_slice(),
            assurance,
        )?;
        let issued_at = Instant::now();
        self.store.prune_expired_quotes(issued_at);
        let quote = self
            .fetch_state
            .quote_verified_input_at(verified_input, issued_at)
            .map_err(super::execution::fetch_execute_error)?;
        debug_assert_eq!(quote.input_commitment, input_commitment);
        let request_commitment_bytes = store_fetch_quote(
            &mut self.store,
            &mut self.fetch_state,
            input_commitment,
            QuoteRecord {
                terms,
                expires_at: issued_at + QUOTE_TTL,
                runner_public_key: caller_key,
                kind: QuoteKind::Fetch { call },
            },
        )?;

        info!(
            request_commitment = %format_request_commitment(&request_commitment_bytes),
            service,
            method,
            amount = QUOTE_AMOUNT,
            "quoted fetch execution"
        );

        Ok(TicketOutcome {
            response: ticket,
            provenance: ExecutionProvenance {
                commitment_id: request_commitment_bytes,
            },
        })
    }
}

fn store_fetch_quote<S: FetchTranscriptStore>(
    store: &mut ExecutorState,
    fetch_state: &mut FetchStateMachine<S>,
    input: InputCommitment,
    quote: QuoteRecord,
) -> Result<[u8; 32], ExecutorError> {
    match store.create_quote(quote) {
        Ok(commitment) => Ok(commitment),
        Err(error) => {
            fetch_state.rollback_quote(input);
            Err(error)
        }
    }
}

fn format_request_commitment(bytes: &[u8; 32]) -> String {
    Digest::from_bytes(*bytes).to_string()
}

#[cfg(test)]
mod tests;
