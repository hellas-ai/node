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
mod tests {
    use super::*;
    use crate::fetch::{FetchCallerPolicy, MemoryFetchTranscriptStore};
    use crate::fetch_policy::{FetchRoute, FetchRoutePolicy};
    use crate::state::MAX_OUTSTANDING_QUOTES;
    use crate::{
        FetchAdaptorError, FetchAdaptorFactory, FetchAdaptorSession, FetchRouteEntry,
        FetchRouteRegistry, MockFetchProvider,
    };
    use hellas_rpc::fetch::build_input_events;
    use hellas_rpc::policy::ExecutePolicy;
    use hellas_rpc::stream::input_event_to_pb;
    use hellas_rpc::{Assurance, ContentId, JobTerms, ProducerSigningKey};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn key(byte: u8) -> ProducerSigningKey {
        ProducerSigningKey::from_secret_bytes([byte; 32]).expect("valid test key")
    }

    fn generic_quote(index: u32, caller_key: hellas_rpc::PublicKey) -> QuoteRecord {
        let mut bytes = [0_u8; 32];
        bytes[..4].copy_from_slice(&index.to_be_bytes());
        let digest = Digest::from_bytes(bytes);
        let input = InputCommitment::from_digest(digest);
        QuoteRecord {
            terms: JobTerms {
                request: RequestCommitment::from_digest(digest),
                provider_genesis: ContentId::from_bytes([1; 32]),
                assurance: Assurance::ProducerSigned,
                amount: QUOTE_AMOUNT,
                ttl_ms: QUOTE_TTL.as_millis() as u64,
            },
            expires_at: Instant::now() + QUOTE_TTL,
            runner_public_key: caller_key,
            kind: QuoteKind::Fetch {
                call: FetchCall::new("test", "run", hellas_rpc::JsonBytes::new(Vec::new()), input),
            },
        }
    }

    #[test]
    fn generic_quote_store_failure_rolls_back_fetch_state() {
        let caller = key(1);
        let caller_key = caller.public_key();
        let environment = ContentId::from_bytes([9; 32]);
        let input = build_input_events(
            "openai",
            "responses",
            b"{}",
            environment,
            Assurance::ProducerSigned,
            &caller,
        )
        .unwrap();
        let input_commitment = hellas_rpc::fetch::verify_input_events(&input)
            .unwrap()
            .input_commitment;
        let mut fetch_state = FetchStateMachine::new(
            MemoryFetchTranscriptStore::default(),
            FetchCallerPolicy::new([caller_key]),
        );
        fetch_state.quote_input(input).unwrap();
        let mut store = ExecutorState::new();
        for index in 0..MAX_OUTSTANDING_QUOTES as u32 {
            store
                .create_quote(generic_quote(index, caller_key))
                .unwrap();
        }
        let (terms, _) = quote_ticket(
            RequestCommitment::from_digest(input_commitment.digest()),
            b"provider",
            Assurance::ProducerSigned,
        )
        .unwrap();

        let error = store_fetch_quote(
            &mut store,
            &mut fetch_state,
            input_commitment,
            QuoteRecord {
                terms,
                expires_at: Instant::now() + QUOTE_TTL,
                runner_public_key: caller_key,
                kind: QuoteKind::Fetch {
                    call: FetchCall::new(
                        "openai",
                        "responses",
                        hellas_rpc::JsonBytes::new(b"{}".to_vec()),
                        input_commitment,
                    ),
                },
            },
        )
        .unwrap_err();

        assert!(matches!(
            error,
            ExecutorError::QueueFull {
                capacity: MAX_OUTSTANDING_QUOTES
            }
        ));
        assert!(matches!(
            fetch_state.quoted(input_commitment),
            Err(crate::fetch::FetchStateError::NotFound)
        ));
    }

    struct RejectingAdaptor {
        environment: ContentId,
        calls: Arc<AtomicUsize>,
    }

    impl FetchAdaptorFactory for RejectingAdaptor {
        fn execution_environment(&self) -> ContentId {
            self.environment
        }

        fn create(&self, _request: &FetchCall) -> Result<FetchAdaptorSession, FetchAdaptorError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err(FetchAdaptorError::failed("unsupported structured request"))
        }
    }

    #[tokio::test]
    async fn malformed_or_unauthorized_quotes_never_reach_the_adaptor() {
        let trusted = key(7);
        let attacker = key(8);
        let environment = ContentId::from_bytes([9; 32]);
        let calls = Arc::new(AtomicUsize::new(0));
        let provider = Arc::new(MockFetchProvider::new(environment));
        let adaptor = Arc::new(RejectingAdaptor {
            environment,
            calls: Arc::clone(&calls),
        });
        let mut routes = FetchRouteRegistry::new();
        routes
            .register(
                FetchRoute::new("openai", "responses"),
                FetchRouteEntry::new(provider, adaptor, FetchRoutePolicy::default()).unwrap(),
            )
            .unwrap();
        let handle = Executor::spawn_with_fetch_routes(
            ExecutePolicy::Any,
            1,
            trusted.clone(),
            b"provider".to_vec(),
            Assurance::ProducerSigned,
            routes,
        )
        .unwrap();

        let attacker_input = build_input_events(
            "openai",
            "responses",
            br#"{}"#,
            environment,
            Assurance::ProducerSigned,
            &attacker,
        )
        .unwrap();
        let unauthorized = handle
            .create_fetch_ticket(PbFetchRequest {
                input: attacker_input.iter().map(input_event_to_pb).collect(),
            })
            .await
            .unwrap_err();
        assert!(matches!(
            unauthorized,
            ExecutorError::InvalidQuoteRequest(_)
        ));

        let trusted_input = build_input_events(
            "openai",
            "responses",
            br#"{}"#,
            environment,
            Assurance::ProducerSigned,
            &trusted,
        )
        .unwrap();
        let mut protobuf = trusted_input
            .iter()
            .map(input_event_to_pb)
            .collect::<Vec<_>>();
        protobuf.push(protobuf[0].clone());
        let malformed = handle
            .create_fetch_ticket(PbFetchRequest { input: protobuf })
            .await
            .unwrap_err();
        assert!(matches!(malformed, ExecutorError::InvalidQuoteRequest(_)));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn adaptor_rejection_happens_before_ticket_state_is_inserted() {
        let caller = key(7);
        let environment = ContentId::from_bytes([9; 32]);
        let input = build_input_events(
            "openai",
            "responses",
            br#"{"unsupported":true}"#,
            environment,
            Assurance::ProducerSigned,
            &caller,
        )
        .unwrap();
        let request = PbFetchRequest {
            input: input.iter().map(input_event_to_pb).collect(),
        };
        let calls = Arc::new(AtomicUsize::new(0));
        let provider = Arc::new(MockFetchProvider::new(environment));
        let adaptor = Arc::new(RejectingAdaptor {
            environment,
            calls: Arc::clone(&calls),
        });
        let mut routes = FetchRouteRegistry::new();
        routes
            .register(
                FetchRoute::new("openai", "responses"),
                FetchRouteEntry::new(provider, adaptor, FetchRoutePolicy::default()).unwrap(),
            )
            .unwrap();
        let handle = Executor::spawn_with_fetch_routes(
            ExecutePolicy::Any,
            1,
            caller,
            b"provider".to_vec(),
            Assurance::ProducerSigned,
            routes,
        )
        .unwrap();

        for _ in 0..2 {
            let error = handle
                .create_fetch_ticket(request.clone())
                .await
                .unwrap_err();
            assert!(matches!(error, ExecutorError::InvalidQuoteRequest(_)));
            assert!(error.to_string().contains("unsupported structured request"));
        }
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }
}
