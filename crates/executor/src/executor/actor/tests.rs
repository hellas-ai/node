use std::collections::VecDeque;

use crate::artifacts::{ArtifactId, InMemoryArtifactStore};
use crate::programs;
use crate::state::{ExecutorState, symbolic_request_to_pb};
use crate::worker::ExecuteWorker;
use catgrad::category::lang::{Term, TypedTerm};
use catgrad::cid::{Cid, Tensor, tensor_dag_cbor_bytes};
use catgrad::path::Path;
use catgrad::runtime::{Program, ProgramBinding, ProgramSpec};
use catgrad_llm::runtime::{TextExecution, TextPolicy};
use hellas_core::{
    CommitmentScheme, DeliveryOutput, DeliveryRequest, JsonBytes, OpaqueRequest,
    ProducerSigningKey, ReceiptEnvelope, RequestCommitment, Symbolic, decode_dag_cbor,
    verify_delivery,
};
use hellas_pb::hellas::{
    CreateTicketRequest, FinishStatus, OpaqueWorkRequest, RunTicketRequest, SymbolicWorkRequest,
    WorkRequest, work_event, work_request,
};
use hellas_rpc::DEFAULT_EXECUTION_QUEUE_CAPACITY;
use hellas_rpc::ExecutorError;
use hellas_rpc::policy::{DownloadPolicy, ExecutePolicy};
use std::sync::Arc;
use tokio::sync::mpsc;

use super::super::ExecutorMessage;
use super::Executor;

fn test_executor(rx: mpsc::UnboundedReceiver<ExecutorMessage>) -> Executor {
    Executor {
        rx,
        store: ExecutorState::new(),
        pending_executions: VecDeque::new(),
        queue_capacity: DEFAULT_EXECUTION_QUEUE_CAPACITY,
        artifacts: InMemoryArtifactStore::default(),
        symbolic_contexts: Default::default(),
        programs: programs::Cache::new(DownloadPolicy::default()),
        worker: ExecuteWorker::stopped(),
        execute_policy: ExecutePolicy::default(),
        metrics: std::sync::Arc::new(crate::metrics::ExecutorMetrics::default()),
        producer_key: Arc::new(ProducerSigningKey::generate()),
        supported_dtypes: vec![catgrad::prelude::Dtype::F32],
    }
}

#[tokio::test]
async fn create_ticket_rejects_malformed_symbolic_request() {
    let handle = Executor::spawn(
        DownloadPolicy::default(),
        ExecutePolicy::default(),
        DEFAULT_EXECUTION_QUEUE_CAPACITY,
        vec![catgrad::prelude::Dtype::F32],
    )
    .expect("executor should start");

    let err = handle
        .create_ticket(CreateTicketRequest {
            request: Some(WorkRequest {
                kind: Some(work_request::Kind::Symbolic(SymbolicWorkRequest {
                    ..Default::default()
                })),
            }),
        })
        .await
        .expect_err("quote should fail");
    assert!(matches!(err, ExecutorError::InvalidQuoteRequest(_)));
}

#[tokio::test]
async fn create_ticket_accepts_cid_only_symbolic_step_from_artifacts() {
    let (_tx, rx) = mpsc::unbounded_channel();
    let mut executor = test_executor(rx);

    let program: Program = ProgramSpec {
        typed_term: TypedTerm {
            term: Term::empty(),
            source_type: vec![],
            target_type: vec![],
        },
        module_path: Path::empty(),
        empty_state_type: vec![],
        max_sequence_length: 2,
        extra_nat_chunk_size: None,
    }
    .into();
    let binding = ProgramBinding::new(program.id(), Default::default());
    let binding_bytes = binding.to_dag_cbor_bytes();
    executor
        .artifacts
        .insert_verified_bytes(ArtifactId::from_bytes(&binding_bytes), binding_bytes)
        .unwrap();
    let program_bytes = program.to_dag_cbor_bytes().unwrap();
    executor
        .artifacts
        .insert_verified_bytes(ArtifactId::from_bytes(&program_bytes), program_bytes)
        .unwrap();

    let input_ids = [7_u32];
    let mut input_bytes = Vec::new();
    for token in input_ids {
        input_bytes.extend_from_slice(&token.to_le_bytes());
    }
    let input_artifact = tensor_dag_cbor_bytes(
        catgrad::prelude::Dtype::U32,
        &catgrad::category::core::Shape(vec![1, input_ids.len()]),
        &input_bytes,
    );
    let input_cid = Cid::<Tensor>::from_dag_cbor_bytes(&input_artifact);
    executor
        .artifacts
        .insert_verified_bytes(ArtifactId::from_bytes(&input_artifact), input_artifact)
        .unwrap();

    let policy = TextPolicy::new(1, vec![]);
    let previous = TextExecution::genesis(binding.id()).id();
    let symbolic_request = hellas_core::SymbolicRequest::Step(hellas_core::SymbolicStepRequest {
        binding_cid: hellas_core::Digest::from_bytes(*binding.id().as_bytes()),
        previous_execution_cid: hellas_core::Digest::from_bytes(*previous.as_bytes()),
        input_tokens_cid: hellas_core::Digest::from_bytes(*input_cid.as_bytes()),
        policy: hellas_core::SymbolicPolicy::new(
            policy.max_new_tokens(),
            policy.stop_token_ids().to_vec(),
        ),
    });
    let expected = RequestCommitment(Symbolic::commit_request(&symbolic_request));

    let outcome = executor
        .handle_quote(CreateTicketRequest {
            request: Some(WorkRequest {
                kind: Some(work_request::Kind::Symbolic(symbolic_request_to_pb(
                    &symbolic_request,
                ))),
            }),
        })
        .await
        .expect("CID-only quote should succeed");

    assert_eq!(outcome.response.request_commitment, expected.0.as_bytes());
}

#[tokio::test]
async fn opaque_ticket_runs_with_signed_json_receipt() {
    let (_tx, rx) = mpsc::unbounded_channel();
    let mut executor = test_executor(rx);
    let payload = br#"{"x":1}"#.to_vec();

    let outcome = executor
        .handle_quote(CreateTicketRequest {
            request: Some(WorkRequest {
                kind: Some(work_request::Kind::Opaque(OpaqueWorkRequest {
                    service: "echo".to_string(),
                    method: "run".to_string(),
                    payload: payload.clone(),
                })),
            }),
        })
        .await
        .expect("opaque quote should succeed");

    let mut execute = executor
        .handle_execute(RunTicketRequest {
            request_commitment: outcome.response.request_commitment.clone(),
        })
        .await
        .expect("opaque execution should succeed");
    let event = execute
        .events
        .recv()
        .await
        .expect("terminal event should arrive")
        .expect("terminal event should be ok");

    let finished = match event.kind.expect("event kind") {
        work_event::Kind::Finished(finished) => finished,
        other => panic!("expected finished event, got {other:?}"),
    };
    assert_eq!(finished.output, payload);
    assert_eq!(finished.status, FinishStatus::EndOfSequence as i32);
    assert_eq!(finished.total_units, payload.len() as u64);

    let envelope: ReceiptEnvelope = decode_dag_cbor(
        &finished
            .receipt
            .expect("receipt envelope should be present")
            .dag_cbor,
    )
    .expect("receipt should decode");
    let request = OpaqueRequest {
        service: "echo".to_string(),
        method: "run".to_string(),
        payload: JsonBytes::new(payload.clone()),
    };
    let output = JsonBytes::new(payload);
    verify_delivery(
        DeliveryRequest::Opaque(&request),
        DeliveryOutput::Opaque(&output),
        &envelope,
    )
    .expect("opaque receipt should verify");
}

#[tokio::test]
async fn execute_with_invalid_quote_fails() {
    let handle = Executor::spawn(
        DownloadPolicy::default(),
        ExecutePolicy::default(),
        DEFAULT_EXECUTION_QUEUE_CAPACITY,
        vec![catgrad::prelude::Dtype::F32],
    )
    .expect("executor should start");

    let result = handle
        .run_ticket(RunTicketRequest {
            request_commitment: vec![0; 32],
        })
        .await;
    assert!(result.is_err());
}

#[test]
fn resolve_accept_dtypes_falls_back_to_preferred_on_empty() {
    let (_tx, rx) = mpsc::unbounded_channel();
    let mut executor = test_executor(rx);
    executor.supported_dtypes = vec![catgrad::prelude::Dtype::BF16, catgrad::prelude::Dtype::F32];

    assert_eq!(
        executor.resolve_accept_dtypes(&[]).unwrap(),
        catgrad::prelude::Dtype::BF16,
    );
}

#[test]
fn resolve_accept_dtypes_picks_first_supported_match() {
    let (_tx, rx) = mpsc::unbounded_channel();
    let mut executor = test_executor(rx);
    executor.supported_dtypes = vec![catgrad::prelude::Dtype::F32, catgrad::prelude::Dtype::F16];

    // Client prefers bf16 first but server doesn't have it; server picks f32.
    let prefs = vec!["bf16".to_string(), "f32".to_string(), "f16".to_string()];
    assert_eq!(
        executor.resolve_accept_dtypes(&prefs).unwrap(),
        catgrad::prelude::Dtype::F32,
    );
}

#[test]
fn resolve_accept_dtypes_rejects_when_no_overlap() {
    let (_tx, rx) = mpsc::unbounded_channel();
    let mut executor = test_executor(rx);
    executor.supported_dtypes = vec![catgrad::prelude::Dtype::F32];

    let prefs = vec!["bf16".to_string(), "f16".to_string()];
    let err = executor
        .resolve_accept_dtypes(&prefs)
        .expect_err("no overlap");
    match err {
        ExecutorError::DtypeNotSupported { request, supported } => {
            // Reports the client's first preference for diagnostic purposes.
            assert_eq!(request, catgrad::prelude::Dtype::BF16);
            assert_eq!(supported, vec![catgrad::prelude::Dtype::F32]);
        }
        other => panic!("expected DtypeNotSupported, got {other:?}"),
    }
}

#[test]
fn resolve_accept_dtypes_rejects_u32_and_garbage() {
    let (_tx, rx) = mpsc::unbounded_channel();
    let mut executor = test_executor(rx);
    executor.supported_dtypes = vec![catgrad::prelude::Dtype::F32];

    assert!(matches!(
        executor.resolve_accept_dtypes(&["u32".to_string()]),
        Err(ExecutorError::InvalidQuoteRequest(_))
    ));
    assert!(matches!(
        executor.resolve_accept_dtypes(&["not-a-dtype".to_string()]),
        Err(ExecutorError::InvalidQuoteRequest(_))
    ));
}
