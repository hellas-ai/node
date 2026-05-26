use std::collections::VecDeque;

use crate::programs;
use crate::state::ExecutorState;
use crate::worker::ExecuteWorker;
use hellas_rpc::DEFAULT_EXECUTION_QUEUE_CAPACITY;
use hellas_rpc::ExecutorError;
use hellas_rpc::policy::{DownloadPolicy, ExecutePolicy};
use tokio::sync::mpsc;

use super::super::ExecutorMessage;
use super::Executor;

fn test_executor(rx: mpsc::UnboundedReceiver<ExecutorMessage>) -> Executor {
    Executor {
        rx,
        store: ExecutorState::new(),
        pending_executions: VecDeque::new(),
        queue_capacity: DEFAULT_EXECUTION_QUEUE_CAPACITY,
        programs: programs::Cache::new(DownloadPolicy::default()),
        worker: ExecuteWorker::stopped(),
        execute_policy: ExecutePolicy::default(),
        metrics: std::sync::Arc::new(crate::metrics::ExecutorMetrics::default()),
        supported_dtypes: vec![catgrad::prelude::Dtype::F32],
        producer_key: std::sync::Arc::new(hellas_core::ProducerSigningKey::generate()),
    }
}

#[tokio::test]
async fn quote_rejects_missing_model_id() {
    let handle = Executor::spawn(
        DownloadPolicy::default(),
        ExecutePolicy::default(),
        DEFAULT_EXECUTION_QUEUE_CAPACITY,
        vec![catgrad::prelude::Dtype::F32],
    )
    .expect("executor should start");

    let err = handle
        .quote(hellas_rpc::pb::hellas::GetQuoteRequest {
            program: b"test-program".to_vec(),
            ..Default::default()
        })
        .await
        .expect_err("quote should fail");
    assert!(matches!(err, ExecutorError::InvalidQuoteRequest(_)));
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
        .execute(hellas_rpc::pb::hellas::ExecuteRequest {
            quote_id: "invalid-quote".to_string(),
            stream_batch_size: None,
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
