use std::collections::{HashMap, VecDeque};

use crate::state::{ExecutionStatus, ExecutorState};
use crate::programs;
use crate::worker::ExecuteWorker;
use hellas_rpc::DEFAULT_EXECUTION_QUEUE_CAPACITY;
use hellas_rpc::ExecutorError;
use hellas_rpc::encode_token_ids;
use hellas_rpc::pb::hellas::{ExecutionStatus as RpcExecutionStatus, execute_stream_event};
use hellas_rpc::policy::{DownloadPolicy, ExecutePolicy};
use tokio::sync::mpsc;
use tokio_stream::StreamExt;

use super::super::{ExecutorMessage, LocalExecutionStream};
use super::Executor;

fn test_executor(
    notify_tx: mpsc::WeakUnboundedSender<ExecutorMessage>,
    rx: mpsc::UnboundedReceiver<ExecutorMessage>,
) -> Executor {
    Executor {
        notify_tx,
        rx,
        store: ExecutorState::new(),
        subscriptions: HashMap::new(),
        pending_executions: VecDeque::new(),
        queue_capacity: DEFAULT_EXECUTION_QUEUE_CAPACITY,
        programs: programs::Cache::new(DownloadPolicy::default()),
        worker: ExecuteWorker::stopped(),
        execute_policy: ExecutePolicy::default(),
        metrics: std::sync::Arc::new(crate::metrics::ExecutorMetrics::default()),
        supported_dtypes: vec![catgrad::prelude::Dtype::F32],
    }
}

fn subscribe_stream(
    executor: &mut Executor,
    execution_id: String,
) -> Result<LocalExecutionStream, ExecutorError> {
    executor.handle_subscribe(execution_id)
}

async fn expect_snapshot(
    stream: &mut LocalExecutionStream,
) -> hellas_rpc::pb::hellas::ExecuteSnapshot {
    let event = stream
        .next()
        .await
        .expect("should receive event")
        .expect("event should be valid");
    match event.event {
        Some(execute_stream_event::Event::Snapshot(snapshot)) => snapshot,
        _ => panic!("expected snapshot event"),
    }
}

async fn expect_progress(
    stream: &mut LocalExecutionStream,
) -> hellas_rpc::pb::hellas::ExecuteProgress {
    let event = stream
        .next()
        .await
        .expect("should receive event")
        .expect("event should be valid");
    match event.event {
        Some(execute_stream_event::Event::Progress(progress)) => progress,
        _ => panic!("expected progress event"),
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
        .start_execution(hellas_rpc::pb::hellas::ExecuteRequest {
            quote_id: "invalid-quote".to_string(),
            stream_batch_size: None,
        })
        .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn output_before_completion_reports_unavailable() {
    let (_tx, rx) = mpsc::unbounded_channel();
    let mut executor = test_executor(
        mpsc::unbounded_channel::<ExecutorMessage>().0.downgrade(),
        rx,
    );

    let execution_id = executor.store.create_execution("");

    let err = executor
        .handle_result(&hellas_rpc::pb::hellas::ExecuteResultRequest {
            execution_id: execution_id.clone(),
        })
        .expect_err("output should not be available yet");
    assert!(matches!(
        err,
        ExecutorError::State(crate::state::StateError::OutputNotAvailable(id)) if id == execution_id
    ));
}

#[tokio::test]
async fn subscribe_sends_snapshot_immediately() {
    let (tx, rx) = mpsc::unbounded_channel();
    let mut executor = test_executor(tx.downgrade(), rx);

    let execution_id = executor.store.create_execution("");
    executor.store.mark_running(&execution_id).unwrap();

    let mut updates =
        subscribe_stream(&mut executor, execution_id.clone()).expect("subscribe should succeed");
    let initial = expect_snapshot(&mut updates).await;

    assert_eq!(initial.status, RpcExecutionStatus::Running as i32);
    assert_eq!(initial.progress, 0);
    assert!(initial.output.is_empty());

    executor.send_status(&execution_id, ExecutionStatus::Completed, None);
    let completed = expect_progress(&mut updates).await;
    assert_eq!(completed.status, RpcExecutionStatus::Completed as i32);
    assert_eq!(completed.progress, 0);
    assert!(completed.output_chunk.is_empty());
    assert!(updates.next().await.is_none());
}

#[tokio::test]
async fn subscribe_after_completion_receives_buffered_output() {
    let (tx, rx) = mpsc::unbounded_channel();
    let mut executor = test_executor(tx.downgrade(), rx);

    let execution_id = executor.store.create_execution("");
    let chunk = encode_token_ids(&[42]);
    executor
        .store
        .append_output_chunk(&execution_id, &chunk, 1)
        .unwrap();
    executor
        .store
        .complete_execution(&execution_id, ExecutionStatus::Completed, None, None)
        .unwrap();

    let mut updates =
        subscribe_stream(&mut executor, execution_id).expect("subscribe should succeed");
    let initial = expect_snapshot(&mut updates).await;

    assert_eq!(initial.status, RpcExecutionStatus::Completed as i32);
    assert_eq!(initial.progress, 1);
    assert_eq!(initial.output, chunk);
    assert!(updates.next().await.is_none());
}

#[tokio::test]
async fn subscribe_midstream_receives_buffered_output_and_future_updates() {
    let (tx, rx) = mpsc::unbounded_channel();
    let mut executor = test_executor(tx.downgrade(), rx);

    let execution_id = executor.store.create_execution("");
    let first_chunk = encode_token_ids(&[11]);
    executor
        .store
        .append_output_chunk(&execution_id, &first_chunk, 1)
        .unwrap();
    executor.store.mark_running(&execution_id).unwrap();

    let mut updates =
        subscribe_stream(&mut executor, execution_id.clone()).expect("subscribe should succeed");
    let initial = expect_snapshot(&mut updates).await;

    assert_eq!(initial.status, RpcExecutionStatus::Running as i32);
    assert_eq!(initial.progress, 1);
    assert_eq!(initial.output, first_chunk);

    let second_chunk = encode_token_ids(&[22]);
    executor.send_progress(
        &execution_id,
        ExecutionStatus::Running,
        2,
        second_chunk.clone(),
        None,
    );
    let update = expect_progress(&mut updates).await;
    assert_eq!(update.status, RpcExecutionStatus::Running as i32);
    assert_eq!(update.progress, 2);
    assert_eq!(update.output_chunk, second_chunk);
}

#[tokio::test]
async fn dropped_last_subscription_closes_stream() {
    let (notify_tx, mut notify_rx) = mpsc::unbounded_channel();
    let (_tx, rx) = mpsc::unbounded_channel();
    let mut executor = test_executor(notify_tx.downgrade(), rx);

    let execution_id = executor.store.create_execution("");

    let updates = executor
        .handle_subscribe(execution_id.clone())
        .expect("subscribe should succeed");
    drop(updates);

    match notify_rx.recv().await {
        Some(ExecutorMessage::SubscriptionsClosed {
            execution_id: closed_execution_id,
        }) => {
            assert_eq!(closed_execution_id, execution_id);
            executor.handle_subscriptions_closed(&closed_execution_id);
            assert!(!executor.subscriptions.contains_key(&closed_execution_id));
        }
        _ => panic!("unexpected executor message"),
    }
}

#[tokio::test]
async fn stats_accumulate_on_completion() {
    let (tx, rx) = mpsc::unbounded_channel();
    let mut executor = test_executor(tx.downgrade(), rx);

    let execution_id = executor.store.create_execution("");
    executor.store.mark_running(&execution_id).unwrap();
    let chunk = encode_token_ids(&[1, 2, 3]);
    executor
        .store
        .append_output_chunk(&execution_id, &chunk, 3)
        .unwrap();

    executor.handle_complete(&execution_id, None, ExecutionStatus::Completed, None);

    let stats = executor.metrics.global_snapshot();
    assert_eq!(stats.generated_tokens, 3);
    assert_eq!(stats.executions_completed, 1);
    assert_eq!(stats.executions_failed, 0);

    // A failed execution should increment the failed counter.
    let execution_id2 = executor.store.create_execution("");
    executor.store.mark_running(&execution_id2).unwrap();
    executor.handle_complete(&execution_id2, None, ExecutionStatus::Failed, None);

    let stats = executor.metrics.global_snapshot();
    assert_eq!(stats.generated_tokens, 3);
    assert_eq!(stats.executions_completed, 1);
    assert_eq!(stats.executions_failed, 1);
}

#[test]
fn resolve_accept_dtypes_falls_back_to_preferred_on_empty() {
    let (tx, rx) = mpsc::unbounded_channel();
    let mut executor = test_executor(tx.downgrade(), rx);
    executor.supported_dtypes = vec![catgrad::prelude::Dtype::BF16, catgrad::prelude::Dtype::F32];

    assert_eq!(
        executor.resolve_accept_dtypes(&[]).unwrap(),
        catgrad::prelude::Dtype::BF16,
    );
}

#[test]
fn resolve_accept_dtypes_picks_first_supported_match() {
    let (tx, rx) = mpsc::unbounded_channel();
    let mut executor = test_executor(tx.downgrade(), rx);
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
    let (tx, rx) = mpsc::unbounded_channel();
    let mut executor = test_executor(tx.downgrade(), rx);
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
    let (tx, rx) = mpsc::unbounded_channel();
    let mut executor = test_executor(tx.downgrade(), rx);
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
