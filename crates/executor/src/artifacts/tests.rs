use super::*;
use commonware_runtime::{Blob as _, Runner as _, Storage as _, Supervisor as _, deterministic};
fn runner_public_key() -> hellas_rpc::PublicKey {
    hellas_rpc::ProducerSigningKey::from_secret_bytes([8; 32])
        .expect("valid test key")
        .public_key()
}

fn evaluate_request(text_execution: Digest) -> EvaluateRequest {
    EvaluateRequest {
        text_execution,
        runner_public_key: runner_public_key(),
        execution_environment: plan().execution_environment,
        nonce: [7; 32],
        assurance: hellas_rpc::Assurance::ProducerSigned,
        retain: true,
    }
}

fn plan() -> QuotePlan {
    QuotePlan {
        vocabulary_size: u64::from(u32::MAX) + 1,
        maximum_capacity: u64::MAX,
        execution_environment: ContentId::from_bytes([8; 32]),
        invocation: Invocation {
            input_ids: vec![1, 2, 3],
            max_new_tokens: 8,
            stop_token_ids: vec![4, 5],
        },
        initial_artifact_id: None,
        runner_public_key: runner_public_key(),
        assurance: hellas_rpc::Assurance::ProducerSigned,
        retention: hellas_rpc::Retention::Retain,
    }
}

fn paid_parts() -> PreparedPaidInputParts {
    let manifest = ProgramManifest::new(
        hellas_rpc::Application::new("hellas/catena-gpu-0.0.1", "causal-lm-0.0.1").unwrap(),
        ContentId::from_bytes([0x42; 32]),
    );
    let execution_environment = manifest.content_id();
    let identity_artifact =
        TextArtifact::identity(BoundTermId::from_digest(execution_environment.digest()));
    let prompt_tokens = TokenIds::from([1, 2, 3]);
    let text_policy = TextPolicy::from_u32_stop_tokens(8, [4, 5]);
    let text_execution = TextExecution::new(
        SourceRef::output(identity_artifact.output_id()),
        prompt_tokens.output_id(),
        text_policy.output_id(),
    );
    let evaluate_request = EvaluateRequest {
        text_execution: text_execution.input_id().digest(),
        runner_public_key: runner_public_key(),
        execution_environment,
        nonce: [7; 32],
        assurance: hellas_rpc::Assurance::ProducerSigned,
        retain: true,
    };
    PreparedPaidInputParts {
        evaluate_request,
        manifest,
        text_execution,
        prompt_tokens,
        text_policy,
        identity_artifact,
    }
}

#[test]
fn journaled_paid_input_resolves_without_courtesy_state() {
    let parts = paid_parts();
    let expected_request = parts.evaluate_request.clone();
    let expected_manifest = parts.manifest.clone();

    let (manifest, resolved) = resolve_prepared_paid_input(parts).unwrap();

    assert_eq!(manifest, expected_manifest);
    assert_eq!(resolved.evaluate_request, expected_request);
    assert_eq!(resolved.invocation.input_ids, [1, 2, 3]);
    assert_eq!(resolved.invocation.max_new_tokens, 8);
    assert_eq!(resolved.invocation.stop_token_ids, [4, 5]);
    assert!(resolved.prepared_artifacts.is_some());
}

#[test]
fn journaled_paid_input_rechecks_its_graph() {
    let mut parts = paid_parts();
    parts.prompt_tokens = TokenIds::from([99]);

    let error = resolve_prepared_paid_input(parts).unwrap_err();

    assert!(error.to_string().contains("prompt tokens id"), "{error}");
}

#[tokio::test]
async fn retained_paid_input_publishes_only_after_success() {
    let (_, resolved) = resolve_prepared_paid_input(paid_parts()).unwrap();
    let mut store = EvaluateArtifactStore::default();
    assert!(
        store
            .resolve_evaluate_request(resolved.evaluate_request.clone())
            .await
            .is_err(),
        "preparing paid work must not populate Courtesy artifacts"
    );

    store
        .record_completed_text_with_prepared(
            &resolved.evaluate_request,
            &resolved.invocation,
            &[10, 11],
            resolved.prepared_artifacts.as_ref(),
        )
        .await
        .unwrap();

    let published = store
        .resolve_evaluate_request(resolved.evaluate_request.clone())
        .await
        .unwrap();
    assert_eq!(published.invocation.input_ids, [1, 2, 3]);
    assert_eq!(published.invocation.max_new_tokens, 8);
    assert_eq!(published.invocation.stop_token_ids, [4, 5]);
}

#[tokio::test]
async fn prepared_text_round_trips_through_store() {
    let mut store = EvaluateArtifactStore::default();
    let recorded = store.record_prepared_text(&plan()).await.unwrap();
    let resolved = store
        .resolve_evaluate_request(recorded.evaluate_request.clone())
        .await
        .unwrap();

    assert_eq!(resolved.evaluate_request, recorded.evaluate_request);
    assert_eq!(resolved.invocation.input_ids, recorded.invocation.input_ids);
    assert_eq!(
        resolved.invocation.max_new_tokens,
        recorded.invocation.max_new_tokens
    );
    assert_eq!(
        resolved.invocation.stop_token_ids,
        recorded.invocation.stop_token_ids
    );
}

#[tokio::test]
async fn completed_text_artifact_can_start_a_followup() {
    let mut store = EvaluateArtifactStore::default();
    let first = store.record_prepared_text(&plan()).await.unwrap();
    let first_artifact = store
        .record_completed_text(&first.evaluate_request, &first.invocation, &[10, 11])
        .await
        .unwrap();
    let mut next_plan = plan();
    next_plan.invocation.input_ids = vec![20];
    next_plan.initial_artifact_id = Some(first_artifact);
    let next = store.record_prepared_text(&next_plan).await.unwrap();
    assert_eq!(next.invocation.input_ids, vec![1, 2, 3, 10, 11, 20]);
    let resolved = store
        .resolve_evaluate_request(next.evaluate_request)
        .await
        .unwrap();

    assert_eq!(resolved.invocation.input_ids, vec![1, 2, 3, 10, 11, 20]);
}

#[tokio::test]
async fn followup_rejects_an_output_artifact_with_inconsistent_state() {
    let mut store = EvaluateArtifactStore::default();
    let first = store.record_prepared_text(&plan()).await.unwrap();
    let execution = TextExecutionId::from_digest(first.evaluate_request.text_execution);
    let generated = store
        .insert_token_ids(TokenIds::from([10, 11]))
        .await
        .unwrap();
    let wrong_state_tokens = store.insert_token_ids(TokenIds::from([99])).await.unwrap();
    let wrong_state = store
        .insert_text_state(TextState::new(wrong_state_tokens))
        .await
        .unwrap();
    let inconsistent = store
        .insert_text_artifact(TextArtifact::output(execution, 2, wrong_state, generated))
        .await
        .unwrap();
    let mut next_plan = plan();
    next_plan.initial_artifact_id = Some(inconsistent.digest());

    let error = store.prepare_text(&next_plan).await.unwrap_err();
    assert!(error.to_string().contains("is inconsistent"), "{error}");
}

#[tokio::test]
async fn followup_revalidates_full_context_capacity() {
    let mut store = EvaluateArtifactStore::default();
    let first = store.record_prepared_text(&plan()).await.unwrap();
    let first_artifact = store
        .record_completed_text(&first.evaluate_request, &first.invocation, &[10, 11])
        .await
        .unwrap();
    let mut next_plan = plan();
    next_plan.invocation.input_ids = vec![20];
    next_plan.maximum_capacity = 13;
    next_plan.initial_artifact_id = Some(first_artifact);

    let error = store.record_prepared_text(&next_plan).await.unwrap_err();
    assert!(error.to_string().contains("environment capacity is 13"));
}

#[tokio::test]
async fn followup_rejects_an_artifact_from_another_environment() {
    let mut store = EvaluateArtifactStore::default();
    let mut other = plan();
    other.execution_environment = ContentId::from_bytes([9; 32]);
    let first = store.record_prepared_text(&other).await.unwrap();
    let first_artifact = store
        .record_completed_text(&first.evaluate_request, &first.invocation, &[10, 11])
        .await
        .unwrap();
    let mut next_plan = plan();
    next_plan.initial_artifact_id = Some(first_artifact);

    let error = store.record_prepared_text(&next_plan).await.unwrap_err();
    assert!(
        error
            .to_string()
            .contains("different execution environment")
    );
}

#[tokio::test]
async fn lazy_input_source_uses_cached_output_artifact() {
    let mut store = EvaluateArtifactStore::default();
    let first = store.record_prepared_text(&plan()).await.unwrap();
    store
        .record_completed_text(&first.evaluate_request, &first.invocation, &[10, 11])
        .await
        .unwrap();
    let first_execution = TextExecutionId::from_digest(first.evaluate_request.text_execution);
    let prompt_tokens = store.insert_token_ids(TokenIds::from([20])).await.unwrap();
    let policy = store
        .insert_policy(TextPolicy::from_u32_stop_tokens(4, []))
        .await
        .unwrap();
    let lazy = TextExecution::new(SourceRef::input(first_execution), prompt_tokens, policy);
    let lazy_id = store.insert_text_execution(lazy).await.unwrap();
    let resolved = store
        .resolve_evaluate_request(evaluate_request(lazy_id.digest()))
        .await
        .unwrap();

    assert_eq!(resolved.invocation.input_ids, vec![1, 2, 3, 10, 11, 20]);
}

#[tokio::test]
async fn lazy_input_rejects_metadata_that_does_not_realize_execution() {
    let mut store = EvaluateArtifactStore::default();
    let first = store.record_prepared_text(&plan()).await.unwrap();
    let first_execution = TextExecutionId::from_digest(first.evaluate_request.text_execution);
    let first_execution_value = store.text_execution(first_execution).await.unwrap();
    let identity_id = match first_execution_value.from() {
        SourceRef::Output(id) => *id,
        SourceRef::Input(_) => panic!("prepared genesis text should start at output"),
    };
    store
        .outputs_by_execution
        .insert(first_execution, identity_id);
    let prompt_tokens = store.insert_token_ids(TokenIds::from([20])).await.unwrap();
    let policy = store
        .insert_policy(TextPolicy::from_u32_stop_tokens(4, []))
        .await
        .unwrap();
    let lazy = TextExecution::new(SourceRef::input(first_execution), prompt_tokens, policy);
    let lazy_id = store.insert_text_execution(lazy).await.unwrap();
    let err = store
        .resolve_evaluate_request(evaluate_request(lazy_id.digest()))
        .await
        .unwrap_err();

    assert!(err.to_string().contains("maps to identity artifact"));
}

#[tokio::test]
async fn unknown_text_execution_is_rejected() {
    let mut store = EvaluateArtifactStore::default();
    let err = store
        .resolve_evaluate_request(evaluate_request(Digest::from_bytes([7; 32])))
        .await
        .unwrap_err();

    assert!(err.to_string().contains("missing TextExecution artifact"));
}

#[tokio::test]
async fn memory_capacity_reserves_before_publishing_a_second_graph() {
    let mut store = EvaluateArtifactStore::new(None, None, 1);
    let first = store.prepare_text(&plan()).await.unwrap();
    store
        .ensure_retention_available(&first.evaluate_request)
        .unwrap();
    store
        .record_completed_text_with_prepared(
            &first.evaluate_request,
            &first.invocation,
            &[10, 11],
            first.prepared_artifacts.as_ref(),
        )
        .await
        .unwrap();
    store
        .ensure_retention_available(&first.evaluate_request)
        .expect("replaying an already-retained execution needs no new slot");
    assert_eq!(
        store.canonical_keys.len(),
        MAX_CANONICAL_OBJECTS_PER_RETAINED_EXECUTION
    );

    let mut second_plan = plan();
    second_plan.invocation.input_ids = vec![99];
    let second = store.prepare_text(&second_plan).await.unwrap();
    let admission_error = store
        .ensure_retention_available(&second.evaluate_request)
        .unwrap_err();
    assert!(matches!(
        admission_error,
        ExecutorError::ResourceExhausted(_)
    ));

    let mut ephemeral = second.evaluate_request.clone();
    ephemeral.retain = false;
    store
        .ensure_retention_available(&ephemeral)
        .expect("ephemeral execution does not consume retained capacity");

    let error = store
        .record_completed_text_with_prepared(
            &second.evaluate_request,
            &second.invocation,
            &[12],
            second.prepared_artifacts.as_ref(),
        )
        .await
        .unwrap_err();

    assert!(matches!(error, ExecutorError::ResourceExhausted(_)));
    assert_eq!(store.retained_executions.len(), 1);
    assert_eq!(
        store.canonical_keys.len(),
        MAX_CANONICAL_OBJECTS_PER_RETAINED_EXECUTION
    );
}

#[test]
fn zero_retained_capacity_rejects_before_execution_but_allows_ephemeral_work() {
    let store = EvaluateArtifactStore::new(None, None, 0);
    let mut request = evaluate_request(Digest::from_bytes([42; 32]));
    assert!(matches!(
        store.ensure_retention_available(&request),
        Err(ExecutorError::ResourceExhausted(_))
    ));

    request.retain = false;
    store.ensure_retention_available(&request).unwrap();
}

#[test]
fn quotes_publish_nothing_and_successful_retained_execution_publishes_its_graph() {
    deterministic::Runner::default().start(|context| async move {
        let config = ArtifactStoreConfig::new(context.child("retained"));
        let mut store = EvaluateArtifactStore::open(config.clone()).await.unwrap();

        let mut ephemeral_plan = plan();
        ephemeral_plan.retention = hellas_rpc::Retention::Ephemeral;
        let ephemeral = store.prepare_text(&ephemeral_plan).await.unwrap();

        assert!(
            store
                .get_canonical_bytes(ephemeral.evaluate_request.text_execution)
                .await
                .is_err(),
            "an unused quote must publish no token graph"
        );
        let mut reopened = EvaluateArtifactStore::open(config.clone()).await.unwrap();
        assert!(
            reopened
                .get_canonical_bytes(ephemeral.evaluate_request.text_execution)
                .await
                .is_err(),
            "ephemeral token graph must not enter persistent storage"
        );

        let retained = store.prepare_text(&plan()).await.unwrap();
        store
            .record_completed_text_with_prepared(
                &retained.evaluate_request,
                &retained.invocation,
                &[10, 11],
                retained.prepared_artifacts.as_ref(),
            )
            .await
            .unwrap();

        let mut reopened = EvaluateArtifactStore::open(config).await.unwrap();
        assert!(
            reopened
                .get_canonical_bytes(retained.evaluate_request.text_execution)
                .await
                .is_ok(),
            "retained artifacts must remain available from persistent storage"
        );
    });
}

#[test]
fn commonware_store_rejects_corrupt_canonical_blob() {
    deterministic::Runner::default().start(|context| async move {
        let config = ArtifactStoreConfig::new(context.child("artifacts"));
        let digest = {
            let mut store = EvaluateArtifactStore::open(config.clone()).await.unwrap();
            let prepared = store.prepare_text(&plan()).await.unwrap();
            store
                .record_completed_text_with_prepared(
                    &prepared.evaluate_request,
                    &prepared.invocation,
                    &[10, 11],
                    prepared.prepared_artifacts.as_ref(),
                )
                .await
                .unwrap();
            prepared.evaluate_request.text_execution
        };
        let (blob, _) = context
            .open(CANONICAL_PARTITION, digest.as_bytes())
            .await
            .unwrap();
        blob.resize(0).await.unwrap();
        blob.write_at_sync(0, b"corrupt".to_vec()).await.unwrap();

        let mut store = EvaluateArtifactStore::open(config).await.unwrap();
        let err = store.get_canonical_bytes(digest).await.unwrap_err();
        assert!(err.to_string().contains("does not match requested digest"));
    });
}

#[test]
fn commonware_store_reopens_typed_artifacts_from_canonical_blobs() {
    deterministic::Runner::default().start(|context| async move {
        let config = ArtifactStoreConfig::new(context);
        let first_artifact;
        let first_request;
        {
            let mut store = EvaluateArtifactStore::open(config.clone()).await.unwrap();
            let first = store.record_prepared_text(&plan()).await.unwrap();
            first_artifact = store
                .record_completed_text(&first.evaluate_request, &first.invocation, &[10, 11])
                .await
                .unwrap();
            first_request = first.evaluate_request;
        }

        let mut store = EvaluateArtifactStore::open(config).await.unwrap();
        let resolved = store.resolve_evaluate_request(first_request).await.unwrap();
        assert_eq!(resolved.invocation.input_ids, vec![1, 2, 3]);

        let mut next_plan = plan();
        next_plan.invocation.input_ids = vec![20];
        next_plan.initial_artifact_id = Some(first_artifact);
        let next = store.record_prepared_text(&next_plan).await.unwrap();
        let resolved = store
            .resolve_evaluate_request(next.evaluate_request)
            .await
            .unwrap();
        assert_eq!(resolved.invocation.input_ids, vec![1, 2, 3, 10, 11, 20]);
    });
}

#[test]
fn commonware_store_reopens_cached_lazy_substitutions() {
    deterministic::Runner::default().start(|context| async move {
        let config = ArtifactStoreConfig::new(context);
        let first_execution;
        {
            let mut store = EvaluateArtifactStore::open(config.clone()).await.unwrap();
            let first = store.record_prepared_text(&plan()).await.unwrap();
            store
                .record_completed_text(&first.evaluate_request, &first.invocation, &[10, 11])
                .await
                .unwrap();
            first_execution = TextExecutionId::from_digest(first.evaluate_request.text_execution);
        }

        let mut store = EvaluateArtifactStore::open(config).await.unwrap();
        let prompt_tokens = store.insert_token_ids(TokenIds::from([20])).await.unwrap();
        let policy = store
            .insert_policy(TextPolicy::from_u32_stop_tokens(4, []))
            .await
            .unwrap();
        let lazy = TextExecution::new(SourceRef::input(first_execution), prompt_tokens, policy);
        let lazy_id = store.insert_text_execution(lazy).await.unwrap();
        let resolved = store
            .resolve_evaluate_request(evaluate_request(lazy_id.digest()))
            .await
            .unwrap();

        assert_eq!(resolved.invocation.input_ids, vec![1, 2, 3, 10, 11, 20]);
    });
}

#[test]
fn commonware_capacity_and_reservations_survive_restart() {
    deterministic::Runner::default().start(|context| async move {
        let config = ArtifactStoreConfig::new(context).with_retained_execution_capacity(1);
        {
            let mut store = EvaluateArtifactStore::open(config.clone()).await.unwrap();
            let first = store.prepare_text(&plan()).await.unwrap();
            store
                .record_completed_text_with_prepared(
                    &first.evaluate_request,
                    &first.invocation,
                    &[10, 11],
                    first.prepared_artifacts.as_ref(),
                )
                .await
                .unwrap();
        }

        let mut reopened = EvaluateArtifactStore::open(config).await.unwrap();
        let mut second_plan = plan();
        second_plan.invocation.input_ids = vec![99];
        let second = reopened.prepare_text(&second_plan).await.unwrap();
        let error = reopened
            .record_completed_text_with_prepared(
                &second.evaluate_request,
                &second.invocation,
                &[12],
                second.prepared_artifacts.as_ref(),
            )
            .await
            .unwrap_err();
        assert!(matches!(error, ExecutorError::ResourceExhausted(_)));
    });
}

#[test]
fn commonware_rejects_a_corrupt_reservation_at_restart() {
    deterministic::Runner::default().start(|context| async move {
        let config = ArtifactStoreConfig::new(context.child("corrupt_reservation"));
        let execution = {
            let mut store = EvaluateArtifactStore::open(config.clone()).await.unwrap();
            let first = store.prepare_text(&plan()).await.unwrap();
            store
                .record_completed_text_with_prepared(
                    &first.evaluate_request,
                    &first.invocation,
                    &[10, 11],
                    first.prepared_artifacts.as_ref(),
                )
                .await
                .unwrap();
            TextExecutionId::from_digest(first.evaluate_request.text_execution)
        };
        let (blob, _) = context
            .open(RETAINED_EXECUTION_PARTITION, execution.as_bytes())
            .await
            .unwrap();
        blob.resize(0).await.unwrap();
        blob.write_at_sync(0, b"corrupt".to_vec()).await.unwrap();

        let error = match EvaluateArtifactStore::open(config).await {
            Ok(_) => panic!("a corrupt reservation must fail closed"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("invalid retained execution reservation")
        );
    });
}
