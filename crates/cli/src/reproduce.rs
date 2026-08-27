//! The client-side separate re-execution, over a second in-process
//! executor.
//!
//! # What this is
//!
//! One implementation of [`Reproducer`], over a second
//! [`ExecutorHandle`] the CLI owns. It runs the retained request in the
//! client's own journal-held bundle — the request both parties signed —
//! through exactly the same evaluate implementation the provider's
//! [`hellas_rpc::work::PaidEvaluateBackend`] uses, and reads the answer
//! back out of the signed transcript.
//!
//! # Why it is separate
//!
//! It reaches no gateway and no network. The handle is held in-process,
//! and nothing here opens a connection or consults a provider. That is
//! the whole of what makes the client's re-execution its own: it is a
//! second run of the same implementation on the client's side of the
//! wire, not a second reading of the provider's answer.
//!
//! It cannot be more independent than that second run is: this repository
//! ships one backend, so the re-execution reproduces the provider's bugs
//! as faithfully as its correct answers. What it is not is a reading of
//! the provider's bytes — the tokens come back out of an execution this
//! process drove, and the digest the client compares is rebuilt from
//! them.
//!
//! # Not covered by a test here
//!
//! That the backend, given this request, produces those tokens. Running
//! it needs model weights, so no check in this repository executes this
//! path end to end — the same gap `hellas_executor::work` documents for
//! the provider's backend.

use hellas_client::work::reproduce::{ReproduceFault, Reproduced, Reproducer};
use hellas_executor::ExecutorHandle;
use hellas_rpc::evaluate::{input_commitment, verify_output_events};
use hellas_rpc::pb::courtesy::PutArtifactRequest;
use hellas_rpc::protocol::artifacts::{Canonical as _, PreparedPaidInputV1};

/// A [`Reproducer`] that runs the retained request over a second
/// in-process executor and reads the answer out of the signed transcript.
///
/// Not yet reached by a command: the client-side paid-work command that
/// drives `collect_checked_result` with this reproducer is a later
/// slice's, so this is constructed nowhere in this crate yet. It is here
/// now because it is the client half of the mount's claim — a separate
/// client-side re-execution — and it belongs beside the executor the CLI
/// already owns.
#[allow(dead_code)]
pub struct LocalReproducer {
    handle: ExecutorHandle,
}

#[allow(dead_code)]
impl LocalReproducer {
    /// Builds a reproducer over `handle`.
    ///
    /// The handle must be a *second* executor — separate from the one the
    /// provider serves from — so the client's run shares no completed
    /// execution with the provider's. It may be a fresh one: the bundle
    /// carries every canonical body the request is resolved from, and
    /// [`Self::reproduce`] publishes them into the handle's own artifact
    /// store before it evaluates.
    #[must_use]
    pub const fn new(handle: ExecutorHandle) -> Self {
        Self { handle }
    }
}

impl Reproducer for LocalReproducer {
    async fn reproduce(&self, bundle: &PreparedPaidInputV1) -> Result<Reproduced, ReproduceFault> {
        // The retained request the bundle both parties signed carries, run
        // in-process. There is no gateway and no network reachable from
        // here, and nothing consults the provider.
        let parts = bundle
            .parts()
            .map_err(|error| ReproduceFault::Body(error.to_string()))?;
        let request = parts.evaluate_request.clone();
        let input = input_commitment(&request);
        let assurance = request.assurance;

        // The hydration below reaches the retained store, which is the
        // one an executor resolves a retained request from. An ephemeral
        // request resolves from a separate memory store this handle
        // deliberately cannot reach, so it is refused as out of profile
        // rather than failing later as a missing artifact.
        if !request.retain {
            return Err(ReproduceFault::Unsupported {
                what: "request is ephemeral rather than retained",
            });
        }

        // A second executor starts with an empty artifact store, and the
        // engine resolves the request from that store — the execution,
        // the prompt tokens, the policy, and the identity artifact it
        // starts from. The bundle carries exactly those canonical bodies,
        // so they are published into this handle before anything is
        // evaluated. Content-addressed both ways: the store refuses bytes
        // that do not hash to their own id, and the resolution re-derives
        // every id it reads, so nothing here can substitute a body the
        // authorization did not commit to.
        for body in [
            parts.text_execution.canonical_bytes(),
            parts.prompt_tokens.canonical_bytes(),
            parts.text_policy.canonical_bytes(),
            parts.identity_artifact.canonical_bytes(),
        ] {
            self.handle
                .put_artifact_handle(PutArtifactRequest {
                    canonical_artifact: body,
                })
                .await
                .map_err(|error| ReproduceFault::Engine(error.to_string()))?;
        }

        let events = self
            .handle
            .run_paid_evaluate(request)
            .await
            .map_err(|error| ReproduceFault::Engine(error.to_string()))?;

        // The answer is read back out of the signed transcript, exactly as
        // the provider's own result was derived from it: the token deltas
        // concatenated in position order, and the terminal's stop reason.
        let output = verify_output_events(input, assurance, &events)
            .map_err(|error| ReproduceFault::Engine(error.to_string()))?;
        Ok(Reproduced {
            output_token_ids: output
                .token_deltas
                .iter()
                .flat_map(|delta| delta.token_ids.iter().copied())
                .collect(),
            stop_reason: output.terminal.stop_reason,
        })
    }
}

// Behind the `evaluate` feature because these tests drive a real
// in-process evaluate engine up to the one thing this environment lacks
// — the model weights. Under plain `node` the executor has no evaluate
// engine at all, so the empty-store failure these tests pin could not
// even be reached: `cargo test -p hellas-cli --features evaluate`.
#[cfg(all(test, feature = "evaluate"))]
mod tests {
    use super::LocalReproducer;
    use hellas_client::work::reproduce::{ReproduceFault, Reproducer as _};
    use hellas_executor::Executor;
    use hellas_rpc::pb::courtesy::GetArtifactRequest;
    use hellas_rpc::protocol::artifacts::{
        BoundTermId, Canonical as _, InputAddressed as _, OutputAddressed as _,
        PreparedPaidInputV1, SourceRef, TextArtifact, TextExecution, TextPolicy, TokenIds,
    };
    use hellas_rpc::{
        Assurance, ContentId, EvaluateProgramManifest, EvaluateRequest, ProducerSigningKey,
        ProgramManifest,
    };

    fn manifest() -> ProgramManifest {
        ProgramManifest::Evaluate(EvaluateProgramManifest {
            weights: vec![ContentId::from_bytes([0x11; 32])],
            graph: ContentId::from_bytes([0x12; 32]),
            config: ContentId::from_bytes([0x13; 32]),
            tokenizer: ContentId::from_bytes([0x14; 32]),
            resolved_revision: "main".into(),
            numeric_profile: "f32-cpu".into(),
            backend_profile: "catena-v1".into(),
            build: ContentId::from_bytes([0x15; 32]),
        })
    }

    fn identity_artifact() -> TextArtifact {
        TextArtifact::identity(
            BoundTermId::from_digest(manifest().content_id().digest()),
            "test-model",
            "main",
            "f32",
        )
    }

    fn text_policy() -> TextPolicy {
        TextPolicy::from_u32_stop_tokens(64, [1, 2])
    }

    fn prompt_tokens() -> TokenIds {
        TokenIds::from(vec![9_u32, 8, 7, 6])
    }

    fn text_execution() -> TextExecution {
        TextExecution::new(
            SourceRef::output(identity_artifact().output_id()),
            prompt_tokens().output_id(),
            text_policy().output_id(),
        )
    }

    fn evaluate_request(retain: bool) -> EvaluateRequest {
        let key = match ProducerSigningKey::from_secret_bytes([0x22; 32]) {
            Ok(key) => key,
            Err(error) => panic!("a fixed scalar is a producer key: {error}"),
        };
        EvaluateRequest {
            text_execution: text_execution().input_id().digest(),
            runner_public_key: key.public_key(),
            execution_environment: manifest().content_id(),
            nonce: [0x33; 32],
            assurance: Assurance::ProducerSigned,
            retain,
        }
    }

    fn bundle(retain: bool) -> PreparedPaidInputV1 {
        PreparedPaidInputV1::new(
            &evaluate_request(retain),
            &manifest(),
            &text_execution(),
            &prompt_tokens(),
            &text_policy(),
            &identity_artifact(),
        )
    }

    fn fresh_reproducer() -> LocalReproducer {
        let key = match ProducerSigningKey::from_secret_bytes([0x44; 32]) {
            Ok(key) => key,
            Err(error) => panic!("a fixed scalar is a producer key: {error}"),
        };
        let handle = match Executor::spawn_with_producer_key(
            hellas_rpc::policy::ExecutePolicy::Eager,
            hellas_rpc::DEFAULT_EXECUTION_QUEUE_CAPACITY,
            vec![hellas_rpc::Dtype::F32],
            key,
            b"genesis".to_vec(),
            Assurance::ProducerSigned,
        ) {
            Ok(handle) => handle,
            Err(error) => panic!("a fresh executor spawns: {error}"),
        };
        LocalReproducer::new(handle)
    }

    /// A fresh second executor is hydrated from the bundle itself.
    ///
    /// The constructor's contract is "a second executor", and a second
    /// executor has an empty artifact store. Before this hydration
    /// existed, the engine failed here with `missing TextExecution
    /// artifact` — the store had never seen the bodies the request is
    /// resolved from. Now the failure is the one thing this test
    /// environment genuinely lacks: the model weights. The store itself
    /// demonstrably holds the bundle's execution afterwards.
    #[tokio::test]
    async fn a_fresh_executor_is_hydrated_from_the_bundle() {
        let reproducer = fresh_reproducer();
        let fault = reproducer
            .reproduce(&bundle(true))
            .await
            .expect_err("no weights for the fixture model exist");
        let ReproduceFault::Engine(reason) = fault else {
            panic!("an engine refusal is an engine fault: {fault:?}");
        };
        assert!(
            !reason.contains("missing TextExecution artifact"),
            "the bundle's bodies were not hydrated: {reason}",
        );
        assert!(
            reason.contains("test-model"),
            "the refusal is about the model, not the store: {reason}",
        );

        // The positive half: the store now holds the exact canonical
        // execution the bundle carried, at its own content id.
        let stored = match reproducer
            .handle
            .get_artifact_handle(GetArtifactRequest {
                digest: text_execution().input_id().digest().as_bytes().to_vec(),
            })
            .await
        {
            Ok(response) => response,
            Err(error) => panic!("the hydrated execution reads back: {error}"),
        };
        assert_eq!(
            stored.canonical_artifact,
            text_execution().canonical_bytes()
        );
    }

    /// An ephemeral request is out of profile, said up front.
    ///
    /// The hydration reaches the retained store, and an ephemeral request
    /// resolves from a memory store this handle deliberately cannot
    /// reach; refusing early is what keeps that from surfacing as a
    /// confusing missing-artifact engine fault.
    #[tokio::test]
    async fn an_ephemeral_request_is_refused_as_out_of_profile() {
        let reproducer = fresh_reproducer();
        let fault = reproducer
            .reproduce(&bundle(false))
            .await
            .expect_err("an ephemeral request cannot be hydrated");
        assert_eq!(
            fault,
            ReproduceFault::Unsupported {
                what: "request is ephemeral rather than retained",
            },
        );
    }
}
