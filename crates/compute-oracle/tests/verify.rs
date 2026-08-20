//! What the independent check catches, and what it cannot.
//!
//! The honest result every test starts from is built the way a provider
//! builds one: a real signed transcript, through
//! `hellas_rpc::protocol::work::terminal_result`. Nothing here computes
//! the expected digest with the function under test, so a derivation
//! that drifted would show up as the oracle rejecting an honest result
//! rather than as two wrongs agreeing.

use hellas_compute_oracle::{
    OracleFault, Reexecuted, Reexecution, ReexecutionRequest, plan, verify,
};
use hellas_kernel::{
    BlockHeight, EdgeId, List, MAX_EDGE_OUTPUTS, NetworkId, Parties, Payout, Secp256k1Signer,
    WorkPaymentTerms, WorkStakeBondTerms,
};
use hellas_rpc::evaluate::{
    EvaluateOutputTranscriptBuilder, EvaluateStopReason, EvaluateTerminal, EvaluateUsage,
    input_commitment,
};
use hellas_rpc::protocol::artifacts::{
    BoundTermId, InputAddressed as _, OutputAddressed as _, PreparedPaidInputV1, SourceRef,
    TextArtifact, TextExecution, TextExecutionId, TextPolicy, TokenIds, completed_text,
};
use hellas_rpc::protocol::work::{
    JobDeadlines, PaidChannel, PaidChannelPolicyV1, PaidExecutionPolicyV1, PaidJobAuthorizationV1,
    PaidJobResultV1, generation_policy_digest, identity_source_digest, private_policy_commitment,
    propose_authorization, terminal_result, work_id,
};
use hellas_rpc::{
    Assurance, ContentId, Digest, EvaluateProgramManifest, EvaluateRequest, OutputEventEnvelope,
    ProducerSigningKey, ProgramManifest, PublicKey,
};

// ── Fixture ───────────────────────────────────────────────────────────

const SALT: [u8; 32] = [0x5a; 32];
const PRICE: u64 = 10;
const HORIZON: u64 = 500;
/// The prompt every job here runs on.
const PROMPT: [u32; 4] = [9, 8, 7, 6];
/// The answer an honest provider returns for it.
const ANSWER: [u32; 3] = [101, 102, 103];
const MODEL: &str = "test-model";
const REVISION: &str = "main";
const DTYPE: &str = "f32";
const MAX_NEW_TOKENS: u32 = 64;
const STOP_TOKENS: [u32; 2] = [1, 2];

fn network() -> NetworkId {
    let Some(network) = NetworkId::new("hellas-test") else {
        panic!("a short ascii id is a legal network id");
    };
    network
}

fn signer(byte: u8) -> Secp256k1Signer {
    let Ok(signer) = Secp256k1Signer::from_secret_scalar([byte; 32]) else {
        panic!("a fixed scalar is a key");
    };
    signer
}

fn client() -> Secp256k1Signer {
    signer(0x21)
}

fn provider() -> Secp256k1Signer {
    signer(0x22)
}

fn provider_producer() -> ProducerSigningKey {
    match ProducerSigningKey::from_secret_bytes([0x22; 32]) {
        Ok(key) => key,
        Err(error) => panic!("a fixed scalar is a producer key: {error}"),
    }
}

fn channel_policy() -> PaidChannelPolicyV1 {
    PaidChannelPolicyV1 {
        compute_credit_limit: 100,
        delivery_credit_limit: 100,
    }
}

fn payment_terms() -> WorkPaymentTerms {
    WorkPaymentTerms {
        bond_edge: EdgeId::from_bytes([0x11; 32]),
        bond_terms: WorkStakeBondTerms {
            parties: Parties::new(provider().party_key(), client().party_key()),
            timeout: BlockHeight::new(HORIZON),
            timeout_outputs: List::take(
                [Payout::new(provider().party_key(), 64); MAX_EDGE_OUTPUTS],
                1,
            ),
            max_job_price: 40,
        },
        private_policy_commitment: private_policy_commitment(network(), &SALT, &channel_policy()),
        omit_response_blocks: hellas_kernel::MIN_OMIT_RESPONSE_BLOCKS,
        start_validity_blocks: 8,
        omission_bond: 4,
    }
}

fn channel() -> PaidChannel {
    match PaidChannel::new(
        network(),
        EdgeId::from_bytes([0x22; 32]),
        payment_terms(),
        &SALT,
        channel_policy(),
    ) {
        Ok(channel) => channel,
        Err(error) => panic!("the fixture channel opens: {error}"),
    }
}

fn manifest() -> ProgramManifest {
    ProgramManifest::Evaluate(EvaluateProgramManifest {
        weights: vec![ContentId::from_bytes([0x11; 32])],
        graph: ContentId::from_bytes([0x12; 32]),
        config: ContentId::from_bytes([0x13; 32]),
        tokenizer: ContentId::from_bytes([0x14; 32]),
        resolved_revision: REVISION.into(),
        numeric_profile: "f32-cpu".into(),
        backend_profile: "catena-v1".into(),
        build: ContentId::from_bytes([0x15; 32]),
    })
}

fn identity_artifact() -> TextArtifact {
    TextArtifact::identity(
        BoundTermId::from_digest(manifest().content_id().digest()),
        MODEL,
        REVISION,
        DTYPE,
    )
}

fn text_policy() -> TextPolicy {
    TextPolicy::from_u32_stop_tokens(MAX_NEW_TOKENS, STOP_TOKENS)
}

fn text_execution() -> TextExecution {
    TextExecution::new(
        SourceRef::output(identity_artifact().output_id()),
        TokenIds::from(PROMPT.to_vec()).output_id(),
        text_policy().output_id(),
    )
}

fn evaluate_request() -> EvaluateRequest {
    EvaluateRequest {
        text_execution: text_execution().input_id().digest(),
        runner_public_key: PublicKey::Secp256k1(client().party_key().to_bytes()),
        execution_environment: manifest().content_id(),
        nonce: [0x33; 32],
        assurance: Assurance::ProducerSigned,
        retain: true,
    }
}

fn bundle() -> PreparedPaidInputV1 {
    PreparedPaidInputV1::new(
        &evaluate_request(),
        &manifest(),
        &text_execution(),
        &TokenIds::from(PROMPT.to_vec()),
        &text_policy(),
        &identity_artifact(),
    )
}

fn execution_policy() -> PaidExecutionPolicyV1 {
    PaidExecutionPolicyV1 {
        allowed_environment: manifest().content_id(),
        generation_policy_digest: match generation_policy_digest(
            &hellas_rpc::protocol::artifacts::Canonical::canonical_bytes(&text_policy()),
        ) {
            Ok(digest) => digest,
            Err(error) => panic!("the fixture policy hashes: {error}"),
        },
        identity_source_digest: match identity_source_digest(
            &hellas_rpc::protocol::artifacts::Canonical::canonical_bytes(&identity_artifact()),
        ) {
            Ok(digest) => digest,
            Err(error) => panic!("the fixture identity hashes: {error}"),
        },
        max_prompt_tokens: 512,
        max_new_tokens: 128,
        max_stop_token_ids: 4,
        max_canonical_output_bytes: 65_536,
        max_spool_bytes: 1_048_576,
        max_encoded_result_frame: 262_144,
        max_encoded_quote_response: 1_048_576,
        dispatch_margin_blocks: 4,
        delivery_margin_blocks: 2,
        oracle_grace_blocks: 6,
        fixed_price: PRICE,
    }
}

fn authorization() -> PaidJobAuthorizationV1 {
    match propose_authorization(
        &channel(),
        &execution_policy(),
        &bundle(),
        1,
        JobDeadlines {
            acceptance: 50,
            terminal: 100,
            payment: 200,
        },
    ) {
        Ok(authorization) => authorization,
        Err(error) => panic!("the fixture authorization builds: {error}"),
    }
}

/// The result an honest provider signs for `answer`, built the way a
/// provider builds one: a real signed transcript, summarised by the
/// crate's own constructor.
fn honest_result(answer: &[u32]) -> PaidJobResultV1 {
    let channel = channel();
    let authorization = authorization();
    let request = evaluate_request();
    let key = provider_producer();
    let mut builder =
        EvaluateOutputTranscriptBuilder::new(input_commitment(&request), request.assurance, &key);
    if let Err(error) = builder.push_token_delta(answer.to_vec()) {
        panic!("a non-empty delta pushes: {error}");
    }
    let usage = EvaluateUsage {
        input_units: PROMPT.len() as u64,
        output_units: answer.len() as u64,
    };
    let billable_units = match usage.billable_units() {
        Ok(units) => units,
        Err(error) => panic!("the fixture usage sums: {error}"),
    };
    // The artifact a provider's store records for this execution. It is
    // pinned to bytes independently in `hellas-rpc`'s vector suite, so
    // this is the provider's side of the correspondence rather than a
    // second call to the thing under test.
    let text_artifact = completed_text(
        TextExecutionId::from_digest(request.text_execution),
        &PROMPT,
        answer,
    )
    .artifact
    .output_id()
    .digest();
    let transcript: Vec<OutputEventEnvelope> = match builder.finish(EvaluateTerminal {
        final_position: answer.len() as u64,
        stop_reason: EvaluateStopReason::END_OF_SEQUENCE,
        text_artifact,
        usage,
        billable_units,
    }) {
        Ok(events) => events,
        Err(error) => panic!("the fixture transcript finishes: {error}"),
    };
    match terminal_result(&channel, &authorization, &transcript) {
        Ok(result) => result,
        Err(error) => panic!("the fixture transcript is a terminal: {error}"),
    }
}

// ── The engine double ─────────────────────────────────────────────────

/// A deterministic engine that returns what it was told to, and records
/// the question it was asked.
struct FixedEngine {
    answer: Result<Reexecuted, OracleFault>,
    asked: std::sync::Mutex<Vec<ReexecutionRequest>>,
}

impl FixedEngine {
    fn answering(tokens: &[u32], stop_reason: EvaluateStopReason) -> Self {
        Self {
            answer: Ok(Reexecuted {
                output_token_ids: tokens.to_vec(),
                stop_reason,
            }),
            asked: std::sync::Mutex::new(Vec::new()),
        }
    }

    fn honest() -> Self {
        Self::answering(&ANSWER, EvaluateStopReason::END_OF_SEQUENCE)
    }

    fn failing(reason: &str) -> Self {
        Self {
            answer: Err(OracleFault::Engine(reason.to_string())),
            asked: std::sync::Mutex::new(Vec::new()),
        }
    }

    fn questions(&self) -> Vec<ReexecutionRequest> {
        match self.asked.lock() {
            Ok(asked) => asked.clone(),
            Err(error) => panic!("the engine's log is readable: {error}"),
        }
    }
}

impl Reexecution for FixedEngine {
    fn reexecute(&self, request: &ReexecutionRequest) -> Result<Reexecuted, OracleFault> {
        match self.asked.lock() {
            Ok(mut asked) => asked.push(request.clone()),
            Err(error) => panic!("the engine's log is writable: {error}"),
        }
        self.answer.clone()
    }
}

fn check(engine: &FixedEngine, result: &PaidJobResultV1) -> Result<(), OracleFault> {
    let channel = channel();
    verify(
        engine,
        channel.network(),
        work_id(&channel, &authorization()),
        &bundle(),
        result,
    )
}

// ── The question the oracle asks ──────────────────────────────────────

/// The plan is derived from the accepted bundle, field by field.
///
/// Each assertion names one thing an engine would otherwise have to be
/// told by the provider.
#[test]
fn the_question_comes_from_the_accepted_bundle() {
    let Ok(plan) = plan(&bundle()) else {
        panic!("the fixture bundle plans");
    };
    assert_eq!(plan.model_id, MODEL);
    assert_eq!(plan.revision, REVISION);
    assert_eq!(plan.dtype, DTYPE);
    assert_eq!(plan.environment, manifest().content_id());
    assert_eq!(plan.prompt_token_ids, PROMPT);
    assert_eq!(plan.max_new_tokens, MAX_NEW_TOKENS);
    // The policy sorts and dedups its stop tokens, so this is the set
    // the execution names rather than the order it was written in.
    assert_eq!(plan.stop_token_ids, [1, 2]);
}

/// A job that resumes a previous output is not one this profile can
/// reexecute, and says so rather than guessing an empty prompt.
#[test]
fn a_job_that_resumes_an_output_is_refused() {
    let resumed = TextArtifact::output(
        TextExecutionId::from_bytes([0x41; 32]),
        3,
        hellas_rpc::protocol::artifacts::TextStateId::from_bytes([0x42; 32]),
        TokenIds::from(vec![1_u32]).output_id(),
    );
    let execution = TextExecution::new(
        SourceRef::output(resumed.output_id()),
        TokenIds::from(PROMPT.to_vec()).output_id(),
        text_policy().output_id(),
    );
    let mut request = evaluate_request();
    request.text_execution = execution.input_id().digest();
    let bundle = PreparedPaidInputV1::new(
        &request,
        &manifest(),
        &execution,
        &TokenIds::from(PROMPT.to_vec()),
        &text_policy(),
        &resumed,
    );
    assert_eq!(
        plan(&bundle),
        Err(OracleFault::Unsupported {
            what: "input is a previous output rather than an identity",
        })
    );
}

// ── The verdict ───────────────────────────────────────────────────────

/// An honest provider's result reproduces, and the engine was asked the
/// bundle's own question.
#[test]
fn an_honest_answer_reproduces() {
    let engine = FixedEngine::honest();
    assert_eq!(check(&engine, &honest_result(&ANSWER)), Ok(()));
    let asked = engine.questions();
    assert_eq!(asked.len(), 1, "the engine is asked once");
    assert_eq!(
        asked
            .first()
            .map(|question| question.prompt_token_ids.clone()),
        Some(PROMPT.to_vec())
    );
}

/// One token other, and the check fails — with the provider's signature
/// over the altered result perfectly valid.
///
/// This is the defect the whole phase exists to catch: a provider free
/// to answer anything, signing honestly, and refused by arithmetic the
/// client did itself.
#[test]
fn one_token_other_is_a_different_answer() {
    let mut altered = ANSWER;
    altered[1] = 999;
    let dishonest = honest_result(&altered);
    assert_ne!(
        dishonest.canonical_output_digest,
        honest_result(&ANSWER).canonical_output_digest,
        "the two results differ, so the check below has something to find",
    );

    let engine = FixedEngine::honest();
    assert_eq!(check(&engine, &dishonest), Err(OracleFault::Mismatch));

    // The control: an engine that agrees with the altered answer
    // accepts it. The oracle compares two computations; it does not
    // know which is right.
    let agreeing = FixedEngine::answering(&altered, EvaluateStopReason::END_OF_SEQUENCE);
    assert_eq!(check(&agreeing, &dishonest), Ok(()));
}

/// A truncated or extended answer is a different answer, though every
/// token it does carry is right.
#[test]
fn a_prefix_and_a_continuation_are_both_refused() {
    let engine = FixedEngine::honest();
    for (name, answer) in [
        ("a prefix", &ANSWER[..2]),
        ("a continuation", &[101, 102, 103, 104][..]),
    ] {
        assert_eq!(
            check(&engine, &honest_result(answer)),
            Err(OracleFault::Mismatch),
            "{name} is not the answer",
        );
    }
}

/// The same tokens under a different stop reason are a different
/// answer.
///
/// The stop reason is signed and is not cosmetic: it is the difference
/// between a job that finished and one that ran out of budget.
#[test]
fn the_stop_reason_is_part_of_the_answer() {
    let honest = honest_result(&ANSWER);
    let other_reason = FixedEngine::answering(&ANSWER, EvaluateStopReason::MAX_OUTPUT);
    assert_eq!(check(&other_reason, &honest), Err(OracleFault::Mismatch));

    // The control: the same engine answering with the signed reason.
    assert_eq!(check(&FixedEngine::honest(), &honest), Ok(()));
}

/// An engine that fails says the check did not happen, and does not say
/// the provider was wrong.
#[test]
fn an_engine_fault_is_not_a_finding() {
    let engine = FixedEngine::failing("the weights did not load");
    let fault = check(&engine, &honest_result(&ANSWER));
    let Err(OracleFault::Engine(reason)) = fault else {
        panic!("an engine fault is reported as one: {fault:?}");
    };
    assert!(reason.contains("the weights did not load"), "{reason}");
}

/// The verdict is bound to the job: the same answer under another
/// `work_id` does not reproduce.
///
/// This is why the client takes the three from one journal record. The
/// digest binds the job, so a caller that paired them wrongly gets a
/// mismatch rather than a wrong pass.
#[test]
fn the_answer_is_bound_to_the_job_it_answers() {
    let engine = FixedEngine::honest();
    let honest = honest_result(&ANSWER);
    let channel = channel();
    assert_eq!(
        verify(
            &engine,
            channel.network(),
            Digest::from_bytes([0x99; 32]),
            &bundle(),
            &honest,
        ),
        Err(OracleFault::Mismatch),
    );

    // And to the network, which the same digest also binds.
    let Some(elsewhere) = NetworkId::new("hellas-other") else {
        panic!("a short ascii id is a legal network id");
    };
    assert_eq!(
        verify(
            &engine,
            elsewhere,
            work_id(&channel, &authorization()),
            &bundle(),
            &honest,
        ),
        Err(OracleFault::Mismatch),
    );
}
