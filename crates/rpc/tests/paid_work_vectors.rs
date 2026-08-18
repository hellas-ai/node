//! Independent vectors and mutation proofs for the paid-work records.
//!
//! Authored outside the implementation module on purpose. Every
//! canonical encoding here is pinned as a hex string decoded field by
//! field, because a round-trip test cannot see a field order that moved
//! in the encoder and the decoder together, and every digest is pinned
//! as a hex string, because a digest recomputed by the same code it is
//! being compared against is not a vector.
//!
//! Each mutation test states what it breaks. A rule with no test that
//! fails when the rule is deleted is not a rule.

#![cfg(feature = "work")]

use hellas_kernel::{
    BlockHeight, EarnedCertificate, EdgeId, EdgeValues, Fees, List, NetworkId, Parties, Payout,
    Secp256k1Signer, Secp256k1Verifier, SigVerifier, TermsHash, WorkPaymentSettlement,
    WorkPaymentTerms, WorkStakeBondTerms, work_payment_settlement,
};
use hellas_rpc::evaluate::{EvaluateStopReason, EvaluateTerminal, EvaluateUsage};
use hellas_rpc::protocol::artifacts::{
    BoundTermId, Canonical, InputAddressed, OutputAddressed, PreparedPaidInputV1, SourceRef,
    TextArtifact, TextExecution, TextPolicy, TextState, TokenIds,
};
use hellas_rpc::protocol::work::{
    CertificateAllocationV1, CreditLedger, InvoiceEntryV1, InvoicedJob, MAX_ALLOCATION_ENTRIES,
    PaidChannel, PaidChannelPolicyV1, PaidExecutionPolicyV1, PaidJobAuthorizationV1,
    PaidJobResultV1, PaidWorkError, PrivateRecord, allocation_digest, canonical_output_digest,
    check_authorization, check_execution_policy, check_prepared_input, check_result,
    execution_policy_digest, generation_policy_digest, identity_source_digest, invoice_digest,
    invoice_empty_root, invoice_entries_root, next_invoice_entry, prepared_input_digest,
    private_policy_commitment, result_digest, work_id,
};
use hellas_rpc::{
    Assurance, ContentId, Digest, Evaluate, EvaluateProgramManifest, EvaluateRequest,
    EventCommitment, ProgramManifest, PublicKey, RequestCommitment,
};

// ── Fixtures ──────────────────────────────────────────────────────────

const NETWORK: &str = "hellas-devnet-1";
const OTHER_NETWORK: &str = "hellas-devnet-22";
/// The channel's certificate capacity, from the kernel's own settlement
/// arithmetic over an edge that locks a million and reserves nothing.
fn capacity() -> WorkPaymentSettlement {
    let Some(settlement) = work_payment_settlement(
        EdgeValues::new(1_000_000 + payment_terms().omission_bond, 0, Fees::ZERO),
        payment_terms().omission_bond,
    ) else {
        panic!("a funded edge prices both exits");
    };
    assert_eq!(settlement.capacity(), 1_000_000);
    settlement
}
const SALT: [u8; 32] = [0x5a; 32];

fn evaluate_request_bytes_of() -> Vec<u8> {
    hellas_rpc::protocol::schemes::evaluate::evaluate_request_bytes(&evaluate_request())
}

/// Assembles bundle bytes from six arbitrary bodies, so a test can build
/// a spelling the constructor would never produce.
fn assemble(bodies: &[&[u8]]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for body in bodies {
        bytes.extend_from_slice(&(body.len() as u32).to_be_bytes());
        bytes.extend_from_slice(body);
    }
    bytes
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The three fallible digests over variable-length bodies, unwrapped.
///
/// Every fixture body here is a few hundred bytes, so the only error
/// these can return — a body too long for its `u32` length prefix — is
/// noise at each of their sixteen call sites.
fn input_digest(channel: &PaidChannel, bundle: &PreparedPaidInputV1) -> Digest {
    prepared_input_digest(channel, bundle).expect("a representable bundle")
}

fn policy_digest_of(policy: &TextPolicy) -> Digest {
    generation_policy_digest(&policy.canonical_bytes()).expect("a representable policy body")
}

fn identity_digest_of(artifact: &TextArtifact) -> Digest {
    identity_source_digest(&artifact.canonical_bytes()).expect("a representable artifact body")
}

fn network() -> NetworkId {
    NetworkId::new(NETWORK).expect("legal network id")
}

fn client() -> Secp256k1Signer {
    Secp256k1Signer::from_secret_scalar([3; 32]).expect("legal scalar")
}

fn provider() -> Secp256k1Signer {
    Secp256k1Signer::from_secret_scalar([4; 32]).expect("legal scalar")
}

fn payment_terms() -> WorkPaymentTerms {
    let bond = WorkStakeBondTerms {
        // Bond maker is the provider, taker is the client; the payment
        // edge mirrors that, which is where `PaidChannel` reads its keys.
        parties: Parties::new(provider().party_key(), client().party_key()),
        timeout: BlockHeight::new(5_000),
        timeout_outputs: List::take(
            [
                Payout::new(provider().party_key(), 900),
                Payout::default(),
                Payout::default(),
                Payout::default(),
            ],
            1,
        ),
        max_job_price: 500,
    };
    WorkPaymentTerms {
        bond_edge: EdgeId::from_bytes([0xb0; 32]),
        bond_terms: bond,
        private_policy_commitment: private_policy_commitment(network(), &SALT, &channel_policy()),
        omit_response_blocks: 32,
        start_validity_blocks: 16,
        omission_bond: 100,
    }
}

fn channel() -> PaidChannel {
    PaidChannel::new(
        network(),
        EdgeId::from_bytes([0xe1; 32]),
        payment_terms(),
        &SALT,
        channel_policy(),
    )
    .expect("terms that commit to this credit policy")
}

/// A channel on another network, or another payment edge.
///
/// The credit commitment binds the network, so terms minted for one
/// network do not open on another: a foreign channel is built from
/// foreign terms, which is what a foreign channel is.
fn channel_on(network: NetworkId, payment_edge: EdgeId) -> PaidChannel {
    let terms = WorkPaymentTerms {
        private_policy_commitment: private_policy_commitment(network, &SALT, &channel_policy()),
        ..payment_terms()
    };
    PaidChannel::new(network, payment_edge, terms, &SALT, channel_policy())
        .expect("terms that commit to this credit policy")
}

fn channel_policy() -> PaidChannelPolicyV1 {
    PaidChannelPolicyV1 {
        compute_credit_limit: 700,
        delivery_credit_limit: 800,
    }
}

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

fn prompt_tokens() -> TokenIds {
    TokenIds::from([9, 8, 7, 6])
}

fn text_policy() -> TextPolicy {
    TextPolicy::from_u32_stop_tokens(64, [2, 1])
}

fn identity_artifact() -> TextArtifact {
    TextArtifact::identity(
        BoundTermId::from_bytes([0x21; 32]),
        "test-model",
        "main",
        "f32",
    )
}

fn text_execution() -> TextExecution {
    TextExecution::new(
        SourceRef::output(identity_artifact().output_id()),
        prompt_tokens().output_id(),
        text_policy().output_id(),
    )
}

fn evaluate_request() -> EvaluateRequest {
    EvaluateRequest {
        text_execution: text_execution().input_id().digest(),
        runner_public_key: PublicKey::Secp256k1(client().party_key().to_bytes()),
        execution_environment: manifest().content_id(),
        nonce: [0x77; 32],
        assurance: Assurance::ProducerSigned,
        retain: true,
    }
}

fn bundle() -> PreparedPaidInputV1 {
    PreparedPaidInputV1::new(
        &evaluate_request(),
        &manifest(),
        &text_execution(),
        &prompt_tokens(),
        &text_policy(),
        &identity_artifact(),
    )
}

fn execution_policy() -> PaidExecutionPolicyV1 {
    PaidExecutionPolicyV1 {
        allowed_environment: manifest().content_id(),
        generation_policy_digest: policy_digest_of(&text_policy()),
        identity_source_digest: identity_digest_of(&identity_artifact()),
        max_prompt_tokens: 8,
        max_new_tokens: 64,
        max_stop_token_ids: 4,
        max_canonical_output_bytes: 4096,
        max_spool_bytes: 65_536,
        max_encoded_result_frame: 262_144,
        max_encoded_quote_response: 1_048_576,
        dispatch_margin_blocks: 20,
        delivery_margin_blocks: 10,
        oracle_grace_blocks: 30,
        fixed_price: 250,
    }
}

fn authorization() -> PaidJobAuthorizationV1 {
    let channel = channel();
    let terms = payment_terms();
    PaidJobAuthorizationV1 {
        channel_id: channel.id(),
        bond_edge: terms.bond_edge,
        bond_terms_hash: terms.bond_terms_hash(),
        payment_edge: channel.payment_edge(),
        payment_terms_hash: channel.payment_terms_hash(),
        execution_policy_digest: execution_policy_digest(&channel, &execution_policy()),
        prepared_input_digest: input_digest(&channel, &bundle()),
        proposal_nonce: 0x0102_0304_0506_0708,
        acceptance_deadline: 1_000,
        request_commitment: Evaluate::commit_request(&evaluate_request()),
        environment_commitment: manifest().content_id(),
        price: 250,
        terminal_deadline: 1_050,
        payment_deadline: 1_100,
    }
}

fn job_result(work_id: Digest) -> PaidJobResultV1 {
    PaidJobResultV1 {
        work_id,
        terminal_transcript_commitment: EventCommitment::from_digest(Digest::from_bytes(
            [0x31; 32],
        )),
        canonical_output_digest: Digest::from_bytes([0x32; 32]),
    }
}

fn earned(cumulative: u64) -> EarnedCertificate {
    EarnedCertificate::new(
        channel().payment_edge(),
        channel().payment_terms_hash(),
        cumulative,
    )
}

// ── Golden encodings ──────────────────────────────────────────────────

/// Every fixed body's exact bytes, decoded field by field.
///
/// The sizes are the second assertion: the plan fixes them, and a body
/// that silently grew a field would still round-trip.
#[test]
fn golden_record_encodings_are_pinned() {
    assert_eq!(PaidChannelPolicyV1::BODY_SIZE, 16);
    assert_eq!(PaidChannelPolicyV1::ENCODED_SIZE, 18);
    assert_eq!(PaidExecutionPolicyV1::BODY_SIZE, 162);
    assert_eq!(PaidExecutionPolicyV1::ENCODED_SIZE, 164);
    assert_eq!(PaidJobAuthorizationV1::BODY_SIZE, 328);
    assert_eq!(PaidJobAuthorizationV1::ENCODED_SIZE, 330);
    assert_eq!(PaidJobResultV1::BODY_SIZE, 96);
    assert_eq!(PaidJobResultV1::ENCODED_SIZE, 98);
    assert_eq!(InvoiceEntryV1::BODY_SIZE, 128);
    assert_eq!(InvoiceEntryV1::ENCODED_SIZE, 130);
    assert_eq!(CertificateAllocationV1::BODY_SIZE, 112);
    assert_eq!(CertificateAllocationV1::ENCODED_SIZE, 114);

    assert_eq!(
        hex(&channel_policy().encode()),
        concat!(
            "01",
            "00",               // format version 1, tag 0 = PAID_CHANNEL_POLICY
            "00000000000002bc", // compute_credit_limit = 700
            "0000000000000320", // delivery_credit_limit = 800
        )
    );

    assert_eq!(
        hex(&job_result(Digest::from_bytes([0x30; 32])).encode()),
        concat!(
            "01",
            "03", // format version 1, tag 3 = PAID_JOB_RESULT
            "3030303030303030303030303030303030303030303030303030303030303030", // work_id
            "3131313131313131313131313131313131313131313131313131313131313131", // transcript
            "3232323232323232323232323232323232323232323232323232323232323232", // output digest
        )
    );

    let entry = InvoiceEntryV1 {
        channel_id: Digest::from_bytes([0xc0; 32]),
        invoice_seq: 1,
        work_id: Digest::from_bytes([0xa1; 32]),
        result_digest: Digest::from_bytes([0xa2; 32]),
        price: 250,
        cumulative_before: 0,
        cumulative_after: 250,
    };
    assert_eq!(
        hex(&entry.encode()),
        concat!(
            "01",
            "04", // format version 1, tag 4 = PRIVATE_INVOICE
            "c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0", // channel_id
            "0000000000000001", // invoice_seq
            "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1", // work_id
            "a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2", // result_digest
            "00000000000000fa", // price = 250
            "0000000000000000", // cumulative_before
            "00000000000000fa", // cumulative_after
        )
    );

    let allocation = CertificateAllocationV1 {
        channel_id: Digest::from_bytes([0xc0; 32]),
        certificate_digest: hellas_kernel::PayloadHash::from_bytes([0xd0; 32]),
        first_invoice_seq: 1,
        last_invoice_seq: 3,
        invoice_entries_root: Digest::from_bytes([0xd1; 32]),
    };
    assert_eq!(
        hex(&allocation.encode()),
        concat!(
            "01",
            "05", // format version 1, tag 5 = CERTIFICATE_ALLOCATION
            "c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0", // channel_id
            "d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0", // certificate
            "0000000000000001", // first_invoice_seq
            "0000000000000003", // last_invoice_seq
            "d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1", // root
        )
    );

    let policy = PaidExecutionPolicyV1 {
        allowed_environment: ContentId::from_bytes([0x40; 32]),
        generation_policy_digest: Digest::from_bytes([0x41; 32]),
        identity_source_digest: Digest::from_bytes([0x42; 32]),
        max_prompt_tokens: 1,
        max_new_tokens: 2,
        max_stop_token_ids: 3,
        max_canonical_output_bytes: 4,
        max_spool_bytes: 5,
        max_encoded_result_frame: 6,
        max_encoded_quote_response: 7,
        dispatch_margin_blocks: 8,
        delivery_margin_blocks: 9,
        oracle_grace_blocks: 10,
        fixed_price: 11,
    };
    assert_eq!(
        hex(&policy.encode()),
        concat!(
            "01",
            "01", // format version 1, tag 1 = PAID_EXECUTION_POLICY
            "4040404040404040404040404040404040404040404040404040404040404040", // environment
            "4141414141414141414141414141414141414141414141414141414141414141", // generation
            "4242424242424242424242424242424242424242424242424242424242424242", // identity
            "00000001", // max_prompt_tokens
            "00000002", // max_new_tokens
            "0003", // max_stop_token_ids
            "0000000000000004", // max_canonical_output_bytes
            "0000000000000005", // max_spool_bytes
            "00000006", // max_encoded_result_frame
            "00000007", // max_encoded_quote_response
            "0000000000000008", // dispatch_margin_blocks
            "0000000000000009", // delivery_margin_blocks
            "000000000000000a", // oracle_grace_blocks
            "000000000000000b", // fixed_price
        )
    );

    let authorization = PaidJobAuthorizationV1 {
        channel_id: Digest::from_bytes([0x50; 32]),
        bond_edge: EdgeId::from_bytes([0x51; 32]),
        bond_terms_hash: TermsHash::from_bytes([0x52; 32]),
        payment_edge: EdgeId::from_bytes([0x53; 32]),
        payment_terms_hash: TermsHash::from_bytes([0x54; 32]),
        execution_policy_digest: Digest::from_bytes([0x55; 32]),
        prepared_input_digest: Digest::from_bytes([0x56; 32]),
        proposal_nonce: 1,
        acceptance_deadline: 2,
        request_commitment: RequestCommitment::from_digest(Digest::from_bytes([0x57; 32])),
        environment_commitment: ContentId::from_bytes([0x58; 32]),
        price: 3,
        terminal_deadline: 4,
        payment_deadline: 5,
    };
    assert_eq!(
        hex(&authorization.encode()),
        concat!(
            "01",
            "02", // format version 1, tag 2 = PAID_JOB_AUTHORIZATION
            "5050505050505050505050505050505050505050505050505050505050505050", // channel_id
            "5151515151515151515151515151515151515151515151515151515151515151", // bond_edge
            "5252525252525252525252525252525252525252525252525252525252525252", // bond_terms
            "5353535353535353535353535353535353535353535353535353535353535353", // payment_edge
            "5454545454545454545454545454545454545454545454545454545454545454", // payment_terms
            "5555555555555555555555555555555555555555555555555555555555555555", // policy digest
            "5656565656565656565656565656565656565656565656565656565656565656", // prepared input
            "0000000000000001", // proposal_nonce
            "0000000000000002", // acceptance_deadline
            "5757575757575757575757575757575757575757575757575757575757575757", // request
            "5858585858585858585858585858585858585858585858585858585858585858", // environment
            "0000000000000003", // price
            "0000000000000004", // terminal_deadline
            "0000000000000005", // payment_deadline
        )
    );
}

/// Maximum-value bodies still encode to their fixed width.
#[test]
fn maximum_value_bodies_stay_fixed_width() {
    let entry = InvoiceEntryV1 {
        channel_id: Digest::from_bytes([0xff; 32]),
        invoice_seq: u64::MAX,
        work_id: Digest::from_bytes([0xff; 32]),
        result_digest: Digest::from_bytes([0xff; 32]),
        price: u64::MAX,
        cumulative_before: u64::MAX,
        cumulative_after: u64::MAX,
    };
    let bytes = entry.encode();
    assert_eq!(bytes.len(), InvoiceEntryV1::ENCODED_SIZE);
    assert_eq!(InvoiceEntryV1::decode(&bytes), Ok(entry));
    assert_eq!(hex(&bytes[2..10]), "ffffffffffffffff");
}

/// Wrong tag, wrong version, truncation, and a trailing byte all reject.
#[test]
fn envelope_and_length_mutations_reject() {
    let bytes = job_result(Digest::from_bytes([0x30; 32])).encode();
    assert!(PaidJobResultV1::decode(&bytes).is_ok());

    // MUTATION: a result body presented under the invoice tag.
    let mut wrong_tag = bytes.clone();
    wrong_tag[1] = 4;
    assert_eq!(
        PaidJobResultV1::decode(&wrong_tag),
        Err(PaidWorkError::WrongRecordTag {
            expected: 3,
            actual: 4
        })
    );

    // MUTATION: an unassigned tag.
    let mut unknown_tag = bytes.clone();
    unknown_tag[1] = 6;
    assert_eq!(
        PaidJobResultV1::decode(&unknown_tag),
        Err(PaidWorkError::WrongRecordTag {
            expected: 3,
            actual: 6
        })
    );

    // MUTATION: a future format version.
    let mut wrong_version = bytes.clone();
    wrong_version[0] = 2;
    assert_eq!(
        PaidJobResultV1::decode(&wrong_version),
        Err(PaidWorkError::UnknownFormatVersion { actual: 2 })
    );

    // MUTATION: one byte short.
    let truncated = &bytes[..bytes.len() - 1];
    assert_eq!(
        PaidJobResultV1::decode(truncated),
        Err(PaidWorkError::RecordLength {
            expected: 98,
            actual: 97
        })
    );

    // MUTATION: one byte long.
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert_eq!(
        PaidJobResultV1::decode(&trailing),
        Err(PaidWorkError::RecordLength {
            expected: 98,
            actual: 99
        })
    );
}

/// A paid-work body must not decode as another paid-work record.
///
/// No two of the six records share a length — asserted here, because it
/// is what this test rests on — so a body relabelled as another record
/// never reaches the tag rule: the length refuses it first, whether or
/// not the tag byte was changed with it. The tag rule is exercised where
/// a record's own length is intact, in
/// `envelope_and_length_mutations_reject`.
#[test]
fn a_body_cannot_be_reinterpreted_under_another_record() {
    let sizes = [
        PaidChannelPolicyV1::ENCODED_SIZE,
        PaidExecutionPolicyV1::ENCODED_SIZE,
        PaidJobAuthorizationV1::ENCODED_SIZE,
        PaidJobResultV1::ENCODED_SIZE,
        InvoiceEntryV1::ENCODED_SIZE,
        CertificateAllocationV1::ENCODED_SIZE,
    ];
    for (index, size) in sizes.iter().enumerate() {
        for other in sizes.iter().skip(index + 1) {
            assert_ne!(size, other, "two records share a length");
        }
    }

    let policy = execution_policy().encode();
    assert_eq!(
        PaidJobAuthorizationV1::decode(&policy),
        Err(PaidWorkError::RecordLength {
            expected: 330,
            actual: 164
        })
    );

    // The tag relabelled too, which changes nothing: the length is read
    // before the envelope is.
    let mut disguised = policy.clone();
    disguised[1] = 2;
    assert_eq!(
        PaidJobAuthorizationV1::decode(&disguised),
        Err(PaidWorkError::RecordLength {
            expected: 330,
            actual: 164
        })
    );
}

// ── Golden digests ────────────────────────────────────────────────────

/// Pinned digests over two legal network ids of different lengths.
///
/// The encoded network carries a one-byte length prefix, so a raw or
/// padded spelling of the same id is a different preimage. Both vectors
/// are pinned; if the prefix were dropped, both would move.
#[test]
fn golden_digests_bind_the_encoded_network() {
    let channel = channel();
    assert_eq!(
        hex(channel.id().as_bytes()),
        "3fb8c6063009d6fa39e41884fcbc325ce0886f34e5ca0ff9f7893fcb9f29cb66"
    );
    assert_eq!(
        hex(&work_id(&channel, &authorization()).into_bytes()),
        "c11e6d67bc0781f0f18e1c50e5de3e38eb02d191aad4e10c28c262ed33132f3b"
    );

    let other = channel_on(
        NetworkId::new(OTHER_NETWORK).expect("legal network id"),
        EdgeId::from_bytes([0xe1; 32]),
    );
    assert_ne!(channel.id(), other.id());
    // Rebuilt by hand rather than by the module that is being pinned:
    // the domain, the one-byte length prefix, and the four commitments,
    // hashed through the crate's other entry point.
    let mut preimage = b"hellas.work.channel.v2".to_vec();
    preimage.push(OTHER_NETWORK.len() as u8);
    preimage.extend_from_slice(OTHER_NETWORK.as_bytes());
    preimage.extend_from_slice(other.payment_edge().as_bytes());
    preimage.extend_from_slice(other.payment_terms_hash().as_bytes());
    preimage.extend_from_slice(other.payment_terms().bond_edge.as_bytes());
    preimage.extend_from_slice(other.payment_terms().bond_terms_hash().as_bytes());
    assert_eq!(Digest::hash(&preimage), other.id());
    assert_eq!(
        hex(other.id().as_bytes()),
        "2242df9d621b8156cec0a1903919d46739dd79665df31e04e5bb5499174e5191"
    );
}

/// The same body in another channel is another digest, and every check
/// that names the channel refuses it.
#[test]
fn records_do_not_cross_channels() {
    let here = channel();
    let sibling = channel_on(network(), EdgeId::from_bytes([0xe2; 32]));
    let elsewhere = channel_on(
        NetworkId::new(OTHER_NETWORK).expect("legal network id"),
        here.payment_edge(),
    );
    let authorization = authorization();
    let result = job_result(work_id(&here, &authorization));
    let entry = InvoiceEntryV1 {
        channel_id: here.id(),
        invoice_seq: 1,
        work_id: result.work_id,
        result_digest: result_digest(&here, &result),
        price: 250,
        cumulative_before: 0,
        cumulative_after: 250,
    };
    let allocation = allocation_over(&[entry], &earned(250));

    assert_ne!(here.id(), sibling.id());
    for (label, other) in [("sibling", &sibling), ("elsewhere", &elsewhere)] {
        assert_ne!(
            work_id(&here, &authorization),
            work_id(other, &authorization),
            "{label} shares this channel's work_id"
        );
        assert_ne!(
            result_digest(&here, &result),
            result_digest(other, &result),
            "{label} shares this channel's result digest"
        );
        assert_ne!(
            invoice_digest(&here, &entry),
            invoice_digest(other, &entry),
            "{label} shares this channel's invoice digest"
        );
        assert_ne!(
            allocation_digest(&here, &allocation),
            allocation_digest(other, &allocation),
            "{label} shares this channel's allocation digest"
        );
        assert_ne!(
            execution_policy_digest(&here, &execution_policy()),
            execution_policy_digest(other, &execution_policy()),
            "{label} shares this channel's policy digest"
        );
        assert_ne!(
            input_digest(&here, &bundle()),
            input_digest(other, &bundle()),
            "{label} shares this channel's prepared input digest"
        );
        // MUTATION: replay this channel's authorization on another one.
        assert_eq!(
            check_authorization(other, &authorization, &execution_policy(), 900),
            Err(PaidWorkError::Mismatch {
                field: "channel_id"
            }),
            "{label} accepted a foreign authorization"
        );
    }
}

// ── Prepared input bundle ─────────────────────────────────────────────

/// The bundle encodes as six big-endian lengths and six bodies, and its
/// digest is reproducible from the same six component bodies with no
/// cache in the process.
#[test]
fn prepared_input_is_reproducible_from_its_components() {
    let bundle = bundle();
    let encoded = bundle.encode().expect("a representable bundle");

    let expected = assemble(&[
        &evaluate_request_bytes_of(),
        &manifest().canonical_bytes(),
        &text_execution().canonical_bytes(),
        &prompt_tokens().canonical_bytes(),
        &text_policy().canonical_bytes(),
        &identity_artifact().canonical_bytes(),
    ]);
    assert_eq!(encoded, expected);

    let decoded = PreparedPaidInputV1::decode(&encoded, 1_048_576).expect("legal bundle");
    assert_eq!(decoded, bundle);
    assert_eq!(
        input_digest(&channel(), &decoded),
        input_digest(&channel(), &bundle)
    );
}

/// Reordering, relabelling, or padding the bundle rejects rather than
/// producing a second acceptable spelling of the same job.
#[test]
fn prepared_input_mutations_reject() {
    let encoded = bundle().encode().expect("a representable bundle");
    let budget = 1_048_576;
    assert!(PreparedPaidInputV1::decode(&encoded, budget).is_ok());

    // MUTATION: swap the prompt-token and policy segments. They decode
    // as each other's schema, so the bundle has no second spelling.
    let swapped = assemble(&[
        &evaluate_request_bytes_of(),
        &manifest().canonical_bytes(),
        &text_execution().canonical_bytes(),
        &text_policy().canonical_bytes(),
        &prompt_tokens().canonical_bytes(),
        &identity_artifact().canonical_bytes(),
    ]);
    assert_ne!(swapped, encoded);
    let err = PreparedPaidInputV1::decode(&swapped, budget)
        .expect("lengths are still well formed")
        .parts()
        .expect_err("swapped components must not parse");
    assert!(
        err.to_string().contains("expected array length 2, got 3"),
        "{err}"
    );

    // MUTATION: the first declared length one byte short. Every later
    // segment then starts one byte early, so the next length is read out
    // of a body and refused before anything is allocated for it.
    let mut short_length = encoded.clone();
    let first_len = u32::from_be_bytes([
        short_length[0],
        short_length[1],
        short_length[2],
        short_length[3],
    ]);
    short_length[..4].copy_from_slice(&(first_len - 1).to_be_bytes());
    let err = PreparedPaidInputV1::decode(&short_length, budget)
        .expect_err("a shortened length must not decode");
    assert!(err.to_string().contains("budget"), "{err}");

    // MUTATION: the last declared length one byte short, which leaves a
    // well-formed prefix and one byte over.
    let mut short_last = encoded.clone();
    let last_prefix = encoded.len() - identity_artifact().canonical_bytes().len() - 4;
    let last_len = u32::from_be_bytes([
        short_last[last_prefix],
        short_last[last_prefix + 1],
        short_last[last_prefix + 2],
        short_last[last_prefix + 3],
    ]);
    short_last[last_prefix..last_prefix + 4].copy_from_slice(&(last_len - 1).to_be_bytes());
    let err = PreparedPaidInputV1::decode(&short_last, budget)
        .expect_err("a shortened final length must not decode");
    assert!(
        err.to_string()
            .contains("trailing bytes after prepared input"),
        "{err}"
    );

    // MUTATION: one appended byte.
    let mut trailing = encoded.clone();
    trailing.push(0);
    let err = PreparedPaidInputV1::decode(&trailing, budget)
        .expect_err("a trailing byte must not decode");
    assert!(
        err.to_string()
            .contains("trailing bytes after prepared input"),
        "{err}"
    );

    // MUTATION: a noncanonical nested body — the last token id re-spelled
    // with a wider integer header.
    let mut widened = prompt_tokens().canonical_bytes();
    let position = widened
        .iter()
        .rposition(|byte| *byte == 6)
        .expect("last token id");
    widened.splice(position..=position, [0x18, 6]);
    let noncanonical = assemble(&[
        &evaluate_request_bytes_of(),
        &manifest().canonical_bytes(),
        &text_execution().canonical_bytes(),
        &widened,
        &text_policy().canonical_bytes(),
        &identity_artifact().canonical_bytes(),
    ]);
    let err = PreparedPaidInputV1::decode(&noncanonical, budget)
        .expect("lengths are still well formed")
        .parts()
        .expect_err("a noncanonical token body must not parse");
    assert!(err.to_string().contains("non-canonical"), "{err}");
}

/// A declared length is never trusted: not against the input, not
/// against the budget, and not in aggregate.
#[test]
fn prepared_input_lengths_are_bounded_before_allocation() {
    let encoded = bundle().encode().expect("a representable bundle");

    // MUTATION: u32::MAX in the first length.
    let mut huge = encoded.clone();
    huge[..4].copy_from_slice(&u32::MAX.to_be_bytes());
    let err = PreparedPaidInputV1::decode(&huge, 1_048_576)
        .expect_err("a u32::MAX length must not decode");
    assert!(err.to_string().contains("budget"), "{err}");

    // MUTATION: six lengths that are individually legal and jointly
    // beyond the budget.
    let budget = encoded.len() - 1;
    let err = PreparedPaidInputV1::decode(&encoded, budget)
        .expect_err("a bundle over its budget must not decode");
    assert!(err.to_string().contains("budget"), "{err}");

    // The exact budget is legal; one byte less is not.
    assert!(PreparedPaidInputV1::decode(&encoded, encoded.len()).is_ok());
}

// ── Streaming hash equivalence ────────────────────────────────────────

/// Every `XFH` preimage hashes the same however it is written, and the
/// single-chunk hasher genuinely cannot take its place.
#[test]
fn streaming_hash_matches_one_shot_under_every_segmentation() {
    let mut preimage = b"hellas.work.prepared-input.v1".to_vec();
    preimage.extend_from_slice(&[0xab; 20_000]);
    let expected = Digest::hash(&preimage);

    for split in [1, 8_191, 8_192, 8_193, 65_536, preimage.len()] {
        let split = split.min(preimage.len());
        let mut hasher = hellas_xet::XetFileHasher::new();
        hasher.update(&preimage[..split]);
        hasher.update(&preimage[split..]);
        assert_eq!(hasher.finalize(), expected, "split at {split}");
    }

    // MUTATION: hash the same preimage with the single-chunk hasher. It
    // asserts rather than truncating, which is exactly why the variable
    // preimages do not use it.
    let panicked = std::panic::catch_unwind(|| {
        let mut hasher = hellas_xet::SingleChunkHasher::new();
        hasher.update(&preimage);
        hasher.finalize()
    });
    assert!(panicked.is_err());
}

/// A legal bundle can be far larger than the single-chunk limit, and its
/// digest is computed anyway.
///
/// This is the test that makes the choice of hasher load-bearing: a
/// prompt of a few thousand tokens puts the prepared-input preimage past
/// [`hellas_xet::MIN_CHUNK_SIZE`], where the single-chunk hasher asserts.
#[test]
fn a_bundle_over_the_single_chunk_limit_still_hashes() {
    let long_prompt = TokenIds::from_u32s(0..4_000);
    let execution = TextExecution::new(
        SourceRef::output(identity_artifact().output_id()),
        long_prompt.output_id(),
        text_policy().output_id(),
    );
    let request = EvaluateRequest {
        text_execution: execution.input_id().digest(),
        ..evaluate_request()
    };
    let large = PreparedPaidInputV1::new(
        &request,
        &manifest(),
        &execution,
        &long_prompt,
        &text_policy(),
        &identity_artifact(),
    );
    assert!(
        large.encode().expect("a representable bundle").len() > hellas_xet::MIN_CHUNK_SIZE,
        "the fixture must exceed the single-chunk limit to be a test of it",
    );
    let digest = input_digest(&channel(), &large);
    assert_ne!(digest, input_digest(&channel(), &bundle()));

    // The same bundle over a channel-sized budget still decodes, and its
    // digest survives the round trip.
    let encoded = large.encode().expect("a representable bundle");
    let decoded = PreparedPaidInputV1::decode(&encoded, 1_048_576).expect("legal bundle");
    assert_eq!(input_digest(&channel(), &decoded), digest);
}

/// Every fixed-record preimage is measured, not assumed, to be under the
/// single-chunk limit.
///
/// The widest is `longest domain || network || channel || widest record`.
/// Both maxima are taken over the whole set rather than named, so the
/// record and the domain that happen to be widest today are asserted to
/// be the widest rather than assumed to stay so.
#[test]
fn widest_fixed_preimage_is_measured() {
    let longest_network =
        NetworkId::new(&"n".repeat(hellas_kernel::MAX_NETWORK_ID_LENGTH)).expect("legal id");
    let encoded_network = 1 + hellas_kernel::MAX_NETWORK_ID_LENGTH;
    for size in [
        PaidChannelPolicyV1::ENCODED_SIZE,
        PaidExecutionPolicyV1::ENCODED_SIZE,
        PaidJobResultV1::ENCODED_SIZE,
        InvoiceEntryV1::ENCODED_SIZE,
        CertificateAllocationV1::ENCODED_SIZE,
    ] {
        assert!(
            size <= PaidJobAuthorizationV1::ENCODED_SIZE,
            "{size} is wider than the record the bound is taken over"
        );
    }
    for domain in [
        "hellas.work.channel.v2",
        "hellas.work.paid-channel-policy.v1",
        "hellas.work.generation-policy.v1",
        "hellas.work.identity-source.v1",
        "hellas.work.execution-policy.v1",
        "hellas.work.prepared-input.v1",
        "hellas.work.paid-job-authorize.v1",
        "hellas.work.paid-job-result.v1",
        "hellas.work.private-invoice.v1",
        "hellas.work.private-invoice-empty.v1",
        "hellas.work.private-invoice-leaf.v1",
        "hellas.work.private-invoice-node.v1",
        "hellas.work.evaluate-output.v1",
    ] {
        assert!(
            domain.len() <= "hellas.work.private-certificate-allocation.v1".len(),
            "{domain} is longer than the domain the bound is taken over"
        );
    }
    let widest = "hellas.work.private-certificate-allocation.v1".len()
        + encoded_network
        + 32
        + PaidJobAuthorizationV1::ENCODED_SIZE;
    assert_eq!(widest, 45 + 64 + 32 + 330);
    assert_eq!(widest, 471);
    assert!(widest < hellas_xet::MIN_CHUNK_SIZE);

    // The four shapes that are not record-shaped are bounded too: the
    // channel id, which has no channel field, and the invoice tree's
    // three nodes, which carry neither network nor channel.
    assert_eq!(
        "hellas.work.channel.v2".len() + encoded_network + 4 * 32,
        214
    );
    assert_eq!("hellas.work.private-invoice-leaf.v1".len() + 8 + 32, 75);
    assert_eq!(
        "hellas.work.private-invoice-node.v1".len() + 8 + 2 + 2 + 64,
        111
    );
    assert_eq!("hellas.work.private-invoice-empty.v1".len() + 1, 37);

    // The widest preimage is also a preimage that must hash rather than
    // panic, so it is actually hashed here.
    let channel = channel_on(longest_network, EdgeId::from_bytes([0xe1; 32]));
    let _ = work_id(&channel, &authorization());
}

// ── Authorization ─────────────────────────────────────────────────────

/// The happy path: both parties check the same authorization against
/// their own terms and sign the same digest.
#[test]
fn both_parties_sign_one_authorization_digest() {
    let channel = channel();
    let authorization = authorization();
    let work_id = check_authorization(&channel, &authorization, &execution_policy(), 900)
        .expect("a legal authorization");
    check_prepared_input(&channel, &authorization, &execution_policy(), &bundle())
        .expect("a legal bundle");

    let payload = hellas_kernel::PayloadHash::from_bytes(work_id.into_bytes());
    let client_sig = client().sign(payload);
    let provider_sig = provider().sign(payload);
    let verifier = Secp256k1Verifier;
    assert!(verifier.verify_sig(client_sig, channel.client_key(), payload));
    assert!(verifier.verify_sig(provider_sig, channel.provider_key(), payload));

    // MUTATION: the client changes the price after the provider signs.
    let mut repriced = authorization;
    repriced.price = 249;
    let moved = work_id_payload(&channel, &repriced);
    assert!(!verifier.verify_sig(provider_sig, channel.provider_key(), moved));
}

fn work_id_payload(
    channel: &PaidChannel,
    authorization: &PaidJobAuthorizationV1,
) -> hellas_kernel::PayloadHash {
    hellas_kernel::PayloadHash::from_bytes(work_id(channel, authorization).into_bytes())
}

/// Every authorization field moves the signed digest.
///
/// A field that did not would be a field either party could change after
/// the other signed.
#[test]
fn every_authorization_field_moves_the_work_id() {
    let channel = channel();
    let base = authorization();
    let signed = work_id(&channel, &base);

    let mutations: Vec<(&str, PaidJobAuthorizationV1)> = vec![
        ("channel_id", {
            let mut m = base;
            m.channel_id = Digest::from_bytes([0; 32]);
            m
        }),
        ("bond_edge", {
            let mut m = base;
            m.bond_edge = EdgeId::from_bytes([0; 32]);
            m
        }),
        ("bond_terms_hash", {
            let mut m = base;
            m.bond_terms_hash = TermsHash::from_bytes([0; 32]);
            m
        }),
        ("payment_edge", {
            let mut m = base;
            m.payment_edge = EdgeId::from_bytes([0; 32]);
            m
        }),
        ("payment_terms_hash", {
            let mut m = base;
            m.payment_terms_hash = TermsHash::from_bytes([0; 32]);
            m
        }),
        ("execution_policy_digest", {
            let mut m = base;
            m.execution_policy_digest = Digest::from_bytes([0; 32]);
            m
        }),
        ("prepared_input_digest", {
            let mut m = base;
            m.prepared_input_digest = Digest::from_bytes([0; 32]);
            m
        }),
        ("proposal_nonce", {
            let mut m = base;
            m.proposal_nonce ^= 1;
            m
        }),
        ("acceptance_deadline", {
            let mut m = base;
            m.acceptance_deadline += 1;
            m
        }),
        ("request_commitment", {
            let mut m = base;
            m.request_commitment = RequestCommitment::from_digest(Digest::from_bytes([0; 32]));
            m
        }),
        ("environment_commitment", {
            let mut m = base;
            m.environment_commitment = ContentId::from_bytes([0; 32]);
            m
        }),
        ("price", {
            let mut m = base;
            m.price += 1;
            m
        }),
        ("terminal_deadline", {
            let mut m = base;
            m.terminal_deadline += 1;
            m
        }),
        ("payment_deadline", {
            let mut m = base;
            m.payment_deadline += 1;
            m
        }),
    ];
    assert_eq!(mutations.len(), 14, "every field must be mutated");
    for (field, mutated) in mutations {
        assert_ne!(
            work_id(&channel, &mutated),
            signed,
            "{field} left the digest alone"
        );
    }
}

/// The authorization's own rules: price bounds, deadline ordering, and
/// the acceptance window.
#[test]
fn authorization_rules_reject_their_violations() {
    let channel = channel();
    let policy = execution_policy();
    let base = authorization();
    assert!(check_authorization(&channel, &base, &policy, 900).is_ok());

    // MUTATION: a free job.
    let mut zero_price = base;
    zero_price.price = 0;
    let mut zero_policy = policy;
    zero_policy.fixed_price = 0;
    zero_price.execution_policy_digest = execution_policy_digest(&channel, &zero_policy);
    assert_eq!(
        check_authorization(&channel, &zero_price, &zero_policy, 900),
        Err(PaidWorkError::PolicyZero {
            field: "fixed_price"
        })
    );

    // MUTATION: a price the bond does not cover.
    let mut over_bond = base;
    over_bond.price = 501;
    let mut over_policy = policy;
    over_policy.fixed_price = 501;
    over_bond.execution_policy_digest = execution_policy_digest(&channel, &over_policy);
    assert_eq!(
        check_authorization(&channel, &over_bond, &over_policy, 900),
        Err(PaidWorkError::PriceOutOfRange {
            price: 501,
            max_job_price: 500
        })
    );

    // MUTATION: a price that disagrees with the signed policy.
    let mut mispriced = base;
    mispriced.price = 249;
    assert_eq!(
        check_authorization(&channel, &mispriced, &policy, 900),
        Err(PaidWorkError::Mismatch { field: "price" })
    );

    // MUTATION: signing after the acceptance window closed.
    assert_eq!(
        check_authorization(&channel, &base, &policy, 1_001),
        Err(PaidWorkError::AcceptanceExpired {
            height: 1_001,
            deadline: 1_000
        })
    );

    // MUTATION: a payment deadline past the channel's admission horizon.
    let mut late = base;
    late.payment_deadline = 5_000;
    assert_eq!(
        check_authorization(&channel, &late, &policy, 900),
        Err(PaidWorkError::DeadlineOrder {
            acceptance: 1_000,
            terminal: 1_050,
            payment: 5_000,
            horizon: 5_000
        })
    );

    // MUTATION: terminal and payment deadlines out of order.
    let mut inverted = base;
    inverted.terminal_deadline = 1_100;
    inverted.payment_deadline = 1_050;
    assert!(matches!(
        check_authorization(&channel, &inverted, &policy, 900),
        Err(PaidWorkError::DeadlineOrder { .. })
    ));
}

/// Every execution-policy field is inside the digest the authorization
/// pins, so a locally re-decoded policy that differs anywhere fails the
/// comparison.
#[test]
fn every_execution_policy_field_moves_its_digest() {
    let channel = channel();
    let base = execution_policy();
    let pinned = execution_policy_digest(&channel, &base);
    let authorization = authorization();

    let mutations: Vec<(&str, PaidExecutionPolicyV1)> = vec![
        ("allowed_environment", {
            let mut m = base;
            m.allowed_environment = ContentId::from_bytes([0; 32]);
            m
        }),
        ("generation_policy_digest", {
            let mut m = base;
            m.generation_policy_digest = Digest::from_bytes([0; 32]);
            m
        }),
        ("identity_source_digest", {
            let mut m = base;
            m.identity_source_digest = Digest::from_bytes([0; 32]);
            m
        }),
        ("max_prompt_tokens", {
            let mut m = base;
            m.max_prompt_tokens += 1;
            m
        }),
        ("max_new_tokens", {
            let mut m = base;
            m.max_new_tokens += 1;
            m
        }),
        ("max_stop_token_ids", {
            let mut m = base;
            m.max_stop_token_ids += 1;
            m
        }),
        ("max_canonical_output_bytes", {
            let mut m = base;
            m.max_canonical_output_bytes += 1;
            m
        }),
        ("max_spool_bytes", {
            let mut m = base;
            m.max_spool_bytes += 1;
            m
        }),
        ("max_encoded_result_frame", {
            let mut m = base;
            m.max_encoded_result_frame += 1;
            m
        }),
        ("max_encoded_quote_response", {
            let mut m = base;
            m.max_encoded_quote_response += 1;
            m
        }),
        ("dispatch_margin_blocks", {
            let mut m = base;
            m.dispatch_margin_blocks += 1;
            m
        }),
        ("delivery_margin_blocks", {
            let mut m = base;
            m.delivery_margin_blocks += 1;
            m
        }),
        ("oracle_grace_blocks", {
            let mut m = base;
            m.oracle_grace_blocks += 1;
            m
        }),
        ("fixed_price", {
            let mut m = base;
            m.fixed_price += 1;
            m
        }),
    ];
    assert_eq!(mutations.len(), 14, "every field must be mutated");
    for (field, mutated) in mutations {
        assert_ne!(
            execution_policy_digest(&channel, &mutated),
            pinned,
            "{field} left the policy digest alone"
        );
        // A recomputed digest does not help: the authorization pins the
        // one both parties agreed to.
        assert_eq!(
            check_authorization(&channel, &authorization, &mutated, 900).err(),
            Some(PaidWorkError::Mismatch {
                field: "execution_policy_digest"
            }),
            "{field} was accepted under a recomputed digest"
        );
    }
}

/// The channel opens its own credit commitment, so a policy the terms do
/// not commit to is a channel that cannot be built.
#[test]
fn a_channel_cannot_be_built_on_an_uncommitted_credit_policy() {
    let terms = payment_terms();
    let edge = EdgeId::from_bytes([0xe1; 32]);
    let build = |network: NetworkId, salt: &[u8; 32], policy: PaidChannelPolicyV1| {
        PaidChannel::new(network, edge, terms.clone(), salt, policy)
    };
    assert!(build(network(), &SALT, channel_policy()).is_ok());

    // MUTATION: a different compute credit limit under the same salt.
    let mut compute = channel_policy();
    compute.compute_credit_limit += 1;
    assert_eq!(
        build(network(), &SALT, compute).err(),
        Some(PaidWorkError::Mismatch {
            field: "private_policy_commitment"
        })
    );

    // MUTATION: a different delivery credit limit.
    let mut delivery = channel_policy();
    delivery.delivery_credit_limit += 1;
    assert!(build(network(), &SALT, delivery).is_err());

    // MUTATION: the same body under a different salt.
    assert!(build(network(), &[0x5b; 32], channel_policy()).is_err());

    // MUTATION: the same body and salt on a different network.
    let other = NetworkId::new(OTHER_NETWORK).expect("legal id");
    assert!(build(other, &SALT, channel_policy()).is_err());

    // The policy the channel opened is the policy it carries.
    let channel = channel();
    assert_eq!(*channel.channel_policy(), channel_policy());
}

/// A job priced above what the channel's credit limits cover is refused
/// at authorization, under the policy that actually prices the job.
///
/// The limits are per-channel and the price is per-authorization, so a
/// comparison made once at setup compares against whichever execution
/// policy happened to be in hand. This one compares against this job's.
#[test]
fn a_price_above_the_channel_credit_limits_is_refused() {
    let policy = execution_policy();
    let base = authorization();
    assert!(check_authorization(&channel(), &base, &policy, 900).is_ok());

    // A second execution policy on the same channel, priced above the
    // compute credit limit and still inside `max_job_price`. The channel
    // committed to neither price: it committed to two limits.
    let thin = PaidChannelPolicyV1 {
        compute_credit_limit: 300,
        delivery_credit_limit: 800,
    };
    let terms = WorkPaymentTerms {
        private_policy_commitment: private_policy_commitment(network(), &SALT, &thin),
        ..payment_terms()
    };
    let channel = PaidChannel::new(
        network(),
        EdgeId::from_bytes([0xe1; 32]),
        terms,
        &SALT,
        thin,
    )
    .expect("terms that commit to this credit policy");

    let mut dear = execution_policy();
    dear.fixed_price = 500;
    let mut authorization = authorization();
    authorization.channel_id = channel.id();
    authorization.payment_terms_hash = channel.payment_terms_hash();
    authorization.price = 500;
    authorization.execution_policy_digest = execution_policy_digest(&channel, &dear);
    authorization.prepared_input_digest = input_digest(&channel, &bundle());

    assert_eq!(
        check_authorization(&channel, &authorization, &dear, 900),
        Err(PaidWorkError::OverEnvelope {
            field: "price against compute_credit_limit",
            actual: 500,
            limit: 300
        })
    );

    // MUTATION: raise the compute limit alone. The delivery limit is a
    // separate rule and refuses on its own.
    let both = PaidChannelPolicyV1 {
        compute_credit_limit: 500,
        delivery_credit_limit: 499,
    };
    let terms = WorkPaymentTerms {
        private_policy_commitment: private_policy_commitment(network(), &SALT, &both),
        ..payment_terms()
    };
    let channel = PaidChannel::new(
        network(),
        EdgeId::from_bytes([0xe1; 32]),
        terms,
        &SALT,
        both,
    )
    .expect("terms that commit to this credit policy");
    authorization.payment_terms_hash = channel.payment_terms_hash();
    authorization.channel_id = channel.id();
    authorization.execution_policy_digest = execution_policy_digest(&channel, &dear);
    assert_eq!(
        check_authorization(&channel, &authorization, &dear, 900),
        Err(PaidWorkError::OverEnvelope {
            field: "price against delivery_credit_limit",
            actual: 500,
            limit: 499
        })
    );
}

/// Every bound the profile requires to be positive is refused at zero,
/// one field at a time.
#[test]
fn an_absent_execution_policy_bound_is_refused() {
    let base = execution_policy();
    assert!(check_execution_policy(&base).is_ok());

    let zeroed: Vec<(&str, PaidExecutionPolicyV1)> = vec![
        (
            "fixed_price",
            PaidExecutionPolicyV1 {
                fixed_price: 0,
                ..base
            },
        ),
        (
            "max_prompt_tokens",
            PaidExecutionPolicyV1 {
                max_prompt_tokens: 0,
                ..base
            },
        ),
        (
            "max_new_tokens",
            PaidExecutionPolicyV1 {
                max_new_tokens: 0,
                ..base
            },
        ),
        (
            "max_canonical_output_bytes",
            PaidExecutionPolicyV1 {
                max_canonical_output_bytes: 0,
                ..base
            },
        ),
        (
            "max_spool_bytes",
            PaidExecutionPolicyV1 {
                max_spool_bytes: 0,
                ..base
            },
        ),
        (
            "max_encoded_result_frame",
            PaidExecutionPolicyV1 {
                max_encoded_result_frame: 0,
                ..base
            },
        ),
        (
            "max_encoded_quote_response",
            PaidExecutionPolicyV1 {
                max_encoded_quote_response: 0,
                ..base
            },
        ),
        (
            "dispatch_margin_blocks",
            PaidExecutionPolicyV1 {
                dispatch_margin_blocks: 0,
                ..base
            },
        ),
        (
            "delivery_margin_blocks",
            PaidExecutionPolicyV1 {
                delivery_margin_blocks: 0,
                ..base
            },
        ),
        (
            "oracle_grace_blocks",
            PaidExecutionPolicyV1 {
                oracle_grace_blocks: 0,
                ..base
            },
        ),
    ];
    assert_eq!(zeroed.len(), 10, "every required bound must be zeroed");
    for (field, policy) in zeroed {
        assert_eq!(
            check_execution_policy(&policy),
            Err(PaidWorkError::PolicyZero { field }),
            "{field} was accepted at zero"
        );
    }

    // `max_stop_token_ids` is the one bound that may be zero: a channel
    // that admits no stop tokens is a usable channel.
    assert!(
        check_execution_policy(&PaidExecutionPolicyV1 {
            max_stop_token_ids: 0,
            ..base
        })
        .is_ok()
    );
}

// ── Prepared input graph ──────────────────────────────────────────────

/// The bundle's nested commitments must equal the authorization and the
/// policy; a digest match is not a graph check.
#[test]
fn prepared_input_graph_is_checked_not_assumed() {
    let channel = channel();
    let policy = execution_policy();
    let authorization = authorization();
    assert!(check_prepared_input(&channel, &authorization, &policy, &bundle()).is_ok());

    // MUTATION: a bundle for a different prompt, with its digest
    // recomputed so only the graph check can catch it.
    let other_prompt = TokenIds::from([1, 2, 3]);
    let other_execution = TextExecution::new(
        SourceRef::output(identity_artifact().output_id()),
        other_prompt.output_id(),
        text_policy().output_id(),
    );
    let other_bundle = PreparedPaidInputV1::new(
        &evaluate_request(),
        &manifest(),
        &other_execution,
        &other_prompt,
        &text_policy(),
        &identity_artifact(),
    );
    let mut repointed = authorization;
    repointed.prepared_input_digest = input_digest(&channel, &other_bundle);
    assert_eq!(
        check_prepared_input(&channel, &repointed, &policy, &other_bundle),
        Err(PaidWorkError::Mismatch {
            field: "text_execution id"
        })
    );

    // MUTATION: an over-long prompt.
    let long_prompt = TokenIds::from([1, 2, 3, 4, 5, 6, 7, 8, 9]);
    let long_execution = TextExecution::new(
        SourceRef::output(identity_artifact().output_id()),
        long_prompt.output_id(),
        text_policy().output_id(),
    );
    let long_request = EvaluateRequest {
        text_execution: long_execution.input_id().digest(),
        ..evaluate_request()
    };
    let long_bundle = PreparedPaidInputV1::new(
        &long_request,
        &manifest(),
        &long_execution,
        &long_prompt,
        &text_policy(),
        &identity_artifact(),
    );
    let mut long_auth = authorization;
    long_auth.prepared_input_digest = input_digest(&channel, &long_bundle);
    long_auth.request_commitment = Evaluate::commit_request(&long_request);
    assert_eq!(
        check_prepared_input(&channel, &long_auth, &policy, &long_bundle),
        Err(PaidWorkError::OverEnvelope {
            field: "prompt tokens",
            actual: 9,
            limit: 8
        })
    );

    // MUTATION: resume from a previous output instead of the identity
    // artifact this profile pins.
    let resumed_execution = TextExecution::new(
        SourceRef::input(text_execution().input_id()),
        prompt_tokens().output_id(),
        text_policy().output_id(),
    );
    let resumed_request = EvaluateRequest {
        text_execution: resumed_execution.input_id().digest(),
        ..evaluate_request()
    };
    let resumed_bundle = PreparedPaidInputV1::new(
        &resumed_request,
        &manifest(),
        &resumed_execution,
        &prompt_tokens(),
        &text_policy(),
        &identity_artifact(),
    );
    let mut resumed_auth = authorization;
    resumed_auth.prepared_input_digest = input_digest(&channel, &resumed_bundle);
    resumed_auth.request_commitment = Evaluate::commit_request(&resumed_request);
    assert_eq!(
        check_prepared_input(&channel, &resumed_auth, &policy, &resumed_bundle),
        Err(PaidWorkError::Mismatch {
            field: "text_execution source"
        })
    );

    // MUTATION: another assurance mode under an otherwise legal bundle.
    let attested = EvaluateRequest {
        assurance: Assurance::AppleAppAttest,
        ..evaluate_request()
    };
    let attested_bundle = PreparedPaidInputV1::new(
        &attested,
        &manifest(),
        &text_execution(),
        &prompt_tokens(),
        &text_policy(),
        &identity_artifact(),
    );
    let mut attested_auth = authorization;
    attested_auth.prepared_input_digest = input_digest(&channel, &attested_bundle);
    attested_auth.request_commitment = Evaluate::commit_request(&attested);
    assert_eq!(
        check_prepared_input(&channel, &attested_auth, &policy, &attested_bundle),
        Err(PaidWorkError::Mismatch {
            field: "request assurance"
        })
    );

    // MUTATION: a runner key that is not the channel's client.
    let delegated = EvaluateRequest {
        runner_public_key: PublicKey::Secp256k1(provider().party_key().to_bytes()),
        ..evaluate_request()
    };
    let delegated_bundle = PreparedPaidInputV1::new(
        &delegated,
        &manifest(),
        &text_execution(),
        &prompt_tokens(),
        &text_policy(),
        &identity_artifact(),
    );
    let mut delegated_auth = authorization;
    delegated_auth.prepared_input_digest = input_digest(&channel, &delegated_bundle);
    delegated_auth.request_commitment = Evaluate::commit_request(&delegated);
    assert_eq!(
        check_prepared_input(&channel, &delegated_auth, &policy, &delegated_bundle),
        Err(PaidWorkError::Mismatch {
            field: "runner_public_key"
        })
    );
}

/// Each binding in the bundle's graph is broken on its own.
///
/// Mutating a component and the record that names it together proves
/// only that *some* check fired. Here every case leaves the rest of the
/// graph intact and recomputes the bundle digest, so the named check is
/// the only thing that can refuse it — which is what makes the check's
/// removal a test failure rather than a silent loss.
#[test]
fn each_graph_binding_is_checked_on_its_own() {
    let channel = channel();
    let policy = execution_policy();
    let base = authorization();

    // A prompt body the execution does not name.
    let other_prompt = TokenIds::from([5, 5, 5, 5]);
    assert_ne!(other_prompt.output_id(), prompt_tokens().output_id());
    let mismatched_prompt = PreparedPaidInputV1::new(
        &evaluate_request(),
        &manifest(),
        &text_execution(),
        &other_prompt,
        &text_policy(),
        &identity_artifact(),
    );
    let mut authorization = base;
    authorization.prepared_input_digest = input_digest(&channel, &mismatched_prompt);
    assert_eq!(
        check_prepared_input(&channel, &authorization, &policy, &mismatched_prompt),
        Err(PaidWorkError::Mismatch {
            field: "prompt_tokens id"
        })
    );

    // A generation policy the execution does not name.
    let other_policy = TextPolicy::from_u32_stop_tokens(32, [3]);
    assert_ne!(other_policy.output_id(), text_policy().output_id());
    let mismatched_policy = PreparedPaidInputV1::new(
        &evaluate_request(),
        &manifest(),
        &text_execution(),
        &prompt_tokens(),
        &other_policy,
        &identity_artifact(),
    );
    let mut authorization = base;
    authorization.prepared_input_digest = input_digest(&channel, &mismatched_policy);
    assert_eq!(
        check_prepared_input(&channel, &authorization, &policy, &mismatched_policy),
        Err(PaidWorkError::Mismatch {
            field: "text_policy id"
        })
    );

    // A manifest that is not the environment the request commits to.
    let other_manifest = ProgramManifest::Evaluate(EvaluateProgramManifest {
        graph: ContentId::from_bytes([0x99; 32]),
        ..match manifest() {
            ProgramManifest::Evaluate(evaluate) => evaluate,
            ProgramManifest::Fetch(_) => panic!("the fixture manifest is an evaluate manifest"),
        }
    });
    assert_ne!(other_manifest.content_id(), manifest().content_id());
    let mismatched_manifest = PreparedPaidInputV1::new(
        &evaluate_request(),
        &other_manifest,
        &text_execution(),
        &prompt_tokens(),
        &text_policy(),
        &identity_artifact(),
    );
    let mut authorization = base;
    authorization.prepared_input_digest = input_digest(&channel, &mismatched_manifest);
    assert_eq!(
        check_prepared_input(&channel, &authorization, &policy, &mismatched_manifest),
        Err(PaidWorkError::Mismatch {
            field: "manifest content id"
        })
    );

    // A request commitment the authorization does not carry.
    let mut restamped = base;
    restamped.request_commitment = RequestCommitment::from_digest(Digest::from_bytes([0x88; 32]));
    assert_eq!(
        check_prepared_input(&channel, &restamped, &policy, &bundle()),
        Err(PaidWorkError::Mismatch {
            field: "request_commitment"
        })
    );

    // An environment commitment the request does not name.
    let mut reenvironed = base;
    reenvironed.environment_commitment = ContentId::from_bytes([0x87; 32]);
    assert_eq!(
        check_prepared_input(&channel, &reenvironed, &policy, &bundle()),
        Err(PaidWorkError::Mismatch {
            field: "environment_commitment"
        })
    );

    // A policy pinned to a generation policy this bundle does not carry.
    let mut repinned = policy;
    repinned.generation_policy_digest = Digest::from_bytes([0x86; 32]);
    assert_eq!(
        check_prepared_input(&channel, &base, &repinned, &bundle()),
        Err(PaidWorkError::Mismatch {
            field: "generation_policy_digest"
        })
    );

    // A policy pinned to an identity artifact this bundle does not
    // carry.
    let mut resourced = policy;
    resourced.identity_source_digest = Digest::from_bytes([0x85; 32]);
    assert_eq!(
        check_prepared_input(&channel, &base, &resourced, &bundle()),
        Err(PaidWorkError::Mismatch {
            field: "identity_source_digest"
        })
    );

    // A bundle whose digest is not the one the authorization named at
    // all: the cheapest check, and the one that must not be the only
    // one.
    let mut unbound = base;
    unbound.prepared_input_digest = Digest::from_bytes([0x84; 32]);
    assert_eq!(
        check_prepared_input(&channel, &unbound, &policy, &bundle()),
        Err(PaidWorkError::Mismatch {
            field: "prepared_input_digest"
        })
    );
}

/// Each bound of the resource envelope refuses on its own.
///
/// Every case here recomputes the bundle digest and leaves the rest of
/// the graph intact, so the named bound is the only thing that can
/// refuse it: deleting any one of them makes exactly one of these
/// assertions return `Ok`.
#[test]
fn each_envelope_bound_is_checked_on_its_own() {
    let channel = channel();
    let base = execution_policy();
    let authorization = authorization();
    assert!(check_prepared_input(&channel, &authorization, &base, &bundle()).is_ok());

    // A bundle larger than the complete quote response this channel
    // agreed to hold. Refused before its digest is even computed: an
    // endpoint does not hash a body it has not agreed to receive.
    let encoded = bundle().encode().expect("a representable bundle");
    let cramped = PaidExecutionPolicyV1 {
        max_encoded_quote_response: 100,
        ..base
    };
    assert_eq!(
        check_prepared_input(&channel, &authorization, &cramped, &bundle()),
        Err(PaidWorkError::OverEnvelope {
            field: "prepared input length",
            actual: encoded.len() as u64,
            limit: 100
        })
    );
    // The exact length is legal; one byte less is not.
    let exact = PaidExecutionPolicyV1 {
        max_encoded_quote_response: encoded.len() as u32,
        ..base
    };
    assert!(check_prepared_input(&channel, &authorization, &exact, &bundle()).is_ok());

    // A generation longer than the policy admits.
    let short = PaidExecutionPolicyV1 {
        max_new_tokens: 63,
        ..base
    };
    assert_eq!(
        check_prepared_input(&channel, &authorization, &short, &bundle()),
        Err(PaidWorkError::OverEnvelope {
            field: "max_new_tokens",
            actual: 64,
            limit: 63
        })
    );

    // More stop tokens than the policy admits.
    let few = PaidExecutionPolicyV1 {
        max_stop_token_ids: 1,
        ..base
    };
    assert_eq!(
        check_prepared_input(&channel, &authorization, &few, &bundle()),
        Err(PaidWorkError::OverEnvelope {
            field: "stop token ids",
            actual: 2,
            limit: 1
        })
    );

    // A request authorized to generate nothing. Zero is inside every
    // bound above it, so nothing but its own rule refuses it.
    let silent = TextPolicy::from_u32_stop_tokens(0, [2, 1]);
    let (silent_bundle, silent_auth) = bundle_with_policy(&channel, &silent);
    let admits_silence = PaidExecutionPolicyV1 {
        generation_policy_digest: policy_digest_of(&silent),
        ..base
    };
    assert_eq!(
        check_prepared_input(&channel, &silent_auth, &admits_silence, &silent_bundle),
        Err(PaidWorkError::PolicyZero {
            field: "request max_new_tokens"
        })
    );
}

/// Rebuilds the bundle and the authorization around one replacement
/// generation policy, leaving every other binding intact.
fn bundle_with_policy(
    channel: &PaidChannel,
    policy: &TextPolicy,
) -> (PreparedPaidInputV1, PaidJobAuthorizationV1) {
    let execution = TextExecution::new(
        SourceRef::output(identity_artifact().output_id()),
        prompt_tokens().output_id(),
        policy.output_id(),
    );
    let request = EvaluateRequest {
        text_execution: execution.input_id().digest(),
        ..evaluate_request()
    };
    let bundle = PreparedPaidInputV1::new(
        &request,
        &manifest(),
        &execution,
        &prompt_tokens(),
        policy,
        &identity_artifact(),
    );
    let authorization = PaidJobAuthorizationV1 {
        prepared_input_digest: input_digest(channel, &bundle),
        request_commitment: Evaluate::commit_request(&request),
        ..authorization()
    };
    (bundle, authorization)
}

/// This profile starts from the identity artifact and nothing else.
///
/// A job resumed from a previous output would be paid for work whose
/// input the bundle does not carry. The policy here is repinned to the
/// output artifact and the execution names it as its source, so the two
/// neighbouring rules — the source check and the identity commitment —
/// both pass, and only the artifact's kind refuses it.
#[test]
fn only_the_identity_artifact_may_start_a_paid_job() {
    let channel = channel();
    let resumed = TextArtifact::output(
        text_execution().input_id(),
        4,
        TextState::new(prompt_tokens().output_id()).output_id(),
        prompt_tokens().output_id(),
    );
    let execution = TextExecution::new(
        SourceRef::output(resumed.output_id()),
        prompt_tokens().output_id(),
        text_policy().output_id(),
    );
    let request = EvaluateRequest {
        text_execution: execution.input_id().digest(),
        ..evaluate_request()
    };
    let bundle = PreparedPaidInputV1::new(
        &request,
        &manifest(),
        &execution,
        &prompt_tokens(),
        &text_policy(),
        &resumed,
    );
    let authorization = PaidJobAuthorizationV1 {
        prepared_input_digest: input_digest(&channel, &bundle),
        request_commitment: Evaluate::commit_request(&request),
        ..authorization()
    };
    let policy = PaidExecutionPolicyV1 {
        identity_source_digest: identity_digest_of(&resumed),
        ..execution_policy()
    };
    assert_eq!(
        check_prepared_input(&channel, &authorization, &policy, &bundle),
        Err(PaidWorkError::Mismatch {
            field: "identity_artifact kind"
        })
    );
}

// ── Result, invoice, allocation ───────────────────────────────────────

/// A result answers one job. Swapping two provider-signed results
/// between two authorizations rejects both invoice transitions.
#[test]
fn results_cannot_be_swapped_between_jobs() {
    let channel = channel();
    let first = authorization();
    let mut second = authorization();
    second.proposal_nonce ^= 0xff;

    let first_id = work_id(&channel, &first);
    let second_id = work_id(&channel, &second);
    assert_ne!(first_id, second_id);

    let first_result = job_result(first_id);
    let second_result = job_result(second_id);

    assert!(next_invoice_entry(&channel, &first, &first_result, 1, 0, capacity()).is_ok());
    assert!(next_invoice_entry(&channel, &second, &second_result, 1, 0, capacity()).is_ok());

    // MUTATION: pay the first job with the second job's result.
    assert_eq!(
        next_invoice_entry(&channel, &first, &second_result, 1, 0, capacity()),
        Err(PaidWorkError::Mismatch { field: "work_id" })
    );
    assert_eq!(
        next_invoice_entry(&channel, &second, &first_result, 1, 0, capacity()),
        Err(PaidWorkError::Mismatch { field: "work_id" })
    );
}

/// The result digest binds the output and the transcript, so re-signing
/// mutated output bytes produces a different digest and a different
/// invoice.
#[test]
fn result_output_mutations_move_the_result_digest() {
    let channel = channel();
    let id = work_id(&channel, &authorization());
    let base = job_result(id);
    let pinned = check_result(&channel, id, &base).expect("a legal result");

    // MUTATION: different output bytes, honestly re-signed by the
    // provider. The digest moves, so the invoice that named the old one
    // no longer describes this result.
    let mut different_output = base;
    different_output.canonical_output_digest = Digest::from_bytes([0x33; 32]);
    assert_ne!(result_digest(&channel, &different_output), pinned);

    // MUTATION: the same answer under a different transcript.
    let mut different_transcript = base;
    different_transcript.terminal_transcript_commitment =
        EventCommitment::from_digest(Digest::from_bytes([0x34; 32]));
    assert_ne!(result_digest(&channel, &different_transcript), pinned);
}

/// A new channel starts at sequence 1 and cumulative 0, and the
/// transition is checked arithmetic against the edge's capacity.
#[test]
fn invoice_transition_is_checked_arithmetic() {
    let channel = channel();
    let authorization = authorization();
    let result = job_result(work_id(&channel, &authorization));

    let first = next_invoice_entry(&channel, &authorization, &result, 1, 0, capacity())
        .expect("a legal first invoice");
    assert_eq!(first.invoice_seq, 1);
    assert_eq!(first.cumulative_before, 0);
    assert_eq!(first.cumulative_after, 250);

    // MUTATION: zero-based sequence numbering.
    assert_eq!(
        next_invoice_entry(&channel, &authorization, &result, 0, 0, capacity()),
        Err(PaidWorkError::InvoiceSequence {
            expected: 1,
            actual: 0
        })
    );

    // MUTATION: a transition that would exceed the edge's capacity.
    let Some(thin) = work_payment_settlement(EdgeValues::new(400, 0, Fees::ZERO), 100) else {
        panic!("a funded edge prices both exits");
    };
    assert_eq!(thin.capacity(), 300);
    assert_eq!(
        next_invoice_entry(&channel, &authorization, &result, 2, 100, thin),
        Err(PaidWorkError::OverCapacity {
            cumulative: 350,
            capacity: 300
        })
    );

    // MUTATION: a cumulative that would wrap.
    let Some(widest) = work_payment_settlement(EdgeValues::new(u64::MAX, 0, Fees::ZERO), 0) else {
        panic!("the largest edge is representable");
    };
    assert_eq!(
        next_invoice_entry(&channel, &authorization, &result, 2, u64::MAX, widest),
        Err(PaidWorkError::Overflow {
            field: "cumulative_after"
        })
    );
}

fn allocation_over(
    entries: &[InvoiceEntryV1],
    certificate: &EarnedCertificate,
) -> CertificateAllocationV1 {
    let channel = channel();
    CertificateAllocationV1 {
        channel_id: channel.id(),
        certificate_digest: certificate.digest(channel.network()),
        first_invoice_seq: entries.first().expect("nonempty").invoice_seq,
        last_invoice_seq: entries.last().expect("nonempty").invoice_seq,
        invoice_entries_root: invoice_entries_root(&channel, entries).expect("legal allocation"),
    }
}

/// Three distinct jobs, invoiced at sequences 1, 2 and 3.
fn three_jobs() -> Vec<InvoicedJob> {
    let channel = channel();
    let mut jobs = Vec::new();
    let mut cumulative = 0;
    for index in 0..3_u64 {
        let mut authorization = authorization();
        authorization.proposal_nonce = index;
        let result = job_result(work_id(&channel, &authorization));
        let entry = next_invoice_entry(
            &channel,
            &authorization,
            &result,
            index + 1,
            cumulative,
            capacity(),
        )
        .expect("a legal invoice");
        cumulative = entry.cumulative_after;
        jobs.push(InvoicedJob {
            authorization,
            result,
            entry,
        });
    }
    jobs
}

fn entries_of(jobs: &[InvoicedJob]) -> Vec<InvoiceEntryV1> {
    jobs.iter().map(|job| job.entry).collect()
}

fn three_entries() -> Vec<InvoiceEntryV1> {
    entries_of(&three_jobs())
}

fn allocation_of(jobs: &[InvoicedJob], certificate: &EarnedCertificate) -> CertificateAllocationV1 {
    allocation_over(&entries_of(jobs), certificate)
}

/// The allocation binds one certificate to exactly one contiguous
/// invoice prefix.
#[test]
fn allocation_binds_the_certificate_to_its_prefix() {
    let channel = channel();
    let jobs = three_jobs();
    let certificate = earned(750);
    let allocation = allocation_of(&jobs, &certificate);

    CreditLedger::new()
        .credit_allocation(&channel, &allocation, &jobs, &certificate)
        .expect("a legal allocation");

    // MUTATION: a certificate for a different total.
    let short = earned(500);
    let mut short_allocation = allocation;
    short_allocation.certificate_digest = short.digest(channel.network());
    assert_eq!(
        CreditLedger::new().credit_allocation(&channel, &short_allocation, &jobs, &short),
        Err(PaidWorkError::Mismatch {
            field: "certificate earned_cumulative"
        })
    );

    // MUTATION: the right total under the wrong allocation digest.
    let mut wrong_digest = allocation;
    wrong_digest.certificate_digest = hellas_kernel::PayloadHash::from_bytes([0; 32]);
    assert_eq!(
        CreditLedger::new().credit_allocation(&channel, &wrong_digest, &jobs, &certificate),
        Err(PaidWorkError::Mismatch {
            field: "certificate_digest"
        })
    );

    // MUTATION: a root over a different prefix with the same entry
    // count. The tree binds absolute sequence numbers, so this cannot
    // pass by having the right shape.
    let mut later = three_entries();
    for entry in &mut later {
        entry.invoice_seq += 3;
    }
    let mut swapped_root = allocation;
    swapped_root.invoice_entries_root =
        invoice_entries_root(&channel, &later).expect("legal allocation");
    assert_eq!(
        CreditLedger::new().credit_allocation(&channel, &swapped_root, &jobs, &certificate),
        Err(PaidWorkError::Mismatch {
            field: "invoice_entries_root"
        })
    );

    // MUTATION: a gap in the sequence.
    let mut gapped = jobs.clone();
    gapped[2].entry.invoice_seq = 4;
    let gapped_allocation = allocation_of(&gapped, &certificate);
    assert_eq!(
        CreditLedger::new().credit_allocation(&channel, &gapped_allocation, &gapped, &certificate),
        Err(PaidWorkError::InvoiceSequence {
            expected: 3,
            actual: 4
        })
    );

    // MUTATION: a cumulative that does not continue its predecessor's.
    let mut skipped = jobs.clone();
    skipped[1].entry.cumulative_before += 1;
    skipped[1].entry.cumulative_after += 1;
    skipped[2].entry.cumulative_before += 1;
    skipped[2].entry.cumulative_after += 1;
    let skipped_allocation = allocation_of(&skipped, &earned(751));
    assert_eq!(
        CreditLedger::new().credit_allocation(
            &channel,
            &skipped_allocation,
            &skipped,
            &earned(751)
        ),
        Err(PaidWorkError::Mismatch {
            field: "cumulative_before"
        })
    );

    // MUTATION: a transition that is not its own two endpoints. The
    // price still matches the authorization, so only the arithmetic can
    // refuse it.
    let mut widened = jobs.clone();
    widened[1].entry.cumulative_after += 1;
    widened[2].entry.cumulative_before += 1;
    widened[2].entry.cumulative_after += 1;
    let widened_allocation = allocation_of(&widened, &earned(751));
    assert_eq!(
        CreditLedger::new().credit_allocation(
            &channel,
            &widened_allocation,
            &widened,
            &earned(751)
        ),
        Err(PaidWorkError::Mismatch {
            field: "cumulative_after"
        })
    );

    // MUTATION: the same job invoiced twice inside one allocation.
    let mut duplicated = jobs.clone();
    duplicated[2].authorization = duplicated[0].authorization;
    duplicated[2].result = duplicated[0].result;
    duplicated[2].entry.work_id = duplicated[0].entry.work_id;
    duplicated[2].entry.result_digest = duplicated[0].entry.result_digest;
    let duplicated_allocation = allocation_of(&duplicated, &certificate);
    assert_eq!(
        CreditLedger::new().credit_allocation(
            &channel,
            &duplicated_allocation,
            &duplicated,
            &certificate
        ),
        Err(PaidWorkError::Duplicate { field: "work_id" })
    );

    // MUTATION: an allocation over no entries at all.
    assert_eq!(
        CreditLedger::new().credit_allocation(&channel, &allocation, &[], &certificate),
        Err(PaidWorkError::AllocationSize { count: 0 })
    );
}

/// A job this ledger has already paid for cannot be billed again, at any
/// later sequence.
///
/// The two entries are byte-identical in everything the invoice binds to
/// the job — the same `work_id`, the same `result_digest`, the same
/// price — and differ only in the sequence and the cumulative pair that
/// an honest second job would also have moved. A prefix rule alone
/// accepts the second one, because it *is* the next prefix; only a
/// ledger that remembers the first refuses it.
#[test]
fn a_credited_job_cannot_be_billed_again_at_a_fresh_sequence() {
    let channel = channel();
    let authorization = authorization();
    let result = job_result(work_id(&channel, &authorization));

    let first = next_invoice_entry(&channel, &authorization, &result, 1, 0, capacity())
        .expect("a legal invoice");
    let again = next_invoice_entry(&channel, &authorization, &result, 2, 250, capacity())
        .expect("the builder recomputes one job's identifiers");
    assert_eq!(first.work_id, again.work_id);
    assert_eq!(first.result_digest, again.result_digest);

    let paid = InvoicedJob {
        authorization,
        result,
        entry: first,
    };
    let rebilled = InvoicedJob {
        authorization,
        result,
        entry: again,
    };

    let mut ledger = CreditLedger::new();
    ledger
        .credit_allocation(
            &channel,
            &allocation_of(&[paid], &earned(250)),
            &[paid],
            &earned(250),
        )
        .expect("a legal allocation");
    assert_eq!(ledger.next_invoice_seq(), 2);
    assert_eq!(ledger.credited_invoice_high_water(), 250);

    // MUTATION: the same job, re-invoiced at the sequence the ledger is
    // now waiting for, at the cumulative it is now waiting for.
    assert_eq!(
        ledger.credit_allocation(
            &channel,
            &allocation_of(&[rebilled], &earned(500)),
            &[rebilled],
            &earned(500),
        ),
        Err(PaidWorkError::Duplicate { field: "work_id" })
    );
    // The refusal credited nothing.
    assert_eq!(ledger.next_invoice_seq(), 2);
    assert_eq!(ledger.credited_invoice_high_water(), 250);
}

/// One allocation continues the last one; it does not start wherever it
/// likes.
///
/// Seeding the expected sequence from the allocation's own first entry
/// makes every allocation a prefix of itself, which is no rule at all.
#[test]
fn an_allocation_must_continue_the_credited_prefix() {
    let channel = channel();
    let jobs = three_jobs();
    let certificate = earned(750);
    let mut ledger = CreditLedger::new();
    ledger
        .credit_allocation(
            &channel,
            &allocation_of(&jobs, &certificate),
            &jobs,
            &certificate,
        )
        .expect("a legal allocation");
    assert_eq!(ledger.next_invoice_seq(), 4);

    // MUTATION: a second allocation that begins nowhere near sequence 4,
    // and is internally contiguous and internally correct.
    let mut far = three_jobs();
    let mut cumulative = 750;
    for (index, job) in far.iter_mut().enumerate() {
        job.authorization.proposal_nonce = 0xf0 + index as u64;
        job.result = job_result(work_id(&channel, &job.authorization));
        job.entry = next_invoice_entry(
            &channel,
            &job.authorization,
            &job.result,
            900_000 + index as u64,
            cumulative,
            capacity(),
        )
        .expect("a legal invoice");
        cumulative = job.entry.cumulative_after;
    }
    let far_certificate = earned(1_500);
    assert_eq!(
        ledger.credit_allocation(
            &channel,
            &allocation_of(&far, &far_certificate),
            &far,
            &far_certificate
        ),
        Err(PaidWorkError::InvoiceSequence {
            expected: 4,
            actual: 900_000
        })
    );

    // MUTATION: the right sequence, the wrong cumulative — an allocation
    // that skips the amount the ledger has already credited.
    let mut restated = three_jobs();
    cumulative = 0;
    for (index, job) in restated.iter_mut().enumerate() {
        job.authorization.proposal_nonce = 0xe0 + index as u64;
        job.result = job_result(work_id(&channel, &job.authorization));
        job.entry = next_invoice_entry(
            &channel,
            &job.authorization,
            &job.result,
            4 + index as u64,
            cumulative,
            capacity(),
        )
        .expect("a legal invoice");
        cumulative = job.entry.cumulative_after;
    }
    assert_eq!(
        ledger.credit_allocation(
            &channel,
            &allocation_of(&restated, &certificate),
            &restated,
            &certificate
        ),
        Err(PaidWorkError::Mismatch {
            field: "cumulative_before"
        })
    );
}

/// An entry is checked against the job it claims to bill, not merely
/// against the entry before it.
///
/// Arithmetic alone accepts an honest `work_id` at ten times its price,
/// because the price↔authorization binding lives in the builder, and a
/// rule that holds only on the honest path holds only for honest
/// providers.
#[test]
fn an_entry_must_name_the_job_and_the_price_it_was_authorized_for() {
    let channel = channel();
    let jobs = three_jobs();
    let certificate = earned(750);

    // MUTATION: an honest job at ten times its authorized price, with
    // every cumulative and the certificate moved to agree.
    let mut dear = jobs.clone();
    dear[1].entry.price = 2_500;
    dear[1].entry.cumulative_after = dear[1].entry.cumulative_before + 2_500;
    dear[2].entry.cumulative_before = dear[1].entry.cumulative_after;
    dear[2].entry.cumulative_after = dear[2].entry.cumulative_before + 250;
    let dear_certificate = earned(3_000);
    assert_eq!(
        CreditLedger::new().credit_allocation(
            &channel,
            &allocation_of(&dear, &dear_certificate),
            &dear,
            &dear_certificate
        ),
        Err(PaidWorkError::Mismatch {
            field: "invoice price"
        })
    );

    // MUTATION: an entry naming a job this endpoint never authorized.
    let mut foreign = jobs.clone();
    foreign[1].entry.work_id = Digest::from_bytes([0x7a; 32]);
    assert_eq!(
        CreditLedger::new().credit_allocation(
            &channel,
            &allocation_of(&foreign, &certificate),
            &foreign,
            &certificate
        ),
        Err(PaidWorkError::Mismatch {
            field: "invoice work_id"
        })
    );

    // MUTATION: an entry billing a result the provider never signed for
    // this job. The result body still answers the job, so only the
    // entry's own copy of the digest is wrong.
    let mut unsigned = jobs.clone();
    unsigned[1].entry.result_digest = Digest::from_bytes([0x7b; 32]);
    assert_eq!(
        CreditLedger::new().credit_allocation(
            &channel,
            &allocation_of(&unsigned, &certificate),
            &unsigned,
            &certificate
        ),
        Err(PaidWorkError::Mismatch {
            field: "invoice result_digest"
        })
    );

    // MUTATION: a result for another job entirely.
    let mut swapped = jobs.clone();
    swapped[1].result = swapped[0].result;
    assert_eq!(
        CreditLedger::new().credit_allocation(
            &channel,
            &allocation_of(&swapped, &certificate),
            &swapped,
            &certificate
        ),
        Err(PaidWorkError::Mismatch { field: "work_id" })
    );
}

/// An entry from another channel is refused, however well it agrees with
/// everything around it.
///
/// The entry's own `channel_id` is the only field that says which
/// channel it belongs to: the tree recomputes over whatever entries it
/// is given, and the work id, result digest and price all come from an
/// authorization that this channel did accept.
#[test]
fn an_entry_from_another_channel_is_refused() {
    let channel = channel();
    let sibling = channel_on(network(), EdgeId::from_bytes([0xe2; 32]));
    assert_ne!(channel.id(), sibling.id());

    let mut jobs = three_jobs();
    jobs[1].entry.channel_id = sibling.id();
    let certificate = earned(750);
    assert_eq!(
        CreditLedger::new().credit_allocation(
            &channel,
            &allocation_of(&jobs, &certificate),
            &jobs,
            &certificate
        ),
        Err(PaidWorkError::Mismatch {
            field: "invoice channel_id"
        })
    );
}

/// The certificate must name this channel's edge, and its terms.
///
/// The terms hash is the sole discriminator between two certificates on
/// one edge under two different terms: the edge matches, the amount
/// matches, and the allocation digest is over the certificate offered.
#[test]
fn allocation_rejects_a_certificate_from_another_edge_or_other_terms() {
    let channel = channel();
    let jobs = three_jobs();

    let other_edge = EarnedCertificate::new(
        EdgeId::from_bytes([0; 32]),
        channel.payment_terms_hash(),
        750,
    );
    let allocation = CertificateAllocationV1 {
        certificate_digest: other_edge.digest(channel.network()),
        ..allocation_of(&jobs, &earned(750))
    };
    assert_eq!(
        CreditLedger::new().credit_allocation(&channel, &allocation, &jobs, &other_edge),
        Err(PaidWorkError::Mismatch {
            field: "certificate payment_edge"
        })
    );

    // MUTATION: this channel's edge under terms it never agreed to.
    let other_terms = EarnedCertificate::new(
        channel.payment_edge(),
        TermsHash::from_bytes([0x9c; 32]),
        750,
    );
    assert_ne!(
        other_terms.payment_terms_hash(),
        channel.payment_terms_hash()
    );
    let allocation = CertificateAllocationV1 {
        certificate_digest: other_terms.digest(channel.network()),
        ..allocation_of(&jobs, &earned(750))
    };
    assert_eq!(
        CreditLedger::new().credit_allocation(&channel, &allocation, &jobs, &other_terms),
        Err(PaidWorkError::Mismatch {
            field: "certificate payment_terms_hash"
        })
    );
}

/// Every invoice-entry field is inside the leaf, so the root moves when
/// any of them does.
#[test]
fn every_invoice_field_moves_the_root() {
    let channel = channel();
    let entries = three_entries();
    let root = invoice_entries_root(&channel, &entries).expect("legal allocation");

    for index in 0..3 {
        for mutate in [
            (|e: &mut InvoiceEntryV1| e.invoice_seq += 100) as fn(&mut InvoiceEntryV1),
            |e: &mut InvoiceEntryV1| e.price += 1,
            |e: &mut InvoiceEntryV1| e.cumulative_before += 1,
            |e: &mut InvoiceEntryV1| e.cumulative_after += 1,
            |e: &mut InvoiceEntryV1| e.work_id = Digest::from_bytes([0; 32]),
            |e: &mut InvoiceEntryV1| e.result_digest = Digest::from_bytes([0; 32]),
            |e: &mut InvoiceEntryV1| e.channel_id = Digest::from_bytes([0; 32]),
        ] {
            let mut mutated = entries.clone();
            mutate(&mut mutated[index]);
            assert_ne!(
                invoice_entries_root(&channel, &mutated).expect("legal allocation"),
                root
            );
        }
    }
}

/// The invoice tree's shape is pinned: widths, absolute starts, and the
/// empty root.
#[test]
fn invoice_tree_shape_is_pinned() {
    let channel = channel();
    let entries = three_entries();

    let single = invoice_entries_root(&channel, &entries[..1]).expect("legal allocation");
    let pair = invoice_entries_root(&channel, &entries[..2]).expect("legal allocation");
    let triple = invoice_entries_root(&channel, &entries).expect("legal allocation");
    assert_ne!(single, pair);
    assert_ne!(pair, triple);
    // A prefix is not the whole: the node binds `n`.
    assert_ne!(
        triple,
        invoice_entries_root(&channel, &entries[..2]).expect("legal")
    );

    // The empty root exists, and is not any real allocation's root.
    let empty = invoice_empty_root();
    assert_ne!(empty, single);
    assert_eq!(
        invoice_entries_root(&channel, &[]),
        Err(PaidWorkError::AllocationSize { count: 0 })
    );

    // A leaf is the digest of its entry under its absolute sequence.
    assert_ne!(single, invoice_digest(&channel, &entries[0]));

    // The tree admits its stated maximum and nothing above it.
    let mut wide = Vec::new();
    for index in 0..MAX_ALLOCATION_ENTRIES + 1 {
        let mut entry = entries[0];
        entry.invoice_seq = index as u64 + 1;
        wide.push(entry);
    }
    assert!(invoice_entries_root(&channel, &wide[..MAX_ALLOCATION_ENTRIES]).is_ok());
    assert_eq!(
        invoice_entries_root(&channel, &wide),
        Err(PaidWorkError::AllocationSize { count: 257 })
    );
}

/// The allocation digest is what the client signs, and every field of
/// the allocation is inside it.
#[test]
fn allocation_digest_binds_every_field() {
    let channel = channel();
    let entries = three_entries();
    let certificate = earned(750);
    let base = allocation_over(&entries, &certificate);
    let pinned = allocation_digest(&channel, &base);

    let mutations: Vec<(&str, CertificateAllocationV1)> = vec![
        ("channel_id", {
            let mut m = base;
            m.channel_id = Digest::from_bytes([0; 32]);
            m
        }),
        ("certificate_digest", {
            let mut m = base;
            m.certificate_digest = hellas_kernel::PayloadHash::from_bytes([0; 32]);
            m
        }),
        ("first_invoice_seq", {
            let mut m = base;
            m.first_invoice_seq += 1;
            m
        }),
        ("last_invoice_seq", {
            let mut m = base;
            m.last_invoice_seq += 1;
            m
        }),
        ("invoice_entries_root", {
            let mut m = base;
            m.invoice_entries_root = Digest::from_bytes([0; 32]);
            m
        }),
    ];
    assert_eq!(mutations.len(), 5);
    for (field, mutated) in mutations {
        assert_ne!(allocation_digest(&channel, &mutated), pinned, "{field}");
    }

    // The signature is over the digest, so a mutated allocation is not
    // the one the client signed.
    let payload = hellas_kernel::PayloadHash::from_bytes(pinned.into_bytes());
    let signature = client().sign(payload);
    assert!(Secp256k1Verifier.verify_sig(signature, channel.client_key(), payload));
    let mut moved = base;
    moved.last_invoice_seq += 1;
    let moved_payload =
        hellas_kernel::PayloadHash::from_bytes(allocation_digest(&channel, &moved).into_bytes());
    assert!(!Secp256k1Verifier.verify_sig(signature, channel.client_key(), moved_payload));
}

/// The invoice tree's leaf and node preimages, rebuilt by hand.
///
/// The width `n` is why this test exists. An honest builder derives `k`
/// from `n` and both subtrees from the entries, so no pair of legal
/// allocations differs in `n` alone — dropping it from the preimage
/// changes no root any other test computes. It is pinned here instead,
/// because the field is what a later inclusion proof would be checked
/// against, and a preimage nothing can fail is a preimage nothing keeps.
#[test]
fn invoice_tree_preimages_are_reproducible_by_hand() {
    let channel = channel();
    let entries = three_entries();
    let pair = &entries[..2];

    let leaf = |seq: u64, entry: &InvoiceEntryV1| {
        let mut preimage = b"hellas.work.private-invoice-leaf.v1".to_vec();
        preimage.extend_from_slice(&seq.to_be_bytes());
        preimage.extend_from_slice(invoice_digest(&channel, entry).as_bytes());
        Digest::hash(&preimage)
    };

    let mut preimage = b"hellas.work.private-invoice-node.v1".to_vec();
    preimage.extend_from_slice(&1_u64.to_be_bytes()); // start
    preimage.extend_from_slice(&2_u16.to_be_bytes()); // n
    preimage.extend_from_slice(&1_u16.to_be_bytes()); // k
    preimage.extend_from_slice(leaf(1, &pair[0]).as_bytes());
    preimage.extend_from_slice(leaf(2, &pair[1]).as_bytes());
    assert_eq!(preimage.len(), 35 + 8 + 2 + 2 + 64);
    assert_eq!(
        Digest::hash(&preimage),
        invoice_entries_root(&channel, pair).expect("legal allocation")
    );

    let mut empty = b"hellas.work.private-invoice-empty.v1".to_vec();
    empty.push(0);
    assert_eq!(Digest::hash(&empty), invoice_empty_root());
}

// ── Canonical output ──────────────────────────────────────────────────

/// The normalized answer ignores chunk boundaries and binds everything
/// the oracle compares.
#[test]
fn canonical_output_digest_normalizes_chunking() {
    let network = network();
    let id = work_id(&channel(), &authorization());
    let terminal = EvaluateTerminal {
        final_position: 4,
        stop_reason: EvaluateStopReason::END_OF_SEQUENCE,
        text_artifact: Digest::from_bytes([0x60; 32]),
        usage: EvaluateUsage {
            input_units: 4,
            output_units: 4,
        },
        billable_units: 8,
    };
    let tokens = [11, 12, 13, 14];
    let digest = canonical_output_digest(network, id, &tokens, &terminal).expect("legal terminal");

    // MUTATION: reorder the tokens.
    assert_ne!(
        canonical_output_digest(network, id, &[11, 12, 14, 13], &terminal).expect("legal"),
        digest
    );

    // MUTATION: another stop reason.
    let mut stopped = terminal.clone();
    stopped.stop_reason = EvaluateStopReason::MAX_OUTPUT;
    assert_ne!(
        canonical_output_digest(network, id, &tokens, &stopped).expect("legal"),
        digest
    );

    // MUTATION: another text artifact.
    let mut artifact = terminal.clone();
    artifact.text_artifact = Digest::from_bytes([0x61; 32]);
    assert_ne!(
        canonical_output_digest(network, id, &tokens, &artifact).expect("legal"),
        digest
    );

    // MUTATION: usage that does not describe the token list.
    let mut usage = terminal.clone();
    usage.usage.output_units = 3;
    assert_eq!(
        canonical_output_digest(network, id, &tokens, &usage),
        Err(PaidWorkError::Mismatch {
            field: "output token count"
        })
    );

    // MUTATION: a billable total that is not the sum.
    let mut billable = terminal.clone();
    billable.billable_units = 9;
    assert_eq!(
        canonical_output_digest(network, id, &tokens, &billable),
        Err(PaidWorkError::Mismatch {
            field: "billable units"
        })
    );

    // The same answer for another job is another digest.
    assert_ne!(
        canonical_output_digest(network, Digest::from_bytes([0; 32]), &tokens, &terminal)
            .expect("legal"),
        digest
    );
}

// ── Independent preimage reproduction ─────────────────────────────────

/// Rebuilds two complete preimages by hand and hashes them through the
/// crate's *other* hashing entry point.
///
/// [`Digest::hash`] chunks its input and takes a Merkle file hash;
/// `work.rs` streams into the allocation-free single-chunk hasher. If the
/// domain, the network's length prefix, the channel argument, or the
/// envelope-plus-body order in this file disagreed with the module's, the
/// two would not meet here. The same two preimages were also hashed
/// outside this workspace with `b3sum --keyed`, twice: once under the Xet
/// DATA key and once under the zero key.
#[test]
fn digest_preimages_are_reproducible_by_hand() {
    let channel = channel();

    let mut preimage = b"hellas.work.channel.v2".to_vec();
    preimage.push(NETWORK.len() as u8);
    preimage.extend_from_slice(NETWORK.as_bytes());
    preimage.extend_from_slice(channel.payment_edge().as_bytes());
    preimage.extend_from_slice(channel.payment_terms_hash().as_bytes());
    preimage.extend_from_slice(payment_terms().bond_edge.as_bytes());
    preimage.extend_from_slice(payment_terms().bond_terms_hash().as_bytes());
    assert_eq!(Digest::hash(&preimage), channel.id());
    assert_eq!(preimage.len(), 22 + 16 + 128);

    let result = job_result(work_id(&channel, &authorization()));
    let mut preimage = b"hellas.work.paid-job-result.v1".to_vec();
    preimage.push(NETWORK.len() as u8);
    preimage.extend_from_slice(NETWORK.as_bytes());
    preimage.extend_from_slice(channel.id().as_bytes());
    preimage.push(1);
    preimage.push(3);
    preimage.extend_from_slice(result.work_id.as_bytes());
    preimage.extend_from_slice(result.terminal_transcript_commitment.as_bytes());
    preimage.extend_from_slice(result.canonical_output_digest.as_bytes());
    assert_eq!(Digest::hash(&preimage), result_digest(&channel, &result));
    assert_eq!(preimage.len(), 30 + 16 + 32 + 98);
    assert_eq!(
        hex(&Digest::hash(&preimage).into_bytes()),
        "4ffac06a6c7d63aa63a0dad62ce1bb4e37881da550a42091a490d084fa32f00d"
    );
}
