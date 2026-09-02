//! Whether a configured channel is the channel on chain, and whether a
//! job may be signed against it.
//!
//! Every observed object here is built from canonical bytes written out
//! field by field, not from a kernel constructor: an endpoint reads
//! these off a wire, so its side of the agreement is a byte layout. A
//! round trip against the kernel's own encoder would pass with two
//! fields transposed; these do not.

#![cfg(feature = "work")]

use hellas_kernel::{
    BlockHeight, Decode as _, Edge, EdgeId, EdgeValues, Fees, LeaseSlots, List, MAX_EDGE_OUTPUTS,
    NetworkId, Parties, Payout, PendingSlot, RegistryChunk, RegistryNamespace, RegistryRecordTag,
    Terms, TermsHash, WorkPaymentTerms, WorkStakeBondTerms,
};
use hellas_rpc::protocol::work::{
    PaidChannelPolicyV1, PaidExecutionPolicyV1, PaidWorkError, private_policy_commitment,
};
use hellas_rpc::protocol::work_setup::{
    CloseDescriptor, LeaseState, OMISSION_PROBABILITY_SCALE, ObservedChannel, OmissionError,
    OmissionMeasurements, PendingState, WorkChannelConfig, WorkChannelDescriptor, WorkSetupError,
    check_omission_economics, payment_terms_hash,
};
use hellas_rpc::protocol::{ContentId, Digest};

// ── Fixture ───────────────────────────────────────────────────────────

const HORIZON: u64 = 500;
const OMISSION_BOND: u64 = 4;
const PAYMENT_VALUE: u64 = 1_000;
const PAYMENT_RESERVE: u64 = 200;
const STAKE: u64 = 64;
const SALT: [u8; 32] = [0x5a; 32];
/// A probability and cost cap the fixture's capacity clears with room,
/// so a test that moves one of the three inputs is testing that input.
const Q: u64 = 999_000;
const COST_CAP: u64 = 1;
/// The response window the fixture's terms admit, and the window `Q` is
/// declared to have been measured over.
const WINDOW: u64 = hellas_kernel::MIN_OMIT_RESPONSE_BLOCKS;

/// The three measurements, at the window the fixture's terms admit.
fn measured(response_probability: u64, response_cost_cap: u64) -> OmissionMeasurements {
    OmissionMeasurements {
        response_probability,
        response_blocks: WINDOW,
        response_cost_cap,
    }
}

fn network() -> NetworkId {
    let Some(network) = NetworkId::new("hellas-test") else {
        panic!("a short ascii id is a legal network id");
    };
    network
}

fn provider_key() -> hellas_kernel::Key {
    hellas_kernel::Key::from_bytes([0x02; hellas_kernel::Key::LENGTH])
}

fn client_key() -> hellas_kernel::Key {
    hellas_kernel::Key::from_bytes([0x03; hellas_kernel::Key::LENGTH])
}

fn bond_edge() -> EdgeId {
    EdgeId::from_bytes([0x11; EdgeId::LENGTH])
}

fn payment_edge() -> EdgeId {
    EdgeId::from_bytes([0x22; EdgeId::LENGTH])
}

fn bond_terms() -> WorkStakeBondTerms {
    WorkStakeBondTerms {
        // Maker = provider, taker = client. The payment edge mirrors it.
        parties: Parties::new(provider_key(), client_key()),
        timeout: BlockHeight::new(HORIZON),
        timeout_outputs: List::take([Payout::new(provider_key(), STAKE); MAX_EDGE_OUTPUTS], 1),
        max_job_price: 40,
    }
}

fn channel_policy() -> PaidChannelPolicyV1 {
    PaidChannelPolicyV1 {
        compute_credit_limit: 40,
        delivery_credit_limit: 40,
    }
}

fn payment_terms() -> WorkPaymentTerms {
    WorkPaymentTerms {
        bond_edge: bond_edge(),
        bond_terms: bond_terms(),
        private_policy_commitment: private_policy_commitment(network(), &SALT, &channel_policy()),
        omit_response_blocks: WINDOW,
        start_validity_blocks: 8,
        omission_bond: OMISSION_BOND,
    }
}

fn execution_policy() -> PaidExecutionPolicyV1 {
    PaidExecutionPolicyV1 {
        allowed_environment: ContentId::from_bytes([0x31; 32]),
        generation_policy_digest: Digest::from_bytes([0x32; 32]),
        identity_source_digest: Digest::from_bytes([0x33; 32]),
        max_prompt_tokens: 512,
        max_new_tokens: 128,
        max_stop_token_ids: 4,
        max_spool_bytes: 1_048_576,
        max_encoded_result_frame: 262_144,
        max_encoded_quote_response: 1_048_576,
        dispatch_margin_blocks: 4,
        delivery_margin_blocks: 2,
        oracle_grace_blocks: 6,
        fixed_price: 10,
    }
}

fn payment_values() -> EdgeValues {
    EdgeValues::new(PAYMENT_VALUE, PAYMENT_RESERVE, Fees::new(0, 0, 0, 0))
}

fn config() -> WorkChannelConfig {
    WorkChannelConfig {
        network: network(),
        payment_edge: payment_edge(),
        payment_terms: payment_terms(),
        policy_salt: SALT,
        channel_policy: channel_policy(),
        execution_policy: execution_policy(),
        expected_payment_values: payment_values(),
        omission: measured(Q, COST_CAP),
    }
}

fn descriptor() -> WorkChannelDescriptor {
    match WorkChannelDescriptor::open(config()) {
        Ok(descriptor) => descriptor,
        Err(error) => panic!("the fixture channel opens: {error}"),
    }
}

// ── Canonical objects, spelled out ────────────────────────────────────

/// Kernel canonical tags. Written here rather than imported because the
/// point of writing the bytes out is that a reader agrees with a
/// *number*, not with a constant that could move with the encoder.
const FORMAT_VERSION: u8 = 1;
const TAG_BLOCK_HEIGHT: u8 = 1;
const TAG_FEES: u8 = 2;
const TAG_PARTIES: u8 = 3;
const TAG_EDGE: u8 = 5;
const TAG_PAYMENT_CLOSE_PENDING: u8 = 23;
const TAG_BOND_LEASE: u8 = 31;
/// `Freeze | Adjudicated`: close-kind tags 3 and 4.
const WORK_PAYMENT_CLOSES: u8 = 0b0001_1000;
/// `Timeout` alone: close-kind tag 1.
const WORK_STAKE_CLOSES: u8 = 0b0000_0010;

struct EdgeBytes {
    value: u64,
    reserve: u64,
    fees: [u64; 4],
    timeout: u64,
    maker: hellas_kernel::Key,
    taker: hellas_kernel::Key,
    terms: TermsHash,
    allowed: u8,
}

impl EdgeBytes {
    fn build(&self) -> Edge {
        let mut out = vec![FORMAT_VERSION, TAG_EDGE];
        out.extend_from_slice(&self.value.to_be_bytes());
        out.extend_from_slice(&self.reserve.to_be_bytes());
        out.extend_from_slice(&[FORMAT_VERSION, TAG_FEES]);
        for fee in self.fees {
            out.extend_from_slice(&fee.to_be_bytes());
        }
        out.extend_from_slice(&[FORMAT_VERSION, TAG_BLOCK_HEIGHT]);
        out.extend_from_slice(&self.timeout.to_be_bytes());
        out.extend_from_slice(&[FORMAT_VERSION, TAG_PARTIES]);
        out.extend_from_slice(&self.maker.to_bytes());
        out.extend_from_slice(&self.taker.to_bytes());
        out.extend_from_slice(self.terms.as_bytes());
        out.push(self.allowed);
        match Edge::decode_exact(&out) {
            Ok(edge) => edge,
            Err(error) => panic!("the hand-written edge is canonical: {error:?}"),
        }
    }
}

fn bond_object() -> Edge {
    EdgeBytes {
        value: STAKE,
        reserve: 0,
        fees: [0; 4],
        timeout: HORIZON,
        maker: provider_key(),
        taker: client_key(),
        terms: Terms::work_stake_bond(bond_terms()).hash(),
        allowed: WORK_STAKE_CLOSES,
    }
    .build()
}

fn payment_object() -> Edge {
    EdgeBytes {
        value: PAYMENT_VALUE,
        reserve: PAYMENT_RESERVE,
        fees: [0; 4],
        timeout: HORIZON,
        // Mirrored: the client funds the payment edge and is its maker.
        maker: client_key(),
        taker: provider_key(),
        terms: payment_terms_hash(payment_terms()),
        allowed: WORK_PAYMENT_CLOSES,
    }
    .build()
}

/// The canonical bytes of one bond lease, written out field by field.
fn lease_over(bond: EdgeId, payment: EdgeId) -> LeaseSlots {
    let mut value = vec![FORMAT_VERSION, TAG_BOND_LEASE];
    // body version
    value.push(2);
    value.extend_from_slice(&bond.to_bytes());
    value.extend_from_slice(&payment.to_bytes());
    value.extend_from_slice(payment_terms_hash(payment_terms()).as_bytes());
    value.extend_from_slice(&payment_terms().private_policy_commitment);
    value.extend_from_slice(&HORIZON.to_be_bytes());

    let slots = [0, 1].map(|index| {
        RegistryChunk::split(
            RegistryNamespace::BondLease,
            RegistryRecordTag::BondLease,
            &value,
            index,
        )
    });
    assert!(slots.iter().all(Option::is_some), "the lease splits");
    let parsed = hellas_kernel::parse_bond_lease(slots, bond);
    assert!(
        matches!(parsed, LeaseSlots::Present(_)),
        "the hand-written lease is readable, got {parsed:?}",
    );
    parsed
}

fn faulty_lease() -> LeaseSlots {
    let Some(chunk) = RegistryChunk::split(
        RegistryNamespace::BondLease,
        RegistryRecordTag::BondLease,
        &[0xff; 8],
        0,
    ) else {
        panic!("a short value splits into one chunk");
    };
    let parsed = hellas_kernel::parse_bond_lease([Some(chunk), Some(chunk)], bond_edge());
    assert!(matches!(parsed, LeaseSlots::Faulty(_)));
    parsed
}

/// The canonical bytes of one live contest, written out field by field.
///
/// Maker-opened, unresponded, at cumulative 5 with no penalty: the
/// values do not matter, its presence does.
fn live_pending() -> PendingSlot {
    let mut value = vec![FORMAT_VERSION, TAG_PAYMENT_CLOSE_PENDING];
    // body version
    value.push(2);
    value.extend_from_slice(&payment_edge().to_bytes());
    // opener_role: maker
    value.push(0);
    value.extend_from_slice(&[0x33; 32]); // start_id
    value.extend_from_slice(&77_u64.to_be_bytes()); // response_deadline
    value.extend_from_slice(&5_u64.to_be_bytes()); // start_cumulative
    value.extend_from_slice(&5_u64.to_be_bytes()); // final_cumulative
    value.push(0); // responded
    value.push(0); // penalty_due
    value.extend_from_slice(&2_u64.to_be_bytes()); // penalty_amount

    let Some(chunk) = RegistryChunk::split(
        RegistryNamespace::PaymentClose,
        RegistryRecordTag::PaymentPending,
        &value,
        0,
    ) else {
        panic!("a fixed-width value always splits");
    };
    let parsed = hellas_kernel::parse_pending_close(Some(chunk), payment_edge());
    assert!(
        matches!(parsed, PendingSlot::Present(_)),
        "the hand-written contest is readable, got {parsed:?}",
    );
    parsed
}

fn faulty_pending() -> PendingSlot {
    let Some(chunk) = RegistryChunk::split(
        RegistryNamespace::PaymentClose,
        RegistryRecordTag::PaymentPending,
        &[0xff; 8],
        0,
    ) else {
        panic!("a short value splits into one chunk");
    };
    let parsed = hellas_kernel::parse_pending_close(Some(chunk), payment_edge());
    assert!(matches!(parsed, PendingSlot::Faulty(_)));
    parsed
}

fn observed<'a>(bond: &'a Edge, payment: &'a Edge) -> ObservedChannel<'a> {
    ObservedChannel {
        height: HORIZON - 1,
        bond: Some(bond),
        payment: Some(payment),
        lease: lease_over(bond_edge(), payment_edge()),
        pending: PendingSlot::Absent,
    }
}

// ── Omission economics ────────────────────────────────────────────────

/// Every one of the four gates, at its limit and one unit past it, with
/// the other three held clear.
#[test]
fn omission_economics_hold_exactly_at_their_four_boundaries() {
    const M: u64 = OMISSION_PROBABILITY_SCALE;

    // `q` is a probability out of M. Zero and M+1 are not.
    assert_eq!(
        check_omission_economics(measured(0, 1), WINDOW, 10, 1),
        Err(OmissionError::ProbabilityOutOfRange { q: 0 }),
    );
    assert_eq!(
        check_omission_economics(measured(M + 1, 1), WINDOW, 10, 1),
        Err(OmissionError::ProbabilityOutOfRange { q: M + 1 }),
    );
    // Zero at zero capacity, where the third inequality is `0 > 0` and
    // refuses on its own. The `q = 0` arm is not what makes this safe;
    // it is what makes the refusal name the thing to change.
    assert_eq!(
        check_omission_economics(measured(0, 1), WINDOW, 10, 0),
        Err(OmissionError::ProbabilityOutOfRange { q: 0 }),
    );
    // q = 1 and q = M are both inside the range; whether they pass is
    // the third inequality's business, not the first's.
    assert_eq!(
        check_omission_economics(measured(M, 1), WINDOW, 10, u64::MAX),
        Ok(())
    );
    assert!(!matches!(
        check_omission_economics(measured(1, 1), WINDOW, 10, 1),
        Err(OmissionError::ProbabilityOutOfRange { .. }),
    ));

    // The window the terms admit must be at least the window `q` was
    // measured over. Equal passes, one block short does not, and longer
    // passes because more time to answer cannot make answering less
    // likely.
    assert_eq!(
        check_omission_economics(measured(M, 1), WINDOW - 1, 10, 0),
        Err(OmissionError::ResponseWindowUnderMeasured {
            window: WINDOW - 1,
            measured: WINDOW,
        }),
    );
    assert_eq!(
        check_omission_economics(measured(M, 1), WINDOW, 10, 0),
        Ok(())
    );
    assert_eq!(
        check_omission_economics(measured(M, 1), WINDOW + 1, 10, 0),
        Ok(())
    );

    // The bond must strictly exceed the measured response cost.
    assert_eq!(
        check_omission_economics(measured(M, 10), WINDOW, 10, 0),
        Err(OmissionError::BondBelowResponseCost { bond: 10, cap: 10 }),
    );
    assert_eq!(
        check_omission_economics(measured(M, 11), WINDOW, 10, 0),
        Err(OmissionError::BondBelowResponseCost { bond: 10, cap: 11 }),
    );
    assert_eq!(
        check_omission_economics(measured(M, 10), WINDOW, 11, 0),
        Ok(())
    );

    // `q*bond > (M-q)*capacity`, strictly. With q = M/2 the two sides
    // are equal at bond == capacity, so this walks that exact edge.
    let half = M / 2;
    assert_eq!(
        check_omission_economics(measured(half, 1), WINDOW, 1_000, 1_000),
        Err(OmissionError::OmissionNotLossMaking {
            responded: u128::from(half) * 1_000,
            omitted: u128::from(M - half) * 1_000,
        }),
    );
    assert_eq!(
        check_omission_economics(measured(half, 1), WINDOW, 1_001, 1_000),
        Ok(())
    );
    assert!(matches!(
        check_omission_economics(measured(half, 1), WINDOW, 1_000, 1_001),
        Err(OmissionError::OmissionNotLossMaking { .. }),
    ));

    // Both products at their widest. `u64 * u64` does not fit `u64`, so
    // a narrower multiplication here would wrap and call the worst case
    // safe.
    assert_eq!(
        check_omission_economics(measured(1, 0), WINDOW, u64::MAX, u64::MAX),
        Err(OmissionError::OmissionNotLossMaking {
            responded: u128::from(u64::MAX),
            omitted: u128::from(M - 1) * u128::from(u64::MAX),
        }),
    );
    assert_eq!(
        check_omission_economics(measured(M, u64::MAX - 1), WINDOW, u64::MAX, u64::MAX),
        Ok(()),
    );
}

/// The window gate is not decoration: a channel whose terms answer
/// faster than the provider measured itself answering does not open.
///
/// Only the measured window moves. The terms, the bond, the capacity,
/// and `q` are the fixture's, so what refuses this is the pairing of a
/// probability with a window it was not measured over.
#[test]
fn a_probability_measured_over_a_longer_window_does_not_open_a_shorter_channel() {
    let mut stale = config();
    stale.omission.response_blocks = WINDOW + 1;
    assert_eq!(
        WorkChannelDescriptor::open(stale),
        Err(WorkSetupError::Omission(
            OmissionError::ResponseWindowUnderMeasured {
                window: WINDOW,
                measured: WINDOW + 1,
            }
        )),
    );
    // The same configuration measured at the window the terms actually
    // admit opens, which is what says the refusal above was the window
    // and not something the mutation dragged along with it.
    assert!(WorkChannelDescriptor::open(config()).is_ok());
}

/// A channel whose configured funding does not clear the inequality is
/// refused at configuration time, before anything is signed.
#[test]
fn a_channel_whose_capacity_defeats_the_bond_does_not_open() {
    // Capacity is `value + reserve - omission_bond` at zero fees, so
    // moving `q` alone is what decides this: at this capacity the
    // provider would have to answer essentially always.
    let mut unlikely = config();
    unlikely.omission.response_probability = 1;
    assert!(matches!(
        WorkChannelDescriptor::open(unlikely),
        Err(WorkSetupError::Omission(
            OmissionError::OmissionNotLossMaking { .. }
        )),
    ));

    // A cost cap at the funded bond, and one below it.
    let mut at_cap = config();
    at_cap.omission.response_cost_cap = OMISSION_BOND;
    assert!(matches!(
        WorkChannelDescriptor::open(at_cap),
        Err(WorkSetupError::Omission(
            OmissionError::BondBelowResponseCost { .. }
        )),
    ));
    let mut under_cap = config();
    under_cap.omission.response_cost_cap = OMISSION_BOND - 1;
    assert!(WorkChannelDescriptor::open(under_cap).is_ok());
}

/// The policy body and its salt have to produce the commitment the
/// terms carry, and the execution policy has to be a usable profile.
#[test]
fn a_descriptor_opens_only_against_its_own_committed_policy() {
    let mut wrong_salt = config();
    wrong_salt.policy_salt = [0x5b; 32];
    assert_eq!(
        WorkChannelDescriptor::open(wrong_salt),
        Err(WorkSetupError::Record(PaidWorkError::Mismatch {
            field: "private_policy_commitment",
        })),
    );

    let mut wrong_policy = config();
    wrong_policy.channel_policy.compute_credit_limit += 1;
    assert_eq!(
        WorkChannelDescriptor::open(wrong_policy),
        Err(WorkSetupError::Record(PaidWorkError::Mismatch {
            field: "private_policy_commitment",
        })),
    );

    let mut zero_price = config();
    zero_price.execution_policy.fixed_price = 0;
    assert_eq!(
        WorkChannelDescriptor::open(zero_price),
        Err(WorkSetupError::Record(PaidWorkError::PolicyZero {
            field: "fixed_price",
        })),
    );

    // A reserve that does not price the dearer exit leaves nothing the
    // channel could bound a certificate by.
    let mut unfunded = config();
    unfunded.expected_payment_values = EdgeValues::new(1, 0, Fees::new(1_000, 0, 0, 0));
    assert_eq!(
        WorkChannelDescriptor::open(unfunded),
        Err(WorkSetupError::Unsettleable),
    );
}

// ── Readiness against a finalized read ────────────────────────────────

/// Every fact readiness rests on, each broken on its own.
#[test]
fn readiness_refuses_each_missing_fact_on_its_own() {
    let descriptor = descriptor();
    let bond = bond_object();
    let payment = payment_object();
    let good = observed(&bond, &payment);

    let ready = match descriptor.check_ready(&good) {
        Ok(ready) => ready,
        Err(error) => panic!("the fixture channel is ready: {error}"),
    };
    assert_eq!(ready.finalized_height(), HORIZON - 1);
    // Capacity is the funded edge's, not the configured expectation's.
    assert_eq!(
        ready.settlement().capacity(),
        PAYMENT_VALUE + PAYMENT_RESERVE - OMISSION_BOND,
    );
    assert_eq!(ready.channel().id(), descriptor.channel().id());

    let missing_bond = ObservedChannel { bond: None, ..good };
    assert_eq!(
        descriptor.check_ready(&missing_bond),
        Err(WorkSetupError::NotLive {
            object: "the bond edge",
        }),
    );
    let missing_payment = ObservedChannel {
        payment: None,
        ..good
    };
    assert_eq!(
        descriptor.check_ready(&missing_payment),
        Err(WorkSetupError::NotLive {
            object: "the payment edge",
        }),
    );

    // A live edge under other terms. Only the terms hash moves.
    let other_bond = EdgeBytes {
        value: STAKE,
        reserve: 0,
        fees: [0; 4],
        timeout: HORIZON,
        maker: provider_key(),
        taker: client_key(),
        terms: TermsHash::from_bytes([0x77; TermsHash::LENGTH]),
        allowed: WORK_STAKE_CLOSES,
    }
    .build();
    assert_eq!(
        descriptor.check_ready(&ObservedChannel {
            bond: Some(&other_bond),
            ..good
        }),
        Err(WorkSetupError::TermsMismatch {
            object: "the bond edge",
        }),
    );
    let other_payment = EdgeBytes {
        value: PAYMENT_VALUE,
        reserve: PAYMENT_RESERVE,
        fees: [0; 4],
        timeout: HORIZON,
        maker: client_key(),
        taker: provider_key(),
        terms: TermsHash::from_bytes([0x78; TermsHash::LENGTH]),
        allowed: WORK_PAYMENT_CLOSES,
    }
    .build();
    assert_eq!(
        descriptor.check_ready(&ObservedChannel {
            payment: Some(&other_payment),
            ..good
        }),
        Err(WorkSetupError::TermsMismatch {
            object: "the payment edge",
        }),
    );

    // The two edges, swapped. Each is live and each hashes to real
    // terms; neither is the object it was asked for.
    assert_eq!(
        descriptor.check_ready(&ObservedChannel {
            bond: Some(&payment),
            payment: Some(&bond),
            ..good
        }),
        Err(WorkSetupError::TermsMismatch {
            object: "the bond edge",
        }),
    );

    // Right terms, wrong parties. Only the party order moves.
    let swapped_bond = EdgeBytes {
        value: STAKE,
        reserve: 0,
        fees: [0; 4],
        timeout: HORIZON,
        maker: client_key(),
        taker: provider_key(),
        terms: Terms::work_stake_bond(bond_terms()).hash(),
        allowed: WORK_STAKE_CLOSES,
    }
    .build();
    assert_eq!(
        descriptor.check_ready(&ObservedChannel {
            bond: Some(&swapped_bond),
            ..good
        }),
        Err(WorkSetupError::PartiesMismatch {
            object: "the bond edge",
        }),
    );
    let swapped_payment = EdgeBytes {
        value: PAYMENT_VALUE,
        reserve: PAYMENT_RESERVE,
        fees: [0; 4],
        timeout: HORIZON,
        maker: provider_key(),
        taker: client_key(),
        terms: payment_terms_hash(payment_terms()),
        allowed: WORK_PAYMENT_CLOSES,
    }
    .build();
    assert_eq!(
        descriptor.check_ready(&ObservedChannel {
            payment: Some(&swapped_payment),
            ..good
        }),
        Err(WorkSetupError::PartiesMismatch {
            object: "the payment edge",
        }),
    );

    // The three lease answers that are not this channel's lease.
    assert_eq!(
        descriptor.check_ready(&ObservedChannel {
            lease: LeaseSlots::Absent,
            ..good
        }),
        Err(WorkSetupError::Lease {
            found: LeaseState::Absent,
        }),
    );
    assert_eq!(
        descriptor.check_ready(&ObservedChannel {
            lease: lease_over(bond_edge(), EdgeId::from_bytes([0x44; EdgeId::LENGTH])),
            ..good
        }),
        Err(WorkSetupError::Lease {
            found: LeaseState::AnotherChannel,
        }),
    );
    assert_eq!(
        descriptor.check_ready(&ObservedChannel {
            lease: faulty_lease(),
            ..good
        }),
        Err(WorkSetupError::Lease {
            found: LeaseState::Faulty,
        }),
    );

    // A contest, and a slot that cannot say whether there is one. Both
    // edges are live and healthy in each case; only the slot moves.
    assert_eq!(
        descriptor.check_ready(&ObservedChannel {
            pending: live_pending(),
            ..good
        }),
        Err(WorkSetupError::PendingClose {
            found: PendingState::Live,
        }),
    );
    assert_eq!(
        descriptor.check_ready(&ObservedChannel {
            pending: faulty_pending(),
            ..good
        }),
        Err(WorkSetupError::PendingClose {
            found: PendingState::Faulty,
        }),
    );

    // The horizon, exactly. One block earlier is admission.
    assert_eq!(
        descriptor.check_ready(&ObservedChannel {
            height: HORIZON,
            ..good
        }),
        Err(WorkSetupError::HorizonPassed {
            height: HORIZON,
            horizon: HORIZON,
        }),
    );
    assert!(
        descriptor
            .check_ready(&ObservedChannel {
                height: HORIZON - 1,
                ..good
            })
            .is_ok()
    );
}

/// A channel funded below what was configured has different economics
/// than the ones that were approved, so the inequality is re-run against
/// the edge that will actually pay.
#[test]
fn readiness_reprices_the_economics_against_the_funded_edge() {
    let descriptor = descriptor();
    let bond = bond_object();
    let payment = payment_object();
    let good = observed(&bond, &payment);

    // The configured expectation is unchanged and still passes; only
    // the funded value moves, and it moves capacity past what this
    // provider's measured availability can deter.
    let overfunded = EdgeBytes {
        value: u64::MAX / 2,
        reserve: PAYMENT_RESERVE,
        fees: [0; 4],
        timeout: HORIZON,
        maker: client_key(),
        taker: provider_key(),
        terms: payment_terms_hash(payment_terms()),
        allowed: WORK_PAYMENT_CLOSES,
    }
    .build();
    assert!(matches!(
        descriptor.check_ready(&ObservedChannel {
            payment: Some(&overfunded),
            ..good
        }),
        Err(WorkSetupError::Omission(
            OmissionError::OmissionNotLossMaking { .. }
        )),
    ));

    // A reserve that does not price the dearer exit.
    let starved = EdgeBytes {
        value: 1,
        reserve: 0,
        fees: [1_000, 0, 0, 0],
        timeout: HORIZON,
        maker: client_key(),
        taker: provider_key(),
        terms: payment_terms_hash(payment_terms()),
        allowed: WORK_PAYMENT_CLOSES,
    }
    .build();
    assert_eq!(
        descriptor.check_ready(&ObservedChannel {
            payment: Some(&starved),
            ..good
        }),
        Err(WorkSetupError::Unsettleable),
    );
}

// ── The per-signature gate ────────────────────────────────────────────

/// Readiness is decided at a height; signing is decided at a signature.
#[test]
fn signing_needs_a_caught_up_cursor_and_deadlines_the_margins_fit() {
    let descriptor = descriptor();
    let bond = bond_object();
    let payment = payment_object();
    let height = 100;
    let observed = ObservedChannel {
        height,
        ..observed(&bond, &payment)
    };
    let Ok(ready) = descriptor.check_ready(&observed) else {
        panic!("the fixture channel is ready");
    };

    let policy = execution_policy();
    let margins = policy.dispatch_margin_blocks + policy.delivery_margin_blocks;
    let terminal = height + margins;
    let payment_deadline = terminal + policy.oracle_grace_blocks;

    // Exactly at both bounds.
    assert_eq!(
        ready.check_signable(height, terminal, payment_deadline),
        Ok(())
    );

    // A cursor one block behind the snapshot the decision was read at.
    assert_eq!(
        ready.check_signable(height - 1, terminal, payment_deadline),
        Err(WorkSetupError::CursorBehind {
            cursor: height - 1,
            height,
        }),
    );
    // A cursor ahead of the snapshot is allowed, and the margins move
    // with it: the same job is signable one block later only against
    // deadlines one block later.
    assert_eq!(
        ready.check_signable(height + 1, terminal + 1, payment_deadline + 1),
        Ok(()),
    );

    // A terminal deadline one block inside the measured margins. It is
    // ordered, legal, and unreachable.
    assert_eq!(
        ready.check_signable(height, terminal - 1, payment_deadline),
        Err(WorkSetupError::TerminalUnreachable {
            height,
            dispatch: policy.dispatch_margin_blocks,
            delivery: policy.delivery_margin_blocks,
            terminal: terminal - 1,
        }),
    );

    // A payment deadline one block inside the measured oracle grace.
    assert_eq!(
        ready.check_signable(height, terminal, payment_deadline - 1),
        Err(WorkSetupError::OracleGraceTooShort {
            terminal,
            payment: payment_deadline - 1,
            actual: policy.oracle_grace_blocks - 1,
            grace: policy.oracle_grace_blocks,
        }),
    );

    // A payment deadline before the terminal one is not a short grace,
    // it is not an interval at all.
    assert_eq!(
        ready.check_signable(height, terminal, terminal - 1),
        Err(WorkSetupError::Record(PaidWorkError::Overflow {
            field: "oracle grace interval",
        })),
    );
}

/// Every bound is measured from the moment the signature is asked for,
/// not from the stale moment readiness was decided at.
///
/// Anchored at the readiness height, the whole interval `[H + margins,
/// C + margins)` passes — and that interval is exactly the deadlines
/// already missed by the time the chain has reached `C`. An honest
/// provider signs them, cannot deliver, and goes unpaid.
#[test]
fn signing_measures_the_margins_from_the_cursor_not_the_readiness_height() {
    let descriptor = descriptor();
    let bond = bond_object();
    let payment = payment_object();
    let height = 100;
    let Ok(ready) = descriptor.check_ready(&ObservedChannel {
        height,
        ..observed(&bond, &payment)
    }) else {
        panic!("the fixture channel is ready");
    };

    let policy = execution_policy();
    let margins = policy.dispatch_margin_blocks + policy.delivery_margin_blocks;
    let grace = policy.oracle_grace_blocks;

    // The deadline that is exactly reachable from the readiness height,
    // offered one block after that height. It is already lost.
    let cursor = height + 1;
    assert_eq!(
        ready.check_signable(cursor, height + margins, height + margins + grace),
        Err(WorkSetupError::TerminalUnreachable {
            height: cursor,
            dispatch: policy.dispatch_margin_blocks,
            delivery: policy.delivery_margin_blocks,
            terminal: height + margins,
        }),
    );

    // Not one block of that interval — all of it. Fifty blocks on, every
    // deadline the readiness height would have admitted is refused, and
    // the first one the cursor can actually reach is admitted.
    let far = height + 50;
    for terminal in (height + margins)..(far + margins) {
        assert!(
            ready
                .check_signable(far, terminal, terminal + grace)
                .is_err(),
            "terminal {terminal} is not reachable from height {far}",
        );
    }
    assert_eq!(
        ready.check_signable(far, far + margins, far + margins + grace),
        Ok(()),
    );

    // And the horizon. The readiness height is inside it forever, so
    // only the cursor can carry a channel past it — an endpoint that
    // never re-read its snapshot would otherwise sign new work for as
    // long as it stayed running.
    assert_eq!(
        ready.check_signable(HORIZON, HORIZON + margins, HORIZON + margins + grace),
        Err(WorkSetupError::HorizonPassed {
            height: HORIZON,
            horizon: HORIZON,
        }),
    );
    assert_eq!(
        ready.check_signable(
            HORIZON - 1,
            HORIZON - 1 + margins,
            HORIZON - 1 + margins + grace,
        ),
        Ok(()),
    );
}

#[test]
fn close_descriptor_round_trips_without_new_work_policy() {
    let armed = descriptor().close_descriptor();
    let bytes = armed.encode();
    assert_eq!(CloseDescriptor::decode(&bytes), Ok(armed.clone()));
    assert_eq!(
        armed
            .expected_settlement()
            .expect("the admitted expected funding settles")
            .capacity(),
        PAYMENT_VALUE + PAYMENT_RESERVE - OMISSION_BOND,
    );

    let funded = payment_object();
    assert_eq!(
        armed
            .funded_settlement(&funded)
            .expect("funded recovery uses the edge")
            .capacity(),
        PAYMENT_VALUE + PAYMENT_RESERVE - OMISSION_BOND,
    );

    let mut trailing = bytes;
    trailing.push(0);
    assert_eq!(
        CloseDescriptor::decode(&trailing),
        Err(WorkSetupError::DescriptorMalformed),
    );
}
