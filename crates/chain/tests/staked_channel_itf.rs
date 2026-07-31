#![cfg(feature = "domain")]
#![allow(clippy::enum_variant_names)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

//! ITF replay of `models/staked_channel.qnt` against the real
//! [`Channel`].
//!
//! The abstract model records, for every step, the exact outcome the
//! Rust must produce — not merely "accepted" or "rejected". The runner
//! asserts the precise `AdmitError` / `SettleError` variant, so a
//! regression that refuses the right jobs for the *wrong reason* is
//! caught rather than silently tolerated.
//!
//! Every field of the schema below is read by the runner. A field that
//! is deserialized and never asserted is not a correspondence, it is
//! decoration.

use std::fs;
use std::path::PathBuf;

use hellas_chain::staked::{
    AdmitError, Channel, JobAcceptanceContext, MakerVoucher, STAKE_BOND_PROTOCOL, SettleError,
    payment_terms,
};
use hellas_kernel::{
    BlockHeight, EdgeId, List, MAX_EDGE_OUTPUTS, Parties, Payout, Secp256k1Signer, StakeBondTerms,
    Terms,
};
use itf::Runner as ItfRunner;
use itf::de::{As, Integer};
use serde::Deserialize;

// -- fixture (mirrors models/staked_channel.qnt's committed pairing) --

const CAPACITY: u64 = 2_000;
const MAX_JOB_PRICE: u64 = 500;
const BOND_TIMEOUT: u64 = 200;
const PAYMENT_TIMEOUT: u64 = 150;
const CLOSE_MARGIN: u64 = 5;
const CHALLENGE_MARGIN: u64 = 20;

fn signer(seed: u8) -> Secp256k1Signer {
    Secp256k1Signer::from_secret_scalar([seed; 32]).expect("non-zero scalar")
}

fn client() -> Secp256k1Signer {
    signer(2)
}

fn provider() -> Secp256k1Signer {
    signer(1)
}

fn bond_terms() -> Terms {
    let provider = provider().party_key();
    let mut outputs = [Payout::default(); MAX_EDGE_OUTPUTS];
    outputs[0] = Payout::new(provider, 1_000);
    Terms::stake_bond(StakeBondTerms {
        protocol: STAKE_BOND_PROTOCOL,
        parties: Parties::new(provider, client().party_key()),
        timeout: BlockHeight::new(BOND_TIMEOUT),
        timeout_outputs: List::take(outputs, 1),
        treasury: signer(3).party_key(),
        award: 700,
        stake: 1_000,
        max_job_price: MAX_JOB_PRICE,
        max_dispute_cost: 200,
        challenge_margin: CHALLENGE_MARGIN,
    })
}

fn payment() -> Terms {
    payment_terms(
        client().party_key(),
        provider().party_key(),
        BlockHeight::new(PAYMENT_TIMEOUT),
        CAPACITY,
    )
}

fn payment_edge() -> EdgeId {
    EdgeId::from_bytes([2; 32])
}

fn fresh_channel() -> Channel {
    Channel::new(
        EdgeId::from_bytes([1; 32]),
        bond_terms(),
        payment_edge(),
        payment(),
        CLOSE_MARGIN,
    )
    .expect("the fixture pairing is well formed")
}

// -- schema (field order mirrors the model's state vars) --------------

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct State {
    active_job: bool,
    #[serde(with = "As::<Integer>")]
    active_price: i64,
    #[serde(with = "As::<Integer>")]
    cumulative: i64,
    #[serde(with = "As::<Integer>")]
    height: i64,
    last_admit: AdmitOutcome,
    last_input: Input,
    last_settle: SettleOutcome,
    #[serde(with = "As::<Integer>")]
    sequence: i64,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize)]
#[serde(tag = "tag", content = "value")]
enum JobShape {
    Ordinary,
    Cheap,
    PriceZero,
    PriceAboveCap,
    DeadlineStale,
    DeadlinePastBond,
    DeadlinePastRedeem,
    Foreign,
    SkippedSequence,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize)]
#[serde(tag = "tag", content = "value")]
enum AdmitOutcome {
    Admitted,
    Busy,
    ForeignJob,
    OutOfSequence,
    DeadlinePassed,
    Uncovered,
    RedemptionMarginExceeded,
    InsufficientCapacity,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize)]
#[serde(tag = "tag", content = "value")]
enum SettleOutcome {
    Settled,
    NoActiveJob,
    TooLateToRedeem,
    WrongFrontier,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize)]
#[serde(tag = "tag", content = "value")]
enum Input {
    NoInput,
    AdmitInput(JobShape),
    RescindInput,
    SettleInput(#[serde(with = "As::<Integer>")] i64),
    TickInput,
}

/// The concrete `AdmitError` each abstract outcome must correspond to.
fn expected_admit(outcome: AdmitOutcome) -> Option<AdmitError> {
    match outcome {
        AdmitOutcome::Admitted => None,
        AdmitOutcome::Busy => Some(AdmitError::Busy),
        AdmitOutcome::ForeignJob => Some(AdmitError::ForeignJob),
        AdmitOutcome::OutOfSequence => Some(AdmitError::OutOfSequence),
        AdmitOutcome::DeadlinePassed => Some(AdmitError::DeadlinePassed),
        AdmitOutcome::Uncovered => Some(AdmitError::Uncovered),
        AdmitOutcome::RedemptionMarginExceeded => Some(AdmitError::RedemptionMarginExceeded),
        AdmitOutcome::InsufficientCapacity => Some(AdmitError::InsufficientCapacity),
    }
}

fn expected_settle(outcome: SettleOutcome) -> Option<SettleError> {
    match outcome {
        SettleOutcome::Settled => None,
        SettleOutcome::NoActiveJob => Some(SettleError::NoActiveJob),
        SettleOutcome::TooLateToRedeem => Some(SettleError::TooLateToRedeem),
        SettleOutcome::WrongFrontier => Some(SettleError::WrongFrontier),
    }
}

/// Builds the concrete job the abstract shape names, from the channel's
/// own next-sequence context, then perturbs exactly the one field the
/// shape is about.
fn job_for(channel: &Channel, shape: JobShape) -> JobAcceptanceContext {
    let (price, deadline) = match shape {
        JobShape::Cheap => (1, 60),
        JobShape::PriceZero => (0, 60),
        JobShape::PriceAboveCap => (MAX_JOB_PRICE + 1, 60),
        JobShape::DeadlineStale => (400, 10),
        JobShape::DeadlinePastBond => (400, 180),
        JobShape::DeadlinePastRedeem => (400, 145),
        JobShape::Ordinary | JobShape::Foreign | JobShape::SkippedSequence => (400, 60),
    };
    let base = channel.job([7; 32], [8; 32], price, BlockHeight::new(deadline));
    match shape {
        JobShape::Foreign => JobAcceptanceContext {
            bond_edge: EdgeId::from_bytes([9; 32]),
            ..base
        },
        JobShape::SkippedSequence => JobAcceptanceContext {
            sequence: base.sequence + 4,
            ..base
        },
        _ => base,
    }
}

struct ChannelRunner;

impl ItfRunner for ChannelRunner {
    type ActualState = Channel;
    type ExpectedState = State;
    type Result = ();
    type Error = String;

    fn init(&mut self, _expected: &Self::ExpectedState) -> Result<Self::ActualState, Self::Error> {
        Ok(fresh_channel())
    }

    fn step(
        &mut self,
        actual: &mut Self::ActualState,
        expected: &Self::ExpectedState,
    ) -> Result<Self::Result, Self::Error> {
        let now = BlockHeight::new(u64::try_from(expected.height).map_err(|_| "negative height")?);
        match expected.last_input {
            Input::NoInput | Input::TickInput => Ok(()),
            Input::RescindInput => {
                actual.rescind();
                Ok(())
            }
            Input::AdmitInput(shape) => {
                let job = job_for(actual, shape);
                let got = actual.admit(now, job).err();
                let want = expected_admit(expected.last_admit);
                if got != want {
                    return Err(format!(
                        "admit {shape:?}: model expects {want:?}, Channel returned {got:?}",
                    ));
                }
                Ok(())
            }
            Input::SettleInput(frontier) => {
                let frontier = u64::try_from(frontier).map_err(|_| "negative frontier")?;
                // The voucher the client would have issued for this
                // frontier. Built directly so the model can explore a
                // frontier that does not advance by the job's price.
                let voucher = MakerVoucher::issue(
                    &client(),
                    provider().party_key(),
                    payment_edge(),
                    payment().hash(),
                    CAPACITY,
                    frontier,
                )
                .ok_or_else(|| format!("frontier {frontier} is unissuable"))?;
                let got = actual.settle(now, voucher).err();
                let want = expected_settle(expected.last_settle);
                if got != want {
                    return Err(format!(
                        "settle {frontier}: model expects {want:?}, Channel returned {got:?}",
                    ));
                }
                Ok(())
            }
        }
    }

    fn result_invariant(
        &self,
        _result: &Self::Result,
        _expected: &Self::ExpectedState,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }

    /// Every observable of the model is compared against the real
    /// channel: the frontier, the sequence, the lock, and the in-flight
    /// job's price.
    fn state_invariant(
        &self,
        actual: &Self::ActualState,
        expected: &Self::ExpectedState,
    ) -> Result<bool, Self::Error> {
        let want_cumulative =
            u64::try_from(expected.cumulative).map_err(|_| "negative cumulative")?;
        if actual.cumulative() != want_cumulative {
            return Err(format!(
                "frontier: Channel {}, model {want_cumulative}",
                actual.cumulative(),
            ));
        }
        let want_sequence = u64::try_from(expected.sequence).map_err(|_| "negative sequence")?;
        if actual.sequence() != want_sequence {
            return Err(format!(
                "sequence: Channel {}, model {want_sequence}",
                actual.sequence(),
            ));
        }
        match (actual.active(), expected.active_job) {
            (Some(job), true) => {
                let want_price =
                    u64::try_from(expected.active_price).map_err(|_| "negative price")?;
                if job.price != want_price {
                    return Err(format!(
                        "in-flight price: Channel {}, model {want_price}",
                        job.price,
                    ));
                }
            }
            (None, false) => {
                if expected.active_price != 0 {
                    return Err("model has no active job but a non-zero price".to_string());
                }
            }
            (job, model_active) => {
                return Err(format!(
                    "lock: Channel active={}, model active={model_active}",
                    job.is_some(),
                ));
            }
        }
        Ok(true)
    }
}

fn fixtures() -> Vec<(PathBuf, String)> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("models")
        .join("traces");
    let mut entries: Vec<_> = fs::read_dir(&dir)
        .unwrap_or_else(|err| panic!("cannot read {}: {err}", dir.display()))
        .filter_map(Result::ok)
        .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "json"))
        .map(|entry| {
            let path = entry.path();
            let json = fs::read_to_string(&path).expect("fixture readable");
            (path, json)
        })
        .collect();
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    entries
}

#[test]
fn replays_staked_channel_fixtures() {
    let fixtures = fixtures();
    assert!(!fixtures.is_empty(), "no staked_channel ITF fixtures found");
    for (path, json) in fixtures {
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        assert!(
            name.starts_with("staked_channel_"),
            "unrecognized fixture prefix: {name}",
        );
        let trace: itf::Trace<State> = itf::trace_from_str(&json)
            .unwrap_or_else(|err| panic!("invalid ITF fixture {name}: {err}"));
        trace
            .run_on(ChannelRunner)
            .unwrap_or_else(|err| panic!("fixture {name} replay failed: {err:?}"));
    }
}

/// The model's committed pairing must be the one the Rust fixture
/// builds — otherwise the replay would be checking a different channel
/// than the model describes.
#[test]
fn fixture_matches_the_modelled_pairing() {
    let channel = fresh_channel();
    let policy = channel.bond_policy();
    assert_eq!(channel.capacity(), CAPACITY);
    assert_eq!(policy.max_job_price, MAX_JOB_PRICE);
    assert_eq!(policy.challenge_margin, CHALLENGE_MARGIN);
    assert_eq!(policy.timeout.get(), BOND_TIMEOUT);
}
