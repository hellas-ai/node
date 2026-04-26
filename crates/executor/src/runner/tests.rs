//! Tests for [`super::decode`].
//!
//! See [`fake`] for the in-memory [`CausalStepper`] implementation that
//! replaces real catgrad model execution. The fake satisfies the safe
//! causal contract by construction (its predictor is a pure function of the
//! complete transcript so far), so it is the right shape to exercise
//! `decode`'s control flow without dragging in tensor compute.

use super::{DecodeOutcome, DecodePlan, decode};
use catgrad_llm::runtime::{CausalStepper, TextStepOutput};
use hellas_rpc::ExecutorError;
use std::cell::RefCell;
use std::rc::Rc;

mod fake {
    //! Deterministic in-memory `CausalStepper` for tests.
    //!
    //! The predictor is `blake3(transcript_so_far)` cast to `u32`. Because
    //! the predictor depends only on the *complete* transcript at each
    //! step, the contract holds by construction:
    //!
    //!     prefill_from_empty(P ++ S)
    //!         == prefill_from_empty(P) ; advance_one(s_i) for each s_i in S
    //!
    //! both as predicted-token sequences and as final transcript state.
    //! That means tests can compare two decode runs that arrive at the same
    //! transcript via different cache paths and assert identical outputs.

    use super::*;

    /// One observed call into the stepper. Tests assert against ordered
    /// sequences of these to verify decode picked the right path.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub(super) enum FakeCall {
        Prefill(Vec<u32>),
        Advance(u32),
        IntoSnapshot,
    }

    /// Snapshot is just the transcript. Resuming a stepper from a snapshot
    /// is constructing a new `FakeStepper` with the same transcript.
    #[derive(Clone, Debug)]
    pub(super) struct FakeSnapshot {
        pub(super) transcript: Vec<u32>,
    }

    pub(super) struct FakeStepper {
        transcript: Vec<u32>,
        calls: Rc<RefCell<Vec<FakeCall>>>,
    }

    impl FakeStepper {
        pub(super) fn empty(calls: Rc<RefCell<Vec<FakeCall>>>) -> Self {
            Self {
                transcript: Vec::new(),
                calls,
            }
        }

        pub(super) fn from_snapshot(
            snapshot: FakeSnapshot,
            calls: Rc<RefCell<Vec<FakeCall>>>,
        ) -> Self {
            Self {
                transcript: snapshot.transcript,
                calls,
            }
        }

        fn predict(&self) -> u32 {
            predict_from_transcript(&self.transcript)
        }
    }

    /// Public so tests can pre-compute expected predictions.
    pub(super) fn predict_from_transcript(transcript: &[u32]) -> u32 {
        let mut hasher = blake3::Hasher::new();
        for &token in transcript {
            hasher.update(&token.to_le_bytes());
        }
        let digest = hasher.finalize();
        let bytes = digest.as_bytes();
        u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
    }

    impl CausalStepper for FakeStepper {
        type Snapshot = FakeSnapshot;

        fn position(&self) -> usize {
            self.transcript.len()
        }

        fn prefill_from_empty(
            &mut self,
            tokens: &[u32],
        ) -> catgrad_llm::Result<TextStepOutput> {
            assert_eq!(self.transcript.len(), 0, "prefill_from_empty on non-empty");
            assert!(!tokens.is_empty(), "prefill_from_empty with empty input");
            self.calls
                .borrow_mut()
                .push(FakeCall::Prefill(tokens.to_vec()));
            self.transcript.extend_from_slice(tokens);
            Ok(TextStepOutput::NextToken(self.predict()))
        }

        fn advance_one(&mut self, token: u32) -> catgrad_llm::Result<TextStepOutput> {
            assert!(!self.transcript.is_empty(), "advance_one on empty");
            self.calls.borrow_mut().push(FakeCall::Advance(token));
            self.transcript.push(token);
            Ok(TextStepOutput::NextToken(self.predict()))
        }

        fn into_snapshot(self) -> Self::Snapshot {
            self.calls.borrow_mut().push(FakeCall::IntoSnapshot);
            FakeSnapshot {
                transcript: self.transcript,
            }
        }
    }
}

use fake::{FakeCall, FakeSnapshot, FakeStepper, predict_from_transcript};

/// Convenience: collect `(generated_tokens_so_far, decoded_chunk_as_u32_le)` per
/// progress callback invocation, for assertion.
type ProgressLog = Vec<(u64, Vec<u32>)>;

fn decode_chunks(bytes: &[u8]) -> Vec<u32> {
    bytes
        .chunks_exact(4)
        .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect()
}

/// Run `decode` with a fresh empty fake stepper. Returns the call log,
/// progress log, first-token-fired flag, and the outcome.
fn run_from_empty(
    plan: DecodePlan<'_>,
) -> (
    Vec<FakeCall>,
    ProgressLog,
    bool,
    Result<DecodeOutcome<FakeSnapshot>, ExecutorError>,
) {
    let calls = Rc::new(RefCell::new(Vec::new()));
    let progress: Rc<RefCell<ProgressLog>> = Rc::new(RefCell::new(Vec::new()));
    let first = Rc::new(RefCell::new(false));

    let stepper = FakeStepper::empty(calls.clone());
    let outcome = {
        let progress = progress.clone();
        let first = first.clone();
        decode(
            stepper,
            plan,
            move || *first.borrow_mut() = true,
            move |emitted, chunk| progress.borrow_mut().push((emitted, decode_chunks(chunk))),
        )
    };

    (
        Rc::try_unwrap(calls).unwrap().into_inner(),
        Rc::try_unwrap(progress).unwrap().into_inner(),
        Rc::try_unwrap(first).unwrap().into_inner(),
        outcome,
    )
}

/// Run `decode` resuming from a `FakeSnapshot`. The snapshot's transcript
/// is used to seed the stepper; the plan must reflect a `cached_prefix_len`
/// equal to that transcript length.
fn run_from_snapshot(
    snapshot: FakeSnapshot,
    plan: DecodePlan<'_>,
) -> (
    Vec<FakeCall>,
    ProgressLog,
    bool,
    Result<DecodeOutcome<FakeSnapshot>, ExecutorError>,
) {
    let calls = Rc::new(RefCell::new(Vec::new()));
    let progress: Rc<RefCell<ProgressLog>> = Rc::new(RefCell::new(Vec::new()));
    let first = Rc::new(RefCell::new(false));

    let stepper = FakeStepper::from_snapshot(snapshot, calls.clone());
    let outcome = {
        let progress = progress.clone();
        let first = first.clone();
        decode(
            stepper,
            plan,
            move || *first.borrow_mut() = true,
            move |emitted, chunk| progress.borrow_mut().push((emitted, decode_chunks(chunk))),
        )
    };

    (
        Rc::try_unwrap(calls).unwrap().into_inner(),
        Rc::try_unwrap(progress).unwrap().into_inner(),
        Rc::try_unwrap(first).unwrap().into_inner(),
        outcome,
    )
}

// ---------------------------------------------------------------------------
// Path-selection unit tests
// ---------------------------------------------------------------------------

#[test]
fn full_prefix_hit_skips_model_and_uses_cached_next_token() {
    let prompt = vec![1, 2, 3, 4, 5];
    let cached_next = 0xCAFE_BABE_u32;
    let (calls, progress, first_fired, outcome) = run_from_snapshot(
        FakeSnapshot {
            transcript: prompt.clone(),
        },
        DecodePlan {
            input_ids: &prompt,
            cached_prefix_len: prompt.len(),
            cached_next_token: Some(cached_next),
            max_new_tokens: 1,
            stop_token_ids: &[],
            batch_size: 1,
        },
    );
    let outcome = outcome.unwrap();

    // Decode emits the cached next token, then attempts to align the
    // session for the snapshot via one extra advance_one — that's the only
    // model call. No prefill, no decode-loop advance_one.
    assert_eq!(
        calls,
        vec![FakeCall::Advance(cached_next), FakeCall::IntoSnapshot]
    );
    assert!(first_fired);
    assert_eq!(outcome.output_tokens, vec![cached_next]);
    assert_eq!(progress, vec![(1, vec![cached_next])]);
    assert!(outcome.final_snapshot.is_some());
}

#[test]
fn empty_session_runs_one_bulk_prefill() {
    let prompt = vec![10, 20, 30, 40];
    let expected_first = predict_from_transcript(&prompt);
    let (calls, progress, first_fired, outcome) = run_from_empty(DecodePlan {
        input_ids: &prompt,
        cached_prefix_len: 0,
        cached_next_token: None,
        max_new_tokens: 1,
        stop_token_ids: &[],
        batch_size: 1,
    });
    let outcome = outcome.unwrap();

    assert_eq!(
        calls,
        vec![
            FakeCall::Prefill(prompt.clone()),
            FakeCall::Advance(expected_first),
            FakeCall::IntoSnapshot,
        ]
    );
    assert!(first_fired);
    assert_eq!(outcome.output_tokens, vec![expected_first]);
    assert_eq!(progress, vec![(1, vec![expected_first])]);
}

#[test]
fn partial_prefix_teacher_forces_each_suffix_token() {
    let prompt = vec![1, 2, 3, 4, 5, 6, 7, 8];
    let split = 3;
    let suffix = &prompt[split..];

    let (calls, _progress, first_fired, outcome) = run_from_snapshot(
        FakeSnapshot {
            transcript: prompt[..split].to_vec(),
        },
        DecodePlan {
            input_ids: &prompt,
            cached_prefix_len: split,
            cached_next_token: None,
            max_new_tokens: 1,
            stop_token_ids: &[],
            batch_size: 1,
        },
    );
    let outcome = outcome.unwrap();

    let mut expected_calls: Vec<FakeCall> = suffix.iter().map(|&t| FakeCall::Advance(t)).collect();
    expected_calls.push(FakeCall::Advance(predict_from_transcript(&prompt)));
    expected_calls.push(FakeCall::IntoSnapshot);
    assert_eq!(calls, expected_calls);
    assert!(first_fired);
    assert_eq!(outcome.output_tokens, vec![predict_from_transcript(&prompt)]);
}

#[test]
fn stop_token_mid_decode_skips_final_snapshot() {
    // Engineer a stop: the predictor is deterministic, so find a prompt
    // whose predicted next token is in i32 range (the runner's stop check
    // skips u32 values that don't fit in i32) and use that prediction as
    // the stop set.
    let (prompt, first_pred) = (1u32..1000)
        .map(|seed| {
            let prompt = vec![seed, seed + 1, seed + 2];
            let pred = predict_from_transcript(&prompt);
            (prompt, pred)
        })
        .find(|(_, pred)| i32::try_from(*pred).is_ok())
        .expect("expected to find an i32-fitting prediction in 1000 tries");
    let stop_tokens = [first_pred as i32];

    let (calls, progress, _first, outcome) = run_from_empty(DecodePlan {
        input_ids: &prompt,
        cached_prefix_len: 0,
        cached_next_token: None,
        max_new_tokens: 16,
        stop_token_ids: &stop_tokens,
        batch_size: 1,
    });
    let outcome = outcome.unwrap();

    // Prefill ran, returned the (now-stop) predicted token — decode loop
    // saw it as a stop and exited before emitting anything. No final
    // snapshot because the session would be one step behind the transcript.
    assert_eq!(calls, vec![FakeCall::Prefill(prompt.clone())]);
    assert!(outcome.output_tokens.is_empty());
    assert!(progress.is_empty());
    assert!(outcome.final_snapshot.is_none());
}

#[test]
fn max_new_tokens_zero_emits_nothing_and_no_snapshot() {
    let prompt = vec![1, 2, 3];
    let (calls, progress, first_fired, outcome) = run_from_empty(DecodePlan {
        input_ids: &prompt,
        cached_prefix_len: 0,
        cached_next_token: None,
        max_new_tokens: 0,
        stop_token_ids: &[],
        batch_size: 1,
    });
    let outcome = outcome.unwrap();

    // Prefill still runs (we always need the next-token at prompt end), but
    // no decode iterations happen, so no advance_one and no snapshot.
    assert_eq!(calls, vec![FakeCall::Prefill(prompt)]);
    assert!(first_fired);
    assert!(outcome.output_tokens.is_empty());
    assert!(progress.is_empty());
    assert!(outcome.final_snapshot.is_none());
}

#[test]
fn batch_size_groups_progress_chunks() {
    let prompt = vec![1, 2, 3];
    let (_calls, progress, _first, outcome) = run_from_empty(DecodePlan {
        input_ids: &prompt,
        cached_prefix_len: 0,
        cached_next_token: None,
        max_new_tokens: 5,
        stop_token_ids: &[],
        batch_size: 2,
    });
    let outcome = outcome.unwrap();

    // 5 tokens emitted in batches of 2 → chunks of sizes [2, 2, 1].
    assert_eq!(outcome.output_tokens.len(), 5);
    let chunk_sizes: Vec<usize> = progress.iter().map(|(_, chunk)| chunk.len()).collect();
    assert_eq!(chunk_sizes, vec![2, 2, 1]);
    let cumulative: Vec<u64> = progress.iter().map(|(g, _)| *g).collect();
    assert_eq!(cumulative, vec![2, 4, 5]);
}

#[test]
fn full_run_caps_at_max_new_tokens_and_yields_snapshot() {
    let prompt = vec![1, 2];
    let (calls, _progress, _first, outcome) = run_from_empty(DecodePlan {
        input_ids: &prompt,
        cached_prefix_len: 0,
        cached_next_token: None,
        max_new_tokens: 4,
        stop_token_ids: &[],
        batch_size: 1,
    });
    let outcome = outcome.unwrap();

    // 1 prefill, 3 advance_one in decode loop, 1 advance_one for final
    // snapshot alignment, 1 into_snapshot.
    let prefills = calls
        .iter()
        .filter(|c| matches!(c, FakeCall::Prefill(_)))
        .count();
    let advances = calls
        .iter()
        .filter(|c| matches!(c, FakeCall::Advance(_)))
        .count();
    let snapshots = calls
        .iter()
        .filter(|c| matches!(c, FakeCall::IntoSnapshot))
        .count();
    assert_eq!(prefills, 1);
    assert_eq!(advances, 4);
    assert_eq!(snapshots, 1);
    assert_eq!(outcome.output_tokens.len(), 4);
    assert!(outcome.final_snapshot.is_some());
}

// ---------------------------------------------------------------------------
// Split-stability proptest
// ---------------------------------------------------------------------------

mod prop {
    use super::*;
    use proptest::prelude::*;

    // Property: for any prompt and split point, decoding from an empty
    // session and decoding from a snapshot at the split point produce
    // identical emitted output tokens.
    //
    // The fake stepper satisfies the split-stability contract by
    // construction. This proptest verifies that `decode` does not break
    // determinism through its cache-state branching: regardless of which
    // path it takes (full bulk prefill vs. teacher-forced suffix replay),
    // the visible output tokens are the same.
    //
    // The second proptest covers the full-prefix-hit path separately,
    // since it's structurally distinct (no model calls in the prefill
    // phase) and worth independent coverage.
    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 256,
            ..ProptestConfig::default()
        })]

        #[test]
        fn split_stable_outputs(
            prompt in proptest::collection::vec(any::<u32>(), 1..32),
            split_ratio in 0_usize..=100,
            max_new in 0u32..16,
            stop_count in 0_usize..3,
            stop_seed in any::<u64>(),
        ) {
            let split = (prompt.len() * split_ratio) / 100;
            // Pick stop tokens deterministically so both runs use the same set.
            let mut stops = Vec::new();
            let mut s = stop_seed;
            for _ in 0..stop_count {
                s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                stops.push((s as u32) as i32);
            }
            let stops_slice = &stops[..];

            // When the split lands at the end of the prompt the caller
            // must ship the predicted next token alongside the snapshot;
            // that's the runner-cache contract. Path A always starts
            // fresh, so its cached_next_token is None.
            let cached_next_b = (split == prompt.len())
                .then(|| predict_from_transcript(&prompt));

            let (_, progress_a, _, outcome_a) = run_from_empty(DecodePlan {
                input_ids: &prompt,
                cached_prefix_len: 0,
                cached_next_token: None,
                max_new_tokens: max_new,
                stop_token_ids: stops_slice,
                batch_size: 1,
            });

            let (_, progress_b, _, outcome_b) = run_from_snapshot(
                FakeSnapshot { transcript: prompt[..split].to_vec() },
                DecodePlan {
                    input_ids: &prompt,
                    cached_prefix_len: split,
                    cached_next_token: cached_next_b,
                    max_new_tokens: max_new,
                    stop_token_ids: stops_slice,
                    batch_size: 1,
                },
            );

            let outcome_a = outcome_a.unwrap();
            let outcome_b = outcome_b.unwrap();
            prop_assert_eq!(&outcome_a.output_tokens, &outcome_b.output_tokens);
            prop_assert_eq!(progress_a, progress_b);
            prop_assert_eq!(
                outcome_a.final_snapshot.is_some(),
                outcome_b.final_snapshot.is_some()
            );
        }

        #[test]
        fn full_prefix_hit_matches_fresh_run(
            prompt in proptest::collection::vec(any::<u32>(), 1..32),
            max_new in 1u32..16,
        ) {
            let cached_next = predict_from_transcript(&prompt);

            let (_, progress_a, _, outcome_a) = run_from_empty(DecodePlan {
                input_ids: &prompt,
                cached_prefix_len: 0,
                cached_next_token: None,
                max_new_tokens: max_new,
                stop_token_ids: &[],
                batch_size: 1,
            });

            let (_, progress_b, _, outcome_b) = run_from_snapshot(
                FakeSnapshot { transcript: prompt.clone() },
                DecodePlan {
                    input_ids: &prompt,
                    cached_prefix_len: prompt.len(),
                    cached_next_token: Some(cached_next),
                    max_new_tokens: max_new,
                    stop_token_ids: &[],
                    batch_size: 1,
                },
            );

            let outcome_a = outcome_a.unwrap();
            let outcome_b = outcome_b.unwrap();
            prop_assert_eq!(&outcome_a.output_tokens, &outcome_b.output_tokens);
            prop_assert_eq!(progress_a, progress_b);
        }
    }
}
