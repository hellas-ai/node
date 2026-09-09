//! §4-B: the two waits, the blocks they cost, and the evidence a number
//! has to have before it may call itself measured.
//!
//! # What is arithmetic here and what is judgement
//!
//! Everything below is arithmetic over numbers somebody else observed.
//! [`MountBudget`] is the observations, reduced to the one number each
//! §4 term contributes; [`MountFloor`] is §4's two waits and the four
//! block counts they imply, computed once and then only read. Nothing
//! here reads a clock, dials anything, or decides what to sample — the
//! probe does that, and hands the result in.
//!
//! ```text
//! Wresp  = 3×fsync_tail_ms + rotation_tail_ms + response_build_ms
//!          + one_block_fetch_ms + max6(rpc_ms + response_worker_ms + validation_ms)
//! S      = ceil(Wresp / lower_tail_block_ms)
//! Wstart = fresh_tip_ms + close_prepared_fsync_ms + rotation_tail_ms
//!          + max6(rpc_ms + general_worker_ms + validation_ms)
//! Sg     = ceil(Wstart / lower_tail_block_ms)
//! R      = ceil((restart_downtime_ms + restart_replay_ms_at_cap) / lower_tail_block_ms)
//! T      = F + G + Ig + Sg + R + 1
//! ```
//!
//! and the three requirements they exist for: `omit_response_blocks ≥
//! F+POLL+G+I+S+R+1`, an alarm margin of `F+G+I+S+R+1`, and `64 ≥ T`.
//!
//! # `max6` is the reader's arithmetic
//!
//! §4 maximises the validator-side addend over six validators. This tree
//! dials one — `serve`'s clock reads and submits through the first
//! validator that answers — so the maximum over six is the maximum over
//! the samples a run actually has, and [`max6`] says so rather than
//! pretending to six. Each addend enters as the largest sample of *that*
//! term, and the three are then summed: `rpc_ms` already contains
//! `response_worker_ms` and `validation_ms` as overlapping intervals, so
//! the sum over-counts. That is deliberate and is not corrected here —
//! over-counting a wait makes the floor larger, which is the direction a
//! fail-closed floor is allowed to be wrong in.
//!
//! # Milliseconds, whole ones
//!
//! Every term is a whole millisecond, rounded up from what the seam
//! observed. The rounding is the same safe direction: a wait rounded up
//! costs blocks, and blocks are what the floor is denominated in. Whole
//! numbers also mean `ceil` division is exact, so a hand-checked example
//! and the code agree to the digit.
//!
//! # The grading
//!
//! [`clopper_pearson_upper_ppb`] is the one-sided 95% Clopper–Pearson
//! upper bound on the *miss* rate, computed from the binomial tail this
//! module evaluates itself. No statistics dependency: the bound is the
//! `p` at which the chance of seeing this few misses falls to 5%, the
//! binomial tail is monotone in `p`, and a bisection over it is the
//! whole method. [`grade_response_probability`] applies §4's rule to it
//! — at least [`TRIAL_FLOOR`] independent trials *and* a bound no worse
//! than [`MISS_BOUND_PPB`] — and returns the `q` those trials earn, or
//! `None` for a field that has to be written `assumed`.

use hellas_kernel::{
    MAX_START_VALIDITY_BLOCKS, RESPONSE_FINALIZATION_BLOCKS, RESPONSE_INCLUSION_BLOCKS,
    RESPONSE_POLL_BLOCKS, RESPONSE_PROPAGATION_BLOCKS,
};

use crate::protocol::work_setup::OMISSION_PROBABILITY_SCALE;

/// Independent trials §4 requires before `q = 0.999` may be claimed.
///
/// Not a preference and not a round number: 2,995 is the smallest `n`
/// for which a clean run — zero misses — has a 95% Clopper–Pearson upper
/// miss bound at or under 0.001. At 2,994 the same clean run bounds the
/// miss rate at 0.0010001, which is worse than the claim. The two rules
/// §4 states are therefore one rule stated twice for a run with no
/// misses, and two different rules for a run with any.
pub const TRIAL_FLOOR: u64 = 2_995;

/// The upper miss bound §4 admits, in parts per billion: `0.001`.
///
/// Parts per billion rather than the `1..=1_000_000` scale `q` is
/// reported on, because the interesting comparisons happen in the sixth
/// decimal place and a bound rounded to the reporting scale would admit
/// a run that missed it.
pub const MISS_BOUND_PPB: u64 = 1_000_000;

/// One minus the confidence the bound is taken at: a 95% one-sided
/// bound.
const ALPHA: f64 = 0.05;

/// Parts per billion in one.
const PPB: f64 = 1_000_000_000.0;

/// Every §4 term the two waits are built from, reduced to the one number
/// each contributes.
///
/// A plain record with public fields, because this is what a probe fills
/// in from what it saw and an artifact reader fills in from what a probe
/// wrote. Every `_ms` field is whole milliseconds rounded up; every
/// `_blocks` field is blocks.
///
/// Nothing here is optional. A term the run could not sample is not a
/// zero — a zero would make the floor *smaller* — it is a field the
/// artifact wrote `assumed`, which turns admission off before this
/// struct is ever built.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MountBudget {
    /// One journal fsync, at the observed tail.
    pub fsync_tail_ms: u64,
    /// One journal rotation, at the observed tail.
    pub rotation_tail_ms: u64,
    /// Building one close response.
    pub response_build_ms: u64,
    /// Fetching one finalized block.
    pub one_block_fetch_ms: u64,
    /// Reading a fresh finalized tip.
    pub fresh_tip_ms: u64,
    /// The fsync that makes a prepared close durable.
    pub close_prepared_fsync_ms: u64,
    /// One validator RPC, whole, as the submitter waits for it.
    pub rpc_ms: u64,
    /// The validator's response worker, queueing included.
    pub response_worker_ms: u64,
    /// The validator's general submission worker.
    pub general_worker_ms: u64,
    /// The validator's extracted response validation.
    pub validation_ms: u64,
    /// Replaying a journal that is at its configured cap.
    pub restart_replay_ms_at_cap: u64,
    /// The gap a restart leaves, outside the replay.
    pub restart_downtime_ms: u64,
    /// The shortest block this deployment was observed to produce.
    pub lower_tail_block_ms: u64,
    /// `Ig`: loaded accepted-to-inclusion blocks for general traffic,
    /// finalization excluded.
    pub general_inclusion_blocks: u64,
}

/// `max6(a + b + c)`: the validator-side addend of both waits.
///
/// One function rather than an inline sum so that the two waits cannot
/// disagree about what the addend is, and so the thing being claimed has
/// somewhere to be written down. What is claimed is narrow: this tree
/// dials one validator, so the six-validator maximum is the maximum over
/// the samples one validator produced, and each addend arrives as the
/// largest sample of its own term. Summing three intervals that overlap
/// over-counts the wait, and a floor that over-counts refuses channels a
/// tighter floor would have admitted — which is the safe way round.
#[must_use]
pub const fn max6(rpc_ms: u64, worker_ms: u64, validation_ms: u64) -> u64 {
    rpc_ms + worker_ms + validation_ms
}

/// Why a measured budget is not one this node may admit work under.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum FloorError {
    /// `lower_tail_block_ms` is not positive, so every wait would cost
    /// infinitely many blocks. §4 refuses admission on it by name.
    #[error("lower_tail_block_ms is zero, so no wait can be priced in blocks")]
    NoLowerTail,
    /// A wait or block-count formula does not fit the `u64` carried by
    /// [`MountFloor`].
    #[error("checked arithmetic overflowed computing {field}")]
    Overflow {
        /// Formula whose result did not fit.
        field: &'static str,
    },
    /// `T` does not fit the fixed 64-block start span.
    #[error("the measured budget needs T={t} blocks and the start span is {span}")]
    StartSpanTooShort {
        /// `T = F + G + Ig + Sg + R + 1`.
        t: u64,
        /// [`MAX_START_VALIDITY_BLOCKS`].
        span: u64,
    },
    /// The signed terms do not carry the fixed start span this profile
    /// admits.
    #[error("the terms' start span is {span} blocks, not the fixed {fixed}")]
    StartSpanNotFixed {
        /// `start_validity_blocks`, as the signed terms fix it.
        span: u64,
        /// [`MAX_START_VALIDITY_BLOCKS`], the profile's fixed span.
        fixed: u64,
    },
    /// The proposed terms give the watcher fewer blocks to answer in
    /// than the measured floor needs.
    #[error(
        "the terms admit {window} blocks to answer a contest, under the measured floor {floor}"
    )]
    ResponseWindowBelowFloor {
        /// `omit_response_blocks`, as the terms fix it.
        window: u64,
        /// `F + POLL + G + I + S + R + 1`.
        floor: u64,
    },
    /// The configured response alarm fires with less margin than the
    /// measured budget needs to answer inside.
    #[error("the response alarm's margin is {margin} blocks, under the measured floor {floor}")]
    AlarmMarginBelowFloor {
        /// `response_alarm_margin_blocks`, as the configuration fixes it.
        margin: u64,
        /// `F + G + I + S + R + 1`.
        floor: u64,
    },
}

/// §4's two waits and the four block counts they imply.
///
/// Built once by [`MountBudget::floor`] and thereafter only read, so the
/// value a startup check consulted and the value an admission consults
/// are the same arithmetic over the same samples. Every field is
/// readable because every one of them is a number an operator has to be
/// able to check by hand against §4.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MountFloor {
    wresp_ms: u64,
    s: u64,
    wstart_ms: u64,
    sg: u64,
    r: u64,
    t: u64,
    min_omit_response_blocks: u64,
    alarm_margin_blocks: u64,
}

impl MountBudget {
    /// Computes §4's floor over these observations.
    ///
    /// # Errors
    ///
    /// [`FloorError::NoLowerTail`] when `lower_tail_block_ms` is not
    /// positive, or [`FloorError::Overflow`] when a wait or block-count
    /// formula does not fit the floor's `u64` fields. Both refuse rather
    /// than invent a smaller floor.
    pub const fn floor(&self) -> Result<MountFloor, FloorError> {
        if self.lower_tail_block_ms == 0 {
            return Err(FloorError::NoLowerTail);
        }
        let block = self.lower_tail_block_ms;

        // Widen before doing any artifact arithmetic. The largest
        // expression below has nine `u64` terms, so every `u128` result
        // is exact; each bound check can therefore refuse before the
        // corresponding value is narrowed back into the floor.

        // Wresp: §5 acts before reading the next backlog block, so the
        // three fsyncs, the rotation, the build and the one block fetch
        // are all in front of the answer, and the validator-side addend
        // is on top of them.
        let response_validator_wide =
            self.rpc_ms as u128 + self.response_worker_ms as u128 + self.validation_ms as u128;
        if response_validator_wide > u64::MAX as u128 {
            return Err(FloorError::Overflow { field: "Wresp" });
        }
        // The wide check proves every non-negative partial sum in
        // `max6` fits too, so its reader-facing arithmetic cannot wrap.
        let response_validator_ms = max6(self.rpc_ms, self.response_worker_ms, self.validation_ms);
        let wresp_wide = 3 * self.fsync_tail_ms as u128
            + self.rotation_tail_ms as u128
            + self.response_build_ms as u128
            + self.one_block_fetch_ms as u128
            + response_validator_ms as u128;
        if wresp_wide > u64::MAX as u128 {
            return Err(FloorError::Overflow { field: "Wresp" });
        }
        let wresp_ms = wresp_wide as u64;
        let s = wresp_ms.div_ceil(block);

        let general_validator_wide =
            self.rpc_ms as u128 + self.general_worker_ms as u128 + self.validation_ms as u128;
        if general_validator_wide > u64::MAX as u128 {
            return Err(FloorError::Overflow { field: "Wstart" });
        }
        let general_validator_ms = max6(self.rpc_ms, self.general_worker_ms, self.validation_ms);
        let wstart_wide = self.fresh_tip_ms as u128
            + self.close_prepared_fsync_ms as u128
            + self.rotation_tail_ms as u128
            + general_validator_ms as u128;
        if wstart_wide > u64::MAX as u128 {
            return Err(FloorError::Overflow { field: "Wstart" });
        }
        let wstart_ms = wstart_wide as u64;
        let sg = wstart_ms.div_ceil(block);

        let restart_wide = self.restart_downtime_ms as u128 + self.restart_replay_ms_at_cap as u128;
        if restart_wide > u64::MAX as u128 {
            return Err(FloorError::Overflow { field: "R" });
        }
        let r = (restart_wide as u64).div_ceil(block);

        let t_wide = RESPONSE_FINALIZATION_BLOCKS as u128
            + RESPONSE_PROPAGATION_BLOCKS as u128
            + self.general_inclusion_blocks as u128
            + sg as u128
            + r as u128
            + 1;
        if t_wide > u64::MAX as u128 {
            return Err(FloorError::Overflow { field: "T" });
        }
        let response_floor_wide = RESPONSE_FINALIZATION_BLOCKS as u128
            + RESPONSE_POLL_BLOCKS as u128
            + RESPONSE_PROPAGATION_BLOCKS as u128
            + RESPONSE_INCLUSION_BLOCKS as u128
            + s as u128
            + r as u128
            + 1;
        if response_floor_wide > u64::MAX as u128 {
            return Err(FloorError::Overflow {
                field: "response-window floor",
            });
        }
        let alarm_floor_wide = RESPONSE_FINALIZATION_BLOCKS as u128
            + RESPONSE_PROPAGATION_BLOCKS as u128
            + RESPONSE_INCLUSION_BLOCKS as u128
            + s as u128
            + r as u128
            + 1;
        if alarm_floor_wide > u64::MAX as u128 {
            return Err(FloorError::Overflow {
                field: "alarm-margin floor",
            });
        }

        Ok(MountFloor {
            wresp_ms,
            s,
            wstart_ms,
            sg,
            r,
            t: t_wide as u64,
            min_omit_response_blocks: response_floor_wide as u64,
            alarm_margin_blocks: alarm_floor_wide as u64,
        })
    }
}

impl MountFloor {
    /// `Wresp`, in milliseconds.
    #[must_use]
    pub const fn wresp_ms(&self) -> u64 {
        self.wresp_ms
    }

    /// `S = ceil(Wresp / lower_tail_block_ms)`.
    #[must_use]
    pub const fn s(&self) -> u64 {
        self.s
    }

    /// `Wstart`, in milliseconds.
    #[must_use]
    pub const fn wstart_ms(&self) -> u64 {
        self.wstart_ms
    }

    /// `Sg = ceil(Wstart / lower_tail_block_ms)`.
    #[must_use]
    pub const fn sg(&self) -> u64 {
        self.sg
    }

    /// `R = ceil((restart_downtime_ms + restart_replay_ms_at_cap) /
    /// lower_tail_block_ms)`.
    #[must_use]
    pub const fn r(&self) -> u64 {
        self.r
    }

    /// `T = F + G + Ig + Sg + R + 1`.
    #[must_use]
    pub const fn t(&self) -> u64 {
        self.t
    }

    /// `F + POLL + G + I + S + R + 1`: the shortest response window
    /// terms may commit under this budget.
    #[must_use]
    pub const fn min_omit_response_blocks(&self) -> u64 {
        self.min_omit_response_blocks
    }

    /// `F + G + I + S + R + 1`: the margin the response alarm must fire
    /// inside.
    #[must_use]
    pub const fn alarm_margin_blocks(&self) -> u64 {
        self.alarm_margin_blocks
    }

    /// `64 ≥ T`, or the refusal.
    ///
    /// The deployment half of the gate §4 puts at startup and provider
    /// admission. It is a refusal and not a warning: a `T` above the
    /// fixed start span is a deployment in which a signed start expires
    /// before the channel it authorises could be reached, and a node
    /// that countersigned anyway would be selling a channel it cannot
    /// settle.
    ///
    /// # Errors
    ///
    /// [`FloorError::StartSpanTooShort`], naming both numbers.
    pub const fn check_start_span(&self) -> Result<(), FloorError> {
        if MAX_START_VALIDITY_BLOCKS >= self.t {
            Ok(())
        } else {
            Err(FloorError::StartSpanTooShort {
                t: self.t,
                span: MAX_START_VALIDITY_BLOCKS,
            })
        }
    }

    /// Checks both the measured floor and the span the parties actually
    /// signed.
    ///
    /// The kernel supplies only an upper bound. This profile fixes the
    /// span at that bound, so a smaller value is not admitted merely
    /// because it happens to clear this deployment's current `T`: it is
    /// a different term from the one the profile offers.
    ///
    /// # Errors
    ///
    /// [`FloorError::StartSpanTooShort`] when this deployment does not
    /// fit the fixed span, or [`FloorError::StartSpanNotFixed`] when the
    /// signed terms carry any other span.
    pub const fn check_terms_start_span(&self, span: u64) -> Result<(), FloorError> {
        if let Err(error) = self.check_start_span() {
            return Err(error);
        }
        if span == MAX_START_VALIDITY_BLOCKS {
            Ok(())
        } else {
            Err(FloorError::StartSpanNotFixed {
                span,
                fixed: MAX_START_VALIDITY_BLOCKS,
            })
        }
    }

    /// Checks one proposed window against
    /// [`Self::min_omit_response_blocks`].
    ///
    /// # Errors
    ///
    /// [`FloorError::ResponseWindowBelowFloor`].
    pub const fn check_response_window(&self, omit_response_blocks: u64) -> Result<(), FloorError> {
        if omit_response_blocks >= self.min_omit_response_blocks {
            Ok(())
        } else {
            Err(FloorError::ResponseWindowBelowFloor {
                window: omit_response_blocks,
                floor: self.min_omit_response_blocks,
            })
        }
    }

    /// Checks one configured alarm margin against
    /// [`Self::alarm_margin_blocks`].
    ///
    /// The comparison is one-sided for the reason the window's is: an
    /// alarm that fires earlier than the budget needs is an alarm that
    /// fires, and one that fires later is one that fires after the
    /// deadline it exists to beat.
    ///
    /// # Errors
    ///
    /// [`FloorError::AlarmMarginBelowFloor`].
    pub const fn check_alarm_margin(&self, margin_blocks: u64) -> Result<(), FloorError> {
        if margin_blocks >= self.alarm_margin_blocks {
            Ok(())
        } else {
            Err(FloorError::AlarmMarginBelowFloor {
                margin: margin_blocks,
                floor: self.alarm_margin_blocks,
            })
        }
    }
}

/// The 95% one-sided Clopper–Pearson upper bound on the miss rate, in
/// parts per billion, rounded up.
///
/// The bound is the largest `p` at which a run this clean still had a 5%
/// chance of happening: `P[misses or fewer | n, p] = 0.05`. That
/// probability falls as `p` rises, so the equation has one root and a
/// bisection finds it. Rounding the answer up is the safe direction — a
/// bound reported smaller than it is would admit a run that did not earn
/// it.
///
/// A run with no trials, or one whose every trial missed, bounds the
/// miss rate at one: `1_000_000_000`.
#[must_use]
pub fn clopper_pearson_upper_ppb(trials: u64, misses: u64) -> u64 {
    if trials == 0 || misses >= trials {
        return PPB as u64;
    }
    let (mut low, mut high) = (0.0_f64, 1.0_f64);
    // Sixty halvings exhaust an f64 mantissa over this interval; a
    // hundred is the same answer with the arithmetic's own headroom.
    for _ in 0..100 {
        let mid = 0.5 * (low + high);
        if binomial_at_most(misses, trials, mid) > ALPHA {
            low = mid;
        } else {
            high = mid;
        }
    }
    let ppb = (high * PPB).ceil();
    if ppb >= PPB { PPB as u64 } else { ppb as u64 }
}

/// `P[at most k successes | n trials, probability p]`.
///
/// Summed from the `k = 0` term upwards by the ratio between successive
/// terms, which never forms a factorial and never leaves the scale of
/// the answer. The first term is taken through a logarithm because
/// `(1-p)^n` underflows for the large `n` and large `p` the bisection
/// visits on its way down; the underflow is the true answer there, and
/// the sum stops early once it reaches one.
fn binomial_at_most(k: u64, n: u64, p: f64) -> f64 {
    if p <= 0.0 {
        return 1.0;
    }
    if p >= 1.0 {
        return f64::from(u8::from(k >= n));
    }
    let complement = 1.0 - p;
    let ratio = p / complement;
    let mut term = (n as f64 * complement.ln()).exp();
    let mut sum = term;
    for i in 0..k {
        term *= (n - i) as f64 / (i + 1) as f64 * ratio;
        sum += term;
        if sum >= 1.0 {
            return 1.0;
        }
    }
    sum
}

/// §4's grading of the response probability: the `q` these trials earn,
/// or `None` for a field that must be written `assumed`.
///
/// Both halves of the rule, and neither is sufficient alone.
/// [`TRIAL_FLOOR`] trials with one miss fails the bound; a clean run of
/// a hundred passes the bound trivially and fails the count. The `q`
/// returned is the complement of the bound on the
/// [`OMISSION_PROBABILITY_SCALE`] the omission economics are computed
/// on, with the bound rounded *up* first, so the availability claimed is
/// never larger than the evidence supports.
#[must_use]
pub fn grade_response_probability(trials: u64, misses: u64) -> Option<u64> {
    if trials < TRIAL_FLOOR {
        return None;
    }
    let upper_ppb = clopper_pearson_upper_ppb(trials, misses);
    if upper_ppb > MISS_BOUND_PPB {
        return None;
    }
    // ppb to the reporting scale, rounding the miss rate up so the
    // availability rounds down.
    let scale = PPB as u64 / OMISSION_PROBABILITY_SCALE;
    Some(OMISSION_PROBABILITY_SCALE - upper_ppb.div_ceil(scale))
}

#[cfg(test)]
mod tests;
