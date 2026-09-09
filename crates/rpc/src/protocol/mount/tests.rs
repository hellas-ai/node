use super::*;

/// A budget whose every term is one, so a formula typo shows up as a
/// term counted the wrong number of times rather than as a wash.
///
/// The three `_ms` terms that carry a coefficient in §4 are given
/// distinct primes for the same reason.
const fn budget() -> MountBudget {
    MountBudget {
        fsync_tail_ms: 5,
        rotation_tail_ms: 7,
        response_build_ms: 11,
        one_block_fetch_ms: 13,
        fresh_tip_ms: 17,
        close_prepared_fsync_ms: 19,
        rpc_ms: 23,
        response_worker_ms: 29,
        general_worker_ms: 31,
        validation_ms: 37,
        restart_replay_ms_at_cap: 41,
        restart_downtime_ms: 43,
        lower_tail_block_ms: 50,
        general_inclusion_blocks: 3,
    }
}

/// Every term of §4, hand-checked.
///
/// `Wresp  = 3×5 + 7 + 11 + 13 + (23+29+37) = 15+7+11+13+89 = 135`
/// `S      = ceil(135/50) = 3`
/// `Wstart = 17 + 19 + 7 + (23+31+37) = 17+19+7+91 = 134`
/// `Sg     = ceil(134/50) = 3`
/// `R      = ceil((43+41)/50) = ceil(84/50) = 2`
/// `T      = 2 + 1 + 3 + 3 + 2 + 1 = 12`
/// `omit   = 2 + 4 + 1 + 8 + 3 + 2 + 1 = 21`
/// `alarm  = 2 + 1 + 8 + 3 + 2 + 1 = 17`
#[test]
fn the_floor_is_the_arithmetic_section_four_writes() {
    let Ok(floor) = budget().floor() else {
        panic!("a positive lower tail prices every wait")
    };

    assert_eq!(floor.wresp_ms(), 135);
    assert_eq!(floor.s(), 3);
    assert_eq!(floor.wstart_ms(), 134);
    assert_eq!(floor.sg(), 3);
    assert_eq!(floor.r(), 2);
    assert_eq!(floor.t(), 12);
    assert_eq!(floor.min_omit_response_blocks(), 21);
    assert_eq!(floor.alarm_margin_blocks(), 17);
    assert_eq!(floor.check_start_span(), Ok(()));
}

/// The divisions round up, and a wait one millisecond over a block
/// costs the whole next block.
#[test]
fn a_wait_that_overruns_a_block_costs_the_next_one() {
    let mut budget = budget();
    // Wresp = 135 exactly; a block of 135 costs one, of 134 costs
    // two.
    budget.lower_tail_block_ms = 135;
    let Ok(exact) = budget.floor() else {
        panic!("a positive lower tail prices every wait")
    };
    assert_eq!(exact.s(), 1);

    budget.lower_tail_block_ms = 134;
    let Ok(over) = budget.floor() else {
        panic!("a positive lower tail prices every wait")
    };
    assert_eq!(over.s(), 2);
}

/// A non-positive lower tail is refused rather than divided by.
#[test]
fn a_block_that_takes_no_time_prices_nothing() {
    let mut budget = budget();
    budget.lower_tail_block_ms = 0;
    assert_eq!(budget.floor(), Err(FloorError::NoLowerTail));
}

/// An artifact can carry every positive `u64`; one too large for a
/// floor formula is a refusal in debug and release alike.
#[test]
fn a_measurement_that_overflows_the_floor_is_refused() {
    let mut budget = budget();
    budget.fsync_tail_ms = u64::MAX;
    assert_eq!(budget.floor(), Err(FloorError::Overflow { field: "Wresp" }));
}

/// `64 ≥ T` admits and `T > 64` refuses, and the refusal names both
/// numbers.
#[test]
fn the_start_span_is_the_gate() {
    let mut budget = budget();
    // Ig alone carries T past the span: T = 2 + 1 + Ig + 3 + 2 + 1.
    budget.general_inclusion_blocks = 55;
    let Ok(admits) = budget.floor() else {
        panic!("a positive lower tail prices every wait")
    };
    assert_eq!(admits.t(), 64);
    assert_eq!(admits.check_start_span(), Ok(()));

    budget.general_inclusion_blocks = 56;
    let Ok(refuses) = budget.floor() else {
        panic!("a positive lower tail prices every wait")
    };
    assert_eq!(refuses.t(), 65);
    assert_eq!(
        refuses.check_start_span(),
        Err(FloorError::StartSpanTooShort { t: 65, span: 64 }),
    );
}

/// Admission binds the span in the signed terms and does not turn
/// the profile's fixed 64 into a per-deployment minimum.
#[test]
fn the_signed_start_span_is_fixed_not_merely_sufficient() {
    let Ok(floor) = budget().floor() else {
        panic!("a positive lower tail prices every wait")
    };
    assert_eq!(floor.t(), 12);
    assert_eq!(floor.check_terms_start_span(64), Ok(()));
    assert_eq!(
        floor.check_terms_start_span(63),
        Err(FloorError::StartSpanNotFixed {
            span: 63,
            fixed: 64,
        }),
        "a span well above T is still not this profile's fixed span",
    );
    assert_eq!(
        floor.check_terms_start_span(8),
        Err(FloorError::StartSpanNotFixed { span: 8, fixed: 64 }),
        "the signed span below T is refused by the value the parties signed",
    );
}

/// The two window requirements are one-sided, and both name their
/// floor.
#[test]
fn a_short_window_and_a_short_margin_are_both_refused() {
    let Ok(floor) = budget().floor() else {
        panic!("a positive lower tail prices every wait")
    };

    assert_eq!(floor.check_response_window(21), Ok(()));
    assert_eq!(floor.check_response_window(4_096), Ok(()));
    assert_eq!(
        floor.check_response_window(20),
        Err(FloorError::ResponseWindowBelowFloor {
            window: 20,
            floor: 21,
        }),
    );

    assert_eq!(floor.check_alarm_margin(17), Ok(()));
    assert_eq!(
        floor.check_alarm_margin(16),
        Err(FloorError::AlarmMarginBelowFloor {
            margin: 16,
            floor: 17,
        }),
    );
}

/// 2,995 is not a round number, it is the answer to the bound.
///
/// A clean run of 2,995 bounds the miss rate at or under 0.001 and a
/// clean run of 2,994 does not — which is what makes §4's two rules
/// one rule for a run with no misses. If the bisection or the
/// binomial tail were wrong, this boundary would move.
#[test]
fn the_trial_floor_is_where_a_clean_run_earns_the_claim() {
    assert!(clopper_pearson_upper_ppb(TRIAL_FLOOR, 0) <= MISS_BOUND_PPB);
    assert!(clopper_pearson_upper_ppb(TRIAL_FLOOR - 1, 0) > MISS_BOUND_PPB);
    // 1 - 0.05^(1/2995), to the part per billion.
    assert_eq!(clopper_pearson_upper_ppb(TRIAL_FLOOR, 0), 999_745);
}

/// The count and the bound are two rules, and each refuses on its
/// own.
#[test]
fn thin_evidence_and_a_missed_bound_are_both_assumed() {
    // Enough trials, one miss too many: 3,000 trials with one miss
    // bounds the miss rate at 0.00158.
    assert_eq!(grade_response_probability(3_000, 1), None);
    // The bound is comfortable and the count is not.
    assert_eq!(grade_response_probability(TRIAL_FLOOR - 1, 0), None);
    assert_eq!(grade_response_probability(100, 0), None);
    // A run in which everything missed.
    assert_eq!(grade_response_probability(10_000, 10_000), None);
}

/// A clean run at the floor earns exactly `q = 0.999`, and a longer
/// run earns more.
#[test]
fn a_graded_run_earns_the_availability_its_bound_leaves() {
    assert_eq!(
        grade_response_probability(TRIAL_FLOOR, 0),
        Some(999_000),
        "the bound is 999_745 ppb, which is 1_000 ppm of miss",
    );
    assert_eq!(
        grade_response_probability(3_000_000, 0),
        Some(999_999),
        "a thousandfold run bounds the miss rate a thousandfold lower",
    );
    // Misses are affordable once there are enough trials to price
    // them: 1 in 5,000 bounds the miss rate at 948_780 ppb, which
    // is 949 ppm.
    assert_eq!(clopper_pearson_upper_ppb(5_000, 1), 948_418);
    assert_eq!(grade_response_probability(5_000, 1), Some(999_051));
}

/// `max6` is a sum, and the overlap it double-counts is the reason
/// it is safe.
#[test]
fn the_validator_addend_over_counts_on_purpose() {
    assert_eq!(max6(23, 29, 37), 89);
    assert!(
        max6(23, 29, 37) >= 23,
        "the addend is never under the whole RPC it contains",
    );
}
