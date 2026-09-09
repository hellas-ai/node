use super::*;

fn assumptions(exclude: &[&str]) -> AssumptionsFile {
    AssumptionsFile {
        budget: TERMS
            .iter()
            .filter(|term| !exclude.contains(term))
            .map(|term| ((*term).to_string(), 7))
            .collect(),
        omission: AssumedOmission {
            response_probability: 999_000,
            response_blocks: 20,
            response_cost_cap: 1,
        },
        expected_payment_values: AssumedPaymentValues {
            value: 1_000,
            reserve: 200,
            base: 0,
            slot: 0,
            proof: 0,
            lifetime: 0,
        },
    }
}

/// The journal workload really appends, really rotates and really
/// reopens, and the three seams it drives really produce samples.
///
/// Nothing is emitted by this test: every sample below is the
/// shipped journal's own, taken on a real file on a real disk.
#[test]
fn the_journal_workload_samples_the_three_seams_it_drives() {
    let dir = tempfile::tempdir().unwrap();
    let probe = Probe::open();

    if let Err(error) = measure_journals(&probe, dir.path()) {
        panic!("the journal workload runs: {error}");
    }

    let fsyncs = probe.observed("fsync_tail_ms");
    assert!(
        fsyncs.len() > 1_000,
        "four generations to the soft limit is thousands of appends, not {}",
        fsyncs.len(),
    );
    assert_eq!(
        probe.observed("rotation_tail_ms").len(),
        GENERATIONS as usize,
        "one rotation sample per generation installed",
    );
    assert_eq!(
        probe.observed("restart_replay_ms_at_cap").len(),
        GENERATIONS as usize,
        "one replay sample per reopen",
    );
    // The probe leaves nothing behind for a real endpoint to trip
    // over.
    assert!(!dir.path().join("bootstrap-probe").exists());
}

/// The eleven terms no bootstrap here can observe are written
/// `assumed`, and the run says which they were.
#[test]
fn what_the_run_did_not_see_is_assumed_and_named() {
    let dir = tempfile::tempdir().unwrap();
    let probe = Probe::open();
    if let Err(error) = measure_journals(&probe, dir.path()) {
        panic!("the journal workload runs: {error}");
    }
    let measured = [
        "fsync_tail_ms",
        "rotation_tail_ms",
        "restart_replay_ms_at_cap",
    ];

    let (artifact, unmeasured) = probe
        .into_artifact(
            "bootstrap-1",
            Digest::from_bytes([0x21; 32]),
            Digest::from_bytes([0x22; 32]),
            &assumptions(&measured),
        )
        .expect("the artifact is written from what the run saw");

    assert_eq!(unmeasured.len(), TERMS.len() - measured.len());
    for term in TERMS {
        let entry = &artifact["budget"][term];
        if measured.contains(&term) {
            assert_eq!(entry["evidence"], "measured", "{term}");
            assert!(entry["samples"].as_array().is_some_and(|s| !s.is_empty()));
        } else {
            assert_eq!(entry["evidence"], "assumed", "{term}");
            assert!(unmeasured.contains(&term), "{term} is not named");
        }
    }
    // No contest was raised, so `q` rests on nothing and says so.
    assert_eq!(artifact["omission"]["response_trials"]["trials"], 0);
    assert_eq!(
        artifact["omission"]["response_probability"]["evidence"],
        "assumed"
    );
}

/// A term that is neither observed nor written down stops the run,
/// by name. It is not defaulted and it is not dropped.
#[test]
fn a_term_nobody_measured_or_assumed_stops_the_run() {
    let probe = Probe::open();

    let error = format!(
        "{:?}",
        probe
            .into_artifact(
                "bootstrap-1",
                Digest::from_bytes([0x21; 32]),
                Digest::from_bytes([0x22; 32]),
                &assumptions(&["lower_tail_block_ms"]),
            )
            .expect_err("a term with no value anywhere is refused"),
    );

    assert!(
        error.contains("lower_tail_block_ms"),
        "the refusal does not name the term: {error}",
    );
}

/// A value written down beside one the run measured is refused: it
/// would never be read, and an operator who wrote it believes
/// otherwise.
#[test]
fn an_assumption_beside_a_measurement_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let probe = Probe::open();
    if let Err(error) = measure_journals(&probe, dir.path()) {
        panic!("the journal workload runs: {error}");
    }

    let error = format!(
        "{:?}",
        probe
            .into_artifact(
                "bootstrap-1",
                Digest::from_bytes([0x21; 32]),
                Digest::from_bytes([0x22; 32]),
                &assumptions(&["rotation_tail_ms", "restart_replay_ms_at_cap"]),
            )
            .expect_err("an assumption beside a measurement is refused"),
    );

    assert!(
        error.contains("fsync_tail_ms"),
        "the refusal does not name the term: {error}",
    );
}
