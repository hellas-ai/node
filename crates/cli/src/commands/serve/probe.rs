//! The bootstrap run: what an operator can actually measure on their own
//! machine, and what they cannot.
//!
//! # Why this exists
//!
//! §4-A gave a node an artifact to read and §4-B gave it a floor to
//! compute from one. Nothing produced an artifact, so paid admission was
//! off in production no matter what the operator did. This is the thing
//! that produces one: it installs the collector every seam in
//! [`hellas_rpc::observe`] emits into, runs the parts of §4's bootstrap
//! this deployment can genuinely run, and writes the raw samples out in
//! the schema [`super::work_config::load_paid_work_duties`] reads back.
//!
//! # What it measures, and what it refuses to pretend about
//!
//! §4 asks a bootstrap run to disable paid admission, create funded
//! contests, fill both queues, and measure fourteen quantities. This
//! probe disables nothing because it countersigns nothing — it never
//! builds a setup endpoint and never reads the artifact it is about to
//! write — and of the fourteen it can genuinely observe three:
//!
//! - `fsync_tail_ms`, from real appends to a real journal on the
//!   operator's own configured root, under the journal's own caps;
//! - `rotation_tail_ms`, from real generation installs at the soft limit
//!   those appends reach;
//! - `restart_replay_ms_at_cap`, from really reopening a journal that is
//!   at its cap and really walking every frame in it.
//!
//! The other eleven it does not observe, and the reason is worth being
//! exact about rather than approximating:
//!
//! - `rpc_ms`, `one_block_fetch_ms`, `fresh_tip_ms`,
//!   `response_build_ms`, `close_prepared_fsync_ms` and
//!   `general_inclusion_blocks` need a funded channel with an open
//!   contest on a live chain. Creating one costs coins this process has
//!   no key to and a client this process is not.
//! - `response_worker_ms`, `general_worker_ms` and `validation_ms` are
//!   emitted **inside a validator's process**
//!   (`crates/rpc/src/call.rs:719,786`, `crates/chain/src/rpc.rs:170`).
//!   A provider running this probe is not that process and cannot
//!   collect from it. An operator who also runs the validators can, by
//!   running a probe there; this one does not claim to have.
//! - `restart_downtime_ms` is the gap a *process* restart leaves. A
//!   probe that does not stop and start the node cannot see it, and
//!   timing a journal reopen instead would under-count it — the one
//!   direction a fail-closed floor may not be wrong in.
//! - `lower_tail_block_ms` is the shortest block this deployment
//!   produces, which needs a chain to be watched over a run.
//!
//! Every one of those is written `assumed`, from a value the operator
//! wrote down, and one `assumed` field is a node that countersigns
//! nothing. That is the honest outcome and it is the point: an artifact
//! claiming `measured` on evidence like this is exactly the failure the
//! whole gate exists to prevent.
//!
//! # The trials are the sharpest of these
//!
//! `q = 0.999` needs 2,995 independent contests answered in time
//! ([`hellas_rpc::protocol::mount::TRIAL_FLOOR`]). This probe raises
//! none, writes `trials: 0`, and the grading turns that into `assumed`
//! without being asked to. Nothing here lowers that threshold and
//! nothing here invents a trial.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context as _, bail};
use hellas_rpc::observe::{Samples, unix_ms};
use hellas_rpc::protocol::Digest;
use hellas_rpc::protocol::mount::clopper_pearson_upper_ppb;
use hellas_rpc::work_store::Role;
use hellas_rpc::work_store::journal::{Journal, JournalId, JournalKind};
use serde::Deserialize;

use crate::commands::CliResult;

/// Generations the journal workload fills and installs.
///
/// Each one is a whole file taken to its soft limit, so it costs one
/// rotation sample, one replay sample, and every append in between. Four
/// is enough that a rotation tail is a tail of something rather than a
/// single observation, and few enough that the run is minutes rather
/// than hours.
const GENERATIONS: u64 = 4;

/// Bytes of payload one probe append writes.
///
/// A journal record, not a token: the seam being sampled is the fsync
/// after a frame, and a frame of a realistic size is what a duty
/// actually waits on.
const RECORD_BYTES: usize = 4 << 10;

/// What the operator asks a bootstrap run to do.
#[derive(Clone, Debug)]
pub struct ProbeOptions {
    /// The paid-work configuration this run measures under. Its bytes
    /// are hashed into the artifact's provenance, because a measurement
    /// is a statement about a configuration.
    pub work_config: PathBuf,
    /// Where the journal workload runs. The operator's own configured
    /// journal root, so the disk being measured is the disk the duties
    /// will run on.
    pub journal_root: PathBuf,
    /// The machine, as the operator names it.
    pub machine: String,
    /// What the operator writes down for every term no run can observe.
    pub assume: PathBuf,
    /// Where the artifact is written.
    pub out: PathBuf,
}

/// The values an operator wrote down for what the run cannot see.
///
/// A file and not a set of flags, and not a table of defaults: §4 says a
/// quantity a bootstrap cannot sample is named and written `assumed`,
/// and a default here would be this binary quietly writing down a number
/// nobody chose. A term that is neither measured nor present in this
/// file stops the run, by name.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AssumptionsFile {
    /// `term: value`, for any of §4's fourteen budget terms.
    budget: BTreeMap<String, u64>,
    /// The three omission numbers, which need funded contests.
    omission: AssumedOmission,
    /// The six expected payment values, which need a funded edge.
    expected_payment_values: AssumedPaymentValues,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AssumedOmission {
    response_probability: u64,
    response_blocks: u64,
    response_cost_cap: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AssumedPaymentValues {
    value: u64,
    reserve: u64,
    base: u64,
    slot: u64,
    proof: u64,
    lifetime: u64,
}

/// The fourteen budget terms, and which end of their observations §4
/// takes.
///
/// The order is the order they appear in the artifact, and the list is
/// the probe's whole vocabulary: a term not here is a term the artifact
/// writer will refuse to emit, which is what keeps this file and
/// [`super::work_config::BudgetFile`] from drifting apart silently.
const TERMS: [&str; 14] = [
    "fsync_tail_ms",
    "rotation_tail_ms",
    "response_build_ms",
    "one_block_fetch_ms",
    "fresh_tip_ms",
    "close_prepared_fsync_ms",
    "rpc_ms",
    "response_worker_ms",
    "general_worker_ms",
    "validation_ms",
    "restart_replay_ms_at_cap",
    "restart_downtime_ms",
    "lower_tail_block_ms",
    "general_inclusion_blocks",
];

/// One bootstrap run, collecting.
///
/// Holds the collector and the moment the run began, and nothing else:
/// every judgement about what was collected is made by the artifact
/// reader, not here. In particular this does not reduce, average, or
/// grade — [`Self::into_artifact`] copies raw samples out and leaves
/// `max6` and the Clopper–Pearson bound to the node that will read them.
pub struct Probe {
    samples: Arc<Samples>,
    started_at_unix_ms: u64,
}

impl Probe {
    /// Opens a run and installs its collector.
    #[must_use]
    pub fn open() -> Self {
        Self {
            samples: Arc::new(Samples::new()),
            started_at_unix_ms: unix_ms(),
        }
    }

    /// Runs one step of the bootstrap with this probe's collector
    /// installed on the calling thread.
    ///
    /// Thread-local rather than global on purpose: the collector is not
    /// a logging configuration and an operator's own subscriber goes on
    /// receiving everything else. A step that spawns work onto other
    /// threads is a step whose samples this probe does not see, which is
    /// why the workload below is the synchronous one.
    pub fn collecting<T>(&self, step: impl FnOnce() -> T) -> T {
        tracing::subscriber::with_default(Arc::clone(&self.samples), step)
    }

    /// Every observation of one term, raw and in emission order.
    ///
    /// Durations arrive as fractional milliseconds and leave as whole
    /// ones, rounded **up**: §4's terms are whole milliseconds, and a
    /// wait rounded up costs blocks, which is the direction a
    /// fail-closed floor is allowed to be wrong in.
    fn observed(&self, quantity: &str) -> Vec<(u64, u64)> {
        self.samples
            .of(quantity)
            .into_iter()
            .map(|sample| (sample.at_unix_ms, sample.ms.ceil().max(0.0) as u64))
            .collect()
    }

    /// Writes the artifact this run earned.
    ///
    /// # Errors
    ///
    /// A term that was neither observed nor assumed, naming it.
    fn into_artifact(
        self,
        machine: &str,
        binary: Digest,
        config: Digest,
        assumed: &AssumptionsFile,
    ) -> CliResult<(serde_json::Value, Vec<&'static str>)> {
        let finished_at_unix_ms = unix_ms();
        let mut budget = serde_json::Map::new();
        let mut unmeasured = Vec::new();
        for term in TERMS {
            let observed = self.observed(term);
            if observed.is_empty() {
                let Some(value) = assumed.budget.get(term) else {
                    bail!(
                        "this run observed no {term} and the assumptions file names none; \
                         §4 wants it written down rather than defaulted"
                    );
                };
                unmeasured.push(term);
                budget.insert(
                    term.to_string(),
                    serde_json::json!({ "evidence": "assumed", "value": value }),
                );
                continue;
            }
            let samples: Vec<serde_json::Value> = observed
                .into_iter()
                .map(|(at_unix_ms, value)| {
                    serde_json::json!({
                        "at_unix_ms": at_unix_ms,
                        "value": value,
                    })
                })
                .collect();
            budget.insert(
                term.to_string(),
                serde_json::json!({ "evidence": "measured", "samples": samples }),
            );
        }
        // A term the assumptions file names and the run measured is an
        // operator writing down something they did not need to, and the
        // number they wrote is not the one that will be used. Saying so
        // is cheaper than letting them believe otherwise.
        let surplus: Vec<&String> = assumed
            .budget
            .keys()
            .filter(|term| !unmeasured.contains(&term.as_str()))
            .collect();
        if !surplus.is_empty() {
            bail!(
                "the assumptions file writes down {surplus:?}, which this run measured; \
                 an assumed value beside a measured one would never be read"
            );
        }

        // No contest was raised, so no contest was answered in time.
        // Zero trials is what the grading is handed, and zero trials
        // grade `assumed` — which is the whole of what this probe can
        // honestly say about `q`.
        let trials = 0_u64;
        let misses = 0_u64;

        Ok((
            serde_json::json!({
                "provenance": {
                    "binary": hex::encode(binary.as_bytes()),
                    "config": hex::encode(config.as_bytes()),
                    "machine": machine,
                    "started_at_unix_ms": self.started_at_unix_ms,
                    "measured_at_unix_ms": finished_at_unix_ms,
                },
                "omission": {
                    "response_probability": assumed_number(assumed.omission.response_probability),
                    "response_blocks": assumed_number(assumed.omission.response_blocks),
                    "response_cost_cap": assumed_number(assumed.omission.response_cost_cap),
                    "response_trials": {
                        "trials": trials,
                        "misses": misses,
                        "miss_upper_ppb": clopper_pearson_upper_ppb(trials, misses),
                    },
                },
                "expected_payment_values": {
                    "value": assumed_number(assumed.expected_payment_values.value),
                    "reserve": assumed_number(assumed.expected_payment_values.reserve),
                    "close_fees": {
                        "base": assumed_number(assumed.expected_payment_values.base),
                        "slot": assumed_number(assumed.expected_payment_values.slot),
                        "proof": assumed_number(assumed.expected_payment_values.proof),
                        "lifetime": assumed_number(assumed.expected_payment_values.lifetime),
                    },
                },
                "budget": budget,
            }),
            unmeasured,
        ))
    }
}

/// One artifact number nobody measured, in §4-A's shape.
fn assumed_number(value: u64) -> serde_json::Value {
    serde_json::json!({ "value": value, "evidence": "assumed", "samples": 0 })
}

/// Fills, rotates and reopens a journal on the operator's own root,
/// which is the one part of §4's bootstrap this process can run alone.
///
/// Everything here is the shipped journal doing what a duty makes it do:
/// [`Journal::append`] fsyncs every frame, [`Journal::at_soft_limit`]
/// says when a caller must move on, [`Journal::rotate`] performs the
/// three-step install, and [`Journal::open_latest`] reopens what was
/// left. No seam is called directly and no timing is taken here — the
/// samples are the journal's own.
///
/// It runs under a key of its own so that it cannot touch, lock, or
/// rotate a journal a real channel owns.
///
/// # Errors
///
/// Whatever the journal refuses, and the filesystem.
pub fn measure_journals(probe: &Probe, root: &Path) -> CliResult<()> {
    let directory = root.join("bootstrap-probe");
    let stem = "probe";
    let id = JournalId {
        kind: JournalKind::Channel,
        role: Role::Provider,
        key: *b"hellas.mount.bootstrap.probe...\0",
        generation: 0,
    };
    let record = vec![0x5a_u8; RECORD_BYTES];

    probe.collecting(|| -> CliResult<()> {
        for _ in 0..GENERATIONS {
            // Reopening between generations is the restart the replay
            // sample is of: the file is at its cap, and the walk is a
            // process coming back to a state it left.
            let (mut journal, replay) =
                Journal::open_latest(&directory, stem, id).with_context(|| {
                    format!("the probe journal under {} opens", directory.display())
                })?;
            journal.observe_replay(hellas_rpc::observe::Timing::start(), replay.records.len());
            while !journal.at_soft_limit() {
                journal
                    .append(&record)
                    .context("the probe journal takes a record")?;
            }
            journal
                .rotate(&record)
                .context("the probe journal installs its successor")?;
        }
        Ok(())
    })?;

    // The probe's own journals are not a duty's, and leaving them under
    // the operator's root would be four files a real endpoint has to
    // step over on every enumeration.
    std::fs::remove_dir_all(&directory).with_context(|| {
        format!(
            "the probe journal directory {} is removed",
            directory.display()
        )
    })
}

/// Runs one bootstrap and writes the artifact it earned.
///
/// The digest printed at the end is what goes in `artifact.digest`: this
/// does not edit the operator's configuration, because a probe that
/// pinned its own output would be a node grading its own homework.
///
/// # Errors
///
/// The configuration and assumptions files, the journal workload, a term
/// that is neither observed nor assumed, and the write.
pub fn run_probe(options: ProbeOptions) -> CliResult<()> {
    let config_bytes = std::fs::read(&options.work_config)
        .with_context(|| format!("failed to read {}", options.work_config.display()))?;
    let assumed: AssumptionsFile = serde_json::from_slice(
        &std::fs::read(&options.assume)
            .with_context(|| format!("failed to read {}", options.assume.display()))?,
    )
    .with_context(|| format!("failed to parse {}", options.assume.display()))?;
    if options.machine.trim().is_empty() {
        bail!("--machine must name the machine this run measures");
    }
    for term in assumed.budget.keys() {
        if !TERMS.contains(&term.as_str()) {
            bail!("the assumptions file names {term}, which is not one of §4's budget terms");
        }
    }

    // The binary that measured, hashed as it sits on disk. A
    // measurement is a statement about a binary, and this is the only
    // way this process can say which one it is.
    let exe = std::env::current_exe().context("the running binary has a path")?;
    let binary = Digest::hash(
        &std::fs::read(&exe).with_context(|| format!("failed to read {}", exe.display()))?,
    );

    tracing::info!(
        root = %options.journal_root.display(),
        generations = GENERATIONS,
        "the bootstrap run begins; paid admission is not touched, because nothing here \
         countersigns",
    );
    let probe = Probe::open();
    measure_journals(&probe, &options.journal_root)?;
    let (artifact, unmeasured) = probe.into_artifact(
        options.machine.trim(),
        binary,
        Digest::hash(&config_bytes),
        &assumed,
    )?;

    let bytes = serde_json::to_vec_pretty(&artifact).context("the artifact encodes")?;
    std::fs::write(&options.out, &bytes)
        .with_context(|| format!("failed to write {}", options.out.display()))?;
    // On stdout and not through the log: the digest is this command's
    // answer, and an operator who has to pin it should not have to
    // raise a log level to be told what it is.
    println!("artifact.path: {}", options.out.display());
    println!(
        "artifact.digest: {}",
        hex::encode(Digest::hash(&bytes).as_bytes()),
    );
    if unmeasured.is_empty() {
        println!("assumed: none; every term rests on this run's own samples");
    } else {
        println!("assumed: {}", unmeasured.join(", "));
        tracing::warn!(
            terms = ?unmeasured,
            "this run observed none of these and wrote what you assumed; one assumed field \
             is a node that countersigns no new channel",
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
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
}
