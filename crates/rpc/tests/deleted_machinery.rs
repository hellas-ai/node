//! The machinery this slice deleted has no reachable caller.
//!
//! The one-job profile replaces the reusable-slot machinery: nonce
//! sequences, the multi-job paid-work set, the identity-wide counterparty
//! loss ledger and its second journal, the interrupted two-file terminal,
//! the loss-of-a-job cause rule, and the paid-twice error the paid-work
//! set alone could construct. None of it is behind a feature or a
//! `cfg` — it is gone — and the proof that it is gone rather than merely
//! unused is that its names appear nowhere in this crate's production
//! source. A caller that could reach it would have to name it, and
//! nothing does.

use std::fs;
use std::path::Path;

/// The identifiers the deleted machinery was reached through. Each named
/// exactly one deleted thing, so a single occurrence anywhere in `src`
/// would be a reachable caller.
const DELETED: &[&str] = &[
    "CounterpartyLoss",
    "paid_work_ids",
    "finish_interrupted_ending",
    "next_proposal_nonce",
    "LossTotals",
    "loss_of",
    // `PaidWorkError::Duplicate` — its only constructor left with
    // `paid_work_ids`, so the variant went with it. The brace keeps
    // this from matching the unrelated `DuplicateFunding` and wire
    // `Duplicate` status.
    "Duplicate {",
];

#[test]
fn the_deleted_machinery_is_named_nowhere_in_production_source() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut offenders = Vec::new();
    scan(&src, &mut offenders);
    assert!(
        offenders.is_empty(),
        "deleted machinery is still named in production source: {offenders:?}",
    );
}

fn scan(dir: &Path, offenders: &mut Vec<String>) {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) => panic!("the source tree is readable at {}: {error}", dir.display()),
    };
    for entry in entries {
        let path = match entry {
            Ok(entry) => entry.path(),
            Err(error) => panic!("a source entry is readable: {error}"),
        };
        if path.is_dir() {
            scan(&path, offenders);
            continue;
        }
        if path.extension().is_none_or(|ext| ext != "rs") {
            continue;
        }
        let text = match fs::read_to_string(&path) {
            Ok(text) => text,
            Err(error) => panic!("{} is readable: {error}", path.display()),
        };
        for name in DELETED {
            if text.contains(name) {
                offenders.push(format!("{} names `{name}`", path.display()));
            }
        }
    }
}
