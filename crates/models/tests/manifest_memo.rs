//! A quote must not rebuild a manifest it already built — and must
//! rebuild one whose files moved underneath it.
//!
//! `program_manifest` runs once per quote, and a quote is something any
//! peer that can dial this node may ask for. Per-file hashing is already
//! remembered by the store's fastresume records; what repeated was
//! everything else: the config parse, the catgrad graph build, the
//! tokenizer manifest encode.
//!
//! Memoizing that is not an ordinary cache. The `ContentId` this returns
//! is signed into an `execution_environment`, so a stale entry is a
//! provider committing to weights it does not have — a claim it loses
//! under the fraud game. Two halves of the key carry that weight, and
//! each is asserted here with a case that fails if it is dropped:
//!
//! - the resolved commit, proved by two revisions that share every blob
//!   and differ only in the snapshot they resolve through;
//! - the identity of every file read, proved by rewriting a shard in
//!   place and requiring a different manifest.

use std::path::{Path, PathBuf};

use hellas_models::Reach;
use hellas_rpc::{ContentId, Dtype};

/// Two commits of one repo. Pinned, so each resolves straight to its
/// snapshot directory and no `refs/` entry is involved.
const COMMIT_A: &str = "c1899de289a04d12100db370d81485cdf75e47ca";
const COMMIT_B: &str = "0e4b1f6a9c2d8b7e5a3f1c0d9b8a7e6f5d4c3b2a";
const MODEL: &str = "hellas-test/memoized-model";

/// Small enough to build in microseconds, real enough that catgrad
/// produces a graph from it — the manifest is a function of that graph.
const CONFIG: &str = r#"{
  "architectures": ["LlamaForCausalLM"],
  "hidden_size": 8,
  "intermediate_size": 16,
  "num_hidden_layers": 1,
  "num_attention_heads": 2,
  "num_key_value_heads": 2,
  "rope_theta": 10000.0,
  "rms_norm_eps": 1e-05,
  "tie_word_embeddings": true,
  "eos_token_id": 2,
  "vocab_size": 32,
  "max_position_embeddings": 128
}"#;

fn scratch(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "hellas-manifest-memo-{}-{name}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("scratch root");
    root
}

/// Writes a repo in the layout the HuggingFace client writes: bytes in
/// `blobs/`, and a snapshot of symlinks per commit pointing at them.
///
/// Both commits point at the *same* blobs, which is what the client does
/// when a revision changes nothing about a file — and what makes the
/// resolved commit the only thing distinguishing the two manifests.
fn hub_repo(root: &Path, commits: &[&str], files: &[(&str, &[u8])]) {
    let base = root.join("models--hellas-test--memoized-model");
    let blobs = base.join("blobs");
    std::fs::create_dir_all(&blobs).expect("blobs");
    for (name, content) in files {
        std::fs::write(blobs.join(format!("{name}-etag")), content).expect("blob");
    }
    for commit in commits {
        let snapshot = base.join("snapshots").join(commit);
        std::fs::create_dir_all(&snapshot).expect("snapshot");
        for (name, _) in files {
            std::os::unix::fs::symlink(
                PathBuf::from("../../blobs").join(format!("{name}-etag")),
                snapshot.join(name),
            )
            .expect("symlink");
        }
    }
}

fn blob(root: &Path, name: &str) -> PathBuf {
    root.join("models--hellas-test--memoized-model")
        .join("blobs")
        .join(format!("{name}-etag"))
}

#[test]
fn a_manifest_is_built_once_and_rebuilt_whenever_its_answer_could_differ() {
    let cache = scratch("hf");
    let state = scratch("state");

    // `Cache::from_env` reads `$HF_HOME/hub`, which is the directory the
    // HuggingFace client would have written into.
    let hub = cache.join("hub");

    // SAFETY: one test in its own binary; nothing else reads these.
    unsafe {
        std::env::set_var("HF_HOME", &cache);
        // Never the developer's own ~/.hellas, and never a cache they
        // happen to have adopted.
        std::env::set_var("HELLAS_STORE_DIR", &state);
    }

    let weights = vec![7_u8; 4096];
    hub_repo(
        &hub,
        &[COMMIT_A, COMMIT_B],
        &[
            ("config.json", CONFIG.as_bytes()),
            ("tokenizer.json", b"{}"),
            ("tokenizer_config.json", b"{}"),
            ("model.safetensors", &weights),
        ],
    );

    let at = |commit: &str| format!("{MODEL}@{commit}");
    let manifest = |spec: &str, dtype: Dtype, backend: &str| {
        hellas_models::program_manifest(spec, dtype, backend, Reach::Local)
            .expect("a materialized model is quotable")
    };

    // -- Built once.
    let first = manifest(&at(COMMIT_A), Dtype::F32, "cpu");
    assert_eq!(first.resolved_revision, COMMIT_A);
    assert_eq!(first.weights, vec![ContentId::hash(&weights)]);
    let stats = hellas_models::program_manifest_memo_stats();
    assert_eq!(
        (stats.hits, stats.misses, stats.entries),
        (0, 1, 1),
        "the first manifest for a model is built, and remembered",
    );

    // -- Answered from the memo the second time.
    let again = manifest(&at(COMMIT_A), Dtype::F32, "cpu");
    assert_eq!(again, first, "the memo must answer with the same manifest");
    let stats = hellas_models::program_manifest_memo_stats();
    assert_eq!(
        (stats.hits, stats.misses, stats.entries),
        (1, 1, 1),
        "the second manifest for the same model must not be rebuilt",
    );

    // -- Anything the manifest is a function of is a different question.
    let f16 = manifest(&at(COMMIT_A), Dtype::F16, "cpu");
    assert_eq!(f16.numeric_profile, "f16");
    assert_ne!(f16.graph, first.graph, "a dtype is a different program");
    let accelerated = manifest(&at(COMMIT_A), Dtype::F32, "accelerated");
    assert_eq!(accelerated.backend_profile, "accelerated");
    let stats = hellas_models::program_manifest_memo_stats();
    assert_eq!(
        (stats.hits, stats.misses, stats.entries),
        (1, 3, 3),
        "dtype and backend profile must each miss",
    );

    // -- The resolved commit. Both revisions share every blob, so every
    //    file identity is the same one; only the snapshot they resolved
    //    through differs, and the manifest says so.
    let other_commit = manifest(&at(COMMIT_B), Dtype::F32, "cpu");
    assert_eq!(
        other_commit.resolved_revision, COMMIT_B,
        "a manifest must name the commit its files resolved through",
    );
    assert_eq!(
        other_commit.weights, first.weights,
        "the two revisions are the same bytes, so the same content ids",
    );
    let stats = hellas_models::program_manifest_memo_stats();
    assert_eq!(
        (stats.hits, stats.misses, stats.entries),
        (1, 4, 4),
        "a second commit of the same bytes is a different manifest",
    );

    // -- The files. A shard rewritten in place is a different model,
    //    however unchanged its name and revision are.
    let rewritten = vec![9_u8; 8192];
    std::fs::write(blob(&hub, "model.safetensors"), &rewritten).expect("rewrite the shard");
    let after_rewrite = manifest(&at(COMMIT_A), Dtype::F32, "cpu");
    assert_eq!(
        after_rewrite.weights,
        vec![ContentId::hash(&rewritten)],
        "the manifest must commit to the bytes that are on this disk now",
    );
    assert_ne!(
        after_rewrite, first,
        "a rewritten shard must not be answered from the memo",
    );
    let stats = hellas_models::program_manifest_memo_stats();
    assert_eq!(
        (stats.hits, stats.misses, stats.entries),
        (1, 5, 5),
        "a file that changed is a miss",
    );

    // -- Purgeable, and purging costs only the rebuild.
    hellas_models::forget_program_manifests();
    let stats = hellas_models::program_manifest_memo_stats();
    assert_eq!(stats.entries, 0, "purging must forget everything");
    let after_purge = manifest(&at(COMMIT_A), Dtype::F32, "cpu");
    assert_eq!(
        after_purge, after_rewrite,
        "a rebuilt manifest must be the manifest it replaced",
    );
    let stats = hellas_models::program_manifest_memo_stats();
    assert_eq!(
        (stats.hits, stats.misses, stats.entries),
        (1, 6, 1),
        "after a purge the next manifest is built again",
    );

    let _ = std::fs::remove_dir_all(&cache);
    let _ = std::fs::remove_dir_all(&state);
}
