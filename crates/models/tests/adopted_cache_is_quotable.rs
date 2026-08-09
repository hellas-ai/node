//! `hellas store adopt` must make a model quotable.
//!
//! The store indexes by content id; the quote gate resolves by
//! HuggingFace cache path. Nothing joined them, so adopting a cache and
//! then watching quotes refuse for a model in it was two subsystems each
//! being individually correct about a different disk — the worst kind of
//! wrong, because neither one logs anything.
//!
//! The claim here is the whole of the convergence, end to end and
//! through the real code paths: a cache the environment does not name,
//! adopted, and then quoted for.
//!
//! The control is the same call before adopting. Without it the test
//! would pass just as happily if the gate had started resolving against
//! every directory on the machine.

use std::path::{Path, PathBuf};

use hellas_models::{ModelAssetsError, Reach};
use hellas_rpc::{ContentId, Dtype};
use hellas_store::ContentStore;
use hellas_store::hf_cache::HfCache;

/// Pinned, so resolution names a snapshot directly and no `refs/` entry
/// is involved.
const COMMIT: &str = "c1899de289a04d12100db370d81485cdf75e47ca";
const MODEL: &str = "hellas-test/adopted-model";

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
        "hellas-adopted-quotable-{}-{name}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("scratch root");
    root
}

/// Writes a repo in the layout the HuggingFace client writes: bytes in
/// `blobs/`, and a snapshot of symlinks pointing at them. Adoption walks
/// the blobs; the quote gate resolves the snapshot. That they meet at
/// one inode is what makes adopting worth anything.
fn hub_repo(root: &Path, files: &[(&str, &[u8])]) {
    let base = root.join("models--hellas-test--adopted-model");
    let blobs = base.join("blobs");
    let snapshot = base.join("snapshots").join(COMMIT);
    std::fs::create_dir_all(&blobs).expect("blobs");
    std::fs::create_dir_all(&snapshot).expect("snapshot");
    for (name, content) in files {
        let etag = format!("{name}-etag");
        std::fs::write(blobs.join(&etag), content).expect("blob");
        std::os::unix::fs::symlink(
            PathBuf::from("../../blobs").join(&etag),
            snapshot.join(name),
        )
        .expect("symlink");
    }
}

#[test]
fn a_model_in_an_adopted_cache_becomes_quotable() {
    let environment_cache = scratch("hf");
    let adopted_cache = scratch("elsewhere");
    let state = scratch("state");

    // SAFETY: one test in its own binary; nothing else reads these.
    unsafe {
        // The cache this machine's HuggingFace client would use. Empty:
        // the model is deliberately somewhere the environment does not
        // name, which is exactly the case `--cache PATH` creates.
        std::env::set_var("HF_HUB_CACHE", &environment_cache);
        std::env::set_var("HF_HOME", &environment_cache);
        // Never the developer's own ~/.hellas.
        std::env::set_var("HELLAS_STORE_DIR", &state);
    }

    let weights = vec![7_u8; 4096];
    hub_repo(
        &adopted_cache,
        &[
            ("config.json", CONFIG.as_bytes()),
            ("tokenizer.json", b"{}"),
            ("tokenizer_config.json", b"{}"),
            ("model.safetensors", &weights),
        ],
    );

    let spec = format!("{MODEL}@{COMMIT}");

    // -- The control. Before adopting, this cache is not this node's.
    let refused = hellas_models::program_manifest(&spec, Dtype::F32, "cpu", Reach::Local)
        .expect_err("a cache nobody adopted is not this node's");
    assert!(
        matches!(refused, ModelAssetsError::NotMaterialized { .. }),
        "expected a not-materialized refusal, got {refused:?}",
    );

    // -- What `hellas store adopt` does: index the blobs, and record
    //    where they were, so later processes resolve against them too.
    let store = ContentStore::new();
    let cache = HfCache::new(&adopted_cache);
    let adopted = cache.adopt_into(&store).expect("adopt");
    assert_eq!(adopted, 4, "four blobs");
    hellas_store::hf_cache::remember_adopted(
        &state.join("adopted-caches"),
        std::path::Path::new(&adopted_cache),
    )
    .expect("remember the root");

    // -- The claim.
    let manifest = hellas_models::program_manifest(&spec, Dtype::F32, "cpu", Reach::Local)
        .expect("a model in an adopted cache must be quotable");

    assert_eq!(
        manifest.resolved_revision, COMMIT,
        "the manifest must name the snapshot it resolved through",
    );
    assert_eq!(manifest.weights, vec![ContentId::hash(&weights)]);
    assert_eq!(manifest.config, ContentId::hash(CONFIG.as_bytes()));
    assert_eq!(manifest.numeric_profile, "f32");
    assert_eq!(manifest.backend_profile, "cpu");

    // The two subsystems now agree about this model's bytes: the id the
    // manifest commits to is one the store already holds. Presence is
    // still not integrity — the store answered by hashing the file, not
    // by believing the path.
    let id = manifest.weights[0].digest();
    assert!(
        store.have(id),
        "the store must hold the content the manifest commits to",
    );

    let _ = std::fs::remove_dir_all(&environment_cache);
    let _ = std::fs::remove_dir_all(&adopted_cache);
    let _ = std::fs::remove_dir_all(&state);
}
