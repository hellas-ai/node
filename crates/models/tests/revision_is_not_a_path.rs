//! A revision is a ref. It is not a path, and it is not a way to read
//! this machine's files.
//!
//! The hole: `hf-hub` resolves a non-sha revision by
//! `push("refs")`, `push(revision)`, `read_to_string`. `PathBuf::push`
//! with an absolute path *replaces* what came before it, and `..` walks
//! out of what remains — so a quote carrying
//! `org/model@/var/log/anything` made the node read that file, take its
//! contents as a commit name, and look for the model there. An
//! unauthenticated caller got arbitrary local reads, memory
//! amplification and an error oracle out of asking for a price.
//!
//! Two controls, because the claim is "refused *before* the read" and an
//! error alone would not show that:
//!
//! - the dependency really does resolve through the named file, asserted
//!   here directly against `hf-hub`;
//! - the same cache, quoted at its honest pinned revision, really does
//!   produce a manifest.
//!
//! So the refusal is not "there was nothing there". Everything was
//! there. The name was refused.

use std::path::{Path, PathBuf};

use hellas_models::{ModelAssetsError, Reach};
use hellas_rpc::Dtype;
use hellas_rpc::spec::ModelSpecError;
use hf_hub::{Cache, Repo, RepoType};

const MODEL: &str = "hellas-test/revision-traversal";
const FOLDER: &str = "models--hellas-test--revision-traversal";
/// Pinned, so the honest control resolves straight to its snapshot.
const COMMIT: &str = "c1899de289a04d12100db370d81485cdf75e47ca";

/// Small enough to build in microseconds, real enough that catgrad
/// produces a graph from it.
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
        "hellas-revision-traversal-{}-{name}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("scratch root");
    root
}

fn put(path: &Path, bytes: &[u8]) {
    std::fs::create_dir_all(path.parent().expect("a parent")).expect("dirs");
    std::fs::write(path, bytes).expect("write");
}

#[test]
fn a_revision_that_names_a_file_on_this_machine_is_refused_before_it_is_read() {
    let root = scratch("root");
    let hub = root.join("hub");
    let state = scratch("state");

    // SAFETY: one test in its own binary; nothing else reads these.
    unsafe {
        std::env::set_var("HF_HOME", &root);
        std::env::set_var("HF_HUB_CACHE", &hub);
        // Never the developer's own ~/.hellas, and never a cache they
        // happen to have adopted.
        std::env::set_var("HELLAS_STORE_DIR", &state);
    }

    let weights = vec![7_u8; 4096];
    let snapshot = hub.join(FOLDER).join("snapshots").join(COMMIT);
    put(&snapshot.join("config.json"), CONFIG.as_bytes());
    put(&snapshot.join("tokenizer.json"), b"{}");
    put(&snapshot.join("tokenizer_config.json"), b"{}");
    put(&snapshot.join("model.safetensors"), &weights);

    // A file outside the cache entirely, whose contents happen to name
    // the snapshot — so a resolver that reads it gets somewhere, and the
    // read is observable from its return value.
    let bait = root.join("bait");
    put(&bait, COMMIT.as_bytes());
    let absolute = bait.to_str().expect("utf-8 scratch path").to_string();

    // -- Control one. This is what the dependency does with the string,
    //    unchanged: it reads the file the revision names.
    assert_eq!(
        Cache::new(hub.clone())
            .repo(Repo::with_revision(
                MODEL.to_string(),
                RepoType::Model,
                absolute.clone(),
            ))
            .get("config.json"),
        Some(snapshot.join("config.json")),
        "hf-hub must resolve through the named file, or this test proves nothing",
    );

    // -- Control two. The same cache, at its honest revision, is
    //    quotable. So what refuses the quotes below is the name, not an
    //    empty disk.
    let honest = hellas_models::program_manifest(
        &format!("{MODEL}@{COMMIT}"),
        Dtype::F32,
        "cpu",
        Reach::Local,
    )
    .expect("a materialized model must be quotable");
    assert_eq!(honest.resolved_revision, COMMIT);

    // -- The claim.
    for revision in [
        absolute.as_str(),
        "../../..",
        "../../../../etc/passwd",
        "/etc/passwd",
    ] {
        let err = hellas_models::program_manifest(
            &format!("{MODEL}@{revision}"),
            Dtype::F32,
            "cpu",
            Reach::Local,
        )
        .expect_err("a revision that is a path must not be resolved");
        assert!(
            matches!(
                err,
                ModelAssetsError::Spec(ModelSpecError::InvalidRevision { .. }),
            ),
            "{revision:?} was refused, but not as a bad name: {err:?}",
        );
        // Not "come back when the operator has it" — there is nothing to
        // come back for. This name is wrong.
        assert_eq!(
            hellas_models::model_assets_wire_code(&err),
            hellas_wire::WireCode::InvalidArgument,
        );
    }

    // The id half of the same lesson. Neutralised today only by
    // `folder_name()` replacing `/` with `--`, which is a dependency's
    // private transform and not a property we own.
    for id in ["../../../etc", "/etc/passwd", "org--evil/model"] {
        assert!(
            matches!(
                hellas_models::program_manifest(id, Dtype::F32, "cpu", Reach::Local),
                Err(ModelAssetsError::Spec(ModelSpecError::InvalidId { .. })),
            ),
            "{id:?} must be refused as a name",
        );
    }

    let _ = std::fs::remove_dir_all(&root);
    let _ = std::fs::remove_dir_all(&state);
}
