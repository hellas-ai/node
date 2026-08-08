# 05 — Stop rebuilding the program manifest on every quote

## What is wrong

`hellas_models::program_manifest` is called once per quote
(`crates/executor/src/state.rs`). Verified: there is no memo — the only
`OnceLock` in `assets.rs` holds the store instance, not any manifest.

Per-file *hashing* is now avoided by fastresume, which was the
multi-gigabyte problem. But everything else still repeats per quote:

- `config.json` read and parsed;
- the catgrad graph built and `serde_json::to_vec`'d;
- the tokenizer manifest re-encoded;
- `model.safetensors.index.json` read and parsed.

Worse, a single `quote_prompt` request does this **twice** — once in
`ModelAssets::load` and once in `program_manifest` — and via the gateway
a third time.

## Done looks like

A manifest memo keyed on

    (model_id, resolved_commit_sha, dtype, backend_profile, VERSION+GIT_REV)

The resolved sha must be read from the ref file, **never** the requested
revision: `main` moves. `VERSION`/`GIT_REV` belong in the key because
`build` is derived from them.

## Watch out for

This is not merely a performance cache. The `ContentId` it returns lands
in the signed quote's `execution_environment`. A stale entry means the
executor cryptographically commits to weights it does not have — a
losable claim under the fraud game. Key conservatively, and make it
purgeable.
