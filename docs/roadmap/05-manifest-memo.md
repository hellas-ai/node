# 05 — Stop rebuilding the program manifest on every quote

**Landed.** What follows is the problem as found and the answer taken.

## What was wrong

`hellas_models::program_manifest` was called once per quote
(`crates/executor/src/state.rs`). Verified at the time: there was no
memo — the only `OnceLock` in `assets.rs` held the store instance, not
any manifest.

Per-file *hashing* was already avoided by fastresume, which was the
multi-gigabyte problem. But everything else still repeated per quote:

- `config.json` read and parsed;
- the catgrad graph built and `serde_json::to_vec`'d;
- the tokenizer manifest re-encoded;
- `model.safetensors.index.json` read and parsed.

Worse, a single `quote_prompt` request did this **twice** — once in
`ModelAssets::load` and once in `program_manifest` — and via the gateway
a third time.

## What landed

A process-wide memo in `crates/models/src/assets.rs`, keyed on

    (model_id, resolved commit, dtype, backend_profile, build,
     identity of every file read)

- The commit is read from the snapshot the files resolved *through*,
  never from the requested revision: `main` moves. It earns its place in
  the key on its own account, because two revisions can share every blob
  and differ only in which commit the manifest names.
- File identity is `hellas_store::fastresume::FileIdentity` — the same
  `(dev, ino, size, mtime_ns, ctime_ns)` the store checks before reusing
  a hash, now public so there is one definition of "the same file" and
  not two.

What is *not* skipped on a hit is resolving and stat-ing the files. That
is what makes the memo safe: a model that stopped being here, or a shard
rewritten in place, is a miss rather than a stale signature.

`forget_program_manifests()` empties it — the "force recheck" the
fastresume records have, for the same reason. `program_manifest_memo_stats()`
reports hits, misses and entries.

## Why the key is conservative

This is not merely a performance cache. The `ContentId` it returns lands
in the signed quote's `execution_environment`. A stale entry means the
executor cryptographically commits to weights it does not have — a
losable claim under the fraud game.

`crates/models/tests/manifest_memo.rs` asserts both halves with cases
that fail when either is dropped from the key: two revisions sharing
every blob (the commit), and a shard rewritten in place (the files).

## What this did not close

`ModelAssets::load` still parses the config and builds its own catgrad
graph on every call, so a `quote_prompt` still does that work twice and
three times through the gateway. The memo removes the repeat *across*
quotes, not the duplication *within* one.
