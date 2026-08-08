# 04 — A running node must use what `adopt` learned

## What is wrong

Verified: nothing in `crates/executor` or the serve path references
`fastresume` or `ContentStore::records()`.

So `hellas store adopt` persists its records to
`~/.hellas/store/fastresume.bin`, and **a running node never reads
them**. The node re-hashes every file on first use.

This makes `adopt` close to pointless in production, which is the
opposite of its entire purpose. It was measured at 647 ms cold versus
549 µs warm on a 29-blob cache — all of that benefit currently accrues
to the CLI process that exits immediately afterwards.

## Done looks like

- The node loads the persisted record at startup and saves it on a
  sensible trigger (shutdown, or after adopting).
- The record path is configurable and defaults beside other Hellas
  state, never inside the HuggingFace cache — that cache is not ours.
- A test that a node started after `adopt` does no hashing for an
  adopted file.

## Watch out for

- Two processes writing one record file. `save` is already atomic
  (temp file + rename), so the loser's work is lost rather than the file
  corrupted — acceptable, but decide it deliberately.
- Loading is not trusting: a loaded record is still validated against
  the live file's identity. Keep that. It is what makes the record a
  cache of work rather than a source of truth.
