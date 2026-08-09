# 04 — A running node must use what `adopt` learned

**Landed.** What follows is the problem as found and the answer taken.

## What was wrong

Verified at the time: nothing in `crates/executor` or the serve path
referenced `fastresume` or `ContentStore::records()`.

So `hellas store adopt` persisted its records and **a running node never
read them**. The node re-hashed every file on first use, which made
`adopt` close to pointless in production — the opposite of its entire
purpose. Measured at 647 ms cold versus 549 µs warm on a 29-blob cache,
all of that benefit accruing to a CLI process that exited immediately
afterwards.

## What landed

- `hellas serve` loads the record at startup and saves it when the
  shutdown signal arrives, before the shutdown timeout that can end in
  `process::exit`.
- The path is `--store-records`, defaulting to
  `$HELLAS_STORE_DIR/fastresume.bin`, else
  `$HOME/.hellas/store/fastresume.bin` — beside the other Hellas state,
  never inside the HuggingFace cache, which is not ours.
- `crates/models/tests/fastresume_in_the_node.rs` proves the record is
  *used* rather than merely read: the record handed to the node names an
  id the file's bytes do not have, so answering with it is proof no
  hashing happened. A stopwatch would have proved nothing.

What makes this worth anything is that adoption hashes `blobs/` while a
quote resolves through `snapshots/`: they are one inode, so the record
adoption wrote is the record the manifest path hits.

## Decisions taken rather than avoided

- **Two processes writing one record file.** `save` is a write-and-
  rename, so the later writer wins whole and the earlier one's work is
  lost rather than the file corrupted. Losing it costs a re-hash, which
  is the cost of not having adopted at all.
- **Saving only at shutdown.** A node killed rather than signalled loses
  what it hashed since start. The same re-hash, and the same bound.
- **Loading is not trusting.** A loaded record is still validated
  against the live file's identity, which is what keeps the file a cache
  of work rather than a source of truth. Tested with a record whose file
  has since changed.
