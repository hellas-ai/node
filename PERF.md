# Hellas Kernel Performance Lock-Ins

This document captures the performance-critical design decisions for the Hellas
kernel that must be locked in *before* substantial implementation work happens.
Several of these are not optimizations — they are structural choices that, if
deferred, become impossible or extremely painful to retrofit.

The model: a **deterministic, pure-function state machine** fed an ordered
command log by Minimmit consensus, with as much per-block work parallelized as
possible while preserving determinism, replica-byte-identity, and DST testability.

The reference systems are TigerBeetle (single-purpose state machine, static
allocation, deterministic simulation testing), Sui (object-centric data model
with declared inputs and a single-owner fast path), Aptos (BlockSTM optimistic
parallel execution), Monad/MegaETH (async I/O during execution as the
high-throughput limit), and Solana (declared account access for static
scheduling).

Items are tagged:

- **[LOCK]** Structural — must be settled now; very hard to retrofit.
- **[OPT]** Best-practice — implement now, but improvable later without API break.
- **[DEFER]** Note for future work — write down the decision so it isn't lost.

---

## Foundations

### 1. The kernel is a pure function `(state, batch) → (state', diff)` [LOCK]

The kernel module performs no I/O, has no clocks, makes no syscalls, spawns no
tasks, and never panics on input it cannot validate. Block height comes from
the block header, not from `SystemTime::now()`. Randomness, if needed, comes
from a seed in the block, not from `getrandom`.

Why: this is the precondition for every other performance and correctness
property. A kernel that calls `tokio::spawn` or reads the system clock cannot
be deterministically replayed, cannot be DST-tested, cannot be parallelized
safely, and cannot have predictable tail latency.

This must be a structural lock-in because once *any* impure call sneaks into
the kernel, every layer above starts depending on the side effect, and pulling
it out becomes a cross-cutting refactor.

Rust shape: the kernel crate compiles with `#![no_std]`-discipline (use `std`
for ergonomics, but no I/O, no `std::time`, no `std::sync::Mutex`, no
`std::thread`). Communication with the outside world happens via channels
owned by callers; the kernel only sees the channel as `&[Tx]` going in and
`&[Diff]` coming out. commonware-runtime/deterministic is the test harness; the
kernel itself doesn't see a runtime.

### 2. Pre-allocate, never free [OPT]

Size every buffer, every queue, every collection at boot from configuration.
Reuse buffers between blocks (`Vec::clear()`, not drop-and-reallocate). Object
pools for hot-path types (Merkle proofs during bisection, signature
verification scratch space, transaction decode buffers).

Why: TigerBeetle's static allocation eliminates allocator-induced tail latency
and makes the system crash-only — if you couldn't allocate at boot, you cannot
run out of memory at runtime. For Hellas, the relevant property is *predictable*
latency under load, which matters for the 366ms target.

Rust shape:
- `bumpalo` arena allocators per-block, reset between blocks.
- `arrayvec::ArrayVec` / `smallvec::SmallVec` for bounded structures.
- Pooled `Vec<u8>` buffers via a typed pool (not ad-hoc) for transaction decode.
- Avoid `String` in the kernel: use `&[u8]` or `bytes::Bytes`.
- `Box<dyn Trait>` is a smell in the hot path. Concrete enums dispatch faster
  and don't allocate.

### 3. Pack blocks aggressively [OPT]

Block size, not block rate, is the throughput dial. Minimmit gives ~220ms per
block; whether that's 100 tx/s or 100K tx/s depends entirely on what fits
inside the block. The consensus protocol cost is per-block; per-tx overhead
should approach zero.

Why: TigerBeetle hits 1M+ TPS by amortizing consensus over batches of ~8K
events per request. Skipping this lesson means accidentally shipping a
"per-block leader bottleneck" that can't be optimized away later.

Concrete:
- Length-prefixed transaction array as block body. Fixed-size headers, no
  nested `Vec` types in wire form.
- Erasure-coding at block level (already in the whitepaper for bandwidth
  distribution) is orthogonal to and complementary with packing.
- Throughput metric is bytes-per-block (or transitions-per-block), not tx/s.

### 4. Move signature verification off the critical path [OPT]

When a block arrives, dispatch all signature verifications to a worker pool in
parallel, *before* the kernel applies anything. The kernel reads from a
"verified" channel and trusts the cryptographic preconditions.

Why: in most consensus systems crypto is the dominant per-tx CPU cost. Putting
it on the consensus thread caps throughput at one core's signature rate.

Specifics:
- BLS aggregate verification: one pairing for the entire block's vote set.
- Batch verification for individual transaction signatures (BLS supports this
  natively via `blst`; for secp256r1 / Ed25519, batch with `ed25519_dalek`'s
  batch API or equivalent).
- `commonware-parallel` with `Rayon` strategy is the right primitive — it lets
  the *same* code path run sequentially under DST and in parallel in production.
- Verification failures fail the entire block (not the individual tx) — this
  is a deliberate simplification: a leader that proposes a block with one bad
  signature has misbehaved, and partial inclusion is a Byzantine vector.

### 5. WAL + checksummed state via commonware-storage [LOCK on the *interface*, OPT on internals]

Persistence is delegated to `commonware-storage` primitives:

- **`commonware-storage::journal`** for the WAL — this is the source of truth.
- **`commonware-storage::qmdb`** for state — Merkleized authenticated DB,
  designed for blockchain workloads.
- **`commonware-storage::bmt` / `merkle::mmr`** for state commitments where
  needed.
- **`commonware-runtime::iouring`** under it on Linux — io_uring is already
  there.

The lock-in is *the interface* between kernel and storage: the kernel produces
a `Diff` (a list of object create/delete/update operations), and the storage
layer applies it. The kernel does not call `write` or `fsync` itself. This is
both a determinism property (kernel is pure) and a separation-of-concerns
property (storage layer can be swapped under the kernel without protocol
changes).

The internals — which LSM, which on-disk format, what compaction strategy —
are commonware's problem, not ours. Verify what QMDB gives you (it's likely
solving most of this) before reinventing.

Disciplines that should hold regardless of the storage backend:
- One fsync per consensus commit (not per tx).
- BLAKE3 checksum on every on-disk block, verified on read.
- Crash recovery replays the WAL up to the last persisted height.

### 6. Fixed-size, zero-copy wire format [OPT]

Hot-path types are `#[repr(C)]` with fixed-size fields, parseable by pointer
cast (modulo endianness). No JSON, no protobuf-with-defaults, no
`serde_json::Value` in the kernel.

Why: parse cost per message should be sub-microsecond. dag-cbor is appropriate
for protocol-level commitments (cross-implementation byte-identity), but the
internal wire format between Hellas nodes can be much tighter.

Specifics:
- `bytemuck::Pod` for fixed-size types (`ObjectId`, `Digest`, `u64` fields).
- `postcard` or `bincode` (with fixed integer widths) for variable-shape types.
- Reserve dag-cbor for receipt bodies and other things that need
  byte-identical hashing across implementations.
- Use `commonware-codec` where it provides the right primitive — it already
  handles fixed-width types and length-prefixed arrays.

### 7. Pipeline consensus against persistence [OPT]

Three stages, each on its own task:

```
[Network] → Verified → Applied → Persisted
```

Don't block round N+1 on round N's fsync. Consensus can vote on round N+1
while the storage layer is still flushing N. Crash recovery replays from the
WAL up to the last persisted height; anything past that is recoverable from
peers.

Why: fsync latency (low ms) is comparable to consensus latency (~hundred ms),
so a naive serial pipeline burns an entire round per block.

Rust shape: SPSC channels between stages (commonware-runtime gives you these,
or `crossbeam`). Backpressure: bounded channels with a configured depth, so a
slow disk can't OOM the verified-but-not-applied buffer.

### 8. Tiny opcode set, tight match-dispatch [LOCK]

The kernel matches on a small fixed enum of operations. From the whitepaper
spec, that's roughly:

- `CoinTransfer` (UTXO movement)
- `HyperedgeOpen`
- `HyperedgeClose::Agree`
- `HyperedgeClose::Timeout`
- `HyperedgeClose::Proof`
- `HyperedgeFinalizeTimeout`

Different `HyperedgeKind`s (Optimistic, future TEE variants) are enum variants
inside a single concrete `ValidityProof` type — *not* trait objects.

Why: branch prediction loves a small, fixed match table. Dynamic dispatch
through a `Box<dyn Validator>` adds an indirect branch and prevents inlining of
the fast paths. This is also a soft form of API discipline: each new variant is
a deliberate decision visible to every reader of `kernel.rs`, not a dependency
injection that hides growth.

This is a [LOCK] because retrofitting from `dyn Trait` to a closed enum is
straightforward; retrofitting from a closed enum to `dyn Trait` for some hot-
path "extensibility" is what people accidentally do under deadline pressure
and never undo.

---

## Parallel Execution

This section is where the user's instruction "lock it in early so we don't
accidentally break it" matters most. Sui-style parallel execution is *not* a
later optimization — the transaction structure, state commitment scheme, and
state storage all have to support it from day one.

### 9. Every transaction declares its read and write sets [LOCK]

Every transaction enumerates the `ObjectId`s it consumes (read set / inputs)
and the `ObjectId`s it produces (write set / outputs) *in the transaction
itself*. The kernel must reject any transaction that touches an object it did
not declare.

For UTXO transitions this is essentially free — the inputs to a `CoinTransfer`
*are* the read set, and the outputs *are* the write set. For `HyperedgeOpen`,
inputs are `client_coins ∪ provider_coins`, output is the new `Edge`. For
`HyperedgeClose`, input is the `Edge`, outputs are the resulting `Coin`s.

Why this is a [LOCK]: parallel execution requires building a conflict graph
*before* execution, and you can only build that graph if every transaction
declares what it touches. If we accidentally allow a transaction whose access
set depends on its inputs (e.g., a generic "compute" transaction that reads a
runtime-determined object), we forfeit static parallelism for that path
forever, and the only way back is a hard fork.

The discipline that enforces this: the kernel function for each opcode takes
the *referenced objects* as arguments, not a `&State`. Pass the resolved
inputs, return the produced outputs, never reach into ambient state. This
makes it syntactically impossible to read undeclared state. Schedule and
prefetch happen outside the kernel.

### 10. Single-owner fast path [LOCK]

Coins owned by a single key, with no shared-object dependencies, can be
transferred without full Minimmit consensus — just a Byzantine consistent
broadcast (BCB) producing 2f+1 signatures, exactly as the whitepaper already
specifies for channel opening (l1.tex §"Hellas State Channels").

This is the FastPay / Sui owner-object model. It's the single largest
performance lever in the system: simple payments don't pay consensus latency
or block-inclusion delay, and the validator's consensus path stops being a
bottleneck for the long tail of small transfers.

Why this is a [LOCK]: the transaction *structure* must distinguish "owner-only
inputs" from "shared inputs" up front. Sui made this a first-class type
distinction (`Owned` vs `Shared` objects). For Hellas:

- `Coin` is owner-only by default — single settlement key, no shared state.
- `Edge` is shared by definition — two parties, either can act, and timeout
  paths can be initiated by either side.
- A transaction that consumes only `Coin`s and produces only `Coin`s is
  *eligible* for the fast path.
- A transaction that touches an `Edge` *must* go through full consensus.

Lock the type-level distinction in now. Adding owner/shared classification to
`Coin` and `Edge` later requires a transaction-format break.

The fast path itself can be implemented v2; what matters now is that the
transaction structure doesn't preclude it.

### 11. No implicit shared state [LOCK]

No global per-tx counters. No chain-wide nonce. No global Merkle root that's
incrementally updated as each transaction applies. No "fee distribution" pass
that touches every transaction's outputs after they're produced.

Why: each of these creates an *implicit* dependency between every pair of
transactions, collapsing the parallel-execution conflict graph into a single
chain.

Specifically:
- Sequence numbers are per-object (per-Coin, per-Edge), not per-chain.
- The state-root computation happens *at block boundary*, not per-tx (see §14).
- Network fees are aggregated at block boundary (e.g., into a single
  validator-payout output), not per-transaction. If a transaction-level fee
  must be charged, the fee output is owned by the transaction sender (then
  collected at end of block) — not written into a shared "fee pool" object.
- Block rewards / inflation, if any, are produced as a single block-level
  output by the kernel after applying transactions. The mint-rule is part of
  the block-application function, not a per-transaction operation.

Identifying these accidental dependencies is hard once they're embedded in the
protocol. The discipline: every protocol-introducing PR must answer "does this
add an object that every transaction in a block reads or writes?" If yes, it
needs an architectural rethink.

### 12. State storage supports concurrent reads [LOCK on the property, OPT on the implementation]

The state structure must allow concurrent point lookups across worker threads
during parallel execution. Worker threads execute non-conflicting transactions
in parallel, each reading its declared input set; if those reads serialize on
a `RwLock` over the entire state, we get sequential execution dressed up as
parallel.

Two patterns work, MVCC and sharded:

- **MVCC (Aptos BlockSTM-style)**: each object carries a version. A reader
  pins a snapshot version; writes produce new versions. No reader blocks a
  writer or vice versa. This is what BlockSTM does for arbitrary EVM workloads
  where read sets aren't declared.
- **Sharded (Solana Sealevel-style)**: state partitioned by `ObjectId`, each
  shard has a single owner thread. Conflict-free transactions in the block
  are routed to non-overlapping shard subsets and run in parallel.

For Hellas, since read/write sets are declared (§9), sharding is the simpler
model — the conflict-graph scheduler can directly route transactions to
disjoint shard owners. MVCC adds machinery we don't need.

`commonware-storage::qmdb` likely provides the right concurrency model;
verify before reinventing. The lock-in is the *property* — the kernel must
not assume single-threaded state access.

### 13. Async state I/O during execution (Monad/MegaETH lesson) [DEFER, but plan for it]

At very high TPS, the bottleneck isn't CPU — it's state I/O. State sets get
larger than RAM; LSM lookups go to disk; a single missed cache line stalls a
worker for microseconds. Monad's MonadDB and MegaETH both treat this as the
real performance frontier and use async I/O during execution.

The pattern: a worker that needs an object issues an async read, parks the
transaction, picks up the next non-conflicting transaction, and resumes the
parked one when its data lands.

This is [DEFER] for v1 — not because it's premature, but because (a) hot
state will fit in RAM at our expected v1 scale, and (b) implementing it
requires the kernel to be structured around explicit "fetch this object,
suspend, resume" rather than "here's the resolved state, run."

The lock-in implication for v1: don't paint into a corner where async state
I/O is impossible. That means the kernel function for each opcode should be
written as if its inputs were *passed in*, not fetched from a global `&State`.
This dovetails with §9. As long as every opcode handler has the form

```rust
fn apply_open(inputs: &OpenInputs, terms: &OpenTerms) -> OpenOutputs;
```

with no implicit fetches, layering async prefetch in front later is a
scheduler change, not a kernel change.

### 14. Parallel-friendly state commitment [LOCK]

The post-block state root must be computable in parallel from the per-object
diffs. *Do not* implement state commitment as "rehash a single global Merkle
tree after every transaction."

Patterns that work:

- **Per-object commitments + accumulator** (Sui-style): each object carries
  its own commitment; the global state root is an accumulator over the set of
  live object commitments. Updates are local; the accumulator update is
  parallelizable.
- **MMR / MMB** (commonware-storage provides both): merkle mountain ranges
  support efficient append; merkle mountain belts handle updates. Both can be
  computed in parallel over a block's diffs.
- **QMDB** (commonware-storage): authenticated state DB with merkle proofs
  built in; designed for blockchain workloads. This is likely the path of
  least resistance.

Pattern that *breaks* parallelism: a single Sparse Merkle Tree updated
linearly per transaction, with the root recomputed each tx. This forces
sequentialization no matter how parallel the execution.

Lock this in by deciding the commitment scheme now, before the kernel exposes
`StateRoot` as a return type that callers depend on.

### 15. Deterministic conflict resolution [LOCK]

When the conflict-graph scheduler decides which transactions can run in
parallel, the resulting order *and* the result of any conflict must be
byte-for-byte identical across replicas. Two patterns:

- **Static schedule per block**: the scheduler builds the conflict graph from
  the block's transactions, produces a deterministic execution schedule (e.g.,
  Kahn's topological sort with ties broken by block index), and every replica
  runs the same schedule. This is what we want with declared read/write sets.
- **Optimistic with deterministic abort rule**: if speculative execution
  conflicts, the lower-block-index transaction wins; the loser is re-executed.
  Required when read/write sets aren't declared (Aptos BlockSTM); not
  required for us.

Lock-in: the scheduling algorithm and tie-breaking rule are part of the
protocol, not the implementation. Two replicas using different "valid"
schedules produce different state roots and the chain forks. Document the
exact algorithm (e.g., "Kahn's algorithm with FIFO queue ordered by block
index") in the spec, not just in code.

### 16. Don't block parallelism with the validator's own bookkeeping [OPT]

Things that look harmless and aren't:
- Per-tx logging that goes through a single `Logger` mutex.
- Metrics counters that are updated per-tx via `Mutex<HashMap>`.
- A single `tracing` span per block that nests every tx span — this can be
  fine, but watch for serialization through a global subscriber.

Use lock-free counters (`AtomicU64`), per-thread metrics aggregated at block
boundary, and per-thread logging buffers flushed at block boundary. The point
is: "we made the kernel parallel but we serialize on metrics" is a real
failure mode.

---

## Reference systems and what specifically transfers

| System | Primary lesson | Where it applies |
|---|---|---|
| TigerBeetle | Pure-function kernel, static allocation, DST | §1, §2, §7 |
| TigerBeetle | Storage fault model, checksums everywhere | §5 |
| TigerBeetle | Tiny opcode set | §8 |
| FastPay | Single-owner objects don't need consensus | §10 |
| Sui | Object-centric model, declared inputs | §9 |
| Sui | Owner vs shared object distinction | §10 |
| Sui | Per-object versioning for conflict detection | §12 |
| Sui | Per-object commitments (state root parallelism) | §14 |
| Aptos BlockSTM | Multi-version state for concurrent reads | §12 (alternative) |
| Aptos BlockSTM | Deterministic re-execution on conflict | §15 |
| Solana Sealevel | Static scheduling from declared accounts | §9, §15 |
| Monad / MonadDB | Async I/O during execution | §13 |
| MegaETH | State I/O is the high-TPS bottleneck | §13 |

---

## Anti-patterns that must never enter the kernel

If a PR introduces any of these, treat it as a structural regression:

- `SystemTime::now()`, `Instant::now()`, `std::time::*` anywhere in the kernel.
- `tokio::spawn`, `async fn` returning futures that hit a runtime, or any
  future executor inside the kernel.
- `Mutex<State>` or `RwLock<State>` over the global state. The state machine
  is single-threaded *inside the kernel*; concurrency lives outside.
- A `Box<dyn Validator>` or `Box<dyn StateMachine>` in the kernel hot path.
- A transaction handler that reads global state not passed as an argument.
- A "global counter" object touched by every transaction (block height
  counter, monotonic nonce, fee pool, sequence number).
- A Sparse Merkle Tree updated linearly per transaction with the root
  threaded through every handler.
- Per-transaction `fsync`, per-transaction logging through a global mutex,
  per-transaction allocation of a `Vec` that exceeds `MAX_*` configured size.
- `serde_json` or any reflective serializer in the kernel's wire path.
- A `Box<dyn Error>` return type in the kernel — kernel errors are a closed
  enum and exhaustively matched.
- `tracing::info!` inside a per-tx hot loop without an `if log_enabled!` gate.

---

## What v1 explicitly defers

Keep these on the roadmap so they don't get re-litigated as design
"decisions" later:

- Async state I/O during execution (§13). v1 fits in RAM; revisit when state
  exceeds RAM or when measured TPS is I/O-bound.
- The fast-path implementation itself — only the *type-level distinction*
  between owner-only and shared transactions is locked in now (§10).
- Cross-shard transactions, if/when state sharding becomes necessary. v1 is
  single-shard.
- Runtime-pluggable validity modes (TEE attestation, etc.) — v1 has only
  Optimistic, but the `ValidityProof` enum has space for new variants (§8).
- Watchtowers / third-party challengers (already deferred in EDGES.md).
- Speculative execution with re-execution on conflict — not needed because
  read/write sets are declared (§9, §15).

---

## Validation that the lock-ins held

A small set of tests that the kernel cannot pass if any of these decisions
got accidentally relaxed:

1. **Determinism test**: run the same block twice from the same starting
   state under commonware-runtime/deterministic; assert byte-identical
   resulting state and diffs.
2. **No-allocator-in-hot-path test**: a benchmark that asserts zero heap
   allocations across N blocks of M transactions, after warmup. (Use
   `tracking-allocator` or `dhat` in test mode.)
3. **Parallel-equivalence test**: run a block under a sequential strategy
   and a rayon strategy via `commonware-parallel`; assert byte-identical
   output.
4. **Read-set discipline test**: a transaction whose handler reaches into
   undeclared global state must fail to compile (enforced by the function
   signature requiring inputs to be passed in).
5. **Replica byte-identity test**: two simulated replicas processing the
   same block produce byte-identical state roots and DB contents.

These should run in CI on every PR. If any starts to flake, treat the flake
as a structural bug, not a test bug.
