# Hellas Kernel Performance Architecture - Codex Notes

Date: 2026-05-09

This memo expands the earlier TigerBeetle/Commonware/Hellas discussion into
kernel-level performance decisions. It is written for the Hellas L1/L2 state
channel system described in the whitepaper and the current `hellas-alto` shape:
a Commonware-based chain with Simplex consensus, QMDB-backed UTXO state, and a
small transaction kernel.

The central thesis:

> Hellas gets fast by making consensus order only scarce commitments, while
> keeping execution, artifacts, transcripts, and most payment updates outside
> consensus. The on-chain kernel should be narrow, deterministic, batched,
> object-oriented, and cheap to replay.

This is the part of TigerBeetle that transfers cleanly. TigerBeetle does not get
performance from being general. It gets performance from choosing a tiny domain,
making the state transition deterministic, batching aggressively, avoiding
dynamic hot-path behavior, and testing the whole system under faults. Hellas
should make the same kind of trade, but around channel settlement and object
state rather than debit/credit transfers.

---

## 1. Adopt the Narrow State Machine Mindset

### Decision

Consensus should order only operations that mutate scarce shared state:

- `Coin* -> Edge` channel opens.
- `Edge -> Coin*` cooperative closes.
- `Edge -> Coin*` timeout closes.
- `Edge -> Coin*` resolve/fraud/attestation closes.
- Validator set, staking, fee, and governance transitions.
- Optional commitment checkpoints for artifact availability or state sync.

Consensus should not order:

- AI execution steps.
- Auction messages.
- Prompts, outputs, model weights, tensors, KV caches, or traces.
- Bisection transcript messages.
- Full producer receipts, unless a validity mode explicitly needs public data.
- Per-token streaming chunks.
- Per-request payment increments inside an already-open channel.

### Rationale

The L1 is a settlement and ordering kernel, not a compute platform. If a
transaction does not spend a coin, lock collateral, unlock collateral, change an
edge, change validator rights, or commit a compact proof, it probably does not
belong in consensus.

This mirrors TigerBeetle's fixed accounting API: the database is fast because it
does one critical thing. For Hellas, the critical thing is not "run AI". It is
"settle commitments and disputes over AI work".

### Kernel Shape

The kernel should be a pure function:

```text
apply_block(parent_state, ordered_commands) -> (new_state, deterministic_diff)
```

The kernel must not:

- Read wall-clock time.
- Perform network I/O.
- Spawn tasks.
- Allocate unbounded data.
- Read undeclared state.
- Parse large artifacts.
- Make policy decisions based on local node conditions.

Inputs such as block height, epoch, randomness, and validator set must be explicit
block/context fields. Timeout logic should use block height or consensus view,
not local time.

---

## 2. Use the New Hyperedge Model, Not the Old Channel Shortcut

### Decision

Use the `HYPEREDGES.md` model as the design center:

- `Coin` and `Edge` as the two core on-chain object families.
- Opening consumes coins and creates one edge: `Coin* -> Edge`.
- Closing/resolving consumes the edge and creates coins: `Edge -> Coin*`.
- Producer receipts are portable execution attestations.
- Settlement messages bind portable receipts into a channel context.
- Only one settlement-sensitive request slot exists per edge in v1.
- Execution scheme and validity mode are separate axes.

Avoid the older `tex/l1.tex` idea that a client can open a channel by collecting
`2f+1` validator signatures and then "broadcasting the aggregate signature" to
lock funds outside the normal ordered state machine.

### Rationale

If a channel open consumes UTXOs, it needs a total order against every other
transaction that could spend the same UTXOs. A `2f+1` signature collection
protocol can be made safe, but then it is no longer a small shortcut: it becomes
a second object-locking consensus path. That would duplicate safety logic and
complicate recovery.

The better performance move is not to bypass consensus for shared-state opens.
It is to:

- Make opens cheap.
- Make channels long-lived.
- Amortize one open across many jobs.
- Keep all job traffic off-chain.

### Practical Rule

Full consensus is required for any operation that consumes or mutates an `Edge`,
or consumes multiple `Coin`s whose ownership does not allow a single-owner fast
path.

Owner-only `Coin -> Coin*` transfers may later use a Sui/FastPay-style fast path,
but that should be a distinct protocol with explicit object ownership rules. Do
not smuggle that mechanism into hyperedge opening.

---

## 3. Object Model: Make Parallelism a Type-Level Property

### Decision

The kernel should distinguish object types by their concurrency semantics:

```rust
enum Object {
    Coin(Coin), // owner-only, single settlement key
    Edge(Edge), // shared settlement object, maker/taker/proof governed
}
```

`Coin` is the owner-only object. `Edge` is the shared object.

Every transaction declares all consumed object IDs. Every transaction produces
deterministic output object IDs. The kernel rejects any transaction that tries to
touch undeclared state.

In the Rust kernel this is the `Op::access() -> Access` surface:
`Open` declares funding coins and its produced edge; `Resolve` declares its
input edge and produced payout coins.

### Rationale

This is the Solana/Sui performance lesson:

- Solana Sealevel runs transactions in parallel because transactions declare all
  accounts they read/write.
- Sui separates owned objects from shared objects; owned-object transactions can
  avoid full consensus, while shared-object transactions go through consensus.
- Aptos/Monad/Sei use optimistic parallel execution because EVM transactions do
  not naturally declare complete access sets.

Hellas has the advantage of not needing EVM compatibility. It should not inherit
the EVM's dynamic-access problem. Make access sets explicit.

### Access Sets

For v1:

- `Open`: reads/spends bounded maker/taker funding coins, creates one edge.
- `Resolve`: reads/spends one edge, creates coins.

Avoid:

- Chain-wide account nonces.
- Global fee-pool object touched by every transaction.
- Global counters touched by every transaction.
- Party or producer global balance updates on every edge resolve.
- Any "registry" object that every request needs to mutate.

If a registry is needed, use immutable snapshots, per-provider objects, or
epoch-level updates. Hot-path work should not contend on one global object.

---

## 4. The Single Frontier Slot Is a Performance Feature

### Decision

Keep v1 hyperedges to one settlement-sensitive frontier slot:

- Many jobs can be prepared, quoted, accepted, and executed off-chain.
- Many results can be `Ready`.
- Only one result enters the settlement-sensitive `ResultClaimed` /
  `AwaitingAcceptance` / `Resolving` frontier at a time.

### Rationale

This looks restrictive but is the right v1 performance trade.

The expensive concurrency is GPU execution, not settlement. The single frontier
slot serializes only the part where economic ambiguity exists. Everything else
can continue concurrently in local scheduler state.

The single slot makes these cheap:

- Timeout formulas.
- Bond accounting.
- Dispute penalties.
- Refusal-to-cosign handling.
- On-chain witness size.
- Deterministic settlement.
- Property testing.

If one maker/taker pair needs more settlement throughput, open multiple
parallel edges. That gives explicit lanes without complicating the base object.

### Future Extension

A fixed small frontier window, such as `W = 2..8`, is plausible later. If added,
it should be a protocol version with bounded arrays and linear settlement logic.
Do not jump directly to arbitrary per-job settlement accounting.

---

## 5. Consensus Choice: Simplex First, Minimmit When the Trade Is Worth It

### Current Position

`hellas-alto` currently uses Commonware `simplex` with an ed25519 scheme. This
is a good conservative default.

### Simplex

Use Simplex when:

- The validator set is adversarial or public enough that `f < n/3` matters.
- Implementation maturity matters more than shaving the last network hop.
- You want Commonware's existing certification path and operational surface.
- You expect block/data dissemination to dominate before the consensus round
  count dominates.

Simplex already gives a useful shape:

- Fast block times.
- Finalization through notarize/finalize votes.
- Application-defined block format.
- Decoupled broadcast/sync.
- Certification before finalization.
- Pluggable cryptography.

### Minimmit

Use Minimmit when:

- You can accept `n >= 5f + 1`, i.e. under 20% Byzantine tolerance.
- Latency is existential for the user experience.
- The validator set is high-quality, permissioned, strongly staked, or otherwise
  operationally controlled enough that the lower Byzantine threshold is acceptable.
- You have benchmarked that consensus round latency, not execution/storage/data
  dissemination, is the bottleneck.

Minimmit is attractive because view progression can happen at the small quorum
while finality waits for the large quorum. But that is a system-level trade, not
a free optimization.

### Recommendation

Start with Simplex until the kernel, object model, mempool, state storage, and
channel settlement are measured. Keep the block/state interfaces narrow enough
that replacing Simplex with Minimmit later is a consensus-module change, not a
kernel rewrite.

Expose low-latency UX through:

- Fast local receipt from provider.
- Off-chain channel updates.
- Speculative display after notarization, if the risk is acceptable.
- Full finality when the consensus certificate arrives.

Do not pick Minimmit just to compensate for slow execution or oversized blocks.

---

## 6. Data Dissemination: Do Not Make the Leader Push Everything

### Decision

The consensus proposal should eventually contain commitments to data, not large
raw data blobs.

Near-term:

- Keep blocks small while the kernel is being built.
- Use `marshal::standard` only while block bodies are comfortably small.
- Use compact transactions and hard block byte limits.

Medium-term:

- Move toward a Quorum Store / Narwhal / Autobahn-like model:
  validators disseminate transaction batches in parallel, create availability
  proofs, and consensus orders batch identifiers.

For larger blocks:

- Evaluate Commonware `marshal::coding` / erasure-coded block dissemination.
- Use coding when leader bandwidth becomes a bottleneck.

### Rationale

Modern high-throughput chains remove the leader's data broadcast bottleneck:

- Aptos Quorum Store decouples data dissemination from metadata ordering.
- Narwhal-style mempools let every validator broadcast batches concurrently.
- Sei Giga's upcoming Autobahn uses parallel lanes and consensus over cuts of
  lane tips.
- Commonware `marshal::coding` disperses erasure-coded shards so the leader does
  not send the full block to everyone.

For Hellas, most artifacts are off-chain. That helps. But even settlement
transactions can grow if `Resolve` starts carrying proofs. The block format must
be designed so proofs and witnesses are bounded or referenced by commitments.

### Availability Proof Shape

If Hellas adds a data-availability mempool, a batch proof should mean:

```text
batch_digest
batch_size_bytes
creator_validator
expiration_height_or_view
quorum signatures promising storage until expiration
```

Consensus orders the proof, not the batch bytes. Execution fetches the batch
from local cache or peers. This is the Aptos Quorum Store lesson.

### Backpressure

Batch creation must be rate-limited by:

- Local execution backlog.
- Batch cache pressure.
- Storage pressure.
- Consensus backlog.
- Per-validator quota.
- Fee market or priority score.

Without backpressure, a faster consensus engine will just overwhelm execution or
artifact storage.

---

## 7. Transaction Shape: Small, Bounded, and Cheap to Decode

### Decision

Consensus transactions should be compact, deterministic, and bounded.

Use:

- Fixed-width integers.
- Fixed-width digests and object IDs.
- Bounded arrays with explicit max lengths.
- Closed enums.
- Domain-separated signing preimages.
- `commonware-codec` for internal consensus types.
- Strict dag-cbor only where cross-implementation artifact commitments need it.

Avoid:

- JSON in consensus transaction bodies.
- Protobuf defaults in consensus-critical bytes.
- Unbounded `Vec`.
- `String` in hot-path kernel state.
- Runtime-dispatched validity handlers.
- Large receipt bodies on-chain.

### Split Encoding Layers

Use two different canonicality layers deliberately:

1. **Consensus/kernel wire format**
   - Commonware codec, fixed fields, small bounded vectors.
   - Optimized for validator throughput and replay.

2. **Artifact/receipt commitment format**
   - Strict dag-cbor or other scheme-specific canonical bytes.
   - Optimized for content addressing and cross-implementation commitments.

Do not represent the same settlement object in both encodings with subtly
different hashes. One object, one protocol identity.

### Output Object IDs

Output IDs should be derived from:

```text
H(domain, tx_digest, output_index)
```

This makes output collisions cryptographically negligible. Keep defensive checks
in debug/test paths, but avoid adding extra random DB reads in the critical path
solely to prove the hash function did not collide.

---

## 8. Signature Verification: Move It Out of the Kernel

### Decision

The kernel should not be the place where expensive signature verification happens.
It should receive verified commands or verification results.

Pipeline:

```text
decode -> cheap syntactic check -> signature batch/preverify -> conflict scheduling -> kernel apply
```

### Current Concern

The current `hellas-alto` transaction path verifies WebAuthn/P-256 signatures in
execution. That is fine for a prototype, but not a high-throughput settlement
kernel.

WebAuthn validation includes JSON parsing, RP ID checks, authenticator data
checks, and P-256 verification. That is expensive and variable.

### Recommendation

Separate two authentication classes:

1. **User wallet authentication**
   - Can remain WebAuthn for UX.
   - Should be handled at wallet/gateway/admission layer.
   - Produces a compact settlement authorization or session key.

2. **Protocol settlement signatures**
   - Use compact deterministic signatures over 32-byte preimages.
   - Consider secp256k1 or ed25519 for party messages.
   - Consider BLS multi/threshold signatures for validator certificates.

The current kernel models this with `ResolveHash` plus 64-byte `Sig`
placeholders. `Agreement` checks that maker and taker placeholders bind to the
same resolve payload; real signature verification still belongs in the
preverification path above.

### Verification Caches

Validators should maintain bounded caches:

- `tx_digest -> syntactic_ok`
- `tx_digest -> signature_ok`
- `receipt_commitment -> producer_sig_ok`
- `frontier_digest -> client_sig_ok/provider_sig_ok`
- `proof_public_inputs_digest -> proof_verified`, only if proof verification is
  deterministic and cache-safe.

Cache hits should be keyed by digest and protocol version, not by raw pointer or
transport source.

### Batch Verification

Use parallel or batch verification where available:

- Consensus certificates: aggregate or threshold signatures when validator count
  grows.
- Transaction signatures: batch ed25519 if using ed25519.
- Proof verification: parallelize across proof objects, but keep per-proof gas or
  cost limits.

One invalid signature in a block should normally invalidate the block, not trigger
partial inclusion logic inside the kernel.

---

## 9. Mempool: Make It Conflict-Aware

### Decision

Replace a FIFO mempool with an object-indexed mempool.

Each pending transaction should advertise:

- Consumed object IDs.
- Produced object count and size.
- Estimated verification cost.
- Estimated execution cost.
- Fee/priority score.
- Expiration height/view.
- Whether it is owner-only or shared.

### Rationale

A FIFO mempool wastes proposer time on transactions that cannot both be included.
If two transactions spend the same coin or close the same edge, at most one can
land. The proposer should know that before building a block.

### Mempool Indices

Maintain:

- `by_input_object: ObjectId -> candidate txs`
- `by_sender/session: Address -> queue`
- `by_fee_bucket`
- `by_expiration`
- `by_kind`
- `by_estimated_cost`

For each object, keep only a bounded number of conflicting candidates. Prefer:

- Higher fee.
- Earlier arrival if fees tie.
- Lower verification cost if fee density ties.
- Transactions with fewer shared-object conflicts.

### Proposal Builder

Build blocks by budget:

- Max bytes.
- Max transaction count.
- Max signature verification units.
- Max proof verification units.
- Max state reads.
- Max state writes.
- Max estimated execution time.
- Max per-object conflicts.

Do not use only `MAX_TXS_PER_BLOCK`. A block of 256 proof-heavy resolves is not
the same as 256 coin transfers.

---

## 10. Execution: Deterministic Static Scheduling First

### Decision

Because Hellas can declare access sets, use deterministic static scheduling, not
Block-STM-style optimistic execution, for native kernel operations.

Algorithm sketch:

1. Decode all transactions.
2. Verify signatures/proofs as needed.
3. Build read/write conflict graph from declared objects.
4. Partition into parallel waves.
5. Tie-break by block index.
6. Execute each wave in parallel.
7. Commit diffs in deterministic block order.
8. Compute the state root from the final diff.

### Why Not Start With Block-STM?

Block-STM is excellent for dynamic-access systems like Move/EVM where read/write
sets may be discovered during execution. Hellas native transactions do not need
that flexibility.

Static scheduling is simpler and has lower tail risk:

- No speculative abort/retry storms.
- No MVCC machinery in the first kernel.
- Easier replay.
- Easier deterministic simulation.
- Easier fee metering.

### When to Reconsider Optimistic Execution

Consider optimistic execution only if Hellas later adds:

- General-purpose smart contracts.
- EVM compatibility.
- Dynamic validity programs.
- On-chain scripts that discover state while running.

Until then, access-set declaration is the higher-performance design.

---

## 11. State Storage: Design Around Random Read Avoidance

### Decision

Use QMDB/commonware-storage as the default path, but keep the kernel/storage
interface as a diff boundary:

```text
kernel: resolved inputs + tx -> output objects + deletes + metadata
storage: apply deterministic diff, persist, expose root/proofs/sync
```

The kernel should not know whether storage is QMDB, an MMR-over-log, an LSM tree,
or an in-memory test backend.

### Rationale

Modern high-performance chains increasingly treat state I/O as the bottleneck:

- Monad emphasizes async execution plus MonadDb for efficient Ethereum state.
- MegaETH calls state trie random I/O and write amplification critical
  bottlenecks and uses specialized trie/storage/JIT work.
- SeiDB focuses on hot-state caching, optimized trie access, versioning, and
  concurrent state access.

For Hellas, the state model is simpler than EVM. Use that advantage:

- Store objects directly by `ObjectId`.
- Avoid trie traversal per object where possible.
- Batch state writes per block.
- Compute roots at block boundary.
- Keep hot object metadata in memory.
- Use append-oriented persistence.

### Read Path

Execution should prefetch all declared inputs for a block before scheduling. If
state grows beyond RAM, add async read scheduling:

```text
prefetch wave inputs -> execute ready txs -> issue reads for future waves -> continue
```

This is the Monad/MegaETH/Reddio lesson: do not stall a worker thread on one
random disk read if there are other ready transactions.

### Write Path

Writes should be block-batched:

- No per-transaction fsync.
- No per-transaction root update.
- No shared write lock around every object.
- Apply diff in sorted object-id order or deterministic block-output order.

Crash recovery should replay committed logs. Durability is a storage-layer
property; deterministic state transition is a kernel property.

---

## 12. State Commitment: Compute Once Per Block

### Decision

The state root should be a block-boundary result, not a transaction-by-transaction
dependency.

Do not thread a mutable `state_root` through every transaction handler.

### Rationale

Per-transaction root updates create an artificial serial dependency. Even if
transactions do not conflict, the root does.

Better shapes:

- Object-level commitments plus accumulator.
- QMDB root after applying a block diff.
- MMR/MMB over update logs.
- Parallel hash tree over sorted block diffs, folded into the authenticated DB.

The important property is that root computation can use all diffs at once and
does not force the execution scheduler to serialize.

### State Sync

Expose sync targets/proofs at finalized block boundaries. Do not require every
node to keep arbitrary intermediate per-transaction roots.

---

## 13. Pipelining: Keep All Stages Busy

### Decision

The validator should be a bounded pipeline:

```text
ingest
  -> decode/admission
  -> preverify
  -> batch/data availability
  -> consensus ordering
  -> execution scheduling
  -> kernel apply
  -> storage commit
  -> state sync / RPC serving
```

No stage should synchronously wait for a later stage unless backpressure says the
node is falling behind.

### Rationale

Aptos explicitly pipelines transaction dissemination, metadata ordering, parallel
execution, batch storage, and ledger certification. Monad and Sei Giga emphasize
asynchronous execution, where consensus orders block `n` while execution works on
earlier blocks. MegaETH uses streaming mini-blocks and async components to get
real-time feedback.

Hellas should do the same within its safety envelope.

### Conservative Version

For L1 safety, finalized state root for block `n` may be required before block
`n+x` commits to that root. That is fine. Still pipeline:

- Consensus can order future command batches.
- Execution can run behind ordering.
- Storage can flush behind execution.
- RPC can serve latest executed state separately from latest finalized order.

Define these separate heads:

- `ordered_height`
- `executed_height`
- `persisted_height`
- `finalized_height`
- `served_height`

Never blur them in code or metrics.

---

## 14. Channel Settlement Formulas Must Be Kernel Invariants

### Decision

Settlement formulas from `HYPEREDGES.md` should be implemented as closed,
exhaustive kernel logic.

The kernel should enforce:

```text
created_client_coins + created_provider_coins + burned + fees <= locked_edge_value
```

and, when exact conservation is required:

```text
created_client_coins + created_provider_coins + burned + fees == locked_edge_value
```

### Rationale

This is the TigerBeetle double-entry lesson. Do not leave value movement to
application convention. The core state machine should make money conservation
the easiest path and invalid settlement impossible.

### Recommended Structure

Use a closed resolve witness enum:

```rust
enum ResolveKind {
    Basic,
    Agreement,
    Timeout,
    ClaimantWins,
    ChallengerWins,
}
```

Then map each case to one deterministic settlement formula.

Avoid:

- Ad hoc settlement arithmetic at call sites.
- Policy callbacks.
- Floating point fee splits.
- Percentages that require rounding without a specified integer rule.

Open terms must constrain values so all splits are exact, or define the exact
rounding rule in integer arithmetic.

---

## 15. Output Availability Is Not the Same as Settlement Correctness

### Decision

State the boundary clearly:

- `ResultClaimed` means a producer signed a committed result claim.
- It does not universally prove the client received usable output bytes.
- Validity modes may add stronger availability/delivery rules, but the universal
  settlement layer should not pretend to solve this.

### Rationale

The v1 advance path can prove a provider sent a signed `ResultClaimed`, but L1
cannot know whether reconstructible output bytes reached the client unless a
delivery proof/DA proof exists.

This is acceptable only if the economic rule is explicit:

- Confirmed delivery and client silence can pay the provider.
- Unconfirmed delivery and client silence should not pay the provider.
- Burning or penalty rules should make refusal-to-ack costly without rewarding
  fake delivery.

### Future Improvements

Potential stronger modes:

- Delivery witness backed by DA.
- Erasure-coded output shards with verifiable availability.
- Encrypted output plus threshold key reconstruction.
- Watchtower/auditor service.
- Attested delivery through a TEE.

Do these as validity-mode extensions, not universal assumptions.

---

## 16. Cryptography Choices: Keep Certificates Small When Validator Count Grows

### Decision

For small validator sets, ed25519 certificates are operationally simple. For
large validator sets or cross-chain proof usage, use aggregate or threshold
certificates.

### Tradeoffs

Ed25519:

- Fast and simple.
- HSM-friendly.
- Good for small committees.
- Certificates grow with signer count.

BLS multisig:

- Compact aggregate signatures.
- Preserves signer attribution depending on construction.
- Slower verification.
- More complex implementation.

BLS threshold:

- Constant-size non-attributable certificates.
- Excellent for light clients and cross-chain messages.
- Requires DKG/resharing and careful operational machinery.

### Hellas Recommendation

Use the simplest scheme that keeps certificate size below the block and network
budget. Do not add threshold DKG before it is needed. But keep protocol surfaces
certificate-opaque so a switch from ed25519 to BLS does not change kernel logic.

---

## 17. Leader and Proposer Policy

### Decision

Separate proposer performance from state correctness.

Consensus should be able to:

- Skip slow/unresponsive leaders quickly.
- Penalize equivocation with evidence.
- Prefer recent performant leaders if the consensus dialect supports it.
- Avoid requiring one leader to carry all data bandwidth.

### Rationale

High-performance chains attack leader bottlenecks in multiple ways:

- Solana forwards transactions to upcoming leaders instead of letting a giant
  mempool accumulate.
- Aptos Quorum Store lets every validator disseminate data.
- Sei Autobahn uses multi-proposer lanes in its upcoming design.
- Commonware coding marshal disperses block data in pieces.

Hellas does not need all of these at once. It does need the architectural
assumption that leader data bandwidth is a bottleneck and must not be put on the
critical path unnecessarily.

### Initial Implementation

- Keep blocks small.
- Make mempool admission fair and conflict-aware.
- Add per-validator quotas for data batches if using DA mempool.
- Measure leader outbound bandwidth.
- Add coding/availability only after measurements show the leader is the limit.

---

## 18. Fast Path for Owner-Only Coins

### Decision

Design `Coin` transactions so they can later use a consensusless fast path:

- Only owner-only objects as inputs.
- No edge/shared object touched.
- No global nonce.
- No global fee-pool mutation.
- Double-spend prevention through object version or one-time object consumption.
- Certificate or quorum proof attached to the transaction/effects.

### Rationale

Sui and Mysticeti-FPC show the pattern: certain objects, such as coins controlled
by one party, can be finalized through reliable broadcast or embedded fast-path
votes without full consensus. This is a major throughput and latency lever.

### v1 Constraint

Do not implement the fast path until the normal consensus path is solid. But
lock in the object semantics now so the fast path remains possible.

### Epoch/Reconfiguration Caution

Fast-path transactions complicate epoch changes. Mysticeti-FPC needs explicit
epoch-change handling so fast-path transactions finalized near the boundary are
not lost or contradicted. If Hellas adds an owner-object fast path, it must
define:

- How fast-path effects are checkpointed into the consensus history.
- How epoch changes pause or drain fast-path voting.
- How equivocation on owned objects is resolved.
- How state sync includes fast-path effects.

---

## 19. Proofs and Disputes: Keep the Common Case Proof-Free

### Decision

The normal successful path should use only signatures and commitments:

```text
Open -> off-chain work -> producer receipt -> party acceptance -> Resolve
```

ZK proofs, bisection witnesses, TEE attestations, and large evidence should only
appear when the selected validity mode requires them.

### Rationale

High throughput comes from making the common case cheap. A fraud-proof system is
useful because it makes dishonest behavior punishable, not because every honest
request should carry a proof.

### Proof Budgeting

Each validity mode needs explicit limits:

- Max public input bytes.
- Max proof bytes.
- Max verification time.
- Max number of proofs per block.
- Max witness commitments referenced.
- Fee required per verification unit.

Proof-heavy transactions should be isolated in block budgeting so they do not
starve normal channel opens/closes.

### Single-Shot vs Interactive

Use the `HYPEREDGES.md` distinction:

- `Unsupported`: no correctness challenge path.
- `SingleShot`: one evidence submission.
- `Interactive`: bisection or multi-round resolution.

The kernel should see only the final settlement outcome or one bounded
transition step. It should not become an interpreter for arbitrary dispute
protocols.

---

## 20. Hardware Sympathy: Apply It Where It Matters

### Decision

Use hardware-aware engineering in the kernel and validator pipeline:

- Preallocate buffers.
- Reuse memory per block.
- Avoid allocator churn.
- Keep hot structs small and cache-friendly.
- Use bounded queues.
- Use lock-free or sharded metrics.
- Batch hashing.
- Batch signature verification.
- Avoid per-transaction logging in hot loops.
- Avoid trait-object dispatch in hot transaction handlers.

### Rationale

TigerBeetle and Firedancer both emphasize removing software overhead. Firedancer
is especially relevant as a clean-slate validator client built around low-latency
systems engineering and minimal syscalls/sandboxing.

For Hellas, this does not mean writing everything in C or abandoning Rust. It
means keeping the hot path plain:

```text
bytes -> bounded decode -> verified command -> object inputs -> pure transition -> diff
```

No hidden dynamic behavior in the middle.

### Memory Policy

Preferred:

- Arenas reset per block.
- `SmallVec`/bounded arrays for common small lists.
- Static max sizes in protocol constants.
- Reusable decode buffers.
- Per-worker scratch buffers.

Avoid:

- Allocating `String`s during execution.
- Cloning full transactions during proposal building.
- Storing large witnesses in state.
- Keeping unbounded mempool vectors.

---

## 21. Networking and RPC Are Separate Products

### Decision

Do not let public RPC behavior define validator hot-path behavior.

Validator P2P:

- Authenticated peer identities.
- Bounded channels.
- Backpressure.
- Per-peer quotas.
- Prioritized consensus/control messages.
- Optional block/batch coding.

Public RPC:

- Rate-limited.
- Cached.
- Geographically distributed if needed.
- Can use WebSockets/gRPC/JSON-RPC for developer UX.
- Should not allocate or parse on the consensus hot path.

### Rationale

MegaETH separates sequencer, replica/RPC nodes, full nodes, DA, and provers.
Hellas is not the same architecture, but the lesson transfers: serving users and
running consensus are different workloads.

Hellas validators can expose RPC for simplicity, but production architecture
should allow read replicas/indexers/artifact gateways to absorb user traffic.

### Metrics

Track separate latencies:

- Client submit -> mempool accepted.
- Mempool accepted -> included/order certified.
- Included -> executed.
- Executed -> persisted.
- Persisted -> served by RPC.
- Channel off-chain request -> provider receipt.
- Provider receipt -> cooperative close.

One "transaction latency" number hides too much.

---

## 22. Fee Model and Congestion

### Decision

Fees should price scarce resources directly:

- Consensus bytes.
- Signature verification units.
- State reads.
- State writes.
- Proof verification units.
- Artifact availability bytes, if validators store them.
- Timeout/resolve priority.

### Rationale

TPS is not the limiting resource. CPU, bandwidth, state I/O, proof verification,
and contention are.

If fees price only "transactions", attackers will choose the most expensive
transaction shape with the cheapest fee. If fees price resources, the block
builder can pack by budget.

### Practical Fee Shape

For each transaction:

```text
fee = base
    + bytes_fee(tx_size)
    + sig_fee(sig_count, sig_kind)
    + state_read_fee(read_count)
    + state_write_fee(write_count)
    + proof_fee(proof_kind, proof_size, verifier_cost)
```

For hyperedges, keep the spent-value fee from `HYPEREDGES.md` if desired, but do
not rely on slashing/burns as predictable protocol revenue. Slashing is an
incentive threat, not a throughput fee market.

---

## 23. What Modern High-Performance Chains Do

This section maps current high-performance-chain patterns to Hellas.

### Sui / Mysticeti

What they do:

- Object-centric data model.
- Owned vs shared object split.
- Fast path for owned-object transactions.
- DAG-based consensus for shared-object ordering.
- Mysticeti integrates fast-path votes into the DAG to reduce extra messages.

What Hellas should adopt:

- `Coin` as owner-only object.
- `Edge` as shared object.
- Explicit conflict definition: two transactions conflict if they consume the
  same object or write the same object.
- Future owner-coin fast path.
- Epoch-change discipline if fast path is added.

What not to copy blindly:

- Full DAG consensus if Simplex/Minimmit plus a small settlement kernel already
  meets latency targets.

### Solana / Sealevel / Firedancer

What they do:

- Transactions declare accounts up front.
- Runtime schedules non-overlapping account sets in parallel.
- Programs are code; accounts hold state.
- Mempool-less/leader-aware forwarding reduces pending transaction buildup.
- Firedancer attacks implementation overhead with a clean-slate, low-latency
  validator client.

What Hellas should adopt:

- Declared access sets.
- Static scheduling.
- Hard compute/byte budgets.
- Conflict-aware mempool.
- Hardware-sympathetic hot path.

What not to copy blindly:

- GPU/SIMD program batching unless Hellas later has many identical on-chain
  instruction executions. Hellas should keep AI compute off-chain.

### Aptos / Block-STM / Quorum Store

What they do:

- Pipeline transaction dissemination, metadata ordering, execution, storage, and
  certification.
- Quorum Store decouples data dissemination from consensus ordering.
- Block-STM uses optimistic parallel execution while preserving serial-equivalent
  results.

What Hellas should adopt:

- Pipeline everything.
- Consider Quorum Store/Narwhal-style batch availability if leader data bandwidth
  becomes a bottleneck.
- Use the Block-STM mental model only for future dynamic-access execution.

What not to copy blindly:

- Optimistic execution for native settlement transactions. Hellas can do better
  with declared access sets.

### Monad

What they do:

- MonadBFT for pipelined consensus.
- RaptorCast for block transmission.
- Asynchronous execution: consensus orders while execution runs in another
  pipeline.
- Optimistic parallel execution for EVM.
- JIT compilation and MonadDb for EVM state access.

What Hellas should adopt:

- Asynchronous consensus/execution pipeline.
- Async state reads when state exceeds RAM.
- Treat storage as a first-class performance bottleneck.
- Keep execution and state commitment decoupled enough to pipeline.

What not to copy blindly:

- EVM compatibility constraints. Hellas should avoid needing optimistic execution
  and JIT by keeping the kernel tiny.

### Sei / Twin Turbo / Sei Giga / Autobahn

What they do:

- Current Sei uses optimized Tendermint, optimistic execution during consensus,
  parallel decoding/validation, OCC execution, and SeiDB.
- Sei Giga targets asynchronous execution and Autobahn multi-proposer lanes.

What Hellas should adopt:

- Parallel decoding and validation.
- OCC only if dynamic execution is added.
- Storage specialization.
- Multi-lane/multi-proposer thinking for data dissemination, not necessarily for
  consensus v1.

What not to copy blindly:

- Upcoming target numbers as if they are current production guarantees.

### MegaETH

What they do:

- Specialized roles: sequencer, replica nodes, full nodes, provers, DA.
- Very low-latency mini-block streaming.
- Specialized state trie/storage/JIT.
- Stateless validation for parallel full-node validation.
- Ethereum L2 settlement and fault proofs.

What Hellas should adopt:

- Separate read-serving replicas/indexers from validator hot path.
- Stream executed results to clients separately from final settlement if useful.
- Optimize state trie/storage instead of assuming generic DBs are enough.
- Consider proof-oriented validation boundaries for heavy dispute modes.

What not to copy blindly:

- Single-sequencer assumptions. Hellas has BFT consensus, not a centralized
  rollup sequencer.

### Commonware / Alto

What they provide:

- Modular consensus, broadcast, codec, coding, storage, runtime, p2p, resolver,
  and deterministic-testing primitives.
- Simplex with application-defined blocks and certification.
- Coding marshal for erasure-coded dissemination.
- QMDB/MMR-style authenticated storage.
- Deterministic runtime for simulation.

What Hellas should adopt:

- Use Commonware primitives rather than rebuilding them.
- Keep application/kernel boundaries aligned with Commonware interfaces.
- Use deterministic simulation early.
- Switch dialects only when measurements justify it.

---

## 24. Current `hellas-alto` Gaps to Fix Before Chasing TPS

These are observations from the current prototype shape.

### Fixed Transaction Count Cap

`MAX_TXS_PER_BLOCK = 256` is a prototype cap. Replace or supplement it with
resource budgets:

- Max block bytes.
- Max decoded transactions.
- Max signature verification cost.
- Max state reads/writes.
- Max proof verification cost.

### FIFO Mempool

The current mempool is effectively a FIFO queue. Replace with conflict-aware,
fee-aware, expiration-aware admission.

### WebAuthn in Execution

WebAuthn verification in the execution path is too expensive for the final
settlement hot path. Move to preverification and compact settlement signatures.

### Sequential Execution

The current kernel applies transactions sequentially. That is fine for initial
correctness. The transaction format should still be changed now so every command
declares object access and can later be scheduled.

### `Coin`-Only State

Add `Edge` as a first-class object family before implementing ad hoc channel
state. Do not bolt channel fields onto coins.

### `marshal::standard`

Keep it while blocks are tiny. Revisit Commonware coding/availability when block
bytes or leader outbound bandwidth become bottlenecks.

---

## 25. Implementation Order

### Phase 1: Correct Narrow Kernel

1. Define `Coin`, `Edge`, `OpenTerms`, `FrontierReceipt`, and resolve witness
   types as bounded codec types.
2. Implement `Open`.
3. Implement `Resolve`.
4. Implement timeout settlement formulas in resolve witnesses.
5. Implement compact `ClaimantWins` / `ChallengerWins` seals without parsing
   full proof systems in the hot path.
6. Keep generated operation-sequence tests around conservation and rollback.
7. Keep replay tests that compare model-shaped traces against Rust `View`.

### Phase 2: Admission and Block Building

1. Add transaction metadata: consumed objects, produced object count, cost hints.
2. Replace FIFO proposal building with conflict-aware block packing.
3. Add signature preverification cache.
4. Add per-kind resource budgets.
5. Add block-level metrics.

### Phase 3: Parallel Execution

1. Build deterministic conflict graph.
2. Execute non-conflicting waves in parallel.
3. Commit diffs in deterministic order.
4. Add sequential-vs-parallel equivalence tests.
5. Add per-worker metrics and allocation tracking.

### Phase 4: Data Dissemination and Storage Scaling

1. Measure leader outbound bandwidth and block propagation latency.
2. If needed, test Commonware `marshal::coding`.
3. If needed, design batch availability proofs.
4. Add state prefetching.
5. Add async state I/O only when measured state reads are the bottleneck.

### Phase 5: Optional Latency Upgrades

1. Re-evaluate Simplex vs Minimmit with real measurements.
2. Consider BLS/threshold certificates if certificate size dominates.
3. Add owner-coin fast path only after consensus path and epoch mechanics are
   stable.

---

## 26. Benchmarks That Matter

Do not optimize to a single TPS number. Track:

### Consensus

- Proposal size bytes.
- Proposal propagation p50/p95/p99.
- Notarization/finalization latency.
- Leader outbound bandwidth.
- Certificate size.
- Timeout/nullification rate.

### Execution

- Tx decode time.
- Signature verification time.
- State read latency.
- State write latency.
- Kernel apply time.
- Merkle/root computation time.
- Sequential vs parallel speedup.
- Conflict rate by object kind.

### Channels

- Open latency.
- Cooperative close latency.
- Timeout close latency.
- Resolve verification latency.
- Jobs per edge before close.
- Frontier slot utilization.
- Dispute frequency.

### Storage

- Fsync latency.
- Write amplification.
- State DB cache hit rate.
- Bytes written per block.
- State sync catch-up throughput.
- Recovery time after crash.

### End User

- Request -> provider accepted.
- Request -> first output byte.
- Output -> producer receipt.
- Receipt -> client acceptance.
- Acceptance -> cooperative close finalized.

---

## 27. Tests That Should Exist Early

### Determinism

- Same block, same starting state, repeated many times -> byte-identical diff and
  root.
- Sequential scheduler vs parallel scheduler -> identical output.
- Different worker counts -> identical output.

### Value Conservation

- Fuzz all `Edge -> Coin*` settlement outcomes.
- Fuzz fee splits and exact integer divisibility.
- Assert no created value exceeds locked value.

### Conflict Scheduling

- Two transactions spending same coin: at most one included.
- Two closes for same edge: at most one included.
- Disjoint edges: parallelizable.
- Disjoint coins: parallelizable.

### Timeout Logic

- Timeout witnesses reveal concrete terms and check the committed timeout height.
- Maker silent in every frontier state.
- Taker silent in every frontier state.
- One-step advance accepted only from the mode-defined active party.
- Stale receipt cannot override newer receipt.
- Mode-specific delivery rules do not leak into the L1 hot path.

### Fault and Recovery

- Crash before persist.
- Crash after persist.
- Replay WAL.
- State sync from peer.
- Missing batch fetch.
- Corrupt artifact bytes rejected by digest.

### Deterministic Simulation

Use Commonware deterministic runtime to simulate:

- Dropped messages.
- Reordered messages.
- Slow leaders.
- Duplicate transactions.
- Equivocation.
- Node restart.
- State sync catch-up.
- Disk/storage errors where the storage layer can model them.

---

## 28. Anti-Patterns

Reject these in the kernel or consensus hot path:

- A global account nonce for all user actions.
- A global fee pool touched per transaction.
- Dynamic state reads not declared by the transaction.
- JSON parsing in block execution.
- Per-transaction fsync.
- Per-transaction state root update.
- Per-transaction RPC callbacks.
- `Box<dyn ValidityMode>` in the kernel.
- Unbounded vectors in consensus objects.
- Floating point arithmetic in settlement.
- On-chain storage of full transcripts.
- On-chain storage of prompts, outputs, weights, or traces.
- Treating provider reputation as a cryptographic guarantee.
- Treating future target TPS claims from other chains as production baselines.

---

## 29. Bottom Line Recommendations

1. Make `HYPEREDGES.md` the source of truth and retire the old `2f+1 signatures
   lock funds` shortcut for shared-state opens.
2. Add `Edge` as a first-class object next to `Coin`.
3. Require every transaction to declare consumed objects.
4. Replace transaction-count block limits with resource budgets.
5. Move signature verification out of kernel execution.
6. Build a conflict-aware mempool.
7. Keep Simplex until measurements show Minimmit is worth the 20% Byzantine
   threshold.
8. Keep blocks small; move to availability/coding only when block bytes dominate.
9. Pipeline consensus, execution, persistence, and serving.
10. Treat state storage as a first-class performance problem, not an
    implementation detail.
11. Keep the common channel path proof-free.
12. Test determinism and value conservation before optimizing TPS.

---

## Sources

- TigerBeetle docs and architecture: https://docs.tigerbeetle.com/ and
  https://github.com/tigerbeetle/tigerbeetle/blob/main/docs/ARCHITECTURE.md
- Commonware primitives: https://commonware.xyz/
- Commonware Simplex docs: https://docs.rs/commonware-consensus/latest/commonware_consensus/simplex/
- Commonware coding marshal post: https://commonware.xyz/blogs/coding
- Commonware buffered signatures post: https://commonware.xyz/blogs/buffered-signatures
- Commonware QMDB post: https://commonware.xyz/blogs/qmdb
- Minimmit paper page: https://arxiv.org/abs/2508.10862
- Sui object model intro: https://sui.io/intro-to-sui-1
- Mysticeti paper: https://docs.sui.io/paper/mysticeti.pdf
- Solana Sealevel: https://solana.com/news/sealevel---parallel-processing-thousands-of-smart-contracts
- Solana Gulf Stream: https://solana.com/news/gulf-stream--solana-s-mempool-less-transaction-forwarding-protocol
- Firedancer docs: https://docs.firedancer.io/
- Aptos whitepaper: https://aptosnetwork.com/whitepaper
- Aptos Quorum Store: https://medium.com/aptoslabs/quorum-store-how-consensus-horizontally-scales-on-the-aptos-blockchain-988866f6d5b0
- Block-STM paper: https://arxiv.org/abs/2203.06871
- Monad docs: https://docs.monad.xyz/
- Sei Giga docs: https://docs.sei.io/learn/sei-giga and
  https://docs.sei.io/learn/sei-giga-specs
- Autobahn paper: https://arxiv.org/abs/2401.10369
- MegaETH docs: https://docs.megaeth.com/ and
  https://docs.megaeth.com/architecture
- MegaETH architecture notes: https://www.megaeth.com/about
