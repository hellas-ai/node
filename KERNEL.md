# Hellas Kernel Model

This document describes the small formal core of Hellas: the parts that must be
specified, tested, and eventually verified for the larger system to be
trustworthy.

The main design rule is decomposition. The full system is too large to model as
one machine. We model small machines with explicit interfaces, then prove or
test that the interfaces compose.

## Kernel Boundary

The kernel is not the model runner, RPC server, Python worker, tokenizer,
provider gateway, or p2p content network.

This document uses "kernel" for the small formal core of the protocol. The hot
L1 kernel is the smaller live-state machine inside that core: coins, live
edges, and resolve operations. State-channel frontiers, receipts, claims, and
dispute transcripts are kernel-relevant protocol objects, but they are not L1
live state.

The kernel is:

- the L1 UTXO transition system
- the state-channel lifecycle
- the validity gadgets used by channels to accept, reject, or dispute claims
- the transaction/event interface between those pieces
- the abstraction boundary between Rust implementation and formal models

Everything else plugs into this kernel.

```text
adapter/executor
  produces calls, results, claims, evidence

validity gadget
  decides why channel peers should believe, dispute, or slash a claim

state channel
  exchanges signed frontiers, receipts, claims, and payments peer-to-peer

L1 ledger
  escrows coins, opens edges, resolves edges, and mints payout coins

consensus
  finalizes an ordered log of L1 transactions
```

## The Shared Vocabulary

All models and implementations should meet at the same operation vocabulary.
This keeps the Rust code and the formal models from drifting.

```rust
enum Op {
    Open(Open),
    Resolve(Resolve),
}

enum EventKind {
    EdgeOpened { inputs: List<CoinId, MAX_EDGE_INPUTS>, output: EdgeId },
    EdgeResolved { input: EdgeId, outputs: List<CoinId, MAX_EDGE_OUTPUTS> },
}
```

The L1 operation vocabulary is intentionally small. Claims, receipts,
frontiers, challenges, and dispute transcripts are state-channel/protocol
objects exchanged peer-to-peer. L1 only sees them if a resolve transaction
carries some bounded resolve proof derived from them.

## Kernel Implementation Invariants

The Rust implementation enforces a small set of rules at the type level rather
than by convention. These are the rules a model checker can rely on and that a
future contributor cannot accidentally break.

### Closed Object Set

There are exactly two on-chain object kinds: `Coin` and `Edge`. New kinds are
not anticipated. The store API, the internal slot type, and every abstraction
in the codebase is sized to this. Future-scaling abstractions (sealed traits,
generic store accessors, kind registries) should not be introduced — they would
pay for an extension that is not coming.

### Reducer Discipline

State transitions follow a two-phase, event-sourced shape:

```text
op_apply(ctx, &Verifier, &Tx, Op) -> KernelResult<Change>   // read-only
change_fold(&mut Tx, &Change)     -> KernelResult<()>       // private mutation
```

`Verifier` is the crypto boundary; `Tx` is the storage boundary. Both are
caller-supplied interfaces, both pure during validation.

- `Event` is the public opaque fact emitted by an operation. Its constructors
  are private; external code cannot fabricate events.
- `Change` is the crate-private reducer output: the public `Event` plus the
  private `Effect` needed to fold the mutation. External code can observe the
  event, but it cannot fabricate or replay effects.
- The only paths to a `State` value are `Genesis::coin` seeds and
  `State::apply(prev, op)?`.
- Mutation lives in one private fold per op. No other code mutates the store.
- Validation and fold must observe the same `Tx` working state. The
  `CoinChanged` and `EdgeChanged` errors exist only to catch a misbehaving
  `Tx` implementation that returns one object during validation and removes a
  different object during fold.

By induction, every reachable kernel state equals either a set of genesis coins
or `apply(prev, op)?` for some op. The model checker explores the transition
relation directly; reachability is not a separate proof obligation.

The atomic-transition mechanics that realize this discipline are described in
[Atomic Transitions](#atomic-transitions).

### Identifier Derivation

Every object id is `H(kind_tag ‖ ...)` where `kind_tag` is a domain separator
unique to the object kind. As consequences:

- `CoinId` and `EdgeId` byte representations cannot collide.
- A backing store may safely use a single byte-keyed map without per-kind
  tables.
- There is no public id-cast operation. Reinterpreting an id between kinds
  would forge a digest the kernel never produced.

`CoinId` and `EdgeId` are concrete byte newtypes — not a phantom-typed `Id<T>`
— because the kind set is closed at two and no kernel code wants to be generic
over "any id".

Operation outputs are not caller-selected. `Open` derives its `EdgeId` from the
edge domain tag, maker/taker funding ids, parties, and `TermsHash`. `Resolve`
derives each payout `CoinId` from the coin domain tag, consumed `EdgeId`, output
position, and owner key. `from_bytes` constructors exist for decoding
already-canonical live state references, genesis seeds, and store keys; they are
not part of output selection.

### Typed Store Boundary

The store presents a typed `Tx` interface. The kernel asks for "the coin at
this `CoinId`" or "the edge at this `EdgeId`", never for "the object at id X".
Storage representation is an implementation choice and does not cross the API
boundary.

```rust
trait Store {
    type Tx<'a>: Tx where Self: 'a;
    fn begin(&mut self) -> Self::Tx<'_>;
}

trait Tx {
    fn coin(&self, id: CoinId) -> Option<Coin>;
    fn insert_coin(&mut self, id: CoinId, coin: Coin) -> KernelResult<(), InsertError>;
    fn remove_coin(&mut self, id: CoinId) -> Option<Coin>;

    fn edge(&self, id: EdgeId) -> Option<Edge>;
    fn insert_edge(&mut self, id: EdgeId, edge: Edge) -> KernelResult<(), InsertError>;
    fn remove_edge(&mut self, id: EdgeId) -> Option<Edge>;

    fn commit(self);
}
```

There is no public `Object` type. In-memory store implementations may use a
private `enum Slot { Coin(Coin), Edge(Edge) }`; database-backed implementations
need not.

`FixedStore` is the no-allocation hot-path backend the kernel ships with: it
pre-allocates every coin/edge slot at construction time and lookup is a small
linear scan. `MapStore` (in `tests/support/`) is the growing-set reference
shape real production backends will follow — `BTreeMap`-backed, transactional
via a working snapshot swapped in on `commit`. Tests run against both so any
`FixedStore`-specific assumption baked into kernel logic surfaces immediately.

### Verifier Boundary

The kernel implements no cryptography. Signature and dispute-seal
verification go through a `Verifier` trait that callers wire in at apply
time:

```rust
trait Verifier {
    fn verify_sig(&self, sig: Sig, key: Key, hash: ResolveHash) -> bool;
    fn verify_seal(
        &self,
        seal: Seal,
        protocol: ProtocolCode,
        kind: ResolveKind,
        hash: ResolveHash,
    ) -> bool;
}
```

`State::apply(context, &verifier, op)` plumbs the verifier through to
`Proof::accepts`. The kernel never sees the verification mechanism.
Production callers wire a real verifier — `Secp256k1Verifier` behind the
`secp256k1` feature flag is the included reference, or a preverified-cache
lookup populated off the apply critical path (PERF.md §4). Tests use
`FakeVerifier`, which accepts the deterministic placeholder shape produced
by `Sig::placeholder` / `Seal::placeholder`. A `RejectVerifier` covers
"production has no key for this proof" cases.

The kernel's `cfg(feature = "fake-crypto")` gate still applies to one place:
`Proof::Basic`. Basic is a structural marker for the modelling/testing
witness — there is no signature to verify, so the verifier is not consulted.
Production builds reject Basic at the type level regardless of the verifier
supplied.

### Per-Digest Types

Every 32-byte digest the kernel handles has its own newtype: `BlockHash`,
`TermsHash`, and one per future digest purpose (claim hashes, evidence hashes,
transaction roots, ...). They share a private `[u8; 32]` shape but are not
interchangeable; the compiler stops cross-purpose assignment. They derive
`Ord` and `PartialOrd` over their byte representation so they compose with
`BTreeMap` and other ordered collections — useful for production stores and
test reference models alike.

`Edge` carries principal value, prepaid resolution reserve,
`Parties { maker, taker }`, and a `TermsHash`, not a stored terms object id.
`Terms::Basic` is the current concrete terms shape: protocol code, parties, the
earliest timeout block height, and the deterministic payout list accepted by a
timeout resolve. It has a deterministic no-allocation BLAKE3 commitment path:
`Terms::hash() -> TermsHash`.

Terms are still not on-chain state. The hot live object stores only
`TermsHash`; concrete terms are an input-side vocabulary used to derive that
commitment and later verify resolve proofs against it.

### Edge Funding Shape

`Open` consumes bounded bilateral `Funding { maker, taker }`, where each party
is a bounded list of `CoinId` values, and carries concrete `Terms`. The produced
edge stores only `TermsHash` and `Parties { maker, taker }` derived from those
terms. The produced `EdgeId` is canonical; it is not supplied by the caller.
Either funding list may be empty; a one-sided or zero-funded open is valid when
total funding covers the context-priced open cost plus the prepaid reserve for
the worst-case bounded resolve path. Funding is invalid exactly when the sum of
funding coin values is less than
`context.fee(open.cost()) + context.fee(open.reserve_cost())`. The produced edge
principal is that remaining value; the reserve is stored separately and is not
payable principal. Maker and taker are positional party identities: the maker is
the party whose open intent or offer is filled, and the taker is the party that
fills it. They are not buyer/seller, requester/provider, payer/worker, or any
other economic meaning. The kernel does not require the maker and taker keys to
be distinct; self-edges are valid and can represent sends, merges, or no-work
channels under higher-level protocol convention.

`Resolve` consumes one `Edge`, carries a bounded resolve proof, and creates a
bounded list of `Payout { owner, value }` values. Payout coin ids are canonical;
they are not supplied by the caller. `Proof` carries a `ResolveKind`:
`Basic`, `Agreement`, `Timeout`, `ClaimantWins`, or `ChallengerWins`. `Basic` is
the degenerate modelling witness that only binds the resolve to the edge's
`TermsHash`; the kernel accepts it only under the `fake-crypto` feature.
`Agreement` is the first real non-basic witness: it requires both maker and
taker signature-shaped witnesses over the same `ResolveHash`, which commits to
the input edge, witness kind, terms, and ordered payouts. Signature verification
is delegated to the `Verifier` trait the caller supplies (see [Verifier
Boundary](#verifier-boundary)); production builds wire `Secp256k1Verifier` or
a preverified-cache verifier; tests wire `FakeVerifier` against the deterministic
`Sig::placeholder` shape. `Timeout` reveals the concrete basic terms, checks
that their commitment equals the edge's `TermsHash`, accepts only when
`Context::block_height() >= Terms::timeout()`, and requires the resolve payout
list to equal the terms' committed timeout payout list — the only resolve path
where the kernel itself enforces a payout shape. `ClaimantWins` and
`ChallengerWins` reveal the same concrete terms and carry a fixed-size `Seal`,
the compact mode-specific verifier result; the kernel asks the verifier whether
the seal binds to the protocol code, outcome kind, and resolve hash. As with
signatures, `Seal::placeholder` is the test shape; production composes a
seal-aware verifier (the included `Secp256k1Verifier` rejects every seal —
seals are protocol-specific and there is no universal seal verifier).
Empty resolve output is valid exactly for a zero-value edge. A resolve is valid
only when the edge reserve covers `context.fee(resolve.cost())`; the reserve is
consumed by the resolve and does not appear in payout coins.

Every kernel rejection self-describes via a structured `ApplyError::Invalid*`
reason: `InvalidOpenReason { FundingInsufficient, FundingOverflow, FeeOverflow,
ReserveOverflow, BoundsExceeded }`, `InvalidResolveReason { ValueMismatch,
ReserveTooSmall, FeeOverflow, PayoutOverflow, BoundsExceeded }`,
`InvalidProofReason { TermsMismatch, BadSignature, BadSeal, TimeoutNotReached,
PayoutMismatch, BasicNotAccepted }`. Callers do not parse free text to tell
"fee schedule changed under me" (`ReserveTooSmall`) from "I miscomputed
payouts" (`ValueMismatch`).

### Resource Costs

Every operation exposes a deterministic `Cost` derived only from bounded
operation shape:

```text
Cost { base, slots, proofs }
Fees { base, slot,  proof  }
```

`base` is fixed per-op overhead; `slots` counts every store slot the kernel
touches (each is read for the existence check and written for the
insert/remove that follows, so reads and writes are structurally equal and
fold into one dimension); `proofs` counts signature/seal verifications.

`Context` carries the active `Fees` schedule and prices costs with
`context.fee(op.cost())`. The L1 open path burns the priced open cost from
funding before creating the edge, and locks a separate resolution reserve priced
from the pessimistic worst-case bounded resolve shape: `MAX_EDGE_OUTPUTS` plus
`ResolveKind::ClaimantWins`. This is deliberate. V1 does not refund unused
reserve and does not price resolves optimistically; the protocol should always
be paid. Resolve checks that the edge reserve can pay the current priced resolve
cost, then consumes the reserve and pays out only edge principal. `Block::fits`
checks the summed block cost against a multi-dimensional resource budget before
admission.

Resolve fees are charged under the *current* block's fee schedule, not the
schedule active when the edge opened. If a fee increase pushes the priced
resolve cost above the locked reserve, the edge becomes unresolvable through
the normal path. Principal stays conserved inside the live edge — it is not
redistributed and not lost from the global accounting — but it cannot be paid
out under that schedule. This asymmetry is intentional: it gives the protocol a
stale-edge collection knob. Lifting fees is the eviction mechanism for edges
nobody bothered to resolve under the original prices. Pinning fees at open
time would close that knob and is explicitly not v1 semantics.

### Access Sets

Every operation exposes a deterministic `Access` set before execution:

```text
Access { coins, edges, new_coins, new_edges }
```

`Open` declares its funding coins and produced edge. `Resolve` declares its
input edge and produced payout coins. The kernel still validates against the
transactional store, but schedulers and model checkers do not need to discover
hot-path state dynamically. `Access::conflicts` is the static pairwise predicate
used to build execution waves: two operations conflict if their consumed or
created coin/edge IDs overlap.

## L1 Model

The L1 machine owns the canonical UTXO state.

It tracks:

- coins
- live edge records
- explicit live-object sets in the abstract models, because zero value and
  absence are distinct
- bounded resolve operations
- block height
- finalized transaction order

It does not know how a model was executed, how a TEE attestation works, or how a
ZK proof was generated. It only knows how to open an edge, resolve an edge, and
verify the bounded resolve proof required by the edge terms.

An edge is live-only. Existence means open. Open consumes funding coins and
creates the live edge. Resolve consumes the edge, deletes it from live L1 state,
and mints payout coins. There is no closed-edge status in live state;
historical closure belongs in events and block history.

### L1 Invariants

The basic invariants are:

- every coin is in exactly one location
- no live coin is spendable twice
- every live edge represents principal consumed from coins at open, minus the
  context-priced open cost and prepaid resolution reserve
- opening an edge consumes funding coins, pays the derived fee, locks the
  derived reserve, and creates the edge atomically
- resolving an edge deletes the edge, consumes the reserve, and creates payout
  coins atomically
- protocol costs are paid before a mutation commits; an operation that cannot
  pay its context-priced cost is invalid
- resolve output coins exist after the resolve event
- resolve output coins may later be spent or escrowed into a new edge
- block height is monotonic
- finalized operations are applied in order
- principal value (sum of all live coin values plus all live edge principal) is
  conserved by every non-genesis operation except for context-priced open costs
  and prepaid resolution reserves

The subtle point is resolved outputs. The live L1 state should not retain a
closed-edge record to police those coins. Once minted, resolve outputs are
normal UTXOs. They must not be required to stay free forever.

## Channel Model

The channel machine owns off-chain state.

It tracks:

- channel participants
- signed channel states
- signed frontiers
- receipts and claims
- latest known sequence numbers
- challenge windows
- dispute transcripts
- watcher obligations
- local party knowledge

The channel model never mutates L1 coins directly. It submits L1 transactions
and observes L1 events.

```text
channel --submits--> Open | Resolve
channel <--observes-- EdgeOpened | EdgeResolved
```

This is the first major composition boundary. The channel does not get to reach
into `State`. It only talks to L1 through transactions and events.

The frontier is not an L1 object. Frontier receipts, producer receipts,
challenge messages, and fraud-game transcripts are passed peer-to-peer inside
the channel. They matter to L1 only if they are summarized by a bounded resolve
proof in a resolve transaction.

### Watcher Liveness

The honest liveness claim is conditional.

Not:

```text
the client can always challenge
```

Instead:

```text
if a party has funds at risk,
and a watcher for that party is live during the challenge window,
and the watcher can deliver the required peer-to-peer challenge or resolve data
before the channel deadline,
then an invalid claim cannot become the channel's accepted resolve state by timeout
```

Watcher liveness is a participant obligation. It is not a global fact about the
network.

This matters because it shapes challenge-window length, watch-tower delegation,
bandwidth, storage, and economic assumptions. A party without a live watcher
accepts timeout risk.

## Validity Gadgets

A validity gadget explains why a claim should be accepted or rejected.

Validity gadgets are not part of the L1 UTXO core, and they are not the same as
the off-chain channel protocol. They are protocol machines used by channel peers
to decide whether to accept, challenge, or sign a frontier.

```text
channel protocol
  says when a party may claim or challenge

validity gadget
  says what makes the claim valid, invalid, proven, slashable, or final

L1
  verifies only the bounded resolve proof required to release escrowed coins
```

The common shape is:

```rust
trait ValidityGadget {
    type Claim;
    type Evidence;
    type Challenge;
    type Verdict;

    fn accept_claim(claim: &Self::Claim, evidence: &Self::Evidence) -> bool;
    fn challenge(claim: &Self::Claim, challenge: &Self::Challenge) -> ChallengeStatus;
    fn resolve(
        claim: &Self::Claim,
        evidence: Option<&Self::Evidence>,
        challenge: Option<&Self::Challenge>,
    ) -> Self::Verdict;
}
```

This trait is illustrative, not a required Rust API. The required protocol
vocabulary is:

- `Claim`
- `Evidence`
- `Challenge`
- `Verdict`
- `Deadline`
- `Bond`

### Trusted

Trusted mode has no cryptographic validity proof beyond producer authorization.

Model:

- evidence: producer signature
- challenge: none
- verdict: accept if signature and claim shape are valid

Security meaning:

- the requester trusts the producer socially or contractually
- L1 cannot distinguish correct from incorrect work

### TEE

TEE mode accepts claims backed by an attestation.

Model initially as predicates:

```text
AcceptedTEEAttestation(claim, evidence)
MeasurementAllowed(measurement)
Fresh(attestation)
```

Assumption:

```text
AcceptedTEEAttestation(claim, evidence)
=> claim was produced by an enclave with an allowed measurement
```

Later, the attestation protocol itself can be modelled in Tamarin if replay,
freshness, key binding, or quote verification become protocol-critical.

### ZK

ZK mode accepts claims backed by a proof.

Model initially as:

```text
Verify(proof, public_inputs, claim)
RelationHolds(public_inputs, claim)
```

Assumption:

```text
Verify(proof, public_inputs, claim)
=> RelationHolds(public_inputs, claim)
```

The top-level model should not include circuit internals. The verifier is an
abstract predicate until the circuit relation is stable.

### Optimistic

Optimistic mode accepts claims after a timeout unless a valid fraud proof
arrives.

Model:

- evidence: none, or a trace/result commitment
- challenge: fraud proof
- verdict: accept after deadline if unchallenged, reject/slash if fraud proof is
  valid

Assumptions:

```text
FraudProofCompleteness:
  if a claim is false, an honest watcher can construct a valid fraud proof

WatcherLiveDuringWindow:
  a party with funds at risk has a live watcher for the whole challenge window

L1InclusionFairness:
  a valid challenge transaction submitted before deadline is finalized before
  timeout settlement
```

The final property is conditional:

```text
under these assumptions, a false claim cannot settle
```

### Optimistic ZK

Optimistic ZK is not just "ZK with a delay". It is a fraud-game gadget where the
claim may contain commitments to a computation trace, and challenges narrow the
dispute until a small check can be performed.

Model it as its own gadget:

- claim: result plus trace commitments
- evidence: optional proof or trace metadata
- challenge: disputed step, fraud witness, or bisection move
- verdict: accept, reject, slash, or continue dispute

The first model should not encode the full trace machinery. It should encode
the fraud-game contract:

```text
if claim is false and honest watcher is live,
then there exists a challenge path leading to reject/slash before finality
```

The detailed step relation can be refined later.

## Adapter And Executor Layer

Adapters are outside the settlement kernel. They produce payloads, results,
claims, and evidence.

Examples:

- `hellas.v1.catgrad`
- `hellas.v1.vllm`
- `hellas.v1.echo`
- future domain-specific adapters

The settlement kernel does not need to know how an adapter parses payload bytes
or invokes an engine. It only sees:

```text
Call
CallResult
Claim
Evidence
```

An adapter may have its own RPC, schema, ALPN, or payload format. The kernel
interface is the claim/evidence boundary, not the adapter's internal API.

## Consensus Interface

Hellas will use a third-party consensus implementation. We should not model that
implementation white-box by default.

The L1 model should depend on a small consensus contract:

```text
Consensus input:
  submitted transactions

Consensus output:
  finalized blocks, each containing an ordered transaction list
```

The L1 transition system applies finalized blocks in order.

### Consensus Assumptions

The kernel needs these guarantees:

- agreement: honest nodes do not finalize conflicting block histories
- finality: once a block is final, it is not reverted beyond the modelled reorg
  bound
- order: finalized transactions have a deterministic order
- validity: invalid transactions are not finalized as successful state changes
- height monotonicity: finalized block height increases
- inclusion fairness: under stated network assumptions, valid submitted
  transactions are eventually finalized or explicitly rejected
- availability: enough transaction data is available for validators and watchers
  to validate relevant transitions

These should be written as assumptions in the model, not hidden in prose.

### Black-Box, Gray-Box, White-Box

Use a black-box consensus model first.

```text
action FinalizeBlock(txs):
  nondeterministically choose an ordered list of pending transactions
  subject to consensus assumptions
  apply them to L1
```

This is enough to verify most L1/channel/validity properties. We do not need to
model proposers, votes, validator sets, gossip, or mempools unless those details
affect the property being checked.

Use a gray-box model when consensus details are protocol-relevant:

- probabilistic finality or reorg windows
- censorship and delayed inclusion
- proposer-controlled transaction ordering
- data availability failures
- light-client trust assumptions
- validator-set changes
- cross-chain bridge finality

Use a white-box model only if:

- Hellas changes the consensus protocol
- the third-party consensus proof is not trusted
- the property depends on a specific internal consensus mechanism
- a bug in consensus ordering/finality would invalidate the Hellas security
  argument and cannot be abstracted as an assumption

For a third-party implementation, the normal approach is assume/guarantee:

```text
Consensus guarantees:
  final ordered blocks satisfying safety/finality/fairness assumptions

L1 assumes:
  exactly those guarantees

L1 guarantees:
  deterministic application of valid transactions and rejection of invalid ones
```

If the consensus provider already has its own proofs or model, link to those and
record exactly which assumptions Hellas relies on.

## Refinement Boundary

The Rust implementation and the formal model connect through an abstraction
function:

```text
view: State -> View
```

`View` is the protocol-relevant part of concrete Rust state. It is a
first-class Rust type, not an ad hoc test helper.

In Rust, `Store` remains the hot apply boundary and does not require
enumeration. Stores that participate in modelling or trace replay implement
the separate `Snapshot` trait whose associated `View` type lets each store
pick its own bounded snapshot shape:

```rust
trait Snapshot {
    type View;
    fn view(&self) -> Self::View;
}
```

`State::view()` returns `<S as Snapshot>::View` — no turbofish at the call
site, the view shape travels with the store. `FixedStore<C, E>` implements
`Snapshot { type View = View<C, E> }`. `MapStore` (the growing reference)
deliberately does not implement `Snapshot` because its capacity has no
compile-time bound; tests iterate via `MapStore::coins()` / `edges()`
instead.

The refinement property is:

```text
view(rust_apply(s, op)) == model_apply(view(s), op)
```

for every valid state `s` and operation `op`, with matching accept/reject
behavior.

The abstraction is allowed to lose information. It must lose information, or it
is not an abstraction. The required property is not injectivity. The required
property is:

```text
if view(s1) == view(s2),
then s1 and s2 have the same enabled protocol operations
and those operations produce the same abstract outcomes
```

This is the anti-drift contract between Rust and the spec.

### ITF Replay

Refinement is mechanically checked by replaying every Quint-generated trace
against the Rust kernel. Each Quint state in `models/l1.qnt` carries
`lastInput` (the action that produced the state) and `lastEvent` (the
abstract event emitted), in addition to the live coin/edge state. The Rust
runner in `tests/itf.rs` is one impl of `itf::Runner` (Cosmos/Malachite
ecosystem standard) that:

1. Deserializes each `.itf.json` fixture into a Rust `State` mirroring the
   Quint variable shape.
2. For each step, reads `lastInput` from the trace and synthesizes the
   corresponding `Op`.
3. Calls `state.apply(context, &FAKE_VERIFIER, &op)`, capturing the emitted
   `EventKind`.
4. Asserts the kernel event matches `lastEvent` (`result_invariant`) and the
   kernel's live state matches the abstract trace (`state_invariant`) at
   every step.

A single glob-based test replays every committed fixture; adding a new Quint
trace test means adding a fixture and zero Rust code. Fixtures whose actions
require placeholder verification are skipped under `--no-default-features`
(production semantics) and run under `--features fake-crypto`.

## Atomic Transitions

Kernel transitions are atomic. A successful `apply` commits exactly one state
transition and returns its `Event`. A failing `apply` leaves state unchanged. A
successful `apply_all` commits one ordered batch and returns a bounded `Diff<N>`
containing the ordered events; any failing operation leaves the whole batch
uncommitted and returns no diff. `apply_block` is the node-facing wrapper around
the same transition, taking a `Block<N>` that pairs `Context` with ordered ops.

The implementation enforces this through the store's transaction boundary,
with the verifier injected as a separate parameter (kernel is verifier-
agnostic; see [Verifier Boundary](#verifier-boundary)):

```rust
impl<S: Store> State<S> {
    pub fn apply<V: Verifier + ?Sized>(
        &mut self,
        ctx: Context,
        verifier: &V,
        op: &Op,
    ) -> KernelResult<Event> {
        let mut tx = self.store.begin();
        let change = op.apply(ctx, verifier, &tx)?;
        change.fold(&mut tx)?;
        tx.commit();
        Ok(change.event())
    }

    pub fn apply_all<V: Verifier + ?Sized, const N: usize>(
        &mut self,
        ctx: Context,
        verifier: &V,
        ops: &List<Op, N>,
    ) -> KernelResult<Diff<N>, BatchError> {
        let mut tx = self.store.begin();
        let mut diff = Diff::empty();
        for (index, op) in ops.iter().enumerate() {
            let event = Self::fold_one(&mut tx, ctx, verifier, op)
                .map_err(|source| BatchError::new(index, source))?;
            diff.push(&event);
        }
        tx.commit();
        Ok(diff)
    }

    pub fn apply_block<V: Verifier + ?Sized, const N: usize>(
        &mut self,
        verifier: &V,
        block: &Block<N>,
    ) -> KernelResult<Diff<N>, BatchError> {
        self.apply_all(block.context(), verifier, block.ops())
    }
}
```

Validation runs read-only against `&Tx`. Mutation runs via `Change::fold`
against `&mut Tx`. `Tx::commit` is called only after both phases succeed; a
dropped (uncommitted) `Tx` rolls back.

This gives property tests a clean handle: every test can reason about `pre`,
`op`, and `post` without worrying about intermediate state.

## Verification Plan

Use different tools for different layers.

### Rust Unit Tests And Proptest

Use for the concrete implementation:

- local transition behavior
- regression tests for discovered bugs
- random multi-step traces
- failure atomicity
- coin conservation

This is the first line of defense. Layered as:

- `tests/channel/` — focused unit tests per operation shape (open, resolve,
  batch, op).
- `tests/sequence.rs` — proptest over random `Op` sequences asserting
  kernel-level invariants (coin/edge conservation).
- `tests/state_machine.rs` — `proptest-state-machine` driving random
  sequences against a `BTreeMap`-backed Rust reference model with
  shrinking. Catches state-tracking divergence between kernel and a
  hand-readable spec impl.
- `tests/parallel.rs` — declared access sets compose into disjoint waves;
  reverse-order execution within a wave produces the same state as ordered.
- `tests/allocation.rs` — `allocation-counter` asserts zero heap allocation
  on the hot apply path.
- `tests/secp256k1.rs` (under `--features secp256k1`) — real ECDSA
  signatures resolve through `Agreement` end-to-end; forged signatures
  reject with `BadSignature`.
- `tests/map_store.rs` — `MapStore` round-trips and 32-edge chains validate
  the `Store` trait composes with non-bounded backends.

### Stateright

Use for small exhaustive Rust-native state exploration:

- all short `Op` sequences over small states
- no double spend
- open consumes input coins exactly once
- resolve consumes input edges exactly once
- payout coins can be reused
- open/resolve sequences preserve L1 invariants
- channel/protocol models cover claim/challenge sequences

Stateright is the best immediate bridge between proptest and formal specs
because it returns executable traces and stays close to Rust.

### Kani

Use later for bounded proof harnesses over stable transition functions.

Kani is useful when the surface is small and deterministic. It is less useful if
the harness spends most of its effort on hash functions, maps, or allocator
internals.

### Verus

Use after the kernel API stabilizes.

Verus is for durable proofs such as:

```text
valid(pre) and apply(pre, op) = post
=> valid(post)
```

It should not be the first tool while the model is still moving. Proof repair
cost is real. Use exploration tools to discover the right state machine, then
use Verus to lock down the stable kernel.

### Quint

Use for abstract protocol models:

- L1 abstraction
- synchronous channel model
- validity gadget abstraction
- assume/guarantee composition

Start without Choreo. First prove the math of claims, deadlines, challenges,
and verdicts under perfect delivery.

The first synchronous L1 model lives in `models/l1.qnt`. It mirrors the Rust
operation vocabulary at an abstract level: `OpenEdge`, `ResolveEdge`, bounded
resolve proof kinds, explicit block height for timeout, live coins, live edges,
and a finite state universe suitable for simulation and trace export. The
separate `models/fees.qnt` model pins the payment-accounting invariant:
principal plus live reserve plus value already paid to the protocol equals
genesis funding.
When the Rust operation vocabulary grows, update these models in the same
change: add the abstract transition, extend the named `*Test` traces,
regenerate the ITF fixtures with `npm run quint:fixtures`, and keep the Rust
replay tests aligned.

### Choreo Or P

Use when the distributed behavior matters:

- message delays
- message loss
- local party knowledge
- timeouts as events
- adversarial scheduling
- watcher availability

Choreo keeps the model in the Quint ecosystem. P is also a serious candidate
for communicating state machines, systematic interleaving exploration, and
runtime log monitoring. Choose when the async layer is concrete enough to judge
ergonomics.

### TLC

Use for temporal/liveness properties:

- no early resolve
- valid challenge blocks timeout resolve
- unchallenged claim eventually becomes resolvable under fairness assumptions
- challenged claim eventually resolves under fairness assumptions

The important part is fairness. Liveness properties are false unless the model
states assumptions about block production, transaction inclusion, and live
watchers.

### UPPAAL TIGA

Use if challenge-window security becomes a timed adversarial game:

- watcher versus adversarial provider
- deadline race
- inclusion latency
- minimum safe challenge-window length

This is not needed for the first kernel, but it is the right family of tools for
timed games.

### Tamarin

Use for cryptographic protocol details:

- signatures
- replay resistance
- freshness
- attestation key binding
- fraud-proof message authentication
- multi-session attacks

Do not model cryptographic byte formats in the top-level channel model. Model
them separately when they become protocol-critical.

## Composition Strategy

Verify in layers:

1. L1 alone
   - UTXO safety
   - edge lifecycle
   - resolve proof acceptance/rejection
   - coin conservation

2. Validity gadget alone
   - accepted claims satisfy that gadget's assumptions
   - invalid claims are rejected or challengeable
   - verdicts are final

3. Channel with abstract L1 and abstract gadget
   - signed state progression
   - claim/challenge timing
   - watcher obligations
   - stale-state protection

4. L1 with abstract consensus
   - finalized transaction order is applied deterministically
   - invalid transactions cannot produce successful events
   - height and finality assumptions are explicit

5. Full abstract system
   - channel transactions feed L1
   - L1 events feed channel
   - validity gadgets decide claims
   - consensus finalizes transaction order

6. Rust refinement
   - traces from the model replay against Rust
   - Rust `View` matches the model state after every step

## What Not To Do

Do not build one giant model of everything.

Do not model a third-party consensus protocol white-box unless the Hellas
property depends on its internals.

Do not put real TEE quotes, ZK proof bytes, or hash preimages into the top-level
protocol model.

Do not let the formal model speak a different operation vocabulary from Rust.

Do not treat liveness as unconditional. Liveness depends on fairness and
watcher obligations.

Do not force every verifier to cover every layer. Different tools are useful
because the system has genuinely different kinds of correctness obligations.

## Near-Term Work

The kernel-shaped items previously listed here are done:

- Serialized ITF trace fixtures from `models/l1.qnt` are committed under
  `models/traces/`. The Rust runner is `itf::Runner`-based; adding a Quint
  trace test means regenerating fixtures, no Rust changes.
- Placeholder `Sig` / `Seal` verification has been replaced by a `Verifier`
  trait the caller wires in. The kernel implements no cryptography. A
  reference `Secp256k1Verifier` lives under the `secp256k1` feature flag.

What's left, in roughly increasing depth:

1. **Adapter layer.** `Call` / `CallResult` / `Claim` / `Evidence` shapes
   that produce the resolve proofs the kernel's `Verifier` will accept. Out
   of crate.
2. **Channel layer.** Off-chain state, signed frontiers, claim/challenge
   timing, watcher obligations. The async/distributed shape moves to Choreo
   or P when the synchronous channel math is settled. Out of crate.
3. **Consensus integration.** The kernel assumes ordered finalized blocks;
   that's the contract. Wiring to a real consensus implementation is
   downstream.
4. **Persistent storage backend.** The `Store` trait composes with
   non-bounded backends (validated by `MapStore`). A real persistent
   backend (likely commonware-storage `qmdb` per PERF.md §5) implements
   `Store` outside this crate.
