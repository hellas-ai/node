# Hellas Kernel Model

This document describes the small formal core of Hellas: the parts that must be
specified, tested, and eventually verified for the larger system to be
trustworthy.

The high-level economic security goal is documented in
`PROTOCOL_SECURITY_MODEL.md`. This document focuses on the implementation and
formal-model boundary that supports that goal.

The modeling method is documented in `FORMAL_MODELING_STRATEGY.md`: keep a
family of small models over a shared algebra, promote focused obligations into
integrated models, and avoid locking the protocol into mechanisms before the
invariants require them.

The main design rule is decomposition. The full system is too large to model as
one machine. We model small machines with explicit interfaces, then prove or
test that the interfaces compose.

## Kernel Boundary

The kernel is not the model runner, RPC server, Python worker, tokenizer,
provider gateway, or p2p content network.

This document uses "kernel" for the small formal core of the protocol. The hot
L1 kernel is the smaller live-state machine inside that core: coins, live
edges, and close operations. State-channel frontiers, receipts, claims, and
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
  escrows coins, opens edges, closes edges, and mints payout coins

consensus
  finalizes an ordered log of L1 transactions
```

## The Shared Vocabulary

All models and implementations should meet at the same operation vocabulary.
This keeps the Rust code and the formal models from drifting.

```rust
enum Tx {
    Open(Open),
    Close(Close),
}

enum EventKind {
    EdgeOpened { inputs: List<CoinId, MAX_EDGE_INPUTS>, output: EdgeId },
    EdgeClosed { input: EdgeId, outputs: List<CoinId, MAX_EDGE_OUTPUTS> },
}
```

The L1 operation vocabulary is intentionally small. Claims, receipts,
frontiers, challenges, and dispute transcripts are state-channel/protocol
objects exchanged peer-to-peer. L1 only sees them if a close transaction
carries some bounded close proof derived from them.

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
tx_apply(ctx, &(SigVerifier + SealVerifier), &Batch, Tx) -> KernelResult<Change>   // read-only
change_fold(&mut Batch, &Change)                          -> KernelResult<()>      // private mutation
```

The `SigVerifier` / `SealVerifier` pair is the crypto boundary; `Batch` is
the storage boundary. Both are caller-supplied interfaces, both pure during
validation.

- `Event` is the public opaque fact emitted by an operation. Its constructors
  are private; external code cannot fabricate events.
- `Change` is the crate-private reducer output: the public `Event` plus the
  private `Effect` needed to fold the mutation. External code can observe the
  event, but it cannot fabricate or replay effects.
- The only paths to a `State` value are `Genesis::coin` seeds and
  `State::apply(prev, tx)?`.
- Mutation lives in one private fold per tx. No other code mutates the store.
- Validation and fold must observe the same `Batch` working state. The
  `CoinChanged` and `EdgeChanged` errors exist only to catch a misbehaving
  `Batch` implementation that returns one object during validation and removes
  a different object during fold.

By induction, every reachable kernel state equals either a set of genesis coins
or `apply(prev, tx)?` for some tx. The model checker explores the transition
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
edge domain tag, maker/taker funding ids, parties, and `TermsHash`. `Close`
derives each payout `CoinId` from the coin domain tag, consumed `EdgeId`, output
position, and owner key. `from_bytes` constructors exist for decoding
already-canonical live state references, genesis seeds, and store keys; they are
not part of output selection.

### Typed Store Boundary

The store presents a typed `Batch` interface. The kernel asks for "the coin at
this `CoinId`" or "the edge at this `EdgeId`", never for "the object at id X".
Storage representation is an implementation choice and does not cross the API
boundary.

```rust
trait Store {
    type Batch<'a>: Batch where Self: 'a;
    fn begin(&mut self) -> Self::Batch<'_>;
}

trait Batch {
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

The kernel implements no cryptography. Two narrow traits draw the
kernel/crypto seam, each scoped to exactly one kind of verification:

```rust
trait SigVerifier {
    fn verify_sig(&self, sig: Sig, key: Key, hash: PayloadHash) -> bool;
}

struct SealPublicInputs<'a> {
    pub edge_id: EdgeId,
    pub protocol: ProtocolCode,
    pub terms_hash: TermsHash,
    pub payouts: &'a List<Payout, MAX_EDGE_OUTPUTS>,
}

trait SealVerifier {
    fn verify_seal(&self, seal: Seal, public: &SealPublicInputs<'_>) -> bool;
}
```

The three `Proof` variants map cleanly onto where validation belongs:

| Variant      | Validator      | Where             |
|--------------|----------------|-------------------|
| `Mutual`     | `SigVerifier`  | external          |
| `Timeout`    | structural     | kernel inline     |
| `Violation`  | `SealVerifier` | external          |

`Mutual` calls `verify_sig` twice (maker, taker) over the canonical close
payload hash, and is only admissible before the edge's committed timeout.
`Timeout` needs no cryptography — the kernel checks
`terms.hash() == edge.terms()`, `context.block_height() >= edge.timeout()`,
and `payouts == terms.timeout_outputs()` inline. `Violation` is also
pre-timeout: after the terms hash matches, the kernel builds
`SealPublicInputs` from the close transaction and live edge, hands them to
`verify_seal`, and forwards a `BadSeal` rejection if the seal isn't
admissible. The kernel itself never inspects seal bytes; the verifier is the
sole authority on whether they admit the close.

`State::apply(context, &verifier, tx)` takes a single `V` constrained by
`SigVerifier + SealVerifier`. Test verifiers (`FakeVerifier`,
`RejectVerifier`) implement both traits on one struct, so callers pass a
single value. Production deployments compose: `Secp256k1Verifier` is the
included reference `SigVerifier` for cooperative closes, and a
protocol-specific `SealVerifier` (ZK proof verifier, TEE attestation
checker, fraud-game seal checker) is wired alongside. There is no kernel-
side cfg flag for proof admission; the only difference between production
and test builds is which `Sig`/`Seal` verifiers they compose.

### Per-Digest Types

Every 32-byte digest the kernel handles has its own newtype: `BlockHash`,
`TermsHash`, and one per future digest purpose (claim hashes, evidence hashes,
transaction roots, ...). They share a private `[u8; 32]` shape but are not
interchangeable; the compiler stops cross-purpose assignment. They derive
`Ord` and `PartialOrd` over their byte representation so they compose with
`BTreeMap` and other ordered collections — useful for production stores and
test reference models alike.

`Edge` carries principal value, prepaid close reserve, the open-time close fee
schedule, committed timeout height, `Parties { maker, taker }`, and a
`TermsHash`, not a stored terms object id. `Terms::Basic` is the current
concrete terms shape: protocol code, parties, the earliest timeout block
height, and the deterministic payout list accepted by a timeout close. It has a
deterministic no-allocation BLAKE3 commitment path:
`Terms::hash() -> TermsHash`.

Terms are still not on-chain state. The hot live object stores only
`TermsHash`; concrete terms are an input-side vocabulary used to derive that
commitment and later verify close proofs against it.

### Edge Funding Shape

`Open` consumes bounded bilateral `Funding { maker, taker }`, where each party
is a bounded list of `CoinId` values, and carries concrete `Terms` plus two
authorizing signatures `(maker_sig, taker_sig)`. The produced edge stores only
`TermsHash` and `Parties { maker, taker }` derived from those terms. The
produced `EdgeId` is canonical; it is not supplied by the caller.

The kernel enforces two authentication rules at apply time, before any
fee/reserve math:

1. **Owner match.** Every coin in `funding.maker` must have
   `coin.owner() == terms.parties().maker()`; same for the taker list. A
   mismatch returns `InvalidOpenReason::FundingUnauthorized`. This stops an
   attacker who knows live coin ids from locking someone else's coin into
   attacker-chosen terms.
2. **Dual signatures.** Both `maker_sig` and `taker_sig` must verify against
   `Tx::open_hash(funding, terms)` under the matching party's key, routed
   through the configured `SigVerifier`. The signed payload binds the
   canonical `EdgeId` (which already commits to funding ids and
   `TermsHash`) under a distinct domain separator so an open signature can
   never be replayed as a close signature or applied to a different edge.
   Failure returns `InvalidOpenReason::BadSignature`.

Either funding list may be empty; a one-sided or zero-funded open is valid when
total funding covers the context-priced open cost, the prepaid active lifetime,
and the close reserve for the worst-case bounded close path. **Both signatures
are still required even with empty funding** — naming a party in
`Terms::parties()` is itself the consent that needs witnessing. Funding is
invalid exactly when the sum of funding coin values is less than:

```text
context.fee(open.cost())
+ context.fees().lifetime() * (terms.timeout() - context.block_height())
+ context.fee(worst_case_close_cost)
```

The produced edge principal is the remaining value; the reserve is stored
separately and is not payable principal or slashable stake. The active lifetime
fee is paid at open and is not refunded. A future sponsored-key policy can make
the effective open debit zero for selected keys, but that is an explicit fee
policy extension rather than a special open shape.

Terms govern the deterministic timeout recovery path. For `Terms::Basic`, open
therefore rejects unless the timeout height is strictly in the future and the
committed `timeout_outputs` sum exactly to the produced edge principal plus the
reserve surplus left after the open-time committed timeout close fee. This
catches terms that would be already expired or structurally unclosable by
timeout before an edge is created, rather than discovering the mismatch at
close time. Future terms shapes must expose the same deterministic value
requirement or make their value domain explicit.

Maker and taker are positional party identities:
the maker is the party whose open intent or offer is filled, and the taker
is the party that fills it. They are not buyer/seller, requester/provider,
payer/worker, or any other economic meaning. The kernel does not require the
maker and taker keys to be distinct; self-edges are valid (both signatures
must still verify under the same key) and can represent sends, merges, or
no-work channels under higher-level protocol convention.

`Close` consumes one `Edge`, carries a bounded close proof, and creates a
bounded list of `Payout { owner, value }` values. Payout coin ids are canonical;
they are not supplied by the caller. `Proof` is one of three variants; each
maps to exactly one validation kind (see [Verifier Boundary](#verifier-boundary)):

- `Proof::Mutual { maker: Sig, taker: Sig }` is the cooperative path. Both
  signatures are taken over the canonical
  `Tx::payload_hash(edge_id, CloseKind::Mutual, edge.terms(), payouts)`. No
  terms are revealed on chain; the kernel computes the payload hash from
  `edge.terms()` and routes both sigs through `SigVerifier::verify_sig`.
  The proof is accepted only while `context.block_height() < edge.timeout()`.
  Production wires `Secp256k1Verifier` (or a preverified-cache verifier);
  tests wire `FakeVerifier` against the deterministic `Sig::placeholder`
  shape.
- `Proof::Timeout { terms: Terms }` reveals the concrete basic terms. The
  kernel enforces `terms.hash() == edge.terms()`,
  `context.block_height() >= edge.timeout()`, and that `payouts` equals the
  terms' committed timeout payout list inline — no verifier is involved
  because none of these checks need cryptography.
- `Proof::Violation { terms: Terms, seal: Seal }` is the dispute path. It
  reveals the concrete terms and carries a fixed-size protocol-specific
  `Seal`. The kernel binds `terms.hash() == edge.terms()` then builds a
  `SealPublicInputs { edge_id, protocol, terms_hash, payouts }` and routes
  the seal through `SealVerifier::verify_seal`. Like `Mutual`, it is accepted
  only while `context.block_height() < edge.timeout()`. The seal is opaque to
  the kernel: protocol-specific dispute games encode the winner inside its
  bytes, and the wired `SealVerifier` decides admissibility. This single
  variant subsumes the earlier separate claimant/challenger paths; the winner
  is read out of the seal at the verifier layer, not encoded in a kernel-level
  discriminant.

  The intended v1+ shape (currently unimplemented — every bundled verifier
  rejects `Violation` with `BadSeal`): the seal is a 32-byte commitment
  produced by a ZK system, with public inputs `(edge_id, terms.hash(),
  payouts)`. The protocol-specific verifier circuit attests "there exists a
  valid trace of the dispute game named by `terms.protocol()` whose terminal
  outcome maps to these payouts." Verification-key lookup happens via a
  chain-level `ProtocolCode → vk` registry maintained outside the kernel —
  `Terms` carries only the code. If the chosen ZK system produces succinct
  ≤32B proofs, the seal *is* the proof; otherwise the seal is a commitment
  (hash, Pedersen, KZG) and the verifier resolves the underlying proof blob
  out of band. Either way the kernel sees only 32 bytes and routes them to
  the verifier unchanged. This "proof normaliser" framing decouples the
  kernel from every protocol-specific dispute mechanism: Truebit-style
  interactive games, optimistic-rollup-style fraud proofs, MACI-style voting,
  or any future shape can all plug in by producing seals with the same
  public-input contract.

Empty close output is valid only when the edge principal plus reserve surplus
for that close path is zero. A close is valid against the principal and proof
committed by the edge; it is not repriced against the current block fee
schedule. The reserve and fee schedule were committed at open time. On close,
the committed close fee is consumed and the reserve surplus is materialized
through the ordinary close outputs. The reserve is not a penalty source;
violation penalties must debit explicit posted stake.

Every kernel rejection self-describes via a structured `ApplyError::Invalid*`
reason: `InvalidOpenReason { FundingInsufficient, FundingOverflow, FeeOverflow,
ReserveOverflow, TimeoutNotFuture, LifetimeFeeOverflow, TermsPayoutOverflow,
TermsValueMismatch, FundingUnauthorized, BadSignature }`,
`InvalidCloseReason { ValueMismatch, PayoutOverflow, ReserveTooSmall }`,
`InvalidProofReason { TermsMismatch, BadSignature, BadSeal, ProofExpired,
TimeoutNotReached, PayoutMismatch }`. Callers do not parse free text to tell
"I miscomputed payouts" (`ValueMismatch`) from "my proof does not match the
edge" (`InvalidProofReason::*`). `InvalidProofReason::BadSignature` and
`BadSeal` come from the wired verifiers; `TermsMismatch`, `ProofExpired`,
`TimeoutNotReached`, and `PayoutMismatch` come from the kernel's inline
lifetime and Timeout/Violation structural checks.

### Resource Costs

Every operation exposes a deterministic `Cost` derived only from bounded
operation shape:

```text
Cost { base, slots, proofs }
Fees { base, slot,  proof,  lifetime }
```

`base` is fixed per-tx overhead; `slots` counts every store slot the kernel
touches (each is read for the existence check and written for the
insert/remove that follows, so reads and writes are structurally equal and
fold into one dimension); `proofs` counts signature/seal verifications.
`lifetime` is not a [`Cost`] dimension: it prices one live edge slot per paid
block and is charged explicitly at open as
`context.fees().lifetime() * (terms.timeout() - context.block_height())`.

`Context` carries the active `Fees` schedule and prices costs with
`context.fee(tx.cost())`; that is execution pricing only. The L1 open path
charges the priced open cost and the lifetime fee from funding before creating
the edge, and locks a separate close reserve priced from the pessimistic
worst-case bounded close shape: `MAX_EDGE_OUTPUTS` plus the worst-case
`CloseKind`. With the collapsed three-variant proof model, `CloseKind::Mutual`
carries two signature-shaped witnesses and is the highest-cost variant at two
proof units; the reserve is sized to that.
Target v1 semantics are that close has no marginal fee. Opening an edge pays or
locks the complete bounded close execution cost up front, and later fee
schedule changes do not make the edge unclosable through the normal close path.
Active-channel lifetime is priced separately from close execution reserve:
current Rust charges one slot-price unit for each block between the open height
and the committed timeout height.

Current Rust follows the no-marginal-close-fee rule: `Edge` stores the open-time
fee schedule, close computes the committed fee from that stored schedule, and
any reserve surplus is paid through the close outputs. `Terms::Basic` represents
timeout principal and timeout reserve surplus as one flat payout list; richer
terms may split those domains explicitly later. `Edge` also stores the committed
timeout height: `Mutual` and `Violation` close paths are pre-timeout paths, and
`Timeout` is the at-or-after-timeout fallback. `Block::fits` checks the summed
block cost against a multi-dimensional resource budget before admission.

## L1 Model

The L1 machine owns the canonical UTXO state.

It tracks:

- coins
- live edge records
- explicit live-object sets in the abstract models, because zero value and
  absence are distinct
- bounded close operations
- block height
- finalized transaction order

It does not know how a model was executed, how a TEE attestation works, or how a
ZK proof was generated. It only knows how to open an edge, close an edge, and
route close proofs to the wired `SigVerifier` / `SealVerifier` configured by
the edge terms.

An edge is live-only. Existence means open. Open consumes funding coins and
creates the live edge. Close consumes the edge, deletes it from live L1 state,
and mints payout coins. There is no closed-edge status in live state;
historical closure belongs in events and block history.

### L1 Invariants

The basic invariants are:

- every coin is in exactly one location
- no live coin is spendable twice
- every live edge represents principal consumed from coins at open, minus the
  context-priced open cost, prepaid lifetime fee, and prepaid close reserve
- deterministic timeout terms pay out edge principal plus timeout reserve
  surplus, not gross funding
- opening an edge consumes funding coins, pays the derived fee, locks the
  derived reserve, commits a future timeout height, and creates the edge
  atomically
- closing an edge deletes the edge, pays only from the open-time committed
  close reserve, distributes any reserve surplus according to terms, and
  creates payout coins atomically
- `Mutual` and `Violation` closes are rejected at or after timeout; `Timeout`
  closes are rejected before timeout
- protocol costs are paid or locked before the mutation that creates the
  liability commits; close execution cost is committed at open
- close output coins exist after the close event
- close output coins may later be spent or escrowed into a new edge
- block height is monotonic
- finalized operations are applied in order
- accounted value across live coins, live edge principal, locked close reserves,
  and paid fees is conserved by every non-genesis operation

The subtle point is close outputs. The live L1 state should not retain a
closed-edge record to police those coins. Once minted, close outputs are
normal UTXOs. They must not be required to stay free forever.

## Channel Model

The channel machine owns off-chain state.

It tracks:

- channel participants
- signed channel states
- signed frontiers
- receipts and claims
- latest known sequence numbers
- proof deadlines
- off-chain dispute transcripts
- proof-submission obligations
- local party knowledge

The channel model never mutates L1 coins directly. It submits L1 transactions
and observes L1 events.

```text
channel --submits--> Open | Close
channel <--observes-- EdgeOpened | EdgeClosed
```

This is the first major composition boundary. The channel does not get to reach
into `State`. It only talks to L1 through transactions and events.

The frontier is not an L1 object. Frontier receipts, producer receipts,
off-chain dispute messages, and fraud-game transcripts are passed peer-to-peer
inside the channel. They matter to L1 only if they are summarized by a bounded
close proof in a close transaction.

Proof-submission obligations are not inferred from private silence. If failing
to submit a proof is meant to be slashable, the obligation must be part of
signed/public channel terms or a later signed state, name the obligor and
deadline, leave enough margin before expiry for inclusion, and be reducible to
a bounded violation seal. Otherwise the L1 sees only ordinary timeout fallback
if no valid final proof is posted before expiry.

Provider stake for jobs is modeled as one reusable posted stake pot plus
per-job logical locks. A job consumes provider stake capacity while it is
unresolved. The lock is released by a successor signed frontier that explicitly
marks the job accepted/released, by the job release deadline, or by a valid
violation proof that awards the configured job penalty to the violated party.
Local frontier queue state is not enough to release stake; the release must be
part of the signed channel state or otherwise reducible to the L1 proof
boundary.

Signed frontiers should commit to inflight job locks with an authenticated
root plus the aggregate locked stake total:

```text
Frontier {
  sequence,
  balances_root,
  active_job_locks_root,
  active_job_locked_total,
  available_provider_stake,
  stake_awards,
  terms_hash,
}
```

The useful shape is a Merkle-sum authenticated map over canonical `JobLock`
leaves, not just a plain membership root. The map root proves inclusion or
removal of a job lock; the sum proves the active locked stake total needed for
the provider stake-capacity invariant.

This is not an on-chain defense mechanism. A `Close` transaction is accepted
iff its proof is valid when submitted. Therefore the verifier relation must not
accept "there exists some old signed frontier where this job was active" as a
complete violation proof. A violation close proof must bind the frontier
commitment, job-lock leaf, penalty, payouts, and terms, and prove that these
public inputs define the final admissible close outcome under the channel
protocol. If that relation is not satisfied, the close is invalid; if it is
satisfied, the kernel accepts it without any later defense round.

### Watcher Liveness

The honest liveness claim is conditional.

Not:

```text
the client can always prove
```

Instead:

```text
if a party has funds at risk,
and a watcher for that party is live until the proof deadline,
and the watcher can deliver the required final proof or close data
before the prepaid lifetime expires,
then an invalid or stale claim cannot become the L1 close outcome by timeout
```

Watcher liveness is a participant obligation. It is not a global fact about the
network.

This matters because it shapes paid lifetime length, proof-deadline margin,
watch-tower delegation, bandwidth, storage, and economic assumptions. A party
without a live watcher accepts timeout fallback risk.

## Validity Gadgets

A validity gadget explains why a claim should be accepted or rejected.

Validity gadgets are not part of the L1 UTXO core, and they are not the same as
the off-chain channel protocol. They are protocol machines used by channel peers
to decide whether to accept, dispute off-chain, prove, or sign a frontier.

```text
channel protocol
  says when a party may claim, dispute off-chain, or produce a proof

validity gadget
  says what makes the claim valid, invalid, proven, slashable, or final

L1
  verifies only the bounded close proof required to release escrowed coins
```

The common shape is:

```rust
trait ValidityGadget {
    type Claim;
    type Evidence;
    type DisputeMove;
    type Verdict;

    fn accept_claim(claim: &Self::Claim, evidence: &Self::Evidence) -> bool;
    fn advance_dispute(claim: &Self::Claim, dispute_move: &Self::DisputeMove) -> DisputeStatus;
    fn resolve(
        claim: &Self::Claim,
        evidence: Option<&Self::Evidence>,
        dispute_move: Option<&Self::DisputeMove>,
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
- off-chain dispute: none
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
- off-chain dispute: fraud proof construction
- verdict: accept after deadline if no final fraud proof is produced,
  reject/slash if a final fraud proof is valid

Assumptions:

```text
FraudProofCompleteness:
  if a claim is false, an honest watcher can construct a valid fraud proof

WatcherLiveUntilProofDeadline:
  a party with funds at risk has a live watcher until the proof deadline

L1InclusionFairness:
  a valid final proof submitted before deadline is finalized before timeout
  settlement
```

The final property is conditional:

```text
under these assumptions, a false claim cannot settle
```

### Optimistic ZK

Optimistic ZK is not just "ZK with a delay". It is a fraud-game gadget where the
claim may contain commitments to a computation trace, and off-chain dispute
moves narrow the dispute until a small check can be performed.

Model it as its own gadget:

- claim: result plus trace commitments
- evidence: optional proof or trace metadata
- off-chain dispute move: disputed step, fraud witness, or bisection move
- verdict: accept, reject, slash, or continue dispute

The first model should not encode the full trace machinery. It should encode
the fraud-game contract:

```text
if claim is false and honest watcher is live,
then there exists an off-chain dispute path that produces a final reject/slash
proof before L1 finality
```

For stake-backed channel/job terms, that final reject/slash proof should also
bind the economic outcome: the violated party, the violator, and the configured
stake penalty. The protocol-specific verifier proves that the fraud-game
terminal state maps to those public outputs. The kernel should continue to see
only the bounded violation seal and public close outputs; stake-aware terms add
the separate stake transfer enabled by that verified violation.

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
view(rust_apply(s, tx)) == model_apply(view(s), tx)
```

for every valid state `s` and transaction `tx`, with matching accept/reject
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

Refinement is mechanically checked by replaying every committed
Quint-generated trace against the Rust kernel. Each replay model state carries
`lastInput` (the action that produced the state) and `lastEvent` (the abstract
event emitted), in addition to the live object state. `models/l1.qnt` covers
the focused L1 lifecycle and invalid-shape traces; `models/l1_fees.qnt` covers
the fee-bearing accepted-transition lifecycle. The Rust runner in `tests/itf.rs`
is one impl of `itf::Runner` (Cosmos/Malachite ecosystem standard) that:

1. Deserializes each `.itf.json` fixture into the Rust fixture schema that
   mirrors that Quint model's variable shape.
2. For each step, reads `lastInput` from the trace and synthesizes the
   corresponding `Tx`.
3. Calls `state.apply(context, &FAKE_VERIFIER, &tx)`, capturing the emitted
   `EventKind`.
4. Asserts the kernel event matches `lastEvent` (`result_invariant`) and the
   kernel's live state matches the abstract trace (`state_invariant`) at
   every step.

A single glob-based test replays every committed fixture. `npm run
quint:fixtures` regenerates both `l1_*.itf.json` and `l1_fees_*.itf.json`.
Fixtures use
`FakeVerifier`, which impls both `SigVerifier` and `SealVerifier` and accepts
the deterministic `Sig::placeholder` / `Seal::placeholder` shape; production
wires real verifier impls in its place.

## Atomic Transitions

Kernel transitions are atomic. A successful `apply` commits exactly one state
transition and returns its `Event`. A failing `apply` leaves state unchanged. A
successful `apply_all` commits one ordered batch and returns a bounded `Diff<N>`
containing the ordered events; any failing transaction leaves the whole batch
uncommitted and returns no diff. `apply_block` is the node-facing wrapper around
the same transition, taking a `Block<N>` that pairs `Context` with ordered txs.

The implementation enforces this through the store's transaction boundary,
with the verifier injected as a separate parameter (kernel is verifier-
agnostic; see [Verifier Boundary](#verifier-boundary)):

```rust
impl<S: Store> State<S> {
    pub fn apply<V: SigVerifier + SealVerifier + ?Sized>(
        &mut self,
        ctx: Context,
        verifier: &V,
        tx: &Tx,
    ) -> KernelResult<Event> {
        let mut batch = self.store.begin();
        let change = tx.apply(ctx, verifier, &batch)?;
        change.fold(&mut batch)?;
        batch.commit();
        Ok(change.event())
    }

    pub fn apply_all<V: SigVerifier + SealVerifier + ?Sized, const N: usize>(
        &mut self,
        ctx: Context,
        verifier: &V,
        txs: &List<Tx, N>,
    ) -> KernelResult<Diff<N>, BatchError> {
        let mut batch = self.store.begin();
        let mut diff = Diff::empty();
        for (index, tx) in txs.iter().enumerate() {
            let event = Self::fold_one(&mut batch, ctx, verifier, tx)
                .map_err(|source| BatchError::new(index, source))?;
            diff.push(&event);
        }
        batch.commit();
        Ok(diff)
    }

    pub fn apply_block<V: SigVerifier + SealVerifier + ?Sized, const N: usize>(
        &mut self,
        verifier: &V,
        block: &Block<N>,
    ) -> KernelResult<Diff<N>, BatchError> {
        self.apply_all(block.context(), verifier, block.txs())
    }
}
```

Validation runs read-only against `&Batch`. Mutation runs via `Change::fold`
against `&mut Batch`. `Batch::commit` is called only after both phases
succeed; a dropped (uncommitted) `Batch` rolls back.

This gives property tests a clean handle: every test can reason about `pre`,
`tx`, and `post` without worrying about intermediate state.

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

- `tests/channel/` — focused unit tests per transaction shape (open, close,
  batch, tx).
- `tests/sequence.rs` — proptest over random `Tx` sequences asserting
  kernel-level invariants (coin/edge conservation).
- `tests/state_machine.rs` — `proptest-state-machine` driving random
  sequences against a `BTreeMap`-backed Rust reference model with
  shrinking. Catches state-tracking divergence between kernel and a
  hand-readable spec impl.
- `tests/allocation.rs` — `allocation-counter` asserts zero heap allocation
  on the hot apply path.
- `tests/secp256k1.rs` (under `--features secp256k1`) — real ECDSA
  signatures close through `Proof::Mutual` end-to-end; forged signatures
  reject with `BadSignature`.
- `tests/map_store.rs` — `MapStore` round-trips and 32-edge chains validate
  the `Store` trait composes with non-bounded backends.

### Stateright

Use for small exhaustive Rust-native state exploration:

- all short `Tx` sequences over small states
- no double spend
- open consumes input coins exactly once
- close consumes input edges exactly once
- payout coins can be reused
- open/close sequences preserve L1 invariants
- channel/protocol models cover claim/proof sequences

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
valid(pre) and apply(pre, tx) = post
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

Start without Choreo. First prove the math of claims, proof deadlines, dispute
transcripts, and verdicts under perfect delivery.

The first synchronous L1 model lives in `models/l1.qnt`. It mirrors the Rust
operation vocabulary at an abstract level: `OpenEdge`, `CloseEdge`, bounded
close proof kinds, explicit block height for timeout, live coins, live edges,
and a finite state universe suitable for simulation and trace export.
`models/l1_fees.qnt` pins the payment-accounting invariant: principal plus live
reserve plus value already paid to the protocol equals genesis funding.
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

- no early close
- valid final proof beats timeout close when submitted before deadline
- claim without a final proof eventually falls back to timeout under fairness
  assumptions
- proven claim eventually closes under fairness assumptions

The important part is fairness. Liveness properties are false unless the model
states assumptions about block production, transaction inclusion, and live
watchers.

### UPPAAL TIGA

Use if proof-deadline security becomes a timed adversarial game:

- watcher versus adversarial provider
- deadline race
- inclusion latency
- minimum safe paid lifetime or proof-deadline margin

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
   - close proof acceptance/rejection
   - coin conservation

2. Validity gadget alone
   - accepted claims satisfy that gadget's assumptions
   - invalid claims are rejected or reduced off-chain to a final proof/seal
   - verdicts are final

3. Channel with abstract L1 and abstract gadget
   - signed state progression
   - proof generation and submission timing
   - expiry/timeout fallback obligations
   - stale receipts are not accepted as L1 proofs

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

- Serialized ITF trace fixtures from `models/l1.qnt` and `models/l1_fees.qnt`
  are committed under `models/traces/`. The Rust runner is `itf::Runner`-based;
  adding a trace test means regenerating fixtures and, for an existing fixture
  schema, no Rust changes.
- Placeholder `Sig` / `Seal` verification has been replaced by two narrow
  caller-wired traits: `SigVerifier` for cooperative-close signatures and
  `SealVerifier` for dispute seals. Timeout admissibility is structural and
  the kernel checks it inline. A reference `Secp256k1Verifier` lives under
  the `secp256k1` feature flag and supplies a real ECDSA `SigVerifier`;
  production deployments compose it with a protocol-specific `SealVerifier`
  (or a hard-reject stub if violations aren't yet supported).

What's left, in roughly increasing depth:

1. **Adapter layer.** `Call` / `CallResult` / `Claim` / `Evidence` shapes
   that produce the close proofs the kernel's `SigVerifier` /
   `SealVerifier` impls will accept. Out of crate.
2. **Channel layer.** Off-chain state, signed frontiers, proof generation and
   submission timing, watcher obligations. The async/distributed shape moves to
   Choreo or P when the synchronous channel math is settled. Out of crate.
3. **Consensus integration.** The kernel assumes ordered finalized blocks;
   that's the contract. Wiring to a real consensus implementation is
   downstream.
4. **Persistent storage backend.** The `Store` trait composes with
   non-bounded backends (validated by `MapStore`). A real persistent
   backend (likely commonware-storage `qmdb` per PERF.md §5) implements
   `Store` outside this crate.
