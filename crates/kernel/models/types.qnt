// -*- mode: Bluespec; -*-
//
// Common type vocabulary for the L1 abstract model.
//
// These ADTs are pure values shared across `verifier.qnt`, `rules/`, and
// `l1.qnt` itself. They mirror the Rust kernel's public types one-to-one:
//
//   Coin   ↔ src/object.rs::Coin       (live coin id, abstracted to a tag)
//   Edge   ↔ src/object.rs::Edge       (live edge id, abstracted to a tag)
//   Proof  ↔ src/tx/proof.rs::Proof    (close witness kind)
//   Input  ↔ src/tx/mod.rs::Tx + Tick/Idle scaffolding
//   Event  ↔ src/event.rs::EventKind
//
// The module is type-only — no state vars, no actions, no predicates that
// touch state. Importing it gives any module the vocabulary to talk about
// kernel objects without taking on ownership of the model's state.

module types {
  // The fixed-finite universe of coin ids the small L1 model explores. Two
  // genesis coins (MakerCoin, TakerCoin) plus four payout outputs let us
  // exercise open → close → open → close sequences without an unbounded
  // id generator. The outputs of Edge1's close are exactly Edge2's
  // funding inputs.
  type Coin =
    | MakerCoin
    | TakerCoin
    | MakerOut1
    | TakerOut1
    | MakerOut2
    | TakerOut2

  // The fixed-finite universe of edge ids. Edge2 is funded from Edge1's
  // close outputs, so at most one is ever live in a well-formed trace.
  type Edge =
    | Edge1
    | Edge2

  // Party identities the model reasons about. `Maker` and `Taker` are the
  // canonical owners of the maker/taker funding lineages; `Adversary` is
  // any third party who knows live coin ids but holds no ownership over
  // them. The abstraction is coarse — a single `Adversary` value stands
  // for the whole class of unauthorized actors — and is enough to express
  // the authorization invariant the kernel must enforce on open.
  type Party =
    | Maker
    | Taker
    | Adversary

  // Open authorization reduced to the security property the kernel needs:
  // the same maker/taker party keys that own the funding lineage and appear
  // in the terms authorized the open. Native and WebAuthn are witness
  // encodings for that same party identity, not separate authorization
  // namespaces.
  type OpenAuth = { maker: Party, taker: Party }

  // Canonical coin ownership. Every concrete coin in the closed universe
  // belongs to exactly one party; the abstraction mirrors the kernel's
  // `Coin::owner` field. `Adversary` never owns anything in any reachable
  // state — the whole point of the authorization property is that the
  // kernel must reject opens that try to consume coins not owned by the
  // claimed parties.
  pure def coinOwner(c: Coin): Party =
    match c {
      | MakerCoin => Maker
      | MakerOut1 => Maker
      | MakerOut2 => Maker
      | TakerCoin => Taker
      | TakerOut1 => Taker
      | TakerOut2 => Taker
    }

  // Close witness kind of a generic bilateral edge. The kernel admits
  // exactly these two shapes; all close-validity policy (terms binding,
  // height, payout shape, signature) lives in the verifier.
  type Proof =
    | Mutual
    | Timeout

  // The action that produced the current state. `NoInput` marks the initial
  // state; every other action records its input here. The Rust ITF runner
  // reads `lastInput` from each trace state, drives the kernel with it, and
  // asserts the kernel's emitted event against `lastEvent`.
  //
  // `RejectedOpenInput` / `RejectedCloseInput` record attempts the model's
  // preconditions refuse. They leave state untouched here, and the Rust
  // runner replays each one against the kernel, asserting the apply is
  // rejected and the store is unchanged — so "the kernel rejects what the
  // model rejects" is exercised by trace replay, not just stated by an
  // `expect(not(can...))` on the abstract side. The model carries no
  // rejection-reason taxonomy, so *which* `ApplyError` fires is pinned by
  // the kernel's unit tests, not by replay.
  type Input =
    | NoInput
    | OpenInput(Edge)
    | CloseInput({ edge: Edge, proof: Proof, makerPay: int, takerPay: int })
    | RejectedOpenInput({ edge: Edge, asMaker: Party, asTaker: Party })
    | RejectedCloseInput({ edge: Edge, proof: Proof, makerPay: int, takerPay: int })
    | TickInput
    | IdleInput

  // Public-event abstraction emitted by the action that produced the
  // current state. `NoEvent` marks init/tick/idle steps that change no live
  // objects. Open / Close produce `EdgeOpenedEvent` / `EdgeClosedEvent`.
  type Event =
    | NoEvent
    | EdgeOpenedEvent(Edge)
    | EdgeClosedEvent(Edge)

  // Closed-universe constants. New id families must be added here before
  // they can appear in invariants without breaking `liveCoinsAreKnown` /
  // `liveEdgesAreKnown`.
  pure val AllCoins = Set(
    MakerCoin,
    TakerCoin,
    MakerOut1,
    TakerOut1,
    MakerOut2,
    TakerOut2,
  )
  pure val AllEdges = Set(Edge1, Edge2)
  pure val AllProofs = Set(Mutual, Timeout)
  pure val AllParties = Set(Maker, Taker, Adversary)

  // Concrete model parameters. Picked small for finite exploration.
  pure val TimeoutHeight = 2
  pure val MakerValue = 10
  pure val TakerValue = 5
  pure val EdgeValue = MakerValue + TakerValue
  pure val MakerPayout = 7
  pure val TakerPayout = 8

  // Total live principal across the whole trace. Genesis funds two coins;
  // value is conserved across every transition, so `coinTotal + edgeTotal`
  // equals this constant in every reachable state.
  pure val Total = EdgeValue

  pure def canonicalCoinValue(c: Coin): int =
    match c {
      | MakerCoin => MakerValue
      | TakerCoin => TakerValue
      | MakerOut1 => MakerPayout
      | MakerOut2 => MakerPayout
      | TakerOut1 => TakerPayout
      | TakerOut2 => TakerPayout
    }

  // Canonical input/output wiring. Each edge's funding sources and close
  // outputs are positionally fixed; the kernel does the same via id
  // derivation in `Tx::edge_id_of` and `CoinId::payout`.
  pure def makerInput(e: Edge): Coin =
    match e {
      | Edge1 => MakerCoin
      | Edge2 => MakerOut1
    }

  pure def takerInput(e: Edge): Coin =
    match e {
      | Edge1 => TakerCoin
      | Edge2 => TakerOut1
    }

  pure def makerOutput(e: Edge): Coin =
    match e {
      | Edge1 => MakerOut1
      | Edge2 => MakerOut2
    }

  pure def takerOutput(e: Edge): Coin =
    match e {
      | Edge1 => TakerOut1
      | Edge2 => TakerOut2
    }

  // Sentinel value for edge slots that are not live. `Adversary` is never a
  // valid economic party key here; invariants only inspect open auth for live
  // edges, so this cannot be mistaken for a real authorization.
  pure val NoOpenAuth = { maker: Adversary, taker: Adversary }

  // The only authorization acceptable for this two-sided funding model is the
  // pair of party keys that owns the coins consumed by the edge.
  pure def canonicalOpenAuth(e: Edge): OpenAuth =
    { maker: coinOwner(makerInput(e)), taker: coinOwner(takerInput(e)) }

  pure def openAuthOk(e: Edge, auth: OpenAuth): bool =
    auth.maker == canonicalOpenAuth(e).maker
      and auth.taker == canonicalOpenAuth(e).taker

  pure def payoutSplitOk(makerPay: int, takerPay: int): bool =
    makerPay == MakerPayout and takerPay == TakerPayout
}
