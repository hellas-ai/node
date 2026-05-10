// -*- mode: Bluespec; -*-
//
// Common type vocabulary for the L1 abstract model.
//
// These ADTs are pure values shared across `verifier.qnt`, `deps/`, `rules/`,
// and `l1.qnt` itself. They mirror the Rust kernel's public types one-to-one:
//
//   Coin   ↔ src/object.rs::Coin       (live coin id, abstracted to a tag)
//   Edge   ↔ src/object.rs::Edge       (live edge id, abstracted to a tag)
//   Proof  ↔ src/op/proof.rs::Proof    (resolve witness kind)
//   Input  ↔ src/op/mod.rs::Op + Tick/Idle scaffolding
//   Event  ↔ src/event.rs::EventKind
//
// The module is type-only — no state vars, no actions, no predicates that
// touch state. Importing it gives any module the vocabulary to talk about
// kernel objects without taking on ownership of the model's state.

module types {
  // The fixed-finite universe of coin ids the small L1 model explores. Two
  // genesis coins (MakerCoin, TakerCoin) plus four payout outputs let us
  // exercise open → resolve → open → resolve sequences without an unbounded
  // id generator. The outputs of Edge1's resolve are exactly Edge2's
  // funding inputs.
  type Coin =
    | MakerCoin
    | TakerCoin
    | MakerOut1
    | TakerOut1
    | MakerOut2
    | TakerOut2

  // The fixed-finite universe of edge ids. Edge2 is funded from Edge1's
  // resolve outputs, so at most one is ever live in a well-formed trace.
  type Edge =
    | Edge1
    | Edge2

  // Resolve witness kind. `Basic` is the modelling/fake-crypto witness;
  // production Rust accepts it only under the `fake-crypto` feature.
  // `Timeout` is the proof-free production path. Agreement / ClaimantWins /
  // ChallengerWins stand in for preverified evidence.
  type Proof =
    | Basic
    | Agreement
    | Timeout
    | ClaimantWins
    | ChallengerWins

  // The action that produced the current state. `NoInput` marks the initial
  // state; every other action records its input here. The Rust ITF runner
  // reads `lastInput` from each trace state, drives the kernel with it, and
  // asserts the kernel's emitted event against `lastEvent`.
  type Input =
    | NoInput
    | OpenInput(Edge)
    | ResolveInput({ edge: Edge, proof: Proof, makerPay: int, takerPay: int })
    | TickInput
    | IdleInput

  // Public-event abstraction emitted by the action that produced the
  // current state. `NoEvent` marks init/tick/idle steps that change no live
  // objects. Open / Resolve produce `EdgeOpenedEvent` / `EdgeResolvedEvent`.
  type Event =
    | NoEvent
    | EdgeOpenedEvent(Edge)
    | EdgeResolvedEvent(Edge)

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
  pure val AllProofs = Set(Basic, Agreement, Timeout, ClaimantWins, ChallengerWins)

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

  // Canonical input/output wiring. Each edge's funding sources and resolve
  // outputs are positionally fixed; the kernel does the same via id
  // derivation in `Open::id` and `CoinId::payout`.
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
}
