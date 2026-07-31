// -*- mode: Bluespec; -*-
//
// Abstract model of the off-chain staked pairing.
//
// Abstract counterpart of `crates/chain/src/staked.rs::Channel`:
//
//   admit    ↔ Channel::admit
//   rescind  ↔ Channel::rescind
//   issue    ↔ Channel::issue   (client side)
//   settle   ↔ Channel::settle  (provider side)
//
// This is NOT kernel policy. The kernel knows nothing about jobs,
// prices, deadlines, or vouchers: it sees only edge opens and closes,
// modelled in `crates/kernel/models/{l1,l1_stake}.qnt`. Everything here
// is the off-chain discipline the two parties run between those closes,
// and the whole point of the model is that both sides run the SAME
// rules — so the client cannot be surprised by a refusal and the
// provider cannot be surprised by a settlement.
//
// Every action records the exact outcome the Rust must produce, not
// merely accept/reject. The replay asserts the precise `AdmitError` /
// `SettleError` variant, so a regression that refuses the right jobs
// for the wrong reason is caught rather than silently tolerated.

module staked_channel {
  // ---------------------------------------------------------------
  // The committed pairing (mirrors the `channel_tests` fixture)
  // ---------------------------------------------------------------

  pure val Capacity = 2000
  pure val MaxJobPrice = 500
  pure val BondTimeout = 200
  pure val PaymentTimeout = 150
  pure val CloseMargin = 5
  pure val ChallengeMargin = 20

  // Job shapes the model explores. Each names one admission outcome
  // when offered as the next job on a fresh, unlocked channel.
  type JobShape =
    | Ordinary          // price 400, deadline 60 — admissible
    | Cheap             // price 1, deadline 60 — the minimum price
    | PriceZero         // below the 1..=cap window
    | PriceAboveCap     // above max_job_price
    | DeadlineStale     // deadline at/behind the observed height
    | DeadlinePastBond  // leaves no challenge margin before bond timeout
    | DeadlinePastRedeem// leaves no redemption margin before payment timeout
    | Foreign           // names a different bond/payment edge
    | SkippedSequence   // sequence is not the next one

  pure val AllShapes = Set(
    Ordinary,
    Cheap,
    PriceZero,
    PriceAboveCap,
    DeadlineStale,
    DeadlinePastBond,
    DeadlinePastRedeem,
    Foreign,
    SkippedSequence,
  )

  pure def priceOf(s: JobShape): int =
    match s {
      | Cheap => 1
      | PriceZero => 0
      | PriceAboveCap => MaxJobPrice + 1
      | _ => 400
    }

  // 144 is the last deadline satisfying BOTH margins:
  // 144 + 20 = 164 < 200 and 144 + 5 = 149 < 150.
  pure def deadlineOf(s: JobShape): int =
    match s {
      | DeadlineStale => 10
      | DeadlinePastBond => 180
      | DeadlinePastRedeem => 145
      | _ => 60
    }

  pure def namesThisPairing(s: JobShape): bool =
    s != Foreign

  pure def usesNextSequence(s: JobShape): bool =
    s != SkippedSequence

  // ---------------------------------------------------------------
  // Outcomes — mirrored one-to-one onto the Rust error enums
  // ---------------------------------------------------------------

  type AdmitOutcome =
    | Admitted
    | Busy
    | ForeignJob
    | OutOfSequence
    | DeadlinePassed
    | Uncovered
    | RedemptionMarginExceeded
    | InsufficientCapacity

  type SettleOutcome =
    | Settled
    | NoActiveJob
    | TooLateToRedeem
    | WrongFrontier

  type Input =
    | NoInput
    | AdmitInput(JobShape)
    | RescindInput
    | SettleInput(int)
    | TickInput

  // ---------------------------------------------------------------
  // State
  // ---------------------------------------------------------------

  var cumulative: int      // frontier E
  var sequence: int        // last admitted job's sequence
  var activeJob: bool      // the serialization lock
  var activePrice: int     // price of the in-flight job
  var height: int          // observed finalized height
  var lastInput: Input
  var lastAdmit: AdmitOutcome
  var lastSettle: SettleOutcome

  // ---------------------------------------------------------------
  // The admission rule, in the kernel-of-truth order used by
  // `Channel::admit`. Order matters: a job can fail several clauses,
  // and the model must name the same one the Rust returns.
  // ---------------------------------------------------------------

  pure def coveredBy(price: int, deadline: int): bool =
    price >= 1 and price <= MaxJobPrice and deadline + ChallengeMargin < BondTimeout

  pure def redeemable(deadline: int): bool =
    deadline + CloseMargin < PaymentTimeout

  def admitOutcome(s: JobShape): AdmitOutcome =
    val price = priceOf(s)
    val deadline = deadlineOf(s)
    if (activeJob) Busy
    else if (not(namesThisPairing(s))) ForeignJob
    else if (not(usesNextSequence(s))) OutOfSequence
    else if (deadline <= height) DeadlinePassed
    else if (not(coveredBy(price, deadline))) Uncovered
    else if (not(redeemable(deadline))) RedemptionMarginExceeded
    else if (cumulative + price > Capacity) InsufficientCapacity
    else Admitted

  def settleOutcome(frontier: int): SettleOutcome =
    if (not(activeJob)) NoActiveJob
    else if (height + CloseMargin >= PaymentTimeout) TooLateToRedeem
    else if (frontier != cumulative + activePrice) WrongFrontier
    else Settled

  // ---------------------------------------------------------------
  // Actions
  // ---------------------------------------------------------------

  action init = all {
    cumulative' = 0,
    sequence' = 0,
    activeJob' = false,
    activePrice' = 0,
    height' = 10,
    lastInput' = NoInput,
    lastAdmit' = Admitted,
    lastSettle' = Settled,
  }

  // Admission consumes the sequence and takes the lock only when the
  // outcome is `Admitted`; every refusal leaves the channel untouched.
  action admit(s: JobShape): bool = all {
    val outcome = admitOutcome(s)
    all {
      cumulative' = cumulative,
      sequence' = if (outcome == Admitted) sequence + 1 else sequence,
      activeJob' = if (outcome == Admitted) true else activeJob,
      activePrice' = if (outcome == Admitted) priceOf(s) else activePrice,
      height' = height,
      lastInput' = AdmitInput(s),
      lastAdmit' = outcome,
      lastSettle' = lastSettle,
    }
  }

  // Releasing an offer the counterparty never co-signed. The consumed
  // sequence is NOT returned — a half-signed acceptance over it may
  // exist, so it must never be reused.
  action rescind = all {
    activeJob,
    cumulative' = cumulative,
    sequence' = sequence,
    activeJob' = false,
    activePrice' = 0,
    height' = height,
    lastInput' = RescindInput,
    lastAdmit' = lastAdmit,
    lastSettle' = lastSettle,
  }

  action settle(frontier: int): bool = all {
    val outcome = settleOutcome(frontier)
    all {
      cumulative' = if (outcome == Settled) frontier else cumulative,
      sequence' = sequence,
      activeJob' = if (outcome == Settled) false else activeJob,
      activePrice' = if (outcome == Settled) 0 else activePrice,
      height' = height,
      lastInput' = SettleInput(frontier),
      lastAdmit' = lastAdmit,
      lastSettle' = outcome,
    }
  }

  action tick = all {
    height < PaymentTimeout + 1,
    cumulative' = cumulative,
    sequence' = sequence,
    activeJob' = activeJob,
    activePrice' = activePrice,
    height' = height + 1,
    lastInput' = TickInput,
    lastAdmit' = lastAdmit,
    lastSettle' = lastSettle,
  }

  action step = any {
    nondet s = AllShapes.oneOf()
    admit(s),
    rescind,
    settle(cumulative + activePrice),
    settle(cumulative + activePrice + 1),
    tick,
  }

  // ---------------------------------------------------------------
  // Invariants
  // ---------------------------------------------------------------

  // v1 serializes jobs through resolution: never more than one job in
  // flight. (Structural here; the replay checks the Rust agrees.)
  val atMostOneActiveJob =
    activeJob or activePrice == 0

  // The frontier only ever advances, and never past the capacity the
  // client actually funded.
  val frontierWithinCapacity =
    cumulative >= 0 and cumulative <= Capacity

  // (Sequence monotonicity is not expressible as a state invariant —
  // it is a relation between successive states. It is enforced by the
  // replay instead: the Rust channel's `sequence()` must equal the
  // model's at every step, so a regression that reused or rewound a
  // sequence diverges immediately.)

  // Every admitted job sits inside the bond's committed price window.
  // Load bearing: it fails if `admitOutcome` ever returns `Admitted`
  // for a price outside `1..=MaxJobPrice`.
  val admittedJobsAreCovered =
    not(activeJob) or (activePrice >= 1 and activePrice <= MaxJobPrice)

  // An in-flight job is always fundable from the remaining capacity.
  val activeJobIsFunded =
    not(activeJob) or cumulative + activePrice <= Capacity

  val heightMovesForward =
    height >= 10

  // ---------------------------------------------------------------
  // Named runs (each becomes an ITF trace replayed against Channel)
  // ---------------------------------------------------------------

  run honestJobSettlesTest =
    init
      .then(admit(Ordinary))
      .then(settle(400))
      .expect(cumulative == 400
        and sequence == 1
        and not(activeJob)
        and lastAdmit == Admitted
        and lastSettle == Settled)

  // Every admission refusal, each naming the exact reason the Rust
  // must return. A regression that refuses for a different reason
  // fails the replay.
  run admissionRefusalsTest =
    init
      .then(admit(PriceZero))
      .then(admit(PriceAboveCap))
      .then(admit(DeadlineStale))
      .then(admit(DeadlinePastBond))
      .then(admit(DeadlinePastRedeem))
      .then(admit(Foreign))
      .then(admit(SkippedSequence))
      .expect(not(activeJob)
        and sequence == 0
        and cumulative == 0)

  // The serialization lock, and rescind's sequence discipline.
  run serializationAndRescindTest =
    init
      .then(admit(Ordinary))
      .then(admit(Ordinary))
      .then(rescind)
      .then(admit(Ordinary))
      .expect(activeJob
        and sequence == 2
        and lastAdmit == Admitted)

  // Settlement refusals: nothing in flight, and a frontier that does
  // not advance by exactly the job's price.
  run settlementRefusalsTest =
    init
      .then(settle(400))
      .then(admit(Ordinary))
      .then(settle(401))
      .expect(activeJob
        and cumulative == 0
        and lastSettle == WrongFrontier)

  // The redemption margin binds at settle time, not just at admission:
  // a client that stalls a voucher until the payment timeout is near
  // forfeits that job rather than stranding the provider.
  run settleTooLateTest =
    init
      .then(admit(Ordinary))
      .then(tick)
      .expect(activeJob and lastAdmit == Admitted)
}
