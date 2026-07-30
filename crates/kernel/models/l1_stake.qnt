// -*- mode: Bluespec; -*-
//
// Kernel-level model of the stake bond edge.
//
// Abstract counterpart of the `Terms::StakeBond` half of the kernel:
//
//   openBond      ↔ src/tx/mod.rs::check_stake_bond_open
//   closeViolation ↔ src/tx/mod.rs::check_violation_payouts
//   closeTimeout  ↔ src/tx/mod.rs Timeout structural checks
//   Mutual        ↔ src/tx/proof.rs::CloseKindSet (StakeBond omits Mutual)
//
// Scope is deliberately one bond edge. The payment channel is an
// ordinary `Basic` edge already covered by `l1.qnt`, and the off-chain
// pairing (job admission, vouchers, margins) is *not* kernel policy —
// it lives in `chain::staked::Channel`, which has NO Quint model yet
// (its rules are covered by `chain::staked`'s Rust tests). The
// only rules asserted here are ones this kernel actually enforces:
// open arithmetic, the close-kind set, pinned slash routing, and the
// timeout return. Fees are zero (dev schedule), so the reserve surplus
// `Q` is zero and the client's slash payout is exactly the award.
//
// There is no adversary party. A violation is bilateral by
// construction — a fraud artifact carries both the client's and the
// provider's signatures — so no third party can assemble or profit
// from a slash. The treasury is a third *recipient*, never an actor.

module l1_stake {
  // ---------------------------------------------------------------
  // Universe
  // ---------------------------------------------------------------

  // Provider funds the stake (bond maker); Client is the committed
  // violation beneficiary (bond taker); Treasury receives the
  // non-award remainder and is required to be neither party.
  type Party =
    | Provider
    | Client
    | Treasury

  // One genesis coin funds the bond; the rest are close outputs. A
  // violation produces (ClientAward, TreasuryRemainder); a timeout
  // produces ProviderReturn.
  type Coin =
    | ProviderCoin
    | ClientAward
    | TreasuryRemainder
    | ProviderReturn

  type Proof =
    | Mutual
    | Timeout
    | Violation

  // The committed bond policy. Mirrors `StakeBondTerms` minus the
  // fields the kernel does not arithmetically constrain.
  type BondTerms = {
    stake: int,
    award: int,
    maxJobPrice: int,
    maxDisputeCost: int,
    challengeMargin: int,
    // The kernel compares `treasury` against both party keys; the
    // model carries the outcome of that comparison directly.
    treasuryIsParty: bool,
  }

  // The finite family of opens the model explores: one well-formed
  // bond plus one witness for every open rejection the kernel raises.
  // Mirrors the negative cases in tests/channel/bond.rs.
  type TermsVariant =
    | Valid
    | StakeMismatch
    | ZeroAward
    | AwardAboveStake
    | AwardBelowFloor
    | TreasuryIsParty
    | JobPriceCapZero
    | ChallengeMarginZero

  type CloseOutcome =
    | Unclosed
    | ClosedViolation
    | ClosedTimeout

  type Input =
    | NoInput
    | OpenInput(TermsVariant)
    | RejectedOpenInput(TermsVariant)
    | CloseInput({ proof: Proof, first: int, second: int })
    | RejectedCloseInput({ proof: Proof, first: int, second: int })
    | TickInput

  type Event =
    | NoEvent
    | EdgeOpenedEvent
    | EdgeClosedEvent

  // ---------------------------------------------------------------
  // Concrete parameters (small, for finite exploration)
  // ---------------------------------------------------------------

  pure val StakeValue = 10
  pure val AwardValue = 7
  pure val JobPriceCap = 4
  pure val DisputeCostCap = 3
  // AwardValue == JobPriceCap + DisputeCostCap: the award floor is
  // exactly met, which is the tightest admissible bond.
  pure val TimeoutHeight = 2

  pure val AllCoins = Set(
    ProviderCoin,
    ClientAward,
    TreasuryRemainder,
    ProviderReturn,
  )
  pure val AllProofs = Set(Mutual, Timeout, Violation)
  pure val AllVariants = Set(
    Valid,
    StakeMismatch,
    ZeroAward,
    AwardAboveStake,
    AwardBelowFloor,
    TreasuryIsParty,
    JobPriceCapZero,
    ChallengeMarginZero,
  )

  pure val ValidTerms: BondTerms = {
    stake: StakeValue,
    award: AwardValue,
    maxJobPrice: JobPriceCap,
    maxDisputeCost: DisputeCostCap,
    challengeMargin: 1,
    treasuryIsParty: false,
  }

  // Each variant perturbs exactly one field, so a rejection identifies
  // exactly one kernel check.
  pure def termsFor(v: TermsVariant): BondTerms =
    match v {
      | Valid => ValidTerms
      | StakeMismatch => { ...ValidTerms, stake: StakeValue - 1 }
      | ZeroAward => { ...ValidTerms, award: 0 }
      | AwardAboveStake => { ...ValidTerms, award: StakeValue + 1 }
      | AwardBelowFloor => { ...ValidTerms, award: AwardValue - 1 }
      | TreasuryIsParty => { ...ValidTerms, treasuryIsParty: true }
      | JobPriceCapZero => { ...ValidTerms, maxJobPrice: 0 }
      | ChallengeMarginZero => { ...ValidTerms, challengeMargin: 0 }
    }

  // The value the funding actually locks. Independent of what the
  // terms *claim* the stake is — that gap is the StakeMismatch case.
  pure val FundedValue = StakeValue

  // ---------------------------------------------------------------
  // Kernel open policy (check_stake_bond_open, in order)
  // ---------------------------------------------------------------

  pure def awardFloor(t: BondTerms): int =
    t.maxJobPrice + t.maxDisputeCost

  pure def openAdmissible(v: TermsVariant): bool =
    val t = termsFor(v)
    and {
      // stake must equal the value the open actually locks
      t.stake == FundedValue,
      // 0 < award <= stake
      t.award > 0,
      t.award <= t.stake,
      // a party-controlled treasury would collapse the penalty to A
      not(t.treasuryIsParty),
      // a zero price cap covers no job
      t.maxJobPrice > 0,
      // a zero challenge margin leaves no block to challenge in
      t.challengeMargin > 0,
      // the award must be able to make the client whole
      t.award >= awardFloor(t),
    }

  // ---------------------------------------------------------------
  // State
  // ---------------------------------------------------------------

  var coins: Coin -> int
  var liveCoins: Set[Coin]
  var bondLive: bool
  var bondValue: int
  var bondTerms: TermsVariant
  var height: int
  var closeOutcome: CloseOutcome
  var lastInput: Input
  var lastEvent: Event

  def liveTerms: BondTerms =
    termsFor(bondTerms)

  def coinTotal: int =
    liveCoins.fold(0, (sum, id) => sum + coins.get(id))

  // ---------------------------------------------------------------
  // Kernel close policy
  // ---------------------------------------------------------------

  // The committed remainder the kernel pins to the treasury output.
  def slashRemainder: int =
    liveTerms.stake - liveTerms.award

  // A `Violation` is admissible before the committed timeout, and only
  // with the pinned two-output shape: the treasury's value is checked
  // exactly, and conservation pins the client's side (award + surplus,
  // where the zero-fee surplus is zero). The kernel checks this shape
  // structurally, so no seal can redirect the award.
  def canCloseViolation(clientPay: int, treasuryPay: int): bool =
    and {
      bondLive,
      height < TimeoutHeight,
      treasuryPay == slashRemainder,
      clientPay + treasuryPay == bondValue,
    }

  // A `Timeout` returns the whole stake to the provider, at or after
  // the committed height. It carries no witness.
  def canCloseTimeout(providerPay: int): bool =
    and {
      bondLive,
      height >= TimeoutHeight,
      providerPay == bondValue,
    }

  // `Mutual` is absent from a stake bond's committed CloseKindSet, so
  // it is refused before any witness is examined — a provider can
  // never co-sign its way out from under a pending fraud proof. There
  // is deliberately no height or payout shape that makes this true.
  def canCloseMutual(first: int, second: int): bool = false

  def canOpen(v: TermsVariant): bool =
    not(bondLive)
      and closeOutcome == Unclosed
      and liveCoins.contains(ProviderCoin)
      and openAdmissible(v)

  // ---------------------------------------------------------------
  // Actions
  // ---------------------------------------------------------------

  action init = all {
    coins' = AllCoins.mapBy(id => if (id == ProviderCoin) FundedValue else 0),
    liveCoins' = Set(ProviderCoin),
    bondLive' = false,
    bondValue' = 0,
    bondTerms' = Valid,
    height' = 1,
    closeOutcome' = Unclosed,
    lastInput' = NoInput,
    lastEvent' = NoEvent,
  }

  // The provider funds the bond; the client co-signs but contributes
  // nothing. Only well-formed terms can land in live state.
  action openBond(v: TermsVariant): bool = all {
    canOpen(v),
    coins' = coins.set(ProviderCoin, 0),
    liveCoins' = liveCoins.exclude(Set(ProviderCoin)),
    bondLive' = true,
    bondValue' = coins.get(ProviderCoin),
    bondTerms' = v,
    height' = height,
    closeOutcome' = closeOutcome,
    lastInput' = OpenInput(v),
    lastEvent' = EdgeOpenedEvent,
  }

  // A refused open leaves every slot untouched. The Rust runner
  // replays these against the kernel and asserts the apply is rejected
  // and the store is unchanged.
  action rejectOpen(v: TermsVariant): bool = all {
    not(canOpen(v)),
    coins' = coins,
    liveCoins' = liveCoins,
    bondLive' = bondLive,
    bondValue' = bondValue,
    bondTerms' = bondTerms,
    height' = height,
    closeOutcome' = closeOutcome,
    lastInput' = RejectedOpenInput(v),
    lastEvent' = NoEvent,
  }

  action closeViolation(clientPay: int, treasuryPay: int): bool = all {
    canCloseViolation(clientPay, treasuryPay),
    coins' = coins
      .set(ClientAward, clientPay)
      .set(TreasuryRemainder, treasuryPay),
    liveCoins' = liveCoins.union(Set(ClientAward, TreasuryRemainder)),
    bondLive' = false,
    bondValue' = 0,
    bondTerms' = bondTerms,
    height' = height,
    closeOutcome' = ClosedViolation,
    lastInput' = CloseInput({ proof: Violation, first: clientPay, second: treasuryPay }),
    lastEvent' = EdgeClosedEvent,
  }

  action closeTimeout(providerPay: int): bool = all {
    canCloseTimeout(providerPay),
    coins' = coins.set(ProviderReturn, providerPay),
    liveCoins' = liveCoins.union(Set(ProviderReturn)),
    bondLive' = false,
    bondValue' = 0,
    bondTerms' = bondTerms,
    height' = height,
    closeOutcome' = ClosedTimeout,
    lastInput' = CloseInput({ proof: Timeout, first: providerPay, second: 0 }),
    lastEvent' = EdgeClosedEvent,
  }

  // Refused closes: a forbidden Mutual, a mis-routed slash, an
  // early timeout, or an expired violation. State is untouched.
  action rejectClose(p: Proof, first: int, second: int): bool = all {
    match p {
      | Mutual => not(canCloseMutual(first, second))
      | Violation => not(canCloseViolation(first, second))
      | Timeout => not(canCloseTimeout(first))
    },
    coins' = coins,
    liveCoins' = liveCoins,
    bondLive' = bondLive,
    bondValue' = bondValue,
    bondTerms' = bondTerms,
    height' = height,
    closeOutcome' = closeOutcome,
    lastInput' = RejectedCloseInput({ proof: p, first: first, second: second }),
    lastEvent' = NoEvent,
  }

  action tick = all {
    height < TimeoutHeight + 1,
    coins' = coins,
    liveCoins' = liveCoins,
    bondLive' = bondLive,
    bondValue' = bondValue,
    bondTerms' = bondTerms,
    height' = height + 1,
    closeOutcome' = closeOutcome,
    lastInput' = TickInput,
    lastEvent' = NoEvent,
  }

  action step = any {
    nondet v = AllVariants.oneOf()
    any {
      openBond(v),
      rejectOpen(v),
    },
    closeViolation(liveTerms.award, slashRemainder),
    closeTimeout(bondValue),
    nondet p = AllProofs.oneOf()
    rejectClose(p, liveTerms.award, slashRemainder),
    tick,
  }

  // ---------------------------------------------------------------
  // Invariants
  // ---------------------------------------------------------------

  // Nothing is minted or burned: the funded stake is either locked in
  // the bond or sitting in payout coins.
  val valueConserved =
    coinTotal + bondValue == FundedValue

  val noNegativeValue =
    AllCoins.forall(id => coins.get(id) >= 0) and bondValue >= 0

  val liveCoinsAreKnown =
    liveCoins.forall(id => AllCoins.contains(id))

  // Dead slots carry no value, so `coinTotal` cannot be gamed by
  // reading a stale payout.
  val deadSlotsAreZero =
    AllCoins.forall(id => liveCoins.contains(id) or coins.get(id) == 0)

  // A live bond always committed admissible terms. The malformed
  // variants can be *attempted* but never land.
  val liveBondIsWellFormed =
    not(bondLive) or openAdmissible(bondTerms)

  // A live bond holds exactly the stake its terms commit.
  val liveBondHoldsCommittedStake =
    not(bondLive) or bondValue == liveTerms.stake

  // The load-bearing one: whenever a slash has happened, the treasury
  // received exactly stake − award and the client exactly the award.
  // The award cannot be redirected to the provider, shorted, or
  // collapsed into a single payout.
  val slashRoutingPinned =
    closeOutcome != ClosedViolation
      or and {
        coins.get(TreasuryRemainder) == termsFor(bondTerms).stake - termsFor(bondTerms).award,
        coins.get(ClientAward) == termsFor(bondTerms).award,
        coins.get(ProviderReturn) == 0,
      }

  // A timeout returns the stake to the provider and awards nothing.
  val timeoutReturnsStakeOnly =
    closeOutcome != ClosedTimeout
      or and {
        coins.get(ProviderReturn) == termsFor(bondTerms).stake,
        coins.get(ClientAward) == 0,
        coins.get(TreasuryRemainder) == 0,
      }

  // A timeout close is only reachable at or after the committed
  // height. (The dual — a slash only *before* it — is a property of
  // the transition, not of the resulting state, since `tick` may
  // advance the height afterwards; it is pinned by
  // `closeTimingRejectedTest` instead.)
  val timeoutOnlyAfterCommittedHeight =
    closeOutcome != ClosedTimeout or height >= TimeoutHeight

  val heightAtLeastGenesis =
    height >= 1

  // ---------------------------------------------------------------
  // Named runs (each becomes an ITF trace replayed against the kernel)
  // ---------------------------------------------------------------

  run bondOpensAndSlashesTest =
    init
      .then(openBond(Valid))
      .then(closeViolation(AwardValue, StakeValue - AwardValue))
      .expect(valueConserved
        and slashRoutingPinned
        and closeOutcome == ClosedViolation
        and not(bondLive))

  run bondOpensAndTimesOutTest =
    init
      .then(openBond(Valid))
      .then(tick)
      .then(closeTimeout(StakeValue))
      .expect(valueConserved
        and timeoutReturnsStakeOnly
        and closeOutcome == ClosedTimeout)

  // Every malformed bond is refused, and none of them mutate state.
  run malformedOpensRejectedTest =
    init
      .then(rejectOpen(StakeMismatch))
      .then(rejectOpen(ZeroAward))
      .then(rejectOpen(AwardAboveStake))
      .then(rejectOpen(AwardBelowFloor))
      .then(rejectOpen(TreasuryIsParty))
      .then(rejectOpen(JobPriceCapZero))
      .then(rejectOpen(ChallengeMarginZero))
      .expect(not(bondLive)
        and valueConserved
        and coinTotal == FundedValue
        and not(canOpen(StakeMismatch))
        and not(canOpen(ZeroAward))
        and not(canOpen(AwardAboveStake))
        and not(canOpen(AwardBelowFloor))
        and not(canOpen(TreasuryIsParty))
        and not(canOpen(JobPriceCapZero))
        and not(canOpen(ChallengeMarginZero)))

  // A Mutual close of a bond is refused no matter the payout split —
  // the close-kind set rejects it before any witness is examined.
  run mutualCloseForbiddenTest =
    init
      .then(openBond(Valid))
      .then(rejectClose(Mutual, AwardValue, StakeValue - AwardValue))
      .then(rejectClose(Mutual, StakeValue, 0))
      .then(rejectClose(Mutual, 0, StakeValue))
      .expect(bondLive
        and closeOutcome == Unclosed
        and not(canCloseMutual(AwardValue, StakeValue - AwardValue))
        and not(canCloseMutual(StakeValue, 0)))

  // Re-routed slashes are refused: paying the provider, shorting the
  // treasury, or collapsing into one output.
  run reroutedSlashRejectedTest =
    init
      .then(openBond(Valid))
      .then(rejectClose(Violation, StakeValue, 0))
      .then(rejectClose(Violation, AwardValue + 1, StakeValue - AwardValue - 1))
      .then(rejectClose(Violation, AwardValue - 1, StakeValue - AwardValue))
      .expect(bondLive
        and closeOutcome == Unclosed
        and not(canCloseViolation(StakeValue, 0))
        and not(canCloseViolation(AwardValue + 1, StakeValue - AwardValue - 1)))

  // Timing: no timeout before the committed height, no slash at or
  // after it.
  run closeTimingRejectedTest =
    init
      .then(openBond(Valid))
      .then(rejectClose(Timeout, StakeValue, 0))
      .then(tick)
      .then(rejectClose(Violation, AwardValue, StakeValue - AwardValue))
      .expect(bondLive
        and height >= TimeoutHeight
        and not(canCloseViolation(AwardValue, StakeValue - AwardValue))
        and canCloseTimeout(StakeValue))
}
