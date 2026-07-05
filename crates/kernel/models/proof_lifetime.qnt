module proof_lifetime {
  import accounting.* from "./accounting"
  import terms.* from "./terms"
  import bounds.* from "./bounds"

  // Focused model for proof-only L1 settlement with prepaid channel lifetime.
  //
  // Hellas L1 does not run an iterative on-chain challenge game. If parties
  // need challenge/proof cycles, they happen off-chain and the L1 sees only
  // the resulting proof artifact. In this model stale receipts and bare signed
  // receipts are therefore not admissible L1 close proofs. The accepted L1
  // paths are:
  //
  // - a fresh mutual close authorization over the exact close payload;
  // - a self-contained latest-state proof artifact;
  // - a violation seal/proof that resolves to the latest-state terms;
  // - a deterministic timeout close once the prepaid lifetime is exhausted.
  //
  // The channel tax is represented as an up-front lifetime fee. It fixes a
  // public expiry height, so live state cannot grow without bound. If the
  // latest-state holder wants an outcome better than the timeout fallback, it
  // must post a valid proof before the channel reaches that expiry.

  type Phase =
    | Live
    | Closed

  type L1Proof =
    | FreshMutualLatestProof
    | SelfContainedLatestProof
    | ViolationProof
    | TimeoutProof
    | BareSignedReceipt
    | StaleReceipt

  var phase: Phase
  var liquid: Party -> int
  var edgePrincipal: int
  var closeReserve: int
  var feesPaid: int
  var rewards: Party -> int
  var height: int
  var currentCloseFee: int
  var finalProof: L1Proof
  var closedAt: int

  pure val MakerFunding = 36
  pure val TakerFunding = 24
  pure val Funding = MakerFunding + TakerFunding
  pure val OpenFee = 5
  pure val CloseReserve = 12
  pure val PrepaidCloseFee = 8
  pure val ReserveSurplus = CloseReserve - PrepaidCloseFee
  pure val MakerReserveSurplus = 2
  pure val TakerReserveSurplus = 2
  pure val RentPerBlock = 2
  pure val PaidLifetimeBlocks = 3
  pure val LifetimeFee = RentPerBlock * PaidLifetimeBlocks
  pure val EdgePrincipal = Funding - OpenFee - CloseReserve - LifetimeFee
  pure val GenesisHeight = 1
  pure val ExpiryHeight = GenesisHeight + PaidLifetimeBlocks
  pure val BaseCloseFee = 8
  pure val RaisedCloseFee = 20

  pure val LatestTerms = basicTerms(
    25,
    12,
    MakerReserveSurplus,
    TakerReserveSurplus,
    0,
    0,
    0,
    0,
  )

  pure val TimeoutTerms = basicTerms(
    18,
    19,
    MakerReserveSurplus,
    TakerReserveSurplus,
    0,
    0,
    0,
    0,
  )

  pure val StaleTerms = basicTerms(
    14,
    23,
    MakerReserveSurplus,
    TakerReserveSurplus,
    0,
    0,
    0,
    0,
  )

  pure def termsOf(p: L1Proof): EconomicTerms =
    match p {
      | FreshMutualLatestProof => LatestTerms
      | SelfContainedLatestProof => LatestTerms
      | ViolationProof => LatestTerms
      | TimeoutProof => TimeoutTerms
      | BareSignedReceipt => StaleTerms
      | StaleReceipt => StaleTerms
    }

  pure def proofOk(p: L1Proof, h: int): bool =
    match p {
      | FreshMutualLatestProof => h < ExpiryHeight
      | SelfContainedLatestProof => h < ExpiryHeight
      | ViolationProof => h < ExpiryHeight
      | TimeoutProof => h >= ExpiryHeight
      | BareSignedReceipt => false
      | StaleReceipt => false
    }

  def recoverWith(t: EconomicTerms): Party -> int =
    AllParties.mapBy(party =>
      liquid.get(party)
        + t.principal.get(party)
        + t.reserveSurplus.get(party)
    )

  def canCloseWithProof(p: L1Proof): bool =
    phase == Live
      and proofOk(p, height)
      and closeReserve >= PrepaidCloseFee
      and termsCoherent(termsOf(p), edgePrincipal, ReserveSurplus, 0, 0)

  def liveHasLatestProofPath: bool =
    phase != Live or canCloseWithProof(SelfContainedLatestProof)

  def latestLowerBound(party: Party): int =
    escapeHatchLowerBound(party, zeroPartyValues, LatestTerms)

  def timeoutLowerBound(party: Party): int =
    escapeHatchLowerBound(party, zeroPartyValues, TimeoutTerms)

  action init = all {
    phase' = Live,
    liquid' = zeroPartyValues,
    edgePrincipal' = EdgePrincipal,
    closeReserve' = CloseReserve,
    feesPaid' = OpenFee + LifetimeFee,
    rewards' = zeroPartyValues,
    height' = GenesisHeight,
    currentCloseFee' = BaseCloseFee,
    finalProof' = StaleReceipt,
    closedAt' = 0,
  }

  action closeWithProof(p) = all {
    canCloseWithProof(p),
    phase' = Closed,
    liquid' = recoverWith(termsOf(p)),
    edgePrincipal' = 0,
    closeReserve' = 0,
    feesPaid' = feesPaid + PrepaidCloseFee,
    rewards' = rewards,
    height' = height,
    currentCloseFee' = currentCloseFee,
    finalProof' = p,
    closedAt' = height,
  }

  action expireByTimeout = all {
    phase == Live,
    height + 1 >= ExpiryHeight,
    closeReserve >= PrepaidCloseFee,
    phase' = Closed,
    liquid' = recoverWith(TimeoutTerms),
    edgePrincipal' = 0,
    closeReserve' = 0,
    feesPaid' = feesPaid + PrepaidCloseFee,
    rewards' = rewards,
    height' = ExpiryHeight,
    currentCloseFee' = currentCloseFee,
    finalProof' = TimeoutProof,
    closedAt' = ExpiryHeight,
  }

  action tickFundedLive = all {
    phase == Live,
    height + 1 < ExpiryHeight,
    phase' = phase,
    liquid' = liquid,
    edgePrincipal' = edgePrincipal,
    closeReserve' = closeReserve,
    feesPaid' = feesPaid,
    rewards' = rewards,
    height' = height + 1,
    currentCloseFee' = currentCloseFee,
    finalProof' = finalProof,
    closedAt' = closedAt,
  }

  action tickClosed = all {
    phase == Closed,
    phase' = phase,
    liquid' = liquid,
    edgePrincipal' = edgePrincipal,
    closeReserve' = closeReserve,
    feesPaid' = feesPaid,
    rewards' = rewards,
    height' = height + 1,
    currentCloseFee' = currentCloseFee,
    finalProof' = finalProof,
    closedAt' = closedAt,
  }

  action raiseFee = all {
    currentCloseFee == BaseCloseFee,
    phase' = phase,
    liquid' = liquid,
    edgePrincipal' = edgePrincipal,
    closeReserve' = closeReserve,
    feesPaid' = feesPaid,
    rewards' = rewards,
    height' = height,
    currentCloseFee' = RaisedCloseFee,
    finalProof' = finalProof,
    closedAt' = closedAt,
  }

  action step = any {
    closeWithProof(FreshMutualLatestProof),
    closeWithProof(SelfContainedLatestProof),
    closeWithProof(ViolationProof),
    closeWithProof(TimeoutProof),
    closeWithProof(BareSignedReceipt),
    closeWithProof(StaleReceipt),
    expireByTimeout,
    tickFundedLive,
    tickClosed,
    raiseFee,
  }

  val valueAccounted =
    partyTotal(liquid)
      + edgePrincipal
      + closeReserve
      + feesPaid
      + partyTotal(rewards) == Funding

  val noNegativeBucket =
    partyNonNegative(liquid)
      and edgePrincipal >= 0
      and closeReserve >= 0
      and feesPaid >= 0
      and partyNonNegative(rewards)

  val lifetimeFeePrepaid =
    LifetimeFee == RentPerBlock * PaidLifetimeBlocks
      and ExpiryHeight == GenesisHeight + PaidLifetimeBlocks

  val noMarginalCloseFee =
    feesPaid
      == OpenFee
        + LifetimeFee
        + if (phase == Closed) {
          PrepaidCloseFee
        } else {
          0
        }

  val liveWithinPaidLifetime =
    phase != Live or height < ExpiryHeight

  val closeReserveCoversCommittedFee =
    phase == Closed or closeReserve >= PrepaidCloseFee

  val feeRaiseCannotStrandProofClose =
    phase == Closed
      or currentCloseFee <= closeReserve
      or closeReserve >= PrepaidCloseFee

  val latestTermsCoherent =
    termsCoherent(LatestTerms, EdgePrincipal, ReserveSurplus, 0, 0)

  val timeoutTermsCoherent =
    termsCoherent(TimeoutTerms, EdgePrincipal, ReserveSurplus, 0, 0)

  val staleTermsCoherent =
    termsCoherent(StaleTerms, EdgePrincipal, ReserveSurplus, 0, 0)

  val staleReceiptNotAdmissible =
    not(canCloseWithProof(StaleReceipt))

  val bareSignedReceiptNotAdmissible =
    not(canCloseWithProof(BareSignedReceipt))

  val closedByAdmissibleProofOnly =
    phase != Closed
      or finalProof == FreshMutualLatestProof
      or finalProof == SelfContainedLatestProof
      or finalProof == ViolationProof
      or finalProof == TimeoutProof

  val latestProofPreservesLatestBound =
    phase != Closed
      or not(
        finalProof == FreshMutualLatestProof
          or finalProof == SelfContainedLatestProof
          or finalProof == ViolationProof
      )
      or AllParties.forall(party => liquid.get(party) == latestLowerBound(party))

  val timeoutCloseUsesTimeoutTerms =
    phase != Closed
      or finalProof != TimeoutProof
      or AllParties.forall(party => liquid.get(party) == timeoutLowerBound(party))

  val closeProofTimingValid =
    phase != Closed
      or any {
        (finalProof == FreshMutualLatestProof
          or finalProof == SelfContainedLatestProof
          or finalProof == ViolationProof)
          and closedAt < ExpiryHeight,
        finalProof == TimeoutProof and closedAt >= ExpiryHeight,
      }

  val closedAtConsistent =
    if (phase == Live) {
      closedAt == 0
    } else {
      GenesisHeight <= closedAt and closedAt <= height
    }

  val expiryClosesByTimeout =
    phase != Closed
      or closedAt < ExpiryHeight
      or finalProof == TimeoutProof

  val timeoutCanReduceLatestBound =
    phase == Closed
      and finalProof == TimeoutProof
      and liquid.get(Maker) < latestLowerBound(Maker)

  val currentCloseFeeKnown =
    currentCloseFee == BaseCloseFee or currentCloseFee == RaisedCloseFee

  val heightAtLeastGenesis =
    height >= GenesisHeight

  run selfContainedLatestProofBeforeExpiryTest =
    init
      .then(tickFundedLive)
      .then(raiseFee)
      .then(closeWithProof(SelfContainedLatestProof))
      .expect(phase == Closed
        and finalProof == SelfContainedLatestProof
        and valueAccounted
        and latestProofPreservesLatestBound
        and feeRaiseCannotStrandProofClose)

  run freshMutualLatestProofBeforeExpiryTest =
    init
      .then(closeWithProof(FreshMutualLatestProof))
      .expect(phase == Closed
        and finalProof == FreshMutualLatestProof
        and valueAccounted
        and latestProofPreservesLatestBound)

  run violationProofResolvesLatestTest =
    init
      .then(raiseFee)
      .then(closeWithProof(ViolationProof))
      .expect(phase == Closed
        and finalProof == ViolationProof
        and valueAccounted
        and latestProofPreservesLatestBound)

  run staleReceiptRejectedTest =
    init
      .expect(staleReceiptNotAdmissible
        and not(canCloseWithProof(StaleReceipt)))

  run bareSignedReceiptRejectedTest =
    init
      .expect(bareSignedReceiptNotAdmissible
        and not(canCloseWithProof(BareSignedReceipt)))

  run timeoutProofBeforeExpiryRejectedTest =
    init
      .then(tickFundedLive)
      .then(tickFundedLive)
      .expect(height == ExpiryHeight - 1
        and not(canCloseWithProof(TimeoutProof))
        and canCloseWithProof(SelfContainedLatestProof)
        and canCloseWithProof(ViolationProof))

  run l1ClosesOutOfFundsAtExpiryTest =
    init
      .then(tickFundedLive)
      .then(tickFundedLive)
      .then(expireByTimeout)
      .expect(phase == Closed
        and height == ExpiryHeight
        and closedAt == ExpiryHeight
        and finalProof == TimeoutProof
        and valueAccounted
        and noMarginalCloseFee
        and closeProofTimingValid
        and timeoutCloseUsesTimeoutTerms)

  run missedLatestProofFallsBackToTimeoutTest =
    init
      .then(tickFundedLive)
      .then(tickFundedLive)
      .then(expireByTimeout)
      .expect(timeoutCanReduceLatestBound
        and liquid.get(Maker) == timeoutLowerBound(Maker)
        and liquid.get(Taker) == timeoutLowerBound(Taker))
}
