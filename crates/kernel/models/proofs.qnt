module proofs {
  import accounting.* from "./accounting"

  // Shared proof vocabulary for economic models.
  //
  // `models/types.qnt::Proof` is tied to the trace-replay L1 object universe.
  // This module keeps the economic models independent while still naming the
  // same kernel close-proof boundary: mutual close, latest-proof close, timeout
  // close, violation close. Incentive penalties are only enforceable when their
  // proof kind maps to an admissible L1 close kind and can actually carry a
  // slash/penalty.

  type L1ProofKind =
    | NoL1Proof
    | MutualClose
    | LatestProofClose
    | TimeoutClose
    | ViolationClose

  type EvidenceKind =
    | NoEvidence
    | ExpiryEvidence
    | ProofObligationBreachEvidence
    | SignedStaleReceiptEvidence
    | BadComputeEvidence

  type ProofObligationKind =
    | NoProofObligation
    | SignedProofDeadlineObligation

  type RequiredProof =
    | NoRequiredProof
    | RequiredSelfContainedLatestProof

  type ProofSubmissionObligation = {
    kind: ProofObligationKind,
    obligor: Party,
    beneficiary: Party,
    requiredProof: RequiredProof,
    createdAt: int,
    proofDeadline: int,
    expiryHeight: int,
    inclusionMargin: int,
    penalty: int,
    penaltyBudget: int,
  }

  type ProofKind =
    | NoProof
    | FreshMutualLatestCloseProof
    | SelfContainedLatestStateProof
    | BareSignedReceiptProof
    | TimeoutFallbackProof
    | ProofObligationBreachSealProof
    | StaleReceiptSealProof
    | BadComputeSealProof

  pure def l1ProofKind(proof: ProofKind): L1ProofKind =
    match proof {
      | NoProof => NoL1Proof
      | FreshMutualLatestCloseProof => MutualClose
      | SelfContainedLatestStateProof => LatestProofClose
      | BareSignedReceiptProof => NoL1Proof
      | TimeoutFallbackProof => TimeoutClose
      | ProofObligationBreachSealProof => ViolationClose
      | StaleReceiptSealProof => ViolationClose
      | BadComputeSealProof => ViolationClose
    }

  pure def proofKindAdmissible(proof: ProofKind): bool =
    l1ProofKind(proof) != NoL1Proof

  pure def proofCanSlash(proof: ProofKind): bool =
    l1ProofKind(proof) == ViolationClose

  pure def proofObligationPublic(obligation: ProofObligationKind): bool =
    obligation == SignedProofDeadlineObligation

  pure def proofObligationPartiesValid(obligation: ProofSubmissionObligation): bool =
    (obligation.obligor == Maker or obligation.obligor == Taker)
      and (obligation.beneficiary == Maker or obligation.beneficiary == Taker)
      and obligation.obligor != obligation.beneficiary

  pure def proofObligationDeadlineHasMargin(obligation: ProofSubmissionObligation): bool =
    obligation.inclusionMargin >= 0
      and obligation.proofDeadline + obligation.inclusionMargin <= obligation.expiryHeight

  pure def proofObligationPenaltyBacked(
    obligation: ProofSubmissionObligation,
    postedStake: int,
  ): bool =
    obligation.penalty > 0
      and obligation.penaltyBudget >= obligation.penalty
      and obligation.penaltyBudget <= postedStake

  pure def proofSubmissionObligationWellFormed(
    obligation: ProofSubmissionObligation,
    postedStake: int,
  ): bool =
    proofObligationPublic(obligation.kind)
      and proofObligationPartiesValid(obligation)
      and obligation.requiredProof == RequiredSelfContainedLatestProof
      and obligation.createdAt < obligation.proofDeadline
      and proofObligationDeadlineHasMargin(obligation)
      and proofObligationPenaltyBacked(obligation, postedStake)

  pure def evidenceCanProveViolation(evidence: EvidenceKind): bool =
    match evidence {
      | NoEvidence => false
      | ExpiryEvidence => false
      | ProofObligationBreachEvidence => true
      | SignedStaleReceiptEvidence => true
      | BadComputeEvidence => true
    }
}
