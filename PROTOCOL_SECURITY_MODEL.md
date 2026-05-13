# Protocol Security Model

This document states the high-level problem Hellas is trying to solve and the
security properties the kernel and formal models must preserve.

`KERNEL.md` describes the implementation boundary. `FEES_SECURITY_MODEL.md`
tracks fee, reserve, and stake decisions. This document sits above both: it
defines what those mechanisms are for.

`FORMAL_MODELING_STRATEGY.md` defines how those properties should be modeled:
small composable models over shared vocabulary, with focused workbenches for
mechanism exploration and integrated models for committed obligations.

## Problem Statement

Hellas lets mutually distrustful parties run an economic interaction off-chain
while retaining an on-chain escape hatch.

The motivating shape is paid compute:

- a user escrows capital to buy compute;
- a provider escrows capital or reputation-bearing stake to make service
  guarantees credible;
- off-chain state updates move value between the parties as work is performed,
  disputed, or abandoned;
- either party can stop cooperating and submit an on-chain close;
- the protocol and chain must still be paid for persistent state and close
  execution.

The system should remain safe even if the counterparty is malicious. A party
should not need to trust that the other party will voluntarily settle fairly.
They should only need to trust the signed state, the validity rules, and the
on-chain close path.

The economic design goal is stronger than bare safety: set up the game so that
cooperating with the protocol is the rational strategy. Malicious or irrational
actors should still be bounded by kernel safety, but ordinary rational actors
should prefer to keep signing valid progress, produce final proofs when needed,
and close through the intended path because deviation has lower expected payoff.

## Arcade Analogy

The user-facing model is close to an arcade card:

- the user deposits money into a card;
- some value is spent playing games;
- some value may be won back;
- the user can cash out the remaining balance;
- there may be a deposit for a physical card or equipment;
- when the card/equipment is returned, any unused deposit comes back according
  to the rules.

The provider-side stake is less visible in the analogy, but it serves the same
trustless purpose: the provider has capital at risk so that cheating, breached
proof obligations, or invalid computation are economically bounded or
punishable.

The important point is not the analogy itself. The important point is that each
participant can reason locally about recoverable capital.

## Core Escape-Hatch Invariant

At every valid protocol state, each party must be able to compute:

- how much of their capital is liquid;
- how much is locked in live edges;
- how much is locked as fee reserve;
- how much is locked as state-slot budget or bond, if active channel lifetime
  is priced separately;
- how much is slashable stake;
- how much is already spent or paid;
- the minimum amount they can recover if they unilaterally use the on-chain
  close path;
- the maximum amount they can lose from the current state.

The escape-hatch lower bound must be derivable from public state, signed terms,
and the party's latest valid witness. It must not depend on counterparty
cooperation after the state is accepted.

Informally:

```text
party_capital =
  liquid
  + recoverable_from_escape_hatch
  + capital_still_at_risk
  + already_spent_or_slashed
```

The model should make the lower bound explicit. A transition is unsafe if it
lets one party reduce another party's escape-hatch recovery without the affected
party's authorization or a valid slashing condition.

The focused Quint models now use `models/bounds.qnt` for the current immediate
form of this function. It computes party recovery from party liquid value plus
the value domains assigned by terms: principal, reserve surplus, state-slot
refunds, and slash exposure. This is still a safety predicate, not a liveness
claim that the close transaction is eventually included.

`models/proof_lifetime.qnt` makes the Hellas L1 boundary explicit: there is no
iterative on-chain challenge game. If a dispute needs interaction, it happens
off-chain and the L1 sees only the resulting proof artifact. The model
therefore treats stale receipts and bare signed receipts as inadmissible L1
close proofs. Latest-state settlement is admissible only through a fresh mutual
close authorization, a self-contained latest-state proof artifact, or a
violation seal that resolves to the latest-state terms. Deterministic timeout
proofs are accepted only once paid lifetime has expired.

`models/settlement_witness.qnt` states the close-proof verifier contract
directly. A valid settlement witness binds the edge, terms identity, payout
shape, expiry height, proof kind, frontier commitment, and stake award. Bare
signed receipts and malformed witnesses are rejected before they can become L1
state transitions.

The remaining timing risk is not stale settlement through an on-chain
challenge window. It is expiry: the v1 channel tax prepays a finite active
lifetime. If the latest-state holder does not post a proof before the edge
runs out of paid lifetime, the L1 closes through the deterministic timeout
fallback. That fallback may be worse than the latest off-chain state, so the
timeout terms and paid lifetime are part of the economic contract. The close
reserve is separate: expiry does not drain close reserve as rent, and close has
no marginal fee beyond the open-time committed close fee.

`models/proofs.qnt` now defines the shared `ProofSubmissionObligation` shape.
`models/proof_obligations.qnt` isolates its lifecycle, and
`models/incentives.qnt` uses the same shape when deciding whether a
proof-obligation-breach penalty is enforceable. Any slashable proof obligation
must require a self-contained latest-state proof, be public, signed or
terms-committed, backed by penalty budget, and timed so the proof deadline is
strictly before channel expiry. If the deadline is missed, a violation seal is
available before expiry; if nobody posts that seal, ordinary timeout fallback
remains non-slashing.

The fraud-game boundary in `KERNEL.md` gives the right abstraction for stake:
interactive dispute work happens off-chain, and L1 receives only the final
proof or seal. If that terminal verdict is a violation, the configured stake
penalty is awarded to the violated party. The verifier proves the verdict is
valid under the protocol/job terms; the terms choose the economic knobs such as
job cost, stake exposure, violation beneficiary, and penalty amount.
`models/staked_obligations.qnt` checks the corresponding value movement:
principal, reserve, fees, posted stake, and stake awards are separate buckets,
and only a valid violation close transfers posted stake to the violated party.

Provider job stake uses a reusable pot with per-job logical locks. The pot is
posted once, then each accepted job reserves capacity from it until the job is
released or slashed. A successor signed frontier can release a job lock when it
explicitly marks the job accepted or removes the job id from active locks. If
that fast path does not happen, the lock releases at its job release deadline
unless a valid violation proof is posted first. `models/job_stake_locks.qnt`
checks the resulting capacity invariant: available provider stake plus active
job locks plus awarded stake always equals posted provider stake.

The signed frontier should commit to active job locks with an authenticated
root and aggregate locked total, preferably a Merkle-sum map. The L1 still does
not run a defense game. A close proof that references a job-lock root must
itself prove the final admissible close outcome under the terms and channel
protocol. Membership in an arbitrary historical root is not sufficient for a
slash. `models/frontier_progression.qnt` makes the freshness boundary explicit:
off-chain peers can reject stale or reintroduced frontiers, but a bare old
signed frontier remains a historical signature. A unilateral kernel close
therefore needs a verifier-visible freshness source such as an L1 anchor, fresh
mutual close authorization, or a self-contained proof/seal.

## Cryptoeconomic Incentive Target

Kernel safety and rational incentives are different claims.

Kernel safety is adversarial:

- invalid transitions do not mutate L1 state;
- stale receipts are not accepted as final proofs;
- accepted closes pay only terms-approved outputs;
- after paid lifetime expires, only the deterministic timeout close path is
  admissible;
- each party can compute its public escape-hatch lower bound.

Cryptoeconomic design is incentive-compatible:

- honest cooperation should have the highest expected payoff for rational
  parties;
- breaching signed proof-submission obligations, submitting stale receipts,
  forcing counterparty proof work, or invalid compute should be unprofitable
  once fees, prepaid lifetime, stake, slashing, and proof costs are included;
- an imbalanced channel should not create a profitable sabotage strategy for
  the party currently losing off-chain;
- if a party has a proof that improves on timeout, posting it before expiry
  should dominate letting the channel fall back to timeout.

The formal model should keep these separate. Safety models prove what the
kernel will or will not accept. Incentive models compare party payoffs across
available strategies under stated rationality assumptions.

The first payoff workbench is `models/incentives.qnt`. It intentionally starts
small: one imbalanced channel represented by `IncentiveTerms`, including
latest terms, timeout fallback terms, stale receipt terms, proof cost, stake,
and penalties. Its job is to expose concrete margins for cooperation versus
deviation, not to prove that every future market parameter is safe. It also
includes a trace showing that deterministic timeout fallback can favor one
party and is not slashable by itself. The punishable proof-related deviation is
breaching a signed proof-submission obligation when the terms provide matching
evidence, a violation proof, and backed stake. Private non-cooperation is not
evidence; a proof-obligation breach requires a public obligation artifact,
usable pre-expiry deadline margin, matching penalty budget, and a missed
deadline. The shared terms vocabulary derives minimum penalty and stake
requirements from the payoff terms, then checks the configured values against
those requirements. Penalties count only when the terms provide a matching
evidence kind, any required public obligation, proof kind that maps to an L1
violation close proof, slash-capable proof obligation, and backed penalty
source; otherwise the model treats the enforceable penalty as zero.

## Accounting Domains

The protocol has multiple value domains. They must not be collapsed into one
integer just because total value is conserved.

- **Principal**: user/provider capital governed by the channel outcome.
- **Open fees**: ordinary resource fees charged to create persistent state.
- **Close reserve**: resource-only capital locked at open to guarantee the
  protocol can be paid for future close execution without a marginal close fee.
  It is not slashable stake.
- **State-slot budget, bond, or prepaid lifetime fee**: capital paid, locked,
  or at risk because an edge occupies persistent live state over time. The v1
  choice is a prepaid finite lifetime fee.
- **Reserve surplus**: close reserve remaining after the open-time committed
  close fee is paid.
- **Stake**: explicit collateral at risk under protocol-specific misbehavior
  rules. It is separate from edge principal and close reserve.
- **Job stake lock**: a logical reservation against posted provider stake for
  one unresolved job. It caps concurrent unresolved work and is released by a
  signed frontier, a release deadline, or a valid violation proof.
- **Slashed value**: stake removed by a valid violation proof and awarded to
  the violated party, unless a future protocol deliberately chooses another
  destination.
- **Rewards**: value paid to a closer, collector, challenger, watcher, or other
  actor if the protocol explicitly creates such an incentive.

The core conservation invariant is:

```text
live coin principal
+ live edge principal
+ locked close reserves
+ state-slot budgets or bonds
+ feesPaid
+ burned
+ available posted stake
+ active job stake locks
+ slashed
+ rewards
= genesis total + explicitly posted stake
```

The exact right-hand side depends on whether stake is seeded as initial capital
or posted later from existing coins. The model must make that choice explicit.

## Terms As The Economic Contract

Terms are the economic contract for an edge. They must specify enough structure
for each party to compute their escape-hatch lower bound.

At minimum, terms need to describe:

- parties;
- timeout or escape-hatch conditions;
- principal payout rules;
- reserve-surplus payout rules;
- state-slot budget, rent, bond, expiry, or collection rules if active channel
  lifetime has a cost;
- stake ownership and slash conditions, if stake exists;
- job stake lock amount, release condition, release deadline, and violation
  proof condition, if the state contains unresolved jobs;
- active job-lock root and aggregate locked-stake total, if unresolved jobs are
  represented by a compact authenticated commitment;
- any reward rules for closers, collectors, challengers, or watchers.

Terms cannot spend the open fee. Terms cannot spend the portion of reserve
needed to pay the close fee committed at open. Terms can, and should, describe
where reserve surplus goes.

Close reserve is not a penalty source. If terms want protocol/job violations to
be punishable, they must bind explicit posted stake and the violation proof must
debit that stake domain.

This implies a separation:

```text
	gross funding
	- open fee
	- prepaid finite lifetime fee
	- locked close reserve
	= edge principal

	locked close reserve
	- open-time committed close fee
	= reserve surplus

	close outputs are governed by terms over edge principal + reserve surplus
```

Funding shape is not part of the safety boundary. The same equation applies
when funding is two-sided, maker-only, taker-only, empty under zero effective
debit, or a self-edge where `maker == taker`. Those are protocol-valid shapes
because both party positions authorize the exact terms and the terms define the
resulting economics. A future sponsored-key fee policy must still name who or
what pays the resource cost; it cannot silently create unpaid persistent state.

## Required Assumptions

The L1 kernel cannot prove every property alone. The model should name which
properties are assumed from adjacent layers.

Consensus must provide:

- deterministic transaction order;
- finalized block height and fee schedule;
- no rollback of finalized state.

Verifiers must provide:

- sound signature verification;
- sound dispute/seal verification;
- deterministic answers for the same witness and public inputs.

State-channel protocol must provide:

- parties only sign states whose escape-hatch lower bounds they accept;
- each signed state binds the relevant terms, balances, stake, and dispute
  commitments;
- off-chain dispute cycles, if any, produce a compact L1-verifiable proof or
  seal rather than an on-chain challenge transcript;
- stale receipts are not admissible L1 close proofs unless the verifier reduces
  them to a valid final proof under the terms;
- each party can construct and submit the close witness required for its escape
  hatch before the prepaid lifetime reaches the deterministic timeout fallback.
- any slashable proof-submission obligation is signed or otherwise committed in
  public terms, names an obligor and deadline, and can be reduced to a final
  L1-verifiable violation seal if breached.

Store/batch layer must provide:

- atomic commits;
- validation and fold observe the same working state;
- typed coin/edge access does not alias.

## Preserved By The L1 Kernel

Given the assumptions above, the L1 kernel should preserve:

- no live coin can be spent twice;
- only authorized funding coins can be locked into an edge;
- accepted opens pay open fee, pay prepaid lifetime fee, lock close reserve,
  and commit a future expiry height;
- edge principal equals gross funding minus open fee, lifetime fee, and
  reserve;
- deterministic close terms match edge principal plus reserve surplus for the
  selected close path;
- a close cannot mint principal;
- a close cannot avoid the open-time committed close fee;
- a close cannot require fresh fee value from the closer;
- a valid violation cannot pay a stake award from close reserve;
- reserve surplus moves according to terms;
- close output ids are canonical and cannot be chosen by the caller;
- invalid transitions do not mutate state.

## Preserved By The Unified Formal Model

The unified Quint model should preserve stronger economic statements than the
current L1-only model:

- global accounting across principal, reserve, fees, stake, slashes, and
  rewards;
- per-party lower-bound accounting for the escape hatch;
- no transition reduces a party's lower-bound recovery except by that party's
  authorization or a valid slash;
- no transition increases persistent state without paying or locking the
  required resource value;
- no live edge can remain forever as unpaid persistent state;
- expired live edges have a deterministic timeout close path, and non-timeout
  proofs cannot settle them;
- fee schedule changes cannot reduce close liveness for existing edges;
- active-state pricing changes have explicit consequences for recovery;
- stale/collector paths move value through named buckets.

The focused `models/lifetime.qnt` model currently exercises the active-state
pricing subset: permanent up-front lifetime, deterministic rent budget, and
state-slot bond/expiry. It proves the close reserve stays separate from
active-state pricing and that fee raises cannot strand an already-open close
path under the target semantics. It also uses party-indexed buckets so a
collector reward can be checked separately from maker/taker principal recovery.

## Consumer Interface

A consumer of the protocol should be able to ask, for any proposed or current
state:

- What must I sign?
- What exact funding and terms are bound by my signature?
- What is my current liquid balance?
- What is my current locked principal?
- What stake do I have at risk?
- What reserve did I contribute or agree to lock?
- What close execution cost was committed up front?
- What state-slot budget, rent, bond, or expiry rule did I accept?
- What is my minimum on-chain recovery if I close now?
- What is my minimum on-chain recovery at future heights if rent or expiry can
  change it?
- What close witness do I need to realize that recovery?
- What can the counterparty do without my cooperation?
- What can the protocol collect in fees or slashes?

If the protocol cannot answer these questions from the current state and terms,
the state is not sufficiently specified for a trustless economic channel.

## Documentation Consequence

The formal model should no longer be described only as "value conservation" or
"open/close shape." The target property is stronger:

> Every reachable accepted state has explicit accounting and an enforceable
> escape-hatch lower bound for each party.

This property is the reason fee reserves, stake, and terms-level surplus
handling must be first-class in the model.
