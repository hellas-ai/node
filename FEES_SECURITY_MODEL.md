# Fee and Staked Security Model

Working document for making fees, reserves, spam prevention, funding, and
staked security first-class in the formal model.

The goal is to make fees and stake a security-critical part of the L1 model.
Every accepted transition should preserve explicit accounting and security
invariants, not just principal conservation.

The high-level economic security target is documented in
`PROTOCOL_SECURITY_MODEL.md`: every accepted state should have explicit
accounting and an enforceable escape-hatch lower bound for each party.

The modeling discipline for keeping fee, reserve, lifetime, stake, and
slashing work composable is documented in `FORMAL_MODELING_STRATEGY.md`.

## Current Kernel Semantics

These are the semantics currently implemented by the Rust kernel and described
in `KERNEL.md`.

- Open consumes funding coins.
- Open pays `context.fee(open.cost())` immediately from funding.
- Open pays `context.fees().lifetime() * paid_lifetime_blocks` immediately from
  funding, where `paid_lifetime_blocks = terms.timeout() -
  context.block_height()`.
- Open locks a close reserve priced as the worst-case bounded close.
- Edge principal is `funding_total - open_fee - lifetime_fee - close_reserve`.
- Close has no marginal/current fee; close execution is funded by the
  open-time committed reserve.
- Current Rust stores the open-time fee schedule on the edge and distributes
  reserve surplus through the close outputs.
- Close materializes payout coins from edge principal plus reserve surplus for
  the selected close path.
- If the current close fee rises above the locked reserve, the edge remains
  closable by the normal close path.
- One-sided funding, empty funding, and same-party edges are protocol-valid
  shapes. Empty funding is accepted only when the effective open debit is zero;
  sponsored zero-fee keys are a future extension that must make the sponsor or
  subsidy bucket explicit.
- Both parties must still authorize the open, even if one side contributes no
  funding.
- Open commits a future timeout height. `Mutual` and `Violation` closes are
  pre-timeout paths; `Timeout` is admissible at or after that height.

These are implementation facts, not necessarily final protocol decisions.

## Target Accounting Invariant

The unified model should track every value bucket explicitly:

```text
live coin principal
+ live edge principal
+ locked close reserves
+ state-slot budgets or bonds
+ feesPaid: ordinary resource fees no longer controlled by channel parties
+ burned value
+ live stake
+ slashed stake
+ claimable rewards
= genesis total
```

If some buckets are intentionally unused in v1, they should still be named and
fixed to zero. That keeps future stake/slashing changes from being bolted on
outside the invariant.

## Cryptoeconomic Objective

Fees, prepaid lifetime, stake, slashing, proof costs, and timeout fallback are
not just accounting details. They are the mechanism that should make protocol
cooperation the rational strategy.

The target is not "everyone behaves honestly." The target is:

```text
expected payoff(cooperate)
  >= expected payoff(deviate)
```

for the relevant rational deviations:

- refuse to sign the next valid state;
- breach a signed proof-submission obligation;
- submit stale receipts to peers or downstream automation;
- wait for deterministic timeout because the timeout fallback is more
  favorable than the latest state;
- force the counterparty to spend proof or close effort;
- leave live state open until prepaid lifetime expires.

The model should treat this as a payoff comparison, not as a kernel safety
invariant. Kernel safety says invalid L1 transitions fail. Incentive
compatibility says valid-but-hostile strategies are made unattractive by the
terms, fees, stake, and timeout rules.

## Decision Log

| Area | Current default | Status |
| --- | --- | --- |
| Ordinary fee destination | `feesPaid` abstract protocol fee sink | Decided |
| Open fee source | Paid from aggregate funding | Decided |
| Close reserve source | Paid from aggregate funding at open | Decided |
| Close reserve slashability | Resource-only; never slashable stake | Decided |
| Terms value domain | Terms govern net edge principal and reserve surplus policy | Decided |
| Reserve refund | Reserve surplus distributed according to terms | Decided |
| Close fee schedule | Open-time committed close budget; no marginal close fee | Decided |
| Fee raise effect | Existing close liveness is unaffected by fee raises | Decided |
| Active channel resource cost | Prepaid finite lifetime fee; close reserve stays separate | Decided |
| One-sided funding | Protocol-valid; terms decide economics | Decided |
| Empty funding | Protocol-valid only when effective open debit is zero | Decided; sponsored keys are future extension |
| Same-party channel | Protocol-valid self-edge | Decided |
| Stake | Reusable provider stake pot with per-job logical locks | Decided for job stake |
| Slashing | Valid job violation proof awards locked job penalty to violated party | Decided for job stake |
| Collector path | No v1 collector reward; expiry uses deterministic timeout close | Decided for v1 |
| Channel tax expiry | Prepaid lifetime fixes deterministic expiry height | Decided |
| Stale receipts on L1 | Rejected unless reduced to valid proof/seal | Needs verifier-visible freshness source |
| Signed frontier freshness | Bare historical signatures are not enough for unilateral close | Mechanism open |
| Incentive compatibility | Cooperation should dominate deviation for rational actors | Open |

## Resolved Decisions

### D1. Ordinary Resource Fees Go To `feesPaid`

Ordinary resource fees charged by accepted L1 transitions move into
`feesPaid`.

`feesPaid` is an abstract protocol fee sink: value in this bucket is no longer
controlled by channel parties as liquid coin principal, edge principal, or
locked close reserve. The unified model does not yet distinguish whether this
value is burned, paid to a sequencer, or routed to a protocol treasury.

This bucket is intentionally narrow:

- `feesPaid` is for ordinary resource fees.
- `feesPaid` is not slashable stake.
- `feesPaid` is not a collector reward.
- `feesPaid` is not challenger or watcher compensation.

If slashing, collector rewards, treasury ownership, or sequencer revenue become
load-bearing protocol concepts, they must use explicit separate buckets or a
refinement of `feesPaid`. They should not be hidden inside the ordinary fee
sink.

Model consequence:

```text
live coin principal
+ live edge principal
+ locked close reserves
+ feesPaid
+ burned
+ slashed
+ rewards
= genesis total
```

### D2. Aggregate Funding Pays Fees And Terms Govern Net Principal

The protocol does not track which party economically paid ordinary open fees or
the close reserve. Open consumes the aggregate funding authorized by the
parties, then debits fees and reserve from that aggregate:

```text
gross_funding
- open_fee
- lifetime_fee
- locked_close_reserve
= edge_principal
```

The edge terms govern `edge_principal` and reserve surplus. They cannot spend
the open fee, lifetime fee, or the portion of reserve needed to pay close fees.
Current `Terms::Basic` represents timeout principal plus timeout reserve
surplus as one flat payout list; richer terms may split the two value domains
explicitly.

This preserves flexibility:

- parties can negotiate fee burden off-chain,
- sponsored or one-sided funding remains possible if otherwise valid,
- the kernel does not need a fee-payer identity,
- fairness comes from both parties authorizing the exact `(funding, terms)`.

Kernel consequence:

- open rejects if `gross_funding < open_fee + lifetime_fee +
  locked_close_reserve`,
- open rejects deterministic timeout terms whose committed payout path does not
  sum to the resulting `edge_principal + timeout_reserve_surplus`,
- close never charges fresh value to the closer and never reprices itself under
  the current block fee schedule.

For current `Terms::Basic`, the deterministic payout path is
`timeout_outputs`, so
`sum(timeout_outputs) == edge_principal + timeout_reserve_surplus` is checked at
open. More expressive future terms must expose equivalent deterministic value
requirements or make their value domain explicit.

### D3. Reserve Surplus Is Distributed According To Terms

The close reserve is not simply consumed as an ordinary protocol fee. It is
capital locked to guarantee that the protocol can be paid for the eventual
close. The close execution price is committed at open. On successful close:

```text
prepaid_close_fee = open_fee_schedule.fee(close_path_cost)
reserve_surplus = locked_close_reserve - prepaid_close_fee
feesPaid += prepaid_close_fee
terms distribute reserve_surplus
```

The close transaction must not consult the current fee schedule to decide
whether it is affordable. The close budget was committed when the edge opened.
If the committed budget cannot cover every valid close path, the open is
invalid.

This decision is required for the trustless economic channel model. Parties are
not only paying for resource usage; they are escrowing capital into a game where
each party needs to know the minimum amount recoverable through the on-chain
escape hatch. If unused reserve disappears into the fee sink, the reserve is an
unbounded economic loss relative to the selected close path rather than a
bounded deposit.

Terms must therefore describe two value domains:

- principal payouts: distribution of `edge_principal`;
- reserve-surplus payouts: distribution of `locked_close_reserve -
  prepaid_close_fee`.

These domains must be explicit and separately checked. Principal terms cannot
spend reserve, and reserve-surplus terms cannot spend the fee required by the
protocol.

Model consequence:

```text
close:
  use the close fee committed at open
  require locked_close_reserve >= prepaid_close_fee
  feesPaid' = feesPaid + prepaid_close_fee
  edge_principal is paid according to close proof / terms
  reserve_surplus is paid according to terms
  locked_close_reserve' = 0
```

Implementation consequence:

Current `Terms::Basic` implements this as a flat close payout list: timeout
outputs include both timeout principal and timeout reserve surplus. Future terms
can make principal and reserve-surplus policies separate fields if that improves
readability or verifier public inputs.

### D4. Close Has No Marginal Fee

Closing a channel should not require fresh capital from the party submitting
the close. All open and close execution cost is paid or locked up front by the
open transaction.

Here, "up front" means the value is removed from spendable channel principal at
open. The model may keep that value in `locked_close_reserve` until close so it
can account for the selected close path and reserve surplus, but no party pays
a new fee at close time.

This has two important consequences:

- close execution is priced by the fee schedule committed at open time;
- later fee raises do not make an already-open edge unclosable through the
  normal close path.

The open-time debit is:

```text
gross_funding
- open_write_fee
- locked_close_reserve
- prepaid_lifetime_fee
= edge_principal
```

`locked_close_reserve` must cover every valid bounded close path for the edge
under the open-time schedule. Close can then be submitted by either party, or
by an allowed helper if terms add one, without that actor posting additional
fee value.

This does not solve active-state growth by itself. A channel can still occupy a
live slot forever unless the open also pays for a permanent lifetime, posts a
state-slot bond, buys a bounded lifetime, or accepts an explicit expiry or
collection path. Close execution reserve and active-state pricing therefore
remain separate concepts.

Model consequence:

```text
open:
  close_fee_schedule[edge] = current_fee_schedule
  locked_close_reserve[edge] >= maxCloseCost(terms, close_fee_schedule[edge])

close:
  fee schedule used for close is close_fee_schedule[edge]
  no debit from live coins
  no dependency on current_fee_schedule for close execution
```

The unified L1 fee model uses this target semantics: a fee raise after open
does not strand an existing edge, close pays only the committed close fee, and
reserve surplus is returned through the modeled payout path.

The model also imports the shared `accounting`, `terms`, and `bounds` modules
so fee accounting is checked per party, not only in aggregate. The modeled
escape-hatch lower bound is liquid value plus terms-assigned principal and
reserve surplus.

Implementation consequence:

Current Rust no longer prices close against the current block fee schedule. The
remaining implementation gap is explicit reserve-surplus distribution in terms.

### D5. Violation Stake Is Awarded To The Violated Party

Fraud-game analysis already treats optimistic and optimistic-ZK disputes as
off-chain games that produce a final L1-verifiable verdict. The L1 does not run
the game. It sees only a bounded proof/seal whose terminal outcome is accept,
reject, slash, or continue-dispute at the protocol layer.

For channel/job violations, the economic rule is:

```text
valid violation close proof
=> transfer configured penalty from violator stake to violated party
```

This transfer is not protocol fee revenue, not burned value, and not close
reserve consumption. It is a separate stake bucket moving from the party that
violated the agreed rule to the party protected by that rule.

The protocol or validity gadget may hardcode the meaning of each violation:
bad compute, invalid claim, missed proof-submission obligation, or another
domain-specific fault. Terms or job configuration supply the economic knobs:

- who posted stake;
- maximum stake exposure;
- violation beneficiary;
- violation penalty;
- principal payout under the violation outcome;
- required proof/deadline conditions.

The important configurable ratio is:

```text
violation_penalty / job_cost
```

or, for concurrent work:

```text
posted_stake >= max_concurrent_exposure * agreed_safety_ratio
```

Model consequence:

```text
violation close:
  principal is paid according to violation terms
  reserve surplus is paid according to reserve-surplus terms
  violator stake decreases by violation_penalty
  violated party recovery increases by violation_penalty
  ordinary fees are unaffected except for committed close execution cost
```

This preserves the domain split: edge principal remains governed by terms,
stake remains a security bucket, and violation proof validity determines when
the stake transfer is enabled.

`models/staked_obligations.qnt` now checks this accounting shape directly. It
keeps edge principal, close reserve, fees, posted stake, and stake awards in
separate buckets. A self-contained latest proof close does not move stake.
Timeout fallback does not move stake. A valid violation close transfers the
configured penalty from the violator's posted stake to the violated party's
award bucket.
The stake award is backed only by a matching posted-stake debit.

### D6. Close Reserve Is Resource-Only

The close reserve is not slashable stake. It is a resource budget locked at
open so that the future bounded close path can be executed without charging a
marginal close fee.

This keeps three economic domains separate:

```text
edge principal:
  paid by terms

close reserve:
  pays committed close execution fee
  distributes surplus by terms

stake:
  backs protocol/job violations
  can move to the violated party after a valid violation proof
```

The main upside is readability of the escape hatch. A party can compute
principal recovery, reserve-surplus recovery, and slash exposure independently.
The protocol also avoids edge cases where an honest close might consume value
that was simultaneously needed as collateral.

Decision:

- close reserve is never a penalty source;
- timeout fallback never awards reserve as stake;
- violation close awards configured stake only from posted stake;
- reserve surplus, if any, is distributed by terms after the committed close
  fee is paid;
- any future protocol that wants slashable collateral must use the explicit
  stake domain.

### D7. Active Channel Lifetime Is Prepaid And Finite

Open pays a separate lifetime fee for the live edge slot. That fee is not the
close reserve and it is not principal. It buys a deterministic number of
blocks or epochs of active lifetime, and therefore fixes a public expiry
height for the edge.

The close reserve remains a close-execution reserve only. Rent, channel tax,
state-slot pricing, and expiry must not silently drain it. This keeps the
escape-hatch calculation readable:

```text
gross funding
- open execution fee
- prepaid finite lifetime fee
- locked close reserve
= edge principal governed by terms
```

Decision:

- v1 uses prepaid finite lifetime, not permanent unpaid live slots;
- the paid lifetime is determined at open from public fee schedule or terms;
- every live edge has a public expiry height;
- no non-timeout proof can settle the edge at or beyond expiry;
- an expired live edge has a deterministic timeout cleanup path;
- latest-state and violation proofs must be posted before expiry;
- if a proof-submission obligation is used, its deadline must leave inclusion
  margin before expiry;
- changing future fee schedules cannot alter the already purchased lifetime or
  drain the close reserve.

The tradeoff is explicit. A longer paid lifetime gives parties more time to
produce and post final proofs, but it costs more up front. A shorter paid
lifetime limits L1 state growth, but makes timeout fallback more likely. That
tradeoff belongs in the terms the parties sign.

### D8. Expiry Resolves Through Terms-Defined Timeout

When active-state coverage expires, the L1 does not start an interactive
challenge game and does not invent a new payout. The edge resolves through the
committed timeout terms.

For v1, expiry is modeled as a deterministic timeout close path:

- before expiry, latest-state and violation proofs are admissible;
- at expiry, timeout fallback is admissible;
- stale receipts remain inadmissible;
- timeout fallback is not slashable by itself;
- closing at expiry still consumes only the open-time committed close fee from
  the close reserve;
- no separate collector reward is paid from channel principal, reserve surplus,
  or stake unless future terms deliberately introduce one.

This means the channel tax is not just a spam fee. It is part of the economic
contract: it sets the time window during which a party can realize a
latest-state or violation-proof recovery. Once that window is missed, timeout
terms define the escape hatch. If timeout is worse for one party than the
latest off-chain state, that risk must be priced through lifetime length,
proof costs, proof-submission obligations, watcher assumptions, and stake.

### D9. Provider Stake Is Reused Through Per-Job Locks

Provider stake is posted as a reusable stake pot. Jobs do not require fresh L1
stake deposits. Instead, each accepted job creates a logical lock against that
pot:

```text
posted_provider_stake
  = available_stake
  + sum(active_job_locks)
  + awarded_or_slashed_stake
```

A job lock names:

- job id;
- provider;
- protected party;
- locked amount;
- maximum violation penalty;
- release deadline;
- violation proof conditions.

Signed frontiers should commit to the active lock set with an authenticated
root and aggregate locked total:

```text
active_job_locks_root
active_job_locked_total
available_provider_stake
stake_awards
```

A Merkle-sum authenticated map is the natural representation. The map root
gives compact inclusion/removal proofs for individual locks, and the aggregate
sum gives the capacity invariant without revealing every active job.

The provider's unresolved concurrency is bounded by available stake. If a
provider posts `100` stake and accepts five unresolved jobs with `20` stake
locks each, the provider has no remaining stake capacity until a job releases
or more stake is posted.

There are three release paths:

- **Accepted frontier release**: a later mutually signed frontier explicitly
  marks the job accepted/released or removes the job id from active locks.
  This is the fast path and reopens provider capacity immediately.
- **Deadline release**: if the protected party disappears, the lock releases at
  the job release deadline unless a valid violation proof has already been
  posted.
- **Violation slash**: before release, a valid violation proof transfers the
  configured job penalty from the locked job stake to the violated party.
  Any locked amount above the penalty returns to available provider stake.

The phrase "the request made it out of the frontier" is therefore only safe if
it means the signed successor frontier explicitly changes the lock set. Local
queue state is not enough. The release witness must be public to the channel
parties and reducible to the L1 close proof or channel-state proof if needed.

There is no on-chain defense step. A close that uses a job-lock root is either
valid by construction or rejected. In particular, the verifier relation must
not treat membership in an arbitrary old signed root as enough to slash. A
violation close proof must bind the relevant frontier commitment, job-lock
leaf, violation predicate, penalty, payouts, and terms, and prove that those
public inputs define the final admissible close outcome for the channel.

`models/job_stake_locks.qnt` checks this lifecycle directly. It verifies that
concurrent job locks cannot exceed the provider stake pot, accepted frontier
release reopens capacity, deadline release reopens capacity, released jobs
cannot be slashed, and stake awards are backed only by slashed job locks.

`models/frontier.qnt` defines the shared frontier commitment vocabulary.
`models/frontier_commitments.qnt` checks the compact-commitment boundary using
that vocabulary. It abstracts the Merkle-sum map to a small root vocabulary and
verifies that accepted closes bind the current admissible frontier, reject
stale active roots after a signed release frontier, reject bad aggregate totals,
and account for slash or release outcomes without an on-chain defense step.

`models/frontier_progression.qnt` separates off-chain peer acceptance from
kernel-close validity. It checks that peers reject lower-sequence stale
frontiers, reject bad aggregate totals, and reject a higher-sequence attempt to
reintroduce the same released or slashed job lock. It also records the important
counterexample: after a peer has accepted a release frontier, the old active
frontier is still a well-formed historical signature. A bare signed frontier is
therefore not a sufficient unilateral L1 close source.

### D10. Bare Signed Frontiers Are Not A Kernel Close Source

A signed frontier proves that the parties signed that frontier. It does not, by
itself, prove that no later frontier exists.

That distinction matters because Hellas does not have an on-chain challenge
round. If the kernel accepted any well-formed historical signed frontier as a
unilateral close proof, a party could close with an old active job-lock root
after signing a later release frontier. The off-chain peer would reject the old
receipt, but the L1 would not know the peer's current frontier.

So a close path that depends on the "current frontier" needs a
verifier-visible freshness source. The viable shapes are:

- an L1-anchored monotonic frontier, where the kernel stores the latest
  accepted sequence/root and close must match that anchor;
- a fresh mutual close authorization over the exact close payload, where both
  parties are consenting to this close now rather than merely revealing an old
  state receipt;
- a self-contained proof/seal whose public inputs make stale frontier
  latestness irrelevant.

Until one of those mechanisms is selected for a particular close path,
`models/frontier_commitments.qnt` should be read as a verifier-boundary model
under a current-frontier assumption. `models/frontier_progression.qnt` is the
guardrail that keeps that assumption explicit.

`models/proof_lifetime.qnt` now uses the same distinction at the close-proof
level. A fresh mutual latest close and a self-contained latest proof are
admissible before expiry. A bare signed receipt is not. Timeout remains the
deterministic fallback after paid lifetime expires.

`models/settlement_witness.qnt` makes the close-proof public input boundary
explicit. An accepted witness must bind:

- the expected edge;
- the terms identity;
- the payout shape;
- the expiry height;
- the close proof kind;
- the frontier commitment;
- the stake award, if any.

It also names the rejected shapes: bare signed receipt, wrong terms, wrong
payouts, wrong edge, wrong expiry, bad frontier aggregate, stale active root
for latest settlement, violation without evidence, violation without an active
slash root, violation without the configured stake award, and timeout before
expiry.

### D11. Open Funding Shape Is Terms-General

One-sided funding, empty funding, and same-party edges are protocol-valid
kernel shapes.

The rule is deliberately uniform:

```text
gross_funding
- open execution fee
- prepaid finite lifetime fee
- locked close reserve
= edge principal governed by terms
```

The kernel does not care whether `gross_funding` came from the maker side, the
taker side, both sides, or neither side. It only checks that the funding coins
are owned by the party positions named in terms, both party positions authorize
the exact open, and aggregate funding covers the required debit.

Consequences:

- maker-only and taker-only opens are valid and required for sponsored,
  deposit-like, voucher-like, and asymmetric commercial terms;
- empty funding is valid only when the effective open debit is zero, such as a
  zero-fee development schedule or a future explicit sponsored-key fee policy;
- a sponsored-key extension must not hide unpaid persistent-state growth; it
  needs an explicit sponsor/subsidy accounting domain or an explicit protocol
  subsidy rule;
- `maker == taker` is valid. Maker and taker are positional roles, not a
  requirement for two distinct keys.

Model consequence:

The unified model must include traces for full funding, maker-only funding,
taker-only funding, empty funding under zero effective debit, insufficient
one-sided funding, and same-party edges. The current Rust suite already has
focused coverage for these kernel shapes; the unified Quint model should keep
them as first-class protocol cases rather than relying on incidental
implementation generality.

## Pricing Invariants For Active Channel Lifetime

Open-time close pricing solves close liveness, but it does not solve active
state growth. The remaining pricing question is whether live channels are a
bounded protocol liability while they remain open.

An active channel consumes at least three kinds of protocol resource:

- the creation/write cost paid by the open;
- the live state slot cost while the edge remains open;
- the future close cost the protocol must be able to execute without trusting
  the counterparty.

The exact resource prices can be abstract. The model does not need to know disk
bytes or database internals, but it does need named units whose accounting is
explicit:

```text
open_write_units
live_edge_slot_units_per_epoch
bounded_close_units
close_output_write_units
```

A fee schedule maps these units to value. The security property is independent
of the numeric price, but not independent of which resources are priced.

Required pricing/resource invariants:

- no accepted transition creates persistent live state without paying or
  locking value for the associated resource;
- every live edge has a funded close path priced at open;
- fee or rent changes cannot silently reduce a party's escape-hatch lower bound
  except through terms the party signed or a valid slash/expiry rule;
- live-state rent, if any, must be deterministic from public state and terms so
  both parties can compute recovery as a function of height;
- close execution reserve must not be accidentally drained by live-state rent
  unless the terms explicitly say that losing close liveness is part of the
  deal;
- there must be no immortal unpaid live slot: active lifetime must be prepaid,
  bonded, expiring, rented, or otherwise explicitly accounted for.

Mechanisms that can satisfy these invariants include:

- higher open fees that prepay storage for a bounded or permanent lifetime;
- a refundable state-slot bond that is returned on close and partially or fully
  collected if the channel is abandoned past an agreed expiry;
- deterministic per-epoch rent drawn from a separate rent budget;
- prepaid close rewards or cleanup rewards that make cleanup profitable;
- bounded fee schedules where the open-time close reserve always covers close
  execution for the edge.

Mechanisms that are not sufficient by themselves:

- making open expensive without defining what lifetime or state liability it
  buys;
- making close cheap while abandoned channels remain free to keep alive;
- current close-time repricing that can strand an edge without a top-up,
  expiry, or collection rule;
- silently taxing principal/reserve in a way that parties cannot include in
  their minimum-recovery calculation.

The likely clean split is:

```text
close_execution_reserve:
  pays only for the bounded on-chain close path

state_slot_budget_or_bond:
  pays for, collateralizes, or expires the live edge slot
```

Keeping these separate preserves the escape-hatch invariant: state rent can
incentivize cleanup without unexpectedly destroying the value reserved for
unilateral close.

## Active Lifetime Model

`models/lifetime.qnt` is a focused policy-comparison model for the active
channel lifetime question. It remains useful as a workbench for alternatives,
but the v1 direction is the prepaid finite-lifetime path modeled more tightly
in `models/proof_lifetime.qnt`.

The model explores three shapes:

- permanent lifetime paid by an up-front slot fee;
- bounded rent budget consumed deterministically over height;
- state-slot bond that can be collected after expiry.

Across all three shapes, the model checks:

- value is accounted across liquid principal, edge principal, close reserve,
  state budget, state bond, fees, and rewards;
- liquid value and rewards are party-indexed, so collector rewards are not
  confused with maker/taker principal recovery;
- every live edge keeps a close reserve that covers the open-time committed
  close fee;
- close remains available for every live edge, even after the current fee
  schedule is raised above the reserve;
- rent never drains the close reserve;
- an expired live edge has an explicit close/collect cleanup path;
- collection can claim only the state-slot budget or bond, not channel
  principal or close reserve surplus beyond the terms-defined path.
- each party's current escape-hatch lower bound is nonnegative and matches the
  value domains assigned by terms.

This model does not prove that someone eventually collects an expired edge.
That is a liveness/fairness property. To make cleanup unavoidable, the
production protocol needs either an automatic transition, a block validity rule
that forbids carrying expired unpaid slots, or an incentive/fairness assumption
that ensures enabled collectors eventually act.

## Proof-Only Lifetime Settlement Model

`models/proof_lifetime.qnt` is a focused workbench for Hellas L1 settlement
when active channel lifetime is paid up front by a channel tax.

It models one live edge with:

- a fresh mutual latest close that resolves to the latest terms;
- a self-contained latest-state proof that resolves to the latest terms;
- a violation proof/seal that also resolves to the latest terms;
- a stale receipt that is not an admissible L1 proof;
- a bare signed receipt that is not an admissible L1 proof;
- a deterministic timeout fallback once the prepaid lifetime is exhausted.

The close-proof public-input boundary is modeled separately in
`models/settlement_witness.qnt`: each accepted settlement witness must bind the
edge, terms, payouts, expiry, proof kind, frontier commitment, and stake award.
This keeps proof timing separate from proof payload binding.

The proof-lifetime model checks that:

- the lifetime fee deterministically fixes the expiry height;
- once expiry is reached, non-timeout proofs no longer settle the edge;
- fresh mutual latest close, self-contained latest proof, and violation proof
  can settle before expiry without consulting the current fee schedule;
- close has no marginal fee: the only close fee paid is the open-time
  committed close fee already covered by the reserve;
- stale receipts and bare signed receipts are rejected at the L1 proof
  boundary;
- timeout close at expiry uses the committed timeout terms;
- close proof timing is explicit: fresh mutual latest, self-contained latest
  proof, and violation before expiry; timeout at or after expiry;
- if the latest-state holder misses the expiry, timeout settlement can reduce
  that party's latest-state lower bound.

This is the important modeling distinction: Hellas L1 does not preserve
latest-state recovery by running a challenge window. It preserves safety by
accepting only valid final proofs. Any iterative challenge/proof cycle must
happen off-chain, and the L1 proof/seal must already encode the resolved
outcome.

## Proof-Obligation Lifecycle Model

`models/proof_obligations.qnt` is a focused workbench for the slashable
proof-submission case. It uses the shared `ProofSubmissionObligation` shape
from `models/proofs.qnt`, so lifecycle and incentive checks agree on what makes
an obligation enforceable.

The modeled obligation contains:

- obligor;
- beneficiary;
- required self-contained latest proof;
- creation height;
- proof deadline;
- channel expiry height;
- penalty amount;
- penalty budget.

The model checks that:

- a self-contained latest proof submitted before the deadline discharges the
  obligation;
- a missed deadline can be reduced to a violation seal before expiry;
- the proof deadline leaves at least one inclusion-margin block before expiry;
- timeout fallback remains a non-slashing close path;
- no slash is possible without a public signed obligation;
- unsafe obligations with deadline equal to expiry are rejected;
- breach-seal recovery is not worse than timeout recovery for the protected
  party.

This is still not a liveness proof. After a missed deadline, the model allows
the scheduler to do nothing until timeout. That path closes by ordinary timeout
and does not slash. A breach penalty helps only if the beneficiary or a watcher
actually posts the violation seal before expiry.

## Stake-Backed Violation Accounting Model

`models/staked_obligations.qnt` composes the proof-obligation timing rule with
explicit stake accounting.

The model tracks:

- liquid close recovery;
- live edge principal;
- locked close reserve;
- fees paid;
- posted stake by party;
- stake awards by party.

The model checks that:

- total value is conserved across principal, reserve, fees, posted stake, and
  stake awards;
- stake awards never exceed posted stake;
- stake awards happen only through a violation proof;
- timeout fallback never awards stake;
- fresh mutual latest close and self-contained latest proof close never award
  stake;
- unbacked and unsafe-late obligations cannot award stake;
- violation close awards the configured penalty to the violated party;
- violation close recovery for the violated party is at least that party's
  timeout and latest-state recovery in the sample terms.

## Incentive Compatibility Model

`models/incentives.qnt` is the first focused payoff workbench. It does not
model L1 transition safety. It compares rational party payoffs under one
`IncentiveTerms` value from `models/terms.qnt`: latest terms, timeout fallback
terms, stale receipt terms, proof costs, stake, penalties, and the evidence
conditions that make each penalty enforceable. The proof-obligation penalty is
now backed by a concrete `ProofSubmissionObligation`, not just a boolean flag.

The current concrete scenario intentionally includes an imbalanced channel:

- latest terms favor the maker;
- timeout terms favor the taker;
- stale receipt terms would favor the taker even more if they were accepted;
- the provider role is modeled as the taker for bad-compute incentives.

The model checks:

- if a final proof improves a party's timeout outcome, posting it before
  expiry beats letting timeout happen;
- deterministic timeout fallback is L1-admissible but not slashable;
- timeout fallback can favor one party, so the terms, paid lifetime, and proof
  cost must make that outcome acceptable before the edge is opened;
- breaching a signed proof-submission obligation is not profitable after an
  enforceable proof-obligation-breach penalty;
- submitting stale receipts is not profitable after attempt cost and penalty;
- bad compute is not profitable after slash;
- all penalties are backed by modeled stake.

A configured penalty counts only if it is enforceable:

```text
proof_obligation_satisfied(deviation)
  = evidence_matches_deviation(deviation, evidence)
    and any_required_public_obligation_is_well_formed(deviation)
    and obligation_deadline_leaves_pre_expiry_margin
    and obligation_penalty_matches_configured_penalty
    and evidence_can_prove_violation(evidence)
    and proof_matches_evidence(evidence, proof)
    and proof_kind_maps_to_l1_close_kind
    and proof_kind_can_carry_slash

penalty_backed(deviation)
  = proof_obligation_satisfied(deviation)
    and penalty_source(deviation) != none
    and penalty_budget(deviation) >= configured_penalty(deviation)

enforceable_penalty(deviation)
  = if penalty_backed(deviation) then configured_penalty(deviation) else 0
```

The payoff model uses `enforceable_penalty`, not the raw configured penalty.
This is the soundness boundary: if the protocol cannot produce evidence and
source the penalty through an admissible L1 close proof, the economic model
does not get to count it.

The model deliberately does not slash private silence. "They had a proof and
did not send it" is not L1 evidence by itself. The enforceable case is a
proof-obligation breach:

- the open terms or a later signed channel state creates a public
  proof-submission obligation;
- the obligation names the required proof, obligor, deadline, penalty amount,
  and penalty budget;
- the deadline passes while the required proof has not closed the edge;
- a violation seal proves the signed obligation plus the missed deadline.

Without that positive obligation artifact, the strategy collapses back to
ordinary timeout fallback. The protocol may still dislike that outcome, but the
model must handle it through timeout terms, proof cost, paid lifetime, and
watcher assumptions rather than by counting a slash.

Derived requirements:

```text
required_proof_obligation_breach_penalty(p)
  = max(0, timeout[p] - latest[p] - deviation_friction + 1)

required_stale_receipt_penalty(p)
  = max(0, stale_receipt[p] - latest[p] - rejected_receipt_cost + 1)

required_bad_compute_penalty(p)
  = max(0, bad_compute_private_gain - deviation_friction + 1)

proof_cost_ceiling(p)
  = max(0, latest[p] - timeout[p] - 1)

required_stake
  = max(enforceable_proof_obligation_breach_penalty,
        enforceable_stale_receipt_penalty,
        enforceable_bad_compute_penalty)
```

Current margins:

```text
required proof-obligation-breach penalty for taker = 7
configured proof-obligation-breach penalty = 9
required stale-receipt penalty for taker = 9
configured stale-receipt penalty = 10
required bad-compute penalty = 4
configured bad-compute penalty = 8
maker proof-cost ceiling = 6
configured proof cost = 2
required stake = 10
posted stake = 12

maker final-proof margin over timeout = 5
taker timeout-fallback advantage over latest = 7
taker proof-obligation-breach margin = 3
taker stale-receipt margin = 2
taker bad-compute margin = 5
```

The small positive margins are deliberate. They make the model sensitive:
reducing a penalty or increasing a deviation gain should produce a nearby
counterexample instead of leaving a huge unexplained buffer. The model also
contains an explicit timeout-fallback trace: with the current imbalanced sample
terms, the taker prefers deterministic timeout fallback to the latest state.
That is not itself a slashable deviation; it is a terms/lifetime/proof-posting
design fact the parties must account for before opening the edge. The
punishable deviation is breaching a signed proof-submission obligation when the
terms provide matching evidence, a violation proof, and backed stake. The model
also contains an unbacked-penalty counterexample: configuring a
proof-obligation-breach penalty without a signed/public obligation and matching
evidence/proof collapses the enforceable penalty to zero and makes the breach
profitable again.
It also contains a late-deadline counterexample: a signed obligation whose
proof deadline is equal to channel expiry is public but unenforceable, because
there is no pre-expiry margin to submit the breach seal.

## Questions To Resolve

### 1. What Are The Value Buckets? Resolved For Ordinary Fees

Question:
Which buckets must the protocol distinguish in state?

Candidate buckets:
- `coins`: user-owned liquid principal.
- `edges`: escrowed channel principal.
- `reserves`: locked resource budget for future close.
- `stateSlotBudget` or `stateSlotBond`: value paid, locked, or at risk for
  occupying live persistent edge state over time.
- `feesPaid`: ordinary protocol resource fees already collected.
- `burned`: value intentionally destroyed.
- `stake`: slashable collateral posted for protocol security.
- `slashed`: collateral removed from a party.
- `rewards`: value claimable by watchers, challengers, collectors, or sequencer.

Model impact:
The top-level accounting invariant depends on this list. If stake and rewards
are real protocol concepts, they should not be hidden inside `feesPaid`.

Decision:
Ordinary accepted-transition resource fees use `feesPaid`, an abstract protocol
fee sink. Burn, treasury, sequencer revenue, slashing, and actor rewards remain
separate concepts unless explicitly refined later.

### 2. Who Pays Open Fees And Close Reserves?

Question:
When an open consumes maker and taker funding, how are fee and reserve debited?

Options:
- Aggregate funding pays everything. This is current kernel behavior.
- Maker pays all fees/reserve.
- Taker pays all fees/reserve.
- Each party pays proportional to contributed funding.
- Fee payer is explicit in the transaction.
- Protocol terms define the split.

Security impact:
This decides whether a party can grief the other by forcing their principal to
pay fees, and whether one-sided funding is economically meaningful.

Model impact:
The unified model must track per-party contribution and resulting per-party
principal if fee burden is not just aggregate.

Decision:
Aggregate funding pays ordinary open fees and the locked close reserve. The
protocol does not track fee-payer identity. Terms govern net edge principal and
the reserve-surplus policy after those debits.

### 3. Are One-Sided And Empty Funding Real Protocol Cases?

Question:
Should maker-only, taker-only, and empty funding be valid at the protocol level,
or are they just kernel-general shapes?

Current Rust:
They are accepted when funding covers open fee, lifetime fee, and close
reserve. Empty funding is only accepted when the effective open debit is zero.

Security impact:
One-sided funding can be useful for sponsored channels or unilateral deposits,
but it changes how fairness and fee burden should be stated.

Model impact:
If allowed, the unified model should explore:
- full funding,
- maker-only funding,
- taker-only funding,
- empty funding under zero effective debit,
- insufficient one-sided funding.

Decision:
One-sided and empty funding are protocol-valid. One-sided funding is a
requirement for sponsored, deposit-like, and asymmetric terms. Empty funding is
valid only when the effective debit is zero; future sponsored-key fee
exemptions must be explicit accounting/policy extensions, not hidden unpaid
state growth.

### 4. What Does The Close Reserve Mean?

Question:
Is the reserve purely a prepaid resource fee, or is it also collateral/stake?

Current Rust:
It is a prepaid resource budget for close execution. The selected close path's
open-time committed fee is consumed at close, and any reserve surplus is
distributed through close outputs. It is not separately slashable.

Options:
- Resource-only reserve.
- Slashable stake.
- Hybrid: reserve pays resource cost, remainder is slashable/refundable.

Security impact:
If reserve is stake, then close behavior, challenge behavior, and failure to
close all need slashing semantics.

Model impact:
Resource reserve and slashable stake should be separate variables unless the
protocol intentionally treats them as one bucket.

Decision:
The close reserve is resource-only. It is not slashable stake and is not a
penalty source. Slashing must debit explicit posted stake.

### 5. Should Unused Reserve Refund?

Question:
If locked reserve exceeds the close fee committed at open, where does the
surplus go?

Current Rust:
Reserve surplus is distributed through the close outputs. For `Terms::Basic`,
the timeout output list is the deterministic timeout surplus policy.

Options:
- No refund. Whole reserve goes to `feesPaid` or `burned`.
- Refund surplus to maker/taker.
- Refund surplus according to original fee payer.
- Convert surplus to reward for closer/collector.
- Distribute surplus according to terms.

Security impact:
No-refund simplifies accounting and discourages spam, but overcharges channels
whose selected close path is cheaper than the worst-case path.

Decision:
Reserve surplus is distributed according to terms. This preserves the
escape-hatch property: each party can evaluate the minimum capital they recover
on-chain from the current agreed state.

Model impact:
The close action must move only the open-time committed close fee to
`feesPaid`. Any surplus must move through a terms-defined payout path.

### 6. Which Fee Schedule Prices Close? Resolved

Question:
Does close use the fee schedule at open time, close time, or a bounded rule?

Current Rust:
Close uses the open-time committed reserve and does not reprice against the
current block fee schedule.

Options:
- Open-time schedule. Edge always carries enough reserve for its future close.
- Close-time schedule. Fee raises can strand old edges.
- Min/max bounded schedule. Fee can change, but only within reserved coverage.
- Close-time schedule with external top-up.
- Expiring channel. Close reserve covers close execution through a declared
  expiry, and post-expiry collection is explicit in terms.
- Separate state-slot rent or bond. Active lifetime is priced separately from
  close execution.

Security impact:
Close-time pricing makes fee raises an eviction knob and can strand users who
do not close before fees rise. That violates the escape-hatch invariant unless
the loss of liveness was an explicit signed term.

Model impact:
The model needs fee schedule state and traces where fees change while edges are
live. It also needs to distinguish the close-execution reserve from any
state-slot rent or bond if active channel lifetime is priced separately.

Decision:
Close execution is priced at open time. Closing has no marginal fee and does
not consult the current fee schedule. Existing edges remain normally closable
after later fee raises.

### 7. What Happens When Active-State Coverage Expires?

Question:
If the close path is prepaid at open, what handles channels whose active-state
lifetime was not prepaid forever?

Current Rust:
`Edge` stores a committed timeout height and enforces close-proof timing:
mutual and violation closes are pre-timeout, while timeout closes are
at-or-after-timeout. Open charges a lifetime fee proportional to the chosen
timeout span using the current lifetime price. A top-up path and collector reward
path do not yet exist.

Options:
- Open fee buys permanent lifetime.
- Open fee buys bounded lifetime; after expiry, a terms-defined collection path
  exists.
- A separate state-slot bond is returned on close and collectable after expiry.
- A separate rent budget is consumed deterministically over height.
- A helper can top up active-state budget without changing channel principal.

Security impact:
This is the remaining active-channel growth tradeoff. Existing close liveness
must not be lost accidentally, but the system also must not accumulate immortal
unpaid live slots.

Model impact:
If there is rent, expiry, top-up, or collection, it must be modeled as a
transition with explicit value movement and per-party recovery impact.

Decision:
For v1, open prepays finite lifetime and fixes a deterministic expiry height.
At expiry, the L1 resolves the edge through committed timeout terms. Latest and
violation proofs are pre-expiry paths. There is no separate v1 collector reward
from channel principal, reserve surplus, or stake.

### 8. What Is Spam Prevention At The Kernel Layer?

Question:
What persistent resources must every accepted transition pay for?

Current Rust:
Open pays for its own operation and locks reserve for worst-case close. Close
has no marginal fee; it consumes only the open-time committed close fee and
distributes reserve surplus through close outputs.

Security impact:
Accepted transactions must not create persistent storage or future verification
work without funding the corresponding resource cost.

Model impact:
Add invariants such as:
- every live edge has locked reserve,
- every live edge has paid open cost,
- every live edge has paid, locked, or expiring state-slot coverage,
- every possible close path is prepaid at open,
- no accepted transition increases persistent live slots without increasing
  `feesPaid`, `reserves`, `stateSlotBudgets`, or reducing user principal
  accordingly.

### 9. What Is Staked Security?

Question:
What collateral exists to make bad behavior expensive?

Possible stake roles:
- maker/taker channel stake,
- operator/sequencer stake,
- prover/watcher stake,
- solver/executor stake,
- dispute bond posted only during challenge.

Questions:
- Who posts stake?
- Where is stake stored?
- What actions slash it?
- Who receives slashed value? For channel/job violations, this is decided:
  the violated party receives the configured stake penalty.
- Can slashed value pay protocol fees or collector rewards?
- Does stake need to cover worst-case damage or only spam/resource cost?

Model impact:
Stake should be its own bucket with explicit owner and slash transitions. It
should not be conflated with close reserve unless that is a deliberate protocol
decision.

### 10. Who Can Collect Fees, Burns, And Slashes?

Question:
Are collected fees burned, paid to sequencer, paid to protocol treasury, paid
to the closer, or paid to a collector?

Security impact:
Rewards determine incentives for closing stale edges, submitting disputes, and
keeping state clean.

Model impact:
If rewards are claimable by a party, the model needs a reward output path, not
just a `feesPaid` accumulator.

Decision:
No v1 collector reward is needed for active lifetime expiry because expiry
uses the deterministic timeout close path. Ordinary fees remain in `feesPaid`.
Channel/job violation stake is awarded to the violated party. Future
watcher/collector/challenger rewards need explicit terms and a separate reward
bucket before the model may count them.

### 11. What Does Same-Party Channel Mean?

Question:
Should `maker == taker` be protocol-valid?

Current Rust:
Allowed.

Security impact:
Same-party channels may be useful for tests/internal flows, but they can hide
authorization and accounting mistakes if the model assumes two distinct
parties.

Model impact:
If allowed, model same-party explicitly. If not allowed, add a kernel/protocol
guard and a rejection test.

Decision:
Same-party channels are protocol-valid. Maker and taker are positional roles;
the protocol does not require two distinct keys.

### 12. Which Layer Owns Fee Admission?

Question:
Does the kernel alone enforce fee sufficiency, or does an outer admission layer
also price failed transaction execution?

Current Rust:
The kernel enforces persistent-state accounting for accepted transactions.
Rejected transactions do not mutate state.

Security impact:
Kernel fees prevent unpaid state growth. They do not by themselves prevent
network spam from invalid transactions. That may belong to mempool/admission,
but the boundary should be explicit.

Model impact:
The L1 model should focus on accepted state transitions. A separate admission
model may be needed for invalid-transaction spam.

## Unified Quint Model Requirements

`models/l1_fees.qnt` is the first unified accepted-transition model. It
combines the L1 open/close lifecycle with fee, reserve, prepaid lifetime,
open-time close fee, terms-defined reserve surplus, explicit posted stake, and
violation stake awards.

It now generates ITF fixtures alongside `models/l1.qnt`. `models/l1.qnt`
continues to cover the focused two-edge lifecycle, invalid open/close shapes,
and noncanonical payout rejection. `models/l1_fees.qnt` covers the
fee-bearing accepted-transition lifecycle and is replayed by a separate Rust
runner that checks fees, reserves, stake buckets, party bindings, and concrete
kernel objects.

`models/l1_fees.qnt` is included in `quint:test`, `quint:run`, and
`quint:verify`. The Apalache verify target uses `--max-steps=4`, which covers
the longest meaningful lifecycle in this single-edge model:
open, optional fee raise, expiry tick, and close. `tick` is capped at the
timeout height and idle is not part of the verified transition relation, so the
checker does not spend time exploring duplicate stutter states.

The focused models remain useful for narrower mechanism checks:
`models/lifetime.qnt` explores lifetime alternatives,
`models/proof_lifetime.qnt` isolates proof timing, and the stake/frontier models
stress their own boundaries.

State variables:
- `coins: Coin -> int`
- `edges: Edge -> int`
- `reserves: Edge -> int`
- `closeFees: Edge -> int`
- `edgeShape: Edge -> FundingShape`
- `edgeParties: Edge -> OpenParties`
- `liveCoins: Set[Coin]`
- `liveEdges: Set[Edge]`
- `paid: int`
- `height: int`
- `currentCloseFee: int`
- `postedStake: Party -> int`
- `stakeAwards: Party -> int`
- `closeOutcome`
- `lastInput`
- `lastEvent`

Core invariants:
- full accounting across all buckets,
- no negative bucket,
- dead slots are zero,
- live edges have reserve,
- live edges have open-time committed close execution fees,
- live edges have paid, locked, or explicitly expiring state-slot coverage,
- reserve belongs only to live edges,
- state-slot budget or bond belongs only to live edges,
- accepted open pays open fee and locks close reserve,
- locked close reserve covers the open-time committed close fee,
- deterministic timeout terms payouts sum to net edge principal plus timeout
  reserve surplus,
- reserve-surplus policy distributes exactly the reserve left after the
  open-time committed close fee,
- each live edge has coherent terms over principal, reserve surplus,
  state-slot budget, and state-slot bond domains,
- every party's escape-hatch lower bound is computable from public state and
  terms,
- expired live edges have a deterministic timeout close path,
- mutual and violation closes are rejected at or after expiry,
- stale receipts and bare signed receipts are not admissible L1 close proofs,
- accepted fresh mutual latest closes, self-contained latest proofs, and
  violation proofs preserve the latest terms-defined lower bound,
- deterministic timeout close uses the committed timeout terms after expiry,
- close cannot mint principal,
- close consumes reserve according to the open-time close fee and chosen
  surplus rule,
- close does not debit live coins or consult the current fee schedule,
- payout values honor close-proof binding,
- funding authorization holds for every live edge,
- fee schedule changes do not reduce close liveness for existing edges,
- violation stake awards are backed only by posted-stake debits.

Trace coverage:
- full two-party funding,
- maker-only funding,
- taker-only funding,
- empty funding under zero effective debit,
- same-party edge,
- underfunded open rejection,
- fee raise before close,
- close after fee raise succeeds using open-time committed close budget,
- channel expiry enables timeout and disables mutual/violation,
- reserve surplus handling,
- violation stake award accounting.

The model intentionally matches the kernel's resource-pricing shape:
full two-party opens pay the full open cost, while maker-only, taker-only, and
self-edge opens pay the lower one-input open cost. Empty opens pay zero only
under a zero-fee context.

Remaining integration gaps:

- multiple sequential edges with fee-bearing accounting;
- noncanonical payout rejection in the unified model, currently covered by
  `models/l1.qnt`;
- unauthorized open rejection in the unified model, currently covered by
  `models/l1.qnt`;
- self-contained latest proofs and bare receipt rejection, currently covered by
  `models/proof_lifetime.qnt` and `models/settlement_witness.qnt`;
- job-lock frontier roots, currently covered by the frontier/job focused
  models.

## Proposed Work Plan

1. Decide whether reserve is resource-only, stake, or hybrid. Done:
   resource-only.
2. Decide who pays fees/reserve. Done: aggregate funding.
3. Model reserve surplus according to terms. Done in focused models.
4. Model active channel lifetime alternatives.
5. Decide how active channel lifetime is priced or bounded. Done for v1:
   prepaid finite lifetime.
6. Decide what happens when active-state coverage expires. Done for v1:
   deterministic timeout close.
7. Implement open-time close pricing in Rust.
8. Decide whether one-sided, empty, and same-party channels are protocol-valid.
   Done: all three are protocol-valid; empty funding requires zero effective
   open debit.
9. Define fee and stake buckets. Done for current model family.
10. Model reusable provider stake with per-job locks. Done in
   `models/job_stake_locks.qnt`.
11. Build unified `models/l1_fees.qnt` or fold fees into `models/l1.qnt`.
    Done: `models/l1_fees.qnt` is the unified fee-bearing accepted-transition
    model.
12. Regenerate ITF fixtures and extend the Rust fixture runner if needed. Done:
    `npm run quint:fixtures` emits both `l1_*.itf.json` and
    `l1_fees_*.itf.json`, and `tests/itf.rs` replays both families.
13. Retire the old focused fee sketch once the unified model covers it. Done:
   the old fee-only model has been removed from the test/verify path in favor
   of `models/l1_fees.qnt`.

## Open Decisions

- [ ] What non-provider stake exists, who posts it, and what slashes it?
- [ ] Does the unified model include admission-layer invalid transaction spam,
  or only accepted L1 transitions?
