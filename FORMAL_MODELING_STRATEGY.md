# Formal Modeling Strategy

This document describes how Hellas should model the whole protocol without
turning the model into the protocol implementation.

The goal is a small, stable modeling language for the system. New mechanisms
should be easy to explore, compare, and discard. The model should lock the
security obligations, not lock us into one implementation too early.

## Core Principle

Do not build one giant model of everything.

Build a family of small models over a shared vocabulary:

- focused workbench models for one mechanism;
- integrated safety models for how mechanisms compose;
- trace-replay models that stay close to Rust;
- liveness models only where fairness or eventual action matters.

Each small model should answer one question. The shared vocabulary and
cross-model invariants are what make the family behave like one coherent model.

## Shared Algebra

Every protocol model should be expressible in terms of the same few concepts:

- parties;
- live objects;
- value buckets;
- authorization;
- terms;
- witnesses;
- transitions;
- public time/height;
- lower-bound recovery.

The shared Quint modules are:

- `models/accounting.qnt`: party-indexed value buckets and totals;
- `models/proofs.qnt`: economic proof kinds mapped to the L1 close-proof
  boundary, including mutual latest close, self-contained latest proof, timeout,
  violation seal, and rejected bare signed receipts, plus the shared
  `ProofSubmissionObligation` shape;
- `models/terms.qnt`: economic terms split by value domain, plus incentive
  terms, penalty enforceability, and derived payoff requirements;
- `models/frontier.qnt`: signed frontier commitment vocabulary for active
  job-lock roots, aggregate locked stake, available stake, and stake awards;
- `models/bounds.qnt`: `escapeHatchLowerBound(...)`.

The important representation rule is:

```text
state + signed terms + witness -> enabled transition + value movement
```

If a mechanism cannot be expressed in that form, either the mechanism is not
kernel-relevant or the shared algebra is missing a concept.

## Model Interface

Focused mechanism models should expose the same shape:

```text
canOpen(...)
canAdvance(...)
canClose(...)
canCollect(...)

valueAccounted
noNegativeBucket
escapeHatchLowerBound
authorizationRequired
cleanupPathExists
```

Not every model needs every action, but the absence should be explicit. For
example, a pure L1 open/close model may have no `canCollect`; an active-state
rent model must have one if rent expiry creates a stale live slot.

## Smallness Rules

A model is too large when changing a mechanism requires editing unrelated
proof obligations.

Use these rules to keep models small:

- Model mechanism inputs, outputs, and obligations, not implementation detail.
- Use finite representative universes with the smallest useful cardinality.
- Collapse cryptography to authenticated facts once a verifier boundary exists.
- Collapse proofs to proof kinds plus public inputs unless proof internals are
  the subject of the model.
- Track value buckets explicitly; do not encode economic meaning in one total.
- Keep dead object slots zero and make live sets define which slots matter.
- Prefer maps indexed by party/object over duplicated maker/taker variables
  when the property is symmetric.
- Prefer one parameterized transition over separate mirrored transitions.
- Use an ADT for mechanism choices when comparing policies.
- Delete or demote a focused model after its obligation is absorbed by a
  stronger integrated model.

The model should be boring. If the model needs clever case splits, the
representation is probably not right yet.

## Symmetry Rules

Symmetry is one of the main tools for keeping the state space small.

Useful symmetries:

- maker and taker are roles, not economic meanings;
- user and provider are policy-level labels, not L1 object kinds;
- funding source and fee burden are terms-level economics unless the kernel
  needs to distinguish them;
- proof kinds should share one close transition where possible;
- resource buckets should use one accounting equation, even when some buckets
  are fixed to zero in v1.

Break symmetry only when the protocol actually grants different authority or
different recovery rights. If two cases differ only in story, they should not
be two model states.

## No Edge Cases By Construction

Prefer representations that make invalid states unrepresentable or obviously
dead:

- live sets determine which map entries have meaning;
- dead slots are zero;
- every value bucket is nonnegative;
- every resource has one owner bucket at a time;
- close output ids are canonical;
- terms state their value domains explicitly;
- reserves, stake, rent, slashes, and rewards are separate buckets unless a
  decision deliberately merges them.

When an edge case remains, turn it into a named trace:

- underfunded open;
- unauthorized open;
- fee raise while edge is live;
- rent/budget exhaustion;
- expired edge collection;
- noncanonical payout;
- stale witness;
- same-party channel;
- one-sided funding.

Named traces are cheaper than prose. They also make it obvious when a future
change stops exercising a case.

## Workbench To Integrated Flow

New mechanisms should move through four stages.

1. Workbench model.
   Isolate the mechanism and compare alternatives with the smallest possible
   state. Example: `models/lifetime.qnt`.

2. Obligation extraction.
   Name the invariants the mechanism must preserve. Example: close reserve is
   not rent; fee raises cannot strand close.

3. Integrated model.
   Add only the chosen concepts and obligations to the main L1/channel model.
   Delete policy alternatives that are no longer under consideration.

4. Rust refinement.
   Add trace replay or reference-model checks so Rust is shown to implement the
   integrated transition vocabulary.

Workbench models are allowed to compare mechanisms. Integrated models should
not keep all rejected mechanisms around unless they are still active protocol
options.

## Safety And Liveness

Keep safety and liveness separate.

Safety asks:

- Is value conserved across named buckets?
- Is any party's lower-bound recovery reduced without authorization or slash?
- Can close be stranded?
- Can persistent state be created without paying or locking resource value?
- Can a stale/collector path take more than the terms allow?

Liveness asks:

- Does an enabled close eventually happen?
- Does an enabled collector eventually act?
- Does an expired unpaid slot eventually leave live state?

Safety can usually be checked in small transition models. Liveness requires a
fairness assumption, an automatic transition, or a scheduling model. Do not hide
liveness behind a safety invariant.

Incentives are a third category. They ask whether rational actors prefer the
protocol path over valid-but-hostile strategies. Keep those as explicit payoff
comparisons over named strategies, not as hidden assumptions inside safety or
liveness checks. Any modeled penalty must pass through an enforceability layer:
matching evidence kind, any required public obligation, matching proof kind,
L1-admissible proof obligation, and backed penalty source.

## System Coverage

The protocol should eventually have focused or integrated models for:

| Area | Model role |
| --- | --- |
| L1 object lifecycle | coin/edge reachability, canonical ids, close payouts |
| Open authorization | native/WebAuthn authorization reduces to party consent |
| Fees and close reserve | open-time close budget, reserve surplus, fee raises |
| Active lifetime | permanent slot fee, rent budget, bond, expiry, collection |
| Terms | value domains, timeout outputs, reserve surplus policy |
| State-channel updates | signed frontiers, monotonic state, verifier-visible freshness source |
| Disputes | valid proof/seal outcomes, stale receipts rejected at L1 |
| Stake and slashing | slash conditions, owner buckets, rewards |
| Incentives | payoff comparison for cooperation vs deviation |
| Consensus boundary | ordered finalized blocks, height, fee schedule visibility |
| Store/refinement | Rust transition view matches model transition view |
| Admission/spam | invalid tx cost if the kernel boundary is not enough |

The coverage table is not a request to model everything immediately. It is a
map for keeping each future modeling task small and composable.

## Promotion Criteria

A focused model is ready to influence implementation when:

- its state variables correspond to named protocol concepts;
- every value movement appears in the accounting invariant;
- every party can compute its recovery lower bound from public state and terms;
- rejected alternatives have named counterexamples or explicit tradeoffs;
- the chosen mechanism has trace tests for the important boundary cases;
- the integrated model can absorb the obligation without copying all policy
  alternatives.

## Current Status

- `models/l1.qnt` is the trace-replay L1 lifecycle model.
  Its Apalache verify target is bounded to five transitions, enough for the
  current two-edge replay vocabulary's longest meaningful open/close handoff.
- `models/l1_fees.qnt` is the first unified accepted-transition model. It
  carries L1 lifecycle state plus fee, reserve, prepaid lifetime, open-time
  close-fee, terms, posted-stake, and violation-award buckets. It now emits ITF
  fixtures alongside `models/l1.qnt`; the Rust runner replays those traces
  against concrete kernel state, including committed close fees, reserve,
  payouts, party bindings, and stake accounting. Its Apalache verify target is
  bounded to four transitions, enough for open → optional fee raise → expiry
  tick → close in the single-edge model.
- `models/lifetime.qnt` is the focused active-channel lifetime workbench.
- `models/proof_lifetime.qnt` is the focused proof-only settlement model. It
  proves that stale receipts and bare signed receipts are not admissible L1
  proofs, that prepaid channel tax bounds live-state lifetime, and that
  deterministic timeout fallback can be worse than the latest off-chain state if
  no final proof is posted before expiry. It also records the actual close
  height, so the model checks the intended timing split directly: fresh mutual
  latest close, self-contained latest proof, and violation proof before expiry;
  timeout close at or after expiry; no marginal close fee beyond the open-time
  committed close fee.
- `models/settlement_witness.qnt` is the focused verifier-interface model for
  close witnesses. It checks that accepted close witnesses bind the expected
  edge, terms identity, payout shape, expiry height, frontier commitment, proof
  kind, and stake award. It also names rejected witnesses for bare signed
  receipts, wrong terms, wrong payouts, wrong edge, wrong expiry, bad aggregate
  frontier, stale active roots for latest settlement, missing violation
  evidence, missing violation stake award, and timeout before expiry.
- `models/proof_obligations.qnt` is the focused lifecycle model for signed
  proof-submission obligations. It proves that slashing requires a public
  obligation requiring a self-contained latest proof, that proof deadlines leave
  pre-expiry margin, and that a breach seal is a violation path rather than
  ordinary timeout fallback.
- `models/staked_obligations.qnt` is the focused stake-accounting model. It
  proves that violation closes transfer configured stake from violator to
  violated party, while self-contained latest proof and timeout closes do not
  move stake. It also checks that stake awards are backed only by matching
  posted-stake debits, not by close reserve or principal.
- `models/job_stake_locks.qnt` is the focused reusable-stake model. It proves
  that per-job locks consume capacity from a provider stake pot, accepted
  frontier release and deadline release reopen that capacity, released jobs
  cannot be slashed, and violation awards are backed only by slashed job locks.
  It abstracts over the authenticated data structure; the protocol docs now
  target a Merkle-sum active-job-lock commitment in signed frontiers.
- `models/frontier_commitments.qnt` is the focused frontier-commitment model.
  It abstracts the Merkle-sum map to a finite root vocabulary and checks the
  verifier boundary: a close proof must bind the current admissible frontier,
  root aggregate, and close outcome. Stale active roots after signed release
  and roots with bad aggregate totals are rejected by construction.
- `models/frontier_progression.qnt` is the focused signed-frontier progression
  model. It checks off-chain peer acceptance rules for monotonic sequence,
  aggregate totals, and one-way job-lock release/slash transitions. It also
  documents the kernel boundary: an old active frontier remains a well-formed
  historical signature after release, so unilateral L1 close needs an anchor,
  fresh mutual close authorization, or a self-contained proof/seal rather than
  a bare signed frontier.
- `models/incentives.qnt` is the focused payoff workbench. It compares
  cooperation against proof-obligation-breach, stale-receipt,
  forced-proof-work, and bad-compute deviations under explicit cost, stake, and
  penalty parameters.
  It uses the same self-contained proof-obligation shape as the lifecycle model
  and keeps deterministic timeout fallback as an admissible non-slashing close
  path so timeout policy is not confused with violation evidence.
- `models/accounting.qnt`, `models/proofs.qnt`, `models/terms.qnt`,
  `models/frontier.qnt`, and `models/bounds.qnt`
  provide the shared economic vocabulary used by focused models. `terms.qnt`
  now includes both L1 value-domain terms and incentive payoff requirements.
- `FEES_SECURITY_MODEL.md` tracks fee, reserve, stake, and lifetime decisions.
- `PROTOCOL_SECURITY_MODEL.md` states the escape-hatch invariant the whole
  family of models must preserve.

The next large modeling step should not be adding more one-off variables to
`models/l1.qnt`. It should be promoting the shared `accounting` / `terms` /
`bounds` vocabulary into an integrated model that can absorb fees, reserves,
lifetime, stake, and slashing while preserving the small transition language
above.
