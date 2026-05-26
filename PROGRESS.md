# Implementation Progress

Audited 2026-05-22 against the live tree. The earlier version of this
file claimed many "Phase N done" items that were design files written
into orphan crates and never wired into the build. This rewrite
separates *live* features from *orphan* files honestly, and reframes
"what's next" against the revised design in `docs/AXES.md` (pass 3).

See `PLAN.md` for the *original* refactor design (now partially
superseded by AXES.md pass 3 — see "Superseded design" below).

## What Works Today (live in the binary)

CLI subcommands wired into `crates/cli/src/main.rs`:

- `hellas identity show-node-id` — print the iroh-derived node id.
- `hellas serve` — run the RPC server (feature-gated `hellas-executor`).
  Catgrad text inference via the old proto (`crates/rpc/proto/hellas.proto`
  service `Execute { GetQuote, QuotePrompt, QuoteChatPrompt, ListModels,
  DecodeTokens, Execute, GetStats, GetModelStats }`).
- `hellas gateway` — HTTP gateway: OpenAI / Anthropic / plain endpoints;
  `--local` / `--verify-local` use the in-process catgrad executor;
  discovery-based remote execution otherwise; `--wrap` mode wraps a child
  process with the gateway as its OpenAI/Anthropic backend.
- `hellas rpc` — direct RPC query.
- `hellas llm` — one-shot LLM inference, local or remote.
- `hellas monitor` — local monitoring.

Other live pieces:

- Persistent iroh node identity.
- Iroh-based discovery and direct addressing.
- catgrad-text inference via `crates/executor` (the old quote → execute
  flow; not the new symbolic/opaque scheme split).
- HTTP gateway provenance headers `x-hellas-commitment-id` and
  `x-hellas-receipt-id` (the original `-id`-suffixed names; the AXES.md
  pass 3 design says these should become `x-hellas-commitment` and
  `x-hellas-receipt`, but that rename hasn't happened in the live code).
- Catgrad megatooler integration (recent commit; `crates/runtime` /
  executor consume catgrad's `ChatTurn`, `ToolDirectory`, `run_decode`).
- Hellas extension inline on protocol-native frames (recent gateway work).
- Gateway `--wrap CMD -- ARGS...` wraps a child process with the gateway
  as its OpenAI/Anthropic backend.

## Started But Not Wired Up (orphan files in this repo)

These were written as part of the original adaptor refactor but were
never integrated into the build. They DO NOT execute. Some import types
from crates that aren't dependencies of the importing crate (so they
won't even compile if wired up as-is).

- `crates/core/` — the entire crate. Newly added to workspace members
  on 2026-05-22; previously orphan. Exports `Digest`, `hash_tuple`,
  `SchemeId`, `CommitmentScheme`, `Symbolic`/`Opaque` adaptor types,
  `SignedReceipt`, `verify_delivery`, etc. (Plus the new `protocol`
  module added today — see "Active refactor" below.) **No active crate
  consumes any of this yet.**
- `crates/catnix/` — newly added to workspace members on 2026-05-22.
  Defines content-addressed catgrad artifact primitives. Designed to be
  consumed by both this repo and hellas-kernel; currently no consumer.
- `crates/cli/src/commands/opaque.rs` — `hellas opaque` subcommand
  implementation. Not declared in `commands/mod.rs`. Imports types from
  `hellas_core` which isn't a dependency of `crates/cli`.
- `crates/cli/src/commands/artifact.rs` — `hellas artifact put/get`
  subcommand. Not declared in `commands/mod.rs`. Same `hellas_core`
  import problem.
- `crates/executor/src/artifacts.rs` — Symbolic/Opaque-aware artifact
  store backed by `iroh-blobs` (memory + filesystem variants). Not
  declared in `crates/executor/src/lib.rs`. Imports `hellas_core` which
  isn't a dependency of the executor. The earlier PROGRESS.md claim that
  this is wired up was false.
- `proto/hellas/{v1,symbolic/v1,opaque/v1,courtesy/v1,swarm/v1}/*.proto`
  — modular proto tree under top-level `proto/`. **Not compiled by any
  build script.** `crates/rpc/build.rs` compiles
  `crates/rpc/proto/hellas.proto` (the OLD flat tree, package `hellas`).
- `crates/rpc/src/peers/`, `crates/cli/src/commands/serve/node_handler.rs`,
  `crates/cli/src/commands/gateway/responses.rs`, `crates/rpc/tests/`,
  `crates/rpc/src/call.rs`, `crates/rpc/src/serve.rs`,
  `crates/rpc/README.md`, `buf.yaml` — touched/added in the WIP work but
  status varies; not audited individually here.

Things that PROGRESS.md (old) claimed to exist but **don't**:

- `crates/pb` / `hellas-pb` package — **does not exist**. The user noted
  "we migrated from pb", which appears to mean the design moved away
  from a separate pb crate. Either way, the old PROGRESS.md's
  "Add generated protobuf crate at crates/pb" claim was false.
- `EvidencedScheme` trait — **does not exist anywhere**. The old
  PROGRESS.md claimed it under Phase 1.
- `--producer-key-path`, `producer-key show`, persistent
  `~/.hellas/signing-key.secp256k1` — **none of this is wired**. The
  iroh node identity is persistent; there is no separate persistent
  *producer signing key*.
- `hellas.commitment` / `hellas.receipt` HTTP headers (no `-id`
  suffix) — live headers still have the `-id` suffix.

## Active Refactor: AXES.md Pass 3 Migration

Driven by `docs/AXES.md` (the layering ADR) and `docs/ZKTLS_PROJECTION_EXAMPLE.md`
(supplementary worked example). Replaces the original Symbolic/Opaque/
Scheme/Assured/Courtesy vocabulary with ProtocolId / Adaptor / Receipt /
Binding / NonBinding / projection.

### Done in this round (2026-05-22)

- Workspace: added `crates/catnix` and `crates/core` to root
  `Cargo.toml` `members`. Excluded `crates/wire` (its
  `discovery-mdns` feature pulls a conflicting iroh dep version).
- Workspace: added `blake3`, `k256`, `serde_bytes`,
  `serde_ipld_dagcbor`, `iroh`, `catnix`, `hellas-core`, `hellas-wire`
  to `[workspace.dependencies]` (orphan crates were inheriting from
  workspace tables that didn't exist).
- `crates/core/src/protocol.rs`: `ProtocolId` (newtype with private
  field, `OPAQUE`/`SYMBOLIC`/`ZK_TLS` constants); `CallCommitment`,
  `ResultPayloadCommitment`; data types `Call`, `CallResult`,
  `CanonicalPayload`, `EvidenceBinding`, `Claim`, `Receipt`; traits
  `Adaptor`, `ProjectCall`, `ProjectResult`, `EvidencedAdaptor`;
  `ProjectionContext` (#[non_exhaustive] empty), `ProjectionError`
  with 8 variants; marker traits `Determinate`, `ProducesTlsWitness`,
  `ProducesTeeExec`, `OptimisticDisputable`. Outer domain tags
  (`hellas.call.v1`, `hellas.result.v1`, `hellas.claim.v1`) on all
  commitments. Delivery-aware sign/verify constructors:
  `Receipt::sign_delivery(call, result, evidence, key)` /
  `Receipt::verify_delivery(call, result)`. `Claim::for_delivery`
  derives both commitments from the actual call/result so they cannot
  drift from the claim's `protocol` field. Crate-root `lib.rs` does
  NOT re-export `protocol::*` to prevent silent migration footgun;
  use `hellas_core::protocol::{...}` explicitly.

### Catnix tag rule

The AXES.md per-adaptor canonical-tag rule was extended to bless
`catnix.<schema>.vN` as a valid adaptor canonical tag prefix.
Catgrad-shaped adaptors (CatgradText today, future image diffusion /
embedding adaptors) project to canonical bytes whose leading tag is
`catnix.term.v1` (the catnix `Term` outer tag); per-adaptor semantics
live in the Term's binding-key conventions, not in the outer tag. No
thin Hellas envelope wrap. See AXES.md §"Per-adaptor canonical tags".

### Next

- **Done**: hand-written CatgradText projection in
  `crates/core/src/adaptors/catgrad_text.rs` (`Adaptor + ProjectCall +
  ProjectResult` against catnix `Term`/`Value` primitives; 8 tests;
  EXPECTED_HEX wire-vector pinned per codex round 6).
- **Done**: side-by-side `CallCommitment` logging in the live quote
  path. New module `crates/executor/src/catnix_bridge.rs` builds a
  `CatgradTextRequest` from the same runtime inputs that produce
  today's `Cid<TextExecution>` and projects it via `CatgradText`.
  Both commitments now log on every quote: `commitment_id` (legacy
  `Cid<TextExecution>`), `catnix_term_id` (BLAKE3 of the projected
  Term canonical bytes), and `catnix_call_commitment`. Projection
  failure is non-fatal (warns, marks the catnix fields
  "projection_failed"). Settlement path still anchored on
  `commitment_id`. 5 new catnix-bridge tests; 28 executor tests pass.
  Placeholder ValueIds for parameters/tokenizer are BLAKE3 of the
  HF locator string (acknowledged-broken; tracks the `BoundTerm` gap
  noted below). Real digests for those come from catgrad-side
  content addressing when that lands.
- Hellas-core is now a direct dependency of hellas-executor. First
  live-binary consumer of the new protocol/adaptor surface.
- Wire completion to build a catnix `TextRunOutput` from the runtime's
  generated tokens / state, alongside the live `TextReceipt`.
- Switch the gateway provenance layer to emit catnix-shaped commitments
  as the primary `x-hellas-commitment` / `x-hellas-receipt` headers
  (renaming from the `-id`-suffixed legacy names).
- Add HF model id / prompt string / tokenizer resolution to projection
  context LAST, after the concrete-input path is fully wired.
- **Done (then redone)**: addressed the `BoundTermId` settlement gap.
  The first attempt gave `BoundTerm` four explicit fields
  (`{ program, parameters, tokenizer, dtype }`); user feedback flagged
  this as text/model-specific leakage (parameters is a hack for
  TaggedTensor hashing; tokenizer is text-domain; really, any catgrad
  Value can be input to a Program). Codex agreed (round 5 review).
  Catnix was rewritten around two primitives:
  - `Value` (marker) + `ValueId = OutputId<Value>`: the universal
    content-addressed reference for any catnix Canonical object.
  - `Term { program: ValueId, bindings: BTreeMap<BindingKey, ValueId> }`
    + `TermId = InputId<Term>`: input-addressed binding of a program
    (itself a Value) to its input Values.
  - `BindingKey::{Arg(u32), Path(Vec<String>), Named(String)}` with
    canonically-distinct schema tags for the three flavors.
  - `Canonical::value_id()` default method (BLAKE3 of canonical bytes
    → `ValueId`) on every Canonical type.
  - `InputAddressed` trait simplified: dropped `Artifact: OutputAddressed`
    bound (so `Term: InputAddressed<Artifact = Value>` works without
    requiring Value to be Canonical itself).
  - `OutputAddressed` trait deleted entirely; replaced by
    `Canonical::value_id()`.
  - `TokenIds`, `TextPolicy`, `TextState` retained as typed Canonical
    Values (each produces a `ValueId` via `value_id()`); validation
    logic (token-id non-negativity, policy stop-token sorting/dedup)
    kept.
  - `TextRunOutput { term: TermId, position, state: ValueId, generated_tokens: ValueId }`
    added — the typed Value produced by running a catgrad-text Term.
  - **Deleted**: `BoundTerm`, `Dtype`, `TextExecution`, `TextSource`,
    `SourceRef<I>`, `TextArtifact`, `TextArtifact::Identity`,
    `TextOutput`, `OutputAddressed`, plus the typed CID aliases
    (`BoundTermId`, `TextExecutionId`, `TextArtifactId`, `TokenIdsId`,
    `TextPolicyId`, `TextStateId`). Per codex: "the existing BoundTerm
    { program, parameters, tokenizer, dtype } should not survive the
    rewrite."
  - Term decoding enforces canonical key-byte ordering on bindings
    (test: `decoder_rejects_out_of_order_term_bindings`).
  - 14 tests pass; full workspace clean.

  Naming caveat documented in `catnix/src/lib.rs` module docs:
  `catnix::Term` is *not* catgrad's `Term` (a graph) nor
  hellas-kernel's `Terms` (protocol-level on-chain). Module-qualify
  in code.

  Where dtype/target/layout now live (per codex): NOT a special
  catnix concept. If dtype changes the graph/types, it lives in the
  Program Value. If it changes tensor bytes, it lives in the
  tensor/parameter Values. If it affects output semantics, it's a
  binding (e.g. `runtime_config`) or baked into the Program. The
  earlier `Dtype` newtype in catnix is gone.

- **Done**: replaced the orphan `crates/executor/src/artifacts.rs`
  with a 350-line catnix-Term/Value-aware artifact store. Old file
  was 1170 lines built on the deleted `BoundTermId`/`TextExecutionId`/
  `TextArtifactId` API and used `iroh-blobs` async. New file is:
  - `ArtifactStore` with `Memory` (in-process `HashMap`) and `Fs`
    (one file per Digest in `blobs/`, one file per TermId in
    `term_outputs/`) backends.
  - Synchronous API; atomic writes via `rename`-from-temp; BLAKE3
    verification on fs reads (returns `BlobCorrupt` rather than
    silently using corrupted bytes).
  - Typed put/get helpers: `put_canonical`, `put_value<V: Canonical>`,
    `put_term`; decoded gets for `TokenIds`, `TextPolicy`,
    `TextState`, `TextRunOutput`, `Term`.
  - `record_term_output(TermId, ValueId)` / `term_output(TermId)`
    side-table. Conflict-detected: recording a different output for
    an already-recorded Term returns `TermOutputConflict` (a producer
    must not give two different outputs for the same input-addressed
    Term under any scheme that promises replay correctness).
  - Now wired into `crates/executor/src/lib.rs` as `pub mod artifacts;`
    — no longer an orphan. `catnix` added to executor's dependencies;
    `tempfile` to dev-dependencies.
  - 5 new unit tests; full workspace `cargo check --workspace
    --all-targets` clean.

  **Not done yet**: the existing executor's Quote → Execute flow
  doesn't USE the new artifact store yet — it still operates on
  `hellas_runtime::TextReceipt` and the old quote shape. Wiring the
  new `ArtifactStore` into the live flow is part of the CatgradText
  projection migration (next chunk).
- Decompose `hellas.courtesy.v1` (when the new proto tree is wired up):
  modality-specific helpers (`Tokenize`, `DecodeTokens`) move into the
  per-adaptor packages as NonBinding; cross-adaptor helpers
  (`PutArtifact`, `GetArtifact`) move to a new `hellas.artifacts.v1`.
- Drop `CreateTicket` and `Execute.RunTicket` from the wire; per-adaptor
  Binding execution RPCs replace them.
- Reserve `/hellas.frontier.v1/1.0` ALPN; do NOT implement the frontier
  layer state machine yet — it's a sibling concern handled when alto
  consolidates in.
- Reconcile the two proto trees: point `crates/rpc/build.rs` at the
  top-level `proto/hellas/` tree once it's been updated to the new
  shape; deprecate `crates/rpc/proto/`.
- Cascade: ALPN strings derived from service FQN
  (`crates/wire/src/transport.rs:160`); hardcoded service names in
  `crates/cli/src/commands/serve/peer_tracker.rs:6`; gateway provenance
  layer (`crates/rpc/src/provenance.rs:22`) generification away from
  `Cid<TextExecution>` / `Cid<TextReceipt>` to generic
  `CallCommitment` / `ResultPayloadCommitment`.

### Catnix vs runtime artifact identity

Codex flagged that catnix `TextArtifact::Output` and runtime
`TextReceipt` commit at different layers (catnix to logical token-state
IDs; runtime to `SnapshotBundle` / tensor CIDs). The bridge requires an
explicit mapping/store for catnix artifact IDs ↔ runtime snapshots,
NOT just deleting redundant types. Safer sequence per codex: construct
runtime policy only from catnix policy at the bridge; forbid settlement
commitments from runtime policy; then delete/rename runtime policy in
a focused runtime migration. `TextPolicy` redundancy is real but
deferred until the bridge lands.

## Superseded Design

The earlier Phase 1–8 plan in this file (and chunks of `PLAN.md`)
described a Symbolic/Opaque/SchemeId/CommitmentScheme/Assured/Courtesy
factoring. AXES.md pass 3 supersedes that with ProtocolId/Adaptor/
Receipt/Binding/NonBinding/projection. The mapping:

| Old (PLAN.md / earlier PROGRESS.md) | New (AXES.md pass 3) |
|---|---|
| `Scheme` (Evaluate/Route as Rust enum) | (removed) — receipts now carry `ProtocolId`; capability gating moves to marker traits |
| `SchemeId` enum (`Symbolic`/`Opaque`/`ZkTls`) | `ProtocolId` newtype with constants (`OPAQUE`/`SYMBOLIC`/`ZK_TLS`) |
| `Symbolic` Rust adaptor type | `CatgradText: Adaptor<PROTOCOL = OPAQUE>` (today; future `SYMBOLIC` if `Determinate` is added) |
| `Opaque` Rust adaptor type | `UntypedRoute: Adaptor<PROTOCOL = OPAQUE>` |
| `CommitmentScheme` trait | `Adaptor` + `ProjectCall` + `ProjectResult` traits (split for the projection boundary) |
| `SignedReceipt` Rust type | `Receipt` (renamed to remove the clash with `Signed`/`NonBinding` axis naming) |
| `Assured` / `Courtesy` RPC pair | `Binding` / `NonBinding` (contractual semantics; not a CID-emission rule) |
| `CreateTicket` RPC, `Execute.RunTicket` | per-adaptor Binding execution RPCs; off-chain frontier messages (Request/Ticket/ResultClaimed/Accepted/Challenge) live in a separate ALPN |
| `QuotePrompt` etc. combined Quote/Ticket APIs | `Tokenize` (NonBinding helper) + caller-side Call construction + per-adaptor `CreateTicket` (if kept) |
| ZkTls as a SchemeId variant | Provenance Evidence variant on a Route adaptor (e.g. `ProtocolId::ZK_TLS` plus `ProducesTlsWitness` marker trait) |

The original PLAN.md remains useful as historical context but should
not be treated as the authoritative design now. AXES.md is.

## Deferred / Future

- **Settlement frontier layer.** Off-chain Request → Ticket →
  ResultClaimed → Accepted | Challenge state machine. Sibling ALPN
  (`/hellas.frontier.v1/1.0`); not implemented in this refactor.
- **Catgrad-text → Determinate.** Migration to deterministic execution
  (fixed sampling seed, deterministic kernels, fixed dtype/layout) so
  `CatgradText` can implement `Determinate` and claim
  `ProtocolId::SYMBOLIC`. Request-shape change, request-version bump.
- **Real Route adaptors.** vLLM, SGLang, llama.cpp, fetch — actual
  worker IPC instead of the current Opaque echo. Was "Phase 5: opaque
  worker IPC" in the old plan.
- **ZkTLS adaptor.** Worked example in `docs/ZKTLS_PROJECTION_EXAMPLE.md`;
  implementation later.
- **Correctness Evidence machinery.** Optimistic dispute, Zk proofs,
  TEE execution attestation. The marker traits and ProtocolId
  requirements are sketched; implementations are downstream.
- **Native iroh-blobs ALPN alongside tonic services.** The current
  `tonic-iroh-transport` builder owns router construction; first
  implementation uses the courtesy artifact API over existing transport.
- **Consolidation with hellas-kernel / hellas-alto.** Per the user's
  roadmap: hellas-kernel is the eventual home for the protocol-layer
  types currently in `crates/core`; hellas-kernel will fold into
  hellas-alto when the kernel is ready; then it all consolidates back
  into this repo. Duplication between this repo's `crates/core` and
  hellas-kernel is acceptable in the interim.
- **`crates/wire` workspace integration.** Currently excluded because
  its `discovery-mdns` optional feature pulls a conflicting
  `iroh-mdns-address-lookup ^0.2` against `tonic-iroh-transport ^0.9`'s
  iroh requirement. Fold back in when the iroh dep tree converges.
