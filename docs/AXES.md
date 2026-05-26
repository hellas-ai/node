# Hellas Protocol Layering

A pinned reference for how the customer-facing wire layer relates to the
kernel-level settlement protocol via typed projection. The doc to point
at when terminology drifts.

Status: ADR (pass 3 — supersedes earlier "five axes" framing). Pins the
two-layer model, the projection boundary between them, the marker-trait
capability model, and the naming we landed on.

## Two layers, joined by projection

The protocol has two layers with a clean boundary:

```text
Wire layer (per-adaptor)            Kernel/settlement layer (universal)
─────────────────────────           ──────────────────────────────────
Fetch.Get(GetRequest)               Call         (input-addressed bytes
ZkTls.Fetch(ZkTlsFetchCall)                       + ProtocolId)
CatgradText.Execute(CatgradReq)     CallResult   (output bytes)
CatgradText.Tokenize(prompt)        Claim        (producer asserts a
Fetch.Probe(target)                               Call → CallResult relation
                                                  under a ProtocolId)
                                    Receipt      (signed Claim)
                                    Evidence     (proof attached to Claim)
                                    Frontier     (channel-state messages:
                                                  Request, Ticket,
                                                  ResultClaimed, ...)

         ╲                                ╱
          ╲     Projection (typed)      ╱
           ╲     ProjectCall :: Req → Result<Call, _>
            ╲    ProjectResult :: Reply → Result<CallResult, _>
             ╲                          ╱
```

Two rules:

- **Wire types are designed for callers.** Each adaptor exposes the RPCs
  that make sense for its domain. Fetch has `Get(url, headers)`. ZkTLS
  has whatever an actual ZkTLS interaction looks like. CatgradText has
  `Execute` and `Tokenize`. No "Execute(Bytes)" prison.
- **The kernel sees only the projected protocol objects.** Settlement,
  signing, evidence verification, and the off-chain channel-state
  machine all operate on `Call`, `CallResult`, `Claim`, `Receipt`,
  `Evidence`. They never inspect adaptor-specific wire types.

The two layers meet through *projection*: each adaptor implements
`ProjectCall` (and result-side equivalents). Both sides of an interaction
agree on the projection in advance; neither needs to trust the other's
implementation of it because both compute the same `Call` from the same
canonical wire bytes.

## Universal property (still): input-addressing

Every Hellas request has identity computed from its inputs *before*
execution:

```text
request_id = hash(transformation_repr, inputs_repr)
```

This is the Nix property — what makes a Hellas request a Hellas request
in the first place. Both wire types (their canonical bytes) and
projected `Call`s (after projection) are input-addressed. Not a
"dimension"; the foundation.

## What lives at each layer

### Wire layer (per-adaptor)

A single proto package per adaptor. Free design.

```proto
// Customer API — idiomatic to the domain. No protocol-aware shape forced.
package hellas.fetch.v1;
service Fetch {
  rpc Get(GetRequest)   returns (stream GetEvent);   // Binding: settles
  rpc Probe(ProbeRequest) returns (ProbeReply);      // NonBinding: helper
}
```

Each adaptor crate provides hand-written projection from its wire types
to the kernel-level protocol objects. The projection is the contract; it
is testable with canonical-vector tests and versioned independently.

### Kernel/settlement layer (universal)

A small set of types the kernel knows about:

```rust
pub enum ProtocolId {
    Opaque,     // bytes-in, bytes-out; producer signature only
    Symbolic,   // input-addressed recipe; admits Correctness Evidence iff Determinate
    ZkTls,     // routed-with-TLS-witness; bytes-in, bytes-out, +TLS proof
    // ... small, kernel-known, slow-growing
}

pub struct Call {
    pub protocol: ProtocolId,
    pub payload: Vec<u8>,      // canonical adaptor-encoded bytes
}

pub struct CallResult {
    pub payload: Vec<u8>,      // canonical adaptor-encoded bytes
}

pub struct Claim {
    pub protocol: ProtocolId,
    pub call_commitment: CallCommitment,        // = blake3(Call canonical bytes)
    pub result_commitment: ResultPayloadCommitment,    // = blake3(CallResult canonical bytes)
    pub producer: ProducerId,
    pub evidence_commitment: Option<EvidenceCommitment>,  // present iff evidence is required
}

pub struct Receipt {
    pub claim: Claim,
    pub signature: ProducerSignature,
}
```

The kernel knows nothing about adaptors. It sees `ProtocolId`, signed
claims over `(call, result, producer, evidence)`, and applies the
protocol's validity gadget. Adaptors are implementation detail outside
the trust boundary.

Note the rename: today's Rust `SignedReceipt` becomes `Receipt`; the
proto wrapper `ReceiptEnvelope` is unchanged. Today's `SchemeId` enum is
gone — `ProtocolId` replaces it with proper protocol-level identity, not
a two-value capability tag.

## Adaptors are implementation-level

An *adaptor* is a Rust type plus per-adaptor proto package that:

- declares its `ProtocolId` (which kernel protocol it produces receipts
  for);
- owns typed Request / Output wire types;
- implements `ProjectCall` and `ProjectResult` (the boundary contract);
- optionally implements *marker traits* declaring its capabilities;
- offers helper RPCs (`Tokenize`, `Probe`, `Decode`, ...) on the wire as
  it sees fit.

```rust
pub trait Adaptor {
    const PROTOCOL: ProtocolId;
    type Request;
    type Output;
}

pub trait ProjectCall: Adaptor {
    fn project_call(req: &Self::Request, ctx: &ProjectionContext)
        -> Result<Call, ProjectionError>;
}

pub trait ProjectResult: Adaptor {
    fn project_result(out: &Self::Output, call: &Call)
        -> Result<CallResult, ProjectionError>;
}
```

Multiple adaptors may implement the same `ProtocolId` (e.g. a `vllm` and
a `llama_cpp` adaptor both claim `ProtocolId::Opaque`). Their receipts
are *indistinguishable at the kernel level*; the only difference is the
customer-facing wire API.

## Capability marker traits

What kinds of evidence an adaptor can produce is expressed by which
marker traits it implements. The marker traits live in `crates/core`
alongside `Adaptor`.

```rust
/// Adaptor's output is uniquely determined by its Call. Required for any
/// Correctness Evidence (Optimistic, Zk, TEE-execution).
pub trait Determinate: Adaptor {}

/// Adaptor can produce a TLS-witness proof binding the result bytes to a
/// specific server-identity policy.
pub trait ProducesTlsWitness: Adaptor {
    type TlsWitness;
}

/// Adaptor runs inside a TEE and can produce an execution attestation.
pub trait ProducesTeeExec: Adaptor {
    type TeeQuote;
}

/// Adaptor accepts an Optimistic-dispute window.
pub trait OptimisticDisputable: Determinate {}
```

Each `ProtocolId` has a static rule for which marker traits an Adaptor
must implement to claim it. The protocol authority enforces this at
build time:

| ProtocolId | Required adaptor capabilities |
|---|---|
| `Opaque` | (none; Adaptor only) |
| `Symbolic` | `Determinate` |
| `ZkTls` | `ProducesTlsWitness` |

**Today's catgrad-text claims `ProtocolId::Opaque`.** It is not
`Determinate` (no fixed seed, no deterministic kernels, no fixed
dtype/layout in the request), so it cannot honestly claim `Symbolic`
under the marker-trait gate above. The current "symbolic" path was
always trust-only at the assurance level; the type system now reflects
that. When catgrad-text becomes Determinate, its `Adaptor::PROTOCOL`
migrates to `Symbolic` — but that's also a request-shape change (the
deterministic profile gets committed into the request bytes) and so a
versioned request type, not a no-op flip.

A separate `ProtocolId::SymbolicIndeterminate` was considered and
rejected. The on-wire "this is a structured input-addressed catgrad
recipe" signal does not belong in `ProtocolId` (which is about
*settlement validity*); it belongs in the per-adaptor canonical tag
(e.g. `hellas.catgrad_text.request.v1`), in service metadata, or in a
non-settlement marker trait like `HasStructuredRecipe`.

## Projection: the boundary contract

Projection is **fallible and context-aware**. It is not infallible
serialization.

```rust
pub struct ProjectionContext {
    pub now: SystemTime,                  // for time-policy projections
    pub tokenizer_versions: TokenizerRegistry,
    pub model_locator: ModelLocator,      // resolves "huggingface://..." → canonical id
    pub ca_bundle_digest: Digest,         // pinned CA set for TLS-bearing protocols
    pub dtype_preferences: DtypePreferences,
    // ... explicit fields per kind of ambient state
}

pub enum ProjectionError {
    AmbientDefault { field: &'static str },  // wire has "auto" / "latest"
    UnresolvedReference { kind: &'static str, id: String },
    BadCanonicalization(...),
    PolicyMissing { kind: &'static str },
    UncommittedAmbientState { kind: &'static str },
    ...
}
```

What projection guarantees, by contract:

1. **No hidden defaults.** If the wire request says "use the latest
   model" or "auto dtype" or "current time" without the *concrete*
   value, projection fails. The producer's chosen concrete must be
   echoed back to the caller in some way (as a separate response field,
   as a returned `Call::payload`, or via a `NonBinding` Probe response)
   so both sides project the same `Call`.
2. **Deterministic encoding.** Two implementations of the same adaptor
   project the same wire bytes to the same `Call::payload`. Tested with
   canonical-vector test files committed alongside the adaptor.
3. **Version-aware.** When projection changes shape, the adaptor's
   protobuf version bumps (`fetch.v2`), the projection function picks
   the right version from the wire type, and old receipts continue to
   verify against the projection rules they were created under.
4. **No silent batch.** One wire RPC projects to *one* `Call`. If a
   stateful customer interaction needs multiple kernel Calls, the
   wrapper must return them explicitly as a batch/plan. Forbidden:
   one customer RPC silently incurring N settlement obligations.

## Binding vs NonBinding

The wire layer has two kinds of RPCs:

- **Binding** — the producer's response *contractually binds* them. The
  RPC participates in the receipt-producing lifecycle. The wire reply
  carries (or terminates a stream with) bytes that project to a
  `CallResult` and a signed `Receipt` over `(Call → CallResult)`.
- **NonBinding** — the producer's response is *advisory*. No contractual
  obligation. The caller may use the response as input to a subsequent
  Binding call (e.g. take `Tokenize` output and feed it into `Execute`)
  but is responsible for any commitment that follows. The provider may
  decline; the response may be wrong; the protocol takes no position.

This pair replaces the earlier `Assured` / `Signed` and `Assured` /
`Courtesy` framings. The semantic is contractual, not cryptographic — a
NonBinding response may carry a producer signature for accountability
and may include CIDs as advice; the rule is that *acceptance into the
settlement layer requires the caller to reproject*. A provider-emitted
commitment from a NonBinding RPC is never directly accepted as
settlement-bearing.

In Rust:

```rust
pub trait BindingEndpoint {
    type Adaptor: Adaptor + ProjectCall + ProjectResult;
    type Request;
    type Reply;
    fn handle(&self, req: Self::Request) -> BindingReply<Self::Adaptor, Self::Reply>;
}

pub trait NonBindingEndpoint {
    type Request;
    type Reply;
    fn handle(&self, req: Self::Request) -> Self::Reply;
}

pub struct BindingReply<A: Adaptor + ProjectCall + ProjectResult, T> {
    pub reply: T,
    pub receipt: Receipt,
}
```

A wrapper at the boundary projects, runs the adaptor's actual handler,
projects the result, signs the receipt:

```rust
fn handle_binding<A, R, P>(req: R, ctx: &ProjectionContext, key: &ProducerKey,
                           inner: impl Fn(R) -> P) -> Result<BindingReply<A, P>, _>
where
    A: ProjectCall + ProjectResult + Adaptor<Request = R, Output = P>,
{
    let call = A::project_call(&req, ctx)?;
    let reply = inner(req);
    let result = A::project_result(&reply, &call)?;
    // sign_delivery derives Claim::call_commitment / result_commitment
    // from the actual call/result, so a producer cannot accidentally
    // sign a claim whose protocol byte disagrees with the call.
    let receipt = Receipt::sign_delivery(
        &call,
        &result,
        EvidenceBinding::None,
        key,
    )?;
    Ok(BindingReply { reply, receipt })
}
```

Per-adaptor proto annotations remain useful for documentation and lint,
but they aren't load-bearing for codegen — convention is enough:

```proto
service Fetch {
  rpc Get(GetRequest) returns (stream GetEvent) {
    option (hellas.v1.binding) = BINDING;
  };
  rpc Probe(ProbeRequest) returns (ProbeReply) {
    option (hellas.v1.binding) = NON_BINDING;
  };
}
```

## Evidence

Two orthogonal categories, both optional.

- **Provenance Evidence** — proves *where bytes came from*, not whether
  they're correct. `TlsWitness`, `TeeSource`. Available to any adaptor
  that implements the relevant marker trait (`ProducesTlsWitness`;
  future `ProducesTeeSource` when TEE provenance lands — only
  `ProducesTeeExec` is currently sketched in code).
- **Correctness Evidence** — proves the `Call → CallResult` relation
  holds. `Optimistic`, `Zk`, `TeeExecution`. Available *only when* the
  adaptor implements `Determinate`. Enforced at the type level —
  `OptimisticDisputable: Determinate`, etc.

### Detachable vs committed

Today's Rust `Receipt` signs only `(protocol, call_cid, result_cid,
producer)`. Evidence that's merely stapled to the envelope outside the
signature can be added, removed, or swapped without invalidating the
receipt.

- **Detachable** (default for diagnostic Provenance) — fine. The
  protocol takes no settlement position on its presence.
- **Committed** (required for settlement-relevant evidence) — the
  receipt body includes an `evidence_commitment: Option<Digest>`
  field, signed together with the rest. The actual evidence bytes
  travel alongside, hash to that digest. ZkTLS-bearing fetch and
  TEE-attested execution land here.

The protocol's claim layer (in hellas-kernel) consults the evidence
commitment to decide whether the receipt satisfies the channel's
agreed evidence predicate. Hellas's `ProtocolId` selects which
predicate applies.

The settlement-bearing receipt itself stays minimal —
`Receipt { claim, signature, public_key }` — and is what gets signed,
hashed, and verified. Evidence travels in an *envelope* alongside the
receipt; whether the envelope's evidence is committed-into-the-body or
detachable depends on the protocol's evidence binding.

```rust
/// What the producer signs. Hashes / signatures are computed over the
/// claim's canonical preimage (including its `evidence_commitment`
/// field where present).
pub struct Receipt {
    pub claim: Claim,
    pub signature: ProducerSignature,
    pub public_key: ProducerPublicKey,
}

/// On-the-wire bundle: a receipt plus any evidence the protocol allows
/// to ride alongside. Provenance is detachable; correctness is type-gated.
pub struct ReceiptEnvelope<A: Adaptor> {
    pub receipt: Receipt,
    pub provenance: Option<ProvenanceEvidence>,
    pub correctness: Option<CorrectnessOf<A>>,  // present only when A: EvidencedAdaptor
}
```

## Per-adaptor canonical tags

Canonical bytes that get hashed into `Call::payload` /
`CallResult::payload` carry a leading tag string identifying the
adaptor and version. The valid tag prefixes are:

```text
hellas.<adaptor>.{request,result}.vN
catnix.<schema>.vN
```

The default is `hellas.<adaptor>.request.v1` etc. — examples:

```text
hellas.fetch.request.v1
hellas.vllm.request.v1
hellas.zktls_fetch.request.v1
hellas.untyped_route.request.v1   (generic escape hatch)
```

The `catnix.*` prefix is *blessed* as a valid Hellas adaptor canonical
tag specifically for catgrad-shaped adaptors. The CatgradText adaptor's
canonical payload IS `catnix::Term::canonical_bytes()` (which starts
with `catnix.term.v1`); we don't wrap it in a thin Hellas envelope.
Rationale: catnix is the schema layer, blessed as a sub-namespace
under the Hellas adaptor tag rule, so that catgrad-shaped adaptors
share canonical bytes verifiable independent of the Hellas adaptor
identity. Future catgrad-shaped adaptors (image diffusion, embedding)
project to `catnix::Term` too — the binding-key conventions inside
the Term carry the per-adaptor semantics, not the outer tag.

Adaptor identity is in the canonical tag (whether `hellas.*` or blessed
`catnix.*`); `ProtocolId` is in the receipt. The kernel sees
`ProtocolId`; a verifier digging into a `Call` sees the adaptor tag.

## Frontier layer (separate, deferred)

The off-chain settlement-frontier state machine (`Request → Ticket →
ResultClaimed → Accepted | Challenge`) is its own concern. It runs on a
separate ALPN:

```text
/hellas.frontier.v1/1.0      ← off-chain channel-state messages
/hellas.fetch.v1/1.0          ← Fetch adaptor RPCs (Binding + NonBinding)
/hellas.catgrad_text.v1/1.0   ← CatgradText adaptor RPCs
```

The frontier layer consumes `CallCommitment` / `ResultPayloadCommitment` /
`Receipt` opaquely. It does not know about `GetRequest` or
`CatgradTextRequest`. It implements the channel state machine described
in `../whitepaper/HYPEREDGES.md` §Settlement Messages.

This refactor does not implement the frontier layer. It
reserves the ALPN, defines the protocol-level types (`Call`,
`CallResult`, `Claim`, `Receipt`, `ProtocolId`), and ensures the
adaptor projection boundary is clean enough that the frontier layer can
be added later without rewriting wire types.

Today's `CreateTicket` and `Execute.RunTicket` RPCs are the wrong shape
for this model — they bake what should be channel-state messages into
the wire-execute layer. They go away when the wire layer becomes
just per-adaptor RPCs.

## What this refactor actually does

Minimum implementation scope:

1. Rewrite this ADR (done — this file).
2. Add core types in `crates/core`: `ProtocolId`, `Call`, `CallResult`,
   `Claim`, `Receipt` (replacing `SignedReceipt`), `EvidenceCommitment`,
   `ProjectionContext`, `ProjectionError`.
3. Replace `CommitmentScheme` trait with `Adaptor` + `ProjectCall` +
   `ProjectResult` + marker traits (`Determinate`, etc.).
4. Drop `SchemeId` enum and the `Symbolic`/`Opaque` Rust types from
   `crates/core/src/schemes/`. Move to `crates/core/src/adaptors/`:
   - `catgrad_text.rs` — `CatgradText` adaptor, `PROTOCOL = Opaque`
     (downgrade from misleading "Symbolic" until Determinate; the wire
     shape is unchanged).
   - `untyped_route.rs` — `UntypedRoute` adaptor, `PROTOCOL = Opaque`.
5. Hand-write the two adaptors' `ProjectCall` / `ProjectResult` impls
   plus canonical-vector test files (`tests/projections/...`).
6. Per-adaptor proto packages: rename `hellas.symbolic.v1` →
   `hellas.catgrad_text.v1`, `hellas.opaque.v1` → `hellas.untyped_route.v1`.
   Decompose `hellas.courtesy.v1`:
   - `Tokenize` (was `QuotePrompt` minus the Ticket and SymbolicRequest
     return fields) → `hellas.catgrad_text.v1` as `NonBinding`,
     returns plaintext token IDs only.
   - `DecodeTokens` → same.
   - `Put/GetArtifact` → new `hellas.artifacts.v1`.
   - `ListModels`, `GetStats` → kept somewhere generic, `NonBinding`.
   - The existing combined Ticket+commitment Quote\* responses go away.
     A new `PrepareTicket` RPC (Binding) takes already-tokenized inputs
     and returns a `Ticket` — but Ticket itself is on its way to being
     a frontier-layer message, so this is interim.
7. Drop `CreateTicket` and `Execute.RunTicket` from the wire. Each
   adaptor that wants a Binding execution RPC defines its own (e.g.
   `CatgradText.Execute`, `Fetch.Get`). The receipt arrives at the
   stream terminus.
8. Reconcile the two proto trees — `crates/rpc/build.rs` currently
   compiles `crates/rpc/proto/hellas.proto`; point it at the top-level
   `proto/hellas/` tree and make `rerun-if-changed` recursive.
9. Add `crates/core`, `crates/wire`, `crates/catnix` to workspace
   members.
10. Update ALPN strings derived from service FQN; update
    `crates/cli/src/commands/serve/peer_tracker.rs:6` and any other
    hardcoded service names.
11. Generalize `crates/rpc/src/provenance.rs` away from
    `Cid<TextExecution>` / `Cid<TextReceipt>` to generic
    `CallCommitment` / `ResultPayloadCommitment`.
12. Docs sweep: PLAN.md, PROGRESS.md, README.md, SIGNATURE_PROPOSAL.md
    vocabulary rewrite. The "Scheme" / "Symbolic" / "Opaque" /
    "courtesy" / "assured" language goes; "ProtocolId" / "Adaptor" /
    "Binding" / "NonBinding" / "projection" replaces it.

Acceptance: `cargo fmt`, `cargo check --workspace --all-targets`,
`cargo test --workspace --lib`, `cargo test -p hellas-core` (including
the projection vector tests), `buf lint`.

## What this refactor explicitly does NOT do

- **No frontier layer implementation.** Reserve the ALPN, define the
  types it'll consume, but don't build the state machine yet.
- **No catgrad-text → Determinate migration.** Today's catgrad-text
  stays Indeterminate; this refactor reflects that honestly by claiming
  `ProtocolId::Opaque`. Migrating to Determinate is a request-shape
  change (the deterministic profile gets committed into the request
  bytes), and thus a versioned-request follow-up, not a no-op
  `PROTOCOL` flip.
- **No Optimistic / Zk / TEE evidence machinery.** The Evidence types
  are declared and the type-level gating is in place; concrete evidence
  variants land when each is actually built.
- **No real ZkTLS adaptor.** ZkTLS appears here as a worked example for
  the design; the actual implementation is later work.
- **No multi-call orchestration.** One Binding wire RPC = one kernel
  `Call`. Stateful adaptors that need multiple Calls return them as an
  explicit batch/plan; this refactor doesn't build either.

For a worked example of projection on a non-trivial adaptor (ZkTLS),
see `ZKTLS_PROJECTION_EXAMPLE.md`.

## Common failure modes

- **Treating ProtocolId as adaptor identity.** Wrong direction: many
  adaptors per `ProtocolId`. Adaptor identity lives in the canonical
  tag string inside `Call::payload`.
- **Treating `Determinate` claim as automatic.** A `Determinate` impl
  is a *claim* the adaptor author makes. It must be justified by
  fixed kernels, fixed dtypes, fixed sampling, etc. The type system
  enforces what's gated *on* `Determinate`; it can't enforce
  determinism itself.
- **Stapling settlement-required evidence without committing it.**
  Detachable evidence can be added/removed/swapped silently. If a
  `ProtocolId` requires evidence (e.g. `ZkTls`), the receipt body
  must commit to the evidence digest.
- **Emitting commitments from NonBinding then accepting them as
  settlement-bearing.** Providers may emit advisory CIDs; the rule
  is that the caller must reproject before using anything as
  settlement-bearing. Don't shortcut.
- **Smuggling multiple settlement obligations into one customer
  RPC.** One Binding wire RPC ↔ one kernel `Call`. Stateful customer
  flows that need many Calls must return them as an explicit
  batch/plan.
- **Defining a customer-facing helper that requires the provider's
  judgment** (today's `QuotePrompt` resolves "auto dtype"; tomorrow's
  `Fetch` might pick a model version). Either: the response echoes
  back the concrete chosen value, or the projection has a context
  field that pins the value, or the helper is structurally
  `NonBinding` and the caller doesn't depend on the provider's
  choice.
- **Erasing adaptor identity in canonical tags.** Never collapse to
  `hellas.opaque.request.v1`. Always `hellas.<adaptor>.request.v1`.
- **Naming a Rust type `SignedReceipt` after the rename.** Rename to
  `Receipt`. The proto wrapper `ReceiptEnvelope` stays as the
  byte-level wrapper around the dag-cbor-encoded `Receipt`.

## Related

- `../hellas-kernel/KERNEL.md` §"Adapter And Executor Layer" — the
  kernel's view of the adaptor boundary (it sees `Call / CallResult /
  Claim / Evidence`, knows about `ProtocolId`, doesn't know about
  adaptors).
- `../whitepaper/HYPEREDGES.md` §"Settlement Messages",
  §"Frontier Typestate", §"Lifecycle" — the off-chain frontier state
  machine. This refactor reserves an ALPN for this and defines
  the types it'll consume; it does not implement the state machine.
- `../whitepaper/PROTOCOLS.md` §"Canonical Protocol Objects" — the
  `Call / Claim / Receipt` shapes copied above.
- `PLAN.md` — implementation plan whose vocabulary this ADR pins.
- `PROGRESS.md` — implementation tracker.
- `SIGNATURE_PROPOSAL.md` — independent track for signature-suite
  agility; orthogonal to the layering here.

## Notes on naming history

For future-me when conversations refer to the old names:

| Old | New | Reason |
|---|---|---|
| Scheme | (gone) — capability gating moves to marker traits; receipt identity is `ProtocolId` | Scheme was a two-valued capability tag conflated with protocol identity |
| `SchemeId` enum | `ProtocolId` enum | Old name was an internal byte tag; new name names what it actually is |
| Symbolic (Rust type) | (gone as Rust type) — `CatgradText: Adaptor<PROTOCOL = Opaque>` until Determinate (`Symbolic` becomes a ProtocolId variant, claimed only when an adaptor implements `Determinate`) | Old Symbolic was Evaluate-class but Indeterminate so produced trust-only receipts; type now reflects that |
| Opaque (Rust type) | `UntypedRoute: Adaptor<PROTOCOL = Opaque>` (`Opaque` is now a ProtocolId variant, not a Rust marker type) | rename for clarity |
| Assured | Binding | contractual semantics, not cryptographic |
| Signed / Courtesy | NonBinding | rule is about settlement-acceptance, not signature presence |
| `CommitmentScheme` trait | `Adaptor` + `ProjectCall` + `ProjectResult` | split for projection boundary; renamed for clarity |
| `SignedReceipt` Rust type | `Receipt` | removes clash with the NonBinding-ish "Signed" naming we considered |
| `Quote*` RPC family | `Tokenize` (NonBinding) + caller-side Call construction | old shape conflated tokenization (Signed) with commitment (Binding); split |
| `CreateTicket` RPC | (gone) — `Ticket` becomes a frontier-layer concept, not a wire RPC | frontier messages are off-chain channel-state, not RPCs |
| `Execute.RunTicket` | per-adaptor Binding execution RPCs (`CatgradText.Execute`, `Fetch.Get`) | adaptor owns its own customer API |
