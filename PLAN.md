# Node Refactor Plan: Symbolic And Opaque Work

Status: WIP implementation plan.

This plan rewrites the current quote/execute path around the commitment model
from `HYPEREDGES.md`:

- `Symbolic` is the catgrad scheme. It is the only v1 scheme with real
  correctness validity.
- `Opaque` is the trust-based engine scheme for vLLM, SGLang, llama.cpp, and
  similar engines. It is producer-signed only in v1.
- Local versus remote is producer placement, not a scheme.
- The node uses real `secp256k1` receipt signatures from the start.
- Python workers never hash, canonicalize, or sign protocol objects.

The core acceptance criterion remains:

Symbolic request construction must stay inside the Symbolic runner or courtesy
path. Adding an Opaque engine must not require constructing catgrad program
bytes, symbolic quote objects, or symbolic provenance.

## Design Decisions Baked In

1. `hellas-core` contains pure protocol primitives only.

   It must not contain async traits, worker handles, vLLM process management,
   catgrad executors, RPC clients, tonic types, or tokio dependencies. It owns
   Hellas commitments, signatures, receipt types, scheme ids, validity ids, and
   thin scheme wrappers needed by the wire protocol. Catgrad artifact identity
   comes from `catnix`, not from `hellas-core`.

2. The runtime trait is just `Runner<S>`, outside `hellas-core`.

   `S` is a `CommitmentScheme`. The type parameter carries the scheme at
   compile time. A `Runner<Symbolic>` cannot accidentally produce an Opaque
   receipt, and a `Runner<Opaque>` cannot accidentally call symbolic quote
   construction unless the implementation does so explicitly.

3. Runtime events are stream-first.

   A runner returns a stream immediately. The final event carries output, plus
   evidence only for schemes that actually have receipt evidence. A signing
   adapter turns that final event into a signed receipt. This avoids the wrong
   shape where `run().await` completes before chunks can be streamed.

4. Receipt signing is real `secp256k1`.

   No zero-signature stubs. No Falcon in v1. Keep the wire shape
   `SignatureKind`-tagged so future suites can be added, but implement only:

   - `SignatureKind::Secp256k1 = 0x00`
   - 33-byte compressed SEC1 public keys
   - 64-byte compact low-S signatures, `r || s`
   - signed message is always a 32-byte digest

5. Iroh keys are networking keys only.

   Producer identity is derived from the producer signing key:

   `ProducerId = H("hellas.producer_id.v1", signature_kind, public_key_bytes)`.

   The signing key is persistent node identity, stored separately from iroh
   transport identity.

6. Remote Opaque is part of this refactor.

   The protobuf is greenfield. We should reshape it to carry both Symbolic and
   Opaque work now, rather than preserve symbolic-only quote RPCs.

7. Opaque output is exact JSON bytes, not token ids.

   Clients should not need tokenizer vocabularies to consume Opaque results.
   Opaque engines return UTF-8 JSON bytes. For LLM text generation those bytes
   can encode:

   ```text
   { "text": "...", "finish_reason": "...", "usage": { ... } }
   ```

   For other jobs the JSON can carry whatever schema the client and provider
   agreed to. Streaming chunks are transport-only; the final receipt commits to
   the complete output bytes.

8. Opaque input is exact JSON bytes.

   There is no protocol-level sampling schema. If a caller wants to pass
   temperature, top-p, stop strings, prompt token ids, images, or tool config,
   those fields live in the Opaque input JSON. Hellas commits to the exact
   bytes; it does not interpret them.

9. No implicit defaults in commitment-bearing objects.

   CLI defaults may exist as user interface behavior, but by the time an object
   is committed every field that affects behavior must be present in canonical
   bytes. No "server default", no omitted sampling field, no implicit model
   revision.

10. Avoid invalid typestates instead of adding `Option`.

    Public protocol and runtime structs should use enum variants or typestate
    structs for `Requested`, `Ticketed`, `Running`, `Finished`, and `Failed`
    states. Do not model "finished fields that are missing until later" with
    optional fields.

## New Crate Layout

Add a new workspace member:

```text
crates/core/
  Cargo.toml
  src/
    lib.rs
    digest.rs
    commitment.rs
    signature.rs
    receipt.rs
    scheme.rs
    value.rs
    schemes/
      symbolic.rs
      opaque.rs
```

Workspace dependencies gain:

```toml
hellas-core = { path = "crates/core", default-features = false }
```

`crates/rpc`, `crates/executor`, and `crates/cli` depend on `hellas-core`.

`hellas-core` dependencies should be small:

- `blake3`
- `serde`
- a strict DAG-CBOR encoder for Hellas protocol objects
- `k256`
- `thiserror`

No `tokio`, no `tonic`, no `prost`, no `catgrad-llm`, no vLLM dependencies.

Symbolic catgrad artifact identity is provided by `catnix` in the catgrad
workspace. `catnix` owns BLAKE3/DAG-CBOR artifact CIDs for catgrad values.
Hellas consumes those CIDs as request/result commitments and then adds producer
receipts, signatures, provenance metadata, and settlement semantics.

### catnix Prerequisite Shape

Before the node refactor, the catgrad workspace should expose a small `catnix`
artifact-addressing layer. It owns canonical DAG-CBOR/BLAKE3 IDs for catgrad
runtime objects. It does not know about Hellas receipts, producer signatures,
settlement, prices, or evidence.

The key abstraction is that input-addressed recipes and output-addressed
artifacts do not share a neutral public `.id()` method:

```rust
pub trait InputAddressed {
    type Artifact: OutputAddressed;

    fn input_id(&self) -> InputId<Self>;
}

pub trait OutputAddressed {
    fn output_id(&self) -> OutputId<Self>;
}

pub struct InputId<I>(Digest);
pub struct OutputId<O>(Digest);

pub enum SourceRef<I: InputAddressed> {
    Input(InputId<I>),
    Output(OutputId<I::Artifact>),
}
```

This binds the lazy recipe to the artifact family it can produce. For text:

```rust
pub type TextSource = SourceRef<TextExecution>;

pub struct TextExecution {
    pub from: TextSource,
    pub prompt_tokens: TokenIdsId,
    pub policy: TextPolicyId,
}

impl InputAddressed for TextExecution {
    type Artifact = TextArtifact;
}

pub enum TextArtifact {
    Identity { bound_term: BoundTermId },
    Output {
        execution: TextExecutionId,
        position: u64,
        state: TextStateId,
        generated_tokens: TokenIdsId,
    },
}

impl OutputAddressed for TextArtifact {}

pub struct TextState {
    pub tokens: TokenIdsId,
}

impl OutputAddressed for TextState {}
```

Genesis is just `SourceRef::Output(identity.output_id())`. Exact continuation
uses `SourceRef::Output(previous_output.output_id())`. Lazy/substitutable
continuation uses `SourceRef::Input(previous_execution.input_id())`.

Avoid the name `Snapshot` for the generic text result. `TextArtifact` is the
family, with `TextArtifact::Output` for produced state and generated-token
artifacts. `TextState` records the materialized token stream via a `TokenIds`
artifact. Prompt and generated token lists are `TokenIds` artifacts, not
generic tensors.

## hellas-core Types

### Digest And Commitments

```rust
pub struct Digest(pub [u8; 32]);

pub struct RequestCommitment(pub Digest);
pub struct ResultCommitment(pub Digest);
pub struct ReceiptCommitment(pub Digest);
pub struct EvidenceCommitment(pub Digest); // future evidenced schemes

#[repr(u8)]
pub enum SchemeId {
    Symbolic = 0x00,
    Opaque = 0x01,
    ZkTls = 0x02,
}
```

`hash_tuple` follows `HYPEREDGES.md` exactly:

```text
magic = "hellas.hash_tuple.v1"
u32_be(tag_len)
tag_ascii_bytes
u32_be(field_count)
for each field:
  u64_be(field_len)
  field_bytes
```

Role-specific commitment newtypes wrap `Digest` directly. Do not stack
`RequestCommitment(Commitment(Digest))`; the semantic role is carried by the
newtype and by the canonical object's leading tag.

Commitments are computed by hashing exact canonical object bytes:

```text
BLAKE3(canonical_payload)
```

Scheme/role separation is carried by the canonical object's own leading tag
string, for example `hellas.opaque.request.v1` or
`hellas.receipt.body.v1`. There is no external `(scheme, role, payload)`
wrapper.

There is no CID or multihash framing in core v1.

### Domain Tags

Create `crates/core/src/tags.rs` and reference these constants from every
encoder, signer, and verifier. Do not duplicate tag strings at call sites.

```rust
pub const HASH_TUPLE_V1: &str = "hellas.hash_tuple.v1";
pub const RECEIPT_SIGNING_V1: &str = "hellas.commitment.receipt.v1";
pub const PRODUCER_ID_V1: &str = "hellas.producer_id.v1";

pub const SYMBOLIC_REQUEST_V1: &str = "hellas.symbolic.request.v1";
pub const SYMBOLIC_OUTPUT_V1: &str = "hellas.symbolic.output.v1";

pub const OPAQUE_REQUEST_V1: &str = "hellas.opaque.request.v1";
pub const OPAQUE_RESULT_V1: &str = "hellas.opaque.result.v1";

pub const RECEIPT_BODY_V1: &str = "hellas.receipt.body.v1";
pub const RECEIPT_EVIDENCED_BODY_V1: &str = "hellas.receipt.evidenced_body.v1";
```

There is deliberately no `hellas.symbolic.policy.v1` tag in core. `TextPolicy`
is a catnix artifact referenced by the `TextExecution` CID. Add such a tag only
if Hellas core takes ownership of that policy object's canonical encoding.

### Signature Types

```rust
#[repr(u8)]
pub enum SignatureKind {
    Secp256k1 = 0x00,
}

pub struct PublicKey {
    pub kind: SignatureKind,
    pub bytes: [u8; 33],
}

pub struct Signature {
    pub kind: SignatureKind,
    pub bytes: [u8; 64],
}

pub struct ProducerId(pub Digest);
```

`ProducerId` is derived only from the public signing key. It is not an iroh
node id.

Key storage:

```text
~/.hellas/signing-key.secp256k1
```

The key file stores the secp256k1 secret scalar bytes. File permissions should
reuse the existing node identity key handling pattern.

`SIGNATURE_PROPOSAL.md` remains useful for persistent signing-key lifecycle and
"pubkey travels with signature" framing. This plan deliberately removes Falcon
from v1.

### Canonical Encoding And Opaque JSON Bytes

Protocol structs are canonically encoded with the same pinned DAG-CBOR encoder
as catgrad. Pin the exact crate and version in `hellas-core` and keep catgrad's
relevant crates on the same encoder version. If these silently diverge, peers
can compute different commitments for the same typed object.

Do not introduce a generic `DagValue` for Opaque input and output in v1.
Opaque work has no deterministic replay requirement, and engine APIs naturally
use JSON numbers for values such as temperature, top-p, and logprobs. Forcing
those payloads through a no-float structural value type creates conversion code
without adding protocol validity.

Instead, Opaque payloads are exact UTF-8 JSON bytes:

```rust
pub struct JsonBytes(pub Vec<u8>);
```

Rules:

- the bytes are committed exactly as supplied;
- whitespace, key order, float spelling, and Unicode escapes are part of the
  address;
- Rust does not normalize, coerce, or float-strip these bytes;
- a local worker may reject bytes that are not valid JSON, but the commitment
  is still over the original bytes;
- Python workers parse the JSON for engine use, but never hash, canonicalize,
  or sign it.

The Opaque request commitment binds `service`, `method`, and the exact payload
JSON bytes. It is not just `BLAKE3(payload)`.

This matches the current `HYPEREDGES.md` Opaque scheme text.

### CommitmentScheme

```rust
pub trait CommitmentScheme {
    type Request;
    type Output;

    const SCHEME: SchemeId;

    fn commit_request(request: &Self::Request) -> RequestCommitment;
    fn commit_output(output: &Self::Output) -> ResultCommitment;
}

// Future extension; not a Phase 1 v1 implementation requirement.
pub trait EvidencedScheme: CommitmentScheme {
    type Evidence;

    fn commit_evidence(evidence: &Self::Evidence) -> EvidenceCommitment;
}
```

This trait is pure addressing. It does not verify correctness, run work, open
channels, or start disputes. Evidence is a second trait because not every
scheme has receipt evidence. Symbolic and Opaque do not implement
`EvidencedScheme` in producer-signed v1; the symbolic result commitment is
already the catgrad output artifact CID.

### Symbolic Scheme

The protocol-level symbolic request is CID-only. Hugging Face model names,
tokenization, dtype negotiation, and local file resolution are courtesy-layer
helpers that may derive this request, but they are not part of the binding
symbolic protocol.

Protocol-level symbolic work is the catnix text execution CID itself:

```rust
pub struct SymbolicRequest {
    pub text_execution_cid: Digest, // catnix InputId<TextExecution>
}

pub struct SymbolicOutput {
    pub text_artifact_cid: Digest, // catnix OutputId<TextArtifact>
}

pub struct Symbolic;
```

The `TextExecution` object contains the catnix `SourceRef<TextExecution>`,
prompt `TokenIdsId`, and `TextPolicyId`. Hellas does not re-encode those fields
under separate tags; otherwise the protocol would create a second request
address that diverges from catnix. The Symbolic request should not inline
megabytes of graph, token, or policy bytes. How a provider resolves CIDs into
bytes is out of scope for this protocol layer.

`hellas-core` does not define `SymbolicPolicy`, token ids, or policy encoding;
those belong to the symbolic runtime artifact layer or to courtesy APIs that
construct those artifacts.

Current Catgrad symbolic execution can use `Input` even if it is not
byte-deterministic. That means the requester allows the provider to realize or
substitute some artifact for the lazy node. If the requester wants exact
continuation, it uses `Output` to pin the realized prior artifact.
Future deterministic lowered IR does not need a different request shape; it
tightens the validity meaning of `Input` so an optimistic/zk mode can
prove that a chosen artifact realizes the lazy node.

`SymbolicOutput` is the catgrad/catnix `TextArtifact` output address.
Reserve `Receipt` for Hellas producer-signed attestations.

The symbolic runner can internally convert `SymbolicRequest` into whatever the
catgrad executor currently needs.

### Opaque Scheme

```rust
pub struct OpaqueRequest {
    pub service: String,
    pub method: String,
    pub payload: JsonBytes,
}

pub struct Opaque;
```

`Opaque::Output` is `JsonBytes`; there is no separate `OpaqueOutput` wrapper.
The producer returns exact UTF-8 JSON bytes, and the result commitment addresses
those bytes.

Executable opaque requests are closed payloads. They do not carry `SourceRef`.
If a conversation, prior result, or artifact reference matters to an opaque
service, it belongs inside `payload` by service convention. Core Hellas does
not recursively resolve opaque payload references before execution.

Courtesy/preparation APIs may accept richer opaque templates with references
and close them into executable requests:

```text
OpaqueTemplateRequest -> OpaqueRequest
```

That closure step is not part of the core opaque execution receipt. A provider
may materialize output-addressed refs into bytes if it advertises that
capability. It should reject input-addressed refs unless it explicitly
advertises scheme-aware substitution or evaluation for the referenced scheme.
Resolving a lazy recipe into a realized artifact is a trust/proof boundary, not
ordinary opaque execution.

`service` and `method` are informational producer claims and dispatch keys, not
validity boundaries. The protocol does not verify that `service` names a real
binary, Nix derivation, container, model, tokenizer, HTTP service, or runtime.
Providers and clients can still use conventions such as:

```text
service = "vllm"
method = "generate"

service = "oci:ghcr.io/vllm/vllm:v0.9.0"
method = "chat.completions"

service = "nix:github:hellas-ai/node#node-vllm-worker"
method = "generate"

service = "llamacpp:local"
method = "completion"
```

The wire accepts arbitrary UTF-8 strings. Opaque has no evidence type in v1.
The signed Opaque receipt says only: this producer claims that this
`(service, method, payload)` request produced this JSON result.

### Receipt Types

Keep the receipt separate from payload bytes.

```rust
pub struct ReceiptBody {
    pub scheme: SchemeId,
    pub request: RequestCommitment,
    pub result: ResultCommitment,
    pub producer: ProducerId,
}

pub struct SignedReceipt {
    pub body: ReceiptBody,
    pub signature: Signature,
    pub public_key: PublicKey,
}
```

Future evidenced receipt extension:

```rust
pub struct EvidencedReceiptBody {
    pub base: ReceiptBody,
    pub evidence_commitment: EvidenceCommitment,
}

pub struct SignedEvidenceReceipt<E> {
    pub body: EvidencedReceiptBody,
    pub signature: Signature,
    pub public_key: PublicKey,
    pub evidence: E,
}
```

Evidence is not forced into every receipt. Symbolic and Opaque producer-signed
v1 use the base `ReceiptBody` with no `evidence_commitment`. Future evidenced
schemes can use `EvidencedReceiptBody`, but symbolic v1 does not duplicate the
catgrad output artifact CID as receipt evidence because it is already the result
commitment. V1 does not need a scheme-specific receipt wrapper because
`ReceiptBody.scheme` already dispatches interpretation.

`receipt_commitment` is:

```text
ReceiptCommitment(BLAKE3(canonical_receipt_body_variant))
```

where `canonical_receipt_body_variant` is the canonical encoding of
`ReceiptBody` for Symbolic/Opaque producer-signed v1, or
`EvidencedReceiptBody` for future evidenced schemes.

The signature preimage is:

```text
receipt_sig_preimage =
  H("hellas.commitment.receipt.v1", canonical_receipt_body_variant)
```

The signature is witness material proving that the producer authorized the
receipt body. It travels with the receipt, but it is not inside the receipt
commitment. This matches `HYPEREDGES.md` and gives the same semantic receipt
one stable address even if signature encodings or future signature suites admit
more than one valid witness for the same body.

For future schemes with evidence, evidence bytes are not included directly in the
receipt body. `EvidencedReceiptBody` includes `evidence_commitment`, which is
the fixed-size commitment to those bytes. Symbolic and Opaque producer-signed
v1 have no evidence and therefore no `evidence_commitment`.

The body contains only commitments and identity. The output payload itself is
sent separately as final output data and can remain off-chain.

Internal constructors for all receipts should enforce the base body:

- `base.scheme == S::SCHEME`
- `base.request == S::commit_request(request)`
- `base.result == S::commit_output(output)`
- `ProducerId::from_public_key(public_key) == base.producer`
- `signature` verifies over `receipt_sig_preimage`

Future evidenced receipt constructors additionally enforce:

- `body.evidence_commitment == S::commit_evidence(evidence)`

Use constructor functions for verified receipts rather than exposing a public
struct literal API that admits inconsistent fields.

`verify_receipt(envelope)` verifies what the envelope carries by itself:
signature, producer id, scheme tag, and evidence commitment if the receipt has
evidence. It cannot recompute the request or result commitments without
external request/output witnesses. Use `verify_delivery(request, output,
envelope)` when those witnesses are available.

## Runtime Traits Outside hellas-core

Create a module in `crates/executor`, for example:

```text
crates/executor/src/work/
  mod.rs
  runner.rs
  signing.rs
```

The runtime trait can be:

```rust
pub trait Runner<S: CommitmentScheme>: Send + Sync {
    type Finished;

    fn stream(
        &self,
        request: S::Request,
    ) -> BoxStream<'static, Result<Event<Self::Finished>, RunError>>;
}

pub enum Event<F> {
    Chunk(Chunk),
    Finished(F),
    Failed(Failure),
}

pub struct Chunk {
    pub position: u64,
    pub bytes: Vec<u8>,
}

pub struct SymbolicFinished {
    pub output: SymbolicOutput,
}

pub struct OpaqueFinished {
    pub output: JsonBytes,
}

pub struct SignedSymbolicFinished {
    pub output: SymbolicOutput,
    pub receipt: SignedReceipt,
}

pub struct SignedOpaqueFinished {
    pub output: JsonBytes,
    pub receipt: SignedReceipt,
}

pub struct Failure {
    pub position: u64,
    pub error: String,
}
```

`Failure` is a runtime/RPC type, not a `hellas-core` protocol primitive.

Then wrap runners with a signing adapter:

```rust
pub struct SigningRunner<R, K> {
    inner: R,
    signer: K,
}
```

`SigningRunner<Runner<S>>` maps:

```text
Chunk             -> Chunk
Failed            -> Failed
SymbolicFinished  -> SignedSymbolicFinished
OpaqueFinished    -> SignedOpaqueFinished
```

This gives the type system two useful boundaries:

- concrete runners are scheme-specific
- public terminal success is signed by construction

The exact names can be adjusted during implementation, but avoid
`SchemeRunner` and `SchemeEvent`. In module context, `Runner<S>` and `Event`
are enough.

Runner implementations may use `mpsc` internally if that is simpler. Keep the
public trait stream-shaped because it matches the existing CLI/RPC flow,
represents cancellation as stream drop, and adapts directly to remote tonic
streams. The allocation and dynamic dispatch from `BoxStream` are not material
next to model execution.

## RPC Reshape

Mechanical layout first:

- source protobuf files live at `proto/hellas`
- generated Rust lives in `crates/pb`
- the Rust package is named `hellas-pb`, so code imports it as `hellas_pb`
- crates that consume generated types import `hellas_pb::pb` directly; `rpc`
  does not re-export the generated module
- proto files should split by functional boundary over time; feature groups in
  `crates/pb` are the intended crate-level switchboard

This layout move is schema-preserving. The protocol reshape below is a separate
step.

The old RPC shape was symbolic-only and used a server-issued session id:

```text
quote symbolic work -> server ticket id
execute server ticket id -> stream execution events
```

Replace it with scheme-specific ticket creation and a generic execution stream:

```protobuf
service Execute {
  rpc RunTicket(RunTicketRequest) returns (stream WorkEvent);
}

service Symbolic {
  rpc CreateTicket(SymbolicRequest) returns (hellas.v1.Ticket);
}

service Opaque {
  rpc CreateTicket(OpaqueRequest) returns (hellas.v1.Ticket);
}
```

Non-core helpers stay out of the execution service:

```protobuf
service Courtesy {
  rpc QuotePreparedText(QuotePreparedTextRequest) returns (QuotePreparedTextResponse);
  rpc QuotePrompt(QuotePromptRequest) returns (QuotePromptResponse);
  rpc QuoteChatPrompt(QuoteChatPromptRequest) returns (QuoteChatPromptResponse);
  rpc ListModels(ListModelsRequest) returns (ListModelsResponse);
  rpc DecodeTokens(DecodeTokensRequest) returns (stream DecodeTokensResponse);
  rpc GetStats(GetStatsRequest) returns (GetStatsResponse);
  rpc GetModelStats(GetModelStatsRequest) returns (GetModelStatsResponse);
}
```

Symbolic and Opaque requests are not wrapped in a universal work oneof. Each
scheme owns its own `CreateTicket` request shape; `Execute` only
knows how to run a ticket by commitment.

Current protocol shape:

```protobuf
message Ticket {
  bytes request_commitment = 1;  // exactly 32 bytes
  uint64 amount = 2;
  uint64 ttl_ms = 3;
}

message RunTicketRequest {
  bytes request_commitment = 1;  // exactly 32 bytes
}

message SymbolicRequest {
  bytes text_execution_cid = 1;  // exactly 32 bytes
}

message OpaqueRequest {
  string service = 1;
  string method = 2;
  bytes payload = 3;  // exact UTF-8 JSON bytes
}
```

This keeps the existing two-step reservation shape while removing the
server-issued session id. The content-addressed request commitment is the run
identifier. Providers may use the same commitment for in-flight coalescing and
receipt/output cache lookup.

Tickets are strictly RPC boundary state. `Runner<S>` never sees `Ticket`,
`amount`, `ttl_ms`, or `RunTicketRequest`; it only receives `S::Request`.
Local execution paths should not perform a mock ticket ceremony.

`request_commitment` addresses work, not a unique run session. Provider v1
semantics:

- if the request is already running, a second `RunTicket` for the same
  `request_commitment` should attach to the existing in-flight work stream;
- if the request completed and the provider still has the output/receipt, it
  may replay the cached terminal result;
- if the provider has no in-flight or cached entry, it may reject the run or
  execute it as a cache miss.

This is the intended payoff of input addressing. For Opaque work, re-executing
the same request could produce a different result, so providers should prefer
attach/replay semantics while the ticket/cache entry is live.

The server may stream chunks. Chunks are transport-only; clients that do not
want them can ignore them. Do not put batching policy into the protocol in v1.

If we later need separate reservations for the same request with different
prices or expiry terms, introduce a signed `TicketBody` with its own
`ticket_commitment`. Do not reintroduce opaque string ids.

### WorkEvent

```protobuf
message WorkEvent {
  oneof kind {
    WorkChunk chunk = 1;
    WorkFinished finished = 2;
    WorkFailed failed = 3;
  }
}

message WorkChunk {
  uint64 position = 1;
  bytes bytes = 2;
}

message WorkFinished {
  bytes output = 1;  // symbolic result bytes or exact opaque JSON bytes
  SignedReceipt receipt = 2;
  FinishStatus status = 3;
}

message WorkFailed {
  uint64 position = 1;
  string error = 2;
}

enum FinishStatus {
  FINISH_STATUS_UNSPECIFIED = 0;
  END_OF_SEQUENCE = 1;
  MAX_OUTPUT = 2;
}
```

Chunks are not settlement-relevant. They are a UX and transport convenience.
The terminal `WorkFinished.output` is the complete output object that the
receipt commits to.

Cancellation is a failed terminal state if it is surfaced at all:

```text
WorkFailed { position, error: "cancelled" }
```

If a client drops the stream, there may be no terminal event delivered to that
client. The provider should cancel local work and avoid signing a successful
receipt for an incomplete output.

### SignedReceipt

```protobuf
message ReceiptBody {
  uint32 scheme = 1;
  bytes request = 2;
  bytes result = 3;
  bytes producer = 4;
}

message SignatureWitness {
  uint32 kind = 1;
  bytes public_key = 2;
  bytes signature = 3;
}

message SignedReceipt {
  ReceiptBody body = 1;
  SignatureWitness signature = 2;
}

```

Invalid wire states are rejected at decode/validation boundaries:

- missing `WorkEvent.kind`
- digest fields with lengths other than 32 bytes
- `SymbolicRequest.text_execution_cid` with length other than 32 bytes
- secp256k1 public keys with lengths other than 33 bytes
- secp256k1 signatures with lengths other than 64 bytes

Protobuf `oneof` fields are explicit typestate variants. Avoid protobuf
`optional` in this path.

### Convenience RPCs

`QuotePreparedText`, `QuotePrompt`, and `QuoteChatPrompt` are courtesy APIs.
They may resolve model files, tokenize text, construct catgrad artifacts, and
return the derived CID-only `SymbolicRequest` plus `Ticket`. They are not core
protocol validity APIs, and providers are not obliged to serve them.

## Local Runtime Shape

### Symbolic Local

Add:

```text
crates/executor/src/symbolic/
  mod.rs
  runner.rs
```

`SymbolicRunner` owns or wraps the current `ExecutorHandle`.

`SymbolicRunner` implements:

```rust
impl Runner<Symbolic> for SymbolicRunner
```

Inside this implementation only:

- convert `SymbolicRequest` into the current executor request
- construct any catgrad execution/preflight objects
- call the existing catgrad executor actor
- stream token chunks as `Event::Chunk`
- collect the final catgrad output artifact CID
- produce a `SymbolicOutput` whose result commitment matches that final
  symbolic artifact

This is where symbolic execution construction belongs. Courtesy quote APIs may
derive a `SymbolicRequest`, but the universal run path must not eagerly build
symbolic/catgrad data.

Acceptance:

```text
rg "build_quote_request" crates/cli crates/executor crates/rpc
```

must show no live protocol path using the old quote vocabulary. There should be
no universal request constructor that eagerly builds symbolic data.

### Opaque Local

Add:

```text
crates/executor/src/opaque/
  mod.rs
  runner.rs
  worker.rs
  protocol.rs
```

`OpaqueRunner` implements:

```rust
impl Runner<Opaque> for OpaqueRunner
```

It sends `OpaqueRequest.payload` to the configured `(service, method)` adapter
and expects final UTF-8 JSON bytes as the Opaque result.

For vLLM:

- the Python worker is a process adapter, not a protocol participant
- JSONL is fine as worker IPC
- worker IPC is not canonical and not consensus-significant
- Rust treats worker output as exact JSON bytes for commitment and display
- Rust computes request/result/evidence commitments
- Rust signs the receipt

Feature split:

- `hellas-core` always has `Opaque` types
- RPC can always carry Opaque work
- local vLLM support is behind an executor feature such as `opaque-vllm`
- a default execute build can include only `SymbolicRunner`

Unsupported local engine behavior:

```text
--scheme opaque --service vllm --method generate
```

on a binary without `opaque-vllm` should fail early with a clear
"opaque service support not compiled in" error.

Remote Opaque can still work from a light client because it only needs the
wire types, not local vLLM libraries.

## CLI Shape

Current mental model:

```text
--backend catgrad|vllm|remote
```

New model:

```text
--scheme symbolic|opaque
--producer self|peer
--service <label>
--method <name>
```

User-facing aliases:

```text
node llm                         # symbolic, self if local executor exists; otherwise peer discovery
node llm --local                  # symbolic, self
node llm --scheme symbolic        # symbolic
node llm --scheme opaque --service vllm --method generate
node llm --scheme opaque --service vllm --method generate --remote
node llm --remote                 # peer producer, scheme negotiated or default symbolic
```

Implementation types should avoid `Option` where possible:

```rust
pub enum SchemeChoice {
    Symbolic,
    Opaque { service: String, method: String },
}

pub enum ProducerChoice {
    SelfNode,
    PeerDirect(RemoteNodeTarget),
    PeerDiscovery { retries: usize },
}

pub enum RunPlan {
    Single {
        scheme: SchemeChoice,
        producer: ProducerChoice,
    },
    Compare {
        primary: PlannedLeg,
        shadow: PlannedLeg,
    },
}

pub struct PlannedLeg {
    pub scheme: SchemeChoice,
    pub producer: ProducerChoice,
}
```

Cross-scheme compare is smoke-only. It can show two outputs, but it must not
claim protocol-level verification.

Protocol validity:

- `SymbolicOptimisticZk` is meaningful only for symbolic catgrad work.
- `OpaqueProducerSigned` means "this producer signed this output for this
  request." It does not mean the output is correct, reproducible, or
  challengeable on-chain.

## Gateway Headers

Gateway metadata exposes the pre-flight commitment and the terminal signed
receipt artifact.

For v1, use these HTTP headers:

```text
x-hellas-commitment: <hex pre-flight commitment>
x-hellas-receipt: <base64url(dag-cbor SignedReceipt)>
```

SSE clients cannot read response headers, so emit terminal in-band events:

```text
event: hellas-receipt
data: {"receipt":"<base64url dag-cbor SignedReceipt>"}
```

Do not expose opaque engine internals as verified facts in headers.

## Phases

### Phase 1: hellas-core

Add `crates/core`.

Implement:

- `Digest`
- `hash_tuple`
- `tags.rs` with central domain-tag constants
- `SchemeId`
- `SignatureKind`
- `PublicKey`
- `Signature`
- `ProducerId`
- secp256k1 signing and verification
- `JsonBytes`
- canonical DAG-CBOR encode/decode helpers
- `CommitmentScheme`
- `Symbolic`
- `Opaque`
- `SourceRef`
- `RequestCommitment`
- `ResultCommitment`
- `ReceiptCommitment`
- `SymbolicRequest`
- `SymbolicOutput`
- `OpaqueRequest`
- `ReceiptBody`
- `SignedReceipt`
- `verify_receipt(receipt: &SignedReceipt) -> Result<(), VerifyError>`
- `verify_delivery(request, output, receipt) -> Result<(), VerifyError>`

Do not implement `EvidencedScheme`, `EvidenceCommitment`,
`EvidencedReceiptBody`, or `SignedEvidenceReceipt` in Phase 1 unless a real v1
evidenced scheme lands at the same time. Keep those as protocol extension
shapes, not unused code.

Tests:

- same payload, same commitment
- changed scheme, changed commitment
- changed canonical object tag, changed commitment
- secp256k1 sign/verify round trip
- invalid signature fails
- public-key-derived `ProducerId` is stable
- Opaque JSON bytes commit exactly, including whitespace and float spelling
- receipt constructors reject mismatched request/result commitments
- `verify_receipt` rejects bad signatures and wrong producer ids
- `verify_delivery` also rejects envelopes whose request or result commitment
  does not match the supplied request/output witness

### Phase 2: Proto And Execution Reshape

Replace the symbolic-only quote protocol with work/ticket/run:

- move source proto files to `proto/hellas`
- generate Rust into `crates/pb`
- update imports to consume `hellas_pb::pb` directly rather than `rpc`
  re-exports
- `Symbolic.CreateTicket`
- `Opaque.CreateTicket`
- `RunTicket`
- `SymbolicRequest`
- `OpaqueRequest`
- `Ticket`
- `RunTicketRequest`
- `WorkEvent`
- `SignedReceipt`
- courtesy quote/tokenizer/model/stat APIs as explicitly non-core helpers

Remove:

- symbolic quote request/response types as core execution protocol objects
- server-issued session ids on the execution path
- catgrad text receipt cid as the only terminal identity

The generated protobuf should be treated as greenfield. No migration shims are
needed. This phase and the current execution refactor land together as one
large PR because removing the old symbolic-only proto without changing the code
that uses it will not compile.

Tests:

- Symbolic request encodes, decodes, and hashes to the same request commitment.
- Opaque request encodes, decodes, and hashes to the same request commitment.
- `RunTicketRequest.request_commitment` rejects non-32-byte values.
- terminal `WorkFinished` must contain a signed receipt.

### Phase 3: Refactor Current Symbolic Execution

This is the second half of the same PR as Phase 2. It is separated here only so
the work is readable.

Replace `ExecutionRequest`'s eager symbolic request field with a typed planned
work object.

Old bad shape:

```rust
pub struct ExecutionRequest {
    runtime: ExecutionRuntime,
    symbolic_request: SymbolicOnlyRequest,
    strategy: ExecutionStrategy,
}
```

New shape:

```rust
pub struct WorkRequestPlan {
    runtime: ExecutionRuntime,
    request: PlannedRequest,
    run_plan: RunPlan,
}

pub enum PlannedRequest {
    Symbolic(SymbolicRequest),
    Opaque(OpaqueRequest),
}
```

If the CLI starts from `PreparedPrompt`, conversion to `SymbolicRequest` happens
only when the selected scheme is Symbolic.

`ModelAssets::build_quote_request` should be replaced or wrapped by:

```rust
ModelAssets::build_symbolic_request(...)
```

Better names for the old execution-planning types:

- symbolic work payload -> `SymbolicRequest`
- ticket response -> `Ticket`
- old session id -> `request_commitment`
- `PreparedRoute` -> avoid this layer if possible; otherwise `PreparedRun`
- `ExecutionRoute` -> `ProducerChoice`
- `ExecutionStrategy` -> `RunPlan`
- `ExecutionRuntime` -> `NodeRuntime`

Acceptance:

- existing local symbolic text generation works
- existing remote symbolic text generation works through the new proto
- `--local` still works as a compatibility alias
- `--verify-local` still works for symbolic/symbolic
- no Opaque code path constructs catgrad program bytes
- no universal constructor builds Symbolic request data before scheme dispatch

### Phase 4: Real Signing In The Runtime

Add a persistent producer signer to node startup.

Producer key UX:

- generate the key eagerly when `node serve` starts, so a misconfigured key path
  fails before accepting work;
- default path: `~/.hellas/signing-key.secp256k1`;
- add `--producer-key-path <path>` for tests and multi-node-on-one-host setups;
- write new keys atomically with tmp-file plus rename;
- set file mode `0600`;
- add a small inspection command such as `node producer-key show` that prints
  the public key and derived `ProducerId`, never the secret key.

Runtime object:

```rust
pub struct NodeRuntime {
    pub producer_key: ProducerKey,
    pub local_symbolic: LocalSymbolicRuntime,
    pub local_opaque: LocalOpaqueRuntime,
    pub remote: RemoteRuntime,
}
```

Use enum variants rather than optional fields where feature-gating allows it:

```rust
pub enum LocalOpaqueRuntime {
    Disabled,
    Vllm(Arc<VllmWorker>),
}

pub enum LocalSymbolicRuntime {
    Disabled,
    Executor(ExecutorHandle),
}
```

The signing adapter assembles receipts:

```text
request commitment = S::commit_request(request)
result commitment = S::commit_output(output)
body = ReceiptBody {
  scheme,
  request: request_commitment,
  result: result_commitment,
  producer,
}
signature = sign(H("hellas.commitment.receipt.v1", canonical_receipt_body))
receipt = SignedReceipt { body, public_key, signature }
```

For future evidenced schemes:

```text
evidence_commitment = S::commit_evidence(evidence)
body = EvidencedReceiptBody {
  base: ReceiptBody { scheme, request, result, producer },
  evidence_commitment,
}
signature = sign(H("hellas.commitment.receipt.v1", canonical_evidenced_body))
receipt = SignedEvidenceReceipt { body, public_key, signature, evidence }
```

Symbolic producer-signed v1 does not use this path. Its catgrad output artifact
CID is the result commitment inside the base receipt body.

`hellas.commitment.receipt.v1` must be imported from the same central domain-tag
table as `HYPEREDGES.md`; do not duplicate the string at call sites.

Python workers never see the producer key.

Tests:

- terminal success from local symbolic includes a valid Symbolic receipt
- terminal success from local opaque includes a valid Opaque receipt
- tampering output after signing causes receipt verification failure
- tampering evidence after signing causes receipt verification failure

### Phase 5: Opaque Worker And Local vLLM Extension

Add a Python worker under:

```text
python/node_opaque_worker/
```

Worker IPC can be JSONL because it is not canonical protocol wire.

Minimum messages:

```text
{"type":"load","service":"vllm","config":{...}}
{"type":"call","id":"...","method":"generate","payload":{...}}
{"type":"chunk","id":"...","position":1,"bytes":"..."}
{"type":"finished","id":"...","result":{...}}
{"type":"failed","id":"...","error":"..."}
{"type":"cancel","id":"..."}
```

Rust responsibilities:

- when Rust constructs an `OpaqueRequest.payload` from CLI flags rather than
  receiving raw JSON bytes, use one deterministic JSON encoder configuration
  everywhere, with sorted keys and no whitespace;
- receive worker output JSON bytes
- validate only enough to display or pass through to clients
- compute commitments
- sign receipt
- surface worker failure as `Event::Failed`
- drop-cancel sends cancel to the worker

Acceptance:

- `node llm --scheme opaque --service vllm --method generate -p "hello"`
  produces final JSON output bytes
- output text can be displayed by the CLI
- terminal event includes `SignedReceipt` whose body scheme is Opaque
- worker death becomes a stream error or failed terminal event, not a panic
- no Python code imports or implements Hellas crypto

### Phase 6: Remote Opaque

Remote Opaque is required by the refactor.

Client side:

- build `OpaqueRequest`
- send `CreateTicket`
- run by `request_commitment`
- receive chunks
- receive `WorkFinished` with `SignedReceipt`
- verify producer signature locally

Provider side:

- reject Opaque if no local adapter supports `(service, method)`
- otherwise run `Runner<Opaque>`
- sign `SignedReceipt`
- return final output JSON bytes and receipt

There is no protocol correctness claim beyond the producer signature.

Tests:

- a client without local vLLM can send Opaque work to a remote provider
- a provider without Opaque support rejects Opaque tickets clearly
- a remote Opaque receipt verifies against the provider public key

### Phase 7: CLI And Gateway Cleanup

CLI:

- replace backend language with scheme and producer language internally
- keep old aliases only where useful
- remove any code path where `remote` is a pseudo-backend

Gateway:

- surface signed receipts
- expose gateway metadata as `hellas.commitment` plus `hellas.receipt`
- `hellas.receipt` is the signed receipt DAG-CBOR bytes, not a
  catgrad text receipt CID
- do not add scheme-specific receipt projections to the generic gateway shape

Verify:

- symbolic/symbolic can compare result commitments and symbolic evidence
- symbolic/opaque and opaque/opaque are smoke tests unless explicitly wired to
  an external user-side comparator
- no cross-scheme smoke test should be described as protocol verification

## Feature Flags

Suggested features:

```toml
[features]
default = ["symbolic", "opaque-wire"]
symbolic = []
opaque-wire = []
opaque-vllm = ["opaque-wire"]
```

Meaning:

- `symbolic`: local catgrad execution support
- `opaque-wire`: parse, build, send, and receive Opaque requests and receipts
- `opaque-vllm`: local vLLM worker support

RPC and `hellas-core` know about Opaque ids and signed receipts by default
because remote Opaque is part of the refactor. Heavy engine code is never a
core dependency. A default binary can therefore understand and forward Opaque
wire objects while still having no local Opaque backend compiled in.

## Invariants To Preserve

1. `hellas-core` is protocol-only.
2. Opaque engines are extensions, not protocol validity machinery.
3. Remote is producer placement, not a scheme.
4. All terminal successes have signed receipts.
5. All receipt signatures are real secp256k1 in v1.
6. Python never signs or canonicalizes.
7. Streaming chunks are not settlement-relevant.
8. Final output is the object being committed.
9. No implicit defaults in committed payloads.
10. Opaque work has no challenge path in v1.

## Practical Search Checks

After implementation:

```text
rg "GetQuoteRequest|GetQuoteResponse|quote_id" crates
```

Expected: no matches outside deleted compatibility comments during the
transition branch.

```text
rg "build_symbolic_request" crates
```

Expected: symbolic runner and symbolic CLI construction only.

```text
rg "secp256k1|SignatureKind|ProducerId" crates/core crates/cli crates/executor crates/rpc
```

Expected: core signature implementation, key loading, receipt assembly, receipt
verification.

```text
rg "vllm|llamacpp|sglang" crates/core
```

Expected: no engine implementation references. At most test labels or comments.

## Deferred

These are deliberately not part of the node refactor:

- optimistic dispute implementation
- aggregate L1 settlement proofs
- TEE attestation modes
- Falcon or other post-quantum signatures
- protocol-level output data availability
- permissionless third-party challengers
- sampling parameter schema
- service/method registry enforcement
- migration compatibility with the current quote proto

## First Implementation Step

Start with `crates/core`.

Do not touch vLLM first. The vLLM worker becomes straightforward only after the
following are real:

- `OpaqueRequest`
- `JsonBytes` as `Opaque::Output`
- `CommitmentScheme for Opaque`
- secp256k1 producer signing
- `SignedReceipt` for Opaque

Once those compile and have tests, refactor Symbolic around the same machinery.
That will expose the precise places where old quote/catgrad construction still
leaks out of the Symbolic path.
