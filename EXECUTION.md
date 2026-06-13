# Execution Model Proposal

This document proposes the next execution architecture for Hellas nodes. The
goal is to separate node hosting, execution schemes, and concrete backends so
local catgrad work and remote provider calls can share the same p2p runtime
without mixing trust boundaries.

## Current State

The current node server is assembled inside the CLI:

- iroh endpoint binding;
- ALPN registration;
- service discovery advertising;
- inbound connection accept loop;
- per-ALPN dispatch;
- node introspection wiring.

Those are runtime responsibilities, not CLI responsibilities. The reusable
transport and accounting pieces already exist in `hellas-wire` and
`hellas-rpc`; the missing layer is the orchestration that hosts a set of
services on an iroh node.

The current `hellas-executor` crate also combines several concepts:

- catgrad-backed symbolic text execution;
- helper APIs for tokenization, chat templating, token decoding, model listing,
  and stats;
- the Fetch provider executor.

The Fetch path is now a real provider executor: `CreateTicket` verifies and
stores the caller-signed input transcript, `RunTicket` admits work under
caller/route/model/rate/spend policy, provider I/O runs off the actor loop, and
the producer signs a continuation-verified output transcript that is persisted
and replayed for completed tickets.

## Runtime Crate

Add a shared runtime crate:

```text
crates/runtime
  NodeRuntime
  service registration
  iroh endpoint binding
  discovery advertising
  inbound connection accept loop
  per-ALPN dispatch
  Node service / introspection
  peer accounting
```

The runtime crate should depend on `hellas-wire` and `hellas-rpc`, but not on
catgrad, OpenAI, Anthropic, or any provider client.

The runtime API should be generic over services. It should not grow
scheme-specific methods such as `with_fetch`, `with_evaluate`, or `with_run`.
Those would recouple runtime to the protocol surface.

Preferred shape:

```rust
let runtime = NodeRuntime::bind(config).await?;
runtime
    .serve(ServiceSet::new()
        .with_service(node_marker, node_dispatcher)
        .with_service(fetch_marker, fetch_dispatcher)
        .with_service(execute_marker, execute_dispatcher))
    .await?;
```

The exact type names can change, but the boundary should stay the same:
runtime hosts registered dispatchers keyed by ALPN/service markers; executor
crates provide the dispatchers.

`ServiceSet` should stay transport-generic. `NodeRuntime` is the iroh host that
binds endpoints, advertises discovery, and drives a `ServiceSet` over iroh
connections. Keeping that seam below the service set lets tests drive the same
dispatch table over an in-memory transport.

Cross-cutting behavior such as accounting, admission control, and rate limits
belongs in runtime middleware applied uniformly to registered dispatchers. A
service registration should describe intent: "serve this protocol with this
dispatcher." It should not repeat accounting wrappers at every call site.

## Executor Modules

Keep execution implementations in `hellas-executor` for now, but make the
modules and features explicit:

```text
crates/executor
  evaluate::catgrad      feature: evaluate-catgrad
  fetch::core            feature: fetch
  fetch::openai          feature: fetch-openai
```

The catgrad backend should be optional. A node that only forwards provider work
must be buildable without catgrad/candle/model dependencies.

If the feature graph becomes hard to maintain, these modules can move into
sibling crates without changing the runtime or protocol shape.

## Scheme Executor Registry

The executor should mirror the runtime registry. Runtime dispatch is keyed by
ALPN. Execution dispatch should be keyed by commitment scheme.

Do not grow central matches over `QuoteKind` or `SchemeId` as new schemes are
added. Register scheme executors instead:

```rust
trait SchemeExecutor {
    fn scheme(&self) -> SchemeId;
    async fn quote(&self, request: SchemeQuoteRequest) -> Result<SchemeQuote>;
    async fn run(&self, ticket: SchemeTicket) -> Result<SchemeEventStream>;
}
```

The exact trait shape can change, but the property should not: a catgrad-free
node is made by not registering the catgrad evaluator. Feature-gating should
remove registrations, not require conditional match arms across the actor.

Discovery should also derive advertised service availability from registered
services. A fetch-only node should not have to maintain a second hand-written
list of unavailable ALPNs.

Ticket creation is per-scheme: the inbound ALPN determines which scheme
executor quotes the work. Ticket execution is unified through `Execute`, so the
actor must look up the stored quote by input commitment, read its `SchemeId`,
and dispatch `run()` to the matching registered executor. The quote's `SchemeId`
domain-separates the stream transcript commitments.

## Trust Models

There are two different commitment models in the codebase. They must not be
conflated.

### Field-Level Canonical Execution

`hellas-wire-adaptors` parses provider wire formats into a canonical execution
request, carried alongside the raw wire body:

```text
BackendRequest {
  execution: ExecutionRequest { canonical: CanonicalExecution {
    model, input, instructions, sampling, tools, tool_choice,
    response_format, reasoning, previous_response_id,
  } },
  raw: RawRequest,   // the original wire JSON
}
```

That is a semantic, field-level model. It is useful for local catgrad execution,
normalizing HTTP providers into a shared internal request shape, rendering
responses, and writing policy that understands provider JSON.

This model is not part of Fetch settlement. Fetch commits to the raw canonical
request bytes inside the input transcript; the field-level view is parsing for
policy and rendering, never receipt material. If a future field-level Evaluate
scheme wants to commit to individual fields, that commitment set must be made
explicit at that point rather than inherited from this parsing layer.

### Streamed Fetch

Fetch commits to an input stream and an output stream:

```text
input  = attested input event transcript
output = attested output event transcript
```

There is no separate request/response execution path. A finite HTTP provider
request is represented as a finite input stream: begin request, request body,
end input. A caller that wants a collected response consumes the output stream
and folds it locally.

This is intentional:

- the provider-facing input is part of the attested input transcript;
- the output observed from the provider is part of the attested output
  transcript;
- no claim is made that the output is independently reproducible.

Fetch executors may parse input events for validation and policy. Parsing for
policy does not change the settlement object. Policy reads events from the input
transcript; settlement signs transcript events.

Commitments must remain domain-separated by scheme and tag. That makes a shared
ticket store keyed by input commitment safe across Fetch and Evaluate: the same
input transcript under different schemes cannot collide unless the underlying
hash is broken.

For Fetch, the parser output should be a policy view, not a canonical execution
object:

```text
FetchPolicyView {
  service,
  method,
  model,
  output_limit,
  input_size,
  unsupported_features,
}
```

The policy view is read-only validation state. It does not contain committed
fields, passthrough fields, or receipt material.

## Fetch Scheme

The semantic Fetch service has this shape:

```protobuf
service Fetch {
  rpc CreateTicket(FetchRequest) returns (hellas.v1.Ticket);
}

message FetchRequest {
  string service = 1;
  string method = 2;
  repeated InputEvent input = 3;
}
```

Until the protocol bump, this semantic input transcript may be encoded through
the current opaque `bytes payload` field. That is a wire encoding detail, not
the Fetch model.

Initial OpenAI Responses mapping (the current wire shape — see Fetch Routes
And Configuration for the naming rule):

```text
service = "openai" | "codex"   (route name the caller addresses)
method  = "responses"
input   = finite Stream<ResponsesInputEvent>
output  = Stream<ResponsesOutputEvent>
```

For the HTTP Responses API, the adaptor lowers the finite JSON request body
into an input event stream:

```text
BeginRequest { service, method }
RequestBody { canonical provider request object }
EndInput
```

Open-ended incremental input is future work. Responses WebSocket mode and
Realtime-style providers need a session anchor and metered billing model,
because the full input transcript commitment is not known before execution
starts. The v1 Fetch shape is streaming-only, but its input stream is finite at
ticket creation time.

During the implementation phase, this can use the current opaque proto, ALPN,
tags, and scheme id. In that phase the tag alone is not a behavioral guarantee;
the route's trusted producer key set decides which producers are allowed to
perform real provider Fetch work.

## Stream Commitment Law

Execution is stream-shaped throughout the stack. There should not be separate
streaming and non-streaming execution paths. A caller that wants a collected
response can consume the stream and fold it locally.

The settlement objects are the attested input transcript and attested output
transcript. Each event is domain-separated, sequenced, linked to the previous
event commitment, and signed by the party responsible for that direction:

- input events are authored and signed by the caller or gateway;
- output events are authored and signed by the producer.

```text
InputEvent {
  scheme,
  sequence,
  previous_event_commitment,
  kind,
  payload_commitment,
  signer,
  canonicalization_id,
}

OutputEvent {
  scheme,
  input_commitment,
  stream_id,
  sequence,
  previous_event_commitment,
  kind,
  payload_commitment,
  signer,
  canonicalization_id,
}

EventReceipt = signature(InputEvent | OutputEvent)
```

The event commitment is the hash of the canonical event body. For v1, finite
input and output are two chains:

- the input chain is signed by the caller or gateway and produces
  `input_commitment`;
- the output chain is signed by the producer and starts from
  `output_genesis`.

The terminal event commits to the final stream root by linking to the preceding
event and declaring the stream status. There is still a terminal event, because
streams need an end-of-stream status, but it is not the only attested event.

Each chain has its own sequence-zero genesis:

```text
input_genesis  = H("hellas.stream.input-genesis.v1", scheme, caller_key)
output_genesis = H("hellas.stream.output-genesis.v1", input_commitment, stream_id)
```

That makes transcripts non-spliceable: an output stream only verifies for the
input transcript that produced it, and an input stream only verifies for the
caller or gateway key authorized to create the ticket.

`stream_id` is derived from the input transcript commitment after the finite
input chain has been committed:

```text
stream_id = H("hellas.stream.id.v1", input_commitment)
```

It is stored with the quote and is not a second idempotency dimension. Replay
returns the stored transcript with the same `stream_id`; a producer must not
mint a fresh stream id for a retry.

Clients can verify each event before rendering it, decoding it, or using it to
drive follow-on work. If an event signature or chain link fails, the stream is
invalid from that point onward.

V1 signs every event. That is the simplest verifier and gives immediate
per-event finality. If signature cost becomes too high, a later protocol
variant can hash-chain every event and sign checkpoints or the terminal root;
that changes verification semantics and should not be introduced as an
implementation detail.

For catgrad evaluation, the natural stream events are token or text deltas. For
Fetch, the natural stream events are application-level provider events, such as
OpenAI Responses events after provider-protocol parsing. The chunk boundary must
be an application boundary, not an arbitrary TCP read or raw SSE framing detail.

For a generic JSON provider stream, the Fetch binding should parse each provider
event, canonicalize the event payload, and attest that canonical event. This
keeps the stream lossless at the provider-event level without making settlement
depend on line endings, buffering, or network chunking.

Canonicalization is consensus-critical. The canonicalization id is part of the
event body so gateways, producers, and verifiers can reject mismatched
canonicalizers explicitly. A provider-event canonicalizer must be deterministic
and content-preserving:

- stable key ordering;
- exact number preservation;
- no silent dropping of unknown fields;
- stable encoding for strings, binary data, nulls, arrays, and objects.

This is also what makes independent sampling work: if a caller distinguishes
two inputs with a metadata field, the canonicalizer must preserve that field or
the two input commitments will collide.

The final response object, if a wire adaptor needs one, is a deterministic fold
over the verified stream transcript. It is not a separate execution path.

The chain proves integrity and ordering of the events it contains. It does not
prove completeness relative to the provider's true output. A producer can
truncate a provider stream and sign a terminal event declaring completion; that
false completion is a producer-trust violation, not something the hash chain can
cryptographically rule out.

## L1 Kernel Boundary

The stream transcript is an off-chain execution artifact. Per-event receipts
let peers verify live progress and build evidence, but they are not L1 close
proofs by themselves.

The L1 kernel accepts compact settlement artifacts under channel terms:
frontier commitments, close proofs, violation seals, timeout paths, and payout
shapes. It does not run an on-chain stream challenge game, and it does not treat
bare signed receipts as final settlement witnesses.

Therefore the stream root should feed the off-chain frontier/job state, not the
kernel directly:

```text
attested stream events
  -> stream transcript root
  -> signed frontier / job-state root
  -> proof or seal accepted by the L1 kernel
```

This keeps online execution verification and L1 settlement separate. A gateway
or peer can reject a bad stream immediately from event signatures and chain
links. An L1 close still needs the proof or seal required by the edge terms,
with the stream root only as committed public input or witness material.

Open item for the L1 integration: define exactly how the transcript root enters
frontier or job state, and which frontier/channel key signs that state. The
stream transcript root may become a leaf, a public input, or part of a hashed
job-state value, but that binding belongs to the channel/frontier protocol
rather than to Fetch itself.

## Fetch Assurance

Fetch is a signature-based trust scheme. It says:

```text
caller C authorized input transcript I
producer P attests that I produced output transcript O
```

It does not provide non-cooperative validity for the external provider call.
That is weaker than an independently checkable `Evaluate` scheme. A future
zkTLS-backed provider scheme can improve assurance, but that should be modeled
as a strategy for Fetch, not as a peer scheme alongside Fetch.

Current `SchemeId` mixes scheme and assurance strategy. A later protocol bump
should separate:

```text
scheme:   Fetch | Evaluate
strategy: ProducerSignature | ZkTls | ...
```

Until that bump, the OpenAI provider executor should be documented as
producer-signature Fetch.

## Producer Identity And Verification

The producer signing key is part of the Fetch trust root. It must be distinct
from the iroh node identity and from provider API keys.

Initial behavior:

- each Fetch node has a durable producer signing key;
- each Fetch node has a route-level trusted caller/gateway key set;
- the gateway route selects a Fetch peer and a trusted producer key set;
- `CreateTicket` records the authorized caller/gateway key bound to the ticket;
- a Fetch output transcript is accepted only if its producer signatures verify
  against a trusted key for that route;
- transcript verification is independent of provider API authentication;
- key rotation is explicit: add the new producer key to the route trust set,
  deploy the producer with the new key, then remove the old key only after
  draining in-flight work and any stored transcripts signed by the old key.

Known v1 limitation: completed-transcript replay verifies stored transcripts
against the producer's *current* key, so rotating the producer key makes
transcripts signed by the old key unservable (the ticket reads as consumed
but cannot replay). Until replay verifies against a key set, rotating a
producer key requires retiring or accepting the loss of its stored
transcripts.

This means a p2p Fetch node is not trusted merely because it is discoverable or
reachable. Discovery finds candidates; route policy decides which producer keys
are accepted for paid provider execution.

Gateway acceptance of a Fetch stream requires all of:

1. the input transcript commitment matches the input events submitted by the
   gateway;
2. the output transcript starts from the accepted input commitment;
3. every input event signature verifies against the caller or gateway key
   recorded on the ticket;
4. every output event signature verifies against a trusted producer key for
   that route;
5. every event chain link verifies, including the genesis link and terminal
   stream status;
6. any folded response object returned to the caller is the deterministic fold
   of the verified output transcript.

The gateway must retain or reconstruct the input transcript it sent until
verification completes. Verifying only producer signatures on output events is
insufficient: a producer could otherwise splice a valid output stream onto a
different input stream.

The producer must also reject unauthenticated input. It verifies input events
against the caller or gateway key recorded at ticket creation, and that key must
come from the producer route's trusted caller/gateway key set. The signer field
inside an input event is descriptive; it is not self-authorizing.

The iroh node identity is not a settlement trust root. It governs discovery,
transport availability, accounting, and abuse resistance. Settlement trust is
split by direction: caller or gateway authorization over input, producer
attestation over output.

Key inventory:

| Key | Holder | Signs | Trusted by |
| --- | --- | --- | --- |
| Caller/gateway key | paying caller or gateway route | finite input transcript | producer, gateway, later dispute verifier |
| Producer key | Fetch executor | output transcript | gateway route and later dispute verifier |
| Iroh node key | node process | transport identity | peer discovery/accounting layer |
| Provider API key | Fetch executor operator | provider HTTP authentication | provider only |
| Frontier/channel key | channel participant | frontier or job-state roots | channel counterparty and L1 proof path |

## Fetch Verifier Spec

Ticket creation verifies and stores the finite input transcript:

1. select the route and scheme from the inbound service;
2. read the caller/gateway key from the input transcript and verify every
   input event signature against it — the signatures prove key possession;
3. require that key to be a member of the route's trusted caller key set —
   membership, not the transcript's own claim, grants authorization;
4. verify input sequence numbers and chain links from `input_genesis`;
5. compute `input_commitment` from the terminal input chain root;
6. derive `stream_id = H("hellas.stream.id.v1", input_commitment)`;
7. store the quote under `input_commitment` with `SchemeId`, caller key,
   `stream_id`, route policy, and expiry.

Ticket execution verifies the quote and constructs the output transcript:

1. look up the quote by `input_commitment`;
2. transition the quote from `Quoted` to `Running`;
3. call the provider off the actor loop;
4. sign output events with the producer key, chaining from `output_genesis`;
5. persist the full input and output transcript before marking completion;
6. replay the stored transcript on later runs of the same completed ticket.

Known v1 limitation: `RunTicket` and completed-transcript replay are authorized
by possession of `input_commitment`, not by a fresh proof of the caller key.
The commitment covers the caller-signed input chain, so only the caller and the
producer can compute it, and transport is encrypted; within that model the
commitment acts as a bearer capability for starting and replaying the ticket it
names. A later protocol revision should bind `RunTicket` to the recorded caller
key — for example, a caller signature over the commitment plus a freshness
element — so run and replay authorization rest on key proof rather than hash
knowledge.

Gateway verification checks both directions:

1. verify the input transcript matches what the gateway submitted;
2. derive the expected `stream_id` from the input commitment;
3. verify the output chain starts at `output_genesis`;
4. verify every output signature against the route's trusted producer key set;
5. verify terminal stream status;
6. fold the verified output transcript into any wire response object returned to
   the caller.

## Policy

Fetch policy is deny-by-default and parser-backed.

For OpenAI Responses, ticket creation should validate:

- the route (for example `openai/responses` or `codex/responses`) is defined;
- input events form a valid provider request;
- `model` is in an allowlist, initially something like `gpt-5.3-codex`;
- input transcript size is under a configured maximum;
- output limit is present and within policy;
- unsupported provider features are rejected before quoting.

The model allowlist and limits are policy over parsed input events. The
attested transcript still commits to those input events.

## Fetch Routes And Configuration

A Fetch node's configuration is a table of routes plus an access policy. A
route is the unit of everything: dispatch, capability limits, caller grants,
and gateway targeting all key off the same `(service, method)` pair.

Naming rule: `service` is the route name the caller addresses and commits to
in the input transcript. The wire contract (what the request body and output
events look like) is the route's `protocol`, an explicit configuration
property — it is not encoded in the service name. Two routes may share a
protocol with different upstreams (`codex/responses` and `openai/responses`
both speak OpenAI Responses); they remain distinct services because they are
distinct products with distinct upstreams, billing, and capability sets. This
needs no wire change: `(service, method)` is already the only route selector a
remote caller commits to, so it must identify exactly one route per node.

The route table is the single source of routing truth:

```text
routes:
  service/method ->
    protocol      (selects the output projector / event canonicalizer)
    upstream      (provider driver: plain HTTP + API key env, Codex OAuth, ...)
    capabilities  (route-wide self-protection: allowed models, max output,
                   optionally max in-flight)
access:
  caller key ->
    route grants  (per-route model allowlist, max output)
    request rate
    spend quota
```

Dispatch is an exact map lookup; registering a duplicate `(service, method)`
is a startup error. Providers do not inspect `service`/`method` — a driver
receives only requests for the route it was registered under. "No such route"
is an admission-shaped error distinct from provider failure; a provider error
means the provider actually failed.

Capabilities and caller grants are the same policy shape applied at two
layers: capabilities answer "can this route safely satisfy this request?"
(operator-to-upstream), grants answer "may this caller spend this route?"
(caller-to-node). Admission validates against their intersection. Per-end-user
policy is the gateway's concern (or a future per-user caller key); the Fetch
node sees caller keys, not users.

Routes and access live in one configuration file so they can be
cross-validated at load: a caller grant naming an undefined route is a
configuration error, not a silent dead entry. The Nix module exposes typed
route/access options and renders this file.

## Idempotency And Billing

Provider calls are paid and non-deterministic. Fetch must avoid implicit retry
semantics that can double-bill or produce a different output for the same
ticket.

Fetch uses an explicit state machine:

```text
Quoted -> Running -> Completed { transcript }
                  -> Failed { reason }
```

Initial behavior:

- ticket creation does not call the provider;
- the `Quoted -> Running` transition is synchronized by the executor actor;
- `RunTicket` calls the provider at most once for a ticket;
- provider I/O runs off the actor loop after the ticket is marked running;
- if the provider call fails before a terminal output transcript exists, emit
  `WorkFailed`;
- do not automatically retry provider calls inside the executor;
- if the provider call succeeds, persist the full attested transcript before
  marking the ticket completed;
- if the client retries `RunTicket` after completion, replay the completed
  transcript;
- if the client retries `RunTicket` after failure, reject the consumed ticket
  unless a future explicit retry policy creates a new ticket.

If retry/caching is added later, it must be explicit in the Fetch executor state
machine and metrics.

The existing short-lived in-memory quote map is suitable for unpaid quotes. It
is not sufficient storage for completed paid Fetch results. Completed Fetch
state needs durable storage so a successful provider call cannot be lost after
billing but before the client receives the terminal transcript.

The input transcript commitment is also the idempotency key. Two Fetch inputs
with identical canonical input transcripts represent the same captured work and
replay the same completed transcript.

This applies to finite input transcripts known at ticket creation time. Open
incremental input streams need a different anchor, such as a caller-chosen
session id, and a metered billing model. They are outside v1.

This remains true for nondeterministic providers. Fetch captures a trusted
producer's observation of an external process; it does not promise that every
rerun of the underlying provider would return the same bytes. Once the producer
successfully completes a ticket, the durable transcript is the answer for that
input transcript commitment.

Clients that want an independent sample must submit different input events, for
example by setting a provider-supported seed, user id, metadata field, or other
explicit request field. The executor must not inject a hidden nonce, because
that would make the committed input transcript differ from the caller's Fetch
input.

When the provider supports idempotency keys, the Fetch executor should derive
the provider key from the input transcript commitment and send it on every
provider call:

```text
Idempotency-Key = hex(input_transcript_commitment)
```

That extends the same idempotency identity across the ticket store, gateway, and
provider billing boundary. Providers without idempotency-key support require
the stricter crash behavior described above: persist `Running` before issuing
the provider call and never automatically re-run recovered indeterminate work.

V1 implements both: every provider HTTP call carries the derived
`Idempotency-Key` header, and `start` durably writes a running marker (keyed
by input commitment, next to the stored transcripts) before the provider is
invoked. A marker without a completed transcript marks the input
indeterminate — ticket creation and run are refused until an operator
resolves it by confirming the provider-side outcome and deleting the marker
(or replaying the completed transcript if one exists).

Provider-level idempotency is scoped to the canonicalization id. The same
logical request canonicalized under different versions can produce different
input commitments and therefore different provider idempotency keys. Route
operators must roll canonicalizer versions in a coordinated way.

## Generated Client Shape

The protocol can be named `Fetch.CreateTicket(FetchRequest)` while ergonomic
Rust callers use a cleaner wrapper.

Generated service markers and low-level clients will likely preserve the RPC
shape:

```rust
let ticket = FetchClientImpl::new(transport)
    .create_ticket(request)
    .await?;
```

Higher-level wrappers should expose intent:

```rust
let output = client.fetch(FetchRequest {
    service: "openai".into(),
    method: "responses".into(),
    input,
}).await?;
```

This is not a semantic conflict. `CreateTicket` quotes committed work.
`client.fetch(...).await?` can create a ticket, run it, verify the transcript,
and return the folded output stream.

## Naming And Protocol Bump

The desired names are:

| Current | Desired | Meaning |
| --- | --- | --- |
| `Opaque` | `Fetch` | Effectful external call: input stream in, attested output stream out. |
| `Symbolic` | `Evaluate` | Computation over committed inputs with a scheme-defined validity model. |
| `Courtesy` | keep for now | Helper APIs that are explicitly outside settlement. |
| `Execute` | keep for now | Generic ticket runner shared by schemes. |

Renaming is wire-breaking:

- proto package/service names affect generated ALPNs;
- commitment tags and `SchemeId` bytes are part of signed receipt identity;
- existing receipts cannot verify under new scheme ids.

Therefore renaming must be a deliberate protocol version bump, not an early
refactor.

Do not rename `Execute` to `Run` now. The value is small and the blast radius is
large. If we want a nicer high-level API, expose `client.run_ticket(...)` or
`client.fetch(...)` wrappers without changing the core service name.

`Courtesy` should not automatically become `Prepare`. The code already uses
"prepare" for tokenization and chat templating, and `Courtesy` carries a useful
trust-boundary signal: these APIs are helpful, optional, and not settlement
objects. Better candidates are still open; keeping `Courtesy` until the protocol
bump is acceptable.

## OpenAI Fetch Node

The OpenAI-backed p2p node should:

- listen on iroh only;
- advertise the existing opaque/fetch ticket service, `Execute`, and `Node`;
- not advertise catgrad evaluate or courtesy/prepare services;
- keep separate identity and producer signing key material;
- read the OpenAI API key from a secret-backed environment file;
- validate provider requests before ticket creation;
- call OpenAI at most once per ticket;
- stream attested provider events.

No HTTP listener is needed. An HTTP gateway can later route `/v1/responses` to
this p2p node by turning the incoming HTTP body into a finite Fetch input stream
and requiring the returned transcript to verify against the route's trusted
producer key set.

## Resequenced Plan

1. Add this proposal and agree on the boundaries. *(done)*
2. Add Fetch verifier and state-machine specs before moving hosting code:
   input/output transcript verification, `Quoted -> Running -> Completed |
   Failed`, durable transcript replay, and off-loop provider I/O. *(done — this
   document)*
3. Add `crates/runtime`; extract node hosting from the CLI behind a generic
   service-registration API.
4. Add the executor scheme registry so schemes are registered rather than
   matched centrally.
5. Feature-gate `hellas-executor` so catgrad is optional and a fetch-only build
   is possible.
6. Build the real Fetch core under the current opaque proto/ALPN/tags. Reuse
   provider parsing for OpenAI policy; commit attested input and output
   transcripts for settlement. *(done)*
7. Add `fetch::openai` as a streaming-only executor. HTTP Responses requests
   lower to finite input streams; provider streaming stays streaming. *(done,
   plus a Codex OAuth provider)*
8. Stand up the OpenAI p2p node on trex with separate identity, state, producer
   key, policy, and secret-backed API key.
9. Add gateway support for routing `/v1/responses` to the p2p Fetch node.
   *(done)*
10. Verify a real attested transcript end-to-end from HTTP request through p2p
   Fetch execution.
11. Only after behavior is proven, perform one protocol version bump for naming:
   `Opaque -> Fetch`, `Symbolic -> Evaluate`, decide `Courtesy`, and resolve
   `ZkTls` as an assurance strategy rather than a scheme.

This keeps the wire stable while the behavior is being built. The rename should
be the final cleanup once the new execution semantics are known-good.
