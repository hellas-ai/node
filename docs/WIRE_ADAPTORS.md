# Wire Adaptors

Wire adaptors translate provider wire formats into backend-neutral execution
requests and render backend-neutral output back into provider wire formats.

They are distinct from Hellas settlement adaptors.

## Layers

```text
HTTP bytes
  -> WireAdaptor parse
ExecutionRequest
  -> backend execution
ExecutionResult / OutputEvent
  -> WireAdaptor render
HTTP response or SSE events
```

For Hellas-backed execution there is another layer below this:

```text
ExecutionRequest
  -> scheme projection (Evaluate program, or Fetch input transcript)
ticket
  -> executor
signed transcript / receipt
  -> ExecutionResult
```

The wire adaptor is not a settlement boundary. It is selected by the HTTP
route and owns provider compatibility. The scheme layer owns canonical
commitment bytes.

## Crate Boundary

`hellas-wire-adaptors` must stay transport-neutral and backend-neutral.

Allowed dependencies are small data-format dependencies such as `serde`,
`serde_json`, and `thiserror`.

The crate must not depend on:

- `hellas-core`
- `hellas-runtime`
- `hellas-executor`
- `hellas-rpc`
- transport crates

Backend implementations live elsewhere and consume `ExecutionRequest`.

## Canonical Versus Raw

Every parsed request projects to:

```rust
pub struct ExecutionRequest {
    pub canonical: CanonicalExecution,
}
```

and travels alongside the original wire body:

```rust
pub struct BackendRequest {
    pub execution: ExecutionRequest,
    pub raw: RawRequest, // original wire JSON
}
```

`canonical` is the semantic, provider-neutral view: what local execution,
policy, and rendering understand. `raw` is the byte-faithful wire body: what
proxy and Fetch backends forward (Fetch commits to the canonical request
bytes inside the signed input transcript — the field-level view is never
receipt material).

The split is semantic: if code needs to understand a field, it is parsed into
`canonical`; if a field only needs to survive the trip to a provider, it rides
in `raw` untouched. There is no field-level commitment set; a future
field-level Evaluate scheme would have to introduce one explicitly.

## Request Shape

`CanonicalExecution` covers the provider-neutral request surface:

- model identity
- input text, messages, or rich input items
- instructions
- sampling options
- tools and tool choice
- structured response format
- reasoning controls
- previous response reference

Provider-specific fields that have no canonical execution meaning stay in the
raw wire body.

`RawRequest` stores both original bytes and parsed JSON. Adaptors should parse
from `RawRequest` so lossless behavior can be tested.

## Output Shape

Backends return `ExecutionResult` for non-streaming calls and `OutputEvent`
values for streaming calls.

`OutputEvent` is intentionally smaller than any one provider's SSE vocabulary.
The adaptor maps each event into zero, one, or many wire events. A stream also
has an explicit start hook so providers such as OpenAI Responses can emit
prefix events before the first model delta.

The core events are:

- text deltas
- tool-call deltas
- structured-output deltas
- usage updates
- finish events
- errors
- provenance

## Backend Contract

Backends consume `BackendRequest` and produce `ExecutionResult` or
`OutputEvent`. `BackendRequest` carries both the projected `ExecutionRequest`
and the original `RawRequest`; raw-preserving backends can forward exact input
bytes while Hellas backends can ignore the raw bytes and execute only the
canonical projection.

Streaming backends return `BackendStream`, which carries an owned event stream
and any pre-flight provenance known before the response body starts.

Expected backend families:

- local catgrad execution
- remote Hellas execution
- HTTP proxy execution
- mocks for tests

The wire adaptor must not assume which backend is used. The backend must not
assume which provider route produced the request beyond the fields present in
`ExecutionRequest`.

`hellas-wire-adaptors` defines the `ExecutionBackend` trait but does not ship
transport-specific implementations. The gateway implements local catgrad
execution and the OpenAI Responses HTTP proxy.

## OpenAI Adaptors

The crate currently includes OpenAI Responses, OpenAI Chat Completions, OpenAI
Completions, and Anthropic Messages. Responses exercises rich inputs,
structured output, response state, and streaming fanout. Chat Completions and
Anthropic Messages keep exact provider message JSON in canonical input items so
tool-call history, tool results, and provider block formats survive projection
without gateway-specific parsing.

Adaptor tests should pin both wire compatibility and the canonical projection
for representative requests.
