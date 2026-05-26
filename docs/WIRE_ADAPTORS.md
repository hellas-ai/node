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
  -> Hellas settlement adaptor projection
Call
  -> executor
CallResult + Receipt
  -> ExecutionResult
```

The wire adaptor is not a settlement boundary. It is selected by the HTTP
route and owns provider compatibility. The settlement adaptor owns canonical
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

## Canonical Versus Passthrough

Every parsed request projects to:

```rust
pub struct ExecutionRequest {
    pub canonical: CanonicalExecution,
    pub passthrough: PassthroughBag,
}
```

`canonical` contains fields a backend may commit to. For a Hellas backend,
these fields are eligible to affect the settlement `Call`.

`passthrough` contains fields preserved for compatibility but not witnessed by
the Hellas receipt. A proxy backend may forward them unchanged. A Hellas
backend must not silently treat passthrough fields as committed behavior.

The split is semantic, not just storage. If a wire field changes execution
behavior, it belongs in `canonical`. If it is retained only to round-trip or
forward to another service, it belongs in `passthrough`.

`CanonicalExecution::committed_fields` records the wire field paths that the
adaptor projected into canonical execution state. Tests for each adaptor should
pin this set for representative requests.

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

Provider-specific fields that have no canonical execution meaning stay in
`PassthroughBag`.

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

Backends consume `ExecutionRequest` and produce `ExecutionResult` or
`OutputEvent`.

Expected backend families:

- local catgrad execution
- remote Hellas execution
- HTTP proxy execution
- mocks for tests

The wire adaptor must not assume which backend is used. The backend must not
assume which provider route produced the request beyond the fields present in
`ExecutionRequest`.

`hellas-wire-adaptors` defines the `ExecutionBackend` trait but does not ship
transport-specific implementations. HTTP proxy backends belong in crates that
can depend on an HTTP client.

## OpenAI Responses First

The first concrete adaptor is OpenAI Responses because it exercises the full
surface: rich inputs, tools, structured output, reasoning controls, response
state, non-streaming rendering, and streaming fanout.

Implementation order:

1. lossless request parsing
2. projection to `ExecutionRequest`
3. non-streaming response rendering
4. streaming event rendering
5. gateway integration

Each step should add fixtures that pin both wire compatibility and the
canonical-versus-passthrough split.
