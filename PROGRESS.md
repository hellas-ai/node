# Implementation Progress

Audited 2026-05-26 against the live tree.

## Live

- `hellas identity show-node-id` prints the iroh-derived node id.
- `hellas serve` runs the RPC server with catgrad text execution when the
  executor feature is enabled.
- `hellas gateway` exposes OpenAI Chat Completions, OpenAI Responses,
  Anthropic Messages, and plain text completion endpoints.
- `hellas rpc`, `hellas llm`, and `hellas monitor` are wired through the
  CLI.
- The gateway can execute locally, execute remotely, verify against a
  secondary route, and wrap child processes as an OpenAI/Anthropic backend.
- Catgrad execution runs through `crates/executor`; model assets and prompt
  preparation live in `crates/rpc::model`.
- Catnix projection is live for catgrad text quotes and completions:
  quotes carry a projected `Call`, completed executions sign a catnix
  `Receipt`, and terminal outcomes carry the receipt commitment.
- Gateway provenance emits `x-hellas-commitment` and `x-hellas-receipt`
  where the data is available before the response is sent. Streaming
  Responses events also carry the terminal receipt commitment in-band.
- `crates/wire-adaptors` is a workspace crate. It defines the
  transport-neutral wire adaptor boundary, backend-neutral execution
  request/result types, and the OpenAI Responses adaptor.

## Architecture

There are two adaptor layers:

- Wire adaptors translate provider request/response shapes to and from
  backend-neutral execution types. They are outside the settlement boundary.
- Settlement adaptors project execution into canonical Hellas `Call`,
  `CallResult`, and `Receipt` bytes. They are inside the settlement boundary.

OpenAI Responses now uses this path in the gateway:

```text
HTTP JSON
  -> OpenAiResponsesAdaptor::parse
  -> OpenAiResponsesAdaptor::to_execution_request
  -> GatewayState::prepare_wire_execution
  -> catgrad execution
  -> ExecutionResult / OutputEvent
  -> OpenAiResponsesAdaptor render
  -> HTTP JSON or SSE
```

The wire adaptor crate remains transport-neutral. HTTP proxy backends,
Hellas RPC backends, and local catgrad backends belong in crates that can
depend on transport/runtime code.

## Current Gaps

- Persistent producer signing keys are not implemented. The executor signs
  catnix receipts with a process-local key.
- Parameters and tokenizer bindings still use locator-derived placeholder
  value IDs. They need content-addressed digests from the relevant catgrad
  subsystems.
- Full receipt bytes are not exposed through the gateway. The gateway ships
  receipt commitments; a verifier still needs a receipt retrieval path.
- The OpenAI Responses wire adaptor supports tool and structured-output
  shapes, but the local catgrad backend currently emits text deltas only for
  that route.
- Chat Completions, Anthropic Messages, and plain completions still use their
  route-local gateway code instead of `hellas-wire-adaptors`.
- HTTP proxy execution is not implemented.

## Verification

- `cargo test --workspace`
- `cargo check --workspace --all-targets`
