# Tool-Parse Failure Handling in the Gateway

## 1. The Bug

Both gateway adapters silently demote tool-call parse errors to a normal stop,
and ship the raw template-encoded model output back to the client as
assistant content.

OpenAI streaming, `crates/cli/src/commands/gateway/openai.rs:108-157`:

```rust
let finish_reason = if prepared.has_tools {
    let step = prepared.parse_tool_calls(&accumulated).unwrap_or_else(|err| {
        warn!(error = %err, "failed to parse tool calls from streamed text");
        None
    });
    match step {
        Some(step) => { /* emit tool_calls, finish ToolCalls */ }
        None => {
            if tx
                .send(Ok(sse_data(&mk_chunk(text_delta(accumulated), None))))
                .is_err()
            { return; }
            openai::FinishReason::Stop
        }
    }
} else { openai::FinishReason::Stop };
```

`accumulated` is the entire model output buffered for tool parsing. On a parse
error this branch flushes that buffer as a text delta and finishes with
`stop`. The client receives a normal-looking assistant message whose content
is the architecture-specific tool sentinel string, for example:

```
<|tool_call|>{"name": "search", "arguments": {"q
```

OpenAI non-streaming, `crates/cli/src/commands/gateway/openai.rs:196-212`:

```rust
let (message, finish_reason) = match prepared.parse_tool_calls(&text) {
    Ok(Some(step)) => (tool_call_message(&step), openai::FinishReason::ToolCalls),
    Ok(None)       => (openai::ChatMessage::assistant(text), openai::FinishReason::Stop),
    Err(err) => {
        warn!(error = %err, "failed to parse tool calls from generated text");
        (openai::ChatMessage::assistant(text), openai::FinishReason::Stop)
    }
};
```

The `Ok(None)` and `Err(_)` arms produce identical responses. A 200 OK comes
back with `choices[0].message.content` set to the raw template text and
`finish_reason: "stop"`.

Anthropic streaming, `crates/cli/src/commands/gateway/anthropic.rs:122-145`:
same shape, the raw `accumulated` is wrapped in a `text` content block and
finished with `end_turn`.

Anthropic non-streaming, `crates/cli/src/commands/gateway/anthropic.rs:255-271`:
same shape, raw text becomes a `ContentBlock::Text` and `stop_reason` is
`end_turn`.

The parser is `ModelAssets::parse_tool_calls` in
`crates/rpc/src/model/assets.rs:138-153`. It dispatches per architecture
(`Qwen3`, `Lfm2`, `Olmo3`, `Qwen3_5`) and propagates whatever those parsers
return. Architectures with no tool support return `Ok(None)`, which is the
legitimate "no tool call" signal and must remain distinct from `Err(_)`.

## 2. Why Silent Demotion Is Wrong

The leaked content is template machinery, not natural assistant prose. Three
concrete consequences:

1. **Chat history corruption.** OpenAI/Anthropic clients append the assistant
   reply to their next request. The client will then send back a user turn
   followed by an assistant turn whose body is `<|tool_call|>...` or the
   equivalent sentinel. On the next prefill the model sees its own template
   markers as input data, which both poisons attention and biases the next
   generation toward producing more sentinel-shaped output. The damage is
   sticky: every turn after the failure carries the corrupted message until
   the client trims history.

2. **Lost tool calls.** When a tool-trained model emits sentinels, it almost
   always intended a real tool call. A parser bug, a truncated stream, or a
   missing close-tag is the most common cause of `Err(_)` from
   `parse_tool_calls`. Demoting that to `stop` tells the client "the model
   chose not to call a tool", which is the opposite of what happened. Any
   client routing on `finish_reason == "tool_calls"` (every agent framework)
   will skip the tool-execution branch and treat the sentinel string as a
   final answer.

3. **No diagnosibility on the wire.** A `warn!` line on the server is the
   only signal. Operators reading their gateway logs see "failed to parse
   tool calls"; the client sees a successful 200 with garbage content and has
   no reason to file a bug.

## 3. Failure Modes To Distinguish

`parse_tool_calls` produces three outcomes that must map to three different
client-visible responses:

| Source                                  | Today                  | Should be                                  |
| --------------------------------------- | ---------------------- | ------------------------------------------ |
| `Ok(None)` — no tool call in output     | `Stop` + assistant text | `Stop` + assistant text (unchanged)        |
| `Ok(Some(step))` — clean tool call      | `ToolCalls` + tool_calls | `ToolCalls` + tool_calls (unchanged)       |
| `Err(_)` — parser saw a malformed call  | `Stop` + raw template  | error response, raw text suppressed         |

The third row is the bug. The error case must not share a code path with the
"no tool call at all" case.

## 4. Proposed Fix

Return an error response. Do not include the raw model output in `content`.
Log the raw output server-side at `debug` (it can be long and may contain
prompt-leaked secrets, so it does not belong at `warn`).

OpenAI non-streaming sketch:

```rust
let (message, finish_reason) = match prepared.parse_tool_calls(&text) {
    Ok(Some(step)) => (tool_call_message(&step), openai::FinishReason::ToolCalls),
    Ok(None)       => (openai::ChatMessage::assistant(text), openai::FinishReason::Stop),
    Err(err) => {
        debug!(raw_output = %text, "tool-call parser raw input");
        warn!(error = %err, "tool-call parser rejected model output");
        return openai_error_response(
            StatusCode::BAD_GATEWAY,
            "model_output_error",
            format!("model produced a tool-call sentinel that could not be parsed: {err}"),
        );
    }
};
```

`openai_error_response` should produce the standard OpenAI error envelope:

```json
{ "error": { "message": "...", "type": "model_output_error", "code": null } }
```

Anthropic non-streaming uses the matching Anthropic error envelope (`type:
"error"`, nested `error.type` of `api_error` or `invalid_request_error`).

The HTTP status should be 502 Bad Gateway. The upstream model produced output
that the gateway could not faithfully translate into the client's protocol;
that is a textbook upstream error, not a 4xx client mistake and not a 200.

## 5. Streaming Variant

Streaming has already started by the time `parse_tool_calls` runs (the buffer
exists precisely because we deferred sending until generation completed).
HTTP status is locked at 200. The error must be delivered as a final SSE
frame in the protocol's framing, then the stream closed without any further
content frames.

OpenAI: emit one frame with `{"error": {"message": ..., "type":
"model_output_error"}}`, then `data: [DONE]`. Do not emit a `delta` carrying
`accumulated`, and do not emit a `finish_reason: "stop"` chunk. The
`Inference error` arm at `openai.rs:97-106` already uses this shape and is
the right template.

Anthropic: emit a `MessageStreamEvent::Error` event using the existing
`StreamError` type, then close. The inference-error arm at
`anthropic.rs:106-120` already does this.

If a separate `GATEWAY_OPENAI_ERROR_FRAMING.md` exists when this is
implemented, follow its conventions for the exact `event:` and `data:` line
shape; the constraints above are the minimum.

## 6. Test Strategy

Tests should not require a real model. Inject a stub `ModelAssets` (or a
`PreparedGeneration` constructor accepting a parser closure) whose
`parse_tool_calls` returns a chosen `Result` while `stream_text` /
`run_to_text` returns a chosen string.

Cases per adapter, per streaming/non-streaming:

1. **Parser errors, non-streaming**: assert HTTP 502, assert response body is
   the protocol-shaped error envelope, assert the body does not contain the
   raw output substring, assert the parser error message is included.
2. **Parser errors, streaming**: collect emitted SSE bytes; assert the only
   non-control frame is the error frame, assert no `delta`/`content_block_delta`
   carries the raw output, assert the stream terminates with the protocol's
   end marker.
3. **Parser returns `Ok(None)`**: assert the existing `Stop`/`end_turn`
   behavior with the model text in `content` is preserved (regression guard
   so the fix does not accidentally route legitimate non-tool replies through
   the error path).
4. **Parser returns `Ok(Some(_))`**: regression guard for the happy path.

A useful integration check: feed a fixed deliberately-malformed sentinel
through the real `parse_qwen3_tool_calls` and assert the gateway responds
with the error envelope, not a 200 containing `<|tool_call|>`.
