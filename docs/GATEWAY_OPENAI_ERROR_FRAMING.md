# OpenAI-Compatible Error Framing in the Gateway

## 1. What Goes Wrong

`crates/cli/src/commands/gateway/openai.rs:97-106` handles a mid-stream
inference failure like this:

```rust
let generated = match generated {
    Ok(output) => output,
    Err(err) => {
        let _ = tx.send(Ok(sse_data(&json!({
            "error": { "message": format!("Inference error: {err}") }
        }))));
        let _ = tx.send(Ok(axum::response::sse::Event::default().data("[DONE]")));
        return;
    }
};
```

The `sse_data` helper (`crates/cli/src/commands/gateway/mod.rs:136-139`) emits
a bare `data:` frame with no SSE `event:` prefix. So the wire output for an
error is exactly:

```text
data: {"role":"assistant"}                              <- initial role chunk
data: {"choices":[{"delta":{"content":"par"},...}]}     <- some text deltas
data: {"error":{"message":"Inference error: ..."}}      <- error frame
data: [DONE]
```

This is broken for OpenAI-compatible clients in three independent ways:

1. The error frame is not a `ChatCompletionChunk`. The official OpenAI Python
   SDK and most generated clients (LangChain's `ChatOpenAI`, Vercel AI SDK,
   `openai-node`, `litellm` passthrough) parse every `data:` frame strictly as
   the streaming chunk schema. A frame whose top-level shape is
   `{"error": {...}}` raises a Pydantic / zod validation error inside the SDK
   rather than being recognized as a stream failure. The user sees a parser
   exception, not the inference error message.
2. There is no chunk with `finish_reason` before the failure. A permissive
   parser that ignores the malformed error frame will only see a sequence of
   `delta` chunks followed by `[DONE]`. By the OpenAI streaming contract the
   absence of any `finish_reason` for choice index 0 means the response was
   truncated, but `[DONE]` says it completed. The client code paths diverge:
   some treat this as a successful but truncated response; others raise
   `IncompleteResponseError`.
3. `[DONE]` is sent after the error. OpenAI's actual convention is that
   `[DONE]` is the success sentinel; on a stream failure the server either
   stops writing and resets the connection, or sends a single error frame and
   closes. Sending `[DONE]` after an error tells well-behaved clients the
   request succeeded and there are no further bytes.

The non-streaming path returns `{"error": {"message": ...}}` with a non-200
status (`crates/cli/src/commands/gateway/state.rs` `HttpError`), which is
correct. The bug is specific to the SSE streaming path after the response
headers and the first chunk have already been sent.

## 2. The OpenAI SSE Convention

OpenAI's streaming chat completions deliver only `data:` lines (no `event:`
field). Each frame is a JSON object matching `ChatCompletionChunk`:

```text
data: {"id":"chatcmpl-...","object":"chat.completion.chunk",
       "created":...,"model":"...","choices":[
         {"index":0,"delta":{"content":"hi"},"finish_reason":null}
       ]}
```

A successful stream ends with a chunk whose `choices[0].finish_reason` is one
of `stop`, `length`, `tool_calls`, `content_filter`, `function_call`, followed
by the literal sentinel:

```text
data: [DONE]
```

For mid-stream failures OpenAI's own server emits a single error frame and
closes the connection without `[DONE]`:

```text
data: {"error":{"message":"...","type":"server_error","code":null,"param":null}}
```

The error object follows the same shape as the non-streaming HTTP error body.
SDK clients special-case a top-level `error` key on a `data:` frame and raise
`APIError` instead of validating against `ChatCompletionChunk`. There is no
trailing `[DONE]` because the stream did not complete successfully.

## 3. The Anthropic Side, For Contrast

`crates/cli/src/commands/gateway/anthropic.rs:106-120` handles the same
condition correctly using `MessageStreamEvent::Error`:

```rust
let generated = match generated {
    Ok(output) => output,
    Err(err) => {
        let _ = tx.send(Ok(sse_event_data(
            "error",
            &anthropic::MessageStreamEvent::Error {
                error: anthropic::StreamError {
                    error_type: "invalid_request_error".to_string(),
                    message: format!("Inference error: {err}"),
                },
            },
        )));
        return;
    }
};
```

Two things differ from the OpenAI path:

- The frame is sent through `sse_event_data`, which prefixes the frame with
  `event: error`. The Anthropic SDK dispatches on the SSE event name, so this
  is the documented `MessageStreamEvent::Error` variant.
- There is no trailing `message_stop` frame after the error. The Anthropic
  stream simply ends.

The two gateways diverge in a way that is not justified by the underlying
provider conventions. Both providers want the error frame followed by stream
termination, with no success sentinel after the failure.

## 4. Proposed Fix

Three concrete changes to `openai.rs`.

First, emit a `finish_reason` chunk before the error frame so permissive
clients can locate the truncation point. Use `length` if the failure happens
after any text was emitted (the closest analogue OpenAI defines for an
incomplete generation), or omit this step if no delta has been sent yet:

```rust
Err(err) => {
    let _ = tx.send(Ok(sse_data(&mk_chunk(
        openai::ChatDelta::default(),
        Some(openai::FinishReason::Length),
    ))));
    // ... error frame, see below
    return;
}
```

Second, emit the error frame in the OpenAI-canonical shape. The top-level
`error` key is what SDKs match on; include `type` so clients that branch on
error class behave correctly:

```rust
let _ = tx.send(Ok(sse_data(&json!({
    "error": {
        "message": format!("Inference error: {err}"),
        "type": "server_error",
        "code": null,
        "param": null,
    }
}))));
```

Third, do not send `[DONE]` on this path. Drop the line:

```rust
let _ = tx.send(Ok(axum::response::sse::Event::default().data("[DONE]")));
```

Returning from the spawned task closes the SSE channel and ends the response
body, which matches OpenAI's behavior of terminating the stream without a
success sentinel.

The tracking of "has any delta been emitted" needs one boolean local in
`stream_response`. The initial assistant-role chunk does not count as content,
so the boolean should flip only when `text_delta(...)` or a tool-call frame is
sent. If false at the time of error, skip the `finish_reason` chunk; the
client will see only the error frame, which is sufficient for strict SDKs.

A secondary consideration: the same `[DONE]`-after-error pattern exists in
`crates/cli/src/commands/gateway/plain.rs:54-65`. The plain completions API
shares the OpenAI SSE convention, so the same fix applies there.

## 5. Compatibility Risk

There is no known in-tree client that depends on the current shape. The CLI
itself talks to its gateway as a peer over RPC, not through the OpenAI HTTP
surface, and the test suite for the gateway does not assert on streaming
error bytes. External users running the gateway behind LangChain, the
official OpenAI SDK, the Vercel AI SDK, or any code generated from the
OpenAI OpenAPI spec will already be seeing parser exceptions on the current
output, so any fix that produces canonical bytes is a strict improvement for
those clients.

The one population that may regress is code that explicitly parses the
current `{"error": {"message": ...}}` plus `[DONE]` shape. None has been
found in this repository, and that shape is non-standard, so accepting the
break is correct.

## 6. Test Strategy

Add a unit test in the gateway module that drives `stream_response` with a
prepared generation whose `stream_text` callback yields one delta and then
returns `Err`. Collect the SSE bytes by exercising `Sse::into_response` and
reading the body stream to completion. Assert on the exact frame sequence:

```rust
#[tokio::test]
async fn stream_error_uses_openai_canonical_shape() {
    let body = run_stream_with_failure_after("par").await;
    let frames = parse_sse_frames(&body);

    assert_eq!(frames.len(), 4);
    assert_chunk_with_role(&frames[0], "assistant");
    assert_chunk_with_delta(&frames[1], "par");
    assert_chunk_with_finish(&frames[2], "length");
    let err: serde_json::Value = serde_json::from_str(&frames[3].data).unwrap();
    assert_eq!(err["error"]["type"], "server_error");
    assert!(err["error"]["message"].as_str().unwrap().contains("Inference error"));

    assert!(!body.contains("[DONE]"));
    for frame in &frames {
        assert!(frame.event.is_none(), "openai frames must not set event:");
    }
}
```

A second test should cover the "error before any delta" case and assert that
no `finish_reason` chunk is emitted, only the role chunk and the error frame.

A third test should round-trip the bytes through the official `async-openai`
crate's streaming parser (or a hand-rolled `ChatCompletionChunk`
deserializer) to prove that real SDKs accept the leading chunks and surface
the error frame as an API error rather than a parse failure.

The Anthropic equivalent already has informal coverage through manual
integration runs; adding an analogous unit test for `anthropic.rs` would
prevent the two paths from drifting again.
