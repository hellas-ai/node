# Tool-Parse Gating in the Gateway

## 1. Current State

`PreparedGeneration` carries an explicit `has_tools` flag, set at preparation
time from the request:

```rust
// crates/cli/src/commands/gateway/state.rs:240
let has_tools = tools.as_ref().is_some_and(|t| !t.is_empty());
// crates/cli/src/commands/gateway/state.rs:266 (anthropic prepare path)
let has_tools = tools.as_ref().is_some_and(|t| !t.is_empty());
```

That flag is consulted by both streaming branches before invoking
`prepared.parse_tool_calls(...)`:

- OpenAI streaming: `crates/cli/src/commands/gateway/openai.rs:108`
  (`if prepared.has_tools { ... let step = prepared.parse_tool_calls(&accumulated) ... }`)
- Anthropic streaming: `crates/cli/src/commands/gateway/anthropic.rs:122`
  (`let stop_reason = if prepared.has_tools { ... let step = prepared.parse_tool_calls(&accumulated) ... }`)

The non-streaming branches do not consult `has_tools` at all. The parser is
called on every response:

- OpenAI non-streaming, `crates/cli/src/commands/gateway/openai.rs:196`:

  ```rust
  let (message, finish_reason) = match prepared.parse_tool_calls(&text) {
      Ok(Some(step)) => (tool_call_message(&step), openai::FinishReason::ToolCalls),
      Ok(None)       => (openai::ChatMessage::assistant(text), openai::FinishReason::Stop),
      Err(err) => { ... }
  };
  ```

- Anthropic non-streaming, `crates/cli/src/commands/gateway/anthropic.rs:261`:

  ```rust
  let step = prepared.parse_tool_calls(&text).unwrap_or_else(|err| {
      warn!(error = %err, "failed to parse tool calls from generated text");
      None
  });
  let (content, stop_reason) = match step {
      Some(step) => (tool_use_blocks(&step), anthropic::StopReason::ToolUse),
      None => (vec![anthropic::ContentBlock::Text { text }], anthropic::StopReason::EndTurn),
  };
  ```

So a plain chat completion that did not request tools still runs through
`ModelAssets::parse_tool_calls` against the full generated text. If the parser
matches anything, the gateway will rewrite the response into a tool-call shape
that the client never asked for: `finish_reason: "tool_calls"` and an empty
content body for OpenAI, a `ToolUse` content block and `stop_reason:
"tool_use"` for Anthropic.

This asymmetry is unintentional. Streaming was deliberately gated; non-streaming
was not.

## 2. Risk

`ModelAssets::parse_tool_calls` (`crates/rpc/src/model/assets.rs:138`) dispatches
on model architecture. Today the registered architectures are
`Qwen3ForCausalLM` / `Qwen3MoeForCausalLM`, the `Qwen3_5*` variants,
`Lfm2*`, and `Olmo2/3/Hybrid`. Concrete trip cases for each:

- **Qwen3** (`parse_qwen3_tool_calls`, catgrad-llm): when the output contains
  no `<tool_call>...</tool_call>` block, it falls back to
  `parse_raw_json_tool_call`, which calls `serde_json::from_str` on the entire
  trimmed output and accepts any object with a `name` field as a tool call.
  Concrete user prompts that trip this with no tools attached:
  - "Reply with a JSON object describing a person, with `name` and `age` keys."
  - "Echo back this JSON: `{\"name\": \"foo\", \"arguments\": {}}`"
  - any code-generation request whose final answer is a single JSON literal.
  The gateway returns `finish_reason: "tool_calls"` with empty content. A naive
  client treats this as a tool invocation for tool name `foo`.
- **Qwen3** with sentinel: the same parser fires on any text containing the
  literal substring `<tool_call>...</tool_call>`. Asking the model "show me an
  example of how Qwen3 emits tool calls" makes it produce exactly that string
  inside a code fence. The gateway rewrites the answer.
- **LFM2**: `<|tool_call_start|>...<|tool_call_end|>` markers anywhere in the
  output. Documentation, fine-tuning examples, or jailbreak-style discussions
  of the model's tokenizer hit this.
- **Olmo3**: `<function_calls>...</function_calls>`. Olmo's own training corpus
  includes documents that describe this format; the model can emit it inside a
  code block when asked to explain itself.

Beyond these specific patterns, the structural problem is that the gateway is
running an architecture-specific parser against arbitrary assistant prose
without the user's consent. The parser's safety properties were designed for
output that the model was *asked to produce* (i.e., tools were attached and
the chat template advertised the tool format). Applying them to free-form text
inverts that assumption.

The streaming side already enforces the right invariant. The non-streaming
side does not.

## 3. The Two Defensible Designs

There are two coherent positions on when to run the tool-call parser:

**(a) Gate strictly on the user passing tools.** If the request did not
include a tools array, never run the parser. The model was not given the tool
schema in its prompt, so any tool-shaped output is by definition not a real
tool call. This is what streaming already does.

**(b) Always run the parser, and require the parser to be false-positive-safe
on arbitrary text.** This means parsers must ignore syntactically valid
sentinels in code blocks, fenced regions, and quoted strings; the Qwen3
fallback `serde_json::from_str` path must be removed; LFM2 and Olmo3 must
detect when their sentinels appear inside a markdown fence.

Recommend (a). It is a one-line invariant ("parser runs iff the user passed
tools") and matches what streaming already does. (b) is a permanent ongoing
maintenance burden on the catgrad parsers and on every future architecture
that registers a parser. There is no client-visible benefit to running the
parser when the user did not ask for tools: even if the model spontaneously
emitted tool sentinels, a tool-less client has no executor to run the call,
and surfacing a `finish_reason: "tool_calls"` with no `tools` ever sent will
break agent frameworks that key on that signal.

## 4. Proposed Fix

Mirror the streaming gate in the non-streaming branch. One change per adapter.

OpenAI non-streaming, `crates/cli/src/commands/gateway/openai.rs:190`:

```rust
async fn respond(prepared: PreparedGeneration) -> Response {
    let (generated, text) = match prepared.run_to_text().await {
        Ok(result) => result,
        Err(err) => return err.into_response(),
    };

    let (message, finish_reason) = if prepared.has_tools {
        match prepared.parse_tool_calls(&text) {
            Ok(Some(step)) => (tool_call_message(&step), openai::FinishReason::ToolCalls),
            Ok(None)       => (openai::ChatMessage::assistant(text), openai::FinishReason::Stop),
            Err(err) => {
                warn!(error = %err, "failed to parse tool calls from generated text");
                (openai::ChatMessage::assistant(text), openai::FinishReason::Stop)
            }
        }
    } else {
        (openai::ChatMessage::assistant(text), openai::FinishReason::Stop)
    };
    // ... build response as before
}
```

Anthropic non-streaming, `crates/cli/src/commands/gateway/anthropic.rs:255`:

```rust
async fn respond(prepared: PreparedGeneration) -> Response {
    let (generated, text) = match prepared.run_to_text().await {
        Ok(result) => result,
        Err(err) => return err.into_response(),
    };

    let (content, stop_reason) = if prepared.has_tools {
        let step = prepared.parse_tool_calls(&text).unwrap_or_else(|err| {
            warn!(error = %err, "failed to parse tool calls from generated text");
            None
        });
        match step {
            Some(step) => (tool_use_blocks(&step), anthropic::StopReason::ToolUse),
            None => (vec![anthropic::ContentBlock::Text { text }], anthropic::StopReason::EndTurn),
        }
    } else {
        (vec![anthropic::ContentBlock::Text { text }], anthropic::StopReason::EndTurn)
    };
    // ... build response as before
}
```

Note the interaction with `GATEWAY_TOOL_PARSE_FAILURE.md`: that doc proposes
returning a 502 on `Err(_)` from the parser. That fix and this fix compose
cleanly. With `has_tools` gating in place, parser errors only occur when the
user actually asked for tools and the model emitted a malformed sentinel,
which is exactly the case where 502 is appropriate.

## 5. Why The Parser Is Or Isn't Safe Today

The parser is not robust against false positives on arbitrary text. Concrete
evidence from
`/home/grw/.cache/cargo/git/checkouts/catgrad-2aac55fc52f3041d/f4da359/catgrad-llm/src/helpers/tool_calls.rs`:

- `parse_qwen3_tool_calls` (line 23) falls through to
  `parse_raw_json_tool_call` (line 106) when no `<tool_call>` tag is found.
  That function calls `serde_json::from_str::<Value>(payload)` on the trimmed
  full output and `parse_json_tool_call_value` accepts any object with a
  `name: String` field, with `arguments` defaulting to empty if absent.
  Acceptance criterion is: "the entire model output is a JSON object with a
  string `name` key". This is a common shape for legitimate non-tool replies.
- `parse_qwen3_5_tool_calls`, `parse_lfm2_tool_calls`, and
  `parse_olmo3_tool_calls` use literal substring search (`output.find(start)`),
  not a tokenizer-aware or markdown-aware scanner. Sentinels inside fenced
  code blocks, inline backtick spans, or quoted prose all match. There is no
  attempt to skip tags inside ``` fences or `<pre>` blocks.
- `find_repeated_payloads` (line 465) treats an opening sentinel without a
  matching close as a hard error (`unterminated wrapped payload starting with
  ...`). Combined with the silent-demotion bug documented in
  `GATEWAY_TOOL_PARSE_FAILURE.md`, half-emitted sentinels in user-facing
  prose currently produce silent corruption of the response body even today.

Fixing the parser to be false-positive-safe would mean: removing the Qwen3
raw-JSON fallback entirely, adding markdown-fence awareness to all four
parsers, and writing a test corpus of "looks like a tool call but isn't".
That is much more work than gating on `has_tools`, and it has to be repeated
for every new architecture.

## 6. Test Strategy

Tests should not require a real model. Inject a stub `PreparedGeneration` (or
construct one whose `run_to_text` returns a chosen string and whose
`parse_tool_calls` records that it was called).

Cases per adapter, non-streaming:

1. **No tools requested, output looks like a Qwen3 tool call**: feed the
   string `{"name": "do_thing", "arguments": {}}` as the model text. Assert
   `finish_reason: "stop"` (OpenAI) / `stop_reason: "end_turn"` (Anthropic),
   assert the response body's content is exactly that string, assert
   `parse_tool_calls` was not called.
2. **No tools requested, output contains a literal `<tool_call>` block**:
   same model text but wrapped in `<tool_call>...</tool_call>`. Same
   assertions.
3. **No tools requested, output contains LFM2 / Olmo3 sentinels**: same
   pattern.
4. **Tools requested, output is a clean tool call**: regression guard.
   Existing behavior preserved.
5. **Tools requested, output is plain text**: regression guard. Existing
   `Stop` / `end_turn` behavior preserved.

The first three cases are the load-bearing ones. They directly assert the
invariant: if the user did not ask for tools, the response body is the raw
model output, character-for-character.

Streaming has its own pre-existing tests for the gate; mirror them so the
asymmetry cannot regress.
