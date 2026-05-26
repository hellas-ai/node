# Tool Call ID Uniqueness in the Gateway

## 1. The Bug

The OpenAI- and Anthropic-compatible gateway endpoints mint tool-call ids from a
positional index local to a single response. The OpenAI side at
`crates/cli/src/commands/gateway/openai.rs:254-264`:

```rust
fn tool_call_value(index: usize, call: &ToolCall) -> Value {
    let arguments = serde_json::to_string(&call.arguments).unwrap_or_else(|_| "{}".to_string());
    json!({
        "id": format!("call_{index}"),
        "type": "function",
        "function": {
            "name": call.name,
            "arguments": arguments,
        },
    })
}
```

The Anthropic side has the same shape at
`crates/cli/src/commands/gateway/anthropic.rs:225` (streaming) and
`crates/cli/src/commands/gateway/anthropic.rs:301` (non-streaming):

```rust
content_block: anthropic::ContentBlock::ToolUse {
    id: format!("toolu_{call_idx}"),
    name: call.name.clone(),
    input: Value::Object(Map::new()),
},
```

```rust
blocks.push(anthropic::ContentBlock::ToolUse {
    id: format!("toolu_{idx}"),
    name: call.name.clone(),
    input: Value::Object(call.arguments.clone()),
});
```

Both sites consume the per-response `enumerate()` index. The first tool call in
*every* response is `call_0` / `toolu_0`, the second is `call_1` / `toolu_1`,
and so on. Within a single response the ids are unique, but they are not
unique across responses in the same conversation, and they are not unique
across the process.

A process-monotonic counter helper already exists in
`crates/cli/src/commands/gateway/mod.rs:146-149`:

```rust
fn next_id(prefix: &str) -> String {
    let n = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    format!("{prefix}-{n}")
}
```

It is used for `chatcmpl-N` (`openai.rs:38`, `openai.rs:215`), `msg-N`
(`anthropic.rs:33`, `anthropic.rs:274`), and `cmpl-N` (`plain.rs`), but not for
tool-call ids.

## 2. Concrete Failure Scenario

Consider an OpenAI client driving a three-turn conversation that involves tool
calls. The client appends both the assistant's tool-call message and the
matching tool-result messages to the running history, exactly as the OpenAI
spec requires, and replays the full history on each turn.

Turn 1, request:

```text
[ {role:"user", content:"What is the weather in Paris and London?"} ]
```

Turn 1, response (gateway emits two parallel tool calls):

```json
{"role":"assistant","tool_calls":[
  {"id":"call_0","function":{"name":"get_weather","arguments":"{\"city\":\"Paris\"}"}},
  {"id":"call_1","function":{"name":"get_weather","arguments":"{\"city\":\"London\"}"}}
]}
```

The client runs both tools and appends:

```json
{"role":"tool","tool_call_id":"call_0","content":"sunny, 22C"}
{"role":"tool","tool_call_id":"call_1","content":"cloudy, 14C"}
```

Turn 2 history sent to the gateway now contains `call_0` and `call_1` as
historical references. The gateway answers. The user follows up:

```text
"Now also check Berlin and Madrid."
```

Turn 3, response (gateway emits two more parallel tool calls):

```json
{"role":"assistant","tool_calls":[
  {"id":"call_0","function":{"name":"get_weather","arguments":"{\"city\":\"Berlin\"}"}},
  {"id":"call_1","function":{"name":"get_weather","arguments":"{\"city\":\"Madrid\"}"}}
]}
```

The client now has four historical tool calls and two pending ones, all using
ids drawn from the set `{call_0, call_1}`. When the client builds the next
request and includes the new tool results:

```json
{"role":"tool","tool_call_id":"call_0","content":"7C, snow"}
{"role":"tool","tool_call_id":"call_1","content":"18C, sunny"}
```

The OpenAI message-sequence rules require each `tool` message to refer to a
`tool_call_id` from the immediately preceding assistant `tool_calls` block, and
several SDKs and frameworks index tool messages by that id to thread results
back to the originating call. Anything that holds the full transcript and
indexes by id - LangChain agents, chat-history stores, log/trace UIs, the
Anthropic-compatible bridge inside our own state.rs - sees four entries
keyed by `call_0` and four entries keyed by `call_1` and cannot tell prior
turns' calls from current ones.

The Anthropic side has the identical shape: `toolu_0` and `toolu_1` are reused
in turn 3 even though the conversation already contains historical `toolu_0`
and `toolu_1` references. Our own state-conversion code preserves these ids
verbatim when round-tripping (`state.rs:394-400`):

```rust
anthropic::ContentBlock::ToolUse { id, name, input } => {
    let arguments = serde_json::to_string(&input).unwrap_or_else(|_| "{}".to_string());
    tool_calls.push(serde_json::json!({
        "id": id,
        "type": "function",
        "function": { "name": name, "arguments": arguments },
    }));
}
```

So a `toolu_0` minted three turns ago and a `toolu_0` minted now collide
inside the OpenAI-shape history we hand to the chat template.

## 3. What Real Clients Require

The wire-level OpenAI Chat Completions and Anthropic Messages APIs do not
strictly reject duplicate tool-call ids on input. Uniqueness is a downstream
contract enforced by clients and tooling that consume the responses:

- The OpenAI Python SDK and JS SDK return `tool_calls` as an array of objects
  with a string `id` and pass that id through to user code; documentation and
  examples treat the id as the stable handle for matching tool results back to
  calls. Helper utilities such as `openai.types.chat.ChatCompletionMessageToolCall`
  and the streaming aggregator key partial deltas by id.
- LangChain's OpenAI integration stores `tool_call_id` on `ToolMessage` and
  uses it to thread tool outputs back into agent state. Its `AgentExecutor`
  loops pair tool invocations to results by id; collisions cause earlier results
  to be overwritten or attributed to the wrong call.
- The `instructor` library and several function-calling agent frameworks build
  a dict keyed by `tool_call_id` to dispatch to local Python functions and to
  collect their outputs. A repeated id silently drops the earlier entry.
- Trace and observability tooling (LangSmith, OpenTelemetry GenAI semantic
  conventions, internal logs) treat `tool_call_id` as a span correlation key.

In practice every consumer that retains conversation history beyond a single
request expects tool-call ids to be unique within at least the conversation,
and treats process-unique or globally-unique ids as the safe default.

## 4. Proposed Fix

Use the existing `next_id` helper for tool-call ids and drop the positional
index from the id. The minimum change at
`crates/cli/src/commands/gateway/openai.rs`:

```rust
fn tool_call_value(_index: usize, call: &ToolCall) -> Value {
    let arguments = serde_json::to_string(&call.arguments).unwrap_or_else(|_| "{}".to_string());
    json!({
        "id": super::next_id("call"),
        "type": "function",
        "function": {
            "name": call.name,
            "arguments": arguments,
        },
    })
}
```

And at `crates/cli/src/commands/gateway/anthropic.rs`, in both
`emit_tool_use_block` and `tool_use_blocks`:

```rust
id: super::next_id("toolu"),
```

`next_id` already wraps a process-wide `AtomicU64` and is in the same module,
so this is a one-line substitution per site. Output ids become
`call-<n>` / `toolu-<n>` where `<n>` monotonically increases for the lifetime
of the gateway process. Two parallel calls inside one response receive
adjacent but distinct ids; two calls in different responses are guaranteed
distinct.

If a stronger guarantee is wanted (ids unique across process restarts and
across multiple gateway instances behind a load balancer, e.g. for
distributed tracing), use UUIDv7 via the `uuid` crate:

```rust
let id = format!("call_{}", uuid::Uuid::now_v7().simple());
```

UUIDv7 keeps lexicographic order matching creation time, which preserves the
debuggability the current `_0`, `_1` ordering provided.

The Anthropic stream emits the id inside a `content_block_start` event and
references the same content block by index inside the matching
`content_block_delta` and `content_block_stop` events; the change is local to
the id field and does not touch the index sequencing.

The two Anthropic sites should share a small helper so the streaming and
non-streaming paths cannot diverge. Today `emit_tool_use_block` builds the
`ContentBlock::ToolUse` inline and `tool_use_blocks` builds a similar value
separately; routing both through a single constructor that calls
`next_id("toolu")` removes the duplication and the chance that a future change
fixes one path but not the other.

## 5. Stability for Existing Clients

The current id format is not a stable contract. No client has any reason to
parse `call_0` or `toolu_0` into a structured value; both are opaque tokens
the client must echo back verbatim in subsequent tool-result messages. The
wire shapes of the OpenAI and Anthropic APIs explicitly treat `id` and
`tool_use_id` as opaque strings.

Changing the format from `call_<n>` to `call-<n>` (or to a UUIDv7) is safe in
both directions: clients that have stored ids from previous responses continue
to use those exact strings, and the gateway never compares newly minted ids
against historical ones. The conversion path in `state.rs` already accepts an
arbitrary id string and round-trips it without inspection
(`state.rs:362-381`, `state.rs:394-400`), so historical ids minted under the
old scheme remain valid as `tool_call_id` references inside continuing
conversations.

## 6. Test Strategy

The current tests in `crates/cli/src/commands/gateway/state.rs:684-829` only
exercise the request-side conversion using literal `toolu_1` / `toolu_2`
inputs - they assert that an id supplied by the *client* round-trips through
the Anthropic-to-OpenAI conversion, not that the ids the *gateway emits* are
unique.

Add tests that exercise the response-side minting:

1. Mint two ids in succession and assert inequality:

   ```rust
   #[test]
   fn tool_call_ids_are_process_unique_across_calls() {
       let call = ToolCall { name: "x".into(), arguments: Default::default() };
       let a = tool_call_value(0, &call);
       let b = tool_call_value(0, &call);
       assert_ne!(a["id"], b["id"]);
   }
   ```

2. Mint a vector of ids inside one response and across two simulated
   responses, collect into a `HashSet`, and assert no collisions:

   ```rust
   let mut seen: HashSet<String> = HashSet::new();
   for _response in 0..3 {
       for idx in 0..2 {
           let id = tool_call_value(idx, &call)["id"].as_str().unwrap().to_string();
           assert!(seen.insert(id), "duplicate tool_call id minted");
       }
   }
   ```

3. Optionally, assert monotonic ordering by parsing the trailing counter -
   useful for debug-log readability but not a correctness requirement.

The Anthropic side needs equivalent tests against `tool_use_blocks` and
`emit_tool_use_block`. Update the existing assertions at `state.rs:715`,
`state.rs:827-828` only if those tests are repurposed to also cover gateway
emission; the round-trip tests as written exercise client-supplied ids and
should keep their literal values.
