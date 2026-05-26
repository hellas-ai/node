# Empty-String model_id in Executor Metrics

## 1. The Bug

`crates/executor/src/executor/actor/execution.rs:174-186` (current working
tree) handles execution completion with:

```rust
let generated = self.store.progress(execution_id).unwrap_or(0);
let model_id = self
    .store
    .model_id(execution_id)
    .ok()
    .map(str::to_owned)
    .unwrap_or_default();
if success {
    self.metrics
        .record_execution_completed(&model_id, generated);
} else {
    self.metrics.record_execution_failed(&model_id, generated);
}
```

When `self.store.model_id(execution_id)` returns `Err(StateError::ExecutionNotFound)`,
`.ok()` yields `None` and `.unwrap_or_default()` substitutes `""`. That empty
string then flows into `ExecutorMetrics::record_execution_completed` /
`record_execution_failed`. Both of those functions unconditionally call
`note_model(model_id)` (`crates/executor/src/metrics.rs:145-154`), which:

- inserts the empty string into `seen_models: Mutex<BTreeSet<String>>`, and
- builds `ModelLabel { model_id: "".to_string() }` and calls
  `Family::get_or_create(&label).inc(...)` on every per-model counter.

There is no skip path for `model_id == ""`. The pre-refactor code held
`Option<String>` and gated all per-model bookkeeping behind `if let Some(...)`.
The current code lost that gate during the metrics consolidation.

## 2. The Effect

Once `handle_complete` runs with a missing model id even once, the executor
process retains an empty-string entry forever:

- Prometheus scrapes show a per-model series with `model_id=""` for every
  `hellas_model_*` counter family (`executions_started`, `executions_completed`,
  `executions_failed`, `prompt_tokens`, `cached_prompt_tokens`,
  `cached_output_tokens`, `prefill_tokens`, `generated_tokens`).
- `seen_models` retains `""`, so `ExecutorMetrics::known_model_ids()` returns
  it and the GetStats RPC produces a `model_stats[]` entry with `model_id = ""`,
  visible to any caller of `Executor::get_stats`.
- Dashboards and alerts that group by `model_id` get a phantom row that
  silently aggregates whatever the failure path observed (typically failures,
  but `record_execution_completed` is reachable too if the store ever drops a
  successful execution before `handle_complete` reads its model id).
- Restarting the process clears the in-memory `Family` and `seen_models`, but
  the Prometheus TSDB retains historical samples for the configured retention
  window.

## 3. When Does model_id() Actually Fail

`ExecutorState::model_id` (`crates/executor/src/state/store.rs:122-124`)
only returns `StateError::ExecutionNotFound` when no `ExecutionRecord` exists
for the supplied id. The current callers of `handle_complete` are:

- `try_start_execution` on the `Stopped(_job)` branch — the execution was
  inserted by `handle_execute` and `mark_running` may or may not have
  succeeded, but the record is still present. `model_id` lookup succeeds.
- `cancel_pending_execution` — the record was inserted by `handle_execute`
  before the job was queued. Lookup succeeds.
- `Executor::handle_worker_event` paths reporting `Completed` / `Failed` from
  the worker — the record exists for the entire lifetime of the worker job.

In normal flow the lookup never fails. The only ways for it to fail are:

1. A future caller removes the execution record before `handle_complete` runs.
2. `handle_complete` is called with an `execution_id` that was never created
   (programming error).
3. A future refactor adds a path that removes the record on early failure
   (currently `handle_execute` does this on `accept_execution` error, but it
   also returns directly afterwards without calling `handle_complete`).

In all three cases the failing call represents either lost state or a state
machine bug, not a real completed execution that legitimately lacks a model
id. The empty-string substitution silently turns these errors into permanent
metric pollution rather than surfacing them.

## 4. Proposed Fix

Recommended: option (a) — propagate `Option<String>`, skip the per-model
family when None, still bump global counters, and log when the lookup fails
so the underlying state-machine issue is visible.

The metrics functions accept the model id; the smallest change is to keep
`Option<&str>` at the boundary and have the per-model branch be a no-op when
the id is missing. Edit `crates/executor/src/executor/actor/execution.rs`:

```rust
let generated = self.store.progress(execution_id).unwrap_or(0);
let model_id = match self.store.model_id(execution_id) {
    Ok(id) => Some(id.to_owned()),
    Err(err) => {
        warn!(%execution_id, %err, "model_id lookup failed at completion");
        None
    }
};
if success {
    self.metrics
        .record_execution_completed(model_id.as_deref(), generated);
} else {
    self.metrics
        .record_execution_failed(model_id.as_deref(), generated);
}
```

And in `crates/executor/src/metrics.rs`, change the three recorders to take
`Option<&str>` and only touch `seen_models` / the per-model `Family` when the
id is `Some`:

```rust
pub(crate) fn record_execution_completed(&self, model_id: Option<&str>, generated: u64) {
    self.generated_tokens.inc_by(generated);
    self.executions_completed.inc();
    if let Some(model_id) = model_id {
        let label = self.note_model(model_id);
        self.by_model_generated_tokens
            .get_or_create(&label)
            .inc_by(generated);
        self.by_model_executions_completed
            .get_or_create(&label)
            .inc();
    }
}
```

Apply the same shape to `record_execution_failed` and `record_execution_started`
(the start path already has `model_id` available from the quote, so it will
always pass `Some`, but the signature change keeps the contract uniform).

Additionally, `note_model` should reject empty strings as a defensive guard:

```rust
fn note_model(&self, model_id: &str) -> Option<ModelLabel> {
    if model_id.is_empty() {
        return None;
    }
    // ... existing body, returning Some(ModelLabel { ... })
}
```

This catches future callers that bypass the `Option` boundary by passing a
string they obtained from `unwrap_or_default()`.

Option (b) — drop the metric entirely when `model_id` is unknown — discards
information about a real completion event from the global counters. That
makes the totals understate reality, which is worse than a known
instrumentation gap.

Option (c) — fix the upstream so the lookup never fails — is correct in the
limit but does not protect against future regressions. Combine it with (a):
keep the lookup that should always succeed, log when it does not, and skip
per-model bookkeeping rather than fabricating a label.

## 5. Test Strategy

Add a unit test against `ExecutorMetrics` that records a completion with
`None`:

```rust
#[test]
fn missing_model_id_does_not_pollute_per_model_family() {
    let metrics = ExecutorMetrics::default();
    metrics.record_execution_completed(None, 7);

    assert_eq!(metrics.global_snapshot().executions_completed, 1);
    assert_eq!(metrics.global_snapshot().generated_tokens, 7);
    assert!(metrics.known_model_ids().is_empty());
    assert_eq!(metrics.model_snapshot("").executions_completed, 0);
}
```

Add a sibling test for `record_execution_failed` and confirm that a normal
recording with `Some("model-x")` still increments both global and per-model
counters.

Add an executor-actor test (alongside the existing tests in
`crates/executor/src/executor/actor/tests.rs`) that constructs an executor,
calls `handle_complete` with an `execution_id` that was never created, and
asserts:

- `metrics.known_model_ids()` does not contain `""` (or anything else),
- `metrics.global_snapshot().executions_failed == 1`.

This exercises the fallback path end-to-end without relying on a fake store.

## 6. Cleanup of Existing Pollution

Any executor process that hit this path before the fix lands carries `""`
in its in-memory `Family` and `seen_models` for the rest of its lifetime.
A restart clears the in-process state. There is no way for the executor to
retroactively retract a series.

Prometheus TSDB samples for `model_id=""` persist for the configured
retention window. Two options:

- Wait for retention to age the samples out. This is the default and requires
  no operator action.
- Use `tsdb delete-series` with a matcher like `{model_id=""}` against the
  Prometheus admin API on each affected scrape target. This is invasive and
  only useful if the empty-id rows are actively breaking dashboards or
  alerting rules.

Dashboards and recording rules that aggregate by `model_id` should add a
defensive `model_id != ""` matcher until the historical pollution ages out.
After the fix is deployed and retention has rolled forward, the matcher can
be removed.
