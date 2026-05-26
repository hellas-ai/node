# Model Load Lock Map Growth in the Gateway

## 1. The Pattern

`crates/cli/src/commands/gateway/state.rs:46` declares:

```rust
model_load_locks: Arc<Mutex<HashMap<String, Arc<Mutex<()>>>>>,
```

`GatewayState::model_assets` (`state.rs:146-180`) uses it to deduplicate
concurrent loads of the same model. The flow is:

```rust
// 1. fast path: hit the populated cache
let cache = self.model_cache.read().await;
if let Some(assets) = cache.get(model) { return Ok(assets.clone()); }

// 2. acquire (or create) the per-model load lock
let load_lock = {
    let mut locks = self.model_load_locks.lock().await;
    locks.entry(model.to_string())
         .or_insert_with(|| Arc::new(Mutex::new(())))
         .clone()
};
let _load_guard = load_lock.lock().await;

// 3. recheck cache, then ModelAssets::load on a blocking pool
```

The purpose is correct and necessary: without this lock, two concurrent requests
for the same uncached model would both spawn a `spawn_blocking` load, doubling
disk and memory traffic and racing each other into `model_cache`.

## 2. The Bug

The `model_load_locks` map only ever grows. Each unique `req.model` string seen
by the gateway permanently inserts one entry of:

```text
String key + Arc<Mutex<()>> + HashMap bucket overhead
```

There is no removal path on success, no removal on failure, no TTL, no LRU, no
size cap. `model_cache` grows similarly, but only on a successful
`ModelAssets::load`, so its growth is bounded by what actually loads. The lock
map is populated before the load is attempted, so even loads that error keep
their entry forever.

`force_model` (`state.rs:99,108-112`) bypasses the request-supplied model name
when set, so production deployments that pin a model are immune. The default
configuration is not.

## 3. Threat Model

This matters when:

- `force_model` is `None`.
- The gateway is reachable by callers who can supply arbitrary `req.model`
  strings (the gateway endpoints in `anthropic.rs`, `openai.rs`, and the plain
  completion handler all accept `req.model` verbatim).
- The process is long-running.

Per-entry cost: one `String` key (24 bytes header plus heap-allocated bytes for
the model name, often 30-80 bytes), one `Arc<Mutex<()>>` (the `Arc` is 16 bytes
of header plus a heap allocation containing a `Mutex<()>` which on Linux is a
`tokio::sync::Mutex` at roughly 64 bytes), plus the `HashMap` bucket and hash
overhead. Realistic budget is 150-250 bytes per unique string in steady state,
several times more during rehashes.

At 150 bytes per entry, one million unique random model strings cost ~150 MB
of resident memory and proportionally hurt every subsequent map lookup because
the inner `tokio::sync::Mutex` serializes every model resolution. A single
attacker sending one request per millisecond reaches that cost in under twenty
minutes. Even at lower rates this becomes a slow leak over weeks.

The contention impact is worse than the memory impact. Every model lookup
takes the outer `model_load_locks` mutex, so a bloated map means every
legitimate request waits behind a longer linear hash probe and grows the
critical section.

## 4. Proposed Fix Options

(a) **Remove entry on lock release** using `Arc::strong_count` checks against a
    `Weak` held inside the map. This is fiddly: the natural place to drop the
    entry is after `_load_guard` is released, but at that point another waiter
    may already hold an `Arc` clone. Workable but error-prone.

(b) **Periodic cleanup task** that walks the map and removes entries whose
    `Arc::strong_count` is one. Simple, but adds a background task and races
    with new lock acquisitions unless the cleanup re-takes the outer mutex.

(c) **Bounded LRU** (`hashlink::LruCache` or equivalent), capped at, e.g.,
    256 entries. New requests beyond the cap evict the oldest entry; the
    evicted entry's `Arc` stays alive for any in-flight waiter, so correctness
    is preserved (deduplication merely degrades for evicted models).

(d) **Up-front allowlist validation** of `req.model` against either
    `force_model` (already done) or a known-models registry (e.g., the set of
    models currently in `model_cache` plus a configured allowed list). Reject
    unknown models with `404 model_not_found` before the lock map is touched.
    This bounds growth by the number of legitimate models the deployment is
    willing to serve.

**Recommendation:** (d) as the primary defense, with (c) as defense in depth.

(d) eliminates the attack surface: the map can only grow by the number of
allowed models, which is finite by configuration. (c) bounds worst-case
behavior even if the allowlist is misconfigured or omitted. Together they cost
roughly:

```rust
// in GatewayOptions
pub allowed_models: Option<Vec<String>>,

// in GatewayState
allowed_models: Option<HashSet<String>>,
model_load_locks: Arc<Mutex<LruCache<String, Arc<Mutex<()>>>>>,

// in model_assets, before touching model_load_locks:
if let Some(allowed) = &self.allowed_models {
    if !allowed.contains(model) {
        anyhow::bail!("model `{model}` is not in the allowed models list");
    }
}
```

`force_model` is a special case of an allowlist of size one, so the existing
flag can be folded into the same check.

The same allowlist gating should be applied to `model_cache` for symmetry,
even though only successful loads reach it. A failed load does not insert,
but `ModelAssets::load` for a long unrecognized HuggingFace repo name can do
substantial network work before failing.

## 5. Test Strategy

Add a unit test against `GatewayState::model_assets` (or a small extracted
`acquire_load_lock` helper) that:

1. Constructs a `GatewayState` with `allowed_models = None` and a small LRU
   cap (say 4) for the test build.
2. Issues `cap + 8` calls to `model_assets` for distinct model names. Each
   call may legitimately fail because the model does not exist on disk; the
   assertion is on the lock map size, not on the load result.
3. Asserts `state.model_load_locks.lock().await.len() <= cap`.

Add a second test with `allowed_models = Some(["a", "b"])`:

1. Calls `model_assets("c")`; expect a `model_not_found`-style error.
2. Asserts that `model_load_locks` is empty afterwards (the lock entry must
   not be created for rejected models).

Both tests are pure CPU and do not require a real `ModelAssets::load` to
succeed; they exercise only the gate and the lock map.
