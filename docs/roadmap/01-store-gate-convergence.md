# 01 — The store and the quote gate must answer one question

**Landed.** What follows is the problem as found, the answer taken, and
the part that is still two things.

## What was wrong

There were two unrelated notions of "does this node have that model".

- **The store** (`crates/store`) indexes by **content id**. This is what
  `hellas store adopt` populates.
- **The quote gate** (`crates/models/src/hf.rs`, `Reach::Local`)
  resolves by **HuggingFace cache path**.

Verified at the time: the quote gate referenced `hellas_store` nowhere.

So `hellas store adopt --cache /data/hf` did not make a model quotable.
An operator who adopted a cache and then watched quotes refuse had been
told two different things by one program, silently, because both
subsystems were individually correct — about different disks.

## What landed

Approach 2 of the two below, at the granularity of a **cache root**.

`adopt` records the root it indexed in `adopted-caches`, beside the
fastresume record. `Reach::Local` resolution consults the environment's
cache first and then every recorded root. `hellas store adopt` followed
by a quote for a model in that cache now succeeds, and
`crates/models/tests/adopted_cache_is_quotable.rs` says so end to end,
with the same call before adopting as its control.

Why not approach 1 — the gate asking the store by content id. It needs
the store to hold a `(model, revision)` → ids map, which only the
manifest builder can compute, and which would then be a *content* claim
consulted by a *presence* check. That is precisely the conflation the
warning below exists to prevent: the gate would start answering "we hold
these bytes" from a remembered id rather than from a `stat`. A cache
root is the unit both halves already speak, so making one populate the
other needed no new claim at all.

## What is still separate

- The store's index is still by content id; the gate still resolves by
  path. They now share one input — which caches this node adopted — but
  they are not one lookup.
- The chunk lists are still not consulted on the path that decides
  whether we can serve a model. Nothing about presence is verifiable
  from a peer's partial response yet; that is [03](03-peer-fetch.md).
- Nothing maps a model to its content ids without building a manifest,
  so [05](05-manifest-memo.md) is unchanged by this.

## Watch out for — both preserved

- Presence is not integrity. The registry is a list of places to look.
  It carries no ids and asserts nothing about any file. The gate still
  stats; the bytes are still hashed when the manifest is built.
- The gate's locality is still **structural** — under `Reach::Local` the
  resolver holds no hub client (`api: None`), only a longer list of
  directories. Reading the registry spends no network.
