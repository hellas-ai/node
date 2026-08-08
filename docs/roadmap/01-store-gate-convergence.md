# 01 — The store and the quote gate must answer one question

## What is wrong

There are two unrelated notions of "does this node have that model".

- **The store** (`crates/store`) indexes by **content id**. This is what
  `hellas store adopt` populates.
- **The quote gate** (`crates/models/src/hf.rs`, `Reach::Local`)
  resolves by **HuggingFace cache path**.

Verified: the quote gate references `hellas_store` nowhere.

## Why it matters

`hellas store adopt` does not make a model quotable. An operator who
adopts a cache and then watches quotes refuse has been told two
different things by one program. Worse, it is silent — both subsystems
are individually correct.

It also means the store's chunk lists — the thing that makes a peer's
partial response verifiable — are not consulted on the path that decides
whether we can serve a model at all.

## Done looks like

One presence question with one answer. Options, in rough preference
order:

1. The gate asks the store. Requires the store to know the mapping from
   `(model, revision, dtype)` to the content ids of that model's files —
   i.e. the manifest becomes a store-resident object, not something
   recomputed. This is the principled answer and the most work.
2. The store adopts *paths* as well as ids, so `adopt` registers the
   snapshot layout the gate resolves against. Cheaper, keeps two
   indexes but makes one populate the other.

Whichever: `hellas store adopt` followed by a quote for an adopted model
must succeed, and there must be a test that says so.

## Watch out for

- Presence is not integrity. The gate stats paths; hashing happens later
  when the manifest is built. Do not let convergence quietly turn a
  path check into an implied content guarantee.
- The gate's locality is currently **structural** — under `Reach::Local`
  the resolver holds no hub client (`api: None`). Do not regress that
  into a boolean during the refactor.
