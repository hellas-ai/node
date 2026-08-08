# 02 — catgrad stops loading models

## What is wrong

`crates/executor/src/model.rs:33` still calls
`catgrad_llm::utils::load_model(model, revision, ...)`, which resolves
files through `hf-hub` and **downloads whatever it does not find**.

It now sits behind a quote that verified local presence, so in practice
it finds the files. But nothing *stops* it fetching — if files vanish
between quote and run, or catgrad wants a file outside the checked set,
a node fetches from HuggingFace during execution.

## The seam already exists and is public

Read at the pinned rev `7629a50`
(`~/.cache/cargo/git/checkouts/catgrad-8531093d3d852bf9/7629a50`):

```rust
// catgrad-llm/src/utils/mod.rs:451
pub fn load_model_weights<B: interpreter::Backend>(
    model_paths: Vec<PathBuf>, backend: &B, dtype: Dtype,
    expert_count: Option<usize>,
) -> Result<(Parameters<B>, typecheck::Parameters, usize)>
```

It takes materialized paths and touches nothing else. All the network in
`load_model` is confined to `get_model_files` (`:72`).
`catgrad_llm_models::utils::get_model` is *structurally* pure —
`catgrad-llm-models` has no I/O dependency at all — so it is safe to
call before anything is materialized.

## One blocker, one line, in a repo we own

`get_num_experts` (`catgrad-llm/src/utils/mod.rs:232`) is private, and
it is the correct fourth argument. Get it wrong and MoE models silently
load their experts unpacked and mismatch the graph. Make it `pub` rather
than copying a silent-failure heuristic into this tree.

## Worth doing at the same time

Put `hf-hub`/`ureq` and `get_model_files` behind a non-default `hub`
feature in catgrad. Then "catgrad cannot fetch" is enforced by the
linker rather than by discipline — which is the claim we actually want
to make about a confidential executor. `catgrad-llm` currently has **no
`[features]` section at all**, so those deps are unconditional.

## Constraints discovered

- **catgrad's currency is paths.** No `&[u8]`, no pre-mmapped variant.
  Whatever the store hands over must be a real file path.
- **It mmaps, then copies.** Every tensor is decoded into a fresh owned
  `Vec` even BF16→BF16. On CPU candle takes that Vec without copying, so
  a 14 GB model is ~14 GB anonymous RSS. Dtype expansion multiplies: a
  BF16 file loaded as F32 is 28 GB.
