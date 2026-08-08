# 06 — Three small defects, found and reported, not yet fixed

Unrelated to each other. Grouped because each is small.

## 6a. CPU providers advertise BF16, which always fails

`crates/cli/src/main.rs:147`:

```rust
if is_local_mode && !cuda_or_metal { vec![F32, F16] } else { vec![BF16, F32, F16] }
```

A provider **serving the network** on a CPU build takes the `else`
branch and advertises BF16. Candle then **panics** —
`panic!("BF16 is only supported by Candle on CUDA/Metal devices")`,
`catgrad/src/interpreter/backend/candle.rs:389` — not an error.

It is contained: `worker.rs:144` catches it and fails the job. So not a
crash, but a capability advertised that can never succeed, after
reading gigabytes. Under the staked flow that is an accepted job the
provider committed to and will always fail.

The doc comment above the function enumerates network mode, local+GPU
and local+CPU — network+CPU is not mentioned, which reads like the case
fell through the condition rather than being chosen.

**Fix:** either the condition (`!cuda_or_metal` alone) or make catgrad
return an error instead of panicking. Both, ideally. **Needs a product
decision**: should a CPU provider serve the network at all?

## 6b. Unvalidated path join from attacker-supplied filenames

`crates/models/src/hf.rs:121` joins a filename onto the snapshot root.
Those filenames come from the model's own `model.safetensors.index.json`
`weight_map` — i.e. from the repository the caller named. A `../..`
component escapes the snapshot directory; the resulting file is read and
hashed.

**Unproven.** The hash is not returned to the caller — only the
manifest's aggregate `ContentId` goes on the wire — so no oracle was
constructed. `hf-hub`'s own write path was not audited.

**Fix:** reject any component that is not a plain filename. Cheap,
and removes the need to reason about whether an oracle exists.

## 6c. The gateway still fetches on demand

`crates/gateway/src/state.rs` uses `Reach::Download`. Deliberate — it is
client-side — but a gateway exposed to untrusted HTTP callers is the
same door as the quote path was, one storey down.

**Decide:** is the gateway ever exposed to untrusted callers? If yes it
needs the same treatment. If no, write that down where someone
deploying it will read it.
