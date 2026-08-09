# 06 — Three small defects, found and reported

**Landed.** Unrelated to each other; grouped because each is small. One
of the three turned out to be misdiagnosed, and the answer taken is not
the one this file first proposed.

## 6a. A BF16 capability that always fails

**The diagnosis was wrong, and the bug was real.**

This file blamed `crates/cli/src/main.rs`'s
`if is_local_mode && !cuda_or_metal` for a provider advertising BF16.
`default_llm_dtypes` is not an advertisement: it is the preference list
`hellas llm` *asks a provider for*, used at `main.rs:837` and nowhere
else. A serving node's dtypes come from `serve --dtype`, which already
defaults per build via `DEFAULT_DTYPE_STR`.

Worse, the proposed fix — `!cuda_or_metal` alone — would have broken the
ordinary case. A GPU provider defaults to `--dtype bf16`, a single
entry; `resolve_accept_dtypes` refuses anything not in that list. A CPU
laptop asking f32 first would be refused, retry f16, be refused again,
and never run.

The real hole is one storey down: **capability is derived from build
features, and the device is a runtime fact**.
`CandleBackend::new_accel(true)` falls back to `Device::Cpu` when no
CUDA or Metal device is present (catgrad `candle.rs`), so a
`candle-cuda` build on a host with no GPU serves BF16 from a CPU device
— where candle *panics* rather than erring. `worker.rs` catches the
panic and fails the job, so every accepted job fails after reading
gigabytes. Under the staked flow that is work the provider committed to
and can never deliver.

**Landed:** `backend::runnable_dtypes` filters the advertised list by
what the selected device can run, once, at executor spawn. A node left
with nothing it can serve refuses to start and names the mismatch. The
CLI's list is unchanged, and its doc comment now says why network mode
asks for BF16 from a CPU build on purpose.

## 6b. Unvalidated path join from attacker-supplied filenames

`crates/models/src/hf.rs` joined weight-map filenames onto the snapshot
root. Those names come from the model's own
`model.safetensors.index.json` — i.e. from the repository the caller
named — and a `..` component walked out of the snapshot to any file this
process can read, which was then opened and hashed.

Still unproven as an oracle: the per-file id is not returned to the
caller, only the manifest's aggregate `ContentId`.

**Landed:** every component of a weight-map name must be a plain name,
checked before anything is opened, refused as
`WeightFileOutsideSnapshot`. Shards in a subdirectory still resolve;
`..`, absolute paths and `.` do not.

## 6c. The gateway still fetches on demand

`crates/gateway/src/state.rs` uses `Reach::Download`, deliberately: the
gateway is the operator's own client-side process and tokenizes for
requests it is itself submitting.

**Unchanged, with the reasoning written where a deployer meets it** —
the doc on `GatewayState::model_assets` and `hellas gateway --help`.
What it says: loopback is the entire access control, there is no inbound
authentication in the crate, and `--host 0.0.0.0` or a reverse proxy
hands every caller a remote fetch primitive, because the model id comes
from the request body. `--force-model` is the only thing today that
takes that choice away.

**Left for George:** whether the gateway is ever exposed to untrusted
callers. If it is, it wants the executor's treatment — a local-reach
mode or a model allowlist — and that is a decision, not a cleanup.
