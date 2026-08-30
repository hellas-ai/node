# Hellas

Hellas executes exact, token-native Catena packages locally
or across the network. The node owns package materialization; remote peers can
select only an operator-configured alias and can never make it fetch or load an
arbitrary path.

## Execution boundary

There are three deliberately separate layers:

| Layer | What it binds |
| --- | --- |
| Catena package identity | Exact program, executable artifacts, linking, executable token-ID/value adapter (not a tokenizer), vocabulary, and capacity |
| Hellas request and signed transcript | Exact package identity, input token IDs, maximum output, caller-selected stop IDs, generated token IDs, and termination reason |
| Local presentation | Prompt text, tokenizer, chat template, and decoded text |

Catena does not specify a tokenizer, chat template, decoder, or default stop
tokens. Hellas does not attest them either. The CLI's `--tokenizer` turns local
text into the token IDs that Hellas does bind, and turns verified output IDs
back into text. Stop IDs are explicit caller policy: repeat `--stop-token` or
comma-separate values. With no such option, only `--max-new-tokens` ends a
normal generation.

Package aliases are local routing names, not identities. For a remote request,
the caller supplies an exact package ID obtained through a trusted,
out-of-band path. The node must prove that its alias resolves to that ID before
the client accepts its quote. `ListPackages` is useful observation, but an
adversarial node is not an authority for the ID the caller expects.
Artifact-addressed requests carry no alias and therefore require an `id/...`
execute-policy rule (or `eager`); an alias rule cannot authorize them by
accident.

## Quickstart: SmolLM2

The examples assume the sibling Catena Runner checkout and an independently
obtained tokenizer JSON:

```bash
PACKAGE=smollm2-135m=../catena-runner/models/smollm2
TOKENIZER=/path/to/smollm2-tokenizer.json
```

Fetch and verify the package, then print the exact ID. The command writes only
the digest to stdout, so it is safe to use in a script:

```bash
PACKAGE_ID=$(cargo run -q -p hellas-cli --features evaluate -- \
  package id --package "$PACKAGE")
printf '%s\n' "$PACKAGE_ID"
```

Distribute that ID with the package through a trusted release channel. Do not
learn it from the node whose execution you are trying to verify.

Run locally. This fetches package artifacts into
`$HOME/.hellas/packages`, verifies them, compiles the package once, and then
executes it:

```bash
cargo run -p hellas-cli --features evaluate -- \
  llm --local --package "$PACKAGE" --tokenizer "$TOKENIZER" \
  --prompt 'The capital of France is'
```

Serve that package to remote callers:

```bash
cargo run -p hellas-cli --features evaluate -- serve \
  --execute-policy 'allow(package/smollm2-135m)' \
  --package "$PACKAGE"
```

`serve` loads every repeated `--package NAME=PATH` before binding. Its default
execution policy is `skip`; use `eager` only when intentionally serving every
package the operator loaded.

Run against a known node. `--provider` is the out-of-band 32-byte content ID
that anchors the remote node's identity; omit `NODE_ID` to use discovery:

```bash
cargo run -p hellas-cli --features evaluate -- \
  --provider "$PROVIDER_CONTENT_ID" \
  llm "$NODE_ID" --package smollm2-135m --package-id "$PACKAGE_ID" \
  --tokenizer "$TOKENIZER" \
  --prompt 'The capital of France is'
```

For a remote result checked against local Catena execution, use
`--verify-local` and pass `NAME=PATH`:

```bash
cargo run -p hellas-cli --features evaluate -- \
  --provider "$PROVIDER_CONTENT_ID" \
  llm "$NODE_ID" --verify-local --package "$PACKAGE" \
  --tokenizer "$TOKENIZER" --prompt 'The capital of France is'
```

Defaults are 16 new tokens, two discovery retries, retained artifacts, and no
stop IDs. Use `--retain=false` when the executor must not retain prompt- or
token-bearing artifacts.

## Qwen3-30B-A3B

Qwen is deliberately opt-in: its current Catena package names about 56.9 GiB
of weights. Use its own independent tokenizer and explicit stop policy. The
runner example currently uses stop IDs `151643` and `151645`:

```bash
cargo run -p hellas-cli --features evaluate -- \
  llm --local \
  --package qwen3-30b-a3b=../catena-runner/models/qwen \
  --tokenizer /path/to/qwen-tokenizer.json \
  --stop-token 151643 --stop-token 151645 \
  --prompt 'The capital of France is'
```

## HTTP gateway

Run a local gateway:

```bash
cargo run -p hellas-cli --features evaluate -- gateway --local \
  --package "$PACKAGE" --tokenizer "$TOKENIZER"
```

Or route it to a remote node:

```bash
cargo run -p hellas-cli --features gateway -- \
  --provider "$PROVIDER_CONTENT_ID" gateway \
  --node-id "$NODE_ID" --package smollm2-135m \
  --package-id "$PACKAGE_ID" --tokenizer "$TOKENIZER"
```

The gateway binds loopback and prints a fresh bearer token at startup. The
Hellas execution backend accepts plain text at `/v1/completions` and simple
text input at `/v1/responses`. Chat, message, reasoning, and tool inputs are
rejected because no chat template is implicit. Select the proxy or Fetch
Responses backend when those semantics come from another explicitly chosen
service.

The exposed routes are:

```text
POST /v1/completions
POST /v1/responses
POST /v1/chat/completions
POST /v1/messages
```

Monitor discovery and peer health:

```bash
cargo run -p hellas-cli -- monitor --timeout-secs 30
```

## Chain

The `chain` feature provides `chain query`, `chain open`, and `chain close`.
The `indexer` feature adds `chain indexer follow`; the `validator` feature adds
`chain validator config`, `chain validator run`, and
`chain validator check-config`.

`chain query --rpc URL` supports `latest-block`, `state-root`, `finalization`,
`finalized-block`, `coin`, `edge`, `validators`, `coins-by-owner`, and
`edges-by-owner`.

`chain open` reads each 32-byte secret scalar from `--maker-key FILE` and
`--taker-key FILE`; `--maker-auth` and `--taker-auth` accept `webauthn` or
`native`. Funding IDs use repeatable or comma-separated `--maker-funding` and
`--taker-funding`. Terms use `--protocol`, `--timeout`, and repeatable or
comma-separated `--timeout-payout SETTLEMENT_KEY:VALUE`. `--terms-out FILE`
writes the canonical reveal for a later timeout close.

`chain close --kind mutual` takes repeatable or comma-separated
`--payout SETTLEMENT_KEY:VALUE` plus both key and auth pairs. `--kind timeout`
takes the same committed payouts and `--terms-file FILE`, with no signer
options.

Stored ownership uses raw, untagged 33-byte settlement keys. P-256 and
secp256k1 keys can own stored coins. Legacy `Transfer` and `MergeCoin`
verification remains P-256-only, and genesis owner strings must decode as
P-256 keys when the validator config is loaded.

Given two P-256 key files whose settlement keys each own a 100-value coin:

```bash
RPC=ws://127.0.0.1:56946
MAKER_KEY=maker.key
TAKER_KEY=taker.key
MAKER_OWNER=maker-settlement-key
TAKER_OWNER=taker-settlement-key
MAKER_COIN=maker-coin-id
TAKER_COIN=taker-coin-id

OPEN=$(
  cargo run --no-default-features --features chain -- chain open \
    --rpc "$RPC" \
    --maker-key "$MAKER_KEY" --maker-auth webauthn \
    --taker-key "$TAKER_KEY" --taker-auth webauthn \
    --maker-funding "$MAKER_COIN" --taker-funding "$TAKER_COIN" \
    --protocol 1 --timeout 1000 \
    --timeout-payout "$MAKER_OWNER:100" \
    --timeout-payout "$TAKER_OWNER:100"
)
EDGE_ID=$(printf '%s\n' "$OPEN" | awk '$1 == "edge_id" { print $2 }')

# After the open finalizes:
PAYLOAD=$(cargo run --no-default-features --features chain -- \
  chain query --rpc "$RPC" latest-block | awk '$1 == "payload" { print $2 }')
cargo run --no-default-features --features chain -- \
  chain query --rpc "$RPC" edge --object-id "$EDGE_ID" --payload "$PAYLOAD"

cargo run --no-default-features --features chain -- chain close \
  --rpc "$RPC" --edge-id "$EDGE_ID" --kind mutual \
  --payout "$MAKER_OWNER:100" --payout "$TAKER_OWNER:100" \
  --maker-key "$MAKER_KEY" --maker-auth webauthn \
  --taker-key "$TAKER_KEY" --taker-auth webauthn

# After the close finalizes:
cargo run --no-default-features --features chain -- \
  chain query --rpc "$RPC" coins-by-owner --owner "$MAKER_OWNER"
cargo run --no-default-features --features chain -- \
  chain query --rpc "$RPC" coins-by-owner --owner "$TAKER_OWNER"
```

## Nix

The Catena interface is being developed in tandem in the sibling
`catena-runner` and `exploratory-catena` checkouts. Until those branches are
published, override both temporary path inputs explicitly (replace the paths
if your checkout layout differs):

```bash
nix develop \
  --override-input catena-runner path:/mnt/Home/src/catena-runner \
  --override-input exploratory-catena path:/mnt/Home/src/exploratory-catena \
  --no-write-lock-file
```

The main outputs are `.#cli` (network client/node/gateway), `.#cli-catena`
(x86_64 Linux plus local Catena execution), and `.#cli-validator`. The current
runner is HIP-only, so the local evaluator is deliberately not advertised on
other systems.

On an x86_64 Linux ROCm host, enter the evaluator shell with the same input
overrides:

```bash
nix develop .#rocm \
  --override-input catena-runner path:/mnt/Home/src/catena-runner \
  --override-input exploratory-catena path:/mnt/Home/src/exploratory-catena \
  --no-write-lock-file
```

Work on the kernel Quint models:

```bash
nix develop .#kernel
nix run .#check-kernel-models
nix run .#check-kernel-model-verify
```

## Docker

The Docker output is a network-only node image. It contains no local Catena or
GPU runtime and is tagged `ghcr.io/hellas-ai/hellas:network`. The derivation
streams a Docker archive to stdout:

```bash
$(nix build .#docker --print-out-paths) | docker load
nix run .#docker-push-all
```

## Dependency maintenance

Available in the development shell:

```bash
cargo audit                # security advisories
cargo outdated --workspace --root-deps-only  # outdated deps
cargo update --workspace   # update Cargo.lock
```
