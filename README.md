# hellas-cli

## Quickstart

Execute:

```bash
cargo run --features candle -- llm -p hey
```

Execute locally with the catgrad backend:

```bash
cargo run --features candle -- llm --local -p hey
```

Verify a remote execution against the local catgrad backend:

```bash
cargo run --features candle -- llm --verify-local -p hey
```

## End-to-end

Run server:

```bash
cargo run --features candle -- serve --execute-policy=eager
```

`serve` without policy flags starts in deny-by-default mode
(`--execute-policy=skip`). Only pass eager or allow-list policies when you
intentionally want a node to serve remote work.

Make a model available on startup:

```bash
cargo run --features candle -- serve \
  --execute-policy=eager \
  --preload HuggingFaceTB/SmolLM2-135M-Instruct
```

Repeat `--preload` for multiple models.

**A node quotes only models it already holds.** `--preload` downloads;
serving does not. A quote for anything else is refused with
`FailedPrecondition` and no bytes fetched — otherwise anyone who could
dial the node could name a 700 GB repository and have the node download
it. A HuggingFace cache the node can already read counts as holding the
model, so mounting one (as the Docker example below does) works without
any preload at all.

Run client:

```bash
cargo run --features candle -- llm bb18ebc065d836ecc7e1f33972d2c17eac9894cd33ce4916f66cb1165ccc7550 -p hey
```

Monitor discovery and peer health:

```bash
cargo run -- monitor --timeout-secs 30
```

Run HTTP gateway (OpenAI / Anthropic / plain completions over Hellas network):

```bash
cargo run --features gateway -- gateway --port 8080
```

Routes:

```bash
POST /v1/chat/completions
POST /v1/responses
POST /v1/messages
POST /v1/completions
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

Enter the default Rust development shell:

```bash
nix develop
```

Work on the kernel Quint models:

```bash
nix develop .#kernel
nix run .#check-kernel-models
nix run .#check-kernel-model-verify
```

## Docker

Docker images: `.#docker-cpu`, `.#docker-cuda12-sm89`, etc. They stream to stdout.

```bash
$(nix build .#docker-cuda12-sm89 --print-out-paths) | docker load
nix run .#docker-push-all                # push all images to ghcr.io/hellas-ai/hellas
```

Run a CUDA server with persistent HF cache and metrics:

```bash
docker run --rm -it \
  --device=nvidia.com/gpu=all \
  -p 31145:31145/udp \
  -p 9090:9090 \
  -v ~/.cache/huggingface:/home/hellas/.cache/huggingface \
  ghcr.io/hellas-ai/hellas:cuda12-sm89 \
  --execute-policy=eager \
  --metrics-port=9090 \
  --preload HuggingFaceTB/SmolLM2-135M-Instruct
```

## Dependency maintenance

Available in the dev shell (`nix develop`):

```bash
cargo audit                # security advisories
cargo outdated --workspace --root-deps-only  # outdated deps
cargo update --workspace   # update Cargo.lock
```
