# hellas-cli

## Quickstart

Install:

```bash
cargo install --git https://github.com/hellas-ai/node
```

Execute:

```bash
cargo run -- execute -p hey
```

Execute locally with the catgrad backend:

```bash
cargo run -- execute --local -p hey
```

Local execution uses the same catgrad executor backend as `serve` and prefers
accelerated backends when available (Metal on macOS, `--features cuda` on Linux).

Verify a remote execution against the local catgrad backend:

```bash
cargo run -- execute --verify-local -p hey
```

## End-to-end

Install server features:

```bash
cargo install --git https://github.com/hellas-ai/node --features serve
```

Run server:

```bash
hellas-cli serve --download-policy=eager --execute-policy=eager
Node Address: bb18ebc065d836ecc7e1f33972d2c17eac9894cd33ce4916f66cb1165ccc7550
RPC server running. Press Ctrl+C to stop
```

`hellas-cli serve` without policy flags now starts in deny-by-default mode
(`--download-policy=skip --execute-policy=skip`). Only pass eager or allow-list
policies when you intentionally want a node to serve remote work.

Preload weights on startup:

```bash
hellas-cli serve \
  --download-policy=eager \
  --execute-policy=eager \
  --preload HuggingFaceTB/SmolLM2-135M-Instruct
```

Repeat `--preload` to warm multiple models before the node starts serving.

Run client:

```bash
cargo run -- execute bb18ebc065d836ecc7e1f33972d2c17eac9894cd33ce4916f66cb1165ccc7550 -p hey
Hello! How can I help you today?
```

Monitor discovery and peer health:

```bash
cargo run -- monitor --timeout-secs 30
```

Run HTTP gateway (OpenAI / Anthropic / plain completions over Hellas network):

```bash
cargo run -- gateway --port 8080
```

Routes:

```bash
POST /v1/chat/completions
POST /v1/messages
POST /v1/completions
```

## Docker

Docker images: `.#docker-cpu`, `.#docker-cuda12-sm89`, etc. They stream to stdout.

```bash
$(nix build .#docker-cuda12-sm89 --print-out-paths) | docker load
nix run .#docker-push-all                # push all images to ghcr.io/hellas-ai/node
```

Run a CUDA server with persistent HF cache, metrics, and Jaeger tracing:

```bash
docker run --rm -it \
  --device=nvidia.com/gpu=all \
  -p 31145:31145/udp \
  -p 9090:9090 \
  -v ~/.cache/huggingface:/home/hellas/.cache/huggingface \
  -e OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=http://jaeger:4318/v1/traces \
  ghcr.io/hellas-ai/node:cuda12-sm89 \
  --download-policy=eager --execute-policy=eager \
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
