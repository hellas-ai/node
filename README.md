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

Load model metadata on startup:

```bash
cargo run --features candle -- serve \
  --execute-policy=eager \
  --preload HuggingFaceTB/SmolLM2-135M-Instruct
```

Repeat `--preload` to load metadata for multiple models.

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
