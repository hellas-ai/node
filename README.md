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
accelerated backends when built with `--features cuda` or `--features metal`.

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

## Docker images via Nix

Build and load CPU server image:

```bash
nix build .#docker-server
docker load < result
docker run --rm -it -p 31145:31145/udp ghcr.io/hellas-ai/node:latest
```

Build and load CUDA server image:

```bash
nix build .#docker-server-cuda
docker load < result
docker run --rm -it --device=nvidia.com/gpu=all -p 31145:31145/udp ghcr.io/hellas-ai/node:cuda-latest
```

Build and push a docker image directly from the flake:

```bash
nix run .#docker-push -- docker-server ghcr.io/hellas-ai/node:latest
nix run .#docker-push -- docker-server-cuda ghcr.io/hellas-ai/node:cuda-latest
nix run .#docker-push -- docker-server-cuda-13-1 ghcr.io/hellas-ai/node:cuda-13.1
```

## Dependency maintenance

Available in the dev shell (`nix develop`):

```bash
cargo audit                # security advisories
cargo outdated --workspace --root-deps-only  # outdated deps
cargo update --workspace   # update Cargo.lock
```
