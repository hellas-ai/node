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
docker run --rm -it -p 31145:31145/udp hellas-server:latest
```

Build and load CUDA server image:

```bash
nix build .#docker-server-cuda
docker load < result
docker run --rm -it --device=nvidia.com/gpu=all -p 31145:31145/udp hellas-server-cuda:latest
```

Or run directly via flake launchers (loads image, runs as current user, mounts HF cache):

```bash
HELLAS_DOWNLOAD_POLICY=eager HELLAS_EXECUTE_POLICY=eager nix run .#docker-run-server
HELLAS_DOWNLOAD_POLICY=eager HELLAS_EXECUTE_POLICY=eager nix run .#docker-run-server-cuda
```

Useful overrides:

```bash
HELLAS_DOWNLOAD_POLICY=eager HELLAS_EXECUTE_POLICY=eager nix run .#docker-run-server
HELLAS_PORT=32145 nix run .#docker-run-server-cuda
HELLAS_HF_CACHE_DIR=$HOME/.cache/huggingface nix run .#docker-run-server-cuda
HELLAS_DATA_DIR=$HOME/.local/share/hellas nix run .#docker-run-server-cuda
HELLAS_LOG=info nix run .#docker-run-server-cuda
```

The docker launchers inherit the CLI's deny-by-default behavior unless you set
`HELLAS_DOWNLOAD_POLICY` and `HELLAS_EXECUTE_POLICY`.

The CUDA launcher expects Docker CDI/NVIDIA integration so `--device=nvidia.com/gpu=all` works.

You can also pass a config file:

```bash
cat > hellas-docker.env <<'EOF'
HELLAS_CONTAINER_NAME=hellas-server-cuda
HELLAS_PORT=32145
HELLAS_HF_CACHE_DIR=$HOME/.cache/huggingface
HELLAS_DATA_DIR=$HOME/.local/share/hellas
HELLAS_DOCKER_USER=1000:100
HELLAS_DOWNLOAD_POLICY=eager
HELLAS_EXECUTE_POLICY=eager
HELLAS_LOG=info
EOF

nix run .#docker-run-server-cuda -- --config ./hellas-docker.env
```

## Dependency hygiene (CI + local)

Run the shared maintenance checks from flake:

```bash
nix run .#dep-hygiene -- check
```

Useful subcommands:

```bash
nix run .#dep-hygiene -- outdated
nix run .#dep-hygiene -- major
nix run .#dep-hygiene -- audit
nix run .#dep-hygiene -- update-check
nix run .#dep-hygiene -- update
```
