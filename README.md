# hellas-cli

## Quickstart

Install:

```bash
cargo install --git https://github.com/hellas-ai/node
```

Execute:

```bash
cargo run -- execute run -p hey
```

## End-to-end

Install server features:

```bash
cargo install --git https://github.com/hellas-ai/node --features serve
```

Run server:

```bash
hellas-cli serve --discovery
Node Address: bb18ebc065d836ecc7e1f33972d2c17eac9894cd33ce4916f66cb1165ccc7550
RPC server running. Press Ctrl+C to stop
```

Run client:

```bash
cargo run -- execute run -p hey bb18ebc065d836ecc7e1f33972d2c17eac9894cd33ce4916f66cb1165ccc7550
Hello! How can I help you today?<|im_end|>%
```
