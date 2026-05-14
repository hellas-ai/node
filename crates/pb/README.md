# hellas-pb

Generated protobuf bindings for Hellas.

By convention, the source `.proto` files live in the repo root, 
under `proto/hellas`.
Generated Rust files are checked in under `src/` so normal builds do not need `protoc`, `buf`, or the protobuf compiler toolchain.

## Features

Package features select which protobuf packages are exposed:

- `hellas` - core shared protocol package.
- `symbolic` - symbolic work package; enables `hellas`.
- `opaque` - opaque work package; enables `hellas`.
- `swarm` - node / peer discovery package.
- `courtesy` - non-core convenience package; enables `hellas` and `symbolic`.

Transport features select generated client/server stubs:

- `client` - export generated gRPC clients for enabled packages.
- `server` - export generated gRPC server traits and service wrappers for
  enabled packages.

Convenience features:

- `all` - enable every package plus `client` and `server`.
- `compile` - regenerate checked-in Rust bindings during build. This also
  enables `all` and pulls in the optional codegen build dependencies.

## Regenerating

After editing files under `proto/`, run:

```sh
cargo check -p hellas-pb --features compile
```

This writes regenerated files into `crates/pb/src/`. Commit the generated files
with the proto changes.

`compile` is intentionally not a default feature. Downstream crates should
depend on the checked-in bindings and enable only the package/client/server
features they actually need.
