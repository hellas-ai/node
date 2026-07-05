# Merge TODO

## Chain CLI

- [x] Move chain process entrypoints under `hellas-cli chain`.
- [x] Remove standalone chain binaries.
- [x] Split chain features into clear production surfaces:
  - `client`
  - `indexer`
  - `validator`
- [x] Keep chain CLI parsing in `hellas-cli`; keep chain runtime logic in `hellas-chain`.
- [x] Add Nix packages/apps/checks for the final CLI surface.
- [ ] Port validator/follower integration tests to the node test matrix.

## Kernel Cutover

- [ ] Replace `hellas-core` with `hellas-kernel`.
- [ ] Move any surviving core primitives into kernel or the crate that owns them.
- [ ] Delete `hellas-core` once no workspace crate depends on it.
- [ ] Keep kernel's strict lints and correctness tests intact.
- [ ] Keep the rest of the workspace on normal `clippy -D warnings`.

## RPC Shape

- [ ] Re-evaluate `wire`, `wire-adaptors`, and `rpc` ownership boundaries.
- [ ] Keep transport mechanics in `wire`.
- [ ] Keep provider-format projection in `wire-adaptors` only if it remains an independent surface.
- [ ] Keep RPC abstractions/codegen composition in `rpc`.
- [ ] Move chain/light-client protobuf ownership to `chain` if that gives the cleanest boundary.
- [ ] Remove any protocol surface that is no longer first-class.

## Kernel Models

- [ ] Restore kernel model checks as first-class gates.
- [ ] Replace ad hoc `npm ci` execution with Nix-built model tooling.
- [ ] Make `nix run .#check` cover the required kernel correctness checks.
- [ ] Keep longer model verification available as an explicit check if it is too expensive for every local run.

## Tests

- [ ] Add node-repo e2e coverage for chain validator startup.
- [ ] Add follower/indexer catch-up and streaming coverage.
- [ ] Add finalized block query coverage by latest, height, and payload.
- [ ] Add owner-index query coverage.
- [ ] Keep wasm light-client checks wired through Nix.

## Dependency Cleanup

- [ ] Reduce duplicate versions where the workspace controls both sides.
- [ ] Track blocked major updates:
  - `p256`
  - `tokenizers`
  - `getrandom`
- [ ] Remove direct dependencies made unnecessary by the kernel/core cutover.
- [ ] Keep `cargo deny` clean.

## Repository Cleanup

- [ ] Remove stale merge artifacts, unused docs, and obsolete comments.
- [ ] Remove references to external source-repo names unless they identify a protocol dependency.
- [ ] Keep the branch buildable after each cleanup commit.
