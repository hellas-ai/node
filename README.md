# Hellas Kernel

`hellas-kernel` is the small deterministic settlement kernel for Hellas.

It models the L1 object transition system for owner-only coins, live channel
edges, edge opens, and edge closes. Everything outside that boundary - RPC,
mempool policy, storage engines, workers, off-chain dispute protocols, and
proof artifact lookup - is host code.

## Start Here

- `INTEGRATION.md`: practical host-facing contract for storage, context,
  verifiers, fees, and the one-party-key model.
- `KERNEL.md`: implementation and formal-model boundary.
- `PROTOCOL_SECURITY_MODEL.md`: high-level safety and escape-hatch goals.
- `FEES_SECURITY_MODEL.md`: fee, reserve, lifetime, and stake reasoning.
- `FORMAL_MODELING_STRATEGY.md`: how the Quint models are organized.
- `TESTING.md`: current test, coverage, mutation, and model-checking baseline.

## Key Ideas

The kernel has two live object kinds:

- `Coin`: owner-only value controlled by one settlement key.
- `Edge`: locked channel value governed by terms and close proofs.

Each party has one kernel `Key`. That same key is used for coin ownership,
edge party identity, open authorization, payout ownership, and cooperative
close signatures when the selected verifier supports that signature type.

There is no separate `open_auth_key`. `OpenAuth` is only the witness format for
the party key:

- `OpenAuth::Native(Sig)` for compact native signatures;
- `OpenAuth::WebAuthn(WebAuthnAssertion)` for passkey-backed open consent.

## Examples

Native secp256k1 open and close, plus one-sided funding and timeout:

```sh
cargo run --example end_to_end --features secp256k1
```

Mixed native/passkey open authorization:

```sh
cargo run --example mixed_open_auth --features secp256k1,webauthn
```

## Development Checks

Before merging behavior changes:

```sh
cargo fmt --all --check
cargo test --all-features
cargo clippy --all-features --all-targets -- -D warnings
npm run quint:test
npm run quint:verify
```

See `TESTING.md` for mutation testing, coverage, and ITF replay commands.
