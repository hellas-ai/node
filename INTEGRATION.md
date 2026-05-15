# Kernel Integration

This document is the practical integration guide for hosts that want to build
transactions, wire storage, and verify authorizations against `hellas-kernel`.

The deeper invariants live in `KERNEL.md`, `PROTOCOL_SECURITY_MODEL.md`, and
`FEES_SECURITY_MODEL.md`. This file states the caller-facing contract.

## Minimal Host Boundary

The kernel needs three host-supplied things:

- a `Store` implementation;
- a `Context` for the current finalized block;
- one verifier value implementing both `SigVerifier` and `SealVerifier`.

The kernel owns transition validity. The host owns persistence, block
ordering, transaction intake, and protocol-specific proof lookup.

```rust
state.apply_block(&verifier, &block)?;
```

`State::apply`, `State::apply_all`, and `State::apply_block` all use the same
validate-then-fold path. A failed operation does not commit store changes.

## Store Contract

`Store::begin` must return a staged `Batch`. Reads and writes for one operation
or block are performed against that staged batch. `Batch::commit` publishes the
staged state.

The batch must be internally consistent:

- `coin(id)` and `remove_coin(id)` must refer to the same object;
- `edge(id)` and `remove_edge(id)` must refer to the same object;
- failed or dropped batches must not mutate parent state;
- `insert_coin` and `insert_edge` must reject occupied or unavailable slots.

The kernel has only two live object kinds: `Coin` and `Edge`. A backend may use
one database, separate tables, an authenticated map, or a preloaded working
set, but the public trait boundary stays typed.

## Context And Fees

`Context` carries:

- finalized block height;
- previous finalized block hash;
- deterministic fee schedule.

Open pays three amounts from funding:

- the open operation fee;
- prepaid lifetime fee through the committed timeout height;
- close reserve priced at open time.

Close has no marginal monetary fee. It consumes the open-time reserve according
to the close proof kind and payout fanout. Any reserve surplus is returned only
through the close outputs committed by the applicable terms.

The examples print these numbers directly:

```sh
cargo run --example end_to_end --features secp256k1
```

## One Party Key

Each party has one kernel-level `Key`.

That key is used for:

- coin ownership;
- edge party identity in `Terms`;
- open authorization;
- payout ownership;
- cooperative-close signature verification when the close proof is `Mutual`.

There is no separate `open_auth_key` in v1. Opening an edge is the act of
moving owned coins into a shared edge under concrete terms. The same key that
owns those coins authorizes that move.

This keeps the key model small:

```text
Coin.owner == Terms.parties().maker/taker
OpenAuth proves consent from that same key
Payout.owner receives value back to that same key space
```

If a party contributes no coins, it must still authorize the open. That is how
the kernel prevents an edge from naming an unwilling party under terms they did
not accept.

## Open Authorization

`OpenAuth` is the witness format for the party key. It is not a separate
identity.

```rust
pub enum OpenAuth {
    Native(Sig),
    WebAuthn(WebAuthnAssertion),
}
```

Both variants authorize the same payload:

```rust
let hash = Tx::open_hash(&funding, &terms);
```

Native authorization is a compact signature over that hash.

`WebAuthn` authorization is a browser/passkey assertion whose
`clientDataJSON.challenge` is the base64url encoding of that same hash. The
party key is the compressed SEC1 encoding of the assertion's P-256 public key.

The bundled kernel verifier treats `WebAuthn` as a portable transaction-signing
envelope. It checks the signature, user-presence/user-verification flags, key
binding, and challenge binding. It does not enforce application origin or
`rpIdHash` policy. If a host wants origin-scoped wallet policy, it should apply
that policy before constructing or accepting `OpenAuth::WebAuthn`.

The mixed example demonstrates maker native auth and taker passkey auth:

```sh
cargo run --example mixed_open_auth --features secp256k1,webauthn
```

## Close Proofs

Close proof routing is intentionally small:

| Proof kind | Checked by | Meaning |
| --- | --- | --- |
| `Mutual` | `SigVerifier::verify_sig` | both parties sign the close payload |
| `Timeout` | kernel structure checks | timeout height reached and outputs match terms |
| `Violation` | `SealVerifier::verify_seal` | protocol-specific proof/seal accepted |

`Secp256k1Verifier` verifies native secp256k1 signatures for `Native` open
auth and `Mutual` close proofs. With the `webauthn` feature enabled, it also
verifies `OpenAuth::WebAuthn` for passkey-backed opens.

It does not turn passkeys into raw cooperative-close signatures. A party whose
kernel key is a passkey P-256 key can authorize open with `WebAuthn` and
receive payouts, but the bundled `Secp256k1Verifier` will not accept that key
for `Proof::Mutual`.

Passkey-backed channels therefore need one of these close paths:

- timeout close under committed terms;
- violation close through a protocol-specific `SealVerifier`;
- a future verifier/signature envelope that explicitly supports passkey or raw
  P-256 cooperative-close signatures.

Do not add a second open key just to work around this. If cooperative close for
passkey parties is required, extend the close witness/verifier story directly.

## Verifier Responsibilities

`SigVerifier` decides party signatures and open authorizations:

```rust
fn verify_sig(&self, sig: Sig, key: Key, hash: PayloadHash) -> bool;
fn verify_open_auth(&self, auth: &OpenAuth, key: Key, hash: PayloadHash) -> bool;
```

The default `verify_open_auth` accepts only `OpenAuth::Native`. Verifiers that
want passkey opens must override it and call
`verify_webauthn_assertion(assertion, key, hash)`.

`SealVerifier` decides protocol-specific violation proofs. The kernel passes
bounded public inputs:

- edge id;
- protocol code;
- terms hash;
- requested payouts.

The seal verifier is where ZK proof verification, TEE attestation checking, or
fraud-game terminal verdict validation belongs. The L1 kernel does not run an
iterative challenge game.

## Integration Checklist

Before submitting kernel transactions from a host:

- derive output ids with `Tx::edge_id_of` and `Tx::close_output_ids` when the
  host needs them ahead of apply;
- sign `Tx::open_hash(&funding, &terms)` for every party named by the terms;
- ensure funding coins are owned by the matching party key;
- choose timeout outputs that exactly match the value recoverable under timeout;
- use `Tx::payload_hash(edge, kind, terms_hash, &outputs)` for mutual close
  signatures or seal public-input construction;
- wire a production verifier that matches the key types and proof modes the
  host accepts;
- buffer events from `apply_iter` until it returns `Ok`, because event callbacks
  fire before the staged batch commits.
