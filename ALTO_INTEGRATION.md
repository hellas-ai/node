# Alto integration plan

How `hellas-kernel` slots into `~/src/hellas-alto`. This is a destructive
migration: alto's current STF, transaction type, and inline crypto get
deleted and replaced by direct dependencies on `hellas-kernel`. No
parallel structures, no adapter wrappers — the kernel becomes alto's
state machine, and alto becomes a thin consensus + persistence shell
around it.

Phase 0 (kernel-side prep) is done: `Access` subsystem removed,
`State::apply_iter` added, deliberate omissions documented in
`Context`. This document is the Phase 1 work plan.

## Surface comparison

| Concern                | Alto today                                              | Hellas-kernel                                  |
|------------------------|----------------------------------------------------------|------------------------------------------------|
| Tx enum                | `Transaction { Transfer, MergeCoin }`                    | `Tx { Open, Close }`                           |
| Object                 | `Coin { owner: Address, value: u64 }`                    | `Coin` (same shape) + `Edge`                   |
| Object id              | `ObjectId = Sha256 Digest`                               | `CoinId`, `EdgeId`                             |
| Sig type               | `WebAuthnSignature { sig, auth_data, client_data }`      | `Sig = [u8; 64]` for native close/open auth; `OpenAuth::WebAuthn` for passkey opens |
| STF                    | `execute_all` / `execute_proposal` (inline, async)       | `State::apply*` (sync, trait-bounded)          |
| Store                  | `UtxoDb<E>` (commonware MMR, async, `Batch::Unmerkleized`) | `Store + Batch` traits (sync)                  |
| Crypto                 | Inline `Transaction::verify_signature`                   | `SigVerifier` + `SealVerifier`; WebAuthn open helpers behind `webauthn` |
| Context                | `Context<Digest, PublicKey>` + height + timestamp        | `Context { height, hash, fees }`               |
| Genesis                | `Vec<(Address, u64)>` looped at height 0                 | `State::genesis(store, &[Genesis::coin(...)])` |
| Fees                   | None                                                     | `Fees`, `Cost` per op                          |
| Block size             | `MAX_TXS_PER_BLOCK` constant, `Vec<Transaction>`         | Variable, via `apply_iter`                     |

## What gets deleted from alto

- `chain/src/execution/kernel.rs` — entire file (~306 lines). The
  `execute_all`, `execute_proposal`, `apply_transaction`,
  `maybe_seed_genesis` functions all go.
- `types/src/lib.rs::Transaction` enum and impl block — replaced by
  `hellas_kernel::Tx`.
- `types/src/lib.rs::Coin` — replaced by `hellas_kernel::Coin`. (Same
  shape, but coming from the kernel crate so tests and protocol all
  point to one source of truth.)
- `types/src/lib.rs::Transaction::verify_signature` — moves into the
  `SigVerifier` impl.
- `types/src/lib.rs::transfer_challenge`, `merge_challenge` — replaced
  by the kernel's canonical open hash (`Tx::open_hash`) for channel
  opens. Alto may still build browser request options, but the
  submitted assertion is carried into the kernel as `OpenAuth::WebAuthn`.
- `chain/src/execution/kernel.rs::ExecutionError` — replaced by
  `hellas_kernel::ApplyError` / `BatchError`. Drop the
  `is_transient_for_mempool` / `is_fatal_storage` classifier and re-add
  if alto's mempool genuinely needs it (the variants will be different
  shape).
- All inline check logic (zero-amount, duplicate inputs, owner match,
  overflow, output collision) — kernel handles equivalents.

## What alto adds

Three direct trait impls on alto's existing types. No new wrapper
structs.

### 1. `impl SigVerifier + SealVerifier for UserVerifier`

Where `UserVerifier` is a unit struct (or carries any policy state
alto needs — e.g. a precomputed-sig cache). The kernel takes one value
that impls *both* traits; we impl them on the same struct so callers
pass `&UserVerifier`.

```rust
// chain/src/execution/verifier.rs (new file, ~35 lines)

use hellas_kernel::{
    verify_webauthn_assertion, PayloadHash, Key, OpenAuth, Seal,
    SealPublicInputs, SealVerifier, Sig, SigVerifier,
};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier as _};

pub struct UserVerifier;

impl SigVerifier for UserVerifier {
    fn verify_sig(&self, sig: Sig, key: Key, hash: PayloadHash) -> bool {
        let Ok(vk) = VerifyingKey::from_sec1_bytes(key.as_bytes()) else {
            return false;
        };
        let Ok(sig) = Signature::from_slice(sig.as_bytes()) else {
            return false;
        };
        vk.verify(hash.as_bytes(), &sig).is_ok()
    }

    fn verify_open_auth(&self, auth: &OpenAuth, key: Key, hash: PayloadHash) -> bool {
        match auth {
            OpenAuth::Native(sig) => self.verify_sig(*sig, key, hash),
            OpenAuth::WebAuthn(assertion) => {
                verify_webauthn_assertion(assertion, key, hash).is_ok()
            }
        }
    }
}

impl SealVerifier for UserVerifier {
    fn verify_seal(&self, _seal: Seal, _public: &SealPublicInputs<'_>) -> bool {
        // No dispute seals in v1. Wire a protocol-specific seal verifier
        // here when violations are supported.
        false
    }
}
```

Timeout structural checks (terms-hash binding, height guard, payout
match) live inside the kernel and need no verifier — the `UserVerifier`
above carries no Timeout logic.

**Important boundary decision: WebAuthn open authorization lives in the
kernel.** Alto's mempool / proposer should not unwrap WebAuthn into a
bare ECDSA `Sig`. For an open, it constructs:

- `OpenAuth::Native(Sig)` for a native party signature, or
- `OpenAuth::WebAuthn(WebAuthnAssertion)` for a passkey assertion.

The kernel verifier checks the WebAuthn assertion directly:

- `clientDataJSON.type == "webauthn.get"`;
- `clientDataJSON.challenge == base64url(Tx::open_hash(...))`;
- UP or UV flag set; AT and ED rejected;
- P-256 signature verifies over
  `sha256(authenticatorData || sha256(clientDataJSON))`;
- P-256 public key compresses to the party `Key`.

Following Tempo's consensus shape, the kernel does not enforce
`origin` or `rpIdHash`. Those bytes remain inside the signed WebAuthn
message, but they are not policy inputs for kernel validity.

### 2. `impl hellas_kernel::Store for UtxoDb<E>` (and a `Batch` adapter)

The friction: alto's `UtxoDb` is **async** (`batches.get(id).await`),
and the kernel's `Store::Batch` is **sync**. Bridging requires alto to
pre-load the working set for the block into a sync in-memory map
before invoking the kernel.

```rust
// chain/src/execution/store.rs (additions, ~120 lines)

use std::collections::HashMap;
use hellas_kernel::{Batch, Coin, CoinId, Edge, EdgeId, InsertError, KernelResult, Store};

/// Synchronous working set for one block's apply pass. Loaded async
/// from `UtxoDb` before kernel invocation; the diff (writes + deletes)
/// is replayed back into the async `DatabaseSet::Unmerkleized` after
/// commit so the merkleized state root advances normally.
pub struct BlockWorkingSet {
    coins: HashMap<CoinId, Option<Coin>>,
    edges: HashMap<EdgeId, Option<Edge>>,
}

impl Store for BlockWorkingSet { /* ... */ }
impl<'a> Batch for &'a mut BlockWorkingSet { /* ... */ }
```

`BlockWorkingSet`:
- Pre-loaded with every `CoinId` / `EdgeId` referenced by the block's
  txs (alto walks the txs to extract the access surface before apply).
- `Batch::coin(id)` and `Batch::edge(id)` return from the map;
  `batch.insert_*` and `batch.remove_*` mutate the map.
- After kernel commit, alto replays the map's writes into the
  `Unmerkleized` batch (`batch = batch.write(id, value)`), which
  produces the next merkleized state and a new root.

**This is the central piece of the integration.** Pre-loading instead
of an async kernel keeps the kernel's purity guarantee intact and
avoids dragging `async-trait` or futures into the no_std kernel.

Alternatives considered and rejected:
- **Async kernel** — pollutes a deterministic embeddable library with
  runtime concerns. No.
- **Block-on inside `Tx`** — requires a tokio runtime handle inside
  kernel; couples kernel to async ecosystem. No.
- **Streaming async/sync bridge per op** — complex, no real benefit
  over batch pre-load.

### 3. Block production wiring in `chain/src/app.rs`

The `Application::propose` / `Application::execute` paths get rewritten
to:

```rust
async fn execute_block<E>(
    db: &UtxoDatabase<E>,
    context: Context,  // hellas_kernel::Context
    txs: Vec<hellas_kernel::Tx>,
) -> Result<(Diff, Digest, UtxoSyncTarget), BatchError>
{
    // 1. Walk txs to collect referenced object ids
    let touched: BTreeSet<ObjectId> = txs.iter().flat_map(touched_ids).collect();

    // 2. Pre-load working set from async store
    let mut ws = BlockWorkingSet::load(db, &touched).await;

    // 3. Wrap in kernel State
    let mut state = State::new(ws);  // (new helper — see below)

    // 4. Invoke kernel
    let mut events = Vec::new();
    state.apply_iter(context, &UserVerifier, txs, |_, ev| events.push(ev.clone()))?;

    // 5. Materialize merkleized state from the working set's writes
    let batch = state.into_store().into_batch(db).await;
    let merkleized = batch.merkleize().await;

    Ok((Diff::from(events), merkleized.root(), merkleized.sync_target()))
}
```

Notes:
- `touched_ids(tx)` is the closest thing alto needs to the deleted
  `Access` set, but it's local-to-alto, doesn't need to be
  kernel-public, and only collects ids (not direction).
- `State::new` doesn't exist on the public kernel API today — only
  `State::genesis` does. **Phase 1 needs a kernel-side `pub fn
  new(store: S) -> Self`** for the case where the store is already
  populated. Trivial addition.
- The replayed batch is what alto already does today (post-execute,
  it merkleizes the batch). The shape of the post-kernel hand-off
  stays unchanged.

### Genesis

Alto's `Vec<(Address, u64)>` allocation list becomes:

```rust
let seeds: Vec<Genesis> = genesis_allocations.iter().enumerate().map(|(i, (addr, value))| {
    let coin_id = hellas_kernel::CoinId::from_bytes(genesis_object_id(i as u16).into());
    let key = hellas_kernel::Key::from_bytes(addr.public_key().to_bytes());
    Genesis::coin(coin_id, key, *value)
}).collect();
State::genesis(store, &seeds)?;
```

The `genesis_object_id(idx)` deterministic id derivation stays in alto
(or moves into a `genesis.rs` helper) — the kernel doesn't care how
coin ids are derived for genesis, only that they're distinct.

### Fees

`Fees::ZERO` plumbed into every `Context` constructor for now. Alto's
fee model design is deferred — the kernel already supports
`Fees { base, slot, proof, lifetime }` and `Cost { base, slots, proofs }`
per op, so when alto wires real fees the kernel side is unchanged. The
`lifetime` price is charged on open for the prepaid live-edge span; it is
separate from execution `slot` pricing.

### Mempool integration

Alto's mempool stays at the alto layer (kernel doesn't see mempools).
The mempool's job changes:

- Accepts `Tx` instead of `Transaction`.
- Build kernel `Tx::open_with_auth(...)` values. WebAuthn assertions
  are not unwrapped; the kernel verifies their challenge binding and
  P-256 signature during apply.
- Drops the `is_transient_for_mempool` classification — kernel's
  `ApplyError::MissingCoin` is the moral equivalent; the mempool
  can pattern-match on `ApplyError` variants to decide retain-vs-drop.

## Migration order (within Phase 1)

1. **Kernel-side: add `State::new`.** ~5 lines. No semantic change;
   just exposes the existing constructor.
2. **Alto: bring `hellas-kernel` in as a path dep.** Update `Cargo.toml`
   under `chain/`.
3. **Alto: write `BlockWorkingSet` + trait impls** (`Store` + `Batch`)
   in `chain/src/execution/store.rs`. Write a small test that loads,
   mutates, replays.
4. **Alto: write `UserVerifier`** in `chain/src/execution/verifier.rs`.
   Standalone test against known secp256r1 vectors.
5. **Alto: rewrite `Application::execute` / `Application::propose`** in
   `chain/src/app.rs` to use the kernel. Existing alto integration tests
   should pass without modification of expected post-state.
6. **Alto: delete `execute_all`, `execute_proposal`,
   `apply_transaction`, `maybe_seed_genesis`** from
   `chain/src/execution/kernel.rs`. File becomes a re-export shim or
   gets deleted entirely.
7. **Alto: delete `Transaction`, `Coin`, `WebAuthnSignature::verify`**
   from `types/src/lib.rs`. WebAuthn envelope type itself stays only if
   it is still useful as an RPC DTO; kernel validation is via
   `hellas_kernel::WebAuthnAssertion`.
8. **Alto: update RPC submission path** to map WebAuthn RPC payloads
   into `OpenAuth::WebAuthn` before mempool insertion.

## Open questions to resolve during Phase 1

1. **One MMR with union object type, not two parallel MMRs.**
   `commonware_glue::stateful::db::DatabaseSet::merkleize` is per-MMR
   — two MMRs means two separate atomicity domains, and a kernel op
   that consumes a coin and creates an edge in one logical step would
   require atomic commits across both. Commonware doesn't expose a
   cross-MMR transactional primitive. The fix: one MMR keyed by a
   shared `ObjectId` (both `CoinId` and `EdgeId` are 32-byte
   domain-separated BLAKE3 digests; their id spaces don't collide),
   with a thin `enum Object { Coin(Coin), Edge(Edge) }` as the MMR's
   value type. Alto's `BlockWorkingSet` exposes `Batch::coin` and
   `Batch::edge` by pattern-matching on the variant. One root, one
   commit, atomic by construction.

2. **Validator-set rotation vs `Context`.** Alto's existing
   `HellasBlock` carries leader pubkey; kernel's `Context` does not.
   This is fine for v1 (the kernel's verifier traits don't bind to
   validators) but if a future protocol mode needs it, the validator set
   comes from alto's consensus and gets handed to `UserVerifier` (not
   into `Context`).

3. **`ObjectId` vs split `CoinId`/`EdgeId`.** Alto uses one
   `ObjectId = Digest` type at the storage layer; kernel uses two typed
   ids at the API layer. They reconcile cleanly: both kernel ids are
   32-byte domain-separated BLAKE3 digests with disjoint id spaces, so
   they slot into a single `ObjectId`-keyed MMR. The kernel's typing is
   preserved at the API surface (`Batch::coin(CoinId)` vs `Batch::edge(EdgeId)`),
   with the conversion happening inside `BlockWorkingSet`.

4. **Block envelope.** Alto's `HellasBlock` carries
   `(height, timestamp, parent, state_root, sync_target, [Transaction])`.
   Replace `[Transaction]` with `Vec<Tx>` (or a length-prefixed encoded
   blob). Block hashing input changes — coordinate with whatever
   downstream consumers (RPC, indexer) decode `HellasBlock`.

## Estimated diff

| Area                      | Delete  | Add   | Net    |
|---------------------------|---------|-------|--------|
| `chain/src/execution/`    | ~310    | ~180  | −130   |
| `types/src/lib.rs`        | ~250    | ~10   | −240   |
| `chain/src/app.rs`        | ~80     | ~120  | +40    |
| `chain/src/rpc.rs`        | ~30     | ~30   | 0      |
| `chain/Cargo.toml`        | +1 dep  |       |        |
| Tests                     | ~300    | ~200  | −100   |
| **Total**                 | ~970    | ~540  | **−430** |

Roughly the same shape of cleanup we got from removing the `Access`
subsystem — about a third of alto's chain logic deletes outright,
replaced by trait impls and kernel calls.

## Out of scope for Phase 1

- Real fee model (Fees::ZERO suffices).
- Dispute seals: admitting `Proof::Violation` requires a
  protocol-specific `SealVerifier` impl; v1 leaves `UserVerifier`'s
  `verify_seal` returning `false`.
- Adding `BlockTime` / timestamp to `Context`.
- Validator-set-bound proofs.
- Edge fanout > current `MAX_EDGE_INPUTS=8` / `MAX_EDGE_OUTPUTS=4`
  bounds. If alto needs more, that's a chain-version change and a
  separate kernel migration.

## Phase 2 preview (node integration)

Once alto runs through the kernel:
- `node` adds `hellas-alto` and `hellas-kernel` as path deps.
- CLI subcommand `node validator` spawns alto's consensus driver.
- CLI subcommand `node worker` keeps the existing `Execute` RPC.
- Validator-exposed external interface = kernel public types
  (`Tx`, `Diff`, `Event`) over gRPC. Proto definitions for `Tx`/`Block`
  /`Event` likely live in this crate as a `tonic`-feature-gated module
  to avoid two sources of truth.
