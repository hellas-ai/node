# Signed attestations: commitment + receipt + request, swappable PQ-ready signature suites

## Context

Today the gateway exposes `commitment_id` and `receipt_id` in HTTP headers / SSE events as bare 32-byte content hashes — no proof that any specific party committed to them. We want **transferable, third-party-verifiable cryptographic attestation** so the chain "client K asked → provider P committed → provider P delivered receipt R" can be reconstructed by anyone holding the response, AND the underlying signature suite can be swapped (classical → post-quantum) without changing the wire format or the call sites that consume signatures.

**Crypto design choice — always include the pubkey in the wire envelope.** Earlier iterations of this design considered ECDSA pubkey recovery (lets the verifier extract the signer's pubkey from `(msg, sig)` algebraically, saving the pubkey bytes on the wire). Recovery is a clever EC-only optimization with no analogue in PQ schemes. To keep the wire format scheme-agnostic — the actual goal — we drop the recovery trick and always carry the pubkey explicitly. Costs +33 bytes for secp256k1 vs the recovery-based design, gains uniform handling for any PQ scheme.

**v1 ships two suites**: `Secp256k1Suite` (classical, fast, small) and `Falcon512Suite` (post-quantum, NIST FIPS 206 candidate, smallest of the standardized PQ options). Falcon is gated behind a **`pq` Cargo feature flag** (default off) so default builds don't carry the `pqcrypto-falcon` C dependency; building `cargo build --features pq` enables the Falcon suite, the Falcon arm in the verifier dispatch, and the `falcon-512` value for `--suites`. Runtime verifier dispatches by scheme tag, so a request signed with secp256k1 and a response signed with Falcon-512 verify on the same code path (provided both ends were built with `--features pq`). Adding ML-DSA, SPHINCS+, or any future suite is `impl SigSuite for X` + register the scheme tag — same pattern, additional feature flag if it brings a heavy dep.

Key lifecycle: **persistent signing key(s)** at `~/.hellas/signing-key.<scheme>`. Provider identity is stable across restarts. Iroh transport key stays as-is (long-lived) — the iroh-key-to-ephemeral flip needs a discovery rework and is a separate PR.

`quote_id` (server-issued opaque session handle) becomes redundant once `commitment_id` is the canonical in-flight identifier and gets removed from the wire entirely as part of this work.

## Header / wire layout

**Each header is self-sufficient** — carries the scheme, the pubkey, the signature, and (for commitment/receipt) the signed identifier. No companion headers required.

**Tonic Request metadata (gateway → executor):**
```
x-hellas-request: <scheme>.<pubkey_b64>.<sig_b64>
```
Signed message: **DAG-CBOR canonical encoding** of a parallel `SignedRequest` struct with serde derives, mapped from the wire `GetQuoteRequest` via a `From` impl. Catgrad already uses `serde_ipld_dagcbor` for its own canonical hashing (commitments etc.); we reuse the same encoder. We do NOT sign the raw prost-encoded bytes — prost is deterministic in practice but the spec doesn't require it, and we want intentional canonical bytes plus proptest coverage to prove the encoding is stable.

Server recomputes the canonical bytes from the request it received (same `From` mapping), then verifies `sig` against `pubkey`. Pubkey identifies the client.

**Tonic Response metadata (executor → gateway):**
```
x-hellas-commitment: <scheme>.<pubkey_b64>.<sig_b64>.<commitment_id_b64>
```
Signed message: `commitment_id` bytes. Verifier parses, verifies `sig` against `pubkey` over `commitment_id`. Pubkey identifies the provider.

**Symmetric scheme rule**: the server signs the response with the *same suite* the client used to sign the corresponding request. The client's choice propagates through the entire interaction; the client never has to handle "I asked in scheme X, server replied in scheme Y." If the server doesn't have a key for the client's chosen suite, it rejects the request upfront (Step 7) — never silently downgrades. Implication: a server's `--suites` list determines both *what it accepts* AND *what it can sign with*; the server generates/loads a signing key for each suite in its list at startup.

**Proto `Completed`** — receipt is terminal so it travels in the stream's last event:
```protobuf
message Completed {
  uint64 total_tokens = 1;
  StopReason stop_reason = 2;
  bytes receipt_cid = 3;
  AttestationSig receipt_sig = 4;   // NEW
}

message AttestationSig {
  string scheme_id = 1;   // "secp256k1", "falcon-512"
  bytes pubkey = 2;       // raw pubkey bytes for the suite
  bytes sig = 3;          // raw signature bytes for the suite
}
```
Driver layer pairs `(receipt_cid, receipt_sig)` into a `SignedReceipt` typed value before handing to consumers.

**HTTP response headers (gateway → HTTP client):**
```
x-hellas-commitment: <scheme>.<pubkey_b64>.<sig_b64>.<commitment_id_b64>      ; both buffered + SSE
x-hellas-receipt:    <scheme>.<pubkey_b64>.<sig_b64>.<receipt_id_b64>         ; buffered only
```

**SSE in-band events (browser EventSource path — can't read headers):**
```
event: hellas-commitment   data: {"scheme":"<id>","pubkey":"<b64>","sig":"<b64>","id":"<b64>"}     ; initial
event: hellas-receipt      data: {"scheme":"<id>","pubkey":"<b64>","sig":"<b64>","id":"<b64>"}     ; terminal
```
Commitment event yielded right before the protocol's initial role/message-start frame. Receipt event yielded immediately before each protocol's terminal frame (`[DONE]` for OpenAI/plain, `message_stop` for Anthropic), only on `Outcome::Completed`.

**All wire encoding is base64url (RFC 4648 URL-safe alphabet, no padding).** This includes header values, SSE event JSON fields, and `Cid<T>::Display` — see "Coordinated catgrad change" below. Saves ~33% of bytes vs hex. The `base64` crate's `URL_SAFE_NO_PAD` engine is the only encoder; one place to read, one place to write.

**Wire-size sanity check (per artifact, per header) using base64url:**

| Suite        | Pubkey | Sig   | id    | Total raw | base64url chars |
|--------------|--------|-------|-------|-----------|-----------------|
| secp256k1    | 33 B   | 64 B  | 32 B  | 129 B     | ~172            |
| Falcon-512   | 897 B  | 666 B | 32 B  | 1595 B    | ~2127           |

Two such headers fit comfortably in 8 KB header limits for secp256k1; Falcon needs ~4.3 KB total which is well within axum/hyper's 16 KB default.

**Coordinated catgrad change:** `Cid<T>::Display` in `/home/grw/src/catgrad/catgrad/src/cid/typed.rs` switches from lowercase hex to base64url-no-pad. This is a breaking wire change (anything that round-tripped CIDs as strings needs to update). Sibling-crate PR; pin the new git rev in our `Cargo.toml`. Migration path: do the catgrad change first, bump our pin, then this PR's tests and helpers all align with the new encoding from the start.

**Renamed from current shape:**
- `x-hellas-commitment-id` → `x-hellas-commitment` (now signature-bearing).
- `x-hellas-receipt-id` → `x-hellas-receipt` (now signature-bearing).
- SSE event `hellas-provenance` → `hellas-commitment` (semantically more precise).

## Crypto trait (`hellas_rpc::sig`)

New file `crates/rpc/src/sig.rs`:

```rust
pub trait SigSuite: 'static + Send + Sync {
    type SigningKey: Send + Sync;
    type VerifyingKey: Clone + Send + Sync + Eq;
    type Signature: Clone + Send + Sync;
    const SCHEME_ID: &'static str;

    fn generate(rng: &mut (impl rand::RngCore + rand::CryptoRng)) -> (Self::SigningKey, Self::VerifyingKey);
    fn verifying_key(sk: &Self::SigningKey) -> Self::VerifyingKey;

    fn sign(sk: &Self::SigningKey, msg: &[u8]) -> Self::Signature;
    fn verify(vk: &Self::VerifyingKey, msg: &[u8], sig: &Self::Signature) -> bool;

    fn vk_to_bytes(vk: &Self::VerifyingKey) -> Vec<u8>;
    fn vk_from_bytes(bytes: &[u8]) -> Result<Self::VerifyingKey, SigError>;
    fn sig_to_bytes(sig: &Self::Signature) -> Vec<u8>;
    fn sig_from_bytes(bytes: &[u8]) -> Result<Self::Signature, SigError>;
    fn sk_to_bytes(sk: &Self::SigningKey) -> Vec<u8>;
    fn sk_from_bytes(bytes: &[u8]) -> Result<Self::SigningKey, SigError>;
}

pub struct Secp256k1Suite;
impl SigSuite for Secp256k1Suite { /* k256-backed; standard ECDSA, no recovery */ }

pub struct Falcon512Suite;
impl SigSuite for Falcon512Suite { /* pqcrypto-falcon-backed */ }

#[derive(Debug, thiserror::Error)]
pub enum SigError { /* parse, length, decode, scheme-unknown, verify-failed */ }
```

Object-safe runtime wrapper:

```rust
pub struct Signer<S: SigSuite> { sk: S::SigningKey, vk: S::VerifyingKey }
impl<S: SigSuite> Signer<S> {
    pub fn generate() -> Self { /* OsRng */ }
    pub fn from_secret_bytes(bytes: &[u8]) -> Result<Self, SigError>;
    pub fn secret_bytes(&self) -> Vec<u8>;        // for persistence
    pub fn sign(&self, msg: &[u8]) -> SignedAttestation;
    pub fn vk_bytes(&self) -> Vec<u8>;
    pub fn scheme_id(&self) -> &'static str { S::SCHEME_ID }
}

pub struct SignedAttestation {
    pub scheme_id: &'static str,
    pub pubkey: Vec<u8>,
    pub sig: Vec<u8>,
}
```

Scheme-dispatched verification (the only place that needs to know about every suite):

```rust
/// Verify msg + sig against pubkey, dispatching by scheme_id. Returns Ok(())
/// on valid signature; Err on any failure (unknown scheme, parse, verify).
pub fn verify_attestation(
    scheme_id: &str,
    pubkey: &[u8],
    msg: &[u8],
    sig: &[u8],
) -> Result<(), SigError>;
```

Implementation: `match scheme_id { "secp256k1" => ..., "falcon-512" => ..., _ => Err(UnknownScheme) }`. Adding a suite = one new arm.

Wire-encoding helpers (all base64url-no-pad; one shared encoder/decoder for byte fields):

```rust
/// "<scheme>.<pubkey_b64>.<sig_b64>.<id_b64>"  — for commitment/receipt headers.
pub fn encode_attested_id(att: &SignedAttestation, id: &[u8; 32]) -> String;
pub fn parse_attested_id(s: &str) -> Result<ParsedAttestedId, SigError>;

/// "<scheme>.<pubkey_b64>.<sig_b64>"  — for the request header (no id; server has the message).
pub fn encode_attested_msg(att: &SignedAttestation) -> String;
pub fn parse_attested_msg(s: &str) -> Result<ParsedAttestedMsg, SigError>;
```

Dependencies (`crates/rpc/Cargo.toml`):
- `k256 = { version = "0.13", features = ["ecdsa", "ecdsa-core", "alloc", "sha2"] }` — always
- `rand = "0.8"` — always
- `base64 = "0.22"` — always (URL_SAFE_NO_PAD engine)
- `pqcrypto-falcon = { version = "0.4", optional = true }` — gated by `pq` feature
- `pqcrypto-traits = { version = "0.3", optional = true }` — gated by `pq` feature

Feature flag:
```toml
[features]
default = []
pq = ["dep:pqcrypto-falcon", "dep:pqcrypto-traits"]
```

Code: `Falcon512Suite` impl, the `Falcon512` variant of `AnySigner`, and the falcon arm in `verify_attestation` are all `#[cfg(feature = "pq")]`. The `--suites` CLI flag's accepted values list is also feature-gated (only `secp256k1` available without `pq`; `secp256k1` + `falcon-512` with).

## Plan

### Step 0 — Coordinated catgrad change: `Cid<T>::Display` to base64url (~30 LOC, sibling repo)

File: `/home/grw/src/catgrad/catgrad/src/cid/typed.rs`.

- `impl<T> std::fmt::Display for Cid<T>` swaps the byte-by-byte hex loop for `base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&self.bytes)`.
- `parse_hex_32` (used by serde Deserialize) renamed and reimplemented as `parse_base64url_32`.
- Existing tests update accordingly (the `cid_display_round_trips_hex` test renames + updates encoded form).
- Add `base64 = "0.22"` to `catgrad/Cargo.toml`.

After this lands as a sibling commit, bump the catgrad git rev in `/home/grw/src/node/Cargo.toml`'s `[workspace.dependencies]` and proceed with Step 1+.

### Step 1 — `SigSuite` trait + `Secp256k1Suite` + `Falcon512Suite` + helpers (~400 LOC)

Files: `crates/rpc/src/sig.rs` (new), `crates/rpc/src/lib.rs` (export), `crates/rpc/Cargo.toml` (deps).

The two suite impls share zero code (different libraries) but are forced into the same trait shape — exactly what we want for swap testing.

Tests (~150 LOC):
- For each suite (parameterized via macro or duplicated):
  - Round-trip sign / verify with a known msg.
  - `vk_to_bytes` / `vk_from_bytes` and `sig_to_bytes` / `sig_from_bytes` round-trip.
  - `sk_to_bytes` / `sk_from_bytes` round-trip (needed for persistence).
  - Tampered msg / tampered sig → `verify` returns `false`.
- Cross-suite:
  - `verify_attestation` dispatches correctly for each scheme.
  - Unknown `scheme_id` returns `SigError::UnknownScheme`.
  - Mixing pubkey-from-suite-A with sig-from-suite-B fails cleanly (pubkey parse error or verify failure, never panic).
- Encoding round-trips: `encode_attested_id` ↔ `parse_attested_id`, `encode_attested_msg` ↔ `parse_attested_msg`.
- Property test (proptest): random msgs + random keypairs round-trip for both suites.

### Step 2 — Drop `quote_id` from the wire (~80 LOC)

Files:
- `crates/rpc/proto/execute.proto`: remove `GetQuoteResponse.quote_id`; rename `ExecuteRequest.quote_id` (string) → `commitment_id` (bytes, exactly 32).
- `crates/rpc/src/pb/...` regenerates.
- `crates/executor/src/state.rs`: `ExecutorState::quotes: HashMap<Cid<TextExecution>, QuoteRecord>`. `create_quote` returns `Cid<TextExecution>`; `get_quote` keys on `Cid`.
- `crates/executor/src/executor/actor/quote.rs`: drop `make_id("quote")`; insert into `store` keyed by `commitment_id`.
- `crates/executor/src/executor/actor/execution.rs`: parse 32-byte `commitment_id` from `ExecuteRequest`, look up by it.
- `crates/executor/src/executor/mod.rs` + `handle.rs`: `QuoteOutcome` no longer carries `quote_id`.
- `crates/cli/src/execution.rs`: `PreparedRoute::Local` and `RemoteExecution` carry `commitment_id: Cid<TextExecution>` (was `quote_id: String`).

Two same-input requests now collide on the same quote slot — natural property of content addressing.

### Step 3 — Persist signing keys + accept-suites config (~120 LOC)

Refactor `crates/cli/src/identity.rs`:
- Extract the file-handling parts (load_or_create, atomic-rename, restricted-perms) into private helpers parameterized by file path and key length.
- Add `pub fn load_or_create_signing_key<S: SigSuite>(path: Option<&Path>) -> Signer<S>`. Each suite has its own file at `~/.hellas/signing-key.<scheme>` (e.g., `signing-key.secp256k1`, `signing-key.falcon-512`). One file per `(host, suite)` identity — a node can have multiple suite identities simultaneously.
- Storage format: raw secret bytes only (length is fixed per suite, recoverable from the trait). No embedded scheme tag — the filename encodes that.

Wire-up sites:
- `crates/cli/src/commands/serve/node.rs` (executor): load or generate a signing key for **each** suite in `--suites` (since the server may need to sign responses with any of them per the symmetric rule). Build a `SuiteRegistry` (a small map from `scheme_id` → `Arc<AnySigner>`), pass to `Executor::spawn`.
- `crates/cli/src/commands/gateway/state.rs` (gateway): load the signing key for the gateway's top-preference suite only (gateway always signs with its top preference; doesn't need keys for other suites). Store the gateway's `--suites` accept list separately for verifying provider responses.

`AnySigner` enum-erases the suite parameter at the boundary. **Always held behind `Arc`** — Rust enums are sized to their largest variant (Falcon-512's keypair is ~2 KB vs secp256k1's ~64 B), but `Arc<AnySigner>` is 8 bytes and clones are refcount bumps. We never store, pass, or clone the bare enum.

```rust
pub enum AnySigner {
    Secp256k1(Signer<Secp256k1Suite>),
    /// Falcon variant is ~2 KB larger than secp256k1; AnySigner is therefore
    /// always wrapped in Arc to avoid stack/copy overhead. The raw enum is
    /// not exposed past construction — every consumer takes Arc<AnySigner>.
    #[cfg(feature = "pq")]
    Falcon512(Signer<Falcon512Suite>),
}
impl AnySigner {
    pub fn sign(&self, msg: &[u8]) -> SignedAttestation { /* dispatch */ }
    pub fn scheme_id(&self) -> &'static str;
    pub fn vk_bytes(&self) -> Vec<u8>;
}
```

CLI flags (one unified flag added to both `serve` and `gateway`, mirroring the existing `--accept-dtypes` shape):
- `--suites <csv>` — preference-ordered list of suites the node will offer (signs outgoing with the first) and accept (verifies incoming against the same list). Default: all compiled-in suites with `secp256k1` first.
  - `--suites secp256k1` — only secp256k1 (signs and accepts).
  - `--suites secp256k1,falcon-512` — prefers secp256k1 for signing; accepts both for verification.
  - `--suites falcon-512` — only Falcon (requires `--features pq`).

The flag's allowed-values list is `cfg(feature = "pq")`-gated — `falcon-512` is rejected at clap-parse time on default builds, with a hint to rebuild with `--features pq`.

Negotiation pattern (no explicit handshake, no retry):
- Client signs the request with its **top suite** in `--suites`. Sends.
- Server checks the scheme tag is in its own `--suites` list. If not → `Status::unauthenticated("scheme '<X>' not in our suites list <[secp256k1, ...]>")` — error message includes server's accepted set so the operator can adjust their `--suites` config and rerun.
- No automatic retry. The premise: both ends configure preference lists; if the intersection is empty, that's an operator config mismatch, not a per-request runtime decision.
- Symmetric for server-signed responses: server signs commitment/receipt with the same suite the client used for the request (per the symmetric scheme rule). Client verifies the scheme is in its own `--suites` list (defense-in-depth — should always be, since it picked the suite). If not → `Status::data_loss("provider used scheme '<X>' not in our accepted list")`.

Tests in `identity.rs` extend: per-suite file round-trips, both suites coexist when both files present, missing file generates new key with restricted perms.

The signing keys are independent of the iroh transport key. `rm ~/.hellas/signing-key.secp256k1 && restart` rotates only the secp256k1 identity.

### Step 4 — Sign commitment at quote time (~40 LOC)

File: `crates/executor/src/executor/actor/quote.rs`.

After computing `commitment_id`:
```rust
let attestation = self.signer.sign(commitment_id.as_bytes());
```

Update `ExecutionProvenance` (`crates/rpc/src/provenance.rs`):
```rust
pub struct ExecutionProvenance {
    pub commitment_id: [u8; 32],
    pub commitment_attestation: SignedAttestation,
}
```

`provenance::write_provenance_metadata` writes the single combined header `x-hellas-commitment: <encode_attested_id(...)>`. `read_provenance_metadata` parses, calls `verify_attestation`, returns the verified `ExecutionProvenance`.

Drop the old `COMMITMENT_HEADER` ("x-hellas-commitment-id") and `RECEIPT_HEADER` ("x-hellas-receipt-id") string constants. Replace with `COMMITMENT_HEADER = "x-hellas-commitment"` / `RECEIPT_HEADER = "x-hellas-receipt"`.

### Step 5 — Sign receipt at execution end (~60 LOC)

Files:
- `crates/executor/src/runner.rs`: after `let receipt_cid = final_state.receipt_id();`, `let receipt_attestation = signer.sign(receipt_cid.as_bytes());`. Thread the signer into the runner via `ExecuteJob` (already carries shared `metrics`).
- `crates/executor/src/state.rs` `Termination::Completed`: add `receipt_attestation: SignedAttestation`.
- `crates/executor/src/state.rs::into_pb()`: serialize `receipt_attestation` into `pb::Completed.receipt_sig: AttestationSig` (typed proto sub-message — see proto change in Step 2).
- `crates/executor/src/worker.rs`: pass through.
- `crates/cli/src/execution.rs`:
  - `Outcome::Completed` gains `receipt_attestation: SignedAttestation` (typed) — parsed from the wire.
  - `parse_outcome` extracts and returns it.

### Step 5.5 — Canonical signing-payload encoding (`hellas_rpc::sig::canonical`) (~120 LOC)

New module `crates/rpc/src/sig/canonical.rs` (or sibling file).

For each signed RPC type, define a parallel `Signed*Request` struct with serde derives that mirrors the wire prost type field-for-field, plus a `From<&WireType>` impl. Sign the **DAG-CBOR canonical encoding** of the parallel struct via `serde_ipld_dagcbor` (the same encoder catgrad uses for `Cid<T>` content addressing). The DAG-CBOR canonical form sorts map keys by length then lexicographically — fully spec-deterministic, no "in practice" disclaimer.

```rust
#[derive(Serialize)]
pub struct SignedQuoteRequest<'a> {
    pub huggingface_model_id: &'a str,
    pub huggingface_revision: &'a str,
    pub input: &'a [u8],
    pub prompt_tokens: u32,
    pub max_new_tokens: u32,
    pub stop_token_ids: &'a [u32],
    pub program: &'a [u8],
}

impl<'a> From<&'a GetQuoteRequest> for SignedQuoteRequest<'a> { ... }

pub fn canonical_bytes<T: Serialize>(value: &T) -> Vec<u8> {
    serde_ipld_dagcbor::to_vec(value).expect("dag-cbor encoding of a typed signed request never fails")
}
```

Same shape for `SignedQuotePromptRequest`, `SignedQuoteChatPromptRequest`, `SignedExecuteRequest`. Signing path: `canonical_bytes(&signed_view).pipe(sign)`. Verifying path: same canonicalization on the received wire type, then `verify`.

**Field-type discipline** (preventive, applies to all `Signed*Request` structs):
- All fields use bare types (`String`, `u32`, `Vec<u8>`, `Vec<u32>`) — never `Option<T>`. proto3 default-presence semantics decode missing-vs-present-with-default scalars to the same Rust value, but `Option<T>` would surface them as different. We avoid the footgun by not exposing presence-distinction in the parallel struct.
- The proto schema for any signed RPC must NOT use `optional` (proto3 explicit-presence) on its fields. Documented in the .proto file with a `// SIGNED — no optional fields` marker.
- The `From<&WireType>` impl is total: every wire-decoded value maps to exactly one parallel-struct value; no normalization branches.

**Proptest coverage** (≥7 properties):
- For each `Signed*Request` type, randomly-generated instances produce **stable bytes across many encode invocations**: `canonical_bytes(&v) == canonical_bytes(&v)` (1000+ runs).
- For each type, two structurally-equal instances produce **identical bytes**: `canonical_bytes(&a) == canonical_bytes(&b)` when `a == b` field-by-field.
- For each type, two structurally-different instances produce **different bytes**: `a != b ⇒ canonical_bytes(&a) != canonical_bytes(&b)`.
- Round-trip via `From<&WireType>`: `canonical_bytes(&Signed::from(&wire))` produces the same bytes as constructing the Signed directly with the same field values.
- **Wire round-trip stability**: `prost::encode(wire) → prost::decode → From → canonical_bytes` produces the same bytes as `From → canonical_bytes` directly. Catches any prost (de)serialization quirks that would break server-side recomputation.

Tests added in the same module + `#[cfg(test)]` propelled by the `proptest` crate (add to dev-deps).

Adding a new signed RPC type later: define the parallel `Signed*Request`, write the From impl, add proptest coverage. Mechanical; no SigSuite changes.

### Step 6 — Client signs execution-related requests (~60 LOC)

File: new `crates/cli/src/sig_interceptor.rs`, used in `crates/cli/src/execution.rs` and `crates/rpc/src/driver.rs`.

**Scope: only the execution-related RPCs are signed.** Specifically `get_quote`, `quote_prompt`, `quote_chat_prompt`, and `execute`. The introspection RPCs (`list_models`, `get_stats`, `get_model_stats`, `preload`) bypass signing — no `x-hellas-request` metadata attached, no verification on the executor side. Rationale: signed attestation is about what we committed to running and what we ran; status/introspection isn't part of that chain.

The `tonic::service::Interceptor` API only sees `Request<()>` (header-time, body not yet serialized) — too early to sign. We wrap explicitly at the driver call sites with the canonical-signing helper from Step 5.5:

```rust
async fn get_quote(&mut self, request: GetQuoteRequest) -> Result<QuotedResponse, Status> {
    let signed_view = SignedQuoteRequest::from(&request);
    let canonical = canonical_bytes(&signed_view);
    let attestation = self.signer.sign(&canonical);    // signs with top-preference suite
    let mut req = tonic::Request::new(request);
    req.metadata_mut().insert(
        "x-hellas-request",
        encode_attested_msg(&attestation).parse().unwrap(),
    );
    let resp = self.client.get_quote(req).await?;
    // extract + verify provider sig from response metadata...
    Ok(...)
}
```

No retry: `signer.sign(...)` always uses the top-preference suite. If the server rejects on scheme mismatch, the error surfaces to the caller for the operator to address by updating `--suites` config.

Driver layer takes `Arc<AnySigner>` at construction (`RemoteExecuteDriver::with_service` gains a signer parameter). `AnySigner` holds the top-preference suite's `Signer<S>`.

For the local mpsc path, the gateway calls `ExecutorHandle::quote/execute` directly. We add the same sign-+-attach step at the local driver-shim site (`impl ExecuteDriver for ExecutorHandle` in `crates/executor/src/executor/handle.rs`) so the verification path is symmetric and one code path verifies both local and remote.

### Step 7 — Executor verifies request sig + checks accept-list (~60 LOC)

File: `crates/executor/src/executor/handle.rs`.

In each of the four execution-related tonic `Execute` trait methods (`get_quote`, `quote_prompt`, `quote_chat_prompt`, `execute`) — NOT `list_models`/`get_stats`/`get_model_stats`/`preload`:
1. Extract `x-hellas-request` from `request.metadata()`. If absent → `Status::unauthenticated("missing x-hellas-request")`.
2. Parse via `parse_attested_msg`. On error → `Status::unauthenticated("malformed x-hellas-request")`.
3. Check the parsed scheme is in the executor's `--suites` list. If not → `Status::unauthenticated("scheme '<X>' not in our suites list <[...]>")` — error message includes both the rejected scheme and the accepted set so the client/operator can self-correct.
4. Build the canonical `Signed*Request` struct via `From<&WireType>`, then `canonical_bytes(&signed)`.
5. Call `verify_attestation(scheme, &pubkey, &canonical, &sig)`. On failure → `Status::unauthenticated("request signature invalid")`.
6. Stash the verified client pubkey in tracing span fields for audit.
7. Stash the request's signing scheme (for use in Step 8: response will be signed with the same suite).

Introspection RPCs skip steps 1-7 entirely — no metadata required. Strict policy on the signed RPCs: any failure rejects the request.

### Step 8 — Server signs response with same suite + gateway verifies (~70 LOC)

**Server side** (in the executor handlers, after Step 7's signature check):
- The handler picks the signing key matching the request's scheme from the `SuiteRegistry` built in Step 3. (It must exist, since we accepted the scheme — both come from the same `--suites` list.)
- Sign commitment_id with that key. Result attached to `Response::metadata_mut()` as `x-hellas-commitment`.
- For execute: pass the signing key (or a closure using it) into the runner so receipt is also signed with the matching suite.

**Gateway side** (`crates/cli/src/execution.rs`):
1. After parsing `x-hellas-commitment` → `(scheme, pubkey, sig, commitment_id)`, check the scheme matches what the gateway signed the request with. (Should always match given the symmetric rule, but verify defensively.) If it mismatches → `Status::data_loss("provider signed response with scheme '<X>' but we sent the request with '<Y>'")`.
2. Check the scheme is in the gateway's `--suites` list (defense-in-depth; if the gateway accepts a suite, it can verify it). If not → `Status::data_loss(...)`.
3. Call `verify_attestation(scheme, &pubkey, &commitment_id, &sig)`. If error → `Status::data_loss("provider commitment failed verification")`.
4. After observing `Outcome::Completed { receipt_cid, receipt_attestation, .. }`, repeat the same checks. On failure, transform the outcome into `Outcome::Failed { error: "provider receipt failed verification" }` so the HTTP user sees an honest failure rather than a forged success.
5. Stash the verified provider pubkey alongside the provenance for downstream consumers.

For the local in-process path: same verification path (cheap, symmetric, single source of truth).

### Step 9 — HTTP layer rewrite (~80 LOC)

Files:
- `crates/cli/src/commands/gateway/provenance_layer.rs`:
  - Read `ExecutionProvenance` from extensions → render `x-hellas-commitment: <encode_attested_id(...)>`.
  - Switch the receipt extension type from `Cid<TextReceipt>` to `SignedReceipt { id: Cid<TextReceipt>, attestation: SignedAttestation }`. Render `x-hellas-receipt: <encode_attested_id(...)>`.
  - Remove the old separate-headers test scaffolding; add new tests asserting that `parse_attested_id` round-trips on the rendered headers and that `verify_attestation` accepts the test signer's output.
- `crates/cli/src/commands/gateway/mod.rs`:
  - Replace `provenance_sse_event` with `commitment_sse_event(prov: &ExecutionProvenance) -> Event`.
  - Replace `receipt_sse_event(cid: &Cid<...>)` with `receipt_sse_event(receipt: &SignedReceipt) -> Event`.
  - Both emit the JSON shape from "Header / wire layout" above (scheme + pubkey + sig + id).
- `crates/cli/src/commands/gateway/{openai,anthropic,plain}.rs`:
  - SSE handlers: yield `commitment_sse_event` first, then `receipt_sse_event` at terminal completion.
  - Buffered handlers: insert `ExecutionProvenance` and `SignedReceipt` extensions on the response.
  - Note: the chat-template / stream-mapper refactor (`ChatTurn`, `OpenAiStreamMapper`, etc.) already in flight has reshaped these handlers but the provenance hooks survive at the same logical points — capture provenance into a local var early, insert into extensions before returning.

### Step 9.5 — `hellas-cli identity show` subcommand (~40 LOC)

New subcommand under `crates/cli/src/main.rs` + `crates/cli/src/commands/identity.rs` (or extend the existing identity-handling module).

```
$ hellas-cli identity show
iroh-node-id:           <base64url>
signing-key.secp256k1:  <base64url pubkey>
signing-key.falcon-512: <base64url pubkey>          # only if file exists / pq build
```

Loads `~/.hellas/identity` and the per-suite signing keys (any that exist), prints their pubkeys. No file creation — read-only inspection. Errors out cleanly if no identity present.

Useful for ops setting up trust stores ("which pubkey should I add to the gateway's known-providers list?") and for sanity-checking that key rotation worked.

### Step 10 — Tests + verification (~200 LOC)

- `crates/rpc/src/sig.rs` — see Step 1.
- `crates/rpc/src/provenance.rs` — extend tonic-metadata round-trip tests to cover the new combined header form + sig verification, for both suites.
- `crates/cli/src/commands/gateway/provenance_layer.rs` — extend the existing Router `oneshot` test to assert:
  - `x-hellas-commitment` header is present and parseable.
  - `verify_attestation` succeeds against the test signer's output.
  - `x-hellas-receipt` likewise.
  - Run the test once per suite (parameterized).
- A new integration-shape test in the layer module exercising both extensions through the full Router for both suites.

End-to-end smoke (manual):
```
RUST_LOG=info cargo run --release --features candle -- gateway --port 8080 --local --force-model HuggingFaceTB/SmolLM2-135M-Instruct
curl -i -X POST http://localhost:8080/v1/chat/completions \
  -H 'content-type: application/json' \
  -d '{"model":"X","messages":[{"role":"user","content":"hi"}],"max_tokens":4}'
```
Expect two new headers; verify `<scheme>.<pubkey>.<sig>.<id>` parses and `verify_attestation` accepts.

Two-process smoke + suite swap:
```
hellas-cli serve --suites falcon-512 --port 50051 &
hellas-cli gateway --suites secp256k1,falcon-512 --remote 127.0.0.1:50051 ...
```
Confirms a Falcon-only executor and a gateway that prefers secp256k1 (but falls back to falcon-512 when secp256k1 isn't accepted by the configured server) interoperate via scheme-tag dispatch.

## Critical files

In modification order:
- `crates/rpc/Cargo.toml` — k256, pqcrypto-falcon, pqcrypto-traits, base64, rand deps
- `crates/rpc/src/sig.rs` — new (trait + both suites + dispatch + encoding)
- `crates/rpc/src/lib.rs` — export
- `crates/rpc/proto/execute.proto` — drop quote_id, rename to commitment_id, add `AttestationSig` + `Completed.receipt_sig`
- `crates/rpc/src/provenance.rs` — extend ExecutionProvenance with attestation field; rename header constants
- `crates/rpc/src/driver.rs` — sign outgoing request bodies; verify response sigs
- `crates/executor/src/state.rs` — quotes keyed by Cid; Termination carries receipt_attestation
- `crates/executor/src/executor/mod.rs` — Executor holds SuiteRegistry
- `crates/executor/src/executor/actor/quote.rs` — sign commitment, drop quote_id
- `crates/executor/src/executor/actor/execution.rs` — lookup by commitment_id
- `crates/executor/src/executor/handle.rs` — verify request sig in tonic Execute impl; attach commitment metadata to Response (with same-suite signing key)
- `crates/executor/src/runner.rs` — sign receipt at termination
- `crates/executor/src/worker.rs` — thread receipt_attestation through Termination
- `crates/cli/src/identity.rs` — refactor for signing-key persistence; add load_or_create_signing_key
- `crates/cli/src/commands/serve/node.rs` (and gateway-spawn site) — load signing keys for all suites in `--suites`, build SuiteRegistry, pass to executor + gateway
- `crates/cli/src/main.rs` — `--suites` flag on `serve` and `gateway`
- `crates/cli/src/execution.rs` — RequestSigner; client-side verify; commitment_id replaces quote_id; receipt_attestation in Outcome
- `crates/cli/src/commands/gateway/state.rs` — PreparedGeneration carries SignedReceipt
- `crates/cli/src/commands/gateway/provenance_layer.rs` — render new headers, update tests
- `crates/cli/src/commands/gateway/mod.rs` — new SSE event helpers (commitment + receipt)
- `crates/cli/src/commands/gateway/{openai,anthropic,plain}.rs` — yield commitment / receipt events; insert SignedReceipt ext on buffered

Estimated diff: ~900 LOC including tests. Largest single chunk is `sig.rs` with two suite impls.

## Verification

After each step cluster:
1. `cargo check --workspace --features candle`
2. `cargo test --workspace --features candle` — both suites tested at every level.
3. `cargo clippy --workspace --features candle --all-targets`

After full implementation:
4. End-to-end smoke per Step 10.
5. **Suite-swap smoke**: run two processes, one signing with secp256k1 and one with Falcon-512, on opposite sides of a request — both verifications succeed.
6. **Header-size sanity**: with `--suites falcon-512`, confirm `curl -i` shows headers and the response parses cleanly. Note the byte size; check it's under axum's default 16 KB header limit.

## Out of scope

- **Identity-bound `commitment_id`** — `commitment_id` is `Hash(program, parameter_cids, prompt_tokens, policy)` per catgrad's `TextExecution` definition. It does NOT include `client_pubkey`. Consequence: two clients submitting identical inputs produce the same commitment_id, so the receipt_sig alone doesn't uniquely bind to a specific client. 3rd-party verifiers reconstruct the chain by combining `(request_bytes, client_sig)` with `(commitment_id, commitment_sig)` — the request bytes connect the client to the commitment via recomputation. Adding `client_pubkey` to TextExecution's hashed inputs would seal this gap but is a catgrad-side change that breaks content-addressed caching; deferred to a separate PR if/when the property is needed for a verifier UX.
- **Iroh ed25519 key flipped to ephemeral** — needs a discovery-layer rework. Separate PR. The wire format chosen here doesn't preclude this — when iroh keys go ephemeral, nothing in the signed-attestation surface changes.
- Iroh ed25519 keys involved in any signing path.
- Session keys, delegation chains, automatic key rotation. (Future; the wire format is forward-compatible — adding a `x-hellas-delegation` header alongside doesn't break anything.)
- Additional signature suites beyond secp256k1 and Falcon-512. ML-DSA, SPHINCS+, etc. all slot into the trait without ceremony when needed.
- HTTP/2 trailers (rejected previously: browser EventSource invisible).
- Pubkey-by-hash + lookup channel (could shrink PQ wire size by transmitting `H(pubkey)` and fetching the full pubkey out of band; adds a distribution layer; revisit if PQ wire size becomes a real problem).
- Signing of intermediate identifiers other than `commitment_id`, `receipt_cid`, and the request body hash.
- Verification policies beyond strict reject-on-failure.
- Persistent client-pubkey trust store ("I trust providers K1, K2, ..."). Verifiers get the verified pubkey out of every signature; what they do with it is upstream of this PR.
- Signing-key rotation tooling beyond "delete the file and restart."
- Identity-based signatures, ring sigs, threshold sigs, aggregatable sigs — interesting PQ properties but none address our problem better than just-include-the-pubkey.
- Replay protection on the signed request (no nonce / timestamp). The natural replay surface is bounded by content-addressed quote consumption (executor consumes quote on Execute; subsequent replays of the same Execute fail with "quote not found"). A captured Quote sig CAN be replayed against the same executor to produce duplicate quote slots, which is benign (idempotent). Front-running an unsent Quote is the residual concern; deferred.
