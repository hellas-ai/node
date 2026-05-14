# Implementation Progress

Working tracker for the node refactor in `PLAN.md`. Keep `PLAN.md` as the
design source; update this file as implementation lands.

## Completed

- [x] Move protobuf sources to `proto/hellas`.
- [x] Add generated protobuf crate at `crates/pb` (`hellas-pb` package).
- [x] Remove `hellas-rpc` protobuf ownership.
- [x] Remove `hellas-rpc` protobuf re-export; call sites import flattened
  `hellas_pb::hellas` bindings directly.
- [x] Phase 1: add `crates/core`.
  - [x] `Digest`, tuple hashing, and `Commitment`.
  - [x] `Commitment` now hashes canonical self-tagged object bytes directly;
    the old external `(scheme, role, payload)` wrapper was removed.
  - [x] protocol tag registry.
  - [x] secp256k1 producer signatures and `ProducerId`.
  - [x] `JsonBytes`.
  - [x] canonical DAG-CBOR helpers using the catgrad-aligned encoder.
  - [x] `CommitmentScheme`, `EvidencedScheme`.
  - [x] `Symbolic` and `Opaque` scheme types.
  - [x] receipt bodies, signed receipts, receipt envelopes.
  - [x] `verify_receipt` and `verify_delivery`.
  - [x] phase acceptance tests.
- [x] Phase 2: proto and execution reshape.
  - [x] `hellas.v1.Execute` exposes only generic `RunTicket`.
  - [x] `hellas.symbolic.v1.Symbolic.CreateTicket` owns symbolic ticket
    creation.
  - [x] `hellas.opaque.v1.Opaque.CreateTicket` owns opaque ticket creation.
  - [x] corrected `SymbolicRequest` to be core protocol only:
    the request names only a catnix `InputId<TextExecution>`.
  - [x] aligned symbolic request commitments with catgrad `TextExecution`
    CIDs, and symbolic result/evidence commitments with catgrad
    `TextArtifact` CIDs.
  - [x] moved Hugging Face model resolution, tokenization, dtype negotiation,
    and text generation helpers into courtesy quote APIs.
  - [x] added `QuotePreparedText`; `QuotePrompt` and `QuoteChatPrompt` now
    delegate through the same courtesy path and return the derived
    CID-only `SymbolicRequest`.
  - [x] `Ticket.request_commitment` replaces the old quote id on the run path.
  - [x] terminal `WorkFinished.receipt` carries the signed receipt envelope.
  - [x] symbolic tickets are keyed by `hellas-core` request commitments.
  - [x] CLI, remote driver, and executor call sites use the new API.
  - [x] checks: `cargo check --workspace`, `cargo test --workspace --lib`,
    `cargo check -p hellas-cli --features candle`, and
    `cargo check -p hellas-pb --features compile`.
- [x] Phase 3: refactor current symbolic execution.
  - [x] Courtesy text quotes construct the catnix `TextExecution` locally from
    the prepared prompt `TokenIds`, `TextPolicy`, and starting `TextArtifact`.
  - [x] The core symbolic protobuf carries only
    `SymbolicRequest.text_execution_cid`.
  - [x] The local worker signs symbolic receipts against a catnix
    `TextArtifact` CID rather than a raw token digest.
  - [x] Direct CID-only symbolic `CreateTicket` resolves locally-known
    catnix `TextExecution` CIDs through the executor-local artifact store.
  - [x] Terminal symbolic receipt signing moved from the worker to the actor
    so output artifacts are recorded before the producer signs the receipt.
  - [x] The artifact store keeps canonical catnix bytes alongside typed local
    values for `TokenIds`, `TextPolicy`, `TextExecution`, `TextState`, and
    `TextArtifact`.
  - [x] Completed symbolic runs now record generated-token `TokenIds`,
    materialized `TextState`, and final `TextArtifact` CIDs.
  - [x] Canonical catnix bytes are inserted into an `iroh-blobs` blob store,
    with the iroh BLAKE3 hash checked against the catnix CID.
  - [x] The executor artifact blob store has memory and filesystem backends;
    `node serve` uses the filesystem store at `--artifact-store-path` (default
    `$HOME/.hellas/artifacts`) while local one-shot executors stay memory-only.
  - [x] Catnix canonical text objects can now be decoded from their canonical
    bytes, so the executor can treat typed maps as caches over the blob store.
  - [x] The filesystem artifact store persists a small symbolic metadata index
    for `BoundTermId -> ModelLocator` and
    `TextExecutionId -> TextArtifactId`, allowing restart-shaped recovery of
    local symbolic requests and cached lazy substitutions.
  - [x] Output-addressed continuations from locally-known `TextArtifact`
    outputs can be materialized by resolving their persisted `TextState`.
  - [x] Lazy `SourceRef::Input` can substitute a locally cached output artifact
    for the referenced input-addressed execution.
  - [x] Courtesy artifact APIs can put/fetch one canonical catnix artifact by
    CID. They deliberately do not publish symbolic interpretation metadata;
    `BoundTermId -> ModelLocator` and `TextExecutionId -> TextArtifactId` stay
    provider-local until that boundary is designed explicitly.
  - [x] `hellas artifact put|get` exposes the courtesy artifact APIs for
    operator-controlled artifact transfer between a local file and a provider's
    artifact store.
  - [x] Lazy `TextExecutionId -> TextArtifactId` metadata is validated when
    used, so a provider rejects mappings to identity artifacts or outputs for a
    different execution.
- [x] Split protobufs by concern.
  - [x] `buf` lint configured at the workspace root.
  - [x] Five package split:
    `hellas.v1`, `hellas.symbolic.v1`, `hellas.opaque.v1`,
    `hellas.swarm.v1`, and `hellas.courtesy.v1`.
  - [x] Core `hellas.v1` owns shared tickets, streaming events, receipt
    envelope bytes, and `Execute.RunTicket`.
  - [x] Symbolic and opaque packages each own their own `CreateTicket` RPC.
  - [x] Courtesy exposes non-core quote/tokenizer/model/stat helpers.
  - [x] Swarm exposes node/discovery metadata.
  - [x] Node serving and discovery advertise `Execute`, `Symbolic`, `Opaque`,
    `Courtesy`, and `Node` separately.
- [x] Add v1 opaque execution without worker IPC.
  - [x] `Opaque.CreateTicket` accepts `OpaqueRequest { service, method, payload }`.
  - [x] Opaque payloads are exact UTF-8 JSON bytes; the executor validates JSON
    syntax but does not normalize or interpret the payload.
  - [x] Opaque execution currently completes locally with the payload as output,
    producing a real `ReceiptEnvelope::Opaque` signed by the producer key.
  - [x] Remote opaque uses `Opaque.CreateTicket` plus generic
    `Execute.RunTicket`; no courtesy API is required.
  - [x] Added executor test coverage for signed opaque delivery receipts.
- [x] Add public opaque CLI entry point.
  - [x] `hellas opaque --service ... --method ... --payload ...` sends exact
    JSON bytes through `Opaque.CreateTicket` and `Execute.RunTicket`.
  - [x] `--payload-file` reads exact JSON bytes from disk.
  - [x] Local mode uses the in-process executor when built with
    `hellas-executor`.
  - [x] Remote mode can use direct node targeting or Opaque-service discovery.
- [x] Phase 4: persistent producer signing key in runtime.
  - [x] producer signing keys persist separately from iroh transport identity
    at `$HOME/.hellas/signing-key.secp256k1` by default.
  - [x] `--producer-key-path` overrides the path for tests and multiple nodes
    on one host.
  - [x] `producer-key show` prints the public key and derived `ProducerId`
    without printing the secret key or touching the iroh identity file.
  - [x] `serve`, gateway local execution, `llm --local` / `--verify-local`,
    and `opaque --local` use the persistent producer key.
- [x] Phase 7: gateway headers.
  - [x] public gateway metadata is now `hellas.commitment` plus
    `hellas.receipt`.
  - [x] HTTP headers are now `x-hellas-commitment` and `x-hellas-receipt`.
  - [x] `hellas.receipt` carries the full signed `ReceiptEnvelope` DAG-CBOR
    bytes encoded base64url, not a catgrad-only text receipt CID.
  - [x] symbolic shadow verification still compares the projected catgrad
    `TextArtifact` CID internally, without exposing it as the universal gateway
    receipt.
- [x] Phase 8: tests and cleanup.
  - [x] refreshed stale `PLAN.md` language around CID-only symbolic requests,
    split protobuf services, gateway metadata, and receipt commitments.
  - [x] removed stale gateway-extension references to deleted docs/plans.
  - [x] stale-name scan is clean for removed quote ids and old gateway metadata
    names across `crates`, `PLAN.md`, and `PROGRESS.md`.
  - [x] targeted checks passed: `cargo check -p hellas-pb --features compile`,
    `cargo check -p hellas-core --lib`, and
    `cargo check -p hellas-executor --lib`.
  - [x] full workspace `cargo fmt`, `cargo check --workspace --all-targets`,
    and `cargo test -p hellas-core -p hellas-rpc -p hellas-executor --lib`
    pass.

## Next Up

## Deferred

- [ ] Phase 5: opaque worker IPC.
- [ ] Native iroh-blobs ALPN alongside the tonic services. The current
  `tonic-iroh-transport` builder owns router construction and only exposes
  tonic service registration, so the first implementation uses the courtesy
  artifact API over existing transport.
- [ ] A design for sharing symbolic interpretation metadata, if we decide that
  should be a courtesy API rather than provider-local state.
