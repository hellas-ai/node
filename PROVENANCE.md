# `ExecutionProvenance` always-Some refactor

Investigation notes from chasing a real bug in the e2e suite. **Local
working notes, not to be committed.**

## The current shape

```rust
// crates/rpc/src/provenance.rs
pub struct ExecutionProvenance {
    pub commitment_id: [u8; 32],
}
```

Four call sites carry an `Option<ExecutionProvenance>` today, but all four
trace back to a single decision:

- `crates/cli/src/execution.rs:590`     — `PreparedRoute::provenance()`
- `crates/cli/src/execution.rs:448`     — `PreparedExecution::provenance()` (delegates to primary)
- `crates/cli/src/commands/gateway/state.rs:61`            — state field
- `crates/cli/src/commands/gateway/provenance_layer.rs:102` — middleware param

The single source of `None`:

```rust
// crates/cli/src/execution.rs
fn provenance(&self) -> Option<&ExecutionProvenance> {
    match self {
        PreparedRoute::Local        { provenance, .. } => Some(provenance),
        PreparedRoute::RemoteDirect(remote)            => Some(&remote.provenance),
        PreparedRoute::RemoteDiscovery { .. }          => None,  // <--
    }
}
```

Rationale (from the existing doc-comment): `RemoteDiscovery` defers quoting
until streaming time (when a peer responds), so at preparation time there's
no commitment yet. The gateway falls back to in-band SSE events.

## How `commitment_id` is currently produced

```rust
// crates/executor/src/executor/actor/quote.rs
let request_commitment = Symbolic::commit_request(&symbolic_request);
```

Where `Symbolic::commit_request(req) = RequestCommitment::from_digest(req.text_execution_cid)`.

The commitment is a pure digest from the `SymbolicRequest`'s
`text_execution_cid`. *Looks* gateway-derivable — but the conversion
`QuotePreparedTextRequest → SymbolicRequest` runs through:

```rust
// crates/executor/src/executor/actor/quote.rs
let plan     = QuotePlan::from_prepared_text_request(request, &supported_dtypes)?;
let resolved = self.artifacts.record_prepared_text(&plan).await?;
let symbolic_request = resolved.symbolic_request.clone();
```

`record_prepared_text` is a stateful op on the executor's artifact store:
it materializes bound terms, resolves the initial artifact (genesis vs
ancestor), and produces the `text_execution_cid`. The bound-term part is a
pure `binding_digest(&locator)`, but the initial-artifact materialization
needs the artifact present in the store.

## Three options for "always-Some provenance"

### (1) Duplicate the catnix derivation on the gateway

Factor `record_prepared_text` into a pure "compute CIDs" path that doesn't
require artifact materialization. Use it on the gateway to produce the same
`text_execution_cid` (and thus the same `commitment_id`) as the executor
will produce later. Verifiability is strongest: gateway-attested
commitment matches the executor's receipt commitment.

- **Pro**: end-to-end verifiable; the gateway's pre-flight commitment is
  the *same* commitment that ends up in the receipt.
- **Con**: requires refactoring catnix usage; the genesis vs initial-artifact
  fork is the tricky bit (gateway might not have the artifact).

### (2) Different commitment shape: `RequestIntentCommitment`

A pure hash over `QuotePreparedTextRequest` contents
(`huggingface_model_id` + `huggingface_revision` + `prompt_token_ids` +
`max_new_tokens` + `start` + `stop_token_ids`). Computed by the gateway
trivially; verifiable against the request payload.

- **Pro**: gateway always has one; trivial to compute.
- **Con**: it's a *different* commitment from the executor's
  `text_execution_cid` commitment. Headers/SSE would carry both —
  gateway's "intent" commitment + executor's "execution" commitment when
  available. New type, mild protocol cruft.

### (3) Reshape the type, not the data

Drop the `Option`. Make `PreparedRoute::RemoteDiscovery` carry whatever
partial commit-derivation it *can* do before peer selection. If that
turns out to require the catnix work from (1) → fold into (1). If we
accept that `RemoteDiscovery` can't produce a real commitment without a
peer, this option degenerates to (2)-with-a-different-name.

## Decision needed

Q1: For our e2e test that just needs the response headers to assert against
something, (2) is cheapest. For the protocol to be actually verifiable
end-to-end in discovery mode, only (1) works correctly.

Q2: Practical for now — the breaking e2e test wants *what* exactly?
Header presence? Header-vs-receipt match? Knowing this picks the option.

## Adjacent: how the bug surfaces

Browsing the call sites, the `Option` cascades:
- The middleware (`provenance_layer.rs`) won't attach `x-hellas-commitment`
  headers when prov is `None`.
- State (`state.rs`) tracks "have we seen provenance yet?" — extra logic
  for the unknown-yet case.
- Tests that grep response headers for the commitment hex fail on
  discovery-mode routes because the header is absent.

Removing the `Option` collapses ~50 lines of "if let Some(prov)" sprinkled
across these files into straight-line code.
