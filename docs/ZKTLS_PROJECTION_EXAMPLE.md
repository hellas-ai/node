# ZkTLS Adaptor: Worked Example Of Projection

A worked example for `docs/AXES.md`'s projection model. Not normative —
it's a thought-experiment to demonstrate why the customer wire layer
must be allowed to be richer than the kernel `Call`, why projection has
to be context-aware, and what a non-trivial `ProtocolId` evidence
requirement looks like.

Status: example. Not an implementation plan. When the actual ZkTLS
adaptor is built, this doc gets superseded by the implementation's own
design notes.

## What ZkTLS actually settles

A ZkTLS fetch isn't a `Dial(peer, cert)` operation; that's a session
helper. What gets *settled* is an entire HTTP-over-TLS exchange with a
provable proof that the response bytes came from a server matching some
identity policy at some point in time, without revealing redacted
portions of the transcript.

The settlement question is: *the producer asserts that bytes `B` were
returned by a server satisfying identity policy `P` for request `R`
during freshness window `W`, under proof profile `Z`.* Anything less
loses the property that makes ZkTLS interesting.

## Customer-facing wire

The customer-facing RPC stays domain-idiomatic. Web developers using
this adaptor don't want to think about Calls or ProtocolIds; they want
to fetch URLs.

```proto
package hellas.zktls_fetch.v1;

service ZkTlsFetch {
  rpc Fetch(ZkTlsFetchRequest) returns (stream ZkTlsFetchEvent) {
    option (hellas.v1.binding) = BINDING;
  };
}

message ZkTlsFetchRequest {
  string method                                = 1;  // "GET", "POST"
  string url_or_origin                         = 2;
  RequestHeadersPolicy headers_policy          = 3;  // pin headers, allow others
  bytes  request_body_commitment               = 4;  // 32B or empty
  ServerIdentityPolicy server_identity_policy  = 5;  // SPKI hash, CA, SNI
  TranscriptRedactionPolicy transcript_redact  = 6;
  FreshnessPolicy freshness_policy             = 7;  // nonce or time bound
  ZkProofProfile proof_profile                 = 8;  // proving system + version
}
```

Note what's *not* on the wire: no `Dial`. No raw peer or certificate
fields. The customer says "I want to fetch this URL under this policy";
the adaptor handles the session-level concerns invisibly.

## Kernel-level projection

```rust
impl Adaptor for ZkTlsFetch {
    const PROTOCOL: ProtocolId = ProtocolId::ZkTls;
    type Request = ZkTlsFetchRequest;
    type Output  = ZkTlsFetchReply;
}

impl ProjectCall for ZkTlsFetch {
    fn project_call(req: &ZkTlsFetchRequest, ctx: &ProjectionContext)
        -> Result<Call, ProjectionError>
    {
        let validated = ValidatedZkTlsFetch::try_from((req, ctx))?;
        Ok(Call {
            protocol: ProtocolId::ZkTls,
            payload: validated.canonical_payload_bytes(),
        })
    }
}

impl ProducesTlsWitness for ZkTlsFetch {
    type TlsWitness = ZkTlsProof;
}
```

The kernel sees `Call { protocol: ZkTls, payload: <canonical bytes> }`.
A receipt verifier checks:

1. Producer signature over the claim.
2. Result commitment is the canonical hash of the returned bytes.
3. Evidence commitment (in the signed body) is the digest of the
   attached `ZkTlsProof`.
4. The `ZkTlsProof`'s public inputs bind:
   - `call_commitment`
   - `result_commitment`
   - `server_identity_policy`
   - `transcript_redact` commitment
   - `freshness_policy`
   - `proof_profile`

That last point is `ProtocolId::ZkTls`'s validity gadget. Different
protocols have different gadgets.

## Why projection has to be context-aware

`ZkTlsFetchRequest::freshness_policy` may specify "within the last 60
seconds." The wire request doesn't (and can't) pin the exact second.
Projection resolves the policy against `ctx.now` to a concrete bound
written into the canonical payload, so both sides project the same
bytes and the verifier knows what window the proof is supposed to
satisfy.

Similarly, `ServerIdentityPolicy` might reference "CAs in the system
trust store." The bytes for "which CAs" depend on the projector's
local CA bundle — that bundle is pinned in `ctx.ca_bundle_digest` and
written canonically into the payload. The producer and verifier must
agree on the same bundle digest, or projection deterministically fails.

Hidden defaults (an `ambient: time_now` that isn't echoed back) are
exactly what `ProjectionError::AmbientDefault` exists to refuse.

## What's not in the customer wire

A few session-level things stay either implicit or in `NonBinding`
helpers:

- TLS handshake state — owned by the producer; not on the wire.
- Connection pooling / multiplexing — implementation detail.
- Cert chain fetching — happens before the settled call; could be a
  `NonBinding` helper `PrefetchCerts(origin)` that returns a snapshot.

The settled call is the *response under the policy*, not the bytes of
the handshake.

## What this demonstrates for AXES.md's design

- A customer RPC can be much richer than the projected `Call`. The
  projection is the contract.
- A `ProtocolId`'s evidence requirement (here: `ZkTls` requires the
  proof to bind specific public inputs) lives in the kernel's
  validity gadget for that protocol, not in the adaptor's code.
- Marker traits (`ProducesTlsWitness`) describe what the adaptor can
  do; the ProtocolId's requirements describe what an adaptor must do
  to claim it.
- Settlement-relevant evidence (ZkProof) must be **committed** into
  the signed receipt body, not stapled detachably. Otherwise an
  attacker could swap proofs.
- The customer never sees `Dial` or any session machinery; the
  protocol never sees `ZkTlsFetchRequest` directly. The projection
  boundary is the only place these two views meet.

## See also

- `docs/AXES.md` — the layering ADR this example illustrates.
- `../hellas-kernel/KERNEL.md` §"Adapter And Executor Layer" — kernel
  side of the boundary.
- `../whitepaper/HYPEREDGES.md` §"Typed Evidence" — evidence taxonomy.
