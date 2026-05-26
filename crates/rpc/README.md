# hellas-rpc

The Hellas node RPC stack: service identities, codegen-emitted client/server
traits, peer-state primitives, admission/accounting policy, response-trailer
provenance helpers, and the call-side helpers used by node consumers.

Transport-independent in spirit; the in-tree transport is iroh's QUIC
substreams via [`hellas-wire`](../wire). The wire layer's protocol is unique
to Hellas — there is no longer a tonic/h2 codepath in production. A h2/gRPC-
compat transport is stubbed for future use; see "Open work".

## Mental model

The network is peer-to-peer. Avoid thinking of a peer as "client" or
"server" in the domain model.

Stable identities:

- `PeerId` — one remote actor (32 bytes, today the iroh endpoint public key).
- `(PeerId, service)` — one remote capability/session scope.
- `(PeerId, service, method)` — one RPC accounting/admission scope.
- Transport links — implementation detail owned by the transport layer.

A peer can initiate requests to us and also serve requests from us. Both
directions update the same peer record.

## Layers

```
┌──────────────────────────────────────────────────────────────┐
│ application: CLI commands, gateway, executor handlers       │
├──────────────────────────────────────────────────────────────┤
│ generated clients & dispatchers (per service)               │
│   Courtesy / Execute / Symbolic / Opaque / Node             │
│   each → ServiceMarker, MethodMarker, Client trait + impl,  │
│           Handler trait, Server dispatcher.                 │
├──────────────────────────────────────────────────────────────┤
│ hellas_rpc::call helpers (transport-generic)                │
│   unary, unary_with_trailer, server_streaming →             │
│     `StreamingCall<R>` (Stream<Item = Result<R,WireStatus>> │
│     + `#[must_use] finish() -> Result<Trailer,WireStatus>`) │
│   dispatch_unary, dispatch_server_streaming                 │
├──────────────────────────────────────────────────────────────┤
│ hellas_wire::transport: StreamTransport, RecvHalf,          │
│   SendHalf, Inbound, TransportContext, Trailer, WireStatus  │
├──────────────────────────────────────────────────────────────┤
│ transports                                                  │
│   iroh::IrohTransport (QUIC bidi substreams) ← in prod      │
│   ws::* (browser / native / CF Durable Object)              │
│   h2::* (stub, gRPC-compat target)                          │
└──────────────────────────────────────────────────────────────┘
```

## Codegen

`build.rs` reads the `.proto` files via `protox`, runs `prost-build` for
message types, and emits hand-rolled service code via `quote!` +
`prettyplease`. Per service:

- `ServiceMarker` impl on a unit struct — carries `ALPN`, etc.
- `MethodMarker` impl per method — carries `METHOD_ID` (a 32-bit
  Blake3-derived id), `NAME`, and the request/response prost types.
- `pub trait XClient` — transport-agnostic in the trait signature, with one
  blanket `impl<T: StreamTransport> XClient for XClientImpl<T>` over the
  generic implementation. Methods delegate to `crate::call::unary` /
  `crate::call::server_streaming` parameterized by `MethodMarker`.
- `pub trait XHandler` — server-side handler trait. One concrete impl per
  application (`ExecutorHandle` in-tree for Courtesy/Execute/Symbolic/
  Opaque; `NodeHandlerImpl` for Node).
- `pub struct XServer<H>(pub H)` + `impl<T: StreamTransport, H: XHandler>
  Dispatcher<T> for XServer<H>` — routes inbound substreams by
  `method_id` and invokes the right handler method.

The generated tables `KNOWN_SERVICES`, `KNOWN_METHODS`, and
`KNOWN_RATE_LIMITED_METHODS` are populated alongside the codegen and feed
the peer directory's policy lookups.

## Call helpers

`crate::call` exposes the transport-generic helpers the codegen emits into.
They are not part of the user-facing API; users call the generated `*Client`
methods.

- `unary<T,M>(transport, req, headers) -> Result<M::Response, WireStatus>`.
- `unary_with_trailer<T,M>(...) -> Result<WithTrailer<M::Response>, _>` —
  exposes the server's terminal trailer metadata to the caller (provenance
  bytes, receipt envelopes, OTel span context, …). The unary protocol shape
  is enforced: exactly one body chunk, then EOF, then a terminal trailer.
  Extra bodies or missing trailers surface as `WireCode::Internal`.
- `server_streaming<T,M>(...) -> Result<StreamingCall<M::Response>, _>` —
  iteration + termination. `StreamingCall<R>` implements
  `Stream<Item = Result<R, WireStatus>>` for body chunks only; the
  `#[must_use]` `finish(self) -> Result<Trailer, WireStatus>` method
  surfaces the terminal trailer (or non-Ok status as `Err`). Body and
  trailer are sequenced by ownership: the protocol invariant "0+ bodies,
  then exactly one terminal trailer" cannot be encoded in an invalid
  order at this API surface.
- `dispatch_unary<T,M,...>`, `dispatch_server_streaming<T,M,...>` —
  server-side counterparts; the generated `XServer<H>` dispatcher calls
  these to drive the handler.

## Peers

Sans-io peer-state primitives. No transport, runtime, clock, or storage
dependencies; callers pass timestamps in.

- `PeerRegistry` (in-memory) holds global facts keyed by `PeerId`:
  first/last seen, transport security + derived `AuthLevel`, trust flag,
  RTT EMA (via `hellas_wire::latency::EwmaLatency`), request/error/
  cancellation counters, per-service state.
- `PeerManager` (`Arc<Mutex<PeerRegistry>>` + monotonic clock) is the
  callable wrapper used by application code.
- `PeerDirectory` adds disclosure policy (`min_disclosed_auth_level`,
  ranking, `ranked_known_peers`) and an inbound-admission split:
  `observe_inbound_request(peer, rtt, policy)` distinguishes
  `InboundRequestPolicy::AccountOnly` (counters but no rate limit) from
  `RateLimited` (per-peer token bucket via `TokenBucket`).

## Address model

Hellas carries *identity* (`PeerId` → iroh `EndpointId`) as durable state.
Direct addresses (SocketAddrs, relay URLs, custom routes) are *ephemeral
dial hints* bundled into an iroh `EndpointAddr` at the call site and
handed to `Endpoint::connect(addr, alpn)` once. They never enter
`PeerManager` / `PeerDirectory`. `presets::N0` configures pkarr/DNS
address lookup, so identity-only routing works when iroh can resolve the
peer.

The CLI's `ExecutionRuntime::remote(secret_key, seed_targets)` builds the
endpoint + `ServiceRegistry`; `RemoteNodeTarget::addr: EndpointAddr` is
the dial-time bundle. `Pool::transport(impl Into<EndpointAddr>)` is the
final dial boundary.

## Provenance trailers

Server handlers emit signed execution provenance (commitment digest, etc.)
in the response `Trailer::metadata`. `crate::provenance` provides
`read_provenance_metadata` and `write_provenance_metadata` helpers; the
codegen-emitted handler return type is `WithTrailer<R>` so handlers can
attach metadata without a separate ack channel. Missing provenance is a
hard failure at the call site (no zero-digest fallback).

## Open work

- **h2 / gRPC-compat transport** (task #14) — `hellas_wire::h2` is a stub.
  Lands a `StreamTransport` impl over `h2` so external gRPC clients can
  reach Hellas services.
- **Admission middleware** — peer identity is not yet threaded into the
  serve path, so request-admission policy is not enforced there.
- **ESP32 follow-ups** — `get_known_peers` returns an empty list on
  device; the wire dispatcher doesn't surface peer identity to handlers.
  See `HELLAS_WIRE_CUTOVER_FINDINGS.md` §§8–9.
- **Generation-rollover defense** — `u16` generation counter wraps to 0
  after `u16::MAX` slot reuses. Defense-in-depth only; gen=0 doesn't
  appear on the wire from a legit peer, so the wrap isn't exploitable.

## Where the docs are

- This README — orientation.
- `~/src/explorer/HELLAS_WIRE_CUTOVER_FINDINGS.md` — chronology of the
  cutover (21 findings, mostly resolved).
- Inline comments at the WHY-non-obvious points.

## Feature gates

The crate exposes several feature gates. The important ones today:

- `iroh` / `iroh-client` / `iroh-server` — enable the iroh transport
  binding and its codegen.
- `discovery` — peer-exchange + mDNS + DHT (today partial — see
  `HELLAS_WIRE_CUTOVER_FINDINGS.md` §14).
- Per-service (`execute`, `symbolic`, `opaque`, `courtesy`, `swarm`,
  `all-protocols`) — gate the codegen for one proto package each.
- `node` — binary-side bundle pulling in catgrad/chatgrad/tokenizers.

`server` enables the dispatcher emission. Default-features is intentionally
empty so downstream binaries opt in only what they ship.
