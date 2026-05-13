# hellas-rpc

`hellas-rpc` owns Hellas node-level RPC plumbing: service identities,
peer-state primitives, admission/accounting policy, peer exchange, provenance
metadata helpers, and the client/server support code used by node consumers.

It does not own every transport. Today the main transport is tonic over iroh,
but the peer model is intentionally transport independent.

## Mental Model

The network is peer-to-peer. Avoid thinking of a peer as "client" or "server"
in the domain model.

The stable identities are:

- `PeerId`: one remote actor.
- `(PeerId, service)`: one remote capability/session scope.
- `(PeerId, service, method)`: one RPC accounting/admission scope.
- Transport links: implementation detail owned by the transport layer.

A peer can initiate requests to us and also serve requests from us. Both
directions update the same peer record.

## Peer Facts vs Service Sessions

`PeerRegistry` stores global facts keyed by `PeerId`:

- first/last seen time
- transport security and derived auth level
- trust flag
- latency EMA
- request/error/cancellation counters
- discovered service facts

Service facts are keyed inside the peer by service name. This means a peer can
be a node provider, executor, courtesy provider, custom downstream service, or
any combination of those.

It is fine for transports to maintain one stateful session per `(peer, service)`.
It is also fine for a transport to temporarily have multiple physical links for
the same `(peer, service)` during races, reconnects, or inbound/outbound overlap.
Those links must converge into the same peer facts. They must not become
separate logical peers.

## Current Transport Boundary

With tonic over iroh today, service ALPN selects the service at connection
setup. That naturally makes the current iroh connection pool scoped like:

```text
(remote peer, service ALPN)
```

Inbound accepted iroh connections and outbound pooled iroh connections may both
exist at the same time. That is allowed. `hellas-rpc` records observations about
the remote peer and service; it does not try to own or deduplicate physical
transport links.

If we later move to a single Hellas session ALPN with substreams, the logical
model should stay the same:

```text
PeerId -> service sessions -> RPCs
```

Only the transport implementation changes.

## Responsibilities

`PeerRegistry` is the pure state machine.

- No async.
- No clock.
- No storage.
- No transport handles.
- Bounded by `PeerRegistryConfig`.

Use it directly only when a target needs strict sans-io control.

`PeerManager` is the normal application wrapper.

- Owns shared registry state.
- Supplies wall-clock timestamps.
- Provides closure-based reads and snapshots.
- Exposes `PeerSession` and `PeerServiceSession<S>` views over the shared state.
- Provides RAII RPC guards so dropped requests release in-flight slots.

Generated clients, hand-written clients, and transport adapters should generally
talk to `PeerManager`, not directly to `PeerRegistry`.

`PeerDirectory` is server-side peer exchange policy.

- Tracks inbound request accounting.
- Applies peer and global rate limits for peer disclosure.
- Filters by service.
- Ranks peers.
- Computes disclosure limits.

Use it for APIs like `GetKnownPeers`.

## Type-Safe Methods

Do not pass RPC method names as ad-hoc strings in application code. The shared
plumbing accepts raw `RequestKind` values for extensibility, but typed clients
should use method marker types:

```rust
pub struct ListModels;

impl MethodKey for ListModels {
    type Service = CourtesyService;
    const NAME: &'static str = "ListModels";
}
```

Built-in Hellas method markers live under `hellas_rpc::service::methods`. Future
RPC codegen should emit the same shape for downstream `.proto` files.

## Calling Patterns

Discovery and transport adapters record capabilities before application code
needs them:

```rust
manager.observe_discovered_service(
    peer,
    DiscoverySource::Transport("discovery"),
    <CourtesyService as ServiceKey>::NAME,
    TransportSecurity::Untrusted,
)?;
```

Outbound RPCs acquire admission before I/O and finish exactly once:

```rust
let courtesy = manager.peer(peer).service::<CourtesyService>();
let mut permit = courtesy.acquire_method::<methods::ListModels>(
    1.0,
    RpcObservation::authenticated_transport("iroh"),
)?;

match client.list_models(request).await {
    Ok(response) => {
        permit.finish_ok();
        Ok(response)
    }
    Err(err) => {
        permit.finish_err(err.to_string());
        Err(err)
    }
}
```

Connection establishment failures use `finish_connect_err`. That records the
failure without claiming the remote service was authenticated or usable.

Inbound RPCs are accounting signals, not capability proof. A browser can call
`GetKnownPeers`; that does not mean it provides the node service.

```rust
directory.observe_inbound_request(
    requester,
    observed_rtt_ms,
    InboundRequestPolicy::rate_limited_method::<methods::GetKnownPeers>(4.0, 1.0),
)?;
```

## Rules

- Peer identity is global. Never create separate logical peers for inbound vs
  outbound traffic.
- Service capability is per `(peer, service)`.
- Request accounting is per `(peer, service, method)`.
- Inbound requests do not imply the requester serves that service.
- Discovery, successful outbound RPCs, and explicit signed handshakes may imply
  service capability.
- Transport security observations should only get stronger unless a future
  policy explicitly models downgrade/revocation.
- Physical transport links are not the source of truth. They feed observations
  into peer state.

## Persistence

The registry is intentionally in-memory. Persistence belongs at the embedding
layer because targets have different storage:

- native binaries may use sqlite, rocksdb, or flat files;
- browsers may use IndexedDB or local storage;
- ESP32-class targets may use NVS/flash with small fixed-size records.

Persist durable facts such as peer id, trust, labels, last known services, and
last successful contact. Do not persist in-flight counts or live permit state.
Rate-limit buckets may be persisted only if a target needs restart-resistant
abuse protection.

## Extensibility

Downstream crates can define their own `.proto` services and implement
`ServiceKey` for their service marker. They get the same peer/session/admission
model:

```rust
pub struct MyService;

impl ServiceKey for MyService {
    const NAME: &'static str = "example.my.v1.MyService";
}
```

The shared primitives do not require Hellas-owned services. Custom services are
just additional `(peer, service)` capabilities.

## What This Crate Does Not Promise

`hellas-rpc` does not guarantee one physical connection per peer. That belongs
to the transport layer.

`hellas-rpc` does not require every transport to expose the same session shape.
Iroh may use service ALPN sessions; WebSocket or UART transports may use a muxed
pipe; a future wire layer may use one peer session with service substreams. All
of those map into the same peer model as long as observations flow through
`PeerManager` / `PeerDirectory`.
