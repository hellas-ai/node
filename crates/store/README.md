# `hellas-store`

A content store addressed by **Xet file hash** — the same hash
HuggingFace uses.

That single choice is what the design turns on: **an existing
HuggingFace cache is already a populated store.** Adopting one is
indexing, not downloading.

## The shape

A Nix store, or a BitTorrent client's view of its own disk. An entry is
named by a hash of its content, so where it came from is not part of its
identity — which is what makes substitution sound rather than merely
convenient. Any source producing the right bytes is as good as any
other.

| BitTorrent | here |
| --- | --- |
| infohash | Xet file hash |
| metainfo / `.torrent` | the chunk list |
| piece + piece hash | chunk + `DATA_KEY`-keyed chunk hash |
| HTTP seed | HuggingFace, ModelScope |
| peers | other providers *(not built)* |
| fastresume | `fastresume::Records` |

## Using it

```
hellas store adopt                 # index the HuggingFace cache in place
hellas store adopt --cache PATH    # or a specific one
hellas store status                # what is remembered
hellas store fetch --id <64 hex> --repo org/name --out PATH
```

`adopt` is a read, not a copy: the store points at the files where they
already lie. Cost is one read per blob — and one read *ever* per
unchanged blob, because the result is persisted.

Measured on a real 29-blob cache: **647 ms cold, 549 µs warm.**

## Indexing produces two things, and the second is the valuable one

`index` returns the content id **and the chunk list**. Keeping only the
id would discard the expensive half of a pass we have to make anyway.

The chunk list is the metainfo. A Xet file hash is a Merkle root over
exactly those descriptors, so holding them makes a later *partial* fetch
verifiable. This matters because **HuggingFace's reconstruction protocol
returns no chunk hashes at all** — content arriving from an untrusted
source is otherwise unverifiable until the whole file is reassembled,
which is a poor way to discover a peer is lying.

## Two rules that are not obvious

**Never trust an id you did not compute.** HuggingFace advertises an
`x-xet-hash` per file. For Xet-native uploads it is exactly the Xet hash
of the content; for legacy-LFS content bridged into Xet it is
measurably *not*, with sha256 confirming the bytes were the ones HF
meant. Ids in this store are ones we computed.

**`have` and `materialize` are different questions.** `have` is local,
cheap, and touches no network — it is the only one a quote may ask.
`materialize` spends bandwidth and disk, and belongs behind admission
control. The split is enforced by two traits: a `Substituter` answers
where content already is; only a `Fetcher` can make it appear.

## Verification

Three layers, deliberately:

1. Per chunk, when we hold a chunk list, as bytes arrive.
2. Whole file, against the id that was requested, before anything is
   written.
3. Re-indexed after writing — so a *fetcher* that lies cannot leave
   bytes in the store under a name they do not own.

## Conformance

The hashing is checked against the published Xet spec vectors, and the
xorb decoder against 50,469 bytes fetched from HuggingFace's own CAS.

Not covered: byte-grouping (compression scheme 2) is exercised only
against this crate's own encoder, because both chunks in the production
fixture use scheme 1. A fixture containing a BG4 chunk should precede
depending on BG4 content.

## Why this crate uses `ureq` and not `reqwest`

Measured, not preferred. The workspace cannot have one HTTP client: at
whole-workspace scope, `iroh` pulls `reqwest` and `hf-hub` pulls `ureq`
regardless of what this crate chooses. Dropping `ureq` here removes
**zero** crates from the workspace and three from a CLI-only build, out
of 381.

The rule, so nobody has to re-derive it:

> **Streaming or async-context HTTP uses `reqwest`. Synchronous,
> fully-buffered content fetch inside `hellas-store` uses `ureq`.**

`reqwest::blocking` would panic if called from inside an async runtime,
and `ContentStore::index` is a sync fn reachable from async code. `ureq`
has no such landmine. Converging the other way — `reqwest` everywhere —
would take this crate from 46 to 121 dependencies to save three.

Both clients are configured with **bundled Mozilla roots**
(`rustls-webpki-roots` / `webpki-roots`) rather than the OS trust store.
Two clients in one binary trusting two different sets of certificate
authorities is a silent policy split, and "which roots did we trust when
we pulled these weights" should have one answer — a reproducible one,
independent of what an admin or MDM installed on the host.

## Not built

Peer-to-peer. `Fetcher` is the seam it implements, and the chunk lists
the store already keeps are what will make a peer's partial response
verifiable — the property HuggingFace's protocol cannot provide. What it
needs is a wire protocol: announce what you hold, ask who has an id,
request chunk ranges.
