# 03 — Peer-to-peer fetch

## Where it plugs in

`Fetcher` (`crates/store/src/lib.rs`) is the seam, already separate from
`Substituter` precisely so that "who can spend bandwidth" is a type-level
distinction. A peer source implements `Fetcher`.

## Why this is better than the HuggingFace path, not merely equal

HuggingFace's reconstruction response carries **no chunk hashes** —
verified live. So a client without an index cannot verify anything until
it has reassembled a whole file, which is a poor way to discover a peer
is lying after fourteen gigabytes.

We already keep the chunk list from indexing. `xorb::decode_chunks`
already verifies chunk-by-chunk when given one. So a peer's partial
response is verifiable **as it arrives** — a property the HTTP seed
cannot offer. This is the BitTorrent property, and it is already built;
only the transport is missing.

## What is missing

A wire protocol over iroh:

- **announce** — what content ids this node holds;
- **have** — does anyone hold this id;
- **request** — give me chunks `[a, b)` of id X.

Note the asymmetry worth exploiting: HuggingFace's CAS is
content-addressed for reads but **not for authorisation** — a token is
scoped to one repo and revision. A peer protocol has no such constraint
and can be purely content-addressed.

## Watch out for

- The transfer unit is not the addressing unit on the HTTP side: chunks
  ship inside xorbs of ~1024. A peer protocol can speak chunks
  directly, and should.
- Do not let a peer choose the chunk boundaries. They come from our own
  index, or from re-chunking what arrives.
- Partial-materialization state (which chunks we hold of an incomplete
  file) is the other half of resume data and is what makes an
  interrupted peer fetch resumable rather than restarted.
