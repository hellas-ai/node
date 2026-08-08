# 07 — Protocol corners that are implemented but untested

The Xet read path is tested against production for the cases we have
fixtures for. These are the ones we do not.

## Untested against production

- **Multi-term and multi-xorb reconstructions.** Every fixture is a
  single term in a single xorb. Term ordering, and the assembly loop
  that concatenates across terms, are exercised only by construction.
- **Non-zero `offset_into_first_range`.** The trimming is unit-tested in
  `hf::verified`, never against a real response that carries one.
- **The HTTP layer itself.** `token`, `reconstruction` and the range
  GETs are covered only by the `#[ignore]`d live test. Nothing in CI
  touches them.
- **Multi-range fetch entries.** The docs describe an
  `X-Xet-Signed-Range` parameter pinning a URL to specific byte ranges.
  Observed responses carry CloudFront params and no such parameter, so
  the multi-range split behaviour is unconfirmed. This was originally
  written into our own module docs as fact from an investigation report
  and corrected only when a test failed — a reminder to write down what
  the wire showed, not what a summary said.

## Covered, for contrast

- Hashing, against the published Xet spec vectors, including a
  796-chunk multi-level Merkle rollup.
- Chunk framing and LZ4-frame decoding, against 50,469 bytes fetched
  from HuggingFace's CAS.
- Byte-grouping (scheme 2), against a fixture from
  `HuggingFaceTB/SmolLM2-135M` whose two chunks are both ragged-length,
  with HuggingFace's own reconstructed plaintext as the oracle.

## Not implemented at all

- **The write path.** Uploading requires the MDB shard format — header,
  file-info section, CAS-info section, footer with HMAC key protection
  and shard key expiry. Roughly 32 KB of spec. Its own slice if we ever
  want to *be* a CAS rather than read one.
- **`VERIFICATION_KEY`** is not vendored. The range hashes it keys live
  in upload-path shards and no read API returns them, so it is only
  needed for the write path or for a range-verification scheme of our
  own.
