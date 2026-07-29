#![allow(clippy::redundant_pub_crate)]

//! All chain-version constants in one place.
//!
//! Changing any value here is a **protocol-incompatible change**. Every
//! deployment must agree on these, and every BLAKE3 commitment computed
//! by the kernel depends on them — coin ids, edge ids, terms commitments,
//! and close hashes would all shift under a different choice of sizes
//! or domain separators.
//!
//! Group by area; document each constant's role; never inline a "magic
//! number" that lives here.

// ── Identifier and hash sizes (bytes) ─────────────────────────────────

/// Length of every kernel hash output. BLAKE3-256 produces a 32-byte
/// digest; every commitment ([`crate::TermsHash`], [`crate::PayloadHash`])
/// and every derived identifier ([`crate::CoinId`], [`crate::EdgeId`],
/// [`crate::BlockHash`]) is this size.
pub(crate) const HASH_LENGTH: usize = 32;

/// Length of a kernel object identifier. Equal to [`HASH_LENGTH`] because
/// every id is derived as a BLAKE3 commitment over canonical fields.
pub(crate) const ID_LENGTH: usize = HASH_LENGTH;

/// Length of a compressed settlement key. 33 bytes is the SEC1
/// compressed form (`02` / `03` prefix byte plus the 32-byte
/// x-coordinate) used by native secp256k1 keys and passkey P-256 keys.
pub(crate) const KEY_LENGTH: usize = 33;

/// Length of each P-256 affine coordinate and compact signature scalar.
pub(crate) const P256_COORDINATE_LENGTH: usize = 32;

/// Length of a compact ECDSA settlement signature: `r ‖ s`, 32 bytes
/// each, no DER framing.
pub(crate) const SIG_LENGTH: usize = 64;

/// Length of a compact dispute seal. v1 commits to a 32-byte seal; if
/// the dispute mode produces a larger artifact (e.g. a ZK proof), the
/// seal is a commitment to that artifact and the verifier resolves it
/// out of band.
pub(crate) const SEAL_LENGTH: usize = 32;

/// Maximum bytes of `authenticatorData || clientDataJSON` carried by one
/// `WebAuthn` authorization assertion.
///
/// Mirrors Tempo's 2 KiB bound: large enough for browser-produced
/// assertion metadata, small enough to keep every kernel transaction
/// payload statically bounded.
pub const MAX_WEBAUTHN_DATA_LENGTH: usize = 2048;

// ── Operation bounds ──────────────────────────────────────────────────

/// Maximum coins that can fund one party in a v1 edge open.
///
/// Four inputs per party covers the expected one-or-two-coin channel
/// open while keeping validation fully bounded. Raising this changes
/// operation shape, resource costs, and model bounds, so it is a
/// chain-version change.
pub const MAX_PARTY_INPUTS: usize = 4;

/// Maximum coins that can fund one v1 edge open. Equals
/// `2 * MAX_PARTY_INPUTS`.
pub const MAX_EDGE_INPUTS: usize = MAX_PARTY_INPUTS * 2;

/// Maximum coins that can be produced by one v1 edge close.
///
/// Four outputs leaves room for maker, taker, and small protocol-defined
/// splits without making every close pay for an unbounded payout
/// fanout. Raising this is also a chain-version change.
pub const MAX_EDGE_OUTPUTS: usize = 4;

// ── Domain separators (BLAKE3 binding prefixes) ───────────────────────
//
// Every kernel hash is computed as `BLAKE3(domain ‖ canonical_bytes)`
// where `domain` is one of the byte strings below. Changing any of
// these strings breaks compatibility with every previously-committed
// hash.

/// Prefix for genesis coin id derivation. Input: allocation index (u32).
pub(crate) const COIN_GENESIS: &[u8] = b"hellas.edge.genesis.v1";

/// Prefix for payout coin id derivation. Inputs: edge id, output index,
/// owner key.
pub(crate) const COIN_PAYOUT: &[u8] = b"hellas.edge.coin.v1";

/// Prefix for edge id derivation. Inputs: terms hash, maker funding ids,
/// taker funding ids.
pub(crate) const EDGE_OPEN: &[u8] = b"hellas.edge.edge.v1";

/// Prefix for open payload hash. Inputs: edge id (which already binds
/// funding ids and terms hash via [`Self::EDGE_OPEN`] domain separation).
/// Maker and taker both sign this hash to authorize one open.
pub(crate) const OPEN: &[u8] = b"hellas.edge.open.v1";

/// Prefix for close payload hash. Inputs: edge id, close kind tag,
/// terms hash, payouts.
pub(crate) const CLOSE: &[u8] = b"hellas.edge.close.v1";

/// Prefix for the basic-terms commitment. Inputs: protocol code,
/// parties, timeout height, timeout payouts.
pub(crate) const TERMS_BASIC: &[u8] = b"hellas.terms.basic.v1";

/// Prefix for the stake-bond terms commitment. Inputs: protocol code,
/// parties, timeout height, timeout payouts, treasury key, award, stake,
/// max job price, max dispute cost.
pub(crate) const TERMS_STAKE_BOND: &[u8] = b"hellas.terms.stake_bond.v1";

/// Prefix for the deterministic seal placeholder used by tests and
/// modelling. Inputs: protocol code, close kind tag, close hash.
#[cfg(any(test, feature = "placeholders"))]
pub(crate) const SEAL_PLACEHOLDER: &[u8] = b"hellas.seal.placeholder.v1";

/// Prefix for the deterministic signature placeholder used by tests and
/// modelling. Inputs: half index (0 or 1), key, close hash.
#[cfg(any(test, feature = "placeholders"))]
pub(crate) const SIG_PLACEHOLDER: &[u8] = b"hellas.sig.placeholder.v1";
