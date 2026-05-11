//! Canonical digest domain separators.

#![allow(clippy::redundant_pub_crate)]

pub(crate) const COIN_GENESIS: &[u8] = b"hellas.edge.genesis.v1";
pub(crate) const COIN_PAYOUT: &[u8] = b"hellas.edge.coin.v1";
pub(crate) const EDGE_OPEN: &[u8] = b"hellas.edge.edge.v1";
pub(crate) const RESOLVE: &[u8] = b"hellas.edge.resolve.v1";
pub(crate) const SEAL_PLACEHOLDER: &[u8] = b"hellas.seal.placeholder.v1";
pub(crate) const SIG_PLACEHOLDER: &[u8] = b"hellas.sig.placeholder.v1";
pub(crate) const TERMS_BASIC: &[u8] = b"hellas.terms.basic.v1";
