//! gRPC-compatible HTTP/2 transport.
//!
//! Scope-deferred for v1 — the iroh + ws transports cover all current
//! consumers. This module exists so the `h2` feature flag can be carved
//! out for the eventual implementation without churning the feature
//! matrix.
//!
//! Spec for the planned implementation is in HELLAS_WIRE_PLAN_v2.md
//! under "gRPC compat on h2 / h3".

#![allow(dead_code)]

/// Placeholder for the eventual `H2Transport` over any
/// `tokio::io::AsyncRead + AsyncWrite`. Will translate `Frame::Open`
/// to an HTTP/2 HEADERS frame with `:path = /{service}/{method}` and
/// the gRPC 5-byte length prefix on each DATA frame.
pub struct H2Transport;

impl H2Transport {
    pub fn new<S>(_io: S) -> Self {
        unimplemented!("h2 transport pending — see HELLAS_WIRE_PLAN_v2.md")
    }
}
