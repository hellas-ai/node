//! gRPC-compatible HTTP/2 transport.
//!
//! The iroh + ws transports cover current consumers. This module reserves
//! the `h2` feature flag for a gRPC-compatible transport.
//!
//! Spec for the planned implementation is in HELLAS_WIRE_PLAN_v2.md
//! under "gRPC compat on h2 / h3".

#![allow(dead_code)]

/// Reserved `H2Transport` type for the gRPC-compatible transport.
pub struct H2Transport;

impl H2Transport {
    pub fn new<S>(_io: S) -> Self {
        unimplemented!("h2 transport is not implemented in this build")
    }
}
