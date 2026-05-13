//! Generated service and method markers for Hellas node RPC services.
//!
//! The marker types in this module are generated from `proto/hellas/**/*.proto`
//! by `crates/rpc/build.rs`. They are intentionally small: service markers
//! implement [`crate::peers::ServiceKey`] and `tonic::server::NamedService`;
//! method markers implement [`crate::peers::MethodKey`].

include!(concat!(env!("OUT_DIR"), "/service_markers.rs"));
