//! Client-side service markers used for ALPN selection with tonic-iroh transport.

use crate::peers::ServiceKey;

/// Service marker for the node RPC service.
pub struct NodeService;

impl ServiceKey for NodeService {
    const NAME: &'static str = "hellas.swarm.v1.Node";
}

impl tonic::server::NamedService for NodeService {
    const NAME: &'static str = <Self as ServiceKey>::NAME;
}

/// Service marker for the execute RPC service.
pub struct ExecuteService;

impl ServiceKey for ExecuteService {
    const NAME: &'static str = "hellas.v1.Execute";
}

impl tonic::server::NamedService for ExecuteService {
    const NAME: &'static str = <Self as ServiceKey>::NAME;
}

/// Service marker for the symbolic ticket RPC service.
pub struct SymbolicService;

impl ServiceKey for SymbolicService {
    const NAME: &'static str = "hellas.symbolic.v1.Symbolic";
}

impl tonic::server::NamedService for SymbolicService {
    const NAME: &'static str = <Self as ServiceKey>::NAME;
}

/// Service marker for the opaque ticket RPC service.
pub struct OpaqueService;

impl ServiceKey for OpaqueService {
    const NAME: &'static str = "hellas.opaque.v1.Opaque";
}

impl tonic::server::NamedService for OpaqueService {
    const NAME: &'static str = <Self as ServiceKey>::NAME;
}

/// Service marker for the provider courtesy RPC service.
pub struct CourtesyService;

impl ServiceKey for CourtesyService {
    const NAME: &'static str = "hellas.courtesy.v1.Courtesy";
}

impl tonic::server::NamedService for CourtesyService {
    const NAME: &'static str = <Self as ServiceKey>::NAME;
}
