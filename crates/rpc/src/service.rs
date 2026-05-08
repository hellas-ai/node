//! Client-side service markers used for ALPN selection with tonic-iroh transport.

/// Service marker for the node RPC service.
pub struct NodeService;

impl tonic::server::NamedService for NodeService {
    const NAME: &'static str = "hellas.swarm.v1.Node";
}

/// Service marker for the execute RPC service.
pub struct ExecuteService;

impl tonic::server::NamedService for ExecuteService {
    const NAME: &'static str = "hellas.v1.Execute";
}

/// Service marker for the symbolic ticket RPC service.
pub struct SymbolicService;

impl tonic::server::NamedService for SymbolicService {
    const NAME: &'static str = "hellas.symbolic.v1.Symbolic";
}

/// Service marker for the opaque ticket RPC service.
pub struct OpaqueService;

impl tonic::server::NamedService for OpaqueService {
    const NAME: &'static str = "hellas.opaque.v1.Opaque";
}

/// Service marker for the provider courtesy RPC service.
pub struct CourtesyService;

impl tonic::server::NamedService for CourtesyService {
    const NAME: &'static str = "hellas.courtesy.v1.Courtesy";
}
