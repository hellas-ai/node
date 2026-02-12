//! Client-side service markers used for ALPN selection with tonic-iroh transport.

/// Service marker for the node RPC service.
pub struct NodeService;

impl tonic::server::NamedService for NodeService {
    const NAME: &'static str = "hellas.Node";
}

/// Service marker for the execute RPC service.
pub struct ExecuteService;

impl tonic::server::NamedService for ExecuteService {
    const NAME: &'static str = "hellas.Execute";
}
