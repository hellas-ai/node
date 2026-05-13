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

/// Type-level method identities for the built-in Hellas services.
///
/// These are the shape codegen should eventually emit next to generated clients.
pub mod methods {
    use super::{CourtesyService, ExecuteService, NodeService, OpaqueService, SymbolicService};
    use crate::peers::MethodKey;

    pub struct GetNodeInfo;

    impl MethodKey for GetNodeInfo {
        type Service = NodeService;
        const NAME: &'static str = "GetNodeInfo";
    }

    pub struct GetKnownPeers;

    impl MethodKey for GetKnownPeers {
        type Service = NodeService;
        const NAME: &'static str = "GetKnownPeers";
    }

    pub struct RunTicket;

    impl MethodKey for RunTicket {
        type Service = ExecuteService;
        const NAME: &'static str = "RunTicket";
    }

    pub struct SymbolicCreateTicket;

    impl MethodKey for SymbolicCreateTicket {
        type Service = SymbolicService;
        const NAME: &'static str = "CreateTicket";
    }

    pub struct OpaqueCreateTicket;

    impl MethodKey for OpaqueCreateTicket {
        type Service = OpaqueService;
        const NAME: &'static str = "CreateTicket";
    }

    pub struct QuotePreparedText;

    impl MethodKey for QuotePreparedText {
        type Service = CourtesyService;
        const NAME: &'static str = "QuotePreparedText";
    }

    pub struct PutArtifact;

    impl MethodKey for PutArtifact {
        type Service = CourtesyService;
        const NAME: &'static str = "PutArtifact";
    }

    pub struct GetArtifact;

    impl MethodKey for GetArtifact {
        type Service = CourtesyService;
        const NAME: &'static str = "GetArtifact";
    }

    pub struct ListModels;

    impl MethodKey for ListModels {
        type Service = CourtesyService;
        const NAME: &'static str = "ListModels";
    }

    pub struct QuotePrompt;

    impl MethodKey for QuotePrompt {
        type Service = CourtesyService;
        const NAME: &'static str = "QuotePrompt";
    }

    pub struct QuoteChatPrompt;

    impl MethodKey for QuoteChatPrompt {
        type Service = CourtesyService;
        const NAME: &'static str = "QuoteChatPrompt";
    }

    pub struct DecodeTokens;

    impl MethodKey for DecodeTokens {
        type Service = CourtesyService;
        const NAME: &'static str = "DecodeTokens";
    }
}
