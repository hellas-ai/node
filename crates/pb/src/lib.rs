//! Generated protobuf bindings for the Hellas protocol.
//!
//! The source `.proto` files live under `proto/hellas` at the workspace root.

mod generated {
    pub mod hellas {
        #[cfg(feature = "courtesy")]
        #[allow(dead_code)]
        pub mod courtesy {
            pub mod v1 {
                include!("hellas.courtesy.v1.rs");
            }
        }

        #[cfg(feature = "hellas")]
        #[allow(dead_code)]
        pub mod v1 {
            include!("hellas.v1.rs");
        }

        #[cfg(feature = "opaque")]
        #[allow(dead_code)]
        pub mod opaque {
            pub mod v1 {
                include!("hellas.opaque.v1.rs");
            }
        }

        #[cfg(feature = "swarm")]
        #[allow(dead_code)]
        pub mod swarm {
            pub mod v1 {
                include!("hellas.swarm.v1.rs");
            }
        }

        #[cfg(feature = "symbolic")]
        #[allow(dead_code)]
        pub mod symbolic {
            pub mod v1 {
                include!("hellas.symbolic.v1.rs");
            }
        }
    }
}

#[allow(unused_macros)]
macro_rules! service_exports {
    ($($path:ident)::+, $client:ident, $server:ident) => {
        #[cfg(feature = "client")]
        pub use $($path)::+::$client;
        #[cfg(feature = "server")]
        pub use $($path)::+::$server;
    };
}

#[cfg(feature = "hellas")]
pub mod hellas {
    pub use crate::generated::hellas::v1::{
        FinishStatus, ReceiptEnvelope, RunTicketRequest, Ticket, WorkChunk, WorkEvent, WorkFailed,
        WorkFinished, work_event,
    };
    service_exports!(crate::generated::hellas::v1, execute_client, execute_server);
}

#[cfg(feature = "symbolic")]
pub mod symbolic {
    pub use crate::generated::hellas::symbolic::v1::SymbolicRequest;
    service_exports!(
        crate::generated::hellas::symbolic::v1,
        symbolic_client,
        symbolic_server
    );
}

#[cfg(feature = "opaque")]
pub mod opaque {
    pub use crate::generated::hellas::opaque::v1::OpaqueRequest;
    service_exports!(
        crate::generated::hellas::opaque::v1,
        opaque_client,
        opaque_server
    );
}

#[cfg(feature = "courtesy")]
pub mod courtesy {
    pub use crate::generated::hellas::courtesy::v1::{
        ChatMessage, DecodeTokensRequest, DecodeTokensResponse, GetArtifactRequest,
        GetArtifactResponse, GetModelStatsRequest, GetModelStatsResponse, GetStatsRequest,
        GetStatsResponse, ListModelsRequest, ListModelsResponse, ModelInfo, ModelStatus,
        ModelTokenStats, PublishArtifactBundleRequest, PublishArtifactBundleResponse,
        QuoteChatPromptRequest, QuoteChatPromptResponse, QuotePreparedTextRequest,
        QuotePreparedTextResponse, QuotePromptRequest, QuotePromptResponse, SymbolicArtifactStart,
        SymbolicBoundTermMetadata, SymbolicExecutionOutputMetadata, SymbolicGenesisStart,
        SymbolicStart, TokenStats, symbolic_start,
    };
    service_exports!(
        crate::generated::hellas::courtesy::v1,
        courtesy_client,
        courtesy_server
    );
}

#[cfg(feature = "swarm")]
pub mod swarm {
    pub use crate::generated::hellas::swarm::v1::{
        GetKnownPeersRequest, GetKnownPeersResponse, GetNodeInfoRequest, GetNodeInfoResponse,
        Presence,
    };
    service_exports!(
        crate::generated::hellas::swarm::v1,
        node_client,
        node_server
    );
}
