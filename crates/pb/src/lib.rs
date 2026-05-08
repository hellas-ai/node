//! Generated protobuf bindings for the Hellas protocol.
//!
//! The source `.proto` files live under `proto/hellas` at the workspace root.

#[cfg(any(
    feature = "common",
    feature = "symbolic",
    feature = "opaque",
    feature = "ticket",
    feature = "execute",
    feature = "courtesy",
    feature = "node",
))]
#[allow(dead_code)]
#[path = "hellas.v1.rs"]
mod generated_hellas;

pub mod hellas {
    #[cfg(feature = "common")]
    pub use crate::generated_hellas::{
        FinishStatus, ReceiptEnvelope, WorkChunk, WorkEvent, WorkFailed, WorkFinished, work_event,
    };

    #[cfg(feature = "symbolic")]
    pub use crate::generated_hellas::{
        SymbolicGenesisExecution, SymbolicStepExecution, SymbolicWorkRequest, symbolic_work_request,
    };

    #[cfg(feature = "opaque")]
    pub use crate::generated_hellas::OpaqueWorkRequest;

    #[cfg(feature = "ticket")]
    pub use crate::generated_hellas::{
        CreateTicketRequest, RunTicketRequest, Ticket, WorkRequest, work_request,
    };

    #[cfg(all(feature = "execute", feature = "client"))]
    pub use crate::generated_hellas::execute_client;
    #[cfg(all(feature = "execute", feature = "server"))]
    pub use crate::generated_hellas::execute_server;

    #[cfg(all(feature = "courtesy", feature = "client"))]
    pub use crate::generated_hellas::courtesy_client;
    #[cfg(all(feature = "courtesy", feature = "server"))]
    pub use crate::generated_hellas::courtesy_server;
    #[cfg(feature = "courtesy")]
    pub use crate::generated_hellas::{
        ChatMessage, DecodeTokensRequest, DecodeTokensResponse, GetModelStatsRequest,
        GetModelStatsResponse, GetStatsRequest, GetStatsResponse, ListModelsRequest,
        ListModelsResponse, ModelInfo, ModelStatus, ModelTokenStats, QuoteChatPromptRequest,
        QuoteChatPromptResponse, QuotePreparedTextRequest, QuotePreparedTextResponse,
        QuotePromptRequest, QuotePromptResponse, SymbolicGenesisStart, SymbolicReceiptStart,
        SymbolicStart, TokenStats, symbolic_start,
    };

    #[cfg(all(feature = "node", feature = "client"))]
    pub use crate::generated_hellas::node_client;
    #[cfg(all(feature = "node", feature = "server"))]
    pub use crate::generated_hellas::node_server;
    #[cfg(feature = "node")]
    pub use crate::generated_hellas::{
        GetKnownPeersRequest, GetKnownPeersResponse, GetNodeInfoRequest, GetNodeInfoResponse,
        Presence,
    };
}
