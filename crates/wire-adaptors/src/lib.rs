//! Adaptors between LLM provider wire formats and the canonical
//! execution vocabulary.

pub mod adaptor;
pub mod anthropic;
pub mod backend;
pub mod error;
pub mod execution;
pub mod openai;
pub mod request;
pub mod wire;

pub use adaptor::{WireAdaptor, WireIngress};
pub use backend::{
    BackendError, BackendFuture, BackendRequest, BackendResult, BackendStream, ExecutionBackend,
    OutputEventStream,
};
pub use error::{AdaptorError, AdaptorResult};
pub use execution::{
    CanonicalExecution, ContentPart, ExecutionErrorInfo, ExecutionRequest, ExecutionResult, Input,
    InputItem, Message, ModelRef, OutputItem, ReasoningOptions, ResponseFormat, SamplingOptions,
    ToolChoice, ToolKind, ToolSpec,
};
// The streaming vocabulary the adaptors produce and consume is protocol
// surface owned by hellas-rpc (it is committed inside signed fetch
// transcripts); re-exported here because it appears throughout this
// crate's own API.
pub use hellas_rpc::output::{
    OutputEvent, Provenance, StopReason, StructuredDelta, TextChannel, ToolCallArgumentsDelta,
    ToolCallEnd, ToolCallStart, Usage,
};
pub use request::RawRequest;
pub use wire::{
    RenderContext, SseDecoder, WireBody, WireEventData, WireHeaders, WireResponse, WireStreamEvent,
};
