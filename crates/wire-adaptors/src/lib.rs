//! Transport-neutral adaptors for LLM wire formats.

pub mod adaptor;
pub mod anthropic;
pub mod backend;
pub mod error;
pub mod execution;
pub mod openai;
pub mod request;
pub mod wire;

pub use adaptor::WireAdaptor;
pub use backend::{
    BackendError, BackendFuture, BackendRequest, BackendResult, BackendStream, ExecutionBackend,
    OutputEventStream,
};
pub use error::{AdaptorError, AdaptorResult};
pub use execution::{
    CanonicalExecution, ContentPart, ExecutionRequest, ExecutionResult, Input, InputItem, Message,
    ModelRef, OutputEvent, OutputItem, Provenance, ReasoningOptions, ResponseFormat,
    SamplingOptions, StopReason, StructuredDelta, TextChannel, ToolCallArgumentsDelta,
    ToolCallDelta, ToolCallEnd, ToolCallStart, ToolChoice, ToolKind, ToolSpec, Usage,
};
pub use request::{FieldPath, PassthroughBag, PassthroughField, RawRequest};
pub use wire::{
    RenderContext, WireBody, WireEventData, WireHeaders, WireResponse, WireStreamEvent,
};
