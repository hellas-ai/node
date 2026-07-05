//! Transport-neutral adaptors for LLM wire formats.

pub mod adaptor;
pub mod anthropic;
pub mod backend;
pub mod error;
pub mod execution;
pub mod fetch_payload;
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
    InputItem, Message, ModelRef, OutputEvent, OutputItem, Provenance, ReasoningOptions,
    ResponseFormat, SamplingOptions, StopReason, StructuredDelta, TextChannel,
    ToolCallArgumentsDelta, ToolCallEnd, ToolCallStart, ToolChoice, ToolKind, ToolSpec, Usage,
};
pub use fetch_payload::{
    FetchEventPayload, FetchPayloadError, FetchTerminalPayload, decode_fetch_event_payload,
    decode_fetch_terminal_payload, encode_fetch_event_payload, encode_fetch_terminal_payload,
};
pub use request::RawRequest;
pub use wire::{
    RenderContext, SseDecoder, WireBody, WireEventData, WireHeaders, WireResponse, WireStreamEvent,
};
