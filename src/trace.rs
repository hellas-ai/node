use tracing::Span;

#[derive(Clone)]
pub(crate) struct Traced<T> {
    value: T,
    parent_span: Span,
}

impl<T> Traced<T> {
    pub(crate) fn capture(value: T) -> Self {
        Self {
            value,
            parent_span: Span::current(),
        }
    }

    /// Wrap a value with an explicit parent span instead of capturing the
    /// current one.  Used when the span must survive an async hop (e.g. the
    /// coding scheduler) without being discarded.
    pub(crate) fn with_span(value: T, parent_span: Span) -> Self {
        Self { value, parent_span }
    }

    pub(crate) fn into_parts(self) -> (T, Span) {
        (self.value, self.parent_span)
    }
}

/// Set a deterministic OpenTelemetry trace context on `span` so that every
/// validator processing the same block produces spans under a shared trace ID.
///
/// - `trace_id` — 16 bytes derived from the block digest (same on all nodes).
/// - `span_id`  — 8 bytes derived from `hash(digest || node_identity)`, unique
///   per node so each validator forms its own causal subtree within the trace.
///
/// This enables cross-node correlation in the tracing backend (Jaeger / Grafana
/// Tempo) without propagating W3C trace context over the wire.
pub(crate) fn set_block_trace_context(
    span: &Span,
    trace_id: [u8; 16],
    span_id: [u8; 8],
) {
    use opentelemetry::trace::{
        SpanContext, SpanId, TraceContextExt, TraceFlags, TraceId, TraceState,
    };
    use tracing_opentelemetry::OpenTelemetrySpanExt;

    let remote_ctx = SpanContext::new(
        TraceId::from_bytes(trace_id),
        SpanId::from_bytes(span_id),
        TraceFlags::SAMPLED,
        true,
        TraceState::default(),
    );

    let _ = span.set_parent(
        opentelemetry::Context::new().with_remote_span_context(remote_ctx),
    );
}
