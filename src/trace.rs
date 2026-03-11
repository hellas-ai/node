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

    pub(crate) fn into_parts(self) -> (T, Span) {
        (self.value, self.parent_span)
    }
}
