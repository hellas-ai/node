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

    pub(crate) fn map<U>(self, f: impl FnOnce(T) -> U) -> Traced<U> {
        let (value, parent_span) = self.into_parts();
        Traced {
            value: f(value),
            parent_span,
        }
    }

    pub(crate) fn into_parts(self) -> (T, Span) {
        (self.value, self.parent_span)
    }

    #[allow(dead_code)]
    pub(crate) fn value(&self) -> &T {
        &self.value
    }
}
