//! Streaming-response wrapper used by the typed call builders.
//!
//! `ManagedStreaming<T>` keeps the request permit alive for the lifetime of
//! the stream so cancellation and error mapping doesn't leak in-flight
//! slots. All other outbound machinery lives in [`crate::call`] now — the
//! previous `tracked_iroh_channel` / `finish_unary` / `finish_streaming`
//! helpers were folded back into the typed call path.

use std::pin::Pin;
use std::task::{Context, Poll};

use futures_core::Stream;

use crate::call::RpcError;
use crate::peers::RpcPermitGuard;

/// Streaming response wrapper that owns the RPC permit for the duration of
/// the stream and surfaces transport errors as the crate's typed [`RpcError`]
/// rather than the underlying `tonic::Status`. Callers can therefore handle
/// every streaming error consistently with the unary call surface without
/// pulling in tonic types.
pub struct ManagedStreaming<T> {
    inner: tonic::codec::Streaming<T>,
    permit: Option<RpcPermitGuard>,
    method: &'static str,
}

impl<T> ManagedStreaming<T> {
    pub fn new(
        inner: tonic::codec::Streaming<T>,
        permit: RpcPermitGuard,
        method: &'static str,
    ) -> Self {
        Self {
            inner,
            permit: Some(permit),
            method,
        }
    }

    pub async fn message(&mut self) -> Result<Option<T>, RpcError>
    where
        Self: Stream<Item = Result<T, RpcError>> + Unpin,
    {
        std::future::poll_fn(|cx| Pin::new(&mut *self).poll_next(cx))
            .await
            .transpose()
    }

    pub fn finish_ok(&mut self) {
        if let Some(mut permit) = self.permit.take() {
            permit.finish_ok();
        }
    }

    pub fn finish_err(&mut self, error: impl Into<String>) {
        if let Some(mut permit) = self.permit.take() {
            permit.finish_err(error.into());
        }
    }
}

impl<T> Stream for ManagedStreaming<T>
where
    tonic::codec::Streaming<T>: Stream<Item = Result<T, tonic::Status>> + Unpin,
{
    type Item = Result<T, RpcError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match Pin::new(&mut self.inner).poll_next(cx) {
            Poll::Ready(Some(Ok(item))) => Poll::Ready(Some(Ok(item))),
            Poll::Ready(Some(Err(status))) => {
                let method = self.method;
                self.finish_err(format!("{method}: {status}"));
                Poll::Ready(Some(Err(RpcError::from_status(method, status))))
            }
            Poll::Ready(None) => {
                self.finish_ok();
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<T> Unpin for ManagedStreaming<T> {}
