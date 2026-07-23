use std::marker::PhantomData;
use std::sync::Arc;

use hellas_wire::{
    Dispatcher, MethodMarker, ServiceMarker, StreamTransport, TransportContext, TransportError,
    WireStatus,
};

use crate::pb::execute::{OpenRequest, OpenResponse};

/// Provider-side proof producer. The transport context supplies the exporter;
/// implementations must never accept one from the request.
pub trait OpenHandler: Send + Sync + 'static {
    fn open(
        &self,
        request: OpenRequest,
        context: TransportContext,
        alpn: &'static [u8],
    ) -> impl Future<Output = Result<OpenResponse, WireStatus>> + Send;
}

impl<H: OpenHandler> OpenHandler for Arc<H> {
    fn open(
        &self,
        request: OpenRequest,
        context: TransportContext,
        alpn: &'static [u8],
    ) -> impl Future<Output = Result<OpenResponse, WireStatus>> + Send {
        self.as_ref().open(request, context, alpn)
    }
}

/// Intercepts one service's `Open` method before forwarding all other methods
/// to its generated dispatcher.
pub struct OpenDispatcher<S, H, M> {
    inner: S,
    handler: H,
    marker: PhantomData<fn() -> M>,
}

impl<S, H, M> OpenDispatcher<S, H, M> {
    pub fn new(inner: S, handler: H) -> Self {
        Self {
            inner,
            handler,
            marker: PhantomData,
        }
    }
}

impl<T, S, H, M> Dispatcher<T> for OpenDispatcher<S, H, M>
where
    T: StreamTransport + Send + Sync,
    T::Stream: Send,
    S: Dispatcher<T, Error = TransportError> + Send + Sync,
    H: OpenHandler,
    M: MethodMarker<Request = OpenRequest, Response = OpenResponse> + Send + Sync,
{
    type Error = TransportError;

    async fn dispatch(&self, inbound: hellas_wire::Inbound<T::Stream>) -> Result<(), Self::Error> {
        if inbound.method_id != M::METHOD_ID {
            return self.inner.dispatch(inbound).await;
        }

        crate::call::dispatch_unary_with_context::<T, M, _, _, _>(inbound, |request, context| {
            self.handler.open(
                request,
                context,
                <M::Service as ServiceMarker>::ALPN.as_bytes(),
            )
        })
        .await
    }
}
