//! Generated managed iroh clients for Hellas node RPC services.
//!
//! These wrappers sit one layer above tonic's generated clients. They keep the
//! tonic request/response types, but route channel acquisition through
//! `PeerManager` admission and keep request permits alive until the RPC has
//! really finished.

use std::pin::Pin;
use std::task::{Context, Poll};

use futures_core::Stream;
use thiserror::Error;

use crate::peers::{IrohRpcPoolError, MethodKey, PeerManager, PeerManagerError, RpcPermitGuard};

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

    pub async fn message(&mut self) -> Result<Option<T>, tonic::Status>
    where
        Self: Stream<Item = Result<T, tonic::Status>> + Unpin,
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
    type Item = Result<T, tonic::Status>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match Pin::new(&mut self.inner).poll_next(cx) {
            Poll::Ready(Some(Ok(item))) => Poll::Ready(Some(Ok(item))),
            Poll::Ready(Some(Err(status))) => {
                let method = self.method;
                self.finish_err(format!("{method}: {status}"));
                Poll::Ready(Some(Err(status)))
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

#[derive(Debug, Error)]
pub enum IrohClientError {
    #[error(transparent)]
    Pool(#[from] IrohRpcPoolError),
    #[error("{method}: {source}")]
    Status {
        method: &'static str,
        source: tonic::Status,
    },
}

#[derive(Debug)]
pub enum IrohChannelError<E> {
    Peer(PeerManagerError),
    Connect { method: &'static str, source: E },
}

impl<E> std::fmt::Display for IrohChannelError<E>
where
    E: std::fmt::Display,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Peer(err) => err.fmt(f),
            Self::Connect { method, source } => write!(f, "connect for {method}: {source}"),
        }
    }
}

impl<E> std::error::Error for IrohChannelError<E> where E: std::fmt::Debug + std::fmt::Display {}

impl<E> From<PeerManagerError> for IrohChannelError<E> {
    fn from(err: PeerManagerError) -> Self {
        Self::Peer(err)
    }
}

pub async fn tracked_iroh_channel<M, Fut, E>(
    manager: &PeerManager,
    peer: tonic_iroh_transport::iroh::EndpointId,
    connect: Fut,
) -> Result<(tonic_iroh_transport::IrohChannel, RpcPermitGuard), IrohChannelError<E>>
where
    M: MethodKey,
    Fut: std::future::Future<Output = Result<tonic_iroh_transport::IrohChannel, E>>,
    E: std::fmt::Display,
{
    let mut permit = manager.acquire_iroh_method::<M>(peer)?;
    match connect.await {
        Ok(channel) => Ok((channel, permit)),
        Err(source) => {
            permit.finish_connect_err(source.to_string());
            Err(IrohChannelError::Connect {
                method: M::NAME,
                source,
            })
        }
    }
}

pub fn finish_unary<M, T>(
    mut permit: RpcPermitGuard,
    result: Result<tonic::Response<T>, tonic::Status>,
) -> Result<tonic::Response<T>, IrohClientError>
where
    M: MethodKey,
{
    match result {
        Ok(response) => {
            permit.finish_ok();
            Ok(response)
        }
        Err(source) => {
            permit.finish_err(format!("{}: {source}", M::NAME));
            Err(IrohClientError::Status {
                method: M::NAME,
                source,
            })
        }
    }
}

pub fn finish_streaming<M, T>(
    mut permit: RpcPermitGuard,
    result: Result<tonic::Response<tonic::codec::Streaming<T>>, tonic::Status>,
) -> Result<tonic::Response<ManagedStreaming<T>>, IrohClientError>
where
    M: MethodKey,
{
    match result {
        Ok(response) => {
            let (metadata, stream, extensions) = response.into_parts();
            Ok(tonic::Response::from_parts(
                metadata,
                ManagedStreaming::new(stream, permit, M::NAME),
                extensions,
            ))
        }
        Err(source) => {
            permit.finish_err(format!("{}: {source}", M::NAME));
            Err(IrohClientError::Status {
                method: M::NAME,
                source,
            })
        }
    }
}

include!(concat!(env!("OUT_DIR"), "/iroh_clients.rs"));
