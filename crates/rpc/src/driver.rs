use std::pin::Pin;

use futures_core::Stream;
use tonic::Status;

use crate::provenance::ExecutionProvenance;
use hellas_pb::courtesy::{QuotePreparedTextRequest, QuotePreparedTextResponse};
use hellas_pb::hellas::{RunTicketRequest, Ticket, WorkEvent};
use hellas_pb::opaque::OpaqueRequest;
use hellas_pb::symbolic::SymbolicRequest;

pub type ExecuteEventStream = Pin<Box<dyn Stream<Item = Result<WorkEvent, Status>> + Send>>;

/// Ticket response paired with the provenance the executor committed to.
/// Carried alongside `Ticket` so callers (the gateway) can
/// expose the same hashes the executor logged at quote/accept time.
#[derive(Debug)]
pub struct QuotedResponse {
    pub response: Ticket,
    pub provenance: ExecutionProvenance,
}

#[derive(Debug)]
pub struct QuotedPreparedTextResponse {
    pub response: QuotePreparedTextResponse,
    pub provenance: ExecutionProvenance,
}

/// Streaming execution paired with the provenance committed to at
/// quote-acceptance time. The producer receipt is terminal and reaches the
/// caller via the streamed `WorkFinished.receipt` field, not through
/// `ExecutionProvenance`.
pub struct StreamedExecution {
    pub stream: ExecuteEventStream,
    pub provenance: ExecutionProvenance,
}

#[tonic::async_trait]
pub trait ExecuteDriver: Send {
    async fn create_symbolic_ticket(
        &mut self,
        request: SymbolicRequest,
    ) -> Result<QuotedResponse, Status>;
    async fn create_opaque_ticket(
        &mut self,
        request: OpaqueRequest,
    ) -> Result<QuotedResponse, Status>;
    async fn quote_prepared_text(
        &mut self,
        request: QuotePreparedTextRequest,
    ) -> Result<QuotedPreparedTextResponse, Status>;
    async fn execute_streaming(
        &mut self,
        request: RunTicketRequest,
    ) -> Result<StreamedExecution, Status>;
}

#[cfg(feature = "iroh-client")]
pub use remote::{ManagedRemoteDriver, RemoteExecuteDriver};

/// Tonic-client-based [`ExecuteDriver`] for outbound iroh RPC. Lives in its
/// own module because it imports `hellas_pb::*::client_stubs::*` (only
/// available with `hellas-pb/client`) and `IrohChannel` from the iroh
/// transport — both gated by `iroh-client`.
#[cfg(feature = "iroh-client")]
mod remote {
    use super::*;

    #[cfg(feature = "compression")]
    use tonic::codec::CompressionEncoding;
    use tonic::codegen::*;
    use tonic_iroh_transport::IrohChannel;

    use crate::GRPC_MESSAGE_LIMIT;
    use crate::provenance::read_provenance_metadata;
    use hellas_pb::courtesy::courtesy_client::CourtesyClient;
    use hellas_pb::courtesy::{
        GetArtifactRequest, GetArtifactResponse, PutArtifactRequest, PutArtifactResponse,
    };
    use hellas_pb::hellas::execute_client::ExecuteClient;
    use hellas_pb::opaque::opaque_client::OpaqueClient;
    use hellas_pb::symbolic::symbolic_client::SymbolicClient;

pub struct RemoteExecuteDriver<T> {
    execute: ExecuteClient<T>,
    symbolic: Option<SymbolicClient<T>>,
    opaque: Option<OpaqueClient<T>>,
    courtesy: Option<CourtesyClient<T>>,
}

impl RemoteExecuteDriver<IrohChannel> {
    pub fn new(channel: IrohChannel) -> Self {
        Self::with_service(channel)
    }
}

impl<T> RemoteExecuteDriver<T>
where
    T: tonic::client::GrpcService<tonic::body::Body> + Clone,
    T::Error: Into<StdError>,
    T::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <T::ResponseBody as Body>::Error: Into<StdError> + Send,
{
    pub fn with_service(service: T) -> Self {
        let symbolic = service.clone();
        let opaque = service.clone();
        let courtesy = service.clone();
        Self {
            execute: Self::configure_execute(ExecuteClient::new(service)),
            symbolic: Some(Self::configure_symbolic(SymbolicClient::new(symbolic))),
            opaque: Some(Self::configure_opaque(OpaqueClient::new(opaque))),
            courtesy: Some(Self::configure_courtesy(CourtesyClient::new(courtesy))),
        }
    }

    pub fn with_services(execute: T, symbolic: T, opaque: T, courtesy: T) -> Self {
        Self {
            execute: Self::configure_execute(ExecuteClient::new(execute)),
            symbolic: Some(Self::configure_symbolic(SymbolicClient::new(symbolic))),
            opaque: Some(Self::configure_opaque(OpaqueClient::new(opaque))),
            courtesy: Some(Self::configure_courtesy(CourtesyClient::new(courtesy))),
        }
    }

    pub fn with_execute_and_courtesy(execute: T, courtesy: T) -> Self {
        Self {
            execute: Self::configure_execute(ExecuteClient::new(execute)),
            symbolic: None,
            opaque: None,
            courtesy: Some(Self::configure_courtesy(CourtesyClient::new(courtesy))),
        }
    }

    pub fn with_execute_and_opaque(execute: T, opaque: T) -> Self {
        Self {
            execute: Self::configure_execute(ExecuteClient::new(execute)),
            symbolic: None,
            opaque: Some(Self::configure_opaque(OpaqueClient::new(opaque))),
            courtesy: None,
        }
    }

    fn configure_execute(client: ExecuteClient<T>) -> ExecuteClient<T> {
        let client = client
            .max_decoding_message_size(GRPC_MESSAGE_LIMIT)
            .max_encoding_message_size(GRPC_MESSAGE_LIMIT);
        #[cfg(feature = "compression")]
        let client = client
            .send_compressed(CompressionEncoding::Zstd)
            .accept_compressed(CompressionEncoding::Zstd);
        client
    }

    fn configure_symbolic(client: SymbolicClient<T>) -> SymbolicClient<T> {
        let client = client
            .max_decoding_message_size(GRPC_MESSAGE_LIMIT)
            .max_encoding_message_size(GRPC_MESSAGE_LIMIT);
        #[cfg(feature = "compression")]
        let client = client
            .send_compressed(CompressionEncoding::Zstd)
            .accept_compressed(CompressionEncoding::Zstd);
        client
    }

    fn configure_opaque(client: OpaqueClient<T>) -> OpaqueClient<T> {
        let client = client
            .max_decoding_message_size(GRPC_MESSAGE_LIMIT)
            .max_encoding_message_size(GRPC_MESSAGE_LIMIT);
        #[cfg(feature = "compression")]
        let client = client
            .send_compressed(CompressionEncoding::Zstd)
            .accept_compressed(CompressionEncoding::Zstd);
        client
    }

    fn configure_courtesy(client: CourtesyClient<T>) -> CourtesyClient<T> {
        let client = client
            .max_decoding_message_size(GRPC_MESSAGE_LIMIT)
            .max_encoding_message_size(GRPC_MESSAGE_LIMIT);
        #[cfg(feature = "compression")]
        let client = client
            .send_compressed(CompressionEncoding::Zstd)
            .accept_compressed(CompressionEncoding::Zstd);
        client
    }

    pub async fn put_artifact(
        &mut self,
        request: PutArtifactRequest,
    ) -> Result<PutArtifactResponse, Status>
    where
        T: tonic::client::GrpcService<tonic::body::Body> + Send + 'static,
        T::Error: Into<StdError>,
        T::ResponseBody: Body<Data = Bytes> + Send + 'static,
        <T::ResponseBody as Body>::Error: Into<StdError> + Send,
        T::Future: Send,
    {
        let courtesy = self
            .courtesy
            .as_mut()
            .ok_or_else(|| Status::unimplemented("courtesy service is not configured"))?;
        Ok(courtesy.put_artifact(request).await?.into_inner())
    }

    pub async fn get_artifact(
        &mut self,
        request: GetArtifactRequest,
    ) -> Result<GetArtifactResponse, Status>
    where
        T: tonic::client::GrpcService<tonic::body::Body> + Send + 'static,
        T::Error: Into<StdError>,
        T::ResponseBody: Body<Data = Bytes> + Send + 'static,
        <T::ResponseBody as Body>::Error: Into<StdError> + Send,
        T::Future: Send,
    {
        let courtesy = self
            .courtesy
            .as_mut()
            .ok_or_else(|| Status::unimplemented("courtesy service is not configured"))?;
        Ok(courtesy.get_artifact(request).await?.into_inner())
    }
}

#[tonic::async_trait]
impl<T> ExecuteDriver for RemoteExecuteDriver<T>
where
    T: tonic::client::GrpcService<tonic::body::Body> + Send + 'static,
    T::Error: Into<StdError>,
    T::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <T::ResponseBody as Body>::Error: Into<StdError> + Send,
    T::Future: Send,
{
    async fn create_symbolic_ticket(
        &mut self,
        request: SymbolicRequest,
    ) -> Result<QuotedResponse, Status> {
        let symbolic = self
            .symbolic
            .as_mut()
            .ok_or_else(|| Status::unimplemented("symbolic service is not configured"))?;
        let resp = symbolic.create_ticket(request).await?;
        let provenance = read_provenance_metadata(resp.metadata())?;
        Ok(QuotedResponse {
            response: resp.into_inner(),
            provenance,
        })
    }

    async fn create_opaque_ticket(
        &mut self,
        request: OpaqueRequest,
    ) -> Result<QuotedResponse, Status> {
        let opaque = self
            .opaque
            .as_mut()
            .ok_or_else(|| Status::unimplemented("opaque service is not configured"))?;
        let resp = opaque.create_ticket(request).await?;
        let provenance = read_provenance_metadata(resp.metadata())?;
        Ok(QuotedResponse {
            response: resp.into_inner(),
            provenance,
        })
    }

    async fn quote_prepared_text(
        &mut self,
        request: QuotePreparedTextRequest,
    ) -> Result<QuotedPreparedTextResponse, Status> {
        let courtesy = self
            .courtesy
            .as_mut()
            .ok_or_else(|| Status::unimplemented("courtesy service is not configured"))?;
        let resp = courtesy.quote_prepared_text(request).await?;
        let provenance = read_provenance_metadata(resp.metadata())?;
        Ok(QuotedPreparedTextResponse {
            response: resp.into_inner(),
            provenance,
        })
    }

    async fn execute_streaming(
        &mut self,
        request: RunTicketRequest,
    ) -> Result<StreamedExecution, Status> {
        let resp = self.execute.run_ticket(request).await?;
        let provenance = read_provenance_metadata(resp.metadata())?;
        Ok(StreamedExecution {
            stream: Box::pin(resp.into_inner()),
            provenance,
        })
    }
}

// ---------------------------------------------------------------------------
// ManagedRemoteDriver — RemoteExecuteDriver with permit lifecycle attached
// ---------------------------------------------------------------------------

use std::task::{Context, Poll};
use crate::peers::{PeerManager, PeerManagerError, RpcPermitGuard};
use crate::service::methods;
use hellas_pb::hellas::work_event;

/// `RemoteExecuteDriver` wrapped with per-call permit management. Each
/// quote/run method acquires the matching [`RpcPermitGuard`] from the
/// shared [`PeerManager`], dispatches to the inner driver, and finishes
/// the permit on the outcome — so callers never need to thread permits
/// through the quote/run flow.
///
/// For `execute_streaming`, the permit travels with the returned stream
/// via [`ManagedExecuteStream`] and resolves on the terminal `Finished`
/// / `Failed` event (or on transport error / unexpected stream end);
/// dropping the stream early resolves it as `Cancelled` through the
/// `RpcPermitGuard` Drop impl.
pub struct ManagedRemoteDriver<T> {
    inner: RemoteExecuteDriver<T>,
    manager: PeerManager,
    peer_id: tonic_iroh_transport::iroh::EndpointId,
}

impl<T> ManagedRemoteDriver<T> {
    pub fn new(
        inner: RemoteExecuteDriver<T>,
        manager: PeerManager,
        peer_id: tonic_iroh_transport::iroh::EndpointId,
    ) -> Self {
        Self {
            inner,
            manager,
            peer_id,
        }
    }

    /// Peer this driver is bound to. Discovery loops use this to mark a
    /// node as tried-and-failed without having to thread `peer_id` past
    /// the driver alongside it.
    pub const fn peer_id(&self) -> tonic_iroh_transport::iroh::EndpointId {
        self.peer_id
    }

    /// Borrow the underlying driver. Useful for tests and for direct
    /// `RemoteExecuteDriver::put_artifact` / `get_artifact` calls that
    /// don't ride through `ExecuteDriver` — those should grow their own
    /// managed wrappers when a non-test caller actually needs them.
    pub fn inner_mut(&mut self) -> &mut RemoteExecuteDriver<T> {
        &mut self.inner
    }

    pub fn into_inner(self) -> RemoteExecuteDriver<T> {
        self.inner
    }
}

/// Map a `PeerManagerError` (admission failure / poisoned mutex / etc.)
/// to a `tonic::Status`. Resource-exhausted captures rate-limit denials,
/// internal captures lock failures.
fn permit_acquire_status(err: PeerManagerError) -> Status {
    match err {
        PeerManagerError::Admission(_) => Status::resource_exhausted(err.to_string()),
        PeerManagerError::Unavailable => Status::internal(err.to_string()),
    }
}

#[tonic::async_trait]
impl<T> ExecuteDriver for ManagedRemoteDriver<T>
where
    T: tonic::client::GrpcService<tonic::body::Body> + Clone + Send + 'static,
    T::Error: Into<StdError>,
    T::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <T::ResponseBody as Body>::Error: Into<StdError> + Send,
    T::Future: Send,
{
    async fn create_symbolic_ticket(
        &mut self,
        request: SymbolicRequest,
    ) -> Result<QuotedResponse, Status> {
        let mut permit = self
            .manager
            .acquire_iroh_method::<methods::SymbolicCreateTicket>(self.peer_id)
            .map_err(permit_acquire_status)?;
        match self.inner.create_symbolic_ticket(request).await {
            Ok(resp) => {
                permit.finish_ok();
                Ok(resp)
            }
            Err(status) => {
                permit.finish_err(format!(
                    "{}: {status}",
                    <methods::SymbolicCreateTicket as crate::peers::RpcMethod>::NAME
                ));
                Err(status)
            }
        }
    }

    async fn create_opaque_ticket(
        &mut self,
        request: OpaqueRequest,
    ) -> Result<QuotedResponse, Status> {
        let mut permit = self
            .manager
            .acquire_iroh_method::<methods::OpaqueCreateTicket>(self.peer_id)
            .map_err(permit_acquire_status)?;
        match self.inner.create_opaque_ticket(request).await {
            Ok(resp) => {
                permit.finish_ok();
                Ok(resp)
            }
            Err(status) => {
                permit.finish_err(format!(
                    "{}: {status}",
                    <methods::OpaqueCreateTicket as crate::peers::RpcMethod>::NAME
                ));
                Err(status)
            }
        }
    }

    async fn quote_prepared_text(
        &mut self,
        request: QuotePreparedTextRequest,
    ) -> Result<QuotedPreparedTextResponse, Status> {
        let mut permit = self
            .manager
            .acquire_iroh_method::<methods::QuotePreparedText>(self.peer_id)
            .map_err(permit_acquire_status)?;
        match self.inner.quote_prepared_text(request).await {
            Ok(resp) => {
                permit.finish_ok();
                Ok(resp)
            }
            Err(status) => {
                permit.finish_err(format!(
                    "{}: {status}",
                    <methods::QuotePreparedText as crate::peers::RpcMethod>::NAME
                ));
                Err(status)
            }
        }
    }

    async fn execute_streaming(
        &mut self,
        request: RunTicketRequest,
    ) -> Result<StreamedExecution, Status> {
        let permit = self
            .manager
            .acquire_iroh_method::<methods::RunTicket>(self.peer_id)
            .map_err(permit_acquire_status)?;
        match self.inner.execute_streaming(request).await {
            Ok(streamed) => {
                let StreamedExecution { stream, provenance } = streamed;
                Ok(StreamedExecution {
                    stream: Box::pin(ManagedExecuteStream {
                        inner: stream,
                        permit: Some(permit),
                    }),
                    provenance,
                })
            }
            Err(status) => {
                let mut permit = permit;
                permit.finish_err(format!(
                    "{}: {status}",
                    <methods::RunTicket as crate::peers::RpcMethod>::NAME
                ));
                Err(status)
            }
        }
    }
}

/// Stream wrapper that owns the RunTicket permit for the lifetime of the
/// execution stream. Finishes the permit on:
/// * a terminal `Finished` / `Failed` wire event (yielded *before* the
///   permit resolves, so a consumer that drops on terminal won't get a
///   spurious `Cancelled`).
/// * an `Err(Status)` from the underlying gRPC stream.
/// * natural end-of-stream (`Ready(None)`).
///
/// If the consumer drops the stream early, `RpcPermitGuard`'s Drop fires
/// and records `Cancelled`.
struct ManagedExecuteStream {
    inner: ExecuteEventStream,
    permit: Option<RpcPermitGuard>,
}

impl Stream for ManagedExecuteStream {
    type Item = Result<WorkEvent, Status>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        match std::pin::Pin::new(&mut self.inner).poll_next(cx) {
            Poll::Ready(Some(Ok(event))) => {
                if matches!(
                    event.kind,
                    Some(work_event::Kind::Finished(_) | work_event::Kind::Failed(_))
                ) {
                    if let Some(mut permit) = self.permit.take() {
                        permit.finish_ok();
                    }
                }
                Poll::Ready(Some(Ok(event)))
            }
            Poll::Ready(Some(Err(status))) => {
                if let Some(mut permit) = self.permit.take() {
                    permit.finish_err(format!(
                        "{}: {status}",
                        <methods::RunTicket as crate::peers::RpcMethod>::NAME
                    ));
                }
                Poll::Ready(Some(Err(status)))
            }
            Poll::Ready(None) => {
                if let Some(mut permit) = self.permit.take() {
                    permit.finish_ok();
                }
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}
}
