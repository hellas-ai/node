use std::pin::Pin;

use futures_core::Stream;
use tonic::Status;
#[cfg(feature = "compression")]
use tonic::codec::CompressionEncoding;
use tonic::codegen::*;
#[cfg(feature = "discovery")]
use tonic_iroh_transport::IrohChannel;

use crate::GRPC_MESSAGE_LIMIT;
use crate::provenance::{ExecutionProvenance, read_provenance_metadata};
use hellas_pb::hellas::courtesy_client::CourtesyClient;
use hellas_pb::hellas::execute_client::ExecuteClient;
use hellas_pb::hellas::{
    CreateTicketRequest, QuotePreparedTextRequest, QuotePreparedTextResponse, RunTicketRequest,
    Ticket, WorkEvent,
};

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
    async fn create_ticket(
        &mut self,
        request: CreateTicketRequest,
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

pub struct RemoteExecuteDriver<T> {
    execute: ExecuteClient<T>,
    courtesy: CourtesyClient<T>,
}

#[cfg(feature = "discovery")]
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
        let courtesy = service.clone();
        Self {
            execute: Self::configure_execute(ExecuteClient::new(service)),
            courtesy: Self::configure_courtesy(CourtesyClient::new(courtesy)),
        }
    }

    pub fn with_services(execute: T, courtesy: T) -> Self {
        Self {
            execute: Self::configure_execute(ExecuteClient::new(execute)),
            courtesy: Self::configure_courtesy(CourtesyClient::new(courtesy)),
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
    async fn create_ticket(
        &mut self,
        request: CreateTicketRequest,
    ) -> Result<QuotedResponse, Status> {
        let resp = self.execute.create_ticket(request).await?;
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
        let resp = self.courtesy.quote_prepared_text(request).await?;
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
