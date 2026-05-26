use std::pin::Pin;

use futures_core::Stream;
use tonic::Status;
#[cfg(feature = "compression")]
use tonic::codec::CompressionEncoding;
use tonic::codegen::*;
#[cfg(feature = "discovery")]
use tonic_iroh_transport::IrohChannel;

use crate::GRPC_MESSAGE_LIMIT;
use crate::pb::hellas::execute_client::ExecuteClient;
use crate::pb::hellas::{ExecuteRequest, ExecuteStreamEvent, GetQuoteRequest, GetQuoteResponse};
use crate::provenance::{ExecutionProvenance, read_provenance_metadata};

pub type ExecuteEventStream =
    Pin<Box<dyn Stream<Item = Result<ExecuteStreamEvent, Status>> + Send>>;

/// Quote response paired with the provenance the executor committed to.
/// Carried alongside `GetQuoteResponse` so callers (the gateway) can
/// expose the same hashes the executor logged at quote/accept time.
#[derive(Debug)]
pub struct QuotedResponse {
    pub response: GetQuoteResponse,
    pub provenance: ExecutionProvenance,
}

/// Streaming execution paired with the provenance committed to at
/// quote-acceptance time. The receipt commitment is terminal and reaches
/// the caller via the streamed `Completed.receipt_commitment` proto field.
pub struct StreamedExecution {
    pub stream: ExecuteEventStream,
    pub provenance: ExecutionProvenance,
}

#[tonic::async_trait]
pub trait ExecuteDriver: Send {
    async fn get_quote(&mut self, request: GetQuoteRequest) -> Result<QuotedResponse, Status>;
    async fn execute_streaming(
        &mut self,
        request: ExecuteRequest,
    ) -> Result<StreamedExecution, Status>;
}

pub struct RemoteExecuteDriver<T> {
    client: ExecuteClient<T>,
}

#[cfg(feature = "discovery")]
impl RemoteExecuteDriver<IrohChannel> {
    pub fn new(channel: IrohChannel) -> Self {
        Self {
            client: Self::configure(ExecuteClient::new(channel)),
        }
    }
}

impl<T> RemoteExecuteDriver<T>
where
    T: tonic::client::GrpcService<tonic::body::Body>,
    T::Error: Into<StdError>,
    T::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <T::ResponseBody as Body>::Error: Into<StdError> + Send,
{
    pub fn with_service(service: T) -> Self {
        Self {
            client: Self::configure(ExecuteClient::new(service)),
        }
    }

    fn configure(client: ExecuteClient<T>) -> ExecuteClient<T> {
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
    async fn get_quote(&mut self, request: GetQuoteRequest) -> Result<QuotedResponse, Status> {
        let resp = self.client.get_quote(request).await?;
        let provenance = read_provenance_metadata(resp.metadata())?;
        Ok(QuotedResponse {
            response: resp.into_inner(),
            provenance,
        })
    }

    async fn execute_streaming(
        &mut self,
        request: ExecuteRequest,
    ) -> Result<StreamedExecution, Status> {
        let resp = self.client.execute(request).await?;
        let provenance = read_provenance_metadata(resp.metadata())?;
        Ok(StreamedExecution {
            stream: Box::pin(resp.into_inner()),
            provenance,
        })
    }
}
