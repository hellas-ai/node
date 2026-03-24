use std::pin::Pin;

use futures_core::Stream;
use tonic::Status;
use tonic::codec::CompressionEncoding;
use tonic::codegen::*;
use tonic::transport::Channel;

use crate::GRPC_MESSAGE_LIMIT;
use crate::pb::hellas::execute_client::ExecuteClient;
use crate::pb::hellas::{
    ExecuteRequest, ExecuteStatusRequest, ExecuteStreamEvent, GetQuoteRequest, GetQuoteResponse,
};

pub type ExecuteEventStream =
    Pin<Box<dyn Stream<Item = Result<ExecuteStreamEvent, Status>> + Send>>;

#[tonic::async_trait]
pub trait ExecuteDriver: Send {
    async fn get_quote(&mut self, request: GetQuoteRequest) -> Result<GetQuoteResponse, Status>;
    async fn execute_streaming(
        &mut self,
        request: ExecuteRequest,
    ) -> Result<ExecuteEventStream, Status>;
}

pub struct RemoteExecuteDriver<T = Channel> {
    client: ExecuteClient<T>,
}

impl RemoteExecuteDriver<Channel> {
    pub fn new(channel: Channel) -> Self {
        Self {
            client: ExecuteClient::new(channel)
                .send_compressed(CompressionEncoding::Zstd)
                .accept_compressed(CompressionEncoding::Zstd)
                .max_decoding_message_size(GRPC_MESSAGE_LIMIT)
                .max_encoding_message_size(GRPC_MESSAGE_LIMIT),
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
            client: ExecuteClient::new(service)
                .send_compressed(CompressionEncoding::Zstd)
                .accept_compressed(CompressionEncoding::Zstd)
                .max_decoding_message_size(GRPC_MESSAGE_LIMIT)
                .max_encoding_message_size(GRPC_MESSAGE_LIMIT),
        }
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
    async fn get_quote(&mut self, request: GetQuoteRequest) -> Result<GetQuoteResponse, Status> {
        Ok(self.client.get_quote(request).await?.into_inner())
    }

    async fn execute_streaming(
        &mut self,
        request: ExecuteRequest,
    ) -> Result<ExecuteEventStream, Status> {
        let execution_id = self
            .client
            .execute(request)
            .await?
            .into_inner()
            .execution_id;
        let stream = self
            .client
            .execute_stream(ExecuteStatusRequest { execution_id })
            .await?
            .into_inner();
        Ok(Box::pin(stream))
    }
}
