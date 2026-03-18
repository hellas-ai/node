use std::pin::Pin;

use futures_core::Stream;
use tonic::codec::CompressionEncoding;
use tonic::transport::Channel;
use tonic::Status;

use crate::pb::hellas::execute_client::ExecuteClient;
use crate::pb::hellas::{
    ExecuteProgress, ExecuteRequest, ExecuteStatusRequest, GetQuoteRequest, GetQuoteResponse,
};
use crate::GRPC_MESSAGE_LIMIT;

pub type ExecuteProgressStream =
    Pin<Box<dyn Stream<Item = Result<ExecuteProgress, Status>> + Send>>;

#[tonic::async_trait]
pub trait ExecuteDriver: Send {
    async fn get_quote(&mut self, request: GetQuoteRequest) -> Result<GetQuoteResponse, Status>;
    async fn execute_streaming(
        &mut self,
        request: ExecuteRequest,
    ) -> Result<ExecuteProgressStream, Status>;
}

pub struct RemoteExecuteDriver {
    client: ExecuteClient<Channel>,
}

impl RemoteExecuteDriver {
    pub fn new(channel: Channel) -> Self {
        Self {
            client: configured_execute_client(channel),
        }
    }

    pub fn from_client(client: ExecuteClient<Channel>) -> Self {
        Self { client }
    }
}

pub fn configured_execute_client(channel: Channel) -> ExecuteClient<Channel> {
    ExecuteClient::new(channel)
        .send_compressed(CompressionEncoding::Gzip)
        .accept_compressed(CompressionEncoding::Gzip)
        .max_decoding_message_size(GRPC_MESSAGE_LIMIT)
        .max_encoding_message_size(GRPC_MESSAGE_LIMIT)
}

#[tonic::async_trait]
impl ExecuteDriver for RemoteExecuteDriver {
    async fn get_quote(&mut self, request: GetQuoteRequest) -> Result<GetQuoteResponse, Status> {
        Ok(self.client.get_quote(request).await?.into_inner())
    }

    async fn execute_streaming(
        &mut self,
        request: ExecuteRequest,
    ) -> Result<ExecuteProgressStream, Status> {
        let execution = self.client.execute(request).await?.into_inner();
        let stream = self
            .client
            .execute_stream(ExecuteStatusRequest {
                execution_id: execution.execution_id,
            })
            .await?
            .into_inner();
        Ok(Box::pin(stream))
    }
}
