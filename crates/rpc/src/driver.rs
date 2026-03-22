use std::pin::Pin;

use futures_core::Stream;
use tonic::codec::CompressionEncoding;
use tonic::transport::Channel;
use tonic::Status;

use crate::pb::hellas::execute_client::ExecuteClient;
use crate::pb::hellas::{
    ExecuteRequest, ExecuteStatusRequest, ExecuteStreamEvent, GetQuoteRequest, GetQuoteResponse,
};
use crate::GRPC_MESSAGE_LIMIT;

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

pub struct RemoteExecuteDriver {
    client: ExecuteClient<Channel>,
}

impl RemoteExecuteDriver {
    pub fn new(channel: Channel) -> Self {
        Self {
            client: Self::client(channel),
        }
    }

    fn client(channel: Channel) -> ExecuteClient<Channel> {
        ExecuteClient::new(channel)
            .send_compressed(CompressionEncoding::Gzip)
            .accept_compressed(CompressionEncoding::Gzip)
            .max_decoding_message_size(GRPC_MESSAGE_LIMIT)
            .max_encoding_message_size(GRPC_MESSAGE_LIMIT)
    }

    async fn subscribe_execution(
        &mut self,
        execution_id: String,
    ) -> Result<ExecuteEventStream, Status> {
        let stream = self
            .client
            .execute_stream(ExecuteStatusRequest { execution_id })
            .await?
            .into_inner();
        Ok(Box::pin(stream))
    }
}

#[tonic::async_trait]
impl ExecuteDriver for RemoteExecuteDriver {
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
        self.subscribe_execution(execution_id).await
    }
}
