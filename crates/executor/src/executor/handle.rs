use crate::ExecutorError;
use hellas_rpc::driver::{ExecuteDriver, ExecuteEventStream};
use hellas_rpc::pb::hellas::execute_server::Execute;
use hellas_rpc::pb::hellas::{
    ExecuteRequest, ExecuteResponse, ExecuteResultRequest, ExecuteResultResponse,
    ExecuteStatusRequest, ExecuteStatusResponse, ExecuteStreamEvent, GetQuoteRequest,
    GetQuoteResponse,
};
use std::pin::Pin;
use tokio::sync::oneshot;
use tonic::Status as TonicStatus;
use tonic::{Request, Response, Status};

use super::{ExecutorHandle, ExecutorMessage, LocalExecutionStream};

impl ExecutorHandle {
    async fn send<T>(
        &self,
        make_message: impl FnOnce(oneshot::Sender<Result<T, ExecutorError>>) -> ExecutorMessage,
    ) -> Result<T, ExecutorError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(make_message(reply_tx))
            .map_err(|_| ExecutorError::ChannelClosed)?;
        reply_rx.await.map_err(|_| ExecutorError::ChannelClosed)?
    }

    pub async fn quote(&self, request: GetQuoteRequest) -> Result<GetQuoteResponse, ExecutorError> {
        self.send(|reply| ExecutorMessage::Quote { request, reply })
            .await
    }

    pub async fn start_execution(
        &self,
        request: ExecuteRequest,
    ) -> Result<ExecuteResponse, ExecutorError> {
        self.send(|reply| ExecutorMessage::Execute { request, reply })
            .await
    }

    pub async fn execution_status(
        &self,
        request: ExecuteStatusRequest,
    ) -> Result<ExecuteStatusResponse, ExecutorError> {
        self.send(|reply| ExecutorMessage::Status { request, reply })
            .await
    }

    pub async fn execution_result(
        &self,
        request: ExecuteResultRequest,
    ) -> Result<ExecuteResultResponse, ExecutorError> {
        self.send(|reply| ExecutorMessage::Result { request, reply })
            .await
    }

    async fn subscribe_execution(
        &self,
        execution_id: String,
    ) -> Result<LocalExecutionStream, ExecutorError> {
        self.send(|reply| ExecutorMessage::Subscribe {
            execution_id,
            reply,
        })
        .await
    }
}

#[tonic::async_trait]
impl Execute for ExecutorHandle {
    async fn get_quote(
        &self,
        request: Request<GetQuoteRequest>,
    ) -> Result<Response<GetQuoteResponse>, Status> {
        Ok(Response::new(self.quote(request.into_inner()).await?))
    }

    async fn execute(
        &self,
        request: Request<ExecuteRequest>,
    ) -> Result<Response<ExecuteResponse>, Status> {
        Ok(Response::new(
            self.start_execution(request.into_inner()).await?,
        ))
    }

    async fn execute_status(
        &self,
        request: Request<ExecuteStatusRequest>,
    ) -> Result<Response<ExecuteStatusResponse>, Status> {
        Ok(Response::new(
            self.execution_status(request.into_inner()).await?,
        ))
    }

    type ExecuteStreamStream =
        Pin<Box<dyn tokio_stream::Stream<Item = Result<ExecuteStreamEvent, TonicStatus>> + Send>>;

    async fn execute_stream(
        &self,
        request: Request<ExecuteStatusRequest>,
    ) -> Result<Response<Self::ExecuteStreamStream>, Status> {
        let execution_id = request.into_inner().execution_id;
        let stream = self.subscribe_execution(execution_id).await?;
        Ok(Response::new(Box::pin(stream) as Self::ExecuteStreamStream))
    }

    async fn execute_result(
        &self,
        request: Request<ExecuteResultRequest>,
    ) -> Result<Response<ExecuteResultResponse>, Status> {
        Ok(Response::new(
            self.execution_result(request.into_inner()).await?,
        ))
    }
}

#[tonic::async_trait]
impl ExecuteDriver for ExecutorHandle {
    async fn get_quote(&mut self, request: GetQuoteRequest) -> Result<GetQuoteResponse, Status> {
        self.quote(request).await.map_err(Into::into)
    }

    async fn execute_streaming(
        &mut self,
        request: ExecuteRequest,
    ) -> Result<ExecuteEventStream, Status> {
        let execution = self.start_execution(request).await?;
        let stream = self.subscribe_execution(execution.execution_id).await?;
        Ok(Box::pin(stream))
    }
}
