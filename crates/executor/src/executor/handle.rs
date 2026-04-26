use hellas_rpc::ExecutorError;
use hellas_rpc::driver::{ExecuteDriver, ExecuteEventStream};
use hellas_rpc::pb::hellas::execute_server::Execute;
use hellas_rpc::pb::hellas::{
    DecodeTokensRequest, DecodeTokensResponse, ExecuteRequest, ExecuteStreamEvent,
    GetModelStatsRequest, GetModelStatsResponse, GetQuoteRequest, GetQuoteResponse,
    GetStatsRequest, GetStatsResponse, ListModelsRequest, ListModelsResponse,
    QuoteChatPromptRequest, QuoteChatPromptResponse, QuotePromptRequest, QuotePromptResponse,
};
use std::pin::Pin;
use tokio::sync::oneshot;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

use super::{ExecuteEventReceiver, ExecutorHandle, ExecutorMessage};

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

    pub async fn quote_prompt(
        &self,
        request: QuotePromptRequest,
    ) -> Result<QuotePromptResponse, ExecutorError> {
        self.send(|reply| ExecutorMessage::QuotePrompt { request, reply })
            .await
    }

    pub async fn quote_chat_prompt(
        &self,
        request: QuoteChatPromptRequest,
    ) -> Result<QuoteChatPromptResponse, ExecutorError> {
        self.send(|reply| ExecutorMessage::QuoteChatPrompt { request, reply })
            .await
    }

    pub async fn list_models(&self) -> Result<ListModelsResponse, ExecutorError> {
        self.send(|reply| ExecutorMessage::ListModels { reply })
            .await
    }

    pub async fn preload_weights(&self, model: String) -> Result<(), ExecutorError> {
        self.send(|reply| ExecutorMessage::Preload { model, reply })
            .await
    }

    pub async fn execute(
        &self,
        request: ExecuteRequest,
    ) -> Result<ExecuteEventReceiver, ExecutorError> {
        self.send(|reply| ExecutorMessage::Execute { request, reply })
            .await
    }

    pub async fn get_stats(&self) -> Result<GetStatsResponse, ExecutorError> {
        self.send(|reply| ExecutorMessage::GetStats { reply }).await
    }

    pub async fn get_model_stats(
        &self,
        request: GetModelStatsRequest,
    ) -> Result<GetModelStatsResponse, ExecutorError> {
        self.send(|reply| ExecutorMessage::GetModelStats { request, reply })
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

    async fn quote_prompt(
        &self,
        request: Request<QuotePromptRequest>,
    ) -> Result<Response<QuotePromptResponse>, Status> {
        Ok(Response::new(
            self.quote_prompt(request.into_inner()).await?,
        ))
    }

    async fn quote_chat_prompt(
        &self,
        request: Request<QuoteChatPromptRequest>,
    ) -> Result<Response<QuoteChatPromptResponse>, Status> {
        Ok(Response::new(
            self.quote_chat_prompt(request.into_inner()).await?,
        ))
    }

    async fn list_models(
        &self,
        _request: Request<ListModelsRequest>,
    ) -> Result<Response<ListModelsResponse>, Status> {
        Ok(Response::new(self.list_models().await?))
    }

    async fn get_stats(
        &self,
        _request: Request<GetStatsRequest>,
    ) -> Result<Response<GetStatsResponse>, Status> {
        Ok(Response::new(self.get_stats().await?))
    }

    async fn get_model_stats(
        &self,
        request: Request<GetModelStatsRequest>,
    ) -> Result<Response<GetModelStatsResponse>, Status> {
        Ok(Response::new(
            self.get_model_stats(request.into_inner()).await?,
        ))
    }

    type ExecuteStream =
        Pin<Box<dyn tokio_stream::Stream<Item = Result<ExecuteStreamEvent, Status>> + Send>>;

    async fn execute(
        &self,
        request: Request<ExecuteRequest>,
    ) -> Result<Response<Self::ExecuteStream>, Status> {
        let receiver = self.execute(request.into_inner()).await?;
        Ok(Response::new(
            Box::pin(ReceiverStream::new(receiver)) as Self::ExecuteStream
        ))
    }

    type DecodeTokensStream =
        Pin<Box<dyn tokio_stream::Stream<Item = Result<DecodeTokensResponse, Status>> + Send>>;

    async fn decode_tokens(
        &self,
        request: Request<tonic::Streaming<DecodeTokensRequest>>,
    ) -> Result<Response<Self::DecodeTokensStream>, Status> {
        use hellas_rpc::decode_token_ids;
        use hellas_rpc::model::ModelAssets;
        use tokio_stream::StreamExt;

        let mut stream = request.into_inner();

        // First message must contain the model ID.
        let first = stream
            .next()
            .await
            .ok_or_else(|| Status::invalid_argument("empty stream"))??;

        let model_spec = if first.huggingface_revision.is_empty() {
            first.huggingface_model_id.clone()
        } else {
            format!(
                "{}@{}",
                first.huggingface_model_id, first.huggingface_revision
            )
        };
        // Tokenizer-only path. The dtype is irrelevant for `decode_tokens`;
        // F32 is just the cheapest valid value for the model-graph build that
        // `ModelAssets::load` does for EOS-id extraction.
        let assets = ModelAssets::load(&model_spec, catgrad::prelude::Dtype::F32)?;

        let output_stream = async_stream::stream! {
            let decode = |bytes: &[u8]| -> Result<DecodeTokensResponse, Status> {
                let ids = decode_token_ids(bytes)?;
                let text = assets.decode_tokens(&ids)?;
                Ok(DecodeTokensResponse { text })
            };

            if !first.token_bytes.is_empty() {
                yield decode(&first.token_bytes);
            }

            tokio::pin!(stream);
            while let Some(result) = stream.next().await {
                let req = match result {
                    Ok(req) => req,
                    Err(status) => {
                        yield Err(status);
                        break;
                    }
                };
                if req.token_bytes.is_empty() {
                    continue;
                }
                let response = decode(&req.token_bytes);
                let stop = response.is_err();
                yield response;
                if stop {
                    break;
                }
            }
        };

        Ok(Response::new(
            Box::pin(output_stream) as Self::DecodeTokensStream
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
        let receiver = self.execute(request).await?;
        Ok(Box::pin(ReceiverStream::new(receiver)))
    }
}
