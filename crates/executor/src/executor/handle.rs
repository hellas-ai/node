use hellas_pb::courtesy::courtesy_server::Courtesy;
use hellas_pb::courtesy::{
    DecodeTokensRequest, DecodeTokensResponse, GetModelStatsRequest, GetModelStatsResponse,
    GetStatsRequest, GetStatsResponse, ListModelsRequest, ListModelsResponse,
    QuoteChatPromptRequest, QuoteChatPromptResponse, QuotePreparedTextRequest,
    QuotePreparedTextResponse, QuotePromptRequest, QuotePromptResponse,
};
use hellas_pb::hellas::execute_server::Execute;
use hellas_pb::hellas::{RunTicketRequest, Ticket, WorkEvent};
use hellas_pb::opaque::OpaqueRequest as PbOpaqueRequest;
use hellas_pb::opaque::opaque_server::Opaque;
use hellas_pb::symbolic::SymbolicRequest as PbSymbolicRequest;
use hellas_pb::symbolic::symbolic_server::Symbolic;
use hellas_rpc::ExecutorError;
use hellas_rpc::driver::{
    ExecuteDriver, QuotedPreparedTextResponse, QuotedResponse, StreamedExecution,
};
use hellas_rpc::provenance::write_provenance_metadata;
use std::pin::Pin;
use tokio::sync::oneshot;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

use super::{ExecuteOutcome, ExecutorHandle, ExecutorMessage, TicketOutcome};

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

    pub async fn create_symbolic_ticket(
        &self,
        request: PbSymbolicRequest,
    ) -> Result<TicketOutcome<Ticket>, ExecutorError> {
        self.send(|reply| ExecutorMessage::QuoteSymbolic { request, reply })
            .await
    }

    pub async fn create_opaque_ticket(
        &self,
        request: PbOpaqueRequest,
    ) -> Result<TicketOutcome<Ticket>, ExecutorError> {
        self.send(|reply| ExecutorMessage::QuoteOpaque { request, reply })
            .await
    }

    pub async fn quote_prompt(
        &self,
        request: QuotePromptRequest,
    ) -> Result<TicketOutcome<QuotePromptResponse>, ExecutorError> {
        self.send(|reply| ExecutorMessage::QuotePrompt { request, reply })
            .await
    }

    pub async fn quote_prepared_text(
        &self,
        request: QuotePreparedTextRequest,
    ) -> Result<TicketOutcome<QuotePreparedTextResponse>, ExecutorError> {
        self.send(|reply| ExecutorMessage::QuotePreparedText { request, reply })
            .await
    }

    pub async fn quote_chat_prompt(
        &self,
        request: QuoteChatPromptRequest,
    ) -> Result<TicketOutcome<QuoteChatPromptResponse>, ExecutorError> {
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

    pub async fn run_ticket(
        &self,
        request: RunTicketRequest,
    ) -> Result<ExecuteOutcome, ExecutorError> {
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
    type RunTicketStream =
        Pin<Box<dyn tokio_stream::Stream<Item = Result<WorkEvent, Status>> + Send>>;

    async fn run_ticket(
        &self,
        request: Request<RunTicketRequest>,
    ) -> Result<Response<Self::RunTicketStream>, Status> {
        let outcome = self.run_ticket(request.into_inner()).await?;
        let mut response =
            Response::new(Box::pin(ReceiverStream::new(outcome.events)) as Self::RunTicketStream);
        write_provenance_metadata(response.metadata_mut(), &outcome.provenance);
        Ok(response)
    }
}

#[tonic::async_trait]
impl Symbolic for ExecutorHandle {
    async fn create_ticket(
        &self,
        request: Request<PbSymbolicRequest>,
    ) -> Result<Response<Ticket>, Status> {
        let outcome = self.create_symbolic_ticket(request.into_inner()).await?;
        let mut response = Response::new(outcome.response);
        write_provenance_metadata(response.metadata_mut(), &outcome.provenance);
        Ok(response)
    }
}

#[tonic::async_trait]
impl Opaque for ExecutorHandle {
    async fn create_ticket(
        &self,
        request: Request<PbOpaqueRequest>,
    ) -> Result<Response<Ticket>, Status> {
        let outcome = self.create_opaque_ticket(request.into_inner()).await?;
        let mut response = Response::new(outcome.response);
        write_provenance_metadata(response.metadata_mut(), &outcome.provenance);
        Ok(response)
    }
}

#[tonic::async_trait]
impl Courtesy for ExecutorHandle {
    async fn quote_prompt(
        &self,
        request: Request<QuotePromptRequest>,
    ) -> Result<Response<QuotePromptResponse>, Status> {
        let outcome = self.quote_prompt(request.into_inner()).await?;
        let mut response = Response::new(outcome.response);
        write_provenance_metadata(response.metadata_mut(), &outcome.provenance);
        Ok(response)
    }

    async fn quote_prepared_text(
        &self,
        request: Request<QuotePreparedTextRequest>,
    ) -> Result<Response<QuotePreparedTextResponse>, Status> {
        let outcome = self.quote_prepared_text(request.into_inner()).await?;
        let mut response = Response::new(outcome.response);
        write_provenance_metadata(response.metadata_mut(), &outcome.provenance);
        Ok(response)
    }

    async fn quote_chat_prompt(
        &self,
        request: Request<QuoteChatPromptRequest>,
    ) -> Result<Response<QuoteChatPromptResponse>, Status> {
        let outcome = self.quote_chat_prompt(request.into_inner()).await?;
        let mut response = Response::new(outcome.response);
        write_provenance_metadata(response.metadata_mut(), &outcome.provenance);
        Ok(response)
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
    async fn create_symbolic_ticket(
        &mut self,
        request: PbSymbolicRequest,
    ) -> Result<QuotedResponse, Status> {
        let outcome = ExecutorHandle::create_symbolic_ticket(self, request)
            .await
            .map_err(<ExecutorError as Into<Status>>::into)?;
        Ok(QuotedResponse {
            response: outcome.response,
            provenance: outcome.provenance,
        })
    }

    async fn create_opaque_ticket(
        &mut self,
        request: PbOpaqueRequest,
    ) -> Result<QuotedResponse, Status> {
        let outcome = ExecutorHandle::create_opaque_ticket(self, request)
            .await
            .map_err(<ExecutorError as Into<Status>>::into)?;
        Ok(QuotedResponse {
            response: outcome.response,
            provenance: outcome.provenance,
        })
    }

    async fn quote_prepared_text(
        &mut self,
        request: QuotePreparedTextRequest,
    ) -> Result<QuotedPreparedTextResponse, Status> {
        let outcome = ExecutorHandle::quote_prepared_text(self, request)
            .await
            .map_err(<ExecutorError as Into<Status>>::into)?;
        Ok(QuotedPreparedTextResponse {
            response: outcome.response,
            provenance: outcome.provenance,
        })
    }

    async fn execute_streaming(
        &mut self,
        request: RunTicketRequest,
    ) -> Result<StreamedExecution, Status> {
        let outcome = ExecutorHandle::run_ticket(self, request)
            .await
            .map_err(<ExecutorError as Into<Status>>::into)?;
        Ok(StreamedExecution {
            stream: Box::pin(ReceiverStream::new(outcome.events)),
            provenance: outcome.provenance,
        })
    }
}
