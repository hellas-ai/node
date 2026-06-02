//! Server-side handler implementations.
//!
//! `ExecutorHandle` implements one Handler trait per service (Execute,
//! Symbolic, Fetch, Courtesy) — the codegen-emitted dispatcher routes
//! inbound RPCs here.

use std::pin::Pin;
use std::sync::Arc;

use catgrad::prelude::Dtype;
use futures_core::Stream;
use futures_util::StreamExt;
use hellas_rpc::ExecutorError;
use hellas_rpc::call::WithTrailer;
use hellas_rpc::model::{ModelAssets, TextOutputDecoder};
use hellas_rpc::pb::courtesy::{
    DecodeTokensRequest, DecodeTokensResponse, GetArtifactRequest, GetArtifactResponse,
    GetModelStatsRequest, GetModelStatsResponse, GetStatsRequest, GetStatsResponse,
    ListModelsRequest, ListModelsResponse, PutArtifactRequest, PutArtifactResponse,
    QuoteChatPromptRequest, QuoteChatPromptResponse, QuotePreparedTextRequest,
    QuotePreparedTextResponse, QuotePromptRequest, QuotePromptResponse,
};
use hellas_rpc::pb::execute::{RunTicketRequest, Ticket, WorkEvent};
use hellas_rpc::pb::fetch::FetchRequest as PbFetchRequest;
use hellas_rpc::pb::symbolic::SymbolicRequest as PbSymbolicRequest;
use hellas_rpc::provenance::write_provenance_metadata;
use hellas_rpc::services::courtesy::CourtesyHandler;
use hellas_rpc::services::execute::ExecuteHandler;
use hellas_rpc::services::fetch::FetchHandler;
use hellas_rpc::services::symbolic::SymbolicHandler;
use hellas_wire::{Metadata, WireCode, WireStatus};
use tokio::sync::oneshot;
use tokio_stream::wrappers::ReceiverStream;

use crate::state::model_spec;

use super::{ExecuteOutcome, ExecutorHandle, ExecutorMessage, TicketOutcome};

type ExecuteStream = Pin<Box<dyn Stream<Item = Result<WorkEvent, WireStatus>> + Send>>;
type DecodeTokensRequestStream =
    Pin<Box<dyn Stream<Item = Result<DecodeTokensRequest, WireStatus>> + Send>>;
type DecodeTokensStream =
    Pin<Box<dyn Stream<Item = Result<DecodeTokensResponse, WireStatus>> + Send>>;

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

    pub async fn create_fetch_ticket(
        &self,
        request: PbFetchRequest,
    ) -> Result<TicketOutcome<Ticket>, ExecutorError> {
        self.send(|reply| ExecutorMessage::QuoteFetch { request, reply })
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

    pub async fn put_artifact_handle(
        &self,
        request: PutArtifactRequest,
    ) -> Result<PutArtifactResponse, ExecutorError> {
        self.send(|reply| ExecutorMessage::PutArtifact { request, reply })
            .await
    }

    pub async fn get_artifact_handle(
        &self,
        request: GetArtifactRequest,
    ) -> Result<GetArtifactResponse, ExecutorError> {
        self.send(|reply| ExecutorMessage::GetArtifact { request, reply })
            .await
    }

    pub async fn list_models_handle(&self) -> Result<ListModelsResponse, ExecutorError> {
        self.send(|reply| ExecutorMessage::ListModels { reply })
            .await
    }

    pub async fn load_model_metadata(&self, model: String) -> Result<(), ExecutorError> {
        self.send(|reply| ExecutorMessage::LoadModelMetadata { model, reply })
            .await
    }

    pub async fn run_ticket_handle(
        &self,
        request: RunTicketRequest,
    ) -> Result<ExecuteOutcome, ExecutorError> {
        self.send(|reply| ExecutorMessage::Execute { request, reply })
            .await
    }

    pub async fn get_stats_handle(&self) -> Result<GetStatsResponse, ExecutorError> {
        self.send(|reply| ExecutorMessage::GetStats { reply }).await
    }

    pub async fn get_model_stats_handle(
        &self,
        request: GetModelStatsRequest,
    ) -> Result<GetModelStatsResponse, ExecutorError> {
        self.send(|reply| ExecutorMessage::GetModelStats { request, reply })
            .await
    }
}

fn with_provenance<R>(outcome: TicketOutcome<R>) -> WithTrailer<R> {
    let mut metadata = Metadata::new();
    write_provenance_metadata(&mut metadata, &outcome.provenance);
    WithTrailer::with_metadata(outcome.response, metadata)
}

// -- ExecuteHandler -----------------------------------------------------------
//
// `run_ticket` is server-streaming. We return a `WorkEvent` stream; the
// codegen wraps it via the call helpers for the wire layer.

impl ExecuteHandler for ExecutorHandle {
    async fn run_ticket(&self, request: RunTicketRequest) -> Result<ExecuteStream, WireStatus> {
        let outcome = self.run_ticket_handle(request).await?;
        let stream: ExecuteStream = Box::pin(ReceiverStream::new(outcome.events));
        drop(outcome.provenance);
        Ok(stream)
    }
}

// -- SymbolicHandler / FetchHandler -----------------------------------------

// The generated trait method declares `impl Into<WithTrailer<T>> + Send`
// as its return; we provide `WithTrailer<T>` directly. The refinement is
// intentional: handler-emitted trailers are concrete.
#[allow(refining_impl_trait)]
impl SymbolicHandler for ExecutorHandle {
    async fn create_ticket(
        &self,
        request: PbSymbolicRequest,
    ) -> Result<WithTrailer<Ticket>, WireStatus> {
        let outcome = self.create_symbolic_ticket(request).await?;
        let result = with_provenance(outcome);
        Ok(result)
    }
}

#[allow(refining_impl_trait)]
impl FetchHandler for ExecutorHandle {
    async fn create_ticket(
        &self,
        request: PbFetchRequest,
    ) -> Result<WithTrailer<Ticket>, WireStatus> {
        let outcome = self.create_fetch_ticket(request).await?;
        let result = with_provenance(outcome);
        Ok(result)
    }
}

// -- CourtesyHandler ---------------------------------------------------------

#[allow(refining_impl_trait)]
impl CourtesyHandler for ExecutorHandle {
    async fn quote_prompt(
        &self,
        request: QuotePromptRequest,
    ) -> Result<WithTrailer<QuotePromptResponse>, WireStatus> {
        let outcome = self.quote_prompt(request).await?;
        let result = with_provenance(outcome);
        Ok(result)
    }

    async fn quote_prepared_text(
        &self,
        request: QuotePreparedTextRequest,
    ) -> Result<WithTrailer<QuotePreparedTextResponse>, WireStatus> {
        let outcome = self.quote_prepared_text(request).await?;
        let result = with_provenance(outcome);
        Ok(result)
    }

    async fn quote_chat_prompt(
        &self,
        request: QuoteChatPromptRequest,
    ) -> Result<WithTrailer<QuoteChatPromptResponse>, WireStatus> {
        let outcome = self.quote_chat_prompt(request).await?;
        let result = with_provenance(outcome);
        Ok(result)
    }

    async fn put_artifact(
        &self,
        request: PutArtifactRequest,
    ) -> Result<PutArtifactResponse, WireStatus> {
        Ok(self.put_artifact_handle(request).await?)
    }

    async fn get_artifact(
        &self,
        request: GetArtifactRequest,
    ) -> Result<GetArtifactResponse, WireStatus> {
        Ok(self.get_artifact_handle(request).await?)
    }

    async fn list_models(
        &self,
        _request: ListModelsRequest,
    ) -> Result<ListModelsResponse, WireStatus> {
        Ok(self.list_models_handle().await?)
    }

    async fn get_stats(&self, _request: GetStatsRequest) -> Result<GetStatsResponse, WireStatus> {
        Ok(self.get_stats_handle().await?)
    }

    async fn get_model_stats(
        &self,
        request: GetModelStatsRequest,
    ) -> Result<GetModelStatsResponse, WireStatus> {
        Ok(self.get_model_stats_handle(request).await?)
    }

    async fn decode_tokens(
        &self,
        request: DecodeTokensRequestStream,
    ) -> Result<DecodeTokensStream, WireStatus> {
        Ok(decode_tokens_stream(request, self.preferred_dtype))
    }
}

fn decode_tokens_stream(
    mut requests: DecodeTokensRequestStream,
    dtype: Dtype,
) -> DecodeTokensStream {
    Box::pin(async_stream::try_stream! {
        let mut decoder: Option<DecodeSession> = None;
        while let Some(item) = requests.next().await {
            let request = item?;
            if decoder.is_none() {
                let assets = load_decode_assets(
                    request.huggingface_model_id.clone(),
                    request.huggingface_revision.clone(),
                    dtype,
                )
                .await?;
                decoder = Some(DecodeSession::new(
                    request.huggingface_model_id.clone(),
                    request.huggingface_revision.clone(),
                    assets,
                ));
            }

            let session = decoder
                .as_mut()
                .expect("decode session is initialized before use");
            session.validate_request_model(&request)?;
            if request.token_bytes.is_empty() {
                continue;
            }
            let text = session.push_bytes(&request.token_bytes)?;
            if !text.is_empty() {
                yield DecodeTokensResponse { text };
            }
        }
    })
}

async fn load_decode_assets(
    model_id: String,
    revision: String,
    dtype: Dtype,
) -> Result<Arc<ModelAssets>, WireStatus> {
    if model_id.is_empty() {
        return Err(WireStatus::new(
            WireCode::InvalidArgument,
            "huggingface_model_id is required on the first decode_tokens request",
        ));
    }
    let spec = model_spec(&model_id, &revision);
    let assets = tokio::task::spawn_blocking(move || ModelAssets::load(&spec, dtype))
        .await
        .map_err(|err| WireStatus::internal(format!("tokenizer load task failed: {err}")))??;
    Ok(Arc::new(assets))
}

struct DecodeSession {
    model_id: String,
    revision: String,
    decoder: TextOutputDecoder,
}

impl DecodeSession {
    fn new(model_id: String, revision: String, assets: Arc<ModelAssets>) -> Self {
        let decoder = TextOutputDecoder::for_model(assets);
        Self {
            model_id,
            revision,
            decoder,
        }
    }

    fn validate_request_model(&self, request: &DecodeTokensRequest) -> Result<(), WireStatus> {
        if request.huggingface_model_id.is_empty() && request.huggingface_revision.is_empty() {
            return Ok(());
        }
        if request.huggingface_model_id == self.model_id
            && request.huggingface_revision == self.revision
        {
            return Ok(());
        }
        Err(WireStatus::new(
            WireCode::InvalidArgument,
            "decode_tokens stream cannot switch tokenizer after the first request",
        ))
    }

    fn push_bytes(&mut self, bytes: &[u8]) -> Result<String, WireStatus> {
        self.decoder
            .push_bytes(bytes)
            .map_err(hellas_wire::WireStatus::from)
    }
}
