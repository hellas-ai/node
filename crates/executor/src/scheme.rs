#![cfg_attr(not(feature = "evaluate"), allow(dead_code))]

use std::any::Any;

use crate::ExecutorError;
use async_trait::async_trait;
use hellas_rpc::PublicKey;
use hellas_rpc::pb::courtesy::{
    GetArtifactRequest, GetArtifactResponse, ListModelsResponse, PutArtifactRequest,
    PutArtifactResponse, QuoteChatPromptRequest, QuoteChatPromptResponse, QuotePreparedTextRequest,
    QuotePreparedTextResponse, QuotePromptRequest, QuotePromptResponse,
};
use hellas_rpc::pb::evaluate::EvaluateRequest as PbEvaluateRequest;
use hellas_rpc::pb::execute::Ticket;

use crate::executor::{ExecuteOutcome, TicketOutcome};
use crate::state::ExecutorState;

pub trait SchemeJob: Any + Send + Sync {
    fn into_any(self: Box<Self>) -> Box<dyn Any + Send>;
    fn clone_box(&self) -> Box<dyn SchemeJob>;
}

impl Clone for Box<dyn SchemeJob> {
    fn clone(&self) -> Self {
        self.clone_box()
    }
}

pub trait SchemeCompletion: Any + Send + Sync {
    fn into_any(self: Box<Self>) -> Box<dyn Any + Send>;
}

pub struct SchemeRunContext {
    pub execution_id: String,
    pub request_commitment: [u8; 32],
}

#[async_trait]
pub trait SchemeEngine: Send + Sync {
    async fn quote_evaluate(
        &mut self,
        store: &mut ExecutorState,
        request: PbEvaluateRequest,
    ) -> Result<TicketOutcome<Ticket>, ExecutorError>;

    async fn quote_prepared_text(
        &mut self,
        store: &mut ExecutorState,
        request: QuotePreparedTextRequest,
    ) -> Result<TicketOutcome<QuotePreparedTextResponse>, ExecutorError>;

    async fn quote_prompt(
        &mut self,
        store: &mut ExecutorState,
        request: QuotePromptRequest,
    ) -> Result<TicketOutcome<QuotePromptResponse>, ExecutorError>;

    async fn quote_chat_prompt(
        &mut self,
        store: &mut ExecutorState,
        request: QuoteChatPromptRequest,
    ) -> Result<TicketOutcome<QuoteChatPromptResponse>, ExecutorError>;

    async fn load_model_metadata(&mut self, model: String) -> Result<(), ExecutorError>;

    async fn put_artifact(
        &mut self,
        request: PutArtifactRequest,
    ) -> Result<PutArtifactResponse, ExecutorError>;

    async fn get_artifact(
        &mut self,
        request: GetArtifactRequest,
    ) -> Result<GetArtifactResponse, ExecutorError>;

    async fn list_models(&self) -> ListModelsResponse;

    fn start(
        &mut self,
        job: Box<dyn SchemeJob>,
        ctx: SchemeRunContext,
    ) -> Result<ExecuteOutcome, ExecutorError>;

    async fn replay_completed(
        &self,
        _request_commitment: [u8; 32],
        _runner_public_key: &PublicKey,
    ) -> Result<Option<ExecuteOutcome>, ExecutorError> {
        Ok(None)
    }

    async fn on_completion(&mut self, completion: Box<dyn SchemeCompletion>);
}
