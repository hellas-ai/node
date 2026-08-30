#![cfg_attr(not(feature = "evaluate"), allow(dead_code))]

use std::any::Any;

use crate::ExecutorError;
use async_trait::async_trait;
use hellas_rpc::pb::courtesy::{
    GetArtifactRequest, GetArtifactResponse, ListPackagesResponse, QuoteResponse,
    QuoteTokensRequest,
};
use hellas_rpc::pb::evaluate::EvaluateRequest as PbEvaluateRequest;
use hellas_rpc::pb::execute::Ticket;
use hellas_rpc::{Assurance, PublicKey};
#[cfg(feature = "evaluate")]
use hellas_rpc::{Digest, ExecutionPackageId};

use crate::executor::{ExecuteOutcome, TicketOutcome};
#[cfg(feature = "evaluate")]
use crate::package::PackageSource;
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

    async fn quote_tokens(
        &mut self,
        store: &mut ExecutorState,
        request: QuoteTokensRequest,
    ) -> Result<TicketOutcome<QuoteResponse>, ExecutorError>;

    /// Fetches, verifies, and loads one Catena package on this node.
    ///
    /// The one path in a serving process that may spend bandwidth on a
    /// package, and deliberately not an RPC: it is reached only from an
    /// operator's package flags or a caller running its own in-process
    /// executor. Every peer-reachable path consults only the resulting
    /// exact-identity registry and refuses what this has not loaded.
    #[cfg(feature = "evaluate")]
    async fn materialize_package(
        &mut self,
        source: PackageSource,
    ) -> Result<ExecutionPackageId, ExecutorError>;

    /// Publish one canonical artifact through the owner-only handle path.
    #[cfg(feature = "evaluate")]
    async fn publish_canonical_artifact(
        &mut self,
        canonical_artifact: Vec<u8>,
    ) -> Result<Digest, ExecutorError>;

    async fn get_artifact(
        &mut self,
        request: GetArtifactRequest,
    ) -> Result<GetArtifactResponse, ExecutorError>;

    async fn list_packages(&self) -> ListPackagesResponse;

    fn start(
        &mut self,
        job: Box<dyn SchemeJob>,
        ctx: SchemeRunContext,
    ) -> Result<ExecuteOutcome, ExecutorError>;

    /// Resolves one request and starts it, with no quote and no ticket.
    ///
    /// The paid path's only way in. It exists because the quote store is
    /// transient and the paid endpoint's journal is not: a provider that
    /// accepted a job and then restarted must execute exactly the job it
    /// accepted, from the bundle on its disk, and a quote lookup could
    /// only fail there.
    ///
    /// It admits nothing financial, and does not pretend to. Its one
    /// caller is `ExecutorHandle::run_paid_evaluate`, which is reachable
    /// by an owner of the handle and by no RPC — the same reach
    /// `materialize_package` has. What makes an invocation through it a
    /// paid one is the running marker the paid endpoint journaled
    /// before calling, and that marker is not visible from here.
    async fn start_request(
        &mut self,
        request: hellas_rpc::EvaluateRequest,
    ) -> Result<ExecuteOutcome, ExecutorError>;

    async fn replay_completed(
        &self,
        _request_commitment: [u8; 32],
        _runner_public_key: &PublicKey,
        _assurance: Assurance,
    ) -> Result<Option<ExecuteOutcome>, ExecutorError> {
        Ok(None)
    }

    async fn on_completion(&mut self, completion: Box<dyn SchemeCompletion>);
}
