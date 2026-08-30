//! Server-side handler implementations.
//!
//! `ExecutorHandle` implements one Handler trait per service (Execute,
//! Evaluate, Fetch, Courtesy) — the codegen-emitted dispatcher routes
//! inbound RPCs here.

use std::pin::Pin;

use crate::ExecutorError;
use futures_core::Stream;
#[cfg(feature = "evaluate")]
use hellas_rpc::ExecutionPackageId;
use hellas_rpc::call::WithTrailer;
use hellas_rpc::pb::courtesy::{
    GetArtifactRequest, GetArtifactResponse, GetPackageStatsRequest, GetPackageStatsResponse,
    GetStatsRequest, GetStatsResponse, ListPackagesRequest, ListPackagesResponse, QuoteResponse,
    QuoteTokensRequest,
};
use hellas_rpc::pb::evaluate::EvaluateRequest as PbEvaluateRequest;
use hellas_rpc::pb::execute::{OpenRequest, OpenResponse, RunTicketRequest, Ticket, WorkEvent};
use hellas_rpc::pb::fetch::FetchRequest as PbFetchRequest;
use hellas_rpc::provenance::write_provenance_metadata;
use hellas_rpc::services::courtesy::CourtesyHandler;
use hellas_rpc::services::evaluate::EvaluateHandler;
use hellas_rpc::services::execute::ExecuteHandler;
use hellas_rpc::services::fetch::FetchHandler;
use hellas_wire::{Metadata, WireCode, WireStatus};
use tokio::sync::oneshot;
use tokio_stream::wrappers::ReceiverStream;

use super::{ExecuteOutcome, ExecutorHandle, ExecutorMessage, TicketOutcome};
#[cfg(feature = "evaluate")]
use crate::PackageSource;

type ExecuteStream = Pin<Box<dyn Stream<Item = Result<WorkEvent, WireStatus>> + Send>>;
impl ExecutorHandle {
    pub(crate) async fn send<T>(
        &self,
        make_message: impl FnOnce(oneshot::Sender<Result<T, ExecutorError>>) -> ExecutorMessage,
    ) -> Result<T, ExecutorError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(make_message(reply_tx))
            .map_err(|_| ExecutorError::ChannelClosed)?;
        reply_rx.await.map_err(|_| ExecutorError::ChannelClosed)?
    }

    pub async fn create_evaluate_ticket(
        &self,
        request: PbEvaluateRequest,
    ) -> Result<TicketOutcome<Ticket>, ExecutorError> {
        self.send(|reply| ExecutorMessage::QuoteEvaluate { request, reply })
            .await
    }

    pub async fn create_fetch_ticket(
        &self,
        request: PbFetchRequest,
    ) -> Result<TicketOutcome<Ticket>, ExecutorError> {
        self.send(|reply| ExecutorMessage::QuoteFetch { request, reply })
            .await
    }

    pub async fn quote_tokens(
        &self,
        request: QuoteTokensRequest,
    ) -> Result<TicketOutcome<QuoteResponse>, ExecutorError> {
        self.send(|reply| ExecutorMessage::QuoteTokens { request, reply })
            .await
    }

    /// Publish one canonical evaluate artifact from an owner-controlled local
    /// workflow. There is intentionally no peer-reachable counterpart.
    #[cfg(feature = "evaluate")]
    pub async fn publish_canonical_artifact(
        &self,
        canonical_artifact: Vec<u8>,
    ) -> Result<hellas_rpc::Digest, ExecutorError> {
        self.send(|reply| ExecutorMessage::PublishCanonicalArtifact {
            canonical_artifact,
            reply,
        })
        .await
    }

    /// Read from the retained Courtesy artifact namespace. Ephemeral job
    /// artifacts are held by a separate memory store in the evaluate engine
    /// and are intentionally unreachable through this handle.
    pub async fn get_artifact_handle(
        &self,
        request: GetArtifactRequest,
    ) -> Result<GetArtifactResponse, ExecutorError> {
        self.send(|reply| ExecutorMessage::GetArtifact { request, reply })
            .await
    }

    pub async fn list_packages_handle(&self) -> Result<ListPackagesResponse, ExecutorError> {
        self.send(|reply| ExecutorMessage::ListPackages { reply })
            .await
    }

    /// Fetches, verifies, and loads one Catena package on this node.
    ///
    /// Only an owner of the handle can call this — there is no RPC for
    /// it — and calling it is what lets quotes for that package alias be
    /// answered at all.
    #[cfg(feature = "evaluate")]
    pub async fn materialize_package(
        &self,
        source: PackageSource,
    ) -> Result<ExecutionPackageId, ExecutorError> {
        self.send(|reply| ExecutorMessage::MaterializePackage { source, reply })
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

    pub async fn get_package_stats_handle(
        &self,
        request: GetPackageStatsRequest,
    ) -> Result<GetPackageStatsResponse, ExecutorError> {
        self.send(|reply| ExecutorMessage::GetPackageStats { request, reply })
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
        let ExecuteOutcome {
            events,
            provenance: _,
        } = outcome;
        let stream: ExecuteStream = Box::pin(ReceiverStream::new(events));
        Ok(stream)
    }
}

// -- EvaluateHandler / FetchHandler -----------------------------------------

// The generated trait method declares `impl Into<WithTrailer<T>> + Send`
// as its return; we provide `WithTrailer<T>` directly. The refinement is
// intentional: handler-emitted trailers are concrete.
#[allow(refining_impl_trait)]
impl EvaluateHandler for ExecutorHandle {
    async fn create_ticket(
        &self,
        request: PbEvaluateRequest,
    ) -> Result<WithTrailer<Ticket>, WireStatus> {
        let outcome = self.create_evaluate_ticket(request).await?;
        let result = with_provenance(outcome);
        Ok(result)
    }
}

#[allow(refining_impl_trait)]
impl FetchHandler for ExecutorHandle {
    async fn open(&self, _request: OpenRequest) -> Result<OpenResponse, WireStatus> {
        Err(WireStatus::new(
            WireCode::FailedPrecondition,
            "confidential open dispatcher is unavailable",
        ))
    }

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
    async fn open(&self, _request: OpenRequest) -> Result<OpenResponse, WireStatus> {
        Err(WireStatus::new(
            WireCode::FailedPrecondition,
            "confidential open dispatcher is unavailable",
        ))
    }

    async fn quote_tokens(
        &self,
        request: QuoteTokensRequest,
    ) -> Result<WithTrailer<QuoteResponse>, WireStatus> {
        let outcome = self.quote_tokens(request).await?;
        let result = with_provenance(outcome);
        Ok(result)
    }

    async fn get_artifact(
        &self,
        request: GetArtifactRequest,
    ) -> Result<GetArtifactResponse, WireStatus> {
        Ok(self.get_artifact_handle(request).await?)
    }

    async fn list_packages(
        &self,
        _request: ListPackagesRequest,
    ) -> Result<ListPackagesResponse, WireStatus> {
        Ok(self.list_packages_handle().await?)
    }

    async fn get_stats(&self, _request: GetStatsRequest) -> Result<GetStatsResponse, WireStatus> {
        Ok(self.get_stats_handle().await?)
    }

    async fn get_package_stats(
        &self,
        request: GetPackageStatsRequest,
    ) -> Result<GetPackageStatsResponse, WireStatus> {
        Ok(self.get_package_stats_handle(request).await?)
    }
}
