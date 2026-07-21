#[macro_use]
extern crate tracing;

mod error;
pub use error::{BackendInitError, ExecutorError, StateError};

#[cfg(feature = "evaluate")]
mod artifact_store;
#[cfg(feature = "evaluate")]
mod artifacts;

#[cfg(feature = "evaluate")]
mod backend;
mod chain;
#[cfg(feature = "evaluate")]
mod evaluate;
mod executor;
mod fetch;
mod fetch_policy;
mod fetch_projection;
mod fetch_provider;
mod fetch_registry;
mod metrics;
mod scheme;
mod state;
#[cfg(feature = "evaluate")]
mod worker;

#[cfg(feature = "evaluate")]
pub use artifact_store::ArtifactStoreConfig;
pub use chain::{
    ChainView, FakeChainView, HeightStream, StakedProvider, acceptance_from_pb, acceptance_to_pb,
    kernel_signer,
};
pub use executor::{Executor, ExecutorHandle, ExecutorSpawnConfig};
pub use fetch::FetchTranscriptStoreBackend;
pub use fetch_policy::{
    CallerAccess, FetchAccessError, FetchAccessPolicy, FetchAdmission, FetchQuotaReservation,
    FetchQuotaStoreBackend, FetchRoute, FetchRouteGrant, FetchRoutePolicy, RequestRateLimit,
    RouteSet, SpendLimit,
};
pub use fetch_projection::{
    FetchProjectionError, FetchProjectionSession, FetchProjector, FetchProjectorFactory,
    FetchRequestView, ProjectedFetch,
};
pub use fetch_provider::{
    FetchProvider, FetchProviderError, FetchProviderFuture, FetchProviderRequest,
    FetchProviderStream, MockFetchProvider,
};
pub use fetch_registry::{DuplicateFetchRoute, FetchRouteEntry, FetchRouteRegistry};
pub use hellas_rpc::services::courtesy::CourtesyServer;
pub use hellas_rpc::services::evaluate::EvaluateServer;
pub use hellas_rpc::services::execute::ExecuteServer;
pub use hellas_rpc::services::fetch::FetchServer;
pub use metrics::ExecutorMetrics;

#[cfg(feature = "evaluate")]
pub(crate) const DEFAULT_MAX_SEQ: u32 = 16;
