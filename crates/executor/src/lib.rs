#[macro_use]
extern crate tracing;

mod artifacts;
mod backend;
mod executor;
mod fetch;
mod fetch_policy;
mod fetch_projection;
mod fetch_provider;
mod fetch_registry;
mod metrics;
mod state;
mod worker;

pub use artifacts::ArtifactStoreConfig;
pub use executor::{Executor, ExecutorHandle, ExecutorSpawnConfig};
pub use fetch_policy::{
    CallerAccess, FetchAccessError, FetchAccessPolicy, FetchAdmission, FetchQuotaReservation,
    FetchQuotaStoreBackend, FetchRoute, FetchRouteGrant, FetchRoutePolicy, RequestRateLimit,
    RouteSet, SpendLimit,
};
pub use fetch_projection::{
    FetchProjectionError, FetchProjectionSession, FetchProjector, FetchProjectorFactory,
    FetchRequestView, FetchUsage, ProjectedFetch,
};
pub use fetch_provider::{
    FetchProvider, FetchProviderError, FetchProviderFuture, FetchProviderRequest,
    FetchProviderStream, MockFetchProvider,
};
pub use fetch_registry::{DuplicateFetchRoute, FetchRouteEntry, FetchRouteRegistry};
pub use hellas_rpc::services::courtesy::CourtesyServer;
pub use hellas_rpc::services::execute::ExecuteServer;
pub use hellas_rpc::services::fetch::FetchServer;
pub use hellas_rpc::services::symbolic::SymbolicServer;
pub use metrics::ExecutorMetrics;

pub(crate) const DEFAULT_MAX_SEQ: u32 = 16;
