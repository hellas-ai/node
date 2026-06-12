use thiserror::Error;

use crate::fetch_provider::FetchProviderRequest;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProjectedFetch {
    Event(Vec<u8>),
    Terminal(Vec<u8>),
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FetchUsage {
    pub input_units: Option<u64>,
    pub output_units: Option<u64>,
    pub total_units: Option<u64>,
}

impl FetchUsage {
    pub fn total_or_output(self) -> u64 {
        self.total_units
            .or(self.output_units)
            .or(self.input_units)
            .unwrap_or_default()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchRequestView {
    pub service: String,
    pub method: String,
    pub model: Option<String>,
    pub max_output_units: Option<u64>,
}

impl FetchRequestView {
    pub fn from_provider_request(request: &FetchProviderRequest) -> Self {
        Self {
            service: request.service.clone(),
            method: request.method.clone(),
            model: None,
            max_output_units: None,
        }
    }
}

pub struct FetchProjectionSession {
    pub request_view: FetchRequestView,
    pub projector: Box<dyn FetchProjector>,
}

pub trait FetchProjector: Send + Sync + 'static {
    fn project(&mut self, bytes: &[u8]) -> Result<Vec<ProjectedFetch>, FetchProjectionError>;
    fn finish(&mut self) -> Result<Vec<ProjectedFetch>, FetchProjectionError>;
    fn usage(&self) -> Option<FetchUsage>;
}

pub trait FetchProjectorFactory: Send + Sync + 'static {
    fn create(
        &self,
        request: &FetchProviderRequest,
    ) -> Result<FetchProjectionSession, FetchProjectionError>;
}

/// A projection error always means projection actually failed. Routing
/// happens in [`crate::FetchRouteRegistry`] before a projector is created,
/// so there is no "not my route" rejection variant.
#[derive(Debug, Error)]
#[error("fetch projection failed: {0}")]
pub struct FetchProjectionError(String);

impl FetchProjectionError {
    pub fn failed(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}
