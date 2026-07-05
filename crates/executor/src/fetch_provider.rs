use std::collections::HashMap;
use std::future::Future;
use std::hash::{Hash, Hasher};
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use futures_core::Stream;
use futures_util::stream;
use hellas_rpc::{Digest, InputCommitment, JsonBytes};

pub type FetchProviderResult<T> = Result<T, FetchProviderError>;
pub type FetchProviderStream =
    Pin<Box<dyn Stream<Item = FetchProviderResult<Vec<u8>>> + Send + 'static>>;
pub type FetchProviderFuture<'a> =
    Pin<Box<dyn Future<Output = FetchProviderResult<FetchProviderStream>> + Send + 'a>>;

pub trait FetchProvider: Send + Sync + 'static {
    fn run(&self, request: FetchProviderRequest) -> FetchProviderFuture<'_>;
}

#[derive(Clone, Debug, Eq)]
pub struct FetchProviderRequest {
    pub service: String,
    pub method: String,
    pub body: JsonBytes,
    /// Commitment over the caller-signed input transcript. Providers derive
    /// the upstream `Idempotency-Key` from it so retries of the same ticket
    /// dedupe at the provider billing boundary.
    pub input_commitment: InputCommitment,
}

impl FetchProviderRequest {
    pub fn new(
        service: impl Into<String>,
        method: impl Into<String>,
        body: JsonBytes,
        input_commitment: InputCommitment,
    ) -> Self {
        Self {
            service: service.into(),
            method: method.into(),
            body,
            input_commitment,
        }
    }

    pub fn idempotency_key(&self) -> String {
        self.input_commitment.digest().to_string()
    }
}

// Identity is the call content. `input_commitment` is derived metadata over
// the signed transcript (which includes the caller key and signatures), so
// including it would make identical provider calls from different callers
// unequal — wrong for the mock store and for call-content dedup.
impl PartialEq for FetchProviderRequest {
    fn eq(&self, other: &Self) -> bool {
        self.service == other.service && self.method == other.method && self.body == other.body
    }
}

impl Hash for FetchProviderRequest {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.service.hash(state);
        self.method.hash(state);
        self.body.hash(state);
    }
}

#[derive(Clone, Debug, Default)]
pub struct MockFetchProvider {
    responses: Arc<Mutex<HashMap<FetchProviderRequest, Vec<Vec<u8>>>>>,
    calls: Arc<Mutex<HashMap<FetchProviderRequest, usize>>>,
}

impl MockFetchProvider {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(
        &self,
        service: impl Into<String>,
        method: impl Into<String>,
        body: impl Into<Vec<u8>>,
        chunks: impl IntoIterator<Item = Vec<u8>>,
    ) {
        let request = mock_key(service, method, body);
        let chunks = chunks.into_iter().collect();
        self.responses
            .lock()
            .expect("mock fetch responses lock poisoned")
            .insert(request, chunks);
    }

    pub fn calls(
        &self,
        service: impl Into<String>,
        method: impl Into<String>,
        body: impl Into<Vec<u8>>,
    ) -> usize {
        let request = mock_key(service, method, body);
        *self
            .calls
            .lock()
            .expect("mock fetch calls lock poisoned")
            .get(&request)
            .unwrap_or(&0)
    }
}

// Eq/Hash ignore the commitment, so any value works as a lookup key.
fn mock_key(
    service: impl Into<String>,
    method: impl Into<String>,
    body: impl Into<Vec<u8>>,
) -> FetchProviderRequest {
    FetchProviderRequest::new(
        service,
        method,
        JsonBytes::new(body.into()),
        InputCommitment::from_digest(Digest::from_bytes([0; 32])),
    )
}

impl FetchProvider for MockFetchProvider {
    fn run(&self, request: FetchProviderRequest) -> FetchProviderFuture<'_> {
        Box::pin(async move {
            let chunks = {
                let mut calls = self
                    .calls
                    .lock()
                    .map_err(|_| FetchProviderError::failed("mock calls lock poisoned"))?;
                *calls.entry(request.clone()).or_default() += 1;

                self.responses
                    .lock()
                    .map_err(|_| FetchProviderError::failed("mock responses lock poisoned"))?
                    .get(&request)
                    .cloned()
            };

            let chunks = chunks.ok_or_else(|| {
                FetchProviderError::failed(format!(
                    "mock fetch response not programmed for {}/{}",
                    request.service, request.method
                ))
            })?;
            Ok(Box::pin(stream::iter(chunks.into_iter().map(Ok))) as FetchProviderStream)
        })
    }
}

/// A provider error always means the provider actually failed. Routing
/// happens in [`crate::FetchRouteRegistry`] before a provider is invoked,
/// so there is no "not my route" rejection variant.
#[derive(Debug, thiserror::Error)]
#[error("fetch provider failed: {0}")]
pub struct FetchProviderError(String);

impl FetchProviderError {
    pub fn failed(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}
