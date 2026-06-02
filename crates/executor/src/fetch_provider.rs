use std::collections::HashMap;
use std::future::Future;
use std::hash::{Hash, Hasher};
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use futures_core::Stream;
use futures_util::stream;
use hellas_core::JsonBytes;

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
}

impl FetchProviderRequest {
    pub fn new(service: impl Into<String>, method: impl Into<String>, body: JsonBytes) -> Self {
        Self {
            service: service.into(),
            method: method.into(),
            body,
        }
    }
}

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
pub struct RejectingFetchProvider;

impl FetchProvider for RejectingFetchProvider {
    fn run(&self, request: FetchProviderRequest) -> FetchProviderFuture<'_> {
        Box::pin(async move {
            Err(FetchProviderError::Rejected(format!(
                "no fetch provider configured for {}/{}",
                request.service, request.method
            )))
        })
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
        chunks: impl IntoIterator<Item = impl Into<Vec<u8>>>,
    ) {
        let request = FetchProviderRequest::new(service, method, JsonBytes::new(body.into()));
        let chunks = chunks.into_iter().map(Into::into).collect();
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
        let request = FetchProviderRequest::new(service, method, JsonBytes::new(body.into()));
        *self
            .calls
            .lock()
            .expect("mock fetch calls lock poisoned")
            .get(&request)
            .unwrap_or(&0)
    }
}

impl FetchProvider for MockFetchProvider {
    fn run(&self, request: FetchProviderRequest) -> FetchProviderFuture<'_> {
        Box::pin(async move {
            let chunks = {
                let mut calls = self
                    .calls
                    .lock()
                    .map_err(|_| FetchProviderError::Failed("mock calls lock poisoned".into()))?;
                *calls.entry(request.clone()).or_default() += 1;

                self.responses
                    .lock()
                    .map_err(|_| FetchProviderError::Failed("mock responses lock poisoned".into()))?
                    .get(&request)
                    .cloned()
            };

            let chunks = chunks.ok_or_else(|| {
                FetchProviderError::Rejected(format!(
                    "mock fetch response not programmed for {}/{}",
                    request.service, request.method
                ))
            })?;
            Ok(Box::pin(stream::iter(chunks.into_iter().map(Ok))) as FetchProviderStream)
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FetchProviderError {
    #[error("fetch request rejected: {0}")]
    Rejected(String),
    #[error("fetch request failed: {0}")]
    Failed(String),
}
