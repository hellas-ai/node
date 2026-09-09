use std::pin::Pin;
use std::sync::Arc;

use hellas_client::iroh::fetch_execution_stream;
use hellas_client::{ExecutionRoute, ExecutionRuntime, FetchExecutionEvent, ProviderTrustAnchor};
use hellas_rpc::fetch::build_input_events_with_retention;
use hellas_rpc::pb::fetch::FetchRequest;
use hellas_rpc::stream::input_event_to_pb;
use hellas_rpc::{Assurance, ContentId, ProducerSigningKey, Retention};
use iroh::{EndpointId, SecretKey};

/// Stable native caller identity. Hosts decide where these secret bytes are
/// persisted (for example, Gate uses its private application directory or the
/// platform credential store); the SDK never writes them implicitly.
#[derive(Clone)]
pub struct ClientIdentity {
    transport_key: SecretKey,
    caller_key: ProducerSigningKey,
}

impl ClientIdentity {
    pub fn generate() -> Self {
        Self {
            transport_key: SecretKey::generate(),
            caller_key: ProducerSigningKey::generate(),
        }
    }

    pub fn from_secret_bytes(
        transport_key: [u8; 32],
        caller_key: [u8; 32],
    ) -> hellas_client::ClientResult<Self> {
        Ok(Self {
            transport_key: SecretKey::from(transport_key),
            caller_key: ProducerSigningKey::from_secret_bytes(caller_key)
                .map_err(hellas_client::ClientError::external)?,
        })
    }

    pub fn transport_secret_bytes(&self) -> [u8; 32] {
        self.transport_key.to_bytes()
    }

    pub fn caller_secret_bytes(&self) -> [u8; 32] {
        self.caller_key.to_secret_bytes()
    }

    pub fn node_id(&self) -> EndpointId {
        self.transport_key.public()
    }

    pub fn transport_key(&self) -> SecretKey {
        self.transport_key.clone()
    }

    pub fn caller_key(&self) -> &ProducerSigningKey {
        &self.caller_key
    }
}

/// Typed input for one verified remote Fetch execution.
pub struct RemoteFetchRequest {
    pub node_id: Option<EndpointId>,
    pub node_addrs: Vec<std::net::SocketAddr>,
    pub retries: usize,
    pub service: String,
    pub method: String,
    pub execution_environment: ContentId,
    pub payload: Vec<u8>,
    pub retention: Retention,
    pub assurance: Assurance,
    pub provider_trust: ProviderTrustAnchor,
}

/// Reusable native client runtime. Its endpoint and caller identity survive
/// across executions, unlike command-specific CLI assembly.
pub struct HellasClient {
    runtime: ExecutionRuntime<()>,
    caller_key: Arc<ProducerSigningKey>,
}

impl HellasClient {
    pub async fn open() -> hellas_client::ClientResult<Self> {
        Self::open_with_identity(ClientIdentity::generate()).await
    }

    pub async fn open_with_identity(identity: ClientIdentity) -> hellas_client::ClientResult<Self> {
        Ok(Self {
            runtime: ExecutionRuntime::remote(identity.transport_key).await?,
            caller_key: Arc::new(identity.caller_key),
        })
    }

    pub fn caller_key(&self) -> &ProducerSigningKey {
        &self.caller_key
    }

    pub fn fetch(
        &self,
        request: RemoteFetchRequest,
    ) -> hellas_client::ClientResult<
        Pin<
            Box<
                dyn futures_core::Stream<Item = hellas_client::ClientResult<FetchExecutionEvent>>
                    + Send
                    + 'static,
            >,
        >,
    > {
        let route = ExecutionRoute::remote(
            request.node_id,
            request.node_addrs,
            request.retries,
            request.provider_trust,
        );
        let input = build_input_events_with_retention(
            &request.service,
            &request.method,
            &request.payload,
            request.execution_environment,
            request.assurance,
            &self.caller_key,
            request.retention,
        )
        .map_err(hellas_client::ClientError::external)?;
        let request = FetchRequest {
            input: input.iter().map(input_event_to_pb).collect(),
        };
        Ok(Box::pin(fetch_execution_stream(
            self.runtime.clone(),
            request,
            route,
            self.caller_key.clone(),
        )))
    }

    pub async fn close(&self) {
        self.runtime.close_remote().await;
    }
}
