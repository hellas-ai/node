use hellas_kernel::domain::{Address, Coin, Digest, ObjectId, Transaction};

/// Flattened proposal metadata for the activity stream.
#[derive(Clone, Debug)]
pub struct ProposalInfo {
    pub epoch: u64,
    pub view: u64,
    pub parent_view: u64,
    pub parent_payload: Digest,
    pub payload: Digest,
}

/// Structured consensus event for the activity stream.
#[derive(Clone, Debug)]
pub enum ConsensusActivity {
    Notarize {
        proposal: ProposalInfo,
        signer: u32,
        signature: Vec<u8>,
    },
    Notarization {
        proposal: ProposalInfo,
        signers: Vec<u32>,
        certificate: Vec<u8>,
    },
    Nullify {
        epoch: u64,
        view: u64,
        signer: u32,
        signature: Vec<u8>,
    },
    Nullification {
        epoch: u64,
        view: u64,
        signers: Vec<u32>,
        certificate: Vec<u8>,
    },
    Finalization {
        proposal: ProposalInfo,
        signers: Vec<u32>,
        certificate: Vec<u8>,
    },
}

/// Summary of the latest finalized block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LatestBlock {
    pub height: u64,
    pub payload: Digest,
    pub state_root: Digest,
    pub finalization: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerCoins {
    pub snapshot: LatestBlock,
    pub coins: Vec<(ObjectId, u64)>,
}

/// Errors returned by light-client queries.
#[derive(Debug, Clone, thiserror::Error)]
pub enum QueryError {
    #[error("query channel closed")]
    ChannelClosed,
    #[error("state unavailable: {0}")]
    StateUnavailable(String),
    #[error("remote rpc error: {0}")]
    Remote(String),
    #[error("connection failed: {0}")]
    Connect(String),
}

impl From<QueryError> for tonic::Status {
    fn from(err: QueryError) -> Self {
        match err {
            QueryError::ChannelClosed => tonic::Status::unavailable("query channel closed"),
            QueryError::StateUnavailable(message) => tonic::Status::failed_precondition(message),
            QueryError::Remote(message) => tonic::Status::unavailable(message),
            QueryError::Connect(message) => tonic::Status::unavailable(message),
        }
    }
}

impl From<tonic::Status> for QueryError {
    fn from(status: tonic::Status) -> Self {
        match status.code() {
            tonic::Code::FailedPrecondition | tonic::Code::OutOfRange => {
                QueryError::StateUnavailable(status.message().to_string())
            }
            _ => QueryError::Remote(status.to_string()),
        }
    }
}

/// Transport-agnostic query interface for light clients.
pub trait LightClient: Clone + Send + Sync + 'static {
    fn get_state_root(&self) -> impl Future<Output = Result<Option<Digest>, QueryError>> + Send;

    fn get_proof(
        &self,
        object_id: ObjectId,
    ) -> impl Future<Output = Result<Option<Vec<u8>>, QueryError>> + Send;

    fn get_coin(
        &self,
        payload: Digest,
        object_id: ObjectId,
    ) -> impl Future<Output = Result<Option<Coin>, QueryError>> + Send;

    fn get_finalization(
        &self,
        payload: Digest,
    ) -> impl Future<Output = Result<Option<Vec<u8>>, QueryError>> + Send;

    fn get_latest_block(
        &self,
    ) -> impl Future<Output = Result<Option<LatestBlock>, QueryError>> + Send;

    fn submit_tx(&self, tx: Transaction) -> impl Future<Output = Result<(), QueryError>> + Send;

    fn get_validators(&self) -> impl Future<Output = Result<Vec<String>, QueryError>> + Send;

    fn get_coins_by_owner(
        &self,
        owner: Address,
    ) -> impl Future<Output = Result<Option<OwnerCoins>, QueryError>> + Send;
}
