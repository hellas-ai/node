//! Chain observation seam.
//!
//! The executor runs in its own process by default; [`ChainView`] is
//! the narrow chain surface it needs — the finalized height,
//! transaction submission, and edge reads. Any
//! [`hellas_chain::LightClient`] satisfies it through the blanket impl,
//! so one executor composes over either topology: connect out to a
//! relay/indexer/validator with a remote light client, or co-host a
//! node in-process and hand its client here. [`FakeChainView`] drives
//! tests with scripted heights and a recording submission sink.

use hellas_chain::domain::{ObjectId, Transaction};
use hellas_chain::staked::JobAcceptanceContext;
use hellas_chain::{EdgeState, LightClient, QueryError};
use hellas_kernel::{BlockHeight, EdgeId, Secp256k1Signer, Sig, TermsHash};
use hellas_rpc::ProducerSigningKey;
use hellas_rpc::pb::execute::{JobAcceptance, signature};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Decodes a wire [`JobAcceptance`] into the canonical context plus the
/// client's signature over its digest.
pub fn acceptance_from_pb(pb: &JobAcceptance) -> Result<(JobAcceptanceContext, Sig), String> {
    let signature = pb
        .client_signature
        .as_ref()
        .and_then(|sig| sig.kind.as_ref())
        .ok_or("acceptance is missing the client signature")?;
    let signature::Kind::Secp256k1(bytes) = signature else {
        return Err("acceptance client signature must be secp256k1".into());
    };
    let context = JobAcceptanceContext {
        bond_edge: EdgeId::from_bytes(fixed32("bond_edge", &pb.bond_edge)?),
        bond_terms: TermsHash::from_bytes(fixed32("bond_terms", &pb.bond_terms)?),
        payment_edge: EdgeId::from_bytes(fixed32("payment_edge", &pb.payment_edge)?),
        sequence: pb.sequence,
        request: fixed32("request", &pb.request)?,
        environment: fixed32("environment", &pb.environment)?,
        price: pb.price,
        terminal_deadline: BlockHeight::new(pb.terminal_deadline),
    };
    Ok((context, Sig::from_bytes(fixed64("client_signature", bytes)?)))
}

/// Encodes the canonical context and the client's digest signature as a
/// wire [`JobAcceptance`].
#[must_use]
pub fn acceptance_to_pb(context: &JobAcceptanceContext, client_signature: Sig) -> JobAcceptance {
    JobAcceptance {
        bond_edge: context.bond_edge.as_bytes().to_vec(),
        bond_terms: context.bond_terms.as_bytes().to_vec(),
        payment_edge: context.payment_edge.as_bytes().to_vec(),
        sequence: context.sequence,
        request: context.request.to_vec(),
        environment: context.environment.to_vec(),
        price: context.price,
        terminal_deadline: context.terminal_deadline.get(),
        client_signature: Some(hellas_rpc::pb::execute::Signature {
            kind: Some(signature::Kind::Secp256k1(
                client_signature.as_bytes().to_vec(),
            )),
        }),
    }
}

fn fixed32(field: &'static str, bytes: &[u8]) -> Result<[u8; 32], String> {
    bytes
        .try_into()
        .map_err(|_| format!("acceptance {field} must be 32 bytes, got {}", bytes.len()))
}

fn fixed64(field: &'static str, bytes: &[u8]) -> Result<[u8; 64], String> {
    bytes
        .try_into()
        .map_err(|_| format!("acceptance {field} must be 64 bytes, got {}", bytes.len()))
}

/// Kernel signer sharing the producer identity's secp256k1 scalar: the
/// provider's on-chain party key IS its RPC identity.
///
/// Same curve, same 32-byte scalar, same 33-byte compressed public key
/// and 64-byte low-S compact signature — only the primitive crate
/// differs (k256 here, libsecp256k1 in the kernel), and the wire bytes
/// are interoperable.
#[must_use]
pub fn kernel_signer(producer: &ProducerSigningKey) -> Secp256k1Signer {
    Secp256k1Signer::from_secret_scalar(producer.to_secret_bytes())
        .expect("producer keys are valid secp256k1 scalars")
}

/// The chain surface the executor needs, and nothing more.
#[async_trait::async_trait]
pub trait ChainView: Send + Sync + 'static {
    /// Highest finalized block height, `None` before the first
    /// finalization is observed.
    async fn finalized_height(&self) -> Result<Option<BlockHeight>, QueryError>;

    /// Submits a transaction to the chain mempool.
    async fn submit(&self, tx: Transaction) -> Result<(), QueryError>;

    /// Reads a live edge at the latest finalized state. `None` when no
    /// block is finalized yet or the edge does not exist there.
    async fn edge(&self, id: ObjectId) -> Result<Option<EdgeState>, QueryError>;
}

#[async_trait::async_trait]
impl<L: LightClient> ChainView for L {
    async fn finalized_height(&self) -> Result<Option<BlockHeight>, QueryError> {
        Ok(self
            .get_latest_block()
            .await?
            .map(|block| BlockHeight::new(block.height)))
    }

    async fn submit(&self, tx: Transaction) -> Result<(), QueryError> {
        self.submit_tx(tx).await
    }

    async fn edge(&self, id: ObjectId) -> Result<Option<EdgeState>, QueryError> {
        let Some(latest) = self.get_latest_block().await? else {
            return Ok(None);
        };
        Ok(self
            .get_edge(latest.payload, id)
            .await?
            .and_then(|lookup| lookup.edge))
    }
}

/// Scriptable in-memory [`ChainView`] for tests: the height is set
/// directly, edges are registered by hand, and submissions are recorded
/// instead of executed.
#[derive(Debug, Clone, Default)]
pub struct FakeChainView {
    inner: Arc<Mutex<FakeChainState>>,
}

#[derive(Debug, Default)]
struct FakeChainState {
    height: Option<u64>,
    edges: HashMap<ObjectId, EdgeState>,
    submitted: Vec<Transaction>,
}

impl FakeChainView {
    /// Creates a view with no finalized block, no edges, and no
    /// recorded submissions.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Scripts the finalized height.
    pub fn set_height(&self, height: u64) {
        self.state().height = Some(height);
    }

    /// Registers an edge readable at the scripted state.
    pub fn put_edge(&self, id: ObjectId, edge: EdgeState) {
        self.state().edges.insert(id, edge);
    }

    /// Everything submitted so far, in order.
    #[must_use]
    pub fn submitted(&self) -> Vec<Transaction> {
        self.state().submitted.clone()
    }

    fn state(&self) -> std::sync::MutexGuard<'_, FakeChainState> {
        self.inner.lock().expect("fake chain state poisoned")
    }
}

#[async_trait::async_trait]
impl ChainView for FakeChainView {
    async fn finalized_height(&self) -> Result<Option<BlockHeight>, QueryError> {
        Ok(self.state().height.map(BlockHeight::new))
    }

    async fn submit(&self, tx: Transaction) -> Result<(), QueryError> {
        self.state().submitted.push(tx);
        Ok(())
    }

    async fn edge(&self, id: ObjectId) -> Result<Option<EdgeState>, QueryError> {
        let state = self.state();
        if state.height.is_none() {
            return Ok(None);
        }
        Ok(state.edges.get(&id).copied())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hellas_rpc::PublicKey;

    #[test]
    fn kernel_signer_shares_the_producer_identity() {
        let producer = ProducerSigningKey::from_secret_bytes([7; 32])
            .expect("non-zero scalar is a valid producer key");
        let signer = kernel_signer(&producer);
        let PublicKey::Secp256k1(compressed) = producer.public_key() else {
            panic!("producer keys are secp256k1");
        };
        assert_eq!(signer.party_key().as_bytes(), &compressed);
    }

    #[tokio::test]
    async fn fake_view_round_trips_height_and_records_submissions() {
        let view = FakeChainView::new();
        let height = view.finalized_height().await.expect("fake never fails");
        assert_eq!(height, None);
        assert!(view.submitted().is_empty());

        view.set_height(42);
        let height = view.finalized_height().await.expect("fake never fails");
        assert_eq!(height, Some(BlockHeight::new(42)));
    }
}
