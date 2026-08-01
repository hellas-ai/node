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

use futures_util::StreamExt as _;
use hellas_chain::domain::{ObjectId, Transaction};
use hellas_chain::staked::{Channel, JobAcceptanceContext, JobResultContext, MakerVoucher};
use hellas_chain::{EdgeState, LightClient, QueryError};
use hellas_kernel::{
    Auth, BlockHeight, EdgeId, List, MAX_EDGE_OUTPUTS, PayloadHash, Payout, Secp256k1Signer, Sig,
    TermsHash,
};
use hellas_rpc::ProducerSigningKey;
use hellas_rpc::call::StreamingCall;
use hellas_rpc::pb::chain::{ActivityEvent, ActivityEventKind};
use hellas_rpc::pb::execute::{
    JobAcceptance, ReceiptResponse, SettleRequest, Signature as PbSignature, signature,
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Everything a staked provider needs: its side of the pairing, the
/// chain it observes, and the feed that tells it the chain moved. One
/// value at the spawn boundary — a staked executor without a chain view
/// is unrepresentable.
pub struct StakedProvider {
    /// The provider's side of the two-edge pairing.
    pub channel: Channel,
    /// The chain the deadline heights are read from.
    pub chain: Arc<dyn ChainView>,
    /// Where new finalized heights arrive from.
    pub heights: Arc<dyn HeightFeed>,
}

/// A source of finalized-height notifications.
///
/// Deliberately separate from [`ChainView`]. Every deadline in the
/// staked protocol is a block height, so the provider's time-based
/// obligations — banking a due frontier, releasing an abandoned job —
/// must be driven by chain progress, never by a wall clock: a polling
/// interval has no defined relationship to block production and would
/// be an invented constant sitting under derived deadlines.
///
/// It cannot live on `ChainView` because a subscription holds state,
/// and `ChainView` has a blanket impl over the stateless
/// [`hellas_chain::LightClient`] trait. Keeping it separate also puts
/// the "how do I learn about new heights" decision where the topology
/// is known: a remote light client has a finalization stream, an
/// in-process node has the validator's broadcast.
#[async_trait::async_trait]
pub trait HeightFeed: Send + Sync + 'static {
    /// Resolves once the finalized height has advanced past `after`.
    ///
    /// An `Err` ends the provider's maintenance loop: the feed owns its
    /// own reconnection, so a surfaced error means the feed has given
    /// up, not that the caller should spin.
    async fn next_after(&self, after: BlockHeight) -> Result<BlockHeight, QueryError>;
}

/// The production feed: waits on the chain's finalization stream, then
/// reads the height it announced.
pub struct FinalizationFeed {
    client: hellas_chain::client::RemoteLightClient,
    stream: tokio::sync::Mutex<Option<StreamingCall<ActivityEvent>>>,
}

impl FinalizationFeed {
    /// Wraps a connected light client as a height feed.
    #[must_use]
    pub const fn new(client: hellas_chain::client::RemoteLightClient) -> Self {
        Self {
            client,
            stream: tokio::sync::Mutex::const_new(None),
        }
    }
}

impl core::fmt::Debug for FinalizationFeed {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.debug_struct("FinalizationFeed").finish()
    }
}

#[async_trait::async_trait]
impl HeightFeed for FinalizationFeed {
    async fn next_after(&self, after: BlockHeight) -> Result<BlockHeight, QueryError> {
        let mut guard = self.stream.lock().await;
        if guard.is_none() {
            *guard = Some(
                self.client
                    .subscribe_activity(vec![ActivityEventKind::Finalization])
                    .await?,
            );
        }
        let stream = guard
            .as_mut()
            .ok_or_else(|| QueryError::Remote("finalization stream missing".into()))?;
        while let Some(event) = stream.next().await {
            event.map_err(|err| QueryError::Remote(err.to_string()))?;
            // The event says something finalized; the height comes from
            // the chain itself, exactly as `follower.rs` does it.
            if let Some(height) = self.client.finalized_height().await?
                && height.get() > after.get()
            {
                return Ok(height);
            }
        }
        Err(QueryError::Remote("finalization stream ended".into()))
    }
}

/// Test feed: resolves whatever height a test publishes.
#[derive(Debug, Clone)]
pub struct FakeHeightFeed {
    updates: tokio::sync::watch::Sender<u64>,
}

impl Default for FakeHeightFeed {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeHeightFeed {
    /// Creates a feed sitting at height zero.
    #[must_use]
    pub fn new() -> Self {
        Self {
            updates: tokio::sync::watch::Sender::new(0),
        }
    }

    /// Publishes a new finalized height, waking any waiter.
    pub fn publish(&self, height: u64) {
        let _ = self.updates.send(height);
    }
}

#[async_trait::async_trait]
impl HeightFeed for FakeHeightFeed {
    async fn next_after(&self, after: BlockHeight) -> Result<BlockHeight, QueryError> {
        let mut rx = self.updates.subscribe();
        loop {
            let current = *rx.borrow_and_update();
            if current > after.get() {
                return Ok(BlockHeight::new(current));
            }
            if rx.changed().await.is_err() {
                return Err(QueryError::ChannelClosed);
            }
        }
    }
}

/// Encodes a kernel signature as its wire form.
pub(crate) fn sig_to_pb(sig: Sig) -> PbSignature {
    PbSignature {
        kind: Some(signature::Kind::Secp256k1(sig.as_bytes().to_vec())),
    }
}

/// Decodes a wire signature that must be a 64-byte secp256k1 witness.
pub(crate) fn sig_from_pb(field: &'static str, pb: Option<&PbSignature>) -> Result<Sig, String> {
    let kind = pb
        .and_then(|sig| sig.kind.as_ref())
        .ok_or_else(|| format!("{field} is missing"))?;
    let signature::Kind::Secp256k1(bytes) = kind else {
        return Err(format!("{field} must be secp256k1"));
    };
    Ok(Sig::from_bytes(fixed64(field, bytes)?))
}

/// The provider's staked receipt: signatures over the acceptance digest
/// and over the result context binding it to the provider's own
/// recorded terminal transcript.
pub(crate) fn receipt_response(
    signer: &Secp256k1Signer,
    acceptance: PayloadHash,
    transcript: [u8; 32],
) -> ReceiptResponse {
    let result = JobResultContext {
        acceptance,
        transcript,
    };
    ReceiptResponse {
        provider_acceptance_signature: Some(sig_to_pb(signer.sign(acceptance))),
        transcript: transcript.to_vec(),
        provider_result_signature: Some(sig_to_pb(signer.sign(result.digest()))),
    }
}

/// Rebuilds the maker voucher a settle request stands for, on the
/// channel's canonical two-output close shape. [`Channel::settle`]
/// still re-validates everything, including the authorization.
pub(crate) fn voucher_from_pb(
    request: &SettleRequest,
    channel: &Channel,
) -> Result<MakerVoucher, String> {
    let payment_edge = EdgeId::from_bytes(fixed32("payment_edge", &request.payment_edge)?);
    let terms_hash = TermsHash::from_bytes(fixed32("payment_terms", &request.payment_terms)?);
    let authorization = sig_from_pb(
        "client_authorization",
        request.client_authorization.as_ref(),
    )?;
    let refund = channel
        .capacity()
        .checked_sub(request.cumulative)
        .ok_or("frontier exceeds the payment capacity")?;
    let mut slots = [Payout::default(); MAX_EDGE_OUTPUTS];
    slots[0] = Payout::new(channel.client(), refund);
    slots[1] = Payout::new(channel.provider(), request.cumulative);
    Ok(MakerVoucher {
        payment_edge,
        terms_hash,
        cumulative: request.cumulative,
        outputs: List::take(slots, 2),
        client_auth: Auth::native(authorization),
    })
}

/// Decodes a wire [`JobAcceptance`] into the canonical context plus the
/// client's signature over its digest.
pub fn acceptance_from_pb(pb: &JobAcceptance) -> Result<(JobAcceptanceContext, Sig), String> {
    let signature = sig_from_pb("client signature", pb.client_signature.as_ref())?;
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
    Ok((context, signature))
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
        client_signature: Some(sig_to_pb(client_signature)),
    }
}

fn fixed32(field: &'static str, bytes: &[u8]) -> Result<[u8; 32], String> {
    bytes
        .try_into()
        .map_err(|_| format!("{field} must be 32 bytes, got {}", bytes.len()))
}

fn fixed64(field: &'static str, bytes: &[u8]) -> Result<[u8; 64], String> {
    bytes
        .try_into()
        .map_err(|_| format!("{field} must be 64 bytes, got {}", bytes.len()))
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
