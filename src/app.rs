mod block;

pub use block::HellasBlock;

use crate::execution::{
    execute_all, execute_proposal,
    store::{UtxoDatabase, UtxoSyncTarget, empty_state},
};
use commonware_actor::Feedback;
use commonware_codec::Encode;
use commonware_consensus::{
    CertifiableBlock, Heightable, Reporter,
    simplex::types::{Activity as SimplexActivity, Context, Proposal},
    types::Height,
};
use commonware_cryptography::{Digestible, sha256::Digest};
use commonware_glue::stateful::{
    Application as StatefulApplication, Proposed,
    db::{DatabaseSet, Merkleized as _, Unmerkleized as _},
};
use commonware_runtime::{BufferPooler, Clock, Metrics, Spawner, Storage};
use commonware_storage::{mmr::Location, qmdb::sync::Target};
use commonware_utils::{SystemTimeExt, non_empty_range};
use futures::{Stream, StreamExt};
use hellas_types::rpc::{ConsensusActivity, ProposalInfo};
use hellas_types::{Address, MAX_TXS_PER_BLOCK, PublicKey, Scheme, Transaction};
use rand::Rng;
use std::{collections::VecDeque, sync::Arc};
use tokio::sync::{Mutex, broadcast};

type MarshalVariant = commonware_consensus::marshal::standard::Standard<HellasBlock>;
pub type MarshalMailbox = commonware_consensus::marshal::core::Mailbox<Scheme, MarshalVariant>;

#[derive(Clone, Copy)]
pub struct ApplicationConfig {
    pub page_cache_size: u16,
    pub page_cache_count: usize,
}

impl Default for ApplicationConfig {
    fn default() -> Self {
        Self {
            page_cache_size: crate::execution::store::DEFAULT_PAGE_CACHE_SIZE.get(),
            page_cache_count: crate::execution::store::DEFAULT_PAGE_CACHE_COUNT.get(),
        }
    }
}

#[derive(Clone, Default)]
pub struct Mempool {
    inner: Arc<Mutex<VecDeque<Transaction>>>,
}

impl Mempool {
    pub async fn submit(&self, tx: Transaction) {
        self.inner.lock().await.push_back(tx);
    }

    async fn snapshot(&self) -> Vec<Transaction> {
        self.inner.lock().await.iter().cloned().collect()
    }

    async fn commit_snapshot(&self, snapshot_len: usize, retained: Vec<Transaction>) {
        let mut mempool = self.inner.lock().await;
        let split_at = snapshot_len.min(mempool.len());
        let tail = mempool.split_off(split_at);
        mempool.clear();
        mempool.extend(retained);
        mempool.extend(tail);
    }
}

#[derive(Clone)]
pub struct Application {
    genesis: HellasBlock,
    genesis_allocations: Arc<Vec<(Address, u64)>>,
}

impl Application {
    pub fn genesis_block(&self) -> HellasBlock {
        self.genesis.clone()
    }

    pub async fn new<E>(
        context: E,
        genesis_leader: PublicKey,
        genesis_allocations: Vec<(Address, u64)>,
        partition_prefix: &str,
        config: ApplicationConfig,
    ) -> Self
    where
        E: Storage + Clock + Metrics + BufferPooler,
    {
        let (state_root, sync_target) = empty_state(
            context,
            partition_prefix,
            config.page_cache_size,
            config.page_cache_count,
        )
        .await;
        Self {
            genesis: HellasBlock::genesis(genesis_leader, state_root, sync_target),
            genesis_allocations: Arc::new(genesis_allocations),
        }
    }
}

fn sync_target_from_merkleized<E>(
    merkleized: &<UtxoDatabase<E> as DatabaseSet<E>>::Merkleized,
) -> UtxoSyncTarget
where
    E: Storage + Clock + Metrics + Send + Sync + 'static,
{
    let bounds = merkleized.bounds();
    Target {
        root: merkleized.root(),
        range: non_empty_range!(bounds.inactivity_floor, Location::new(bounds.total_size)),
    }
}

impl<E> StatefulApplication<E> for Application
where
    E: Rng + Spawner + Metrics + Clock + Storage + Send + Sync + 'static,
{
    type SigningScheme = Scheme;
    type Context = Context<Digest, PublicKey>;
    type Block = HellasBlock;
    type Databases = UtxoDatabase<E>;
    type InputProvider = Mempool;

    fn sync_targets(block: &Self::Block) -> <Self::Databases as DatabaseSet<E>>::SyncTargets {
        block.sync_target()
    }

    async fn genesis(&mut self) -> Self::Block {
        self.genesis.clone()
    }

    async fn propose(
        &mut self,
        context: (E, Self::Context),
        ancestry: impl Stream<Item = Self::Block> + Send,
        batches: <Self::Databases as DatabaseSet<E>>::Unmerkleized,
        input: &mut Self::InputProvider,
    ) -> Option<Proposed<Self, E>> {
        let (runtime, consensus_context) = context;
        let mut ancestry = Box::pin(ancestry);
        let parent = ancestry.next().await?;
        let candidates = input.snapshot().await;
        let snapshot_len = candidates.len();
        let (batches, txs, retained) = match execute_proposal(
            parent.height(),
            candidates,
            &self.genesis_allocations,
            MAX_TXS_PER_BLOCK,
            batches,
        )
        .await
        {
            Ok(result) => result,
            Err(err) => {
                error!(?err, "proposal execution failed");
                return None;
            }
        };
        let merkleized = batches.merkleize().await.expect("UTXO merkleize failed");
        input.commit_snapshot(snapshot_len, retained).await;

        let timestamp = runtime.current().epoch_millis().max(parent.timestamp());
        let block = HellasBlock::new(
            consensus_context,
            parent.digest(),
            Height::new(parent.height().get() + 1),
            timestamp,
            merkleized.root(),
            sync_target_from_merkleized(&merkleized),
            txs,
        );
        Some(Proposed { block, merkleized })
    }

    async fn verify(
        &mut self,
        context: (E, Self::Context),
        ancestry: impl Stream<Item = Self::Block> + Send,
        batches: <Self::Databases as DatabaseSet<E>>::Unmerkleized,
    ) -> Option<<Self::Databases as DatabaseSet<E>>::Merkleized> {
        let (runtime, consensus_context) = context;
        let mut ancestry = Box::pin(ancestry);
        let block = ancestry.next().await?;
        let parent = ancestry.next().await?;
        if let Err(err) = block.validate(
            &consensus_context,
            Height::new(parent.height().get() + 1),
            parent.digest(),
            runtime.current().epoch_millis(),
            parent.timestamp(),
        ) {
            warn!(%err, payload = ?block.digest(), "block validation failed");
            return None;
        }

        let batches = execute_all(
            parent.height(),
            block.txs(),
            &self.genesis_allocations,
            batches,
        )
        .await
        .map_err(|err| {
            warn!(?err, payload = ?block.digest(), "block execution failed");
            err
        })
        .ok()?;
        let merkleized = batches.merkleize().await.expect("UTXO merkleize failed");
        let computed_sync_target = sync_target_from_merkleized(&merkleized);
        if merkleized.root() != block.state_root() || computed_sync_target != block.sync_target() {
            warn!(
                payload = ?block.digest(),
                claimed_state_root = ?block.state_root(),
                computed_state_root = ?merkleized.root(),
                claimed_sync_target = ?block.sync_target(),
                computed_sync_target = ?computed_sync_target,
                "block root mismatch"
            );
            return None;
        }
        Some(merkleized)
    }

    async fn apply(
        &mut self,
        _context: (E, Self::Context),
        block: &Self::Block,
        batches: <Self::Databases as DatabaseSet<E>>::Unmerkleized,
    ) -> <Self::Databases as DatabaseSet<E>>::Merkleized {
        let parent_height = Height::new(block.height().get().saturating_sub(1));
        let batches = execute_all(
            parent_height,
            block.txs(),
            &self.genesis_allocations,
            batches,
        )
        .await
        .expect("replay of certified block failed");
        let merkleized = batches.merkleize().await.expect("UTXO merkleize failed");
        assert_eq!(merkleized.root(), block.state_root());
        assert_eq!(
            sync_target_from_merkleized(&merkleized),
            block.sync_target()
        );
        merkleized
    }

    async fn finalized(
        &mut self,
        _context: (E, Self::Context),
        block: &Self::Block,
        _databases: &Self::Databases,
    ) {
        info!(
            name: "app.finalized",
            height = %block.height(),
            view = %block.context().round.view(),
            payload = ?block.digest(),
            tx_count = block.txs().len(),
        );
    }
}

#[derive(Clone)]
pub struct ActivityReporter<R> {
    inner: R,
    activity_tx: broadcast::Sender<ConsensusActivity>,
}

impl<R> ActivityReporter<R> {
    pub fn new(inner: R, activity_tx: broadcast::Sender<ConsensusActivity>) -> Self {
        Self { inner, activity_tx }
    }
}

impl<R> Reporter for ActivityReporter<R>
where
    R: Reporter<Activity = hellas_types::Activity> + Send,
{
    type Activity = hellas_types::Activity;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        if let Some(converted) = convert_activity(&activity) {
            let _ = self.activity_tx.send(converted);
        }
        self.inner.report(activity)
    }
}

fn proposal_info(p: &Proposal<Digest>) -> ProposalInfo {
    ProposalInfo {
        epoch: p.round.epoch().get(),
        view: p.round.view().get(),
        parent_view: p.parent.get(),
        parent_payload: Digest::from([0u8; 32]),
        payload: p.payload,
    }
}

fn certificate_signers() -> Vec<u32> {
    Vec::new()
}

fn convert_activity(activity: &hellas_types::Activity) -> Option<ConsensusActivity> {
    match activity {
        SimplexActivity::Notarize(n) => Some(ConsensusActivity::Notarize {
            proposal: proposal_info(&n.proposal),
            signer: n.attestation.signer.get(),
            signature: n.attestation.signature.encode().to_vec(),
        }),
        SimplexActivity::Notarization(n) | SimplexActivity::Certification(n) => {
            Some(ConsensusActivity::Notarization {
                proposal: proposal_info(&n.proposal),
                signers: certificate_signers(),
                certificate: n.certificate.encode().to_vec(),
            })
        }
        SimplexActivity::Nullify(n) => Some(ConsensusActivity::Nullify {
            epoch: n.round.epoch().get(),
            view: n.round.view().get(),
            signer: n.attestation.signer.get(),
            signature: n.attestation.signature.encode().to_vec(),
        }),
        SimplexActivity::Nullification(n) => Some(ConsensusActivity::Nullification {
            epoch: n.round.epoch().get(),
            view: n.round.view().get(),
            signers: certificate_signers(),
            certificate: n.certificate.encode().to_vec(),
        }),
        SimplexActivity::Finalization(f) => Some(ConsensusActivity::Finalization {
            proposal: proposal_info(&f.proposal),
            signers: certificate_signers(),
            certificate: f.certificate.encode().to_vec(),
        }),
        SimplexActivity::ConflictingNotarize(_) => None,
        SimplexActivity::Finalize(_)
        | SimplexActivity::ConflictingFinalize(_)
        | SimplexActivity::NullifyFinalize(_) => None,
    }
}
