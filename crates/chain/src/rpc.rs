//! Local implementation of the light-client query interface.

use std::collections::{BTreeMap, BTreeSet, btree_map::Entry};

use crate::domain::{
    Coin, Object, ObjectId, ObjectKind, SettlementKey, Transaction, coin_object_id, edge_object_id,
    registry_chunk_object_id,
};
use crate::{
    app::{Mempool, MempoolEntry, RESPONSE_MEMPOOL_CAPACITY},
    execution::store::UtxoDatabase,
    indexer::ChainIndexer,
    light_client::{
        ConsensusInfo, EdgeLookup, EdgeRecord, EdgeState, FinalizedBlock, FinalizedBlockQuery,
        LatestBlock, LightClient, OwnerCoins, OwnerEdges, QueryError,
    },
    owner_index::{OwnerIndex, OwnerIndexError},
    work_view::{FinalizedWorkView, WorkChannelQuery, WorkChannelSnapshot},
};
use commonware_cryptography::sha256::Digest;
use hellas_kernel::{
    Batch as KernelBatch, BlockHash, BlockHeight, Coin as KernelCoin, CoinId,
    Context as KernelContext, Edge, EdgeId, InsertError, KernelResult, NetworkId,
    PaymentCloseResponse, RegistryChunk, RegistryChunkId, bond_lease_slots, check_response,
    pending_payment_close_slot,
};
use hellas_rpc::SubmitTxOutcome;
use hellas_rpc::observe::{LEVEL, TARGET, Timing};

/// In-process [`LightClient`] backed by the local application handle.
#[derive(Clone)]
pub struct LocalLightClient {
    databases: UtxoDatabase<commonware_runtime::tokio::Context>,
    owner_index: OwnerIndex,
    mempool: Mempool,
    chain_indexer: ChainIndexer,
    consensus_info: ConsensusInfo,
}

impl LocalLightClient {
    pub fn new(
        databases: UtxoDatabase<commonware_runtime::tokio::Context>,
        owner_index: OwnerIndex,
        mempool: Mempool,
        chain_indexer: ChainIndexer,
        consensus_info: ConsensusInfo,
    ) -> Self {
        Self {
            databases,
            owner_index,
            mempool,
            chain_indexer,
            consensus_info,
        }
    }

    async fn submit_general(&self, tx: Transaction) -> SubmitTxOutcome {
        let entry = MempoolEntry::new(tx);
        let mut mempool = self.mempool.inner.lock().await;
        if mempool
            .general
            .iter()
            .any(|resident| resident.digest == entry.digest)
        {
            return SubmitTxOutcome::Duplicate;
        }
        if mempool.general.len() >= crate::GENERAL_MEMPOOL_CAPACITY {
            return SubmitTxOutcome::Full;
        }
        mempool.general.push_back(entry);
        SubmitTxOutcome::Enqueued
    }

    async fn submit_response(
        &self,
        response: PaymentCloseResponse,
    ) -> Result<SubmitTxOutcome, QueryError> {
        let Some(network) = NetworkId::new(&self.consensus_info.network_id) else {
            return Err(QueryError::StateUnavailable(format!(
                "network id `{}` does not fit a kernel NetworkId",
                self.consensus_info.network_id
            )));
        };
        let transaction = Transaction::Kernel(hellas_kernel::Tx::move_action(
            hellas_kernel::Move::RespondPaymentClose(response),
        ));
        let incoming = MempoolEntry::new(transaction);
        let slot = (response.payment_edge(), response.start_id());

        // Hold one finalized reader across authentication, the resident sweep,
        // and insertion. An unauthenticated newcomer is checked before taking
        // the mempool lock, so it cannot make the node reverify residents.
        let reader = self.databases.read().await;
        let state_root = reader.root();
        let cursor = self.owner_index.cursor();
        if cursor.height == 0 {
            return Err(QueryError::StateUnavailable(
                "no finalized application state is available".to_string(),
            ));
        }
        if cursor.state_root != state_root {
            return Err(QueryError::StateUnavailable(
                "owner index and application state are not synchronized".to_string(),
            ));
        }
        if self
            .chain_indexer
            .get_finalization(cursor.payload)
            .await?
            .is_none()
        {
            return Err(QueryError::StateUnavailable(
                "owner index cursor finalization is unavailable".to_string(),
            ));
        }
        let Some(admission_height) = cursor.height.checked_add(1) else {
            return Err(QueryError::StateUnavailable(
                "finalized height has no successor for response admission".to_string(),
            ));
        };
        let context = KernelContext::with_fees(
            network,
            BlockHeight::new(admission_height),
            BlockHash::from_bytes(cursor.payload.0),
            crate::domain::KERNEL_FEES,
        );

        let mut batch = ResponseAdmissionBatch::default();
        let incoming_edge = response.payment_edge();
        match reader
            .get(&edge_object_id(incoming_edge))
            .await
            .map_err(|error| QueryError::StateUnavailable(format!("edge read failed: {error:?}")))?
        {
            Some(Object::Edge(edge)) => {
                batch.edges.insert(incoming_edge, edge);
            }
            Some(object) => {
                return Err(QueryError::WrongObjectKind {
                    expected: ObjectKind::Edge,
                    actual: object.kind(),
                });
            }
            None => {}
        }
        let incoming_pending = pending_payment_close_slot(network, incoming_edge);
        match reader
            .get(&registry_chunk_object_id(incoming_pending))
            .await
            .map_err(|error| {
                QueryError::StateUnavailable(format!("registry read failed: {error:?}"))
            })? {
            Some(Object::RegistryChunk(chunk)) => {
                batch.registry.insert(incoming_pending, chunk);
            }
            Some(object) => {
                return Err(QueryError::WrongObjectKind {
                    expected: ObjectKind::RegistryChunk,
                    actual: object.kind(),
                });
            }
            None => {}
        }

        let verifier = crate::execution::ChainVerifier::new();
        // `validation_ms`: the extracted response validator, the one §4
        // adds to a validator's RPC and its worker. Both an admitted and
        // a rejected response paid for it, so both are sampled — the
        // rejection is validation that ran, not validation that did not.
        let validated = Timing::start();
        let admissible = check_response(&response, context, &verifier, &batch).is_ok();
        if let Some(ms) = validated.ms() {
            tracing::event!(
                name: "validation_ms",
                target: TARGET,
                LEVEL,
                edge = ?incoming_edge,
                start_id = ?response.start_id(),
                admissible,
                ms,
            );
        }
        if !admissible {
            return Ok(SubmitTxOutcome::ValidationRejected);
        }

        // Serialize the sweep and insertion only after the newcomer has
        // authenticated. Residents are still judged against the same reader.
        let mut mempool = self.mempool.inner.lock().await;
        let residents: Vec<PaymentCloseResponse> = mempool
            .responses
            .values()
            .filter_map(|entry| payment_close_response(&entry.transaction).copied())
            .collect();
        for candidate in residents.iter() {
            let edge_id = candidate.payment_edge();
            if let Entry::Vacant(slot) = batch.edges.entry(edge_id) {
                match reader
                    .get(&edge_object_id(edge_id))
                    .await
                    .map_err(|error| {
                        QueryError::StateUnavailable(format!("edge read failed: {error:?}"))
                    })? {
                    Some(Object::Edge(edge)) => {
                        slot.insert(edge);
                    }
                    Some(object) => {
                        return Err(QueryError::WrongObjectKind {
                            expected: ObjectKind::Edge,
                            actual: object.kind(),
                        });
                    }
                    None => {}
                }
            }
            let pending_id = pending_payment_close_slot(network, edge_id);
            if let Entry::Vacant(slot) = batch.registry.entry(pending_id) {
                match reader
                    .get(&registry_chunk_object_id(pending_id))
                    .await
                    .map_err(|error| {
                        QueryError::StateUnavailable(format!("registry read failed: {error:?}"))
                    })? {
                    Some(Object::RegistryChunk(chunk)) => {
                        slot.insert(chunk);
                    }
                    Some(object) => {
                        return Err(QueryError::WrongObjectKind {
                            expected: ObjectKind::RegistryChunk,
                            actual: object.kind(),
                        });
                    }
                    None => {}
                }
            }
        }

        mempool.responses.retain(|_, resident| {
            payment_close_response(&resident.transaction).is_some_and(|resident_response| {
                check_response(resident_response, context, &verifier, &batch).is_ok()
            })
        });
        if mempool
            .responses
            .get(&slot)
            .is_some_and(|resident| resident.digest == incoming.digest)
        {
            return Ok(SubmitTxOutcome::Duplicate);
        }

        if mempool.responses.contains_key(&slot)
            || mempool.responses.len() >= RESPONSE_MEMPOOL_CAPACITY
        {
            return Ok(SubmitTxOutcome::Full);
        }
        mempool.responses.insert(slot, incoming);
        Ok(SubmitTxOutcome::Enqueued)
    }
}

fn payment_close_response(transaction: &Transaction) -> Option<&PaymentCloseResponse> {
    let Transaction::Kernel(hellas_kernel::Tx::Move {
        action: hellas_kernel::Move::RespondPaymentClose(response),
    }) = transaction
    else {
        return None;
    };
    Some(response)
}

#[derive(Default)]
struct ResponseAdmissionBatch {
    edges: BTreeMap<EdgeId, Edge>,
    registry: BTreeMap<RegistryChunkId, RegistryChunk>,
}

impl KernelBatch for ResponseAdmissionBatch {
    fn coin(&self, _id: CoinId) -> Option<KernelCoin> {
        None
    }
    fn insert_coin(&mut self, _id: CoinId, _coin: KernelCoin) -> KernelResult<(), InsertError> {
        Err(InsertError::Unavailable)
    }
    fn remove_coin(&mut self, _id: CoinId) -> Option<KernelCoin> {
        None
    }
    fn edge(&self, id: EdgeId) -> Option<Edge> {
        self.edges.get(&id).copied()
    }
    fn insert_edge(&mut self, _id: EdgeId, _edge: Edge) -> KernelResult<(), InsertError> {
        Err(InsertError::Unavailable)
    }
    fn remove_edge(&mut self, _id: EdgeId) -> Option<Edge> {
        None
    }
    fn registry_chunk(&self, id: RegistryChunkId) -> Option<RegistryChunk> {
        self.registry.get(&id).copied()
    }
    fn insert_registry_chunk(
        &mut self,
        _id: RegistryChunkId,
        _chunk: RegistryChunk,
    ) -> KernelResult<(), InsertError> {
        Err(InsertError::Unavailable)
    }
    fn remove_registry_chunk(&mut self, _id: RegistryChunkId) -> Option<RegistryChunk> {
        None
    }
    fn commit(self) {}
}

fn owner_lookup_error(error: OwnerIndexError) -> QueryError {
    match error {
        OwnerIndexError::WrongObjectKind {
            expected, actual, ..
        } => QueryError::WrongObjectKind { expected, actual },
        error => QueryError::StateUnavailable(format!("owner index lookup failed: {error}")),
    }
}

async fn finalized_floor_height(
    chain_indexer: &ChainIndexer,
    payload: Digest,
) -> Result<u64, QueryError> {
    let Some(finalized) = chain_indexer
        .get_finalized_block(FinalizedBlockQuery::Payload(payload))
        .await?
    else {
        return Err(QueryError::StateUnavailable(
            "requested payload is not finalized".to_string(),
        ));
    };
    Ok(finalized.snapshot.height)
}

fn require_finalized_floor(floor_height: u64, cursor_height: u64) -> Result<(), QueryError> {
    if floor_height > cursor_height {
        return Err(QueryError::StateUnavailable(
            "requested payload is newer than the application state".to_string(),
        ));
    }
    Ok(())
}

async fn get_edge_at(
    databases: &UtxoDatabase<commonware_runtime::tokio::Context>,
    owner_index: &OwnerIndex,
    chain_indexer: &ChainIndexer,
    payload: Digest,
    object_id: ObjectId,
) -> Result<Option<EdgeLookup>, QueryError> {
    let cursor = owner_index.cursor();
    if cursor.height == 0 {
        return Ok(None);
    }
    let floor_height = finalized_floor_height(chain_indexer, payload).await?;

    let reader = databases.read().await;
    let state_root = reader.root();
    let cursor = owner_index.cursor();
    require_finalized_floor(floor_height, cursor.height)?;
    if cursor.state_root != state_root {
        return Err(QueryError::StateUnavailable(
            "owner index and application state are not synchronized".to_string(),
        ));
    }
    let edge = match reader
        .get(&object_id)
        .await
        .map_err(|error| QueryError::StateUnavailable(format!("edge read failed: {error:?}")))?
    {
        Some(Object::Edge(edge)) => Some(EdgeState::from(edge)),
        Some(object) => {
            return Err(QueryError::WrongObjectKind {
                expected: ObjectKind::Edge,
                actual: object.kind(),
            });
        }
        None => None,
    };
    Ok(Some(EdgeLookup { state_root, edge }))
}

async fn get_coin_at(
    owner_index: &OwnerIndex,
    chain_indexer: &ChainIndexer,
    payload: Digest,
    object_id: ObjectId,
) -> Result<Option<Coin>, QueryError> {
    let (cursor, coin) = owner_index.get_coin_snapshot(&object_id);
    if cursor.height == 0 {
        return Ok(None);
    }
    let floor_height = finalized_floor_height(chain_indexer, payload).await?;
    require_finalized_floor(floor_height, cursor.height)?;
    coin.map_err(owner_lookup_error)
}

/// Reads every object of one work channel under one database snapshot.
///
/// The reader is taken once and every object comes out of it, which is
/// the whole point: separate `get` calls would answer from up to as many
/// states, and the combinations that produces read as healthy channels
/// that never existed.
///
/// The queried funding coins come out of that same reader, not out of
/// the owner index and not out of a second call. A setup decision locks
/// a provider's stake on the premise that the client's funding is still
/// live, and a coin read at any other state is a premise about a state
/// the decision is not being made at.
///
/// The state the reader holds is the state the owner index has applied
/// up to, so the finalized block reported beside the objects is that
/// index's cursor. If the two have drifted apart between the two reads
/// the whole snapshot is refused rather than reported at a block it was
/// not read at.
async fn work_channel_snapshot_at(
    databases: &UtxoDatabase<commonware_runtime::tokio::Context>,
    owner_index: &OwnerIndex,
    chain_indexer: &ChainIndexer,
    network: NetworkId,
    query: WorkChannelQuery,
) -> Result<Option<WorkChannelSnapshot>, QueryError> {
    let reader = databases.read().await;
    let state_root = reader.root();
    // Read after the reader is held: a cursor sampled before it says
    // nothing about the state the objects will come out of.
    let cursor = owner_index.cursor();
    if cursor.height == 0 {
        return Ok(None);
    }
    if cursor.state_root != state_root {
        return Err(QueryError::StateUnavailable(
            "owner index and application state are not synchronized".to_string(),
        ));
    }
    let Some(finalization) = chain_indexer.get_finalization(cursor.payload).await? else {
        return Err(QueryError::StateUnavailable(
            "owner index cursor finalization is unavailable".to_string(),
        ));
    };

    let mut bond = None;
    let mut payment = None;
    for (slot, edge) in [
        (&mut bond, query.bond_edge),
        (&mut payment, query.payment_edge),
    ] {
        *slot =
            match reader.get(&edge_object_id(edge)).await.map_err(|error| {
                QueryError::StateUnavailable(format!("edge read failed: {error:?}"))
            })? {
                Some(Object::Edge(edge)) => Some(edge),
                Some(object) => {
                    return Err(QueryError::WrongObjectKind {
                        expected: ObjectKind::Edge,
                        actual: object.kind(),
                    });
                }
                None => None,
            };
    }

    let [first_lease, second_lease] = bond_lease_slots(network, query.bond_edge);
    let mut registry = [None, None, None];
    for (stored, id) in registry.iter_mut().zip([
        first_lease,
        second_lease,
        pending_payment_close_slot(network, query.payment_edge),
    ]) {
        *stored = match reader
            .get(&registry_chunk_object_id(id))
            .await
            .map_err(|error| {
                QueryError::StateUnavailable(format!("registry read failed: {error:?}"))
            })? {
            Some(Object::RegistryChunk(chunk)) => Some(chunk),
            Some(object) => {
                return Err(QueryError::WrongObjectKind {
                    expected: ObjectKind::RegistryChunk,
                    actual: object.kind(),
                });
            }
            None => None,
        };
    }
    let [lease_first, lease_second, pending_slot] = registry;

    let mut live_funding = BTreeSet::new();
    for coin in &query.funding {
        match reader
            .get(&coin_object_id(*coin))
            .await
            .map_err(|error| QueryError::StateUnavailable(format!("coin read failed: {error:?}")))?
        {
            Some(Object::Coin(_)) => {
                live_funding.insert(*coin);
            }
            // A spent coin is absent, and that is the answer the
            // preflight wants. An object of another kind under a coin's
            // derived id is not an answer at all.
            None => {}
            Some(object) => {
                return Err(QueryError::WrongObjectKind {
                    expected: ObjectKind::Coin,
                    actual: object.kind(),
                });
            }
        }
    }

    Ok(Some(WorkChannelSnapshot::new(
        query,
        LatestBlock {
            height: cursor.height,
            payload: cursor.payload,
            state_root,
            finalization,
        },
        bond,
        payment,
        [lease_first, lease_second],
        pending_slot,
        live_funding,
    )))
}

impl FinalizedWorkView for LocalLightClient {
    async fn work_channel_snapshot(
        &self,
        query: WorkChannelQuery,
    ) -> Result<Option<WorkChannelSnapshot>, QueryError> {
        // The registry slots are keyed by network, so a node whose
        // genesis names an id the kernel cannot carry cannot derive
        // them. Answering with slots derived from some other id would
        // be answering about a different chain's channel.
        let Some(network) = NetworkId::new(&self.consensus_info.network_id) else {
            return Err(QueryError::StateUnavailable(format!(
                "network id `{}` does not fit a kernel NetworkId",
                self.consensus_info.network_id
            )));
        };
        work_channel_snapshot_at(
            &self.databases,
            &self.owner_index,
            &self.chain_indexer,
            network,
            query,
        )
        .await
    }
}

impl LightClient for LocalLightClient {
    async fn get_state_root(&self) -> Result<Option<Digest>, QueryError> {
        Ok(Some(self.databases.read().await.root()))
    }

    async fn get_proof(&self, object_id: ObjectId) -> Result<Option<Vec<u8>>, QueryError> {
        let _ = object_id;
        Err(QueryError::StateUnavailable(
            "key proofs are not available".to_string(),
        ))
    }

    async fn get_coin(
        &self,
        payload: Digest,
        object_id: ObjectId,
    ) -> Result<Option<Coin>, QueryError> {
        get_coin_at(&self.owner_index, &self.chain_indexer, payload, object_id).await
    }

    async fn get_edge(
        &self,
        payload: Digest,
        object_id: ObjectId,
    ) -> Result<Option<EdgeLookup>, QueryError> {
        get_edge_at(
            &self.databases,
            &self.owner_index,
            &self.chain_indexer,
            payload,
            object_id,
        )
        .await
    }

    async fn get_finalization(&self, payload: Digest) -> Result<Option<Vec<u8>>, QueryError> {
        self.chain_indexer.get_finalization(payload).await
    }

    async fn get_latest_block(&self) -> Result<Option<LatestBlock>, QueryError> {
        self.chain_indexer.get_latest_block().await
    }

    async fn get_finalized_block(
        &self,
        query: FinalizedBlockQuery,
    ) -> Result<Option<FinalizedBlock>, QueryError> {
        self.chain_indexer.get_finalized_block(query).await
    }

    async fn submit_tx(&self, tx: Transaction) -> Result<SubmitTxOutcome, QueryError> {
        if crate::light_client::canonical_submission_size(&tx)
            > crate::MAX_CANONICAL_TRANSACTION_BYTES
        {
            return Err(QueryError::InvalidTransaction(format!(
                "canonical transaction exceeds {} bytes",
                crate::MAX_CANONICAL_TRANSACTION_BYTES,
            )));
        }
        if let Some(response) = payment_close_response(&tx).copied() {
            self.submit_response(response).await
        } else {
            Ok(self.submit_general(tx).await)
        }
    }

    async fn get_validators(&self) -> Result<Vec<String>, QueryError> {
        Ok(self.consensus_info.validators.clone())
    }

    async fn get_consensus_info(&self) -> Result<ConsensusInfo, QueryError> {
        Ok(self.consensus_info.clone())
    }

    async fn get_coins_by_owner(
        &self,
        owner: SettlementKey,
    ) -> Result<Option<OwnerCoins>, QueryError> {
        let (cursor, coins) = self.owner_index.get_coins_by_owner_snapshot(&owner);
        if cursor.height == 0 {
            return Ok(None);
        }
        let Some(finalization) = self.chain_indexer.get_finalization(cursor.payload).await? else {
            return Err(QueryError::StateUnavailable(
                "owner index cursor finalization is unavailable".to_string(),
            ));
        };
        Ok(Some(OwnerCoins {
            snapshot: LatestBlock {
                height: cursor.height,
                payload: cursor.payload,
                state_root: cursor.state_root,
                finalization,
            },
            coins,
        }))
    }

    async fn get_edges_by_owner(
        &self,
        owner: SettlementKey,
    ) -> Result<Option<OwnerEdges>, QueryError> {
        let (cursor, edges) = self.owner_index.get_edges_by_owner_snapshot(&owner);
        if cursor.height == 0 {
            return Ok(None);
        }
        let Some(finalization) = self.chain_indexer.get_finalization(cursor.payload).await? else {
            return Err(QueryError::StateUnavailable(
                "owner index cursor finalization is unavailable".to_string(),
            ));
        };
        Ok(Some(OwnerEdges {
            snapshot: LatestBlock {
                height: cursor.height,
                payload: cursor.payload,
                state_root: cursor.state_root,
                finalization,
            },
            edges: edges
                .into_iter()
                .map(|(object_id, edge)| EdgeRecord {
                    object_id,
                    maker: edge.maker,
                    taker: edge.taker,
                })
                .collect(),
        }))
    }
}

#[cfg(test)]
mod tests;
