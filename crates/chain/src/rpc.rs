//! Local implementation of the light-client query interface.

use std::collections::BTreeSet;

use crate::domain::{
    Coin, Object, ObjectId, ObjectKind, SettlementKey, Transaction, coin_object_id, edge_object_id,
    registry_chunk_object_id,
};
use crate::{
    app::Mempool,
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
use hellas_kernel::{NetworkId, bond_lease_slots, pending_payment_close_slot};

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

    async fn submit_tx(&self, tx: Transaction) -> Result<(), QueryError> {
        self.mempool.submit(tx).await;
        Ok(())
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
mod tests {
    use super::*;
    use crate::{
        config::Config,
        domain::{KERNEL_FEES, ObjectKind, Transaction, edge_object_id, genesis_object_id},
        execution::{
            ChainVerifier, execute_all,
            store::utxo_db_config,
            test_support::{
                consensus_fixture, finalization, index_block, index_genesis, kernel_fixture,
                legacy_address, run_qmdb,
            },
        },
        indexer::spawn_follower_indexer,
        owner_index::ApplyOutcome,
    };
    use commonware_cryptography::Digestible as _;
    use commonware_glue::stateful::db::{DatabaseSet, Merkleized as _, Unmerkleized as _};
    use commonware_runtime::{Handle, Supervisor as _};
    use hellas_kernel::{BlockHash, BlockHeight, Context as KernelContext};

    async fn finalized_payload_indexer(
        context: commonware_runtime::tokio::Context,
        genesis: crate::HellasBlock,
        finalized: crate::HellasBlock,
    ) -> (ChainIndexer, Handle<()>) {
        let fixture = consensus_fixture(91);
        let config = Config {
            mailbox_size: 32,
            replay_buffer: 32,
            write_buffer: 32,
            page_cache_size: 1024,
            page_cache_count: 8,
            ..Config::default()
        };
        let (indexer, handle) = spawn_follower_indexer(
            context,
            "rpc_finalized_floor",
            config,
            fixture.verifier.clone(),
            genesis,
        )
        .await
        .expect("chain indexer");
        indexer
            .ingest_finalized(finalized.clone(), finalization(&fixture, &finalized))
            .await
            .expect("finalized floor ingest");
        (indexer, handle)
    }

    #[test]
    fn owner_index_wrong_kind_maps_structurally() {
        let id = ObjectId::from([0x42; 32]);
        let error = owner_lookup_error(OwnerIndexError::WrongObjectKind {
            id,
            expected: ObjectKind::Coin,
            actual: ObjectKind::Edge,
        });
        assert!(matches!(
            error,
            QueryError::WrongObjectKind {
                expected: ObjectKind::Coin,
                actual: ObjectKind::Edge,
            }
        ));
    }

    /// One work channel, opened for real, read back as one answer.
    ///
    /// Everything here comes from one QMDB reader at one finalized
    /// block: both edges, both lease slots, and the pending-close slot.
    /// The lease is `Present` because a payment open wrote it, not
    /// because this test wrote a chunk that looks like one — which is
    /// the only way to find out that the endpoint derives the same slots
    /// the kernel does.
    #[test]
    fn work_channel_snapshot_reads_every_object_at_one_finalized_block() {
        use hellas_kernel::{
            Auth, BlockHeight, CoinId, Funding, LeaseSlots, List, MAX_EDGE_OUTPUTS,
            MAX_PARTY_INPUTS, Parties, Payout, PendingSlot, Secp256k1Signer, Terms as KernelTerms,
            Tx as KernelTx, WorkPaymentTerms, WorkStakeBondTerms,
        };

        const FUNDING: u64 = 100;
        const STAKE: u64 = 12;
        const HORIZON: u64 = 500;

        let network = crate::domain::TEST_NETWORK;
        let Ok(client) = Secp256k1Signer::from_secret_scalar([0x21; 32]) else {
            panic!("client key");
        };
        let Ok(provider) = Secp256k1Signer::from_secret_scalar([0x22; 32]) else {
            panic!("provider key");
        };
        let client_key = client.party_key();
        let provider_key = provider.party_key();

        let bond = WorkStakeBondTerms {
            parties: Parties::new(provider_key, client_key),
            timeout: BlockHeight::new(HORIZON),
            timeout_outputs: List::take([Payout::new(provider_key, STAKE); MAX_EDGE_OUTPUTS], 1),
            max_job_price: 4,
        };
        let bond_terms = KernelTerms::work_stake_bond(bond.clone());
        let bond_funding = Funding::new(
            List::take(
                [CoinId::from_bytes(genesis_object_id(1).into()); MAX_PARTY_INPUTS],
                1,
            ),
            List::take(
                [CoinId::from_bytes([0; CoinId::LENGTH]); MAX_PARTY_INPUTS],
                0,
            ),
        );
        let bond_edge = KernelTx::edge_id_of(&bond_funding, &bond_terms);
        let bond_open_hash = KernelTx::open_hash(network, &bond_funding, &bond_terms);
        let bond_open = KernelTx::open(
            bond_funding,
            bond_terms,
            Auth::native(provider.sign(bond_open_hash)),
            Auth::native(client.sign(bond_open_hash)),
        );

        let payment_terms = KernelTerms::work_payment(WorkPaymentTerms {
            bond_edge,
            bond_terms: bond,
            private_policy_commitment: [0x25; 32],
            omit_response_blocks: hellas_kernel::MIN_OMIT_RESPONSE_BLOCKS,
            start_validity_blocks: 8,
            omission_bond: 2,
        });
        let payment_funding = Funding::new(
            List::take(
                [CoinId::from_bytes(genesis_object_id(0).into()); MAX_PARTY_INPUTS],
                1,
            ),
            List::take(
                [CoinId::from_bytes([0; CoinId::LENGTH]); MAX_PARTY_INPUTS],
                0,
            ),
        );
        let payment_edge = KernelTx::edge_id_of(&payment_funding, &payment_terms);
        let payment_open_hash = KernelTx::open_hash(network, &payment_funding, &payment_terms);
        let payment_open = KernelTx::open(
            payment_funding,
            payment_terms,
            Auth::native(client.sign(payment_open_hash)),
            Auth::native(provider.sign(payment_open_hash)),
        );

        // The two coins the opens spend, and one the fixture leaves
        // alone. After both opens are applied the first two are gone and
        // the third is not, which is the whole of what a setup preflight
        // asks.
        let spent_by_bond = CoinId::from_bytes(genesis_object_id(1).into());
        let spent_by_payment = CoinId::from_bytes(genesis_object_id(0).into());
        let untouched = CoinId::from_bytes(genesis_object_id(2).into());
        let funding: BTreeSet<CoinId> = [spent_by_bond, spent_by_payment, untouched]
            .into_iter()
            .collect();
        let query = WorkChannelQuery {
            bond_edge,
            payment_edge,
            funding: funding.clone(),
        };

        run_qmdb(|runtime| async move {
            let indexer_context = runtime.child("chain_indexer");
            let config = utxo_db_config(&runtime, "rpc_work_snapshot", 1024, 8);
            let database = <UtxoDatabase<_> as DatabaseSet<_>>::init(runtime, config).await;
            let allocations = vec![
                (SettlementKey::from(client_key), FUNDING),
                (SettlementKey::from(provider_key), STAKE),
                // A third allocation, left unspent: the wrong-kind case
                // below needs a coin that still exists after both opens
                // have consumed the first two.
                (SettlementKey::from(legacy_address(41)), 7),
            ];
            let genesis = index_genesis();

            // Block one: the genesis allocations alone.
            let floor_root = apply(&database, &allocations, 1, &[]).await;
            let floor_block = index_block(&genesis, floor_root, Vec::new());

            // Block two: the two opens, in the order setup requires.
            let transactions = vec![
                Transaction::Kernel(bond_open),
                Transaction::Kernel(payment_open),
            ];
            let open_root = apply(&database, &allocations, 2, &transactions).await;
            let open_block = index_block(&floor_block, open_root, transactions);

            let fixture = consensus_fixture(93);
            let (chain_indexer, _handle) = spawn_follower_indexer(
                indexer_context,
                "rpc_work_snapshot",
                Config {
                    mailbox_size: 32,
                    replay_buffer: 32,
                    write_buffer: 32,
                    page_cache_size: 1024,
                    page_cache_count: 8,
                    ..Config::default()
                },
                fixture.verifier.clone(),
                genesis.clone(),
            )
            .await
            .expect("chain indexer");
            for block in [&floor_block, &open_block] {
                chain_indexer
                    .ingest_finalized(block.clone(), finalization(&fixture, block))
                    .await
                    .expect("finalized ingest");
            }

            let behind_allocations = allocations.clone();
            let index = OwnerIndex::new(network, &genesis, allocations);

            // Before either block is applied there is no finalized state
            // to answer from, which is not the same fact as "this is not
            // a channel".
            assert!(matches!(
                work_channel_snapshot_at(&database, &index, &chain_indexer, network, query.clone())
                    .await,
                Ok(None),
            ));

            assert_eq!(
                index.apply_finalized(&floor_block),
                Ok(ApplyOutcome::Applied)
            );
            assert_eq!(
                index.apply_finalized(&open_block),
                Ok(ApplyOutcome::Applied)
            );

            let snapshot =
                work_channel_snapshot_at(&database, &index, &chain_indexer, network, query.clone())
                    .await
                    .expect("work channel snapshot")
                    .expect("finalized state is available");

            assert_eq!(snapshot.query(), &query);
            assert_eq!(
                snapshot.block().height,
                commonware_consensus::Heightable::height(&open_block).get()
            );
            assert_eq!(snapshot.block().state_root, open_root);
            assert_eq!(snapshot.block().payload, open_block.digest());
            assert_eq!(snapshot.block().state_root, database.read().await.root());

            let bond_state = snapshot.bond().expect("the bond edge is live");
            assert_eq!(bond_state.value(), STAKE);
            let payment_state = snapshot.payment().expect("the payment edge is live");
            assert_eq!(payment_state.value(), FUNDING);

            // The lease the payment open wrote, read out of the slots
            // the kernel derives.
            let LeaseSlots::Present(lease) = snapshot.lease() else {
                panic!("an open payment channel holds its bond's lease");
            };
            assert_eq!(lease.bond_edge(), bond_edge);
            assert_eq!(lease.payment_edge(), payment_edge);
            assert_eq!(lease.admission_horizon(), HORIZON);
            assert_eq!(snapshot.pending(), PendingSlot::Absent);

            // The coin answer, at the same block and out of the same
            // reader. Both opens have executed, so the two coins they
            // funded are gone and the third is not — and the reply is
            // the survivors, not the question.
            let live: BTreeSet<CoinId> = [untouched].into_iter().collect();
            assert_eq!(snapshot.live_funding(), &live);
            assert_eq!(snapshot.live_funding_of(&funding), Some(&live));
            // A snapshot is an answer about the coins its own query
            // named. Asked about any other set it says so rather than
            // reporting a subset of a different question.
            assert_eq!(
                snapshot.live_funding_of(&[spent_by_bond].into_iter().collect()),
                None,
            );

            // The same answer, through the wire, byte for byte. The
            // response carries canonical kernel objects, so what comes
            // back is the object consensus stored and not a re-spelling
            // of its fields — and a re-spelling is exactly what the
            // equality below would not catch if the wire carried one.
            let encoded = crate::server::work_channel_snapshot_response(Some(snapshot.clone()));
            assert_eq!(
                crate::client::work_channel_snapshot_from_proto(
                    query.clone(),
                    encoded.clone(),
                    None
                )
                .expect("the wire carries a decodable snapshot"),
                Some(snapshot.clone()),
            );

            // One lease slot dropped. Reading its absence as an empty
            // slot would report a live lease as absent, so the count is
            // exact rather than padded.
            let mut short = encoded.clone();
            short.lease_slots.truncate(1);
            assert!(matches!(
                crate::client::work_channel_snapshot_from_proto(query.clone(), short, None),
                Err(QueryError::Remote(_)),
            ));

            // One lease slot's bytes truncated. A chunk that does not
            // decode is not an empty slot either.
            let mut corrupt = encoded.clone();
            if let Some(slot) = corrupt.lease_slots.first_mut()
                && let Some(chunk) = slot.chunk.as_mut()
            {
                chunk.pop();
            }
            assert!(matches!(
                crate::client::work_channel_snapshot_from_proto(query.clone(), corrupt, None),
                Err(QueryError::Remote(_)),
            ));

            // The pending-close slot message dropped. An empty slot is a
            // permission — it is what says no contest is open and new
            // work may be admitted — so an omitted field must not be
            // read as one.
            let mut silent = encoded.clone();
            silent.pending_slot = None;
            assert!(matches!(
                crate::client::work_channel_snapshot_from_proto(query.clone(), silent, None),
                Err(QueryError::Remote(_)),
            ));

            // A coin reported live that the query never named. Nothing
            // in an unrequested coin id could have been checked, and a
            // decision would read it as this transaction's funding, so
            // the reply is refused rather than trimmed.
            let mut invented = encoded.clone();
            invented.live_funding.push(
                CoinId::from_bytes([0xc0; CoinId::LENGTH])
                    .to_bytes()
                    .to_vec(),
            );
            assert!(matches!(
                crate::client::work_channel_snapshot_from_proto(query.clone(), invented, None),
                Err(QueryError::Remote(_)),
            ));

            // A coin the query named and the reply leaves out is not
            // refused: that omission is exactly how a spent coin is
            // reported, and refusing it would make every real
            // preflight failure unreadable.
            let mut spent = encoded;
            spent.live_funding.clear();
            let Ok(Some(reported)) =
                crate::client::work_channel_snapshot_from_proto(query.clone(), spent, None)
            else {
                panic!("an empty live set is an answer");
            };
            assert!(reported.live_funding().is_empty());

            // An index one block behind the database it is reporting
            // for. Its cursor block is finalized and its finalization
            // is available, so nothing but the root disagrees — and a
            // snapshot reported at that cursor would carry objects read
            // from a state the cursor never named.
            let behind = OwnerIndex::new(network, &genesis, behind_allocations);
            assert_eq!(
                behind.apply_finalized(&floor_block),
                Ok(ApplyOutcome::Applied)
            );
            assert_ne!(behind.cursor().state_root, database.read().await.root());
            assert!(
                chain_indexer
                    .get_finalization(behind.cursor().payload)
                    .await
                    .expect("finalization query")
                    .is_some(),
                "the behind cursor's own block is finalized, so only the root disagrees",
            );
            assert!(matches!(
                work_channel_snapshot_at(
                    &database,
                    &behind,
                    &chain_indexer,
                    network,
                    query.clone()
                )
                .await,
                Err(QueryError::StateUnavailable(_)),
            ));

            // A channel naming a bond nobody opened is absent, not
            // faulty, and its edges are absent too.
            let absent = work_channel_snapshot_at(
                &database,
                &index,
                &chain_indexer,
                network,
                WorkChannelQuery {
                    bond_edge: hellas_kernel::EdgeId::from_bytes([0xa7; 32]),
                    payment_edge: hellas_kernel::EdgeId::from_bytes([0xa8; 32]),
                    funding: [CoinId::from_bytes([0xa9; CoinId::LENGTH])]
                        .into_iter()
                        .collect(),
                },
            )
            .await
            .expect("absent channel snapshot")
            .expect("finalized state is available");
            assert!(absent.bond().is_none());
            assert!(absent.payment().is_none());
            assert_eq!(absent.lease(), LeaseSlots::Absent);
            assert_eq!(absent.pending(), PendingSlot::Absent);
            assert!(
                absent.live_funding().is_empty(),
                "a coin nobody minted is not live",
            );

            // A live edge named as a funding coin is a typed refusal
            // too. Coin, edge, and chunk ids share one address space, so
            // the kind of the object found is the only thing that says
            // the question was answered.
            assert!(matches!(
                work_channel_snapshot_at(
                    &database,
                    &index,
                    &chain_indexer,
                    network,
                    WorkChannelQuery {
                        bond_edge,
                        payment_edge,
                        funding: [CoinId::from_bytes(payment_edge.to_bytes())]
                            .into_iter()
                            .collect(),
                    },
                )
                .await,
                Err(QueryError::WrongObjectKind {
                    expected: ObjectKind::Coin,
                    actual: ObjectKind::Edge,
                }),
            ));

            // A coin where an edge was asked for is a typed refusal, not
            // an absent edge.
            assert!(matches!(
                work_channel_snapshot_at(
                    &database,
                    &index,
                    &chain_indexer,
                    network,
                    WorkChannelQuery {
                        bond_edge: hellas_kernel::EdgeId::from_bytes(genesis_object_id(2).into()),
                        payment_edge,
                        funding: BTreeSet::new(),
                    },
                )
                .await,
                Err(QueryError::WrongObjectKind {
                    expected: ObjectKind::Edge,
                    actual: ObjectKind::Coin,
                }),
            ));
        });
    }

    /// Executes one block's transactions and finalizes the result,
    /// returning the state root they produce.
    async fn apply(
        database: &UtxoDatabase<commonware_runtime::tokio::Context>,
        allocations: &[(SettlementKey, u64)],
        height: u64,
        transactions: &[Transaction],
    ) -> Digest {
        let batches = database.new_batches().await;
        let batches = execute_all(
            KernelContext::with_fees(
                crate::domain::TEST_NETWORK,
                BlockHeight::new(height),
                BlockHash::from_bytes([0; BlockHash::LENGTH]),
                KERNEL_FEES,
            ),
            &ChainVerifier::new(),
            transactions,
            allocations,
            batches,
        )
        .await
        .expect("block executes");
        let merkleized = batches.merkleize().await.expect("state merkleizes");
        let root = merkleized.root();
        database.finalize(merkleized).await;
        root
    }

    #[test]
    fn get_edge_reads_qmdb_with_served_root_and_typed_kind() {
        run_qmdb(|runtime| async move {
            let indexer_context = runtime.child("chain_indexer");
            let config = utxo_db_config(&runtime, "rpc_get_edge", 1024, 8);
            let database = <UtxoDatabase<_> as DatabaseSet<_>>::init(runtime, config).await;
            let fixture = kernel_fixture(3).expect("kernel fixture");
            let mut allocations = fixture.allocations.clone();
            allocations.push((SettlementKey::from(legacy_address(41)), 7));
            let genesis = index_genesis();

            let batches = database.new_batches().await;
            let batches = execute_all(
                KernelContext::with_fees(
                    crate::domain::TEST_NETWORK,
                    BlockHeight::new(1),
                    BlockHash::from_bytes([0; BlockHash::LENGTH]),
                    KERNEL_FEES,
                ),
                &ChainVerifier::new(),
                &[],
                &allocations,
                batches,
            )
            .await
            .expect("genesis allocations execute");
            let merkleized = batches.merkleize().await.expect("genesis merkleizes");
            let floor_root = merkleized.root();
            database.finalize(merkleized).await;

            let floor_block = index_block(&genesis, floor_root, Vec::new());
            let (chain_indexer, _indexer_handle) =
                finalized_payload_indexer(indexer_context, genesis.clone(), floor_block.clone())
                    .await;
            let latest = chain_indexer
                .get_latest_block()
                .await
                .expect("latest block query")
                .expect("finalized floor");
            assert_eq!(latest.payload, floor_block.digest());
            let finalized_payload = latest.payload;
            let uninitialized_index =
                OwnerIndex::new(crate::domain::TEST_NETWORK, &genesis, allocations.clone());
            assert!(matches!(
                get_edge_at(
                    &database,
                    &uninitialized_index,
                    &chain_indexer,
                    Digest::from([0x10; 32]),
                    ObjectId::from([0x20; 32]),
                )
                .await,
                Ok(None)
            ));

            let transactions = vec![Transaction::Kernel(fixture.open.clone())];
            let batches = database.new_batches().await;
            let batches = execute_all(
                KernelContext::with_fees(
                    crate::domain::TEST_NETWORK,
                    BlockHeight::new(2),
                    BlockHash::from_bytes([0; BlockHash::LENGTH]),
                    KERNEL_FEES,
                ),
                &ChainVerifier::new(),
                &transactions,
                &allocations,
                batches,
            )
            .await
            .expect("open executes");
            let merkleized = batches.merkleize().await.expect("state merkleizes");
            let state_root = merkleized.root();
            database.finalize(merkleized).await;

            let index = OwnerIndex::new(crate::domain::TEST_NETWORK, &genesis, allocations.clone());
            assert_eq!(
                index.apply_finalized(&floor_block),
                Ok(ApplyOutcome::Applied)
            );
            let block = index_block(&floor_block, state_root, transactions.clone());
            assert_eq!(index.apply_finalized(&block), Ok(ApplyOutcome::Applied));
            assert_ne!(index.cursor().payload, finalized_payload);
            let edge_id = edge_object_id(fixture.edge);
            let expected_edge = match database
                .read()
                .await
                .get(&edge_id)
                .await
                .expect("edge read")
            {
                Some(Object::Edge(edge)) => EdgeState::from(edge),
                other => panic!("expected stored edge, found {other:?}"),
            };

            let found = get_edge_at(
                &database,
                &index,
                &chain_indexer,
                finalized_payload,
                edge_id,
            )
            .await
            .expect("edge lookup")
            .expect("indexed state is available");
            assert_eq!(found.state_root, state_root);
            assert_eq!(found.edge, Some(expected_edge));

            let absent = get_edge_at(
                &database,
                &index,
                &chain_indexer,
                finalized_payload,
                ObjectId::from([0xa5; 32]),
            )
            .await
            .expect("absent edge lookup")
            .expect("indexed state is available");
            assert_eq!(absent.state_root, state_root);
            assert_eq!(absent.edge, None);

            assert!(matches!(
                get_edge_at(
                    &database,
                    &index,
                    &chain_indexer,
                    Digest::from([0x44; 32]),
                    edge_id,
                )
                .await,
                Err(QueryError::StateUnavailable(_))
            ));

            assert!(matches!(
                get_edge_at(
                    &database,
                    &index,
                    &chain_indexer,
                    finalized_payload,
                    genesis_object_id(2),
                )
                .await,
                Err(QueryError::WrongObjectKind {
                    expected: ObjectKind::Edge,
                    actual: ObjectKind::Coin,
                })
            ));

            assert!(
                get_coin_at(
                    &index,
                    &chain_indexer,
                    finalized_payload,
                    genesis_object_id(2),
                )
                .await
                .expect("finalized coin floor")
                .is_some()
            );
            assert!(matches!(
                get_coin_at(
                    &index,
                    &chain_indexer,
                    Digest::from([0x44; 32]),
                    genesis_object_id(2),
                )
                .await,
                Err(QueryError::StateUnavailable(_))
            ));

            let skewed_index = OwnerIndex::new(crate::domain::TEST_NETWORK, &genesis, allocations);
            assert_eq!(
                skewed_index.apply_finalized(&floor_block),
                Ok(ApplyOutcome::Applied)
            );
            let skewed_block = index_block(&floor_block, Digest::from([0x55; 32]), transactions);
            assert_eq!(
                skewed_index.apply_finalized(&skewed_block),
                Ok(ApplyOutcome::Applied)
            );
            assert!(matches!(
                get_edge_at(
                    &database,
                    &skewed_index,
                    &chain_indexer,
                    finalized_payload,
                    ObjectId::from([0xa6; 32]),
                )
                .await,
                Err(QueryError::StateUnavailable(_))
            ));
            let qmdb_root = database.read().await.root();
            assert_ne!(skewed_index.cursor().state_root, qmdb_root);
        });
    }
}
