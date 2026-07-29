use super::{store::UtxoDatabase, verifier::StakedOpenPolicy, working_set::BlockWorkingSet};
use crate::domain::{
    Address, Coin, MAX_STAKED_LIFETIME_BLOCKS, Object, ObjectId, ObjectKind, SettlementKey,
    Transaction, coin_object_id, edge_object_id, genesis_object_id, output_object_id,
};
use commonware_codec::{Encode, EncodeSize};
use commonware_cryptography::{Hasher, Sha256};
use commonware_glue::stateful::db::DatabaseSet;
use commonware_runtime::{Clock, Metrics, Storage};
use hellas_kernel::{
    ApplyError, Coin as KernelCoin, CoinId, Context as KernelContext, EdgeId, Event, EventKind,
    InvalidProofReason, SealVerifier, SigVerifier, State, Tx as KernelTx,
};
use thiserror::Error;

type Batch<E> = <UtxoDatabase<E> as DatabaseSet<E>>::Unmerkleized;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ExecutionError {
    #[error("object not found: {id:?}")]
    ObjectNotFound { id: ObjectId },
    #[error("wrong object kind for {id:?}: expected {expected}, found {actual}")]
    WrongObjectKind {
        id: ObjectId,
        expected: ObjectKind,
        actual: ObjectKind,
    },
    #[error("invalid signature")]
    InvalidSignature,
    #[error("insufficient balance: available={available} requested={requested}")]
    InsufficientBalance { available: u64, requested: u64 },
    #[error("transfer amount must be > 0")]
    ZeroAmount,
    #[error("duplicate merge input: {id:?}")]
    DuplicateInput { id: ObjectId },
    #[error("merge requires at least 2 inputs")]
    TooFewMergeInputs,
    #[error("merge inputs must be strictly increasing")]
    NonCanonicalMergeInputs,
    #[error("merge inputs must have the same owner")]
    MergeOwnerMismatch,
    #[error("merge overflowed u64 total")]
    MergeOverflow,
    #[error("output object collision: {id:?}")]
    OutputCollision { id: ObjectId },
    #[error("storage error: {0}")]
    Storage(String),
    #[error("kernel host/store contract failure: {error:?}")]
    KernelHostContract { error: ApplyError },
    #[error("kernel transaction rejected: {error:?}")]
    KernelApply { error: ApplyError },
    #[error("staked open rejected: the wired verifier cannot verify any dispute seal")]
    StakedOpenUnsupported,
    #[error("staked open lifetime {blocks} blocks exceeds the consensus cap {max}")]
    StakedLifetimeExceeded { blocks: u64, max: u64 },
}

impl ExecutionError {
    pub fn is_transient_for_mempool(&self) -> bool {
        matches!(
            self,
            Self::ObjectNotFound { .. }
                | Self::KernelApply {
                    error: ApplyError::InvalidProof {
                        reason: InvalidProofReason::TimeoutNotReached,
                        ..
                    }
                }
        )
    }

    pub fn is_fatal_storage(&self) -> bool {
        matches!(self, Self::Storage(_) | Self::KernelHostContract { .. })
    }
}

fn storage_err<E: core::fmt::Debug>(err: E) -> ExecutionError {
    ExecutionError::Storage(format!("{err:?}"))
}

fn require_coin(id: ObjectId, object: Option<Object>) -> Result<Coin, ExecutionError> {
    match object {
        Some(Object::Coin(coin)) => Ok(coin),
        Some(object) => Err(ExecutionError::WrongObjectKind {
            id,
            expected: ObjectKind::Coin,
            actual: object.kind(),
        }),
        None => Err(ExecutionError::ObjectNotFound { id }),
    }
}

fn legacy_owner_address(owner: SettlementKey) -> Result<Address, ExecutionError> {
    Address::try_from(owner).map_err(|_| ExecutionError::InvalidSignature)
}

async fn object_exists<E>(batches: &Batch<E>, id: &ObjectId) -> Result<bool, ExecutionError>
where
    E: Storage + Clock + Metrics + Send + Sync + 'static,
{
    batches
        .get(id)
        .await
        .map(|value| value.is_some())
        .map_err(storage_err)
}

pub async fn execute_all<E, V>(
    context: KernelContext,
    verifier: &V,
    txs: &[Transaction],
    genesis_allocations: &[(SettlementKey, u64)],
    batches: Batch<E>,
) -> Result<Batch<E>, ExecutionError>
where
    E: Storage + Clock + Metrics + Send + Sync + 'static,
    V: SigVerifier + SealVerifier + StakedOpenPolicy,
{
    let mut batches = maybe_seed_genesis(context, genesis_allocations, batches);
    for tx in txs {
        let next = apply_transaction(batches, context, verifier, tx)
            .await
            .map_err(|(_, err)| err)?;
        batches = next;
    }
    Ok(batches)
}

pub async fn execute_proposal<E, V>(
    context: KernelContext,
    verifier: &V,
    candidates: Vec<Transaction>,
    genesis_allocations: &[(SettlementKey, u64)],
    max_txs: usize,
    max_tx_bytes: usize,
    batches: Batch<E>,
) -> Result<(Batch<E>, Vec<Transaction>, Vec<Transaction>), ExecutionError>
where
    E: Storage + Clock + Metrics + Send + Sync + 'static,
    V: SigVerifier + SealVerifier + StakedOpenPolicy,
{
    let mut batches = maybe_seed_genesis(context, genesis_allocations, batches);
    let mut included = Vec::new();
    let mut retained = Vec::new();
    let mut included_bytes = 0_usize;
    let mut candidates = candidates.into_iter();

    while let Some(tx) = candidates.next() {
        let next_bytes = included_bytes.saturating_add(tx.encode_size());
        if included.len() >= max_txs || next_bytes > max_tx_bytes {
            retained.push(tx);
            retained.extend(candidates);
            break;
        }

        match apply_transaction(batches, context, verifier, &tx).await {
            Ok(next) => {
                batches = next;
                included_bytes = next_bytes;
                included.push(tx);
            }
            Err((next, err)) if err.is_transient_for_mempool() => {
                batches = next;
                retained.push(tx);
            }
            Err((next, err)) if err.is_fatal_storage() => {
                let _ = next;
                return Err(err);
            }
            Err((next, _err)) => {
                batches = next;
            }
        }
    }

    Ok((batches, included, retained))
}

fn maybe_seed_genesis<E>(
    context: KernelContext,
    genesis_allocations: &[(SettlementKey, u64)],
    mut batches: Batch<E>,
) -> Batch<E>
where
    E: Storage + Clock + Metrics + Send + Sync + 'static,
{
    if context.block_height().get() != 1 {
        return batches;
    }

    for (idx, (owner, balance)) in genesis_allocations.iter().enumerate() {
        let Ok(validator_index) = u16::try_from(idx) else {
            warn!(
                index = idx,
                "validator index overflow; truncating genesis allocation"
            );
            break;
        };
        let id = genesis_object_id(validator_index);
        let coin = Coin {
            owner: *owner,
            value: *balance,
        };
        batches = batches.write(id, Some(Object::Coin(coin)));
    }
    batches
}

async fn apply_transaction<E, V>(
    mut batches: Batch<E>,
    context: KernelContext,
    verifier: &V,
    tx: &Transaction,
) -> Result<Batch<E>, (Batch<E>, ExecutionError)>
where
    E: Storage + Clock + Metrics + Send + Sync + 'static,
    V: SigVerifier + SealVerifier + StakedOpenPolicy,
{
    match tx {
        Transaction::Transfer {
            input,
            recipient,
            amount,
            ..
        } => {
            let object = match batches.get(input).await.map_err(storage_err) {
                Ok(object) => object,
                Err(err) => return Err((batches, err)),
            };
            let coin = match require_coin(*input, object) {
                Ok(coin) => coin,
                Err(err) => return Err((batches, err)),
            };
            let owner = match legacy_owner_address(coin.owner) {
                Ok(owner) => owner,
                Err(err) => return Err((batches, err)),
            };
            if !tx.verify_signature(&owner) {
                return Err((batches, ExecutionError::InvalidSignature));
            }
            if *amount == 0 {
                return Err((batches, ExecutionError::ZeroAmount));
            }
            if *amount > coin.value {
                return Err((
                    batches,
                    ExecutionError::InsufficientBalance {
                        available: coin.value,
                        requested: *amount,
                    },
                ));
            }

            let tx_digest = Sha256::hash(&tx.encode());
            let recipient_id = output_object_id(&tx_digest, 0);
            match object_exists(&batches, &recipient_id).await {
                Ok(false) => {}
                Ok(true) => {
                    return Err((
                        batches,
                        ExecutionError::OutputCollision { id: recipient_id },
                    ));
                }
                Err(err) => return Err((batches, err)),
            }

            let change_value = coin.value - amount;
            let change_id = if change_value > 0 {
                let id = output_object_id(&tx_digest, 1);
                let exists = if id == recipient_id {
                    true
                } else {
                    match object_exists(&batches, &id).await {
                        Ok(exists) => exists,
                        Err(err) => return Err((batches, err)),
                    }
                };
                if exists {
                    return Err((batches, ExecutionError::OutputCollision { id }));
                }
                Some(id)
            } else {
                None
            };

            batches = batches.write(*input, None);
            batches = batches.write(
                recipient_id,
                Some(Object::Coin(Coin {
                    owner: SettlementKey::from(recipient),
                    value: *amount,
                })),
            );

            if let Some(change_id) = change_id {
                batches = batches.write(
                    change_id,
                    Some(Object::Coin(Coin {
                        owner: coin.owner,
                        value: change_value,
                    })),
                );
            }
            Ok(batches)
        }
        Transaction::MergeCoin { inputs, .. } => {
            if inputs.len() < 2 {
                return Err((batches, ExecutionError::TooFewMergeInputs));
            }
            for pair in inputs.as_slice().windows(2) {
                if pair[0] == pair[1] {
                    return Err((batches, ExecutionError::DuplicateInput { id: pair[0] }));
                }
                if pair[0] > pair[1] {
                    return Err((batches, ExecutionError::NonCanonicalMergeInputs));
                }
            }

            let mut owner: Option<SettlementKey> = None;
            let mut total = 0u64;
            for input in inputs {
                let object = match batches.get(input).await.map_err(storage_err) {
                    Ok(object) => object,
                    Err(err) => return Err((batches, err)),
                };
                let coin = match require_coin(*input, object) {
                    Ok(coin) => coin,
                    Err(err) => return Err((batches, err)),
                };
                if let Some(expected_owner) = owner.as_ref() {
                    if &coin.owner != expected_owner {
                        return Err((batches, ExecutionError::MergeOwnerMismatch));
                    }
                } else {
                    owner = Some(coin.owner);
                }
                total = match total.checked_add(coin.value) {
                    Some(total) => total,
                    None => return Err((batches, ExecutionError::MergeOverflow)),
                };
            }
            let Some(owner) = owner else {
                return Err((batches, ExecutionError::MergeOwnerMismatch));
            };
            let address = match legacy_owner_address(owner) {
                Ok(address) => address,
                Err(err) => return Err((batches, err)),
            };
            if !tx.verify_signature(&address) {
                return Err((batches, ExecutionError::InvalidSignature));
            }

            let tx_digest = Sha256::hash(&tx.encode());
            let output_id = output_object_id(&tx_digest, 0);
            match object_exists(&batches, &output_id).await {
                Ok(false) => {}
                Ok(true) => {
                    return Err((batches, ExecutionError::OutputCollision { id: output_id }));
                }
                Err(err) => return Err((batches, err)),
            }

            for input in inputs {
                batches = batches.write(*input, None);
            }
            batches = batches.write(
                output_id,
                Some(Object::Coin(Coin {
                    owner,
                    value: total,
                })),
            );
            Ok(batches)
        }
        Transaction::Kernel(tx) => apply_kernel_transaction(batches, context, verifier, tx).await,
    }
}

async fn load_coin_slot<E>(
    batches: &Batch<E>,
    working: &mut BlockWorkingSet,
    id: CoinId,
) -> Result<(), ExecutionError>
where
    E: Storage + Clock + Metrics + Send + Sync + 'static,
{
    let object_id = coin_object_id(id);
    let coin = match batches.get(&object_id).await.map_err(storage_err)? {
        Some(Object::Coin(coin)) => Some(KernelCoin::from(coin)),
        Some(object) => {
            return Err(ExecutionError::WrongObjectKind {
                id: object_id,
                expected: ObjectKind::Coin,
                actual: object.kind(),
            });
        }
        None => None,
    };
    working.insert_coin_slot(id, coin);
    Ok(())
}

async fn load_edge_slot<E>(
    batches: &Batch<E>,
    working: &mut BlockWorkingSet,
    id: EdgeId,
) -> Result<(), ExecutionError>
where
    E: Storage + Clock + Metrics + Send + Sync + 'static,
{
    let object_id = edge_object_id(id);
    let edge = match batches.get(&object_id).await.map_err(storage_err)? {
        Some(Object::Edge(edge)) => Some(edge),
        Some(object) => {
            return Err(ExecutionError::WrongObjectKind {
                id: object_id,
                expected: ObjectKind::Edge,
                actual: object.kind(),
            });
        }
        None => None,
    };
    working.insert_edge_slot(id, edge);
    Ok(())
}

async fn load_kernel_slots<E>(
    batches: &Batch<E>,
    tx: &KernelTx,
) -> Result<BlockWorkingSet, ExecutionError>
where
    E: Storage + Clock + Metrics + Send + Sync + 'static,
{
    let mut working = BlockWorkingSet::new();
    match tx {
        KernelTx::Open { funding, terms, .. } => {
            for id in funding.maker().iter().chain(funding.taker()) {
                load_coin_slot(batches, &mut working, *id).await?;
            }
            load_edge_slot(batches, &mut working, KernelTx::edge_id_of(funding, terms)).await?;
        }
        KernelTx::Close { input, outputs, .. } => {
            load_edge_slot(batches, &mut working, *input).await?;
            for id in KernelTx::close_output_ids(*input, outputs).iter() {
                load_coin_slot(batches, &mut working, *id).await?;
            }
        }
    }
    Ok(working)
}

// `State::apply` uses the same MissingCoin/MissingEdge variants during its
// read-only validation and during its fold. The immutable parent working set
// distinguishes them: an absent preloaded value is user-controlled and
// transient, while a value that existed before apply but vanished during fold
// proves that the host violated the kernel Batch contract.
fn classify_kernel_error(working: &BlockWorkingSet, source: ApplyError) -> ExecutionError {
    match source {
        ApplyError::MissingCoin { id } if working.coin(id).is_none() => {
            ExecutionError::ObjectNotFound {
                id: coin_object_id(id),
            }
        }
        ApplyError::MissingEdge { id } if working.edge(id).is_none() => {
            ExecutionError::ObjectNotFound {
                id: edge_object_id(id),
            }
        }
        ApplyError::MissingCoin { .. }
        | ApplyError::CoinChanged { .. }
        | ApplyError::MissingEdge { .. }
        | ApplyError::EdgeChanged { .. }
        | ApplyError::CoinInsertRejected { .. }
        | ApplyError::EdgeInsertRejected { .. } => {
            ExecutionError::KernelHostContract { error: source }
        }
        ApplyError::OutputExists { .. }
        | ApplyError::EdgeExists { .. }
        | ApplyError::DuplicateInput { .. }
        | ApplyError::InvalidOpen { .. }
        | ApplyError::InvalidClose { .. }
        | ApplyError::InvalidProof { .. } => ExecutionError::KernelApply { error: source },
    }
}

fn replay_kernel_event<E>(
    mut batches: Batch<E>,
    working: &BlockWorkingSet,
    event: &Event,
) -> (Batch<E>, Option<ExecutionError>)
where
    E: Storage + Clock + Metrics + Send + Sync + 'static,
{
    // Event order is the consensus-authoritative diff. Never enumerate the
    // HashMaps in BlockWorkingSet: their iteration order is process-local.
    match event.kind() {
        EventKind::EdgeOpened { inputs, output } => {
            for id in inputs {
                if working.coin(*id).is_some() {
                    return (
                        batches,
                        Some(ExecutionError::KernelHostContract {
                            error: ApplyError::CoinChanged { id: *id },
                        }),
                    );
                }
                batches = batches.write(coin_object_id(*id), None);
            }
            let Some(edge) = working.edge(*output) else {
                return (
                    batches,
                    Some(ExecutionError::KernelHostContract {
                        error: ApplyError::MissingEdge { id: *output },
                    }),
                );
            };
            batches = batches.write(edge_object_id(*output), Some(Object::Edge(edge)));
        }
        EventKind::EdgeClosed { input, outputs } => {
            if working.edge(*input).is_some() {
                return (
                    batches,
                    Some(ExecutionError::KernelHostContract {
                        error: ApplyError::EdgeChanged { id: *input },
                    }),
                );
            }
            batches = batches.write(edge_object_id(*input), None);
            for id in outputs {
                let Some(coin) = working.coin(*id) else {
                    return (
                        batches,
                        Some(ExecutionError::KernelHostContract {
                            error: ApplyError::MissingCoin { id: *id },
                        }),
                    );
                };
                batches = batches.write(coin_object_id(*id), Some(Object::Coin(Coin::from(coin))));
            }
        }
    }
    (batches, None)
}

/// Consensus admission for staked (fraud-game) opens, checked before the
/// kernel ever sees the transaction. A bond whose `Violation` path can
/// never verify is just locked funds with a dead dispute game, so staked
/// opens are refused unless the wired verifier admits them; admitted
/// bonds must still commit a bounded lifetime, because lifetime fees are
/// zero and a distant timeout would be operationally permanent.
fn check_staked_open<V: StakedOpenPolicy>(
    context: KernelContext,
    verifier: &V,
    tx: &KernelTx,
) -> Result<(), ExecutionError> {
    let KernelTx::Open { terms, .. } = tx else {
        return Ok(());
    };
    if terms.as_stake_bond().is_none() {
        return Ok(());
    }
    if !verifier.admits_staked_opens() {
        return Err(ExecutionError::StakedOpenUnsupported);
    }
    let blocks = terms
        .timeout()
        .get()
        .saturating_sub(context.block_height().get());
    if blocks > MAX_STAKED_LIFETIME_BLOCKS {
        return Err(ExecutionError::StakedLifetimeExceeded {
            blocks,
            max: MAX_STAKED_LIFETIME_BLOCKS,
        });
    }
    Ok(())
}

async fn apply_kernel_transaction<E, V>(
    batches: Batch<E>,
    context: KernelContext,
    verifier: &V,
    tx: &KernelTx,
) -> Result<Batch<E>, (Batch<E>, ExecutionError)>
where
    E: Storage + Clock + Metrics + Send + Sync + 'static,
    V: SigVerifier + SealVerifier + StakedOpenPolicy,
{
    if let Err(err) = check_staked_open(context, verifier, tx) {
        return Err((batches, err));
    }
    let working = match load_kernel_slots(&batches, tx).await {
        Ok(working) => working,
        Err(err) => return Err((batches, err)),
    };
    let mut state = State::new(working);
    let event = match state.apply(context, verifier, tx) {
        Ok(event) => event,
        Err(source) => {
            let err = classify_kernel_error(state.store(), source);
            return Err((batches, err));
        }
    };
    let working = state.into_store();
    let (batches, replay_error) = replay_kernel_event(batches, &working, &event);
    match replay_error {
        Some(error) => Err((batches, error)),
        None => Ok(batches),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{KERNEL_FEES, MAX_TXS_PER_BLOCK};
    use crate::execution::{
        ChainVerifier,
        store::{UtxoDatabase, utxo_db_config},
        test_support::{
            index_block, index_genesis, kernel_fixture, kernel_fixture_at, legacy_address,
            run_qmdb, validator_key,
        },
    };
    use crate::owner_index::{ApplyOutcome, OwnerIndex};
    use commonware_glue::stateful::db::{DatabaseSet, Merkleized as _, Unmerkleized as _};
    use commonware_runtime::{Supervisor as _, tokio};
    use hellas_kernel::{BlockHash, BlockHeight, InsertError};
    use std::collections::{BTreeMap, BTreeSet};

    fn context(height: u64) -> KernelContext {
        KernelContext::with_fees(
            BlockHeight::new(height),
            BlockHash::from_bytes([height.saturating_sub(1) as u8; BlockHash::LENGTH]),
            KERNEL_FEES,
        )
    }

    async fn database(context: tokio::Context, partition: &str) -> UtxoDatabase<tokio::Context> {
        let config = utxo_db_config(&context, partition, 1024, 8);
        <UtxoDatabase<_> as DatabaseSet<_>>::init(context, config).await
    }

    async fn apply_and_finalize(
        database: &UtxoDatabase<tokio::Context>,
        context: KernelContext,
        txs: &[Transaction],
        genesis_allocations: &[(SettlementKey, u64)],
    ) -> commonware_cryptography::sha256::Digest {
        let batches = database.new_batches().await;
        let batches = execute_all(
            context,
            &ChainVerifier::new(),
            txs,
            genesis_allocations,
            batches,
        )
        .await
        .expect("block executes");
        let merkleized = batches.merkleize().await.expect("block merkleizes");
        let root = merkleized.root();
        database.finalize(merkleized).await;
        root
    }

    async fn read_objects(
        database: &UtxoDatabase<tokio::Context>,
        ids: &BTreeSet<ObjectId>,
    ) -> (
        BTreeMap<ObjectId, Coin>,
        BTreeMap<ObjectId, hellas_kernel::Edge>,
    ) {
        let reader = database.read().await;
        let mut coins = BTreeMap::new();
        let mut edges = BTreeMap::new();
        for id in ids {
            match reader.get(id).await.expect("QMDB object read") {
                Some(Object::Coin(coin)) => {
                    coins.insert(*id, coin);
                }
                Some(Object::Edge(edge)) => {
                    edges.insert(*id, edge);
                }
                None => {}
            }
        }
        (coins, edges)
    }

    async fn assert_index_matches_qmdb(
        database: &UtxoDatabase<tokio::Context>,
        index: &OwnerIndex,
        known_ids: &[ObjectId],
        known_edge_owners: &[SettlementKey],
    ) {
        let indexed_coins = index.all_coins_for_test();
        let indexed_edges = index.all_edges_for_test();
        // QMDB does not expose a full object iterator. Probe every id derived
        // from the applied transaction graph plus every id known to the index,
        // so index-only extras cannot hide from this state-set comparison.
        let mut probe_ids: BTreeSet<_> = known_ids.iter().copied().collect();
        probe_ids.extend(indexed_coins.keys().copied());
        probe_ids.extend(indexed_edges.keys().copied());

        let (coins, edges) = read_objects(database, &probe_ids).await;
        assert_eq!(indexed_coins, coins);
        assert_eq!(
            indexed_edges.keys().copied().collect::<BTreeSet<_>>(),
            edges.keys().copied().collect::<BTreeSet<_>>()
        );

        let mut edge_owners: BTreeSet<_> = known_edge_owners.iter().copied().collect();
        for (id, edge) in &edges {
            let indexed = crate::owner_index::IndexedEdge::from(edge.parties());
            assert_eq!(indexed_edges.get(id), Some(&indexed));
            edge_owners.insert(indexed.maker);
            edge_owners.insert(indexed.taker);
        }
        for owner in edge_owners {
            let expected: Vec<_> = edges
                .iter()
                .filter_map(|(id, edge)| {
                    let indexed = crate::owner_index::IndexedEdge::from(edge.parties());
                    (owner == indexed.maker || owner == indexed.taker).then_some((*id, indexed))
                })
                .collect();
            assert_eq!(index.get_edges_by_owner(&owner), expected);
        }
    }

    #[test]
    fn edge_in_coin_slot_is_typed_and_non_transient() {
        let id = ObjectId::from([0x44; 32]);
        let err = require_coin(id, Some(Object::Edge(crate::domain::test_edge())))
            .expect_err("edge is not a coin");
        assert_eq!(
            err,
            ExecutionError::WrongObjectKind {
                id,
                expected: ObjectKind::Coin,
                actual: ObjectKind::Edge,
            }
        );
        assert!(!err.is_transient_for_mempool());
    }

    #[test]
    fn non_p256_owner_is_invalid_not_transient() {
        let owner = SettlementKey::from_bytes([0xa5; SettlementKey::LENGTH]);
        let err = legacy_owner_address(owner).expect_err("not a P-256 point");
        assert_eq!(err, ExecutionError::InvalidSignature);
        assert!(!err.is_transient_for_mempool());
    }

    #[test]
    fn qmdb_genesis_open_mutual_close_lands_payouts_and_consumes_edge() {
        run_qmdb(|runtime| async move {
            let database = database(runtime, "mutual_close").await;
            let fixture = kernel_fixture(10).expect("kernel fixture");
            apply_and_finalize(
                &database,
                context(1),
                &[Transaction::Kernel(fixture.open.clone())],
                &fixture.allocations,
            )
            .await;

            let edge_id = edge_object_id(fixture.edge);
            assert!(matches!(
                database
                    .read()
                    .await
                    .get(&edge_id)
                    .await
                    .expect("edge read"),
                Some(Object::Edge(_))
            ));

            apply_and_finalize(
                &database,
                context(2),
                &[Transaction::Kernel(fixture.mutual_close.clone())],
                &fixture.allocations,
            )
            .await;
            assert_eq!(
                database
                    .read()
                    .await
                    .get(&edge_id)
                    .await
                    .expect("edge read"),
                None
            );
            for (id, payout) in fixture.payout_ids().iter().zip(&fixture.outputs) {
                assert_eq!(
                    database
                        .read()
                        .await
                        .get(&coin_object_id(*id))
                        .await
                        .expect("payout read"),
                    Some(Object::Coin(Coin {
                        owner: SettlementKey::from(payout.owner()),
                        value: payout.value(),
                    }))
                );
            }
        });
    }

    #[test]
    fn owner_index_matches_qmdb_across_legacy_and_kernel_blocks() {
        run_qmdb(|runtime| async move {
            let database = database(runtime, "index_qmdb_agreement").await;
            let mutual = kernel_fixture(10).expect("mutual-close fixture");
            let timeout = kernel_fixture_at(4, 2, 9, 10).expect("timeout-close fixture");
            let legacy_owner = legacy_address(21);
            let legacy_recipient = legacy_address(22);
            let mut allocations = mutual.allocations.clone();
            allocations.extend_from_slice(&timeout.allocations);
            allocations.push((SettlementKey::from(&legacy_owner), 90));

            let transfer = Transaction::transfer(
                &validator_key(21),
                genesis_object_id(4),
                legacy_recipient,
                35,
            )
            .expect("legacy transfer fixture");
            let transfer_digest = Sha256::hash(&transfer.encode());
            let transfer_recipient = output_object_id(&transfer_digest, 0);
            let transfer_change = output_object_id(&transfer_digest, 1);
            let mutual_edge_id = edge_object_id(mutual.edge);
            let timeout_edge_id = edge_object_id(timeout.edge);
            let mutual_payout_ids: Vec<_> = mutual
                .payout_ids()
                .iter()
                .copied()
                .map(coin_object_id)
                .collect();
            let timeout_payout_ids: Vec<_> = timeout
                .payout_ids()
                .iter()
                .copied()
                .map(coin_object_id)
                .collect();
            let mut known_ids: Vec<_> = (0..=4).map(genesis_object_id).collect();
            known_ids.extend([
                transfer_recipient,
                transfer_change,
                mutual_edge_id,
                timeout_edge_id,
            ]);
            known_ids.extend_from_slice(&mutual_payout_ids);
            known_ids.extend_from_slice(&timeout_payout_ids);
            known_ids.sort_unstable();
            known_ids.dedup();
            let mutual_parties = mutual.terms.parties();
            let timeout_parties = timeout.terms.parties();
            let known_edge_owners = [
                SettlementKey::from(mutual_parties.maker()),
                SettlementKey::from(mutual_parties.taker()),
                SettlementKey::from(timeout_parties.maker()),
                SettlementKey::from(timeout_parties.taker()),
            ];
            let genesis = index_genesis();
            let index = OwnerIndex::new(&genesis, allocations.clone());
            let first_txs = vec![
                transfer,
                Transaction::Kernel(mutual.open.clone()),
                Transaction::Kernel(timeout.open.clone()),
            ];
            let first_root =
                apply_and_finalize(&database, context(1), &first_txs, &allocations).await;
            let first_block = index_block(&genesis, first_root, first_txs);
            assert_eq!(
                index.apply_finalized(&first_block),
                Ok(ApplyOutcome::Applied)
            );
            assert_index_matches_qmdb(&database, &index, &known_ids, &known_edge_owners).await;

            let second_txs = vec![Transaction::Kernel(mutual.mutual_close.clone())];
            let second_root =
                apply_and_finalize(&database, context(2), &second_txs, &allocations).await;
            let second_block = index_block(&first_block, second_root, second_txs);
            assert_eq!(
                index.apply_finalized(&second_block),
                Ok(ApplyOutcome::Applied)
            );
            assert_index_matches_qmdb(&database, &index, &known_ids, &known_edge_owners).await;

            let third_txs = Vec::new();
            let third_root =
                apply_and_finalize(&database, context(3), &third_txs, &allocations).await;
            let third_block = index_block(&second_block, third_root, third_txs);
            assert_eq!(
                index.apply_finalized(&third_block),
                Ok(ApplyOutcome::Applied)
            );
            assert_index_matches_qmdb(&database, &index, &known_ids, &known_edge_owners).await;

            let fourth_txs = vec![Transaction::Kernel(timeout.timeout_close.clone())];
            let fourth_root =
                apply_and_finalize(&database, context(4), &fourth_txs, &allocations).await;
            let fourth_block = index_block(&third_block, fourth_root, fourth_txs);
            assert_eq!(
                index.apply_finalized(&fourth_block),
                Ok(ApplyOutcome::Applied)
            );
            assert_index_matches_qmdb(&database, &index, &known_ids, &known_edge_owners).await;
        });
    }

    #[test]
    fn qmdb_timeout_close_succeeds_after_height_advance() {
        run_qmdb(|runtime| async move {
            let database = database(runtime, "timeout_close").await;
            let fixture = kernel_fixture(3).expect("kernel fixture");
            apply_and_finalize(
                &database,
                context(1),
                &[Transaction::Kernel(fixture.open.clone())],
                &fixture.allocations,
            )
            .await;
            apply_and_finalize(&database, context(2), &[], &fixture.allocations).await;
            apply_and_finalize(
                &database,
                context(3),
                &[Transaction::Kernel(fixture.timeout_close.clone())],
                &fixture.allocations,
            )
            .await;

            assert_eq!(
                database
                    .read()
                    .await
                    .get(&edge_object_id(fixture.edge))
                    .await
                    .expect("edge read"),
                None
            );
            for id in fixture.payout_ids().iter() {
                assert!(matches!(
                    database
                        .read()
                        .await
                        .get(&coin_object_id(*id))
                        .await
                        .expect("payout read"),
                    Some(Object::Coin(_))
                ));
            }
        });
    }

    #[test]
    fn identical_kernel_block_has_identical_qmdb_root() {
        run_qmdb(|runtime| async move {
            let first = database(runtime.child("determinism_a"), "determinism_a").await;
            let second = database(runtime.child("determinism_b"), "determinism_b").await;
            let fixture = kernel_fixture(10).expect("kernel fixture");
            let txs = [Transaction::Kernel(fixture.open.clone())];
            let first_root =
                apply_and_finalize(&first, context(1), &txs, &fixture.allocations).await;
            let second_root =
                apply_and_finalize(&second, context(1), &txs, &fixture.allocations).await;
            assert_eq!(first_root, second_root);
        });
    }

    #[test]
    fn kernel_error_taxonomy_distinguishes_transient_drop_and_fatal() {
        run_qmdb(|runtime| async move {
            let fixture = kernel_fixture(10).expect("kernel fixture");

            let missing_database = database(runtime.child("missing"), "missing_taxonomy").await;
            let missing_batches = missing_database.new_batches().await;
            let (_, included, retained) = execute_proposal(
                context(1),
                &ChainVerifier::new(),
                vec![Transaction::Kernel(fixture.open.clone())],
                &[],
                MAX_TXS_PER_BLOCK,
                usize::MAX,
                missing_batches,
            )
            .await
            .expect("missing input is not fatal");
            assert!(included.is_empty());
            assert_eq!(retained.len(), 1);

            let bad_auth_database = database(runtime.child("bad_auth"), "bad_auth_taxonomy").await;
            let bad_auth_batches = bad_auth_database.new_batches().await;
            let (_, included, retained) = execute_proposal(
                context(1),
                &ChainVerifier::new(),
                vec![Transaction::Kernel(
                    fixture.bad_auth_open().expect("bad-auth fixture"),
                )],
                &fixture.allocations,
                MAX_TXS_PER_BLOCK,
                usize::MAX,
                bad_auth_batches,
            )
            .await
            .expect("bad auth is a non-fatal drop");
            assert!(included.is_empty());
            assert!(retained.is_empty());

            let contract_database = database(runtime.child("contract"), "contract_taxonomy").await;
            let contract_batches = contract_database.new_batches().await;
            let contract_batches = execute_all(
                context(1),
                &ChainVerifier::new(),
                &[],
                &fixture.allocations,
                contract_batches,
            )
            .await
            .expect("genesis seed");
            let working = load_kernel_slots(&contract_batches, &fixture.open)
                .await
                .expect("preload funded slots");
            let input = fixture
                .funding
                .maker()
                .iter()
                .next()
                .copied()
                .expect("maker input");
            let fatal = classify_kernel_error(&working, ApplyError::MissingCoin { id: input });
            assert!(fatal.is_fatal_storage());
            assert_eq!(
                fatal,
                ExecutionError::KernelHostContract {
                    error: ApplyError::MissingCoin { id: input },
                }
            );
            assert!(
                ExecutionError::KernelHostContract {
                    error: ApplyError::CoinInsertRejected {
                        id: input,
                        reason: InsertError::Unavailable,
                    },
                }
                .is_fatal_storage()
            );
        });
    }

    #[test]
    fn staked_opens_are_gated_at_consensus_execution() {
        use hellas_kernel::{
            Auth, BlockHeight as KernelHeight, Funding, Key as KernelKey, List,
            MAX_EDGE_OUTPUTS as OUTPUTS, MAX_PARTY_INPUTS as INPUTS, Parties,
            Payout as KernelPayout, ProtocolCode, SealPublicInputs, Sig, StakeBondTerms,
            Terms as KernelTerms,
        };

        /// Delegates all verification to [`ChainVerifier`] but admits
        /// staked opens, standing in for the future seal-capable dev
        /// verifier.
        struct AdmittingVerifier(ChainVerifier);
        impl SigVerifier for AdmittingVerifier {
            fn verify_sig(
                &self,
                sig: Sig,
                party_key: KernelKey,
                hash: hellas_kernel::PayloadHash,
            ) -> bool {
                self.0.verify_sig(sig, party_key, hash)
            }
        }
        impl SealVerifier for AdmittingVerifier {
            fn verify_seal(
                &self,
                seal: hellas_kernel::Seal,
                public: &SealPublicInputs<'_>,
            ) -> bool {
                self.0.verify_seal(seal, public)
            }
        }
        impl StakedOpenPolicy for AdmittingVerifier {
            fn admits_staked_opens(&self) -> bool {
                true
            }
        }

        let staked_open = |timeout: u64| {
            let terms = KernelTerms::stake_bond(StakeBondTerms {
                protocol: ProtocolCode::new(1),
                parties: Parties::new(
                    KernelKey::from_bytes([2; KernelKey::LENGTH]),
                    KernelKey::from_bytes([3; KernelKey::LENGTH]),
                ),
                timeout: KernelHeight::new(timeout),
                timeout_outputs: List::take([KernelPayout::default(); OUTPUTS], 0),
                treasury: KernelKey::from_bytes([4; KernelKey::LENGTH]),
                award: 1,
                stake: 1,
                max_job_price: 1,
                max_dispute_cost: 0,
                challenge_margin: 1,
            });
            let zero = CoinId::from_bytes([0; CoinId::LENGTH]);
            let empty = List::take([zero; INPUTS], 0);
            let garbage = Auth::native(Sig::from_bytes([0; 64]));
            Transaction::Kernel(KernelTx::open(
                Funding::new(empty.clone(), empty),
                terms,
                garbage.clone(),
                garbage,
            ))
        };

        run_qmdb(|runtime| async move {
            let database = database(runtime, "staked_gate").await;
            let batches = database.new_batches().await;

            // Production verifier (no preverified-seals feature): refused
            // before the kernel sees it, and dropped (not retained) from
            // proposals.
            #[cfg(not(feature = "preverified-seals"))]
            let batches = {
                let (batches, error) =
                    apply_transaction(batches, context(1), &ChainVerifier::new(), &staked_open(50))
                        .await
                        .err()
                        .expect("staked open refused in production");
                assert_eq!(error, ExecutionError::StakedOpenUnsupported);
                assert!(!error.is_transient_for_mempool());
                assert!(!error.is_fatal_storage());
                let (batches, included, retained) = execute_proposal(
                    context(1),
                    &ChainVerifier::new(),
                    vec![staked_open(50)],
                    &[],
                    MAX_TXS_PER_BLOCK,
                    usize::MAX,
                    batches,
                )
                .await
                .expect("gated staked open is a non-fatal drop");
                assert!(included.is_empty());
                assert!(retained.is_empty());
                batches
            };

            // Admitting verifier: the lifetime cap holds...
            let admitting = AdmittingVerifier(ChainVerifier::new());
            let over_cap = 1 + crate::domain::MAX_STAKED_LIFETIME_BLOCKS + 1;
            let (batches, error) =
                apply_transaction(batches, context(1), &admitting, &staked_open(over_cap))
                    .await
                    .err()
                    .expect("over-cap staked open refused");
            assert_eq!(
                error,
                ExecutionError::StakedLifetimeExceeded {
                    blocks: crate::domain::MAX_STAKED_LIFETIME_BLOCKS + 1,
                    max: crate::domain::MAX_STAKED_LIFETIME_BLOCKS,
                }
            );

            // ...and an in-cap staked open falls through to ordinary
            // kernel validation (here: rejected by the kernel because the
            // committed stake exceeds the zero funding — proof the gate
            // itself no longer blocks it).
            let (_batches, error) =
                apply_transaction(batches, context(1), &admitting, &staked_open(50))
                    .await
                    .err()
                    .expect("kernel still validates admitted staked opens");
            assert!(matches!(error, ExecutionError::KernelApply { .. }));
        });
    }

    #[test]
    fn timeout_not_reached_is_retained_but_proof_expired_is_dropped() {
        let input = EdgeId::from_bytes([0x55; EdgeId::LENGTH]);
        let working = BlockWorkingSet::new();
        let timeout_not_reached = classify_kernel_error(
            &working,
            ApplyError::InvalidProof {
                input,
                reason: InvalidProofReason::TimeoutNotReached,
            },
        );
        assert_eq!(
            timeout_not_reached,
            ExecutionError::KernelApply {
                error: ApplyError::InvalidProof {
                    input,
                    reason: InvalidProofReason::TimeoutNotReached,
                },
            }
        );
        assert!(timeout_not_reached.is_transient_for_mempool());

        let proof_expired = classify_kernel_error(
            &working,
            ApplyError::InvalidProof {
                input,
                reason: InvalidProofReason::ProofExpired,
            },
        );
        assert_eq!(
            proof_expired,
            ExecutionError::KernelApply {
                error: ApplyError::InvalidProof {
                    input,
                    reason: InvalidProofReason::ProofExpired,
                },
            }
        );
        assert!(!proof_expired.is_transient_for_mempool());
    }

    #[test]
    fn open_edge_id_collision_with_coin_is_wrong_kind_drop_and_preserves_state() {
        run_qmdb(|runtime| async move {
            let database = database(runtime, "open_coin_collision").await;
            let fixture = kernel_fixture(10).expect("kernel fixture");
            let batches = database.new_batches().await;
            let batches = execute_all(
                context(1),
                &ChainVerifier::new(),
                &[],
                &fixture.allocations,
                batches,
            )
            .await
            .expect("genesis seed");
            let collision_id = edge_object_id(fixture.edge);
            let collision = Object::Coin(Coin {
                owner: fixture.maker,
                value: 7,
            });
            let batches = batches.write(collision_id, Some(collision));
            let verifier = ChainVerifier::new();
            let (batches, error) = apply_transaction(
                batches,
                context(1),
                &verifier,
                &Transaction::Kernel(fixture.open.clone()),
            )
            .await
            .err()
            .expect("coin collision rejects open");
            assert_eq!(
                error,
                ExecutionError::WrongObjectKind {
                    id: collision_id,
                    expected: ObjectKind::Edge,
                    actual: ObjectKind::Coin,
                }
            );
            assert!(!error.is_transient_for_mempool());

            let (batches, included, retained) = execute_proposal(
                context(1),
                &ChainVerifier::new(),
                vec![Transaction::Kernel(fixture.open.clone())],
                &[],
                MAX_TXS_PER_BLOCK,
                usize::MAX,
                batches,
            )
            .await
            .expect("wrong-kind candidate is a non-fatal proposal drop");
            assert!(included.is_empty());
            assert!(retained.is_empty());
            let batches = execute_all(context(1), &ChainVerifier::new(), &included, &[], batches)
                .await
                .expect("block without dropped open replays");
            assert_eq!(
                batches.get(&collision_id).await.expect("collision read"),
                Some(collision)
            );
            for (index, (owner, value)) in fixture.allocations.iter().enumerate() {
                let id = genesis_object_id(u16::try_from(index).expect("fixture index"));
                assert_eq!(
                    batches.get(&id).await.expect("funding read"),
                    Some(Object::Coin(Coin {
                        owner: *owner,
                        value: *value,
                    }))
                );
            }
        });
    }

    #[test]
    fn open_edge_id_collision_with_edge_is_edge_exists_drop_and_preserves_state() {
        run_qmdb(|runtime| async move {
            let database = database(runtime, "open_edge_collision").await;
            let fixture = kernel_fixture(10).expect("kernel fixture");
            let batches = database.new_batches().await;
            let batches = execute_all(
                context(1),
                &ChainVerifier::new(),
                &[],
                &fixture.allocations,
                batches,
            )
            .await
            .expect("genesis seed");
            let collision_id = edge_object_id(fixture.edge);
            let collision = Object::Edge(crate::domain::test_edge());
            let batches = batches.write(collision_id, Some(collision));
            let verifier = ChainVerifier::new();
            let (batches, error) = apply_transaction(
                batches,
                context(1),
                &verifier,
                &Transaction::Kernel(fixture.open.clone()),
            )
            .await
            .err()
            .expect("edge collision rejects open");
            assert_eq!(
                error,
                ExecutionError::KernelApply {
                    error: ApplyError::EdgeExists { id: fixture.edge },
                }
            );
            assert!(!error.is_transient_for_mempool());

            let (batches, included, retained) = execute_proposal(
                context(1),
                &ChainVerifier::new(),
                vec![Transaction::Kernel(fixture.open.clone())],
                &[],
                MAX_TXS_PER_BLOCK,
                usize::MAX,
                batches,
            )
            .await
            .expect("edge-exists candidate is a non-fatal proposal drop");
            assert!(included.is_empty());
            assert!(retained.is_empty());
            let batches = execute_all(context(1), &ChainVerifier::new(), &included, &[], batches)
                .await
                .expect("block without dropped open replays");
            assert_eq!(
                batches.get(&collision_id).await.expect("collision read"),
                Some(collision)
            );
            for (index, (owner, value)) in fixture.allocations.iter().enumerate() {
                let id = genesis_object_id(u16::try_from(index).expect("fixture index"));
                assert_eq!(
                    batches.get(&id).await.expect("funding read"),
                    Some(Object::Coin(Coin {
                        owner: *owner,
                        value: *value,
                    }))
                );
            }
        });
    }

    #[test]
    fn proposal_byte_budget_stops_admission_and_retains_the_tail() {
        run_qmdb(|runtime| async move {
            let database = database(runtime, "byte_budget").await;
            let fixture = kernel_fixture(10).expect("kernel fixture");
            let open = Transaction::Kernel(fixture.open.clone());
            let close = Transaction::Kernel(fixture.mutual_close.clone());
            let budget = open.encode_size();
            let batches = database.new_batches().await;
            let (batches, included, retained) = execute_proposal(
                context(1),
                &ChainVerifier::new(),
                vec![open, close.clone(), close],
                &fixture.allocations,
                MAX_TXS_PER_BLOCK,
                budget,
                batches,
            )
            .await
            .expect("proposal execution");

            assert_eq!(included.len(), 1);
            assert_eq!(retained.len(), 2);
            assert!(
                matches!(included.first(), Some(Transaction::Kernel(tx)) if tx == &fixture.open)
            );
            assert!(
                retained
                    .iter()
                    .all(|tx| matches!(tx, Transaction::Kernel(tx) if tx == &fixture.mutual_close))
            );
            assert!(matches!(
                batches
                    .get(&edge_object_id(fixture.edge))
                    .await
                    .expect("edge read"),
                Some(Object::Edge(_))
            ));
        });
    }
}
