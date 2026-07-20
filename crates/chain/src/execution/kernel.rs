use super::store::UtxoDatabase;
use crate::domain::{
    Address, Coin, Object, ObjectId, ObjectKind, SettlementKey, Transaction, genesis_object_id,
    output_object_id,
};
use commonware_codec::Encode;
use commonware_consensus::types::Height;
use commonware_cryptography::{Hasher, Sha256};
use commonware_glue::stateful::db::DatabaseSet;
use commonware_runtime::{Clock, Metrics, Storage};
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
    #[error("kernel transactions cannot execute before M4")]
    KernelTransactionUnsupported,
}

impl ExecutionError {
    pub fn is_transient_for_mempool(&self) -> bool {
        matches!(self, Self::ObjectNotFound { .. })
    }

    pub fn is_fatal_storage(&self) -> bool {
        matches!(self, Self::Storage(_))
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

pub async fn execute_all<E>(
    parent_height: Height,
    txs: &[Transaction],
    genesis_allocations: &[(SettlementKey, u64)],
    batches: Batch<E>,
) -> Result<Batch<E>, ExecutionError>
where
    E: Storage + Clock + Metrics + Send + Sync + 'static,
{
    let mut batches = maybe_seed_genesis(parent_height, genesis_allocations, batches);
    for tx in txs {
        let next = apply_transaction(batches, tx)
            .await
            .map_err(|(_, err)| err)?;
        batches = next;
    }
    Ok(batches)
}

pub async fn execute_proposal<E>(
    parent_height: Height,
    candidates: Vec<Transaction>,
    genesis_allocations: &[(SettlementKey, u64)],
    max_txs: usize,
    batches: Batch<E>,
) -> Result<(Batch<E>, Vec<Transaction>, Vec<Transaction>), ExecutionError>
where
    E: Storage + Clock + Metrics + Send + Sync + 'static,
{
    let mut batches = maybe_seed_genesis(parent_height, genesis_allocations, batches);
    let mut included = Vec::new();
    let mut retained = Vec::new();

    for tx in candidates {
        if included.len() >= max_txs {
            retained.push(tx);
            continue;
        }

        match apply_transaction(batches, &tx).await {
            Ok(next) => {
                batches = next;
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
    parent_height: Height,
    genesis_allocations: &[(SettlementKey, u64)],
    mut batches: Batch<E>,
) -> Batch<E>
where
    E: Storage + Clock + Metrics + Send + Sync + 'static,
{
    if parent_height != Height::zero() {
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

async fn apply_transaction<E>(
    mut batches: Batch<E>,
    tx: &Transaction,
) -> Result<Batch<E>, (Batch<E>, ExecutionError)>
where
    E: Storage + Clock + Metrics + Send + Sync + 'static,
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
        Transaction::Kernel(_) => Err((batches, ExecutionError::KernelTransactionUnsupported)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
