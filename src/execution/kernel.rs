use commonware_codec::Encode;
use commonware_cryptography::{Hasher, Sha256};
use hellas_types::{Address, Coin, ObjectId, Transaction, genesis_object_id, output_object_id};
use std::collections::HashMap;
use thiserror::Error;

pub(crate) type ObjectState = HashMap<ObjectId, Coin>;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct StateDiff {
    pub(crate) created: Vec<(ObjectId, Coin)>,
    pub(crate) deleted: Vec<ObjectId>,
}

pub(crate) struct BlockExecution {
    pub(crate) state: ObjectState,
    pub(crate) created: Vec<(ObjectId, Coin)>,
    pub(crate) deleted: Vec<ObjectId>,
}

impl BlockExecution {
    pub(crate) fn diff(&self) -> StateDiff {
        StateDiff {
            created: self.created.clone(),
            deleted: self.deleted.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ExecutionError {
    #[error("object not found: {id:?}")]
    ObjectNotFound { id: ObjectId },
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
}

#[must_use = "genesis execution must be captured to initialize state deterministically"]
pub fn genesis_state(allocations: &[(Address, u64)]) -> BlockExecution {
    let mut state = ObjectState::new();
    let mut created = Vec::new();
    for (idx, (owner, balance)) in allocations.iter().enumerate() {
        let Ok(validator_index) = u16::try_from(idx) else {
            warn!(
                index = idx,
                "validator index overflow; truncating genesis allocation"
            );
            break;
        };
        let id = genesis_object_id(validator_index);
        let coin = Coin {
            owner: owner.clone(),
            value: *balance,
        };
        state.insert(id, coin.clone());
        created.push((id, coin));
    }
    BlockExecution {
        state,
        created,
        deleted: Vec::new(),
    }
}

#[must_use = "block execution result must be applied or rejected explicitly"]
pub fn execute_block(
    parent_state: &ObjectState,
    txs: &[Transaction],
) -> Result<BlockExecution, ExecutionError> {
    let mut state = parent_state.clone();
    let mut created = Vec::new();
    let mut deleted = Vec::new();
    for tx in txs {
        execute_transaction_with_tracking(&mut state, tx, Some(&mut created), Some(&mut deleted))?;
    }
    Ok(BlockExecution {
        state,
        created,
        deleted,
    })
}

pub(crate) fn execute_transaction(
    state: &mut ObjectState,
    tx: &Transaction,
) -> Result<(), ExecutionError> {
    execute_transaction_with_tracking(state, tx, None, None)
}

pub(crate) fn apply_diff(state: &mut ObjectState, diff: &StateDiff) {
    for object_id in &diff.deleted {
        state.remove(object_id);
    }
    for (object_id, coin) in &diff.created {
        state.insert(*object_id, coin.clone());
    }
}

fn execute_transaction_with_tracking(
    state: &mut ObjectState,
    tx: &Transaction,
    mut created: Option<&mut Vec<(ObjectId, Coin)>>,
    mut deleted: Option<&mut Vec<ObjectId>>,
) -> Result<(), ExecutionError> {
    match tx {
        Transaction::Transfer {
            input,
            recipient,
            amount,
            ..
        } => {
            let coin = state
                .get(input)
                .cloned()
                .ok_or(ExecutionError::ObjectNotFound { id: *input })?;
            if !tx.verify_signature(&coin.owner) {
                return Err(ExecutionError::InvalidSignature);
            }
            if *amount == 0 {
                return Err(ExecutionError::ZeroAmount);
            }
            if *amount > coin.value {
                return Err(ExecutionError::InsufficientBalance {
                    available: coin.value,
                    requested: *amount,
                });
            }

            let tx_digest = Sha256::hash(&tx.encode());
            let recipient_id = output_object_id(&tx_digest, 0);
            if state.contains_key(&recipient_id) {
                return Err(ExecutionError::OutputCollision { id: recipient_id });
            }

            let change_value = coin.value - amount;
            let change_id = if change_value > 0 {
                let id = output_object_id(&tx_digest, 1);
                if id == recipient_id || state.contains_key(&id) {
                    return Err(ExecutionError::OutputCollision { id });
                }
                Some(id)
            } else {
                None
            };

            state.remove(input);
            if let Some(deleted) = deleted.as_mut() {
                deleted.push(*input);
            }

            let recipient_coin = Coin {
                owner: recipient.clone(),
                value: *amount,
            };
            state.insert(recipient_id, recipient_coin.clone());
            if let Some(created) = created.as_mut() {
                created.push((recipient_id, recipient_coin));
            }

            if let Some(change_id) = change_id {
                let change_coin = Coin {
                    owner: coin.owner.clone(),
                    value: change_value,
                };
                state.insert(change_id, change_coin.clone());
                if let Some(created) = created.as_mut() {
                    created.push((change_id, change_coin));
                }
            }
            Ok(())
        }
        Transaction::MergeCoin { inputs, .. } => {
            if inputs.len() < 2 {
                return Err(ExecutionError::TooFewMergeInputs);
            }
            for pair in inputs.windows(2) {
                if pair[0] == pair[1] {
                    return Err(ExecutionError::DuplicateInput { id: pair[0] });
                }
                if pair[0] > pair[1] {
                    return Err(ExecutionError::NonCanonicalMergeInputs);
                }
            }

            let mut owner: Option<Address> = None;
            let mut total = 0u64;
            for input in inputs {
                let coin = state
                    .get(input)
                    .cloned()
                    .ok_or(ExecutionError::ObjectNotFound { id: *input })?;
                if let Some(expected_owner) = owner.as_ref() {
                    if &coin.owner != expected_owner {
                        return Err(ExecutionError::MergeOwnerMismatch);
                    }
                } else {
                    owner = Some(coin.owner.clone());
                }
                total = total
                    .checked_add(coin.value)
                    .ok_or(ExecutionError::MergeOverflow)?;
            }
            let Some(owner) = owner else {
                return Err(ExecutionError::MergeOwnerMismatch);
            };
            if !tx.verify_signature(&owner) {
                return Err(ExecutionError::InvalidSignature);
            }

            let tx_digest = Sha256::hash(&tx.encode());
            let output_id = output_object_id(&tx_digest, 0);
            if state.contains_key(&output_id) {
                return Err(ExecutionError::OutputCollision { id: output_id });
            }

            for input in inputs {
                state.remove(input);
                if let Some(deleted) = deleted.as_mut() {
                    deleted.push(*input);
                }
            }
            let merged = Coin {
                owner,
                value: total,
            };
            state.insert(output_id, merged.clone());
            if let Some(created) = created.as_mut() {
                created.push((output_id, merged));
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::sha256::Digest;
    use hellas_types::{
        Transaction, addr_from_signing_key, merge_challenge, mock_webauthn_sign,
        secp256r1_key_from_seed, transfer_challenge,
    };

    fn key(seed: u64) -> p256::ecdsa::SigningKey {
        secp256r1_key_from_seed(seed)
    }

    fn addr(key: &p256::ecdsa::SigningKey) -> Address {
        addr_from_signing_key(key)
    }

    fn signed_transfer(
        key: &p256::ecdsa::SigningKey,
        input: ObjectId,
        recipient: Address,
        amount: u64,
    ) -> Transaction {
        let challenge = transfer_challenge(&input, &recipient, amount);
        Transaction::Transfer {
            input,
            recipient,
            amount,
            signature: mock_webauthn_sign(key, &challenge),
        }
    }

    fn signed_merge(key: &p256::ecdsa::SigningKey, mut inputs: Vec<ObjectId>) -> Transaction {
        inputs.sort();
        let challenge = merge_challenge(&inputs);
        Transaction::MergeCoin {
            inputs,
            signature: mock_webauthn_sign(key, &challenge),
        }
    }

    #[test]
    fn genesis_state_creates_coins() {
        let a = addr(&key(1));
        let b = addr(&key(2));
        let allocations = vec![(a.clone(), 100), (b.clone(), 250), (a, 7), (b, 9)];
        let exec = genesis_state(&allocations);
        assert_eq!(exec.created.len(), 4);
        assert!(exec.deleted.is_empty());
        assert_eq!(exec.state.len(), 4);
    }

    #[test]
    fn transfer_debits_and_credits() {
        let sender_key = key(10);
        let sender = addr(&sender_key);
        let recipient = addr(&key(11));
        let input = Digest::from([1; 32]);
        let mut parent = ObjectState::new();
        parent.insert(
            input,
            Coin {
                owner: sender.clone(),
                value: 100,
            },
        );

        let tx = signed_transfer(&sender_key, input, recipient.clone(), 40);
        let exec = execute_block(&parent, std::slice::from_ref(&tx)).expect("execute");
        assert_eq!(exec.deleted, vec![input]);
        assert_eq!(exec.created.len(), 2);
        let total: u64 = exec.created.iter().map(|(_, coin)| coin.value).sum();
        assert_eq!(total, 100);
        assert_eq!(exec.created[0].1.owner, recipient);
        assert_eq!(exec.created[0].1.value, 40);
        assert_eq!(exec.created[1].1.owner, sender);
        assert_eq!(exec.created[1].1.value, 60);
    }

    #[test]
    fn invalid_signature_rejected() {
        let sender_key = key(10);
        let wrong_key = key(11);
        let sender = addr(&sender_key);
        let recipient = addr(&key(12));
        let input = Digest::from([1; 32]);
        let mut parent = ObjectState::new();
        parent.insert(
            input,
            Coin {
                owner: sender,
                value: 100,
            },
        );

        let tx = signed_transfer(&wrong_key, input, recipient, 50);
        assert!(matches!(
            execute_block(&parent, std::slice::from_ref(&tx)),
            Err(ExecutionError::InvalidSignature)
        ));
    }

    #[test]
    fn merge_combines_values() {
        let owner_key = key(20);
        let owner = addr(&owner_key);
        let in1 = Digest::from([1; 32]);
        let in2 = Digest::from([2; 32]);
        let mut parent = ObjectState::new();
        parent.insert(
            in1,
            Coin {
                owner: owner.clone(),
                value: 7,
            },
        );
        parent.insert(
            in2,
            Coin {
                owner: owner.clone(),
                value: 13,
            },
        );

        let tx = signed_merge(&owner_key, vec![in2, in1]);
        let exec = execute_block(&parent, std::slice::from_ref(&tx)).expect("execute");
        assert_eq!(exec.created.len(), 1);
        assert_eq!(exec.created[0].1.owner, owner);
        assert_eq!(exec.created[0].1.value, 20);
        assert_eq!(exec.deleted.len(), 2);
    }

    #[test]
    fn non_canonical_merge_inputs_rejected() {
        let owner_key = key(30);
        let owner = addr(&owner_key);
        let in1 = Digest::from([1; 32]);
        let in2 = Digest::from([2; 32]);
        let mut parent = ObjectState::new();
        parent.insert(
            in1,
            Coin {
                owner: owner.clone(),
                value: 7,
            },
        );
        parent.insert(in2, Coin { owner, value: 13 });

        let challenge = merge_challenge(&[in2, in1]);
        let tx = Transaction::MergeCoin {
            inputs: vec![in2, in1],
            signature: mock_webauthn_sign(&owner_key, &challenge),
        };
        assert!(matches!(
            execute_block(&parent, std::slice::from_ref(&tx)),
            Err(ExecutionError::NonCanonicalMergeInputs)
        ));
    }
}
