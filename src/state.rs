use crate::object::{
    Coin, GENESIS_BALANCE, ObjectId, Transaction, genesis_object_id, output_object_id,
};
use commonware_codec::Encode;
use commonware_cryptography::{Hasher, Sha256};
use hellas_types::PublicKey;
use std::collections::HashMap;

pub type ObjectState = HashMap<ObjectId, Coin>;

pub struct BlockExecution {
    pub state: ObjectState,
    pub created: Vec<(ObjectId, Coin)>,
    pub deleted: Vec<ObjectId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionError {
    ObjectNotFound { id: ObjectId },
    InvalidSignature,
    InsufficientBalance { available: u64, requested: u64 },
    ZeroAmount,
    DuplicateInput { id: ObjectId },
    TooFewMergeInputs,
    NonCanonicalMergeInputs,
    MergeOwnerMismatch,
    MergeOverflow,
    OutputCollision { id: ObjectId },
}

pub fn genesis_state(validators: &[PublicKey]) -> BlockExecution {
    let mut state = ObjectState::new();
    let mut created = Vec::new();
    for (idx, validator) in validators.iter().enumerate() {
        let validator_index = u16::try_from(idx).expect("validator index should fit in u16");
        let id = genesis_object_id(validator_index);
        let coin = Coin {
            owner: validator.clone(),
            value: GENESIS_BALANCE,
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

pub fn execute_block(
    parent_state: &ObjectState,
    txs: &[Transaction],
) -> Result<BlockExecution, ExecutionError> {
    let mut state = parent_state.clone();
    let mut created = Vec::new();
    let mut deleted = Vec::new();
    for tx in txs {
        execute_transaction(&mut state, tx, &mut created, &mut deleted)?;
    }
    Ok(BlockExecution {
        state,
        created,
        deleted,
    })
}

fn execute_transaction(
    state: &mut ObjectState,
    tx: &Transaction,
    created: &mut Vec<(ObjectId, Coin)>,
    deleted: &mut Vec<ObjectId>,
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
            deleted.push(*input);

            let recipient_coin = Coin {
                owner: recipient.clone(),
                value: *amount,
            };
            state.insert(recipient_id, recipient_coin.clone());
            created.push((recipient_id, recipient_coin));

            if let Some(change_id) = change_id {
                let change_coin = Coin {
                    owner: coin.owner.clone(),
                    value: change_value,
                };
                state.insert(change_id, change_coin.clone());
                created.push((change_id, change_coin));
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

            let mut owner: Option<PublicKey> = None;
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
            let owner = owner.expect("merge with >=2 inputs must have owner");
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
                deleted.push(*input);
            }
            let merged = Coin {
                owner,
                value: total,
            };
            state.insert(output_id, merged.clone());
            created.push((output_id, merged));
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::Transaction;
    use commonware_cryptography::Signer;
    use commonware_cryptography::sha256::Digest;
    use hellas_types::PrivateKey;

    fn keys(n: usize) -> Vec<PrivateKey> {
        (0..n)
            .map(|i| PrivateKey::from_seed(i as u64 + 1))
            .collect()
    }

    fn sorted_public_keys(n: usize) -> Vec<PublicKey> {
        let mut pks: Vec<_> = keys(n).into_iter().map(|k| k.public_key()).collect();
        pks.sort();
        pks
    }

    #[test]
    fn genesis_state_creates_coins() {
        let validators = sorted_public_keys(4);
        let exec = genesis_state(&validators);
        assert_eq!(exec.state.len(), 4);
        assert_eq!(exec.created.len(), 4);
        assert!(exec.deleted.is_empty());
        for (idx, pk) in validators.iter().enumerate() {
            let id = genesis_object_id(u16::try_from(idx).unwrap());
            let coin = exec.state.get(&id).expect("genesis coin");
            assert_eq!(coin.owner, *pk);
            assert_eq!(coin.value, GENESIS_BALANCE);
        }
    }

    #[test]
    fn genesis_state_is_deterministic_for_same_sorted_input() {
        let validators = sorted_public_keys(6);
        let a = genesis_state(&validators);
        let b = genesis_state(&validators);
        assert_eq!(a.state, b.state);
    }

    #[test]
    fn transfer_debits_and_credits() {
        let keys = keys(2);
        let sender = keys[0].public_key();
        let recipient = keys[1].public_key();
        let input = Digest::from([1; 32]);
        let mut parent = ObjectState::new();
        parent.insert(
            input,
            Coin {
                owner: sender.clone(),
                value: 100,
            },
        );

        let tx = Transaction::transfer(&keys[0], input, recipient.clone(), 40);
        let exec = execute_block(&parent, std::slice::from_ref(&tx)).expect("execute");
        assert!(!exec.state.contains_key(&input));
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
    fn transfer_exact_amount_has_no_change() {
        let keys = keys(2);
        let sender = keys[0].public_key();
        let recipient = keys[1].public_key();
        let input = Digest::from([2; 32]);
        let mut parent = ObjectState::new();
        parent.insert(
            input,
            Coin {
                owner: sender,
                value: 100,
            },
        );

        let tx = Transaction::transfer(&keys[0], input, recipient, 100);
        let exec = execute_block(&parent, std::slice::from_ref(&tx)).expect("execute");
        assert_eq!(exec.created.len(), 1);
        assert_eq!(exec.created[0].1.value, 100);
    }

    #[test]
    fn transfer_self_splits_coin() {
        let keys = keys(1);
        let owner = keys[0].public_key();
        let input = Digest::from([3; 32]);
        let mut parent = ObjectState::new();
        parent.insert(
            input,
            Coin {
                owner: owner.clone(),
                value: 100,
            },
        );
        let tx = Transaction::transfer(&keys[0], input, owner.clone(), 20);
        let exec = execute_block(&parent, std::slice::from_ref(&tx)).expect("execute");
        assert_eq!(exec.created.len(), 2);
        assert!(exec.created.iter().all(|(_, coin)| coin.owner == owner));
    }

    #[test]
    fn insufficient_balance_rejected() {
        let keys = keys(2);
        let input = Digest::from([4; 32]);
        let mut parent = ObjectState::new();
        parent.insert(
            input,
            Coin {
                owner: keys[0].public_key(),
                value: 10,
            },
        );
        let tx = Transaction::transfer(&keys[0], input, keys[1].public_key(), 11);
        assert!(matches!(
            execute_block(&parent, std::slice::from_ref(&tx)),
            Err(ExecutionError::InsufficientBalance { .. })
        ));
    }

    #[test]
    fn zero_amount_rejected() {
        let keys = keys(2);
        let input = Digest::from([5; 32]);
        let mut parent = ObjectState::new();
        parent.insert(
            input,
            Coin {
                owner: keys[0].public_key(),
                value: 10,
            },
        );
        let tx = Transaction::transfer(&keys[0], input, keys[1].public_key(), 0);
        assert!(matches!(
            execute_block(&parent, std::slice::from_ref(&tx)),
            Err(ExecutionError::ZeroAmount)
        ));
    }

    #[test]
    fn invalid_signature_rejected() {
        let keys = keys(2);
        let input = Digest::from([6; 32]);
        let mut parent = ObjectState::new();
        parent.insert(
            input,
            Coin {
                owner: keys[0].public_key(),
                value: 10,
            },
        );
        let tx = Transaction::transfer(&keys[1], input, keys[1].public_key(), 1);
        assert!(matches!(
            execute_block(&parent, std::slice::from_ref(&tx)),
            Err(ExecutionError::InvalidSignature)
        ));
    }

    #[test]
    fn nonexistent_input_rejected() {
        let keys = keys(2);
        let tx = Transaction::transfer(&keys[0], Digest::from([7; 32]), keys[1].public_key(), 1);
        assert!(matches!(
            execute_block(&ObjectState::new(), std::slice::from_ref(&tx)),
            Err(ExecutionError::ObjectNotFound { .. })
        ));
    }

    #[test]
    fn merge_combines_values() {
        let keys = keys(1);
        let owner = keys[0].public_key();
        let input_a = Digest::from([8; 32]);
        let input_b = Digest::from([9; 32]);
        let mut parent = ObjectState::new();
        parent.insert(
            input_a,
            Coin {
                owner: owner.clone(),
                value: 7,
            },
        );
        parent.insert(
            input_b,
            Coin {
                owner: owner.clone(),
                value: 13,
            },
        );

        let tx = Transaction::merge(&keys[0], vec![input_b, input_a]);
        let exec = execute_block(&parent, std::slice::from_ref(&tx)).expect("execute");
        assert_eq!(exec.created.len(), 1);
        assert_eq!(exec.created[0].1.owner, owner);
        assert_eq!(exec.created[0].1.value, 20);
        assert_eq!(exec.deleted.len(), 2);
    }

    #[test]
    fn merge_different_owners_rejected() {
        let keys = keys(2);
        let input_a = Digest::from([10; 32]);
        let input_b = Digest::from([11; 32]);
        let mut parent = ObjectState::new();
        parent.insert(
            input_a,
            Coin {
                owner: keys[0].public_key(),
                value: 7,
            },
        );
        parent.insert(
            input_b,
            Coin {
                owner: keys[1].public_key(),
                value: 13,
            },
        );

        let tx = Transaction::merge(&keys[0], vec![input_a, input_b]);
        assert!(matches!(
            execute_block(&parent, std::slice::from_ref(&tx)),
            Err(ExecutionError::MergeOwnerMismatch)
        ));
    }

    #[test]
    fn merge_too_few_inputs_rejected() {
        let keys = keys(1);
        let tx = Transaction::merge(&keys[0], vec![Digest::from([12; 32])]);
        assert!(matches!(
            execute_block(&ObjectState::new(), std::slice::from_ref(&tx)),
            Err(ExecutionError::TooFewMergeInputs)
        ));
    }

    #[test]
    fn duplicate_input_rejected() {
        let keys = keys(1);
        let owner = keys[0].public_key();
        let input = Digest::from([13; 32]);
        let mut parent = ObjectState::new();
        parent.insert(input, Coin { owner, value: 5 });
        let tx = Transaction::MergeCoin {
            inputs: vec![input, input],
            signature: keys[0].sign(
                crate::object::MERGE_NAMESPACE,
                &crate::object::merge_signed_bytes(&[input, input]),
            ),
        };
        assert!(matches!(
            execute_block(&parent, std::slice::from_ref(&tx)),
            Err(ExecutionError::DuplicateInput { .. })
        ));
    }

    #[test]
    fn merge_overflow_rejected() {
        let keys = keys(1);
        let owner = keys[0].public_key();
        let input_a = Digest::from([14; 32]);
        let input_b = Digest::from([15; 32]);
        let mut parent = ObjectState::new();
        parent.insert(
            input_a,
            Coin {
                owner: owner.clone(),
                value: u64::MAX,
            },
        );
        parent.insert(input_b, Coin { owner, value: 1 });
        let tx = Transaction::merge(&keys[0], vec![input_a, input_b]);
        assert!(matches!(
            execute_block(&parent, std::slice::from_ref(&tx)),
            Err(ExecutionError::MergeOverflow)
        ));
    }

    #[test]
    fn output_collision_is_checked() {
        let keys = keys(2);
        let sender = keys[0].public_key();
        let recipient = keys[1].public_key();
        let input = Digest::from([16; 32]);
        let tx = Transaction::transfer(&keys[0], input, recipient, 10);
        let collision_id = output_object_id(&Sha256::hash(&tx.encode()), 0);

        let mut parent = ObjectState::new();
        parent.insert(
            input,
            Coin {
                owner: sender,
                value: 10,
            },
        );
        parent.insert(
            collision_id,
            Coin {
                owner: keys[1].public_key(),
                value: 1,
            },
        );
        assert!(matches!(
            execute_block(&parent, std::slice::from_ref(&tx)),
            Err(ExecutionError::OutputCollision { .. })
        ));
    }

    #[test]
    fn non_canonical_merge_inputs_rejected() {
        let keys = keys(1);
        let owner = keys[0].public_key();
        let input_a = Digest::from([17; 32]);
        let input_b = Digest::from([18; 32]);
        let mut parent = ObjectState::new();
        parent.insert(
            input_a,
            Coin {
                owner: owner.clone(),
                value: 2,
            },
        );
        parent.insert(input_b, Coin { owner, value: 3 });
        let unsorted = [input_b, input_a];
        let tx = Transaction::MergeCoin {
            inputs: unsorted.to_vec(),
            signature: keys[0].sign(
                crate::object::MERGE_NAMESPACE,
                &crate::object::merge_signed_bytes(&unsorted),
            ),
        };
        assert!(matches!(
            execute_block(&parent, std::slice::from_ref(&tx)),
            Err(ExecutionError::NonCanonicalMergeInputs)
        ));
    }
}
