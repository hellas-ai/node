#![cfg_attr(not(test), allow(dead_code))]

use super::protocol::{BlockKey, ShardMessage, ZodaCommitment, ZodaShard};
use super::transport::ShardTransport;
use super::validators::{DistributionError, ValidatorSet};
use crate::trace::Traced;
use futures::SinkExt;
use futures::channel::mpsc;
use hellas_types::PublicKey;
use std::{
    collections::HashMap,
    sync::{Mutex, MutexGuard},
};

pub struct MockShardTransport {
    recipients: Mutex<HashMap<PublicKey, Vec<mpsc::UnboundedSender<Traced<ShardMessage>>>>>,
    validators: ValidatorSet,
}

impl Default for MockShardTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl MockShardTransport {
    pub fn new() -> Self {
        Self {
            recipients: Mutex::new(HashMap::new()),
            validators: ValidatorSet::new(),
        }
    }

    pub fn declare(&self, public_key: &PublicKey) {
        self.validators.declare(public_key);
    }

    pub fn finalize_validators(&self) {
        self.validators.finalize();
    }

    async fn send_to(&self, target: &PublicKey, message: ShardMessage) {
        let channels: Vec<_> = {
            let recipients = self.lock_recipients();
            recipients.get(target).cloned().unwrap_or_default()
        };
        for mut ch in channels {
            if let Err(err) = ch.send(Traced::capture(message.clone())).await {
                error!(?err, ?target, "failed to send shard relay message");
            }
        }
    }
}

impl ShardTransport for MockShardTransport {
    fn register(&self, public_key: &PublicKey) -> mpsc::UnboundedReceiver<Traced<ShardMessage>> {
        let (sender, receiver) = mpsc::unbounded();
        let mut recipients = self.lock_recipients();
        recipients
            .entry(public_key.clone())
            .or_default()
            .push(sender);
        receiver
    }

    fn validator_count(&self) -> u16 {
        self.validators.count()
    }

    fn validator_index(&self, public_key: &PublicKey) -> Option<u16> {
        self.validators.index(public_key)
    }

    async fn broadcast_except(&self, sender: &PublicKey, message: ShardMessage) {
        let targets: Vec<_> = {
            let recipients = self.lock_recipients();
            recipients
                .keys()
                .filter(|pk| *pk != sender)
                .cloned()
                .collect()
        };
        for target in targets {
            self.send_to(&target, message.clone()).await;
        }
    }

    async fn distribute_shards(
        &self,
        proposer: &PublicKey,
        key: BlockKey,
        commitment: ZodaCommitment,
        shards: Vec<ZodaShard>,
    ) {
        let assignments = match self.validators.assign_shards(proposer, shards) {
            Ok(assignments) => assignments,
            Err(DistributionError::CountMismatch { shards, validators }) => {
                warn!(
                    digest = ?key.digest,
                    shards,
                    validators,
                    "shard count does not match validator count"
                );
                return;
            }
            Err(DistributionError::IndexTooLarge { index }) => {
                warn!(digest = ?key.digest, index, "validator index too large");
                return;
            }
            Err(DistributionError::NotFinalized) => {
                warn!(
                    digest = ?key.digest,
                    "attempted shard distribution before validator finalization"
                );
                return;
            }
        };

        for (target, shard_index, shard) in assignments {
            let message = ShardMessage::initial(proposer, key, commitment, shard, shard_index);
            self.send_to(&target, message).await;
        }
    }
}

impl MockShardTransport {
    fn lock_recipients(
        &self,
    ) -> MutexGuard<'_, HashMap<PublicKey, Vec<mpsc::UnboundedSender<Traced<ShardMessage>>>>> {
        match self.recipients.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                warn!("mock recipients lock poisoned; continuing with inner state");
                poisoned.into_inner()
            }
        }
    }
}
