#![cfg_attr(not(test), allow(dead_code))]

use super::transport::ShardTransport;
use super::{BlockKey, DistributionError, ShardMessage, ValidatorSet, ZodaCommitment, ZodaShard};
use futures::SinkExt;
use futures::channel::mpsc;
use hellas_types::PublicKey;
use std::{
    collections::HashMap,
    sync::{Mutex, MutexGuard},
};
use std::{future::Future, pin::Pin};

pub struct MockShardTransport {
    recipients: Mutex<HashMap<PublicKey, Vec<mpsc::UnboundedSender<ShardMessage>>>>,
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

    pub fn validator_count(&self) -> u16 {
        self.validators.count()
    }

    pub fn register(&self, public_key: &PublicKey) -> mpsc::UnboundedReceiver<ShardMessage> {
        let (sender, receiver) = mpsc::unbounded();
        let mut recipients = self.lock_recipients();
        recipients
            .entry(public_key.clone())
            .or_default()
            .push(sender);
        receiver
    }

    pub fn validator_index(&self, public_key: &PublicKey) -> Option<u16> {
        self.validators.index(public_key)
    }

    async fn send_to(&self, target: &PublicKey, message: ShardMessage) {
        let channels: Vec<_> = {
            let recipients = self.lock_recipients();
            recipients.get(target).cloned().unwrap_or_default()
        };
        for mut ch in channels {
            if let Err(err) = ch.send(message.clone()).await {
                error!(?err, ?target, "failed to send shard relay message");
            }
        }
    }

    pub async fn broadcast_except(&self, sender: &PublicKey, message: ShardMessage) {
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

    pub async fn distribute_shards(
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
        };

        for (target, shard_index, shard) in assignments {
            let message = ShardMessage::initial(proposer, key, commitment, shard, shard_index);
            self.send_to(&target, message).await;
        }
    }
}

impl ShardTransport for MockShardTransport {
    fn register(&self, public_key: &PublicKey) -> mpsc::UnboundedReceiver<ShardMessage> {
        Self::register(self, public_key)
    }

    fn validator_count(&self) -> u16 {
        Self::validator_count(self)
    }

    fn validator_index(&self, public_key: &PublicKey) -> Option<u16> {
        Self::validator_index(self, public_key)
    }

    fn broadcast_except<'a>(
        &'a self,
        sender: &'a PublicKey,
        message: ShardMessage,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async move { Self::broadcast_except(self, sender, message).await })
    }

    fn distribute_shards<'a>(
        &'a self,
        proposer: &'a PublicKey,
        key: BlockKey,
        commitment: ZodaCommitment,
        shards: Vec<ZodaShard>,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            Self::distribute_shards(self, proposer, key, commitment, shards).await;
        })
    }
}

impl MockShardTransport {
    fn lock_recipients(
        &self,
    ) -> MutexGuard<'_, HashMap<PublicKey, Vec<mpsc::UnboundedSender<ShardMessage>>>> {
        match self.recipients.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                warn!("mock recipients lock poisoned; continuing with inner state");
                poisoned.into_inner()
            }
        }
    }
}
