use super::{BlockKey, ShardMessage, ZodaCommitment, ZodaShard};
use futures::{SinkExt, channel::mpsc};
use hellas_types::PublicKey;
use std::{
    collections::HashMap,
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

pub struct ShardRelay {
    recipients: Mutex<HashMap<PublicKey, Vec<mpsc::UnboundedSender<ShardMessage>>>>,
    validators: Mutex<Vec<PublicKey>>,
    finalized: AtomicBool,
}

impl Default for ShardRelay {
    fn default() -> Self {
        Self::new()
    }
}

impl ShardRelay {
    pub fn new() -> Self {
        Self {
            recipients: Mutex::new(HashMap::new()),
            validators: Mutex::new(Vec::new()),
            finalized: AtomicBool::new(false),
        }
    }

    pub fn declare(&self, public_key: PublicKey) {
        assert!(
            !self.finalized.load(Ordering::Relaxed),
            "validators already finalized"
        );
        let mut validators = self.validators.lock().unwrap();
        if !validators.contains(&public_key) {
            validators.push(public_key);
        }
    }

    pub fn finalize_validators(&self) {
        let mut validators = self.validators.lock().unwrap();
        validators.sort();
        validators.dedup();
        self.finalized.store(true, Ordering::Relaxed);
    }

    pub fn validator_count(&self) -> u16 {
        let validators = self.validators.lock().unwrap();
        u16::try_from(validators.len()).expect("validator count should fit in u16")
    }

    pub fn register(&self, public_key: &PublicKey) -> mpsc::UnboundedReceiver<ShardMessage> {
        let (sender, receiver) = mpsc::unbounded();
        let mut recipients = self.recipients.lock().unwrap();
        recipients
            .entry(public_key.clone())
            .or_default()
            .push(sender);
        receiver
    }

    pub fn validator_index(&self, public_key: &PublicKey) -> Option<u16> {
        if !self.finalized.load(Ordering::Relaxed) {
            return None;
        }
        let validators = self.validators.lock().unwrap();
        validators
            .binary_search(public_key)
            .ok()
            .and_then(|idx| u16::try_from(idx).ok())
    }

    async fn send_to(&self, target: &PublicKey, message: ShardMessage) {
        let channels: Vec<_> = {
            let recipients = self.recipients.lock().unwrap();
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
            let recipients = self.recipients.lock().unwrap();
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
        let validators = self.validators.lock().unwrap().clone();
        if shards.len() != validators.len() {
            warn!(
                digest = ?key.digest,
                shards = shards.len(),
                validators = validators.len(),
                "shard count does not match validator count"
            );
            return;
        }

        for (idx, (target, shard)) in validators.into_iter().zip(shards).enumerate() {
            if &target == proposer {
                continue;
            }
            let Some(shard_index) = u16::try_from(idx).ok() else {
                warn!(index = idx, "validator index too large");
                continue;
            };
            let message = ShardMessage::Initial {
                sender: proposer.clone(),
                key,
                commitment,
                shard,
                shard_index,
            };
            self.send_to(&target, message).await;
        }
    }
}
