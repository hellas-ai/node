use super::transport::ShardTransport;
use super::{
    BlockKey, DistributionError, ShardMessage, ValidatorSet, WireShardMessage, ZodaCommitment,
    ZodaShard,
};
use commonware_p2p::{
    Receiver as P2pReceiver, Recipients, Sender as P2pSender,
    utils::codec::{WrappedReceiver, WrappedSender, wrap},
};
use commonware_runtime::{Handle, Spawner};
use futures::{SinkExt, channel::mpsc, lock::Mutex as AsyncMutex};
use hellas_types::PublicKey;
use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard},
};

pub struct AuthenticatedShardTransport<S, R>
where
    S: P2pSender<PublicKey = PublicKey>,
    R: P2pReceiver<PublicKey = PublicKey>,
{
    local_subscribers: Mutex<Vec<mpsc::UnboundedSender<ShardMessage>>>,
    validators: ValidatorSet,
    me: PublicKey,
    network_sender: AsyncMutex<WrappedSender<S, WireShardMessage>>,
    network_receiver: AsyncMutex<WrappedReceiver<R, WireShardMessage>>,
}

impl<S, R> AuthenticatedShardTransport<S, R>
where
    S: P2pSender<PublicKey = PublicKey>,
    R: P2pReceiver<PublicKey = PublicKey>,
{
    pub fn new(me: PublicKey, network_sender: S, network_receiver: R) -> Self {
        let (network_sender, network_receiver) = wrap((), network_sender, network_receiver);
        Self {
            local_subscribers: Mutex::new(Vec::new()),
            validators: ValidatorSet::new(),
            me,
            network_sender: AsyncMutex::new(network_sender),
            network_receiver: AsyncMutex::new(network_receiver),
        }
    }

    pub fn declare(&self, public_key: PublicKey) {
        self.validators.declare(public_key);
    }

    pub fn finalize_validators(&self) {
        self.validators.finalize();
    }

    pub fn start<E>(self: Arc<Self>, context: E) -> Handle<()>
    where
        E: Spawner,
    {
        context.spawn(move |_ctx| async move {
            self.run_inbound().await;
        })
    }

    async fn run_inbound(&self) {
        loop {
            let recv_result = {
                let mut receiver = self.network_receiver.lock().await;
                receiver.recv().await
            };
            let (sender, wire_message) = match recv_result {
                Ok(msg) => msg,
                Err(err) => {
                    warn!(?err, "shard transport receiver closed");
                    break;
                }
            };
            let wire_message = match wire_message {
                Ok(wire_message) => wire_message,
                Err(err) => {
                    warn!(?sender, ?err, "failed to decode wire shard message");
                    continue;
                }
            };
            let message = wire_message.with_sender(sender);
            self.dispatch_local(message).await;
        }
    }

    async fn dispatch_local(&self, message: ShardMessage) {
        let channels: Vec<_> = {
            let subscribers = self.lock_subscribers();
            subscribers.clone()
        };
        for mut ch in channels {
            if let Err(err) = ch.send(message.clone()).await {
                error!(?err, "failed to forward shard message to local app");
            }
        }
    }

    async fn send_wire(&self, recipients: Recipients<PublicKey>, message: WireShardMessage) {
        let mut sender = self.network_sender.lock().await;
        if let Err(err) = sender.send(recipients, message, false).await {
            warn!(?err, "failed to send shard wire message");
        }
    }

    async fn broadcast_except_internal(&self, sender: &PublicKey, message: ShardMessage) {
        if message.sender() != sender {
            warn!("broadcast sender mismatch; dropping shard message");
            return;
        }

        let targets = self.validators.others(sender);
        if targets.is_empty() {
            return;
        }
        self.send_wire(Recipients::Some(targets), message.to_wire())
            .await;
    }

    async fn distribute_shards_internal(
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
            let wire_message = WireShardMessage::Initial {
                key,
                commitment,
                shard,
                shard_index,
            };
            self.send_wire(Recipients::One(target), wire_message).await;
        }
    }
}

impl<S, R> ShardTransport for AuthenticatedShardTransport<S, R>
where
    S: P2pSender<PublicKey = PublicKey>,
    R: P2pReceiver<PublicKey = PublicKey>,
{
    fn register(&self, public_key: &PublicKey) -> mpsc::UnboundedReceiver<ShardMessage> {
        if public_key != &self.me {
            warn!(
                requested = ?public_key,
                local = ?self.me,
                "authenticated transport only supports local subscription for self"
            );
            let (_sender, receiver) = mpsc::unbounded();
            return receiver;
        }
        let (sender, receiver) = mpsc::unbounded();
        let mut subscribers = self.lock_subscribers();
        subscribers.push(sender);
        receiver
    }

    fn validator_count(&self) -> u16 {
        self.validators.count()
    }

    fn validator_index(&self, public_key: &PublicKey) -> Option<u16> {
        self.validators.index(public_key)
    }

    fn broadcast_except<'a>(
        &'a self,
        sender: &'a PublicKey,
        message: ShardMessage,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async move { self.broadcast_except_internal(sender, message).await })
    }

    fn distribute_shards<'a>(
        &'a self,
        proposer: &'a PublicKey,
        key: BlockKey,
        commitment: ZodaCommitment,
        shards: Vec<ZodaShard>,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            self.distribute_shards_internal(proposer, key, commitment, shards)
                .await;
        })
    }
}

impl<S, R> AuthenticatedShardTransport<S, R>
where
    S: P2pSender<PublicKey = PublicKey>,
    R: P2pReceiver<PublicKey = PublicKey>,
{
    fn lock_subscribers(&self) -> MutexGuard<'_, Vec<mpsc::UnboundedSender<ShardMessage>>> {
        match self.local_subscribers.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                warn!("local subscriber lock poisoned; continuing with inner state");
                poisoned.into_inner()
            }
        }
    }
}
