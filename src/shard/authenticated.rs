use super::{BlockKey, ShardMessage, ShardTransport, WireShardMessage, ZodaCommitment, ZodaShard};
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
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

pub struct AuthenticatedShardTransport<S, R>
where
    S: P2pSender<PublicKey = PublicKey>,
    R: P2pReceiver<PublicKey = PublicKey>,
{
    local_subscribers: Mutex<Vec<mpsc::UnboundedSender<ShardMessage>>>,
    validators: Mutex<Vec<PublicKey>>,
    finalized: AtomicBool,
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
            validators: Mutex::new(Vec::new()),
            finalized: AtomicBool::new(false),
            me,
            network_sender: AsyncMutex::new(network_sender),
            network_receiver: AsyncMutex::new(network_receiver),
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
            let subscribers = self.local_subscribers.lock().unwrap();
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

        let targets: Vec<_> = {
            let validators = self.validators.lock().unwrap();
            validators
                .iter()
                .filter(|pk| *pk != sender)
                .cloned()
                .collect()
        };
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
        assert_eq!(
            public_key, &self.me,
            "authenticated transport only supports local subscription for self"
        );
        let (sender, receiver) = mpsc::unbounded();
        let mut subscribers = self.local_subscribers.lock().unwrap();
        subscribers.push(sender);
        receiver
    }

    fn validator_count(&self) -> u16 {
        let validators = self.validators.lock().unwrap();
        u16::try_from(validators.len()).expect("validator count should fit in u16")
    }

    fn validator_index(&self, public_key: &PublicKey) -> Option<u16> {
        if !self.finalized.load(Ordering::Relaxed) {
            return None;
        }
        let validators = self.validators.lock().unwrap();
        validators
            .binary_search(public_key)
            .ok()
            .and_then(|idx| u16::try_from(idx).ok())
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
