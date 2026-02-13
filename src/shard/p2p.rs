use super::codec::WireShardMessage;
use super::protocol::{BlockKey, ShardMessage, ZodaCommitment, ZodaShard};
use super::transport::ShardTransport;
use super::validators::{DistributionError, ValidatorSet};
use crate::trace::Traced;
use commonware_actor::{Actor, ingress, service::ServiceBuilder};
use commonware_p2p::{
    Receiver as P2pReceiver, Recipients, Sender as P2pSender,
    utils::codec::{WrappedReceiver, WrappedSender, wrap},
};
use commonware_runtime::{Handle, Spawner};
use futures::{channel::mpsc, lock::Mutex as AsyncMutex};
use hellas_types::PublicKey;
use std::{
    convert::Infallible,
    sync::{Arc, Mutex, MutexGuard},
};

type WireSender<S> = WrappedSender<S, WireShardMessage>;
type WireReceiver<R> = WrappedReceiver<R, WireShardMessage>;

struct WireIo<S, R>
where
    S: P2pSender<PublicKey = PublicKey>,
    R: P2pReceiver<PublicKey = PublicKey>,
{
    sender: AsyncMutex<WireSender<S>>,
    receiver: Mutex<Option<WireReceiver<R>>>,
}

impl<S, R> WireIo<S, R>
where
    S: P2pSender<PublicKey = PublicKey>,
    R: P2pReceiver<PublicKey = PublicKey>,
{
    fn new(network_sender: S, network_receiver: R) -> Self {
        let (network_sender, network_receiver) = wrap((), network_sender, network_receiver);
        Self {
            sender: AsyncMutex::new(network_sender),
            receiver: Mutex::new(Some(network_receiver)),
        }
    }

    async fn send(&self, recipients: Recipients<PublicKey>, message: WireShardMessage) {
        let mut sender = self.sender.lock().await;
        if let Err(err) = sender.send(recipients, message, false).await {
            warn!(?err, "failed to send shard wire message");
        }
    }

    fn take_receiver(&self) -> Option<WireReceiver<R>> {
        let mut receiver = self.lock_receiver();
        receiver.take()
    }

    fn lock_receiver(&self) -> MutexGuard<'_, Option<WireReceiver<R>>> {
        match self.receiver.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                warn!("network receiver lock poisoned; continuing with inner state");
                poisoned.into_inner()
            }
        }
    }
}

ingress! {
    InboundMailbox,

    tell Dispatch {
        message: ShardMessage,
    };
}

pub struct AuthenticatedShardTransport<S, R>
where
    S: P2pSender<PublicKey = PublicKey>,
    R: P2pReceiver<PublicKey = PublicKey>,
{
    local_subscribers: Mutex<Vec<mpsc::UnboundedSender<Traced<ShardMessage>>>>,
    validators: ValidatorSet,
    me: PublicKey,
    io: WireIo<S, R>,
}

struct InboundActor<S, R>
where
    S: P2pSender<PublicKey = PublicKey>,
    R: P2pReceiver<PublicKey = PublicKey>,
{
    transport: Arc<AuthenticatedShardTransport<S, R>>,
    network_receiver: WireReceiver<R>,
}

impl<S, R> AuthenticatedShardTransport<S, R>
where
    S: P2pSender<PublicKey = PublicKey>,
    R: P2pReceiver<PublicKey = PublicKey>,
{
    const INITIAL_SHARD_REDUNDANCY: usize = 1;

    pub fn new(me: &PublicKey, network_sender: S, network_receiver: R) -> Self {
        Self {
            local_subscribers: Mutex::new(Vec::new()),
            validators: ValidatorSet::new(),
            me: me.clone(),
            io: WireIo::new(network_sender, network_receiver),
        }
    }

    pub fn declare(&self, public_key: &PublicKey) {
        self.validators.declare(public_key);
    }

    pub fn finalize_validators(&self) {
        self.validators.finalize();
    }

    pub fn start<E>(self: Arc<Self>, context: E) -> Handle<()>
    where
        E: Spawner,
    {
        let network_receiver = self.io.take_receiver();
        let Some(network_receiver) = network_receiver else {
            warn!("shard inbound service already started; ignoring duplicate start");
            return context.spawn(|_context| async {});
        };

        let actor = InboundActor {
            transport: self,
            network_receiver,
        };
        let (mailbox, service) = ServiceBuilder::new(actor).build(context);
        service.start_with(mailbox)
    }

    fn dispatch_local(&self, message: ShardMessage) {
        let mut subscribers = self.lock_subscribers();
        let mut idx = 0usize;
        while idx < subscribers.len() {
            if let Err(err) = subscribers[idx].unbounded_send(Traced::capture(message.clone())) {
                warn!(?err, "dropping dead local shard subscriber");
                subscribers.swap_remove(idx);
            } else {
                idx += 1;
            }
        }
    }

    async fn send_wire(&self, recipients: Recipients<PublicKey>, message: WireShardMessage) {
        self.io.send(recipients, message).await;
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
            Err(DistributionError::NotFinalized) => {
                warn!(
                    digest = ?key.digest,
                    "attempted shard distribution before validator finalization"
                );
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
            for _ in 0..Self::INITIAL_SHARD_REDUNDANCY {
                self.send_wire(Recipients::One(target.clone()), wire_message.clone())
                    .await;
            }
        }
    }

    async fn send_to_internal(&self, recipient: &PublicKey, message: ShardMessage) {
        self.send_wire(Recipients::One(recipient.clone()), message.to_wire())
            .await;
    }
}

impl<S, R> ShardTransport for AuthenticatedShardTransport<S, R>
where
    S: P2pSender<PublicKey = PublicKey>,
    R: P2pReceiver<PublicKey = PublicKey>,
{
    fn register(&self, public_key: &PublicKey) -> mpsc::UnboundedReceiver<Traced<ShardMessage>> {
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

    async fn broadcast_except(&self, sender: &PublicKey, message: ShardMessage) {
        self.broadcast_except_internal(sender, message).await;
    }

    async fn send_to(&self, recipient: &PublicKey, message: ShardMessage) {
        self.send_to_internal(recipient, message).await;
    }

    async fn distribute_shards(
        &self,
        proposer: &PublicKey,
        key: BlockKey,
        commitment: ZodaCommitment,
        shards: Vec<ZodaShard>,
    ) {
        self.distribute_shards_internal(proposer, key, commitment, shards)
            .await;
    }
}

impl<S, R> AuthenticatedShardTransport<S, R>
where
    S: P2pSender<PublicKey = PublicKey>,
    R: P2pReceiver<PublicKey = PublicKey>,
{
    fn lock_subscribers(&self) -> MutexGuard<'_, Vec<mpsc::UnboundedSender<Traced<ShardMessage>>>> {
        match self.local_subscribers.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                warn!("local subscriber lock poisoned; continuing with inner state");
                poisoned.into_inner()
            }
        }
    }
}

impl<E, S, R> Actor<E> for InboundActor<S, R>
where
    E: Spawner,
    S: P2pSender<PublicKey = PublicKey>,
    R: P2pReceiver<PublicKey = PublicKey>,
{
    type Mailbox = InboundMailbox;
    type Ingress = InboundMailboxMessage;
    type Error = Infallible;
    type Snapshot = ();
    type Args = InboundMailbox;

    fn snapshot(&self, _args: &Self::Args) -> Self::Snapshot {}

    async fn on_read_write(
        &mut self,
        _context: &mut E,
        _args: &mut InboundMailbox,
        message: InboundMailboxReadWriteMessage,
    ) -> Result<(), Self::Error> {
        match message {
            InboundMailboxReadWriteMessage::Dispatch { message } => {
                self.transport.dispatch_local(message);
            }
        }
        Ok(())
    }

    async fn on_external(
        &mut self,
        _context: &mut E,
        _args: &mut InboundMailbox,
    ) -> Option<InboundMailboxReadWriteMessage> {
        loop {
            let recv_result = self.network_receiver.recv().await;
            let (sender, wire_message) = match recv_result {
                Ok(msg) => msg,
                Err(err) => {
                    warn!(?err, "shard transport receiver closed");
                    return None;
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
            return Some(InboundMailboxReadWriteMessage::Dispatch { message });
        }
    }
}
