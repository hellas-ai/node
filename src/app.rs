use crate::shard::{
    BlockKey, CodingImpl, ShardEffect, ShardMessage, ShardReconstructor, ShardTransport,
    ZodaCommitment, ZodaShard, coding_config,
};
use bytes::Bytes;
use commonware_codec::{DecodeExt, Encode};
use commonware_coding::Scheme as CodingScheme;
use commonware_consensus::{
    Automaton as Au, Relay as Re, Reporter as Rp,
    types::{Epoch, Round, View},
};
use commonware_cryptography::{Hasher, Sha256, sha256::Digest};
use commonware_macros::select_loop;
use commonware_parallel::Sequential;
use commonware_runtime::{Clock, ContextCell, Handle, Spawner, spawn_cell};
use commonware_utils::{
    SystemTimeExt,
    channels::fallible::{AsyncFallibleExt, OneshotExt},
};
use futures::{
    StreamExt,
    channel::{mpsc, oneshot},
};
use hellas_types::{Activity as HActivity, Context, PublicKey};
use std::collections::{HashMap, VecDeque};

/// Milliseconds in the future to allow for block timestamps.
const SYNCHRONY_BOUND: u64 = 500;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PayloadValidationError {
    DigestMismatch {
        computed: Digest,
        expected: Digest,
    },
    InvalidEncoding,
    RoundMismatch {
        parsed: Round,
        expected: Round,
    },
    ParentMismatch {
        parsed: Digest,
        expected: Digest,
    },
    InvalidParentEncoding,
    FutureTimestamp {
        timestamp: u64,
        now: u64,
    },
    TimestampRegression {
        timestamp: u64,
        parent_timestamp: u64,
    },
}

fn genesis_payload(epoch: Epoch) -> Bytes {
    let round = Round::new(epoch, View::zero());
    let parent = Digest::from([0u8; 32]);
    encode_payload(round, parent, 0)
}

fn genesis_digest(epoch: Epoch) -> Digest {
    payload_digest(&genesis_payload(epoch))
}

fn encode_payload(round: Round, parent: Digest, timestamp: u64) -> Bytes {
    (round, parent, timestamp).encode()
}

fn payload_digest(contents: &Bytes) -> Digest {
    Sha256::hash(contents)
}

/// Decode the timestamp from an encoded payload.
fn decode_timestamp(contents: &Bytes) -> Option<u64> {
    let mut reader = contents.clone();
    let (_, _, timestamp) = <(Round, Digest, u64)>::decode(&mut reader).ok()?;
    Some(timestamp)
}

fn validate_payload(
    expected_round: Round,
    expected_parent: Digest,
    expected_payload: Digest,
    contents: &Bytes,
    now: u64,
    parent_contents: &Bytes,
) -> Result<(), PayloadValidationError> {
    let computed = payload_digest(contents);
    if computed != expected_payload {
        return Err(PayloadValidationError::DigestMismatch {
            computed,
            expected: expected_payload,
        });
    }

    let mut reader = contents.clone();
    let Ok((parsed_round, parent, timestamp)) = <(Round, Digest, u64)>::decode(&mut reader) else {
        return Err(PayloadValidationError::InvalidEncoding);
    };

    if parsed_round != expected_round {
        return Err(PayloadValidationError::RoundMismatch {
            parsed: parsed_round,
            expected: expected_round,
        });
    }

    if parent != expected_parent {
        return Err(PayloadValidationError::ParentMismatch {
            parsed: parent,
            expected: expected_parent,
        });
    }

    if timestamp > now.saturating_add(SYNCHRONY_BOUND) {
        return Err(PayloadValidationError::FutureTimestamp { timestamp, now });
    }

    let Some(parent_timestamp) = decode_timestamp(parent_contents) else {
        return Err(PayloadValidationError::InvalidParentEncoding);
    };
    if timestamp < parent_timestamp {
        return Err(PayloadValidationError::TimestampRegression {
            timestamp,
            parent_timestamp,
        });
    }

    Ok(())
}

fn missing_dependency(
    seen: &HashMap<Digest, Bytes>,
    context: &Context,
    payload: Digest,
) -> Option<Digest> {
    if !seen.contains_key(&payload) {
        return Some(payload);
    }
    if !seen.contains_key(&context.parent.1) {
        return Some(context.parent.1);
    }
    None
}

// ---------------------------------------------------------------------------
// Mailbox messages
// ---------------------------------------------------------------------------

pub enum Message {
    Genesis {
        epoch: Epoch,
        response: oneshot::Sender<Digest>,
    },
    Propose {
        context: Context,
        response: oneshot::Sender<Digest>,
    },
    Verify {
        context: Context,
        payload: Digest,
        response: oneshot::Sender<bool>,
    },
    Broadcast {
        payload: Digest,
    },
}

struct DeferredVerify {
    context: Context,
    payload: Digest,
    response: oneshot::Sender<bool>,
}

// ---------------------------------------------------------------------------
// Mailbox — the Clone+Send frontend that implements Automaton + Relay
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct Mailbox {
    sender: mpsc::Sender<Message>,
}

impl Au for Mailbox {
    type Digest = Digest;
    type Context = Context;

    async fn genesis(&mut self, epoch: Epoch) -> Self::Digest {
        let (response, receiver) = oneshot::channel();
        self.sender
            .send_lossy(Message::Genesis { epoch, response })
            .await;
        receiver.await.expect("genesis failed")
    }

    async fn propose(&mut self, context: Self::Context) -> oneshot::Receiver<Self::Digest> {
        let (response, receiver) = oneshot::channel();
        self.sender
            .send_lossy(Message::Propose { context, response })
            .await;
        receiver
    }

    async fn verify(
        &mut self,
        context: Self::Context,
        payload: Self::Digest,
    ) -> oneshot::Receiver<bool> {
        let (response, receiver) = oneshot::channel();
        self.sender
            .send_lossy(Message::Verify {
                context,
                payload,
                response,
            })
            .await;
        receiver
    }
}

impl Re for Mailbox {
    type Digest = Digest;

    async fn broadcast(&mut self, payload: Self::Digest) {
        self.sender.send_lossy(Message::Broadcast { payload }).await;
    }
}

// ---------------------------------------------------------------------------
// NoopReporter — logs finalizations, discards other activity
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct TraceReporter;

impl Rp for TraceReporter {
    type Activity = HActivity;

    async fn report(&mut self, activity: Self::Activity) {
        info!(activity = ?activity);
    }
}

// ---------------------------------------------------------------------------
// Application actor — runs in a spawned task, handles the real logic
// ---------------------------------------------------------------------------

pub struct Application<E: Clock + Spawner> {
    context: ContextCell<E>,

    relay: std::sync::Arc<dyn ShardTransport>,
    shard_rx: mpsc::UnboundedReceiver<ShardMessage>,

    mailbox_rx: mpsc::Receiver<Message>,

    pending: HashMap<Digest, Bytes>,
    pending_order: VecDeque<Digest>,
    pending_shards: HashMap<Digest, (BlockKey, ZodaCommitment, Vec<ZodaShard>)>,
    seen: HashMap<Digest, Bytes>,
    shard_reconstructor: ShardReconstructor,
}

impl<E: Clock + Spawner> Application<E> {
    const MAX_PENDING_DIGESTS: usize = 256;
    const MAX_WAITER_KEYS: usize = 512;

    pub fn new(
        context: E,
        relay: std::sync::Arc<dyn ShardTransport>,
        me: &PublicKey,
    ) -> (Self, Mailbox) {
        let shard_rx = relay.register(me);
        let (sender, receiver) = mpsc::channel(1024);
        let my_index = relay
            .validator_index(me)
            .expect("validators must be declared and finalized before application construction");
        let coding_config = coding_config(relay.validator_count());

        (
            Self {
                context: ContextCell::new(context),
                relay,
                shard_rx,
                mailbox_rx: receiver,
                pending: HashMap::new(),
                pending_order: VecDeque::new(),
                pending_shards: HashMap::new(),
                seen: HashMap::new(),
                shard_reconstructor: ShardReconstructor::new(me.clone(), my_index, coding_config),
            },
            Mailbox { sender },
        )
    }

    fn genesis(&mut self, epoch: Epoch) -> Digest {
        let payload = genesis_payload(epoch);
        let digest = genesis_digest(epoch);
        self.seen.insert(digest, payload);
        digest
    }

    fn propose(&mut self, context: &Context) -> Digest {
        let timestamp = self.context.current().epoch_millis();
        let payload = encode_payload(context.round, context.parent.1, timestamp);
        let digest = payload_digest(&payload);
        let key = BlockKey::new(context.round, digest);
        let (commitment, shards) = CodingImpl::encode(
            self.shard_reconstructor.coding_config(),
            payload.as_ref(),
            &Sequential,
        )
        .expect("zoda encode failed");

        self.pending.insert(digest, payload.clone());
        self.pending_shards
            .insert(digest, (key, commitment, shards));
        self.touch_pending(digest);
        self.seen.insert(digest, payload);
        digest
    }

    fn verify(&self, context: &Context, payload: Digest, contents: &Bytes) -> bool {
        let parent_bytes = self
            .seen
            .get(&context.parent.1)
            .expect("parent dependency should be checked before verify");
        let now = self.context.current().epoch_millis();
        match validate_payload(
            context.round,
            context.parent.1,
            payload,
            contents,
            now,
            parent_bytes,
        ) {
            Ok(()) => true,
            Err(PayloadValidationError::DigestMismatch { computed, expected }) => {
                warn!(?computed, ?expected, "digest mismatch");
                false
            }
            Err(PayloadValidationError::InvalidEncoding) => {
                warn!("invalid payload encoding");
                false
            }
            Err(PayloadValidationError::RoundMismatch { parsed, expected }) => {
                warn!(?parsed, ?expected, "round mismatch");
                false
            }
            Err(PayloadValidationError::ParentMismatch { parsed, expected }) => {
                warn!(?parsed, ?expected, "parent mismatch");
                false
            }
            Err(PayloadValidationError::InvalidParentEncoding) => {
                warn!(parent = ?context.parent.1, "invalid parent payload encoding");
                false
            }
            Err(PayloadValidationError::FutureTimestamp { timestamp, now }) => {
                warn!(timestamp, now, "timestamp too far in the future");
                false
            }
            Err(PayloadValidationError::TimestampRegression {
                timestamp,
                parent_timestamp,
            }) => {
                warn!(timestamp, parent_timestamp, "timestamp before parent");
                false
            }
        }
    }

    fn handle_verify_request(
        &mut self,
        context: Context,
        payload: Digest,
        response: oneshot::Sender<bool>,
        waiters: &mut HashMap<Digest, Vec<DeferredVerify>>,
        waiter_order: &mut VecDeque<Digest>,
    ) {
        if let Some(missing_digest) = missing_dependency(&self.seen, &context, payload) {
            self.queue_waiter(
                waiters,
                waiter_order,
                missing_digest,
                DeferredVerify {
                    context,
                    payload,
                    response,
                },
            );
            return;
        }

        let contents = self
            .seen
            .get(&payload)
            .expect("payload dependency should be checked before verify")
            .clone();
        let valid = self.verify(&context, payload, &contents);
        response.send_lossy(valid);
    }

    fn queue_waiter(
        &self,
        waiters: &mut HashMap<Digest, Vec<DeferredVerify>>,
        waiter_order: &mut VecDeque<Digest>,
        digest: Digest,
        deferred: DeferredVerify,
    ) {
        if !waiters.contains_key(&digest) {
            waiter_order.push_back(digest);
        }
        waiters.entry(digest).or_default().push(deferred);

        while waiters.len() > Self::MAX_WAITER_KEYS {
            let Some(oldest) = waiter_order.pop_front() else {
                break;
            };
            if let Some(stale) = waiters.remove(&oldest) {
                for deferred in stale {
                    deferred.response.send_lossy(false);
                }
            }
        }
    }

    fn resolve_waiters(
        &mut self,
        digest: Digest,
        waiters: &mut HashMap<Digest, Vec<DeferredVerify>>,
        waiter_order: &mut VecDeque<Digest>,
    ) {
        if let Some(pos) = waiter_order.iter().position(|d| *d == digest) {
            waiter_order.remove(pos);
        }
        if let Some(pending) = waiters.remove(&digest) {
            for deferred in pending {
                self.handle_verify_request(
                    deferred.context,
                    deferred.payload,
                    deferred.response,
                    waiters,
                    waiter_order,
                );
            }
        }
    }

    fn fail_waiters(
        &self,
        digest: Digest,
        waiters: &mut HashMap<Digest, Vec<DeferredVerify>>,
        waiter_order: &mut VecDeque<Digest>,
    ) {
        if let Some(pos) = waiter_order.iter().position(|d| *d == digest) {
            waiter_order.remove(pos);
        }
        if let Some(stale) = waiters.remove(&digest) {
            for deferred in stale {
                deferred.response.send_lossy(false);
            }
        }
    }

    fn touch_pending(&mut self, digest: Digest) {
        if !self.pending_order.contains(&digest) {
            self.pending_order.push_back(digest);
        }
        while self.pending_order.len() > Self::MAX_PENDING_DIGESTS {
            let Some(oldest) = self.pending_order.pop_front() else {
                break;
            };
            self.pending.remove(&oldest);
            self.pending_shards.remove(&oldest);
        }
    }

    async fn apply_shard_effect(
        &mut self,
        effect: ShardEffect,
        waiters: &mut HashMap<Digest, Vec<DeferredVerify>>,
        waiter_order: &mut VecDeque<Digest>,
    ) {
        match effect {
            ShardEffect::Broadcast(message) => {
                self.relay
                    .broadcast_except(self.shard_reconstructor.me(), *message)
                    .await;
            }
            ShardEffect::Reconstructed { key, contents } => {
                self.seen.insert(key.digest, contents);
                self.pending.remove(&key.digest);
                self.pending_shards.remove(&key.digest);
                self.resolve_waiters(key.digest, waiters, waiter_order);
            }
            ShardEffect::Failed { key } => {
                self.fail_waiters(key.digest, waiters, waiter_order);
            }
        }
    }

    async fn handle_shard_message(
        &mut self,
        message: ShardMessage,
        waiters: &mut HashMap<Digest, Vec<DeferredVerify>>,
        waiter_order: &mut VecDeque<Digest>,
    ) {
        let effects = self
            .shard_reconstructor
            .handle_message(message, &self.seen, |sender| {
                self.relay.validator_index(sender)
            });
        for effect in effects {
            self.apply_shard_effect(effect, waiters, waiter_order).await;
        }
    }

    async fn broadcast_payload(&mut self, digest: Digest) {
        let Some((key, commitment, shards)) = self.pending_shards.remove(&digest) else {
            warn!(?digest, "broadcast requested for unknown pending shards");
            return;
        };
        self.relay
            .distribute_shards(self.shard_reconstructor.me(), key, commitment, shards)
            .await;
    }

    pub fn start(mut self) -> Handle<()> {
        spawn_cell!(self.context, self.run().await)
    }

    async fn run(mut self) {
        let mut waiters: HashMap<Digest, Vec<DeferredVerify>> = HashMap::new();
        let mut waiter_order: VecDeque<Digest> = VecDeque::new();

        select_loop! {
            self.context,
            on_stopped => {
                debug!("application shutting down");
            },
            message = self.mailbox_rx.next() => {
                let message = match message {
                    Some(message) => message,
                    None => break,
                };
                match message {
                    Message::Genesis { epoch, response } => {
                        let digest = self.genesis(epoch);
                        response.send_lossy(digest);
                    }
                    Message::Propose { context, response } => {
                        let digest = self.propose(&context);
                        response.send_lossy(digest);
                    }
                    Message::Verify { context, payload, response } => {
                        let key = BlockKey::new(context.round, payload);
                        let leader = context.leader.clone();
                        self.handle_verify_request(
                            context,
                            payload,
                            response,
                            &mut waiters,
                            &mut waiter_order,
                        );
                        for msg in self.shard_reconstructor.note_known_key(key, leader) {
                            self.handle_shard_message(msg, &mut waiters, &mut waiter_order)
                                .await;
                        }
                    }
                    Message::Broadcast { payload } => {
                        self.broadcast_payload(payload).await;
                    }
                }
            },
            shard = self.shard_rx.next() => {
                let shard = shard.expect("shard relay closed");
                self.handle_shard_message(shard, &mut waiters, &mut waiter_order).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shard::MockShardTransport;
    use commonware_consensus::minimmit::scheme::ed25519 as minimmit_ed25519;
    use commonware_consensus::types::{Epoch, View};
    use commonware_cryptography::certificate::mocks::Fixture;
    use commonware_runtime::{Clock, Metrics, Runner, deterministic};
    use futures::channel::oneshot::Canceled;
    use proptest::prelude::*;
    use std::{sync::Arc, time::Duration};

    /// Cap timestamp ranges to avoid saturating_add degeneracy near u64::MAX.
    const MAX_TIMESTAMP: u64 = u64::MAX - SYNCHRONY_BOUND - 10_001;

    fn make_round(epoch: u16, view: u16) -> Round {
        Round::new(Epoch::new(epoch as u64), View::new(view as u64))
    }

    fn mutate_byte(mut bytes: Vec<u8>, index: usize) -> Vec<u8> {
        let idx = index % bytes.len();
        bytes[idx] ^= 0x01;
        bytes
    }

    fn default_parent_contents() -> Bytes {
        genesis_payload(Epoch::new(0))
    }

    proptest! {
        #[test]
        fn valid_payload_is_accepted(
            epoch in any::<u16>(),
            view in any::<u16>(),
            parent in any::<[u8; 32]>(),
            timestamp in 0u64..=MAX_TIMESTAMP,
            slack in 0u64..=SYNCHRONY_BOUND,
        ) {
            let round = make_round(epoch, view);
            let parent = Digest::from(parent);
            let contents = encode_payload(round, parent, timestamp);
            let payload = payload_digest(&contents);
            let now = timestamp + slack;
            let parent_contents = default_parent_contents();

            prop_assert_eq!(
                validate_payload(round, parent, payload, &contents, now, &parent_contents),
                Ok(())
            );
        }

        #[test]
        fn mutated_payload_is_rejected(
            epoch in any::<u16>(),
            view in any::<u16>(),
            parent in any::<[u8; 32]>(),
            timestamp in 0u64..=MAX_TIMESTAMP,
            index in any::<usize>(),
        ) {
            let round = make_round(epoch, view);
            let parent = Digest::from(parent);
            let contents = encode_payload(round, parent, timestamp);
            let payload = payload_digest(&contents);
            let mutated = Bytes::from(mutate_byte(contents.to_vec(), index));
            let parent_contents = default_parent_contents();

            assert!(matches!(
                validate_payload(
                    round,
                    parent,
                    payload,
                    &mutated,
                    timestamp + SYNCHRONY_BOUND,
                    &parent_contents,
                ),
                Err(PayloadValidationError::DigestMismatch { .. })
            ));
        }

        #[test]
        fn round_mismatch_is_rejected(
            epoch in any::<u16>(),
            view in any::<u16>(),
            parent in any::<[u8; 32]>(),
            timestamp in 0u64..=MAX_TIMESTAMP,
        ) {
            let round = make_round(epoch, view);
            let parent = Digest::from(parent);
            let contents = encode_payload(round, parent, timestamp);
            let payload = payload_digest(&contents);
            let now = timestamp + SYNCHRONY_BOUND;
            let parent_contents = default_parent_contents();

            let wrong_round = make_round(epoch.wrapping_add(1), view);
            assert!(matches!(
                validate_payload(
                    wrong_round,
                    parent,
                    payload,
                    &contents,
                    now,
                    &parent_contents,
                ),
                Err(PayloadValidationError::RoundMismatch { .. })
            ));
        }

        #[test]
        fn parent_mismatch_is_rejected(
            epoch in any::<u16>(),
            view in any::<u16>(),
            parent in any::<[u8; 32]>(),
            timestamp in 0u64..=MAX_TIMESTAMP,
        ) {
            let round = make_round(epoch, view);
            let parent = Digest::from(parent);
            let contents = encode_payload(round, parent, timestamp);
            let payload = payload_digest(&contents);
            let now = timestamp + SYNCHRONY_BOUND;
            let parent_contents = default_parent_contents();

            let mut wrong_parent = parent.0;
            wrong_parent[0] ^= 0x01;
            assert!(matches!(
                validate_payload(
                    round,
                    Digest::from(wrong_parent),
                    payload,
                    &contents,
                    now,
                    &parent_contents,
                ),
                Err(PayloadValidationError::ParentMismatch { .. })
            ));
        }

        #[test]
        fn future_timestamp_is_rejected(
            epoch in any::<u16>(),
            view in any::<u16>(),
            parent in any::<[u8; 32]>(),
            now in 0u64..=MAX_TIMESTAMP,
            delta in (SYNCHRONY_BOUND + 1)..=(SYNCHRONY_BOUND + 10_000),
        ) {
            let round = make_round(epoch, view);
            let parent = Digest::from(parent);
            let timestamp = now + delta;
            let contents = encode_payload(round, parent, timestamp);
            let payload = payload_digest(&contents);
            let parent_contents = default_parent_contents();

            assert!(matches!(
                validate_payload(round, parent, payload, &contents, now, &parent_contents),
                Err(PayloadValidationError::FutureTimestamp { .. })
            ));
        }

        #[test]
        fn past_timestamp_is_accepted(
            epoch in any::<u16>(),
            view in any::<u16>(),
            parent in any::<[u8; 32]>(),
            timestamp in 0u64..=MAX_TIMESTAMP,
            age in 0u64..=1_000_000u64,
        ) {
            let round = make_round(epoch, view);
            let parent = Digest::from(parent);
            let contents = encode_payload(round, parent, timestamp);
            let payload = payload_digest(&contents);
            let now = timestamp + age;
            let parent_contents = default_parent_contents();

            prop_assert_eq!(
                validate_payload(round, parent, payload, &contents, now, &parent_contents),
                Ok(())
            );
        }

        #[test]
        fn timestamp_regression_is_rejected(
            epoch in any::<u16>(),
            view in any::<u16>(),
            parent_digest in any::<[u8; 32]>(),
            parent_ts in 1u64..=MAX_TIMESTAMP,
            regression in 1u64..=1_000u64,
        ) {
            let round = make_round(epoch, view);
            let parent_digest = Digest::from(parent_digest);
            let child_ts = parent_ts - regression;
            let contents = encode_payload(round, parent_digest, child_ts);
            let payload = payload_digest(&contents);
            let now = parent_ts + SYNCHRONY_BOUND;

            // Build parent payload bytes
            let parent_round = make_round(epoch, view.wrapping_sub(1));
            let parent_contents = encode_payload(parent_round, Digest::from([0u8; 32]), parent_ts);

            assert!(matches!(
                validate_payload(round, parent_digest, payload, &contents, now, &parent_contents),
                Err(PayloadValidationError::TimestampRegression { .. })
            ));
        }

        #[test]
        fn monotonic_timestamp_is_accepted(
            epoch in any::<u16>(),
            view in any::<u16>(),
            parent_digest in any::<[u8; 32]>(),
            parent_ts in 0u64..=(MAX_TIMESTAMP / 2),
            advance in 0u64..=1_000u64,
        ) {
            let round = make_round(epoch, view);
            let parent_digest = Digest::from(parent_digest);
            let child_ts = parent_ts + advance;
            let contents = encode_payload(round, parent_digest, child_ts);
            let payload = payload_digest(&contents);
            let now = child_ts + SYNCHRONY_BOUND;

            let parent_round = make_round(epoch, view.wrapping_sub(1));
            let parent_contents = encode_payload(parent_round, Digest::from([0u8; 32]), parent_ts);

            prop_assert_eq!(
                validate_payload(round, parent_digest, payload, &contents, now, &parent_contents),
                Ok(())
            );
        }
    }

    #[test]
    fn invalid_encoding_is_rejected() {
        let round = Round::new(Epoch::new(1), View::new(1));
        let parent = Digest::from([7; 32]);
        let contents = Bytes::from_static(b"not-a-valid-payload");
        let payload = payload_digest(&contents);
        let parent_contents = default_parent_contents();

        assert!(matches!(
            validate_payload(round, parent, payload, &contents, 0, &parent_contents),
            Err(PayloadValidationError::InvalidEncoding)
        ));
    }

    #[test]
    fn invalid_parent_encoding_is_rejected() {
        let round = Round::new(Epoch::new(1), View::new(1));
        let parent = Digest::from([7; 32]);
        let contents = encode_payload(round, parent, 10);
        let payload = payload_digest(&contents);
        let bad_parent_contents = Bytes::from_static(b"bad-parent");

        assert!(matches!(
            validate_payload(round, parent, payload, &contents, 10, &bad_parent_contents),
            Err(PayloadValidationError::InvalidParentEncoding)
        ));
    }

    #[test]
    fn genesis_has_zero_timestamp() {
        let epoch = Epoch::new(1);
        let payload = genesis_payload(epoch);
        assert_eq!(decode_timestamp(&payload), Some(0));
    }

    #[test]
    fn preleader_shards_drain_after_verify() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));

        runner.start(|mut context| async move {
            let Fixture { participants, .. }: Fixture<hellas_types::Scheme> =
                minimmit_ed25519::fixture(&mut context, b"app-shard-test", 6);

            let relay = Arc::new(MockShardTransport::new());
            for participant in participants.iter() {
                relay.declare(participant.clone());
            }
            relay.finalize_validators();

            let mut mailboxes = Vec::new();
            let mut handles = Vec::new();
            for (idx, participant) in participants.iter().enumerate() {
                let (app, mailbox) = Application::new(
                    context.with_label(&format!("app_{idx}")),
                    relay.clone(),
                    participant,
                );
                handles.push(app.start());
                mailboxes.push(mailbox);
            }

            let epoch = Epoch::new(1);
            let mut genesis = None;
            for mailbox in mailboxes.iter_mut() {
                let digest = mailbox.genesis(epoch).await;
                if let Some(existing) = genesis {
                    assert_eq!(existing, digest);
                } else {
                    genesis = Some(digest);
                }
            }
            let genesis = genesis.expect("genesis should be set");

            let round = Round::new(epoch, View::new(1));
            let proposal_context = Context {
                round,
                leader: participants[0].clone(),
                parent: (View::zero(), genesis),
            };

            let digest = mailboxes[0]
                .propose(proposal_context.clone())
                .await
                .await
                .expect("proposal should resolve");

            // Broadcast before any verify to force pre-leader buffering.
            mailboxes[0].broadcast(digest).await;
            context.sleep(Duration::from_millis(10)).await;

            let mut verify_rx_1 = mailboxes[1].verify(proposal_context.clone(), digest).await;
            context.sleep(Duration::from_millis(10)).await;
            match verify_rx_1.try_recv() {
                Ok(Some(v)) => panic!("verify should not resolve yet, got {:?}", v),
                Ok(None) => {}
                Err(Canceled) => panic!("verify receiver canceled unexpectedly"),
            }

            let verify_rx_2 = mailboxes[2].verify(proposal_context, digest).await;
            assert!(verify_rx_2.await.expect("verify 2 should resolve"));
            assert!(verify_rx_1.await.expect("verify 1 should resolve"));

            drop(handles);
        });
    }
}
