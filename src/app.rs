use bytes::Bytes;
use commonware_codec::{DecodeExt, Encode};
use commonware_consensus::{
    Automaton as Au, Relay as Re, Reporter as Rp,
    types::{Epoch, Round, View},
};
use commonware_cryptography::{Hasher, Sha256, sha256::Digest};
use commonware_macros::select_loop;
use commonware_runtime::{Clock, ContextCell, Handle, Spawner, spawn_cell};
use commonware_utils::{
    SystemTimeExt,
    channels::fallible::{AsyncFallibleExt, OneshotExt},
};
use futures::{
    SinkExt, StreamExt,
    channel::{mpsc, oneshot},
};
use hellas_types::{Activity as HActivity, Context, PublicKey};
use std::collections::HashMap;

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

    /// Relay for distributing block bytes to peers.
    relay: std::sync::Arc<InMemoryRelay>,

    /// Receiver for block bytes from other peers via the relay.
    broadcast_rx: mpsc::UnboundedReceiver<(Digest, Bytes)>,

    mailbox_rx: mpsc::Receiver<Message>,

    /// Block bytes we proposed, keyed by digest. Waiting to be broadcast.
    pending: HashMap<Digest, Bytes>,

    /// Block bytes we've seen (from relay or our own proposals), keyed by digest.
    seen: HashMap<Digest, Bytes>,
}

impl<E: Clock + Spawner> Application<E> {
    pub fn new(
        context: E,
        relay: std::sync::Arc<InMemoryRelay>,
        me: &PublicKey,
    ) -> (Self, Mailbox) {
        let broadcast_rx = relay.register(me);
        let (sender, receiver) = mpsc::channel(1024);

        (
            Self {
                context: ContextCell::new(context),
                relay,
                broadcast_rx,
                mailbox_rx: receiver,
                pending: HashMap::new(),
                seen: HashMap::new(),
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
        self.pending.insert(digest, payload.clone());
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
        &self,
        context: Context,
        payload: Digest,
        response: oneshot::Sender<bool>,
        waiters: &mut HashMap<Digest, Vec<DeferredVerify>>,
    ) {
        if let Some(missing_digest) = missing_dependency(&self.seen, &context, payload) {
            waiters
                .entry(missing_digest)
                .or_default()
                .push(DeferredVerify {
                    context,
                    payload,
                    response,
                });
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

    async fn broadcast_payload(&self, me: &PublicKey, digest: Digest) {
        let contents = self
            .pending
            .get(&digest)
            .expect("broadcast called for unknown payload");
        self.relay.broadcast(me, (digest, contents.clone())).await;
    }

    pub fn start(mut self, me: PublicKey) -> Handle<()> {
        spawn_cell!(self.context, self.run(me).await)
    }

    async fn run(mut self, me: PublicKey) {
        // Pending verify requests waiting for block data
        let mut waiters: HashMap<Digest, Vec<DeferredVerify>> = HashMap::new();

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
                        self.handle_verify_request(context, payload, response, &mut waiters);
                    }
                    Message::Broadcast { payload } => {
                        self.broadcast_payload(&me, payload).await;
                    }
                }
            },
            broadcast = self.broadcast_rx.next() => {
                let (digest, data) = broadcast.expect("broadcast relay closed");
                self.seen.insert(digest, data.clone());
                // Process any pending verifications
                if let Some(pending) = waiters.remove(&digest) {
                    for deferred in pending {
                        self.handle_verify_request(
                            deferred.context,
                            deferred.payload,
                            deferred.response,
                            &mut waiters,
                        );
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// InMemoryRelay — distributes block bytes between Application actors
// ---------------------------------------------------------------------------

pub struct InMemoryRelay {
    #[allow(clippy::type_complexity)]
    recipients: std::sync::Mutex<HashMap<PublicKey, Vec<mpsc::UnboundedSender<(Digest, Bytes)>>>>,
}

impl Default for InMemoryRelay {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryRelay {
    pub fn new() -> Self {
        Self {
            recipients: std::sync::Mutex::new(HashMap::new()),
        }
    }

    pub fn register(&self, public_key: &PublicKey) -> mpsc::UnboundedReceiver<(Digest, Bytes)> {
        let (sender, receiver) = mpsc::unbounded();
        let mut recipients = self.recipients.lock().unwrap();
        recipients
            .entry(public_key.clone())
            .or_default()
            .push(sender);
        receiver
    }

    pub async fn broadcast(&self, sender: &PublicKey, (payload, data): (Digest, Bytes)) {
        let channels: Vec<_> = {
            let recipients = self.recipients.lock().unwrap();
            recipients
                .iter()
                .filter(|(pk, _)| *pk != sender)
                .flat_map(|(_, senders)| senders.clone())
                .collect()
        };
        for mut ch in channels {
            if let Err(e) = ch.send((payload, data.clone())).await {
                error!(?e, "failed to send to relay recipient");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_consensus::types::{Epoch, View};
    use proptest::prelude::*;

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
}
