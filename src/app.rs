mod core;
mod mailbox;
mod payload;

pub use mailbox::Mailbox;

use crate::shard::{ShardMessage, ShardTransport, coding_config};
use commonware_consensus::Reporter;
use commonware_cryptography::sha256::Digest;
use commonware_macros::select_loop;
use commonware_runtime::{Clock, ContextCell, Handle, Spawner, spawn_cell};
use commonware_utils::{SystemTimeExt, channels::fallible::OneshotExt};
use core::{AppCore, CoreEffect, CoreEffects, NetworkEffect};
use futures::{StreamExt, channel::mpsc};
use hellas_types::{Activity, PublicKey};
use mailbox::Message;

#[derive(Clone, Copy)]
pub(crate) struct FinalizationNotice {
    pub payload: Digest,
    pub parent_payload: Digest,
}

// ---------------------------------------------------------------------------
// TraceReporter — logs consensus activity
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct TraceReporter;

impl Reporter for TraceReporter {
    type Activity = Activity;

    async fn report(&mut self, activity: Self::Activity) {
        info!(activity = ?activity);
    }
}

// ---------------------------------------------------------------------------
// Application actor — async driver over AppCore
// ---------------------------------------------------------------------------

pub(crate) struct Application<E: Clock + Spawner> {
    context: ContextCell<E>,

    relay: std::sync::Arc<dyn ShardTransport>,
    shard_rx: mpsc::UnboundedReceiver<ShardMessage>,
    finalization_rx: mpsc::UnboundedReceiver<FinalizationNotice>,

    mailbox_rx: mpsc::Receiver<Message>,

    core: AppCore,
}

impl<E: Clock + Spawner> Application<E> {
    const MAILBOX_CAPACITY: usize = 1024;

    pub(crate) fn new(
        context: E,
        relay: std::sync::Arc<dyn ShardTransport>,
        me: &PublicKey,
        validators: Vec<PublicKey>,
    ) -> (Self, Mailbox, mpsc::UnboundedSender<FinalizationNotice>) {
        let (finalization_tx, finalization_rx) = mpsc::unbounded();
        let (app, mailbox) =
            Self::new_with_finalization_receiver(context, relay, me, validators, finalization_rx);
        (app, mailbox, finalization_tx)
    }

    fn new_with_finalization_receiver(
        context: E,
        relay: std::sync::Arc<dyn ShardTransport>,
        me: &PublicKey,
        validators: Vec<PublicKey>,
        finalization_rx: mpsc::UnboundedReceiver<FinalizationNotice>,
    ) -> (Self, Mailbox) {
        let shard_rx = relay.register(me);
        let (sender, receiver) = mpsc::channel(Self::MAILBOX_CAPACITY);
        let my_index = relay.validator_index(me).unwrap_or_else(|| {
            warn!("validator index unavailable for local key; defaulting to index 0");
            0
        });
        let coding_config = coding_config(relay.validator_count());
        let core = AppCore::new(me, validators, my_index, coding_config);

        (
            Self {
                context: ContextCell::new(context),
                relay,
                shard_rx,
                finalization_rx,
                mailbox_rx: receiver,
                core,
            },
            Mailbox::new(sender),
        )
    }

    fn apply_reply_effect(&mut self, effect: CoreEffect) {
        match effect {
            CoreEffect::RespondDigest { response, digest } => {
                response.send_lossy(digest);
            }
            CoreEffect::RespondVerify { response, valid } => {
                response.send_lossy(valid);
            }
            #[cfg(debug_assertions)]
            CoreEffect::RespondCoin { response, coin } => {
                response.send_lossy(coin);
            }
        }
    }

    async fn apply_network_effect(&mut self, effect: NetworkEffect) {
        match effect {
            NetworkEffect::BroadcastShard(message) => {
                self.relay.broadcast_except(self.core.me(), *message).await;
            }
            NetworkEffect::DistributeShards {
                key,
                commitment,
                shards,
            } => {
                self.relay
                    .distribute_shards(self.core.me(), key, commitment, shards)
                    .await;
            }
        }
    }

    async fn apply_core_effects(&mut self, effects: CoreEffects) {
        for effect in effects.replies {
            self.apply_reply_effect(effect);
        }
        for effect in effects.network {
            self.apply_network_effect(effect).await;
        }
    }

    pub(crate) fn start(mut self) -> Handle<()> {
        spawn_cell!(self.context, self.run().await)
    }

    async fn run(mut self) {
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
                let now = self.context.current().epoch_millis();
                let relay = &self.relay;
                let effects = self
                    .core
                    .on_message(message, now, &|sender| relay.validator_index(sender));
                self.apply_core_effects(effects).await;
            },
            shard = self.shard_rx.next() => {
                match shard {
                    Some(shard) => {
                        let now = self.context.current().epoch_millis();
                        let relay = &self.relay;
                        let effects = self
                            .core
                            .on_shard_message(shard, now, &|sender| relay.validator_index(sender));
                        self.apply_core_effects(effects).await;
                    }
                    None => {
                        warn!("shard relay closed");
                        break;
                    }
                }
            },
            finalized = self.finalization_rx.next() => {
                match finalized {
                    Some(finalized) => {
                        let effects = self.core.on_finalized(finalized.payload, finalized.parent_payload);
                        self.apply_core_effects(effects).await;
                    }
                    None => {
                        warn!("finalization channel closed");
                        break;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::payload::{
        PayloadValidationError, SYNCHRONY_BOUND, decode_timestamp, encode_payload, genesis_payload,
        payload_digest, validate_payload,
    };
    use crate::shard::mock::MockShardTransport;
    use bytes::Bytes;
    use commonware_consensus::minimmit::scheme::ed25519 as minimmit_ed25519;
    use commonware_consensus::types::{Epoch, Round, View};
    use commonware_consensus::{Automaton, Relay};
    use commonware_cryptography::certificate::mocks::Fixture;
    use commonware_runtime::{Clock, Metrics, Runner, deterministic};
    use futures::channel::oneshot::Canceled;
    use hellas_types::Context;
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

            prop_assert!(matches!(
                validate_payload(round, parent, payload, &contents, now, &parent_contents),
                Ok(txs) if txs.is_empty()
            ));
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

            prop_assert!(matches!(
                validate_payload(round, parent, payload, &contents, now, &parent_contents),
                Ok(txs) if txs.is_empty()
            ));
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

            prop_assert!(matches!(
                validate_payload(round, parent_digest, payload, &contents, now, &parent_contents),
                Ok(txs) if txs.is_empty()
            ));
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
                relay.declare(participant);
            }
            relay.finalize_validators();

            let mut mailboxes = Vec::new();
            let mut handles = Vec::new();
            let mut finalization_txs = Vec::new();
            for (idx, participant) in participants.iter().enumerate() {
                let (app, mailbox, finalization_tx) = Application::new(
                    context.with_label(&format!("app_{idx}")),
                    relay.clone(),
                    participant,
                    participants.clone(),
                );
                handles.push(app.start());
                mailboxes.push(mailbox);
                finalization_txs.push(finalization_tx);
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
            drop(finalization_txs);
        });
    }

}
