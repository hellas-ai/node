use super::AuthenticatedShardTransport;
use super::core::{ShardEffect, ShardRecoverer};
use super::protocol::{
    BlockKey, CodingImpl, ShardMessage, ZodaCommitment, ZodaShard, coding_config,
};
use super::transport::ShardTransport;
use bytes::Bytes;
use commonware_coding::Scheme as CodingScheme;
use commonware_consensus::types::{Epoch, Round, View};
use commonware_cryptography::{Hasher, Sha256, Signer, ed25519, sha256::Digest};
use commonware_p2p::{
    Receiver as P2pReceiver, Sender as P2pSender,
    simulated::{Config as NetworkConfig, Link, Network},
};
use commonware_parallel::Sequential;
use commonware_runtime::{Clock, Metrics, Quota, Runner, Spawner, deterministic};
use futures::{FutureExt, StreamExt, channel::mpsc};
use hellas_types::PublicKey;
use std::collections::HashMap;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

const VALIDATOR_COUNT: usize = 6;
const SHARD_CHANNEL: u64 = 0;
const TICK_SLEEP: Duration = Duration::from_millis(1);
const MAX_TICKS: usize = 10_000;

struct BlockDistribution {
    key: BlockKey,
    commitment: ZodaCommitment,
    shards: Vec<ZodaShard>,
    payload: Bytes,
}

struct ShardNode<S, R>
where
    S: P2pSender<PublicKey = PublicKey>,
    R: P2pReceiver<PublicKey = PublicKey>,
{
    public_key: PublicKey,
    relay: Arc<AuthenticatedShardTransport<S, R>>,
    shard_rx: mpsc::UnboundedReceiver<ShardMessage>,
    recoverer: ShardRecoverer,
    seen: HashMap<Digest, Bytes>,
}

struct ShardNetwork<S, R>
where
    S: P2pSender<PublicKey = PublicKey>,
    R: P2pReceiver<PublicKey = PublicKey>,
{
    validators: Vec<PublicKey>,
    leader_index: usize,
    index_by_validator: HashMap<PublicKey, u16>,
    nodes: Vec<ShardNode<S, R>>,
}

impl<S, R> ShardNetwork<S, R>
where
    S: P2pSender<PublicKey = PublicKey>,
    R: P2pReceiver<PublicKey = PublicKey>,
{
    fn new<E>(
        context: E,
        validators: Vec<PublicKey>,
        leader_index: usize,
        mut registrations: HashMap<PublicKey, (S, R)>,
    ) -> Self
    where
        E: Spawner + Clone,
    {
        let validator_count = u16::try_from(validators.len()).expect("validator count fits u16");
        let mut sorted = validators.clone();
        sorted.sort();
        let index_by_validator: HashMap<_, _> = sorted
            .into_iter()
            .enumerate()
            .map(|(idx, pk)| {
                (
                    pk,
                    u16::try_from(idx).expect("validator index should fit into u16"),
                )
            })
            .collect();

        let mut nodes = Vec::with_capacity(validators.len());
        for validator in validators.iter() {
            let (network_sender, network_receiver) = registrations
                .remove(validator)
                .expect("missing shard registration");
            let relay = Arc::new(AuthenticatedShardTransport::new(
                validator,
                network_sender,
                network_receiver,
            ));
            for participant in validators.iter() {
                relay.declare(participant);
            }
            relay.finalize_validators();
            let shard_rx = relay.register(validator);
            let _transport_handle = relay.clone().start(context.clone());

            let my_index = *index_by_validator
                .get(validator)
                .expect("validator index must exist");
            let recoverer =
                ShardRecoverer::new(validator, my_index, coding_config(validator_count));
            nodes.push(ShardNode {
                public_key: validator.clone(),
                relay,
                shard_rx,
                recoverer,
                seen: HashMap::new(),
            });
        }

        Self {
            validators,
            leader_index,
            index_by_validator,
            nodes,
        }
    }

    async fn handle_message(
        &mut self,
        node_idx: usize,
        message: ShardMessage,
        recovered: &mut HashMap<(usize, Digest), Bytes>,
    ) {
        let index_by_validator = self.index_by_validator.clone();
        let effects = {
            let node = &mut self.nodes[node_idx];
            node.recoverer.handle_message(message, &node.seen, |pk| {
                index_by_validator.get(pk).copied()
            })
        };

        for effect in effects {
            match effect {
                ShardEffect::Broadcast(message) => {
                    let (relay, me) = {
                        let node = &self.nodes[node_idx];
                        (node.relay.clone(), node.public_key.clone())
                    };
                    relay.broadcast_except(&me, *message).await;
                }
                ShardEffect::Recovered { key, contents } => {
                    self.nodes[node_idx]
                        .seen
                        .insert(key.digest, contents.clone());
                    recovered.insert((node_idx, key.digest), contents);
                }
                ShardEffect::Failed { .. } => {}
            }
        }
    }

    async fn drive<C: Clock>(
        &mut self,
        context: &mut C,
        distributions: &[BlockDistribution],
        expected_total: Option<usize>,
        max_ticks: usize,
    ) -> HashMap<(usize, Digest), Bytes> {
        let mut recovered = HashMap::new();
        let leader = self.validators[self.leader_index].clone();

        for distribution in distributions {
            for node_idx in 0..self.nodes.len() {
                let drained = self.nodes[node_idx]
                    .recoverer
                    .note_known_key(distribution.key, &leader);
                for message in drained {
                    self.handle_message(node_idx, message, &mut recovered).await;
                }
            }

            let leader_relay = self.nodes[self.leader_index].relay.clone();
            leader_relay
                .distribute_shards(
                    &leader,
                    distribution.key,
                    distribution.commitment,
                    distribution.shards.clone(),
                )
                .await;
        }

        for _ in 0..max_ticks {
            if let Some(expected) = expected_total {
                if recovered.len() >= expected {
                    break;
                }
            }

            for node_idx in 0..self.nodes.len() {
                loop {
                    let maybe_message = {
                        let rx = &mut self.nodes[node_idx].shard_rx;
                        rx.next().now_or_never().flatten()
                    };
                    let Some(message) = maybe_message else {
                        break;
                    };
                    self.handle_message(node_idx, message, &mut recovered).await;
                }
            }

            context.sleep(TICK_SLEEP).await;
        }

        recovered
    }
}

fn validator_keys(count: usize) -> Vec<PublicKey> {
    (0..count)
        .map(|seed| {
            ed25519::PrivateKey::from_seed(
                u64::try_from(seed).expect("validator seed should fit into u64"),
            )
            .public_key()
        })
        .collect()
}

fn build_distribution(validators: usize, view: u64, payload: &[u8]) -> BlockDistribution {
    let validator_count = u16::try_from(validators).expect("validator count fits u16");
    let config = coding_config(validator_count);
    let (commitment, shards) =
        CodingImpl::encode(&config, payload, &Sequential).expect("encode should succeed");
    let key = BlockKey::new(
        Round::new(Epoch::new(1), View::new(view)),
        Sha256::hash(payload),
    );
    BlockDistribution {
        key,
        commitment,
        shards,
        payload: Bytes::copy_from_slice(payload),
    }
}

fn base_network_config() -> NetworkConfig {
    NetworkConfig {
        max_size: 1024 * 1024,
        disconnect_on_block: true,
        tracked_peer_sets: None,
    }
}

#[test]
fn happy_path_recovery() {
    let runner = deterministic::Runner::timed(Duration::from_secs(30));
    runner.start(|mut context| async move {
        let validators = validator_keys(VALIDATOR_COUNT);
        let link = Link {
            latency: Duration::from_millis(10),
            jitter: Duration::from_millis(1),
            success_rate: 1.0,
        };

        let (network, oracle) = Network::new(context.with_label("network"), base_network_config());
        network.start();
        let quota = Quota::per_second(NonZeroU32::MAX);
        let mut registrations = HashMap::with_capacity(validators.len());
        for validator in validators.iter() {
            let control = oracle.control(validator.clone());
            let channel = control
                .register(SHARD_CHANNEL, quota)
                .await
                .expect("failed to register shard channel");
            registrations.insert(validator.clone(), channel);
        }
        for src in validators.iter() {
            for dst in validators.iter() {
                if src == dst {
                    continue;
                }
                oracle
                    .add_link(src.clone(), dst.clone(), link.clone())
                    .await
                    .expect("failed to add simulated link");
            }
        }

        let leader_index = 0usize;
        let mut shard_network = ShardNetwork::new(
            context.clone(),
            validators.clone(),
            leader_index,
            registrations,
        );
        let distribution = build_distribution(VALIDATOR_COUNT, 1, b"happy-path-payload");
        let digest = distribution.key.digest;
        let expected = validators.len().saturating_sub(1);

        let recovered = shard_network
            .drive(&mut context, &[distribution], Some(expected), MAX_TICKS)
            .await;

        assert_eq!(
            recovered.len(),
            expected,
            "all non-leader validators should recover"
        );
        for node_idx in 0..validators.len() {
            if node_idx == leader_index {
                continue;
            }
            let contents = recovered
                .get(&(node_idx, digest))
                .expect("non-leader should recover payload");
            assert_eq!(contents.as_ref(), b"happy-path-payload");
        }
    });
}

#[test]
fn lossy_delivery_still_recovers() {
    let runner = deterministic::Runner::timed(Duration::from_secs(30));
    runner.start(|mut context| async move {
        let validators = validator_keys(VALIDATOR_COUNT);
        let link = Link {
            latency: Duration::from_millis(10),
            jitter: Duration::from_millis(5),
            success_rate: 0.8,
        };

        let (network, oracle) = Network::new(context.with_label("network"), base_network_config());
        network.start();
        let quota = Quota::per_second(NonZeroU32::MAX);
        let mut registrations = HashMap::with_capacity(validators.len());
        for validator in validators.iter() {
            let control = oracle.control(validator.clone());
            let channel = control
                .register(SHARD_CHANNEL, quota)
                .await
                .expect("failed to register shard channel");
            registrations.insert(validator.clone(), channel);
        }
        for src in validators.iter() {
            for dst in validators.iter() {
                if src == dst {
                    continue;
                }
                oracle
                    .add_link(src.clone(), dst.clone(), link.clone())
                    .await
                    .expect("failed to add simulated link");
            }
        }

        let leader_index = 0usize;
        let mut shard_network = ShardNetwork::new(
            context.clone(),
            validators.clone(),
            leader_index,
            registrations,
        );
        let distribution = build_distribution(VALIDATOR_COUNT, 2, b"lossy-path-payload");
        let digest = distribution.key.digest;
        let payload = distribution.payload.clone();

        let recovered = shard_network
            .drive(&mut context, &[distribution], None, MAX_TICKS)
            .await;

        let recovered_non_leaders = (0..validators.len())
            .filter(|idx| *idx != leader_index)
            .filter_map(|idx| recovered.get(&(idx, digest)))
            .filter(|contents| contents.as_ref() == payload.as_ref())
            .count();
        assert!(
            recovered_non_leaders > 0,
            "expected at least one non-leader to recover under lossy delivery"
        );
    });
}

#[test]
fn concurrent_block_recoveries() {
    let runner = deterministic::Runner::timed(Duration::from_secs(30));
    runner.start(|mut context| async move {
        let validators = validator_keys(VALIDATOR_COUNT);
        let link = Link {
            latency: Duration::from_millis(5),
            jitter: Duration::from_millis(1),
            success_rate: 1.0,
        };

        let (network, oracle) = Network::new(context.with_label("network"), base_network_config());
        network.start();
        let quota = Quota::per_second(NonZeroU32::MAX);
        let mut registrations = HashMap::with_capacity(validators.len());
        for validator in validators.iter() {
            let control = oracle.control(validator.clone());
            let channel = control
                .register(SHARD_CHANNEL, quota)
                .await
                .expect("failed to register shard channel");
            registrations.insert(validator.clone(), channel);
        }
        for src in validators.iter() {
            for dst in validators.iter() {
                if src == dst {
                    continue;
                }
                oracle
                    .add_link(src.clone(), dst.clone(), link.clone())
                    .await
                    .expect("failed to add simulated link");
            }
        }

        let leader_index = 0usize;
        let mut shard_network = ShardNetwork::new(
            context.clone(),
            validators.clone(),
            leader_index,
            registrations,
        );
        let distributions = vec![
            build_distribution(VALIDATOR_COUNT, 11, b"block-a"),
            build_distribution(VALIDATOR_COUNT, 12, b"block-b"),
            build_distribution(VALIDATOR_COUNT, 13, b"block-c"),
        ];
        let expected = distributions
            .len()
            .saturating_mul(validators.len().saturating_sub(1));
        let digests: Vec<_> = distributions
            .iter()
            .map(|distribution| distribution.key.digest)
            .collect();
        let payload_by_digest: HashMap<_, _> = distributions
            .iter()
            .map(|distribution| (distribution.key.digest, distribution.payload.clone()))
            .collect();

        let recovered = shard_network
            .drive(&mut context, &distributions, Some(expected), MAX_TICKS)
            .await;

        assert_eq!(
            recovered.len(),
            expected,
            "all non-leaders should recover all blocks"
        );
        for node_idx in 0..validators.len() {
            if node_idx == leader_index {
                continue;
            }
            for digest in digests.iter().copied() {
                let payload = payload_by_digest
                    .get(&digest)
                    .expect("payload must exist for every digest");
                let contents = recovered
                    .get(&(node_idx, digest))
                    .expect("missing recovered payload");
                assert_eq!(contents.as_ref(), payload.as_ref());
            }
        }
    });
}
