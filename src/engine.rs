use crate::app::{
    Application, ApplicationConfig, HellasBlock, MarshalMailbox, MarshalVariant, TraceReporter,
};
use crate::config::Config;
use commonware_broadcast::buffered;
use commonware_codec::Encode;
use commonware_consensus::{
    Reporter,
    elector::RoundRobin,
    marshal::{self, resolver::p2p, standard},
    minimmit,
};
use commonware_cryptography::{
    Sha256,
    certificate::{ConstantProvider, Scheme as _},
    sha256::Digest,
};
use commonware_p2p::{Blocker, Provider as PeerProvider, Receiver, Sender};
use commonware_runtime::{BufferPooler, Clock, ContextCell, Handle, Metrics, Spawner, Storage};
use commonware_storage::archive::immutable;
use futures::FutureExt;
use hellas_types::rpc::{ConsensusActivity, NotarizeInfo, ProposalInfo};
use hellas_types::{Activity, Address, EPOCH, PublicKey, Scheme};
use rand_core::CryptoRngCore;
use std::{
    num::{NonZeroU64, NonZeroUsize},
    time::Duration,
};
use tokio::sync::broadcast;

type Finalization = commonware_consensus::minimmit::types::Finalization<Scheme, Digest>;
type FinalizationStore<E> = immutable::Archive<E, Digest, Finalization>;
type BlockStore<E> = immutable::Archive<E, Digest, HellasBlock>;
type MarshalActor<E> = marshal::core::Actor<
    E,
    MarshalVariant,
    ConstantProvider<Scheme, commonware_consensus::types::Epoch>,
    FinalizationStore<E>,
    BlockStore<E>,
    commonware_consensus::types::FixedEpocher,
    commonware_parallel::Sequential,
>;

fn proposal_info(p: &commonware_consensus::minimmit::types::Proposal<Digest>) -> ProposalInfo {
    ProposalInfo {
        epoch: p.round.epoch().get(),
        view: p.round.view().get(),
        parent_view: p.parent.get(),
        parent_payload: p.parent_payload,
        payload: p.payload,
    }
}

fn notarize_info(
    n: &commonware_consensus::minimmit::types::Notarize<Scheme, Digest>,
) -> NotarizeInfo {
    NotarizeInfo {
        proposal: proposal_info(&n.proposal),
        signer: n.attestation.signer.get(),
        signature: n.attestation.signature.encode().to_vec(),
    }
}

fn convert_activity(activity: &Activity) -> ConsensusActivity {
    match activity {
        Activity::Notarize(n) => ConsensusActivity::Notarize {
            proposal: proposal_info(&n.proposal),
            signer: n.attestation.signer.get(),
            signature: n.attestation.signature.encode().to_vec(),
        },
        Activity::MNotarization(m) => ConsensusActivity::MNotarization {
            proposal: proposal_info(&m.proposal),
            signers: m.certificate.signers.iter().map(|p| p.get()).collect(),
            certificate: m.certificate.encode().to_vec(),
        },
        Activity::Nullify(n) => ConsensusActivity::Nullify {
            epoch: n.round.epoch().get(),
            view: n.round.view().get(),
            signer: n.attestation.signer.get(),
            signature: n.attestation.signature.encode().to_vec(),
        },
        Activity::Nullification(n) => ConsensusActivity::Nullification {
            epoch: n.round.epoch().get(),
            view: n.round.view().get(),
            signers: n.certificate.signers.iter().map(|p| p.get()).collect(),
            certificate: n.certificate.encode().to_vec(),
        },
        Activity::Finalization(f) => ConsensusActivity::Finalization {
            proposal: proposal_info(&f.proposal),
            signers: f.certificate.signers.iter().map(|p| p.get()).collect(),
            certificate: f.certificate.encode().to_vec(),
        },
        Activity::ConflictingNotarize(c) => ConsensusActivity::ConflictingNotarize {
            first: notarize_info(&c.first),
            second: notarize_info(&c.second),
        },
    }
}

#[derive(Clone)]
struct ActivityReporter<F, O> {
    forward: F,
    observe: O,
    activity_tx: broadcast::Sender<ConsensusActivity>,
}

impl<F, O> Reporter for ActivityReporter<F, O>
where
    F: Reporter<Activity = Activity>,
    O: Reporter<Activity = Activity>,
{
    type Activity = Activity;

    async fn report(&mut self, activity: Self::Activity) {
        let _ = self.activity_tx.send(convert_activity(&activity));
        self.observe.report(activity.clone()).await;
        self.forward.report(activity).await;
    }
}

pub struct Engine<E, D, B, R>
where
    E: BufferPooler + Clock + CryptoRngCore + Spawner + Storage + Metrics,
    D: PeerProvider<PublicKey = PublicKey> + Clone,
    B: Blocker<PublicKey = PublicKey> + Clone,
    R: Reporter<Activity = Activity>,
{
    context: ContextCell<E>,
    application: Application,
    minimmit: minimmit::Engine<
        E,
        Scheme,
        RoundRobin<Sha256>,
        B,
        Digest,
        standard::Inline<
            E,
            Scheme,
            Application,
            HellasBlock,
            commonware_consensus::types::FixedEpocher,
            marshal::core::MinimmitConsensus<Scheme, Digest>,
        >,
        standard::Inline<
            E,
            Scheme,
            Application,
            HellasBlock,
            commonware_consensus::types::FixedEpocher,
            marshal::core::MinimmitConsensus<Scheme, Digest>,
        >,
        ActivityReporter<MarshalMailbox, R>,
        commonware_parallel::Sequential,
    >,
    marshal_actor: MarshalActor<E>,
    buffer_engine: buffered::Engine<E, PublicKey, HellasBlock, D>,
    buffer: buffered::Mailbox<PublicKey, HellasBlock>,
    me: PublicKey,
    peer_provider: D,
    blocker: B,
    mailbox_size: usize,
    fetch_timeout: Duration,
}

impl<E, D, B, R> Engine<E, D, B, R>
where
    E: BufferPooler + Clock + CryptoRngCore + Spawner + Storage + Metrics,
    D: PeerProvider<PublicKey = PublicKey> + Clone,
    B: Blocker<PublicKey = PublicKey> + Clone,
    R: Reporter<Activity = Activity>,
{
    pub async fn new(
        context: E,
        config: Config,
        scheme: Scheme,
        peer_provider: D,
        blocker: B,
        me: &PublicKey,
        genesis_allocations: Vec<(Address, u64)>,
        observer: R,
    ) -> (Self, Application, broadcast::Sender<ConsensusActivity>) {
        let partition_prefix = format!("hellas_{me}");

        let finalizations_by_height = Self::init_finalization_store(
            context.with_label("finalizations_by_height"),
            &partition_prefix,
            &config,
        )
        .await;
        let finalized_blocks = Self::init_block_store(
            context.with_label("finalized_blocks"),
            &partition_prefix,
            &config,
        )
        .await;

        let application = Application::new(
            context.with_label("app"),
            me,
            genesis_allocations,
            partition_prefix.clone(),
            ApplicationConfig {
                page_cache_size: config.page_cache_size,
                page_cache_count: config.page_cache_count,
                min_propose_delay: config.min_propose_delay,
                execution_retention_depth: (config.activity_timeout as usize).max(1),
            },
            &finalized_blocks,
        )
        .await;

        let provider = ConstantProvider::new(scheme.clone());
        let epocher =
            commonware_consensus::types::FixedEpocher::new(NonZeroU64::new(u64::MAX).unwrap());
        let marshal_config = marshal::Config {
            provider,
            epocher: epocher.clone(),
            partition_prefix: partition_prefix.clone(),
            mailbox_size: config.mailbox_size,
            view_retention_timeout: commonware_consensus::types::ViewDelta::new(
                config.activity_timeout,
            ),
            prunable_items_per_section: NonZeroU64::new(256).unwrap(),
            page_cache: config.page_cache(&context),
            replay_buffer: NonZeroUsize::new(config.replay_buffer).unwrap_or(NonZeroUsize::MIN),
            key_write_buffer: NonZeroUsize::new(config.write_buffer).unwrap_or(NonZeroUsize::MIN),
            value_write_buffer: NonZeroUsize::new(config.write_buffer).unwrap_or(NonZeroUsize::MIN),
            block_codec_config: (),
            max_repair: NonZeroUsize::new(config.max_repair).unwrap_or(NonZeroUsize::MIN),
            max_pending_acks: NonZeroUsize::new(1).unwrap(),
            strategy: commonware_parallel::Sequential,
        };
        let (marshal_actor, marshal_mailbox, _height) = MarshalActor::init(
            context.clone(),
            finalizations_by_height,
            finalized_blocks,
            marshal_config,
        )
        .await;
        application.attach_marshal(marshal_mailbox.clone());

        let broadcast_config = buffered::Config {
            public_key: me.clone(),
            mailbox_size: config.mailbox_size,
            deque_size: config.broadcast_cache_per_peer,
            priority: false,
            codec_config: (),
            peer_provider: peer_provider.clone(),
        };
        let (buffer_engine, buffer) = buffered::Engine::new(context.clone(), broadcast_config);

        let (activity_tx, _) = broadcast::channel(1024);
        let reporter = ActivityReporter {
            forward: marshal_mailbox.clone(),
            observe: observer,
            activity_tx: activity_tx.clone(),
        };

        let inline = standard::Inline::new(
            context.clone(),
            application.clone(),
            marshal_mailbox,
            epocher,
        );
        let inner = minimmit::Engine::new(
            context.clone(),
            minimmit::Config {
                scheme,
                elector: RoundRobin::<Sha256>::default(),
                blocker: blocker.clone(),
                automaton: inline.clone(),
                relay: inline,
                reporter,
                strategy: commonware_parallel::Sequential,
                partition: me.to_string(),
                mailbox_size: config.mailbox_size,
                epoch: EPOCH,
                replay_buffer: NonZeroUsize::new(config.replay_buffer).unwrap_or(NonZeroUsize::MIN),
                write_buffer: NonZeroUsize::new(config.write_buffer).unwrap_or(NonZeroUsize::MIN),
                page_cache: config.page_cache(&context),
                leader_timeout: config.leader_timeout,
                notarization_timeout: config.notarization_timeout,
                nullify_retry: config.nullify_retry,
                activity_timeout: commonware_consensus::types::ViewDelta::new(
                    config.activity_timeout,
                ),
                skip_timeout: commonware_consensus::types::ViewDelta::new(config.skip_timeout),
                fetch_timeout: config.fetch_timeout,
                fetch_concurrent: config.fetch_concurrent,
            },
        );

        (
            Self {
                context: ContextCell::new(context),
                application: application.clone(),
                minimmit: inner,
                marshal_actor,
                buffer_engine,
                buffer,
                me: me.clone(),
                peer_provider,
                blocker,
                mailbox_size: config.mailbox_size,
                fetch_timeout: config.fetch_timeout,
            },
            application,
            activity_tx,
        )
    }

    pub fn start(
        mut self,
        vote_network: (
            impl Sender<PublicKey = PublicKey> + 'static,
            impl Receiver<PublicKey = PublicKey> + 'static,
        ),
        certificate_network: (
            impl Sender<PublicKey = PublicKey> + 'static,
            impl Receiver<PublicKey = PublicKey> + 'static,
        ),
        consensus_resolver_network: (
            impl Sender<PublicKey = PublicKey> + 'static,
            impl Receiver<PublicKey = PublicKey> + 'static,
        ),
        marshal_resolver_network: (
            impl Sender<PublicKey = PublicKey> + 'static,
            impl Receiver<PublicKey = PublicKey> + 'static,
        ),
        broadcast_network: (
            impl Sender<PublicKey = PublicKey> + 'static,
            impl Receiver<PublicKey = PublicKey> + 'static,
        ),
    ) -> Handle<()> {
        let context = self.context.take();
        context.spawn(move |ctx| async move {
            enum Exit {
                Stopped,
                Broadcast,
                Marshal,
                Minimmit,
            }

            let broadcast_handle = self.buffer_engine.start(broadcast_network);
            let resolver_cfg = p2p::Config {
                public_key: self.me.clone(),
                peer_provider: self.peer_provider.clone(),
                blocker: self.blocker.clone(),
                mailbox_size: self.mailbox_size,
                initial: Duration::from_secs(1),
                timeout: self.fetch_timeout,
                fetch_retry_timeout: Duration::from_millis(100),
                priority_requests: false,
                priority_responses: false,
            };
            let resolver = p2p::init(&ctx, resolver_cfg, marshal_resolver_network);
            let marshal_handle =
                self.marshal_actor
                    .start(self.application.clone(), self.buffer, resolver);
            let minimmit_handle = self.minimmit.start(
                vote_network,
                certificate_network,
                consensus_resolver_network,
            );

            let exit = futures::future::select_all(vec![
                ctx.stopped().map(|_| Exit::Stopped).boxed(),
                broadcast_handle.map(|_| Exit::Broadcast).boxed(),
                marshal_handle.map(|_| Exit::Marshal).boxed(),
                minimmit_handle.map(|_| Exit::Minimmit).boxed(),
            ])
            .await
            .0;
            match exit {
                Exit::Stopped => {}
                Exit::Broadcast => panic!("broadcast subsystem exited unexpectedly"),
                Exit::Marshal => panic!("marshal subsystem exited unexpectedly"),
                Exit::Minimmit => panic!("minimmit subsystem exited unexpectedly"),
            }
        })
    }

    async fn init_finalization_store(
        context: E,
        partition_prefix: &str,
        config: &Config,
    ) -> FinalizationStore<E> {
        let page_cache = config.page_cache(&context);
        immutable::Archive::init(
            context,
            immutable::Config {
                metadata_partition: format!("{partition_prefix}-finalizations-by-height-metadata"),
                freezer_table_partition: format!(
                    "{partition_prefix}-finalizations-by-height-freezer-table"
                ),
                freezer_table_initial_size: 64,
                freezer_table_resize_frequency: 10,
                freezer_table_resize_chunk_size: 10,
                freezer_key_partition: format!(
                    "{partition_prefix}-finalizations-by-height-freezer-key"
                ),
                freezer_key_page_cache: page_cache,
                freezer_value_partition: format!(
                    "{partition_prefix}-finalizations-by-height-freezer-value"
                ),
                freezer_value_target_size: 1024,
                freezer_value_compression: None,
                ordinal_partition: format!("{partition_prefix}-finalizations-by-height-ordinal"),
                items_per_section: NonZeroU64::new(256).unwrap(),
                codec_config: Scheme::certificate_codec_config_unbounded(),
                replay_buffer: NonZeroUsize::new(config.replay_buffer).unwrap_or(NonZeroUsize::MIN),
                freezer_key_write_buffer: NonZeroUsize::new(config.write_buffer)
                    .unwrap_or(NonZeroUsize::MIN),
                freezer_value_write_buffer: NonZeroUsize::new(config.write_buffer)
                    .unwrap_or(NonZeroUsize::MIN),
                ordinal_write_buffer: NonZeroUsize::new(config.write_buffer)
                    .unwrap_or(NonZeroUsize::MIN),
            },
        )
        .await
        .expect("failed to initialize finalizations archive")
    }

    async fn init_block_store(
        context: E,
        partition_prefix: &str,
        config: &Config,
    ) -> BlockStore<E> {
        let page_cache = config.page_cache(&context);
        immutable::Archive::init(
            context,
            immutable::Config {
                metadata_partition: format!("{partition_prefix}-finalized-blocks-metadata"),
                freezer_table_partition: format!(
                    "{partition_prefix}-finalized-blocks-freezer-table"
                ),
                freezer_table_initial_size: 64,
                freezer_table_resize_frequency: 10,
                freezer_table_resize_chunk_size: 10,
                freezer_key_partition: format!("{partition_prefix}-finalized-blocks-freezer-key"),
                freezer_key_page_cache: page_cache,
                freezer_value_partition: format!(
                    "{partition_prefix}-finalized-blocks-freezer-value"
                ),
                freezer_value_target_size: 1024,
                freezer_value_compression: None,
                ordinal_partition: format!("{partition_prefix}-finalized-blocks-ordinal"),
                items_per_section: NonZeroU64::new(256).unwrap(),
                codec_config: (),
                replay_buffer: NonZeroUsize::new(config.replay_buffer).unwrap_or(NonZeroUsize::MIN),
                freezer_key_write_buffer: NonZeroUsize::new(config.write_buffer)
                    .unwrap_or(NonZeroUsize::MIN),
                freezer_value_write_buffer: NonZeroUsize::new(config.write_buffer)
                    .unwrap_or(NonZeroUsize::MIN),
                ordinal_write_buffer: NonZeroUsize::new(config.write_buffer)
                    .unwrap_or(NonZeroUsize::MIN),
            },
        )
        .await
        .expect("failed to initialize finalized blocks archive")
    }
}

impl Default for TraceReporter {
    fn default() -> Self {
        Self
    }
}
