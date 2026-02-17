use crate::app::{AppMailbox, Application, ApplicationConfig, FinalizationNotice};
use crate::config::Config;
use crate::shard::AuthenticatedShardTransport;
use commonware_codec::Encode;
use commonware_consensus::{Reporter, elector::RoundRobin, minimmit};
use commonware_cryptography::certificate::Scheme as _;
use commonware_cryptography::{Sha256, sha256::Digest};
use commonware_p2p::{Blocker, Receiver, Sender};
use commonware_parallel::Sequential;
use commonware_runtime::{BufferPooler, Clock, Handle, Metrics, Spawner, Storage};
use hellas_types::{Activity, PublicKey, Scheme};
use hellas_types::rpc::{ConsensusActivity, NotarizeInfo, ProposalInfo};
use prometheus_client::metrics::counter::Counter;
use rand_core::CryptoRngCore;
use std::sync::Arc;
use tokio::sync::broadcast;

fn proposal_info(p: &commonware_consensus::minimmit::types::Proposal<Digest>) -> ProposalInfo {
    ProposalInfo {
        epoch: p.round.epoch().get(),
        view: p.round.view().get(),
        parent_view: p.parent.get(),
        parent_payload: p.parent_payload,
        payload: p.payload,
    }
}

fn notarize_info(n: &commonware_consensus::minimmit::types::Notarize<Scheme, Digest>) -> NotarizeInfo {
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
struct AppReporter<R> {
    mailbox: AppMailbox,
    inner: R,
    notarize_total: Counter,
    activity_tx: broadcast::Sender<ConsensusActivity>,
}

impl<R> AppReporter<R> {
    fn new(
        context: &impl Metrics,
        mailbox: AppMailbox,
        inner: R,
        activity_tx: broadcast::Sender<ConsensusActivity>,
    ) -> Self {
        let notarize_total = Counter::default();
        context.register(
            "notarize_total",
            "total notarize votes observed",
            notarize_total.clone(),
        );
        Self {
            mailbox,
            inner,
            notarize_total,
            activity_tx,
        }
    }
}

impl<R> Reporter for AppReporter<R>
where
    R: Reporter<Activity = Activity>,
{
    type Activity = Activity;

    async fn report(&mut self, activity: Self::Activity) {
        if let Activity::Notarize(_) = &activity {
            self.notarize_total.inc();
        }
        if let Activity::Finalization(finalization) = &activity {
            self.mailbox
                .finalize(FinalizationNotice {
                    payload: finalization.proposal.payload,
                    parent_payload: finalization.proposal.parent_payload,
                    certificate_bytes: finalization.encode().to_vec().into(),
                })
                .await;
        }
        let _ = self.activity_tx.send(convert_activity(&activity));
        self.inner.report(activity).await;
    }
}

pub struct Engine<E, B, R>
where
    E: Clock + CryptoRngCore + Spawner + Storage + Metrics + BufferPooler,
    B: Blocker<PublicKey = PublicKey>,
    R: Reporter<Activity = Activity>,
{
    inner: minimmit::Engine<
        E,
        Scheme,
        RoundRobin<Sha256>,
        B,
        Digest,
        AppMailbox,
        AppMailbox,
        AppReporter<R>,
        Sequential,
    >,
    #[allow(dead_code)] // keep app alive
    app_handle: Handle<()>,
}

impl<E, B, R> Engine<E, B, R>
where
    E: Clock + CryptoRngCore + Spawner + Storage + Metrics + BufferPooler,
    B: Blocker<PublicKey = PublicKey>,
    R: Reporter<Activity = Activity>,
{
    pub fn new<S, N>(
        context: E,
        config: Config,
        scheme: Scheme,
        blocker: B,
        relay: Arc<AuthenticatedShardTransport<S, N>>,
        me: &PublicKey,
        reporter: R,
    ) -> (Self, AppMailbox, broadcast::Sender<ConsensusActivity>)
    where
        S: Sender<PublicKey = PublicKey>,
        N: Receiver<PublicKey = PublicKey>,
    {
        let validators: Vec<PublicKey> = scheme.participants().iter().cloned().collect();
        let partition_prefix = format!("hellas_{}", me);
        let app = Application::new(
            context.with_label("app"),
            relay.clone(),
            me,
            validators,
            partition_prefix,
            ApplicationConfig {
                page_cache_size: config.page_cache_size,
                page_cache_count: config.page_cache_count,
                verify_wait_timeout: config.fetch_timeout,
                min_propose_delay: config.min_propose_delay,
            },
        );
        let (app_handle, mailbox) = app.start();
        let tx_mailbox = mailbox.clone();
        let (activity_tx, _) = broadcast::channel(1024);
        let reporter = AppReporter::new(&context.with_label("chain"), mailbox.clone(), reporter, activity_tx.clone());

        let cfg = config.into_minimmit(&context, scheme, blocker, mailbox.clone(), mailbox, reporter, me);
        let inner = minimmit::Engine::new(context, cfg);

        (Self { inner, app_handle }, tx_mailbox, activity_tx)
    }

    pub fn start(
        self,
        vote_network: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
        certificate_network: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
        resolver_network: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
    ) -> Handle<()> {
        self.inner
            .start(vote_network, certificate_network, resolver_network)
    }
}
