use crate::app::{Application, FinalizationNotice, Mailbox};
use crate::config::Config;
use crate::shard::{AuthenticatedShardTransport, ShardTransport};
use commonware_consensus::{Reporter, elector::RoundRobin, minimmit};
use commonware_cryptography::certificate::Scheme as _;
use commonware_cryptography::{Sha256, sha256::Digest};
use commonware_p2p::{Blocker, Receiver, Sender};
use commonware_parallel::Sequential;
use commonware_runtime::{Clock, Handle, Metrics, Spawner, Storage};
use hellas_types::{Activity, PublicKey, Scheme};
use rand_core::CryptoRngCore;
use std::sync::Arc;

#[derive(Clone)]
struct AppReporter<R> {
    finalization: futures::channel::mpsc::UnboundedSender<FinalizationNotice>,
    inner: R,
}

impl<R> AppReporter<R> {
    fn new(
        finalization: futures::channel::mpsc::UnboundedSender<FinalizationNotice>,
        inner: R,
    ) -> Self {
        Self {
            finalization,
            inner,
        }
    }
}

impl<R> Reporter for AppReporter<R>
where
    R: Reporter<Activity = Activity>,
{
    type Activity = Activity;

    async fn report(&mut self, activity: Self::Activity) {
        if let Activity::Finalization(finalization) = &activity {
            if let Err(err) = self.finalization.unbounded_send(FinalizationNotice {
                payload: finalization.proposal.payload,
                parent_payload: finalization.proposal.parent_payload,
            }) {
                error!(
                    ?err,
                    "failed to forward finalization notice to app; aborting"
                );
                std::process::abort();
            }
        }
        self.inner.report(activity).await;
    }
}

pub struct Engine<E, B, R>
where
    E: Clock + CryptoRngCore + Spawner + Storage + Metrics,
    B: Blocker<PublicKey = PublicKey>,
    R: Reporter<Activity = Activity>,
{
    inner: minimmit::Engine<
        E,
        Scheme,
        RoundRobin<Sha256>,
        B,
        Digest,
        Mailbox,
        Mailbox,
        AppReporter<R>,
        Sequential,
    >,
    #[allow(dead_code)]
    app_handle: Handle<()>,
}

impl<E, B, R> Engine<E, B, R>
where
    E: Clock + CryptoRngCore + Spawner + Storage + Metrics,
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
    ) -> (Self, Mailbox)
    where
        S: Sender<PublicKey = PublicKey>,
        N: Receiver<PublicKey = PublicKey>,
    {
        let validators: Vec<PublicKey> = scheme.participants().iter().cloned().collect();
        let relay_for_app: Arc<dyn ShardTransport> = relay;
        let partition_prefix = format!("hellas_{}", me);
        let (app, mailbox, finalization_tx) = Application::new(
            context.with_label("app"),
            relay_for_app,
            me,
            validators,
            partition_prefix,
        );
        let app_handle = app.start();
        let tx_mailbox = mailbox.clone();
        let reporter = AppReporter::new(finalization_tx, reporter);

        let cfg = config.into_minimmit(scheme, blocker, mailbox.clone(), mailbox, reporter, me);
        let inner = minimmit::Engine::new(context, cfg);

        (Self { inner, app_handle }, tx_mailbox)
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
