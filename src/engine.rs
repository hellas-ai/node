use crate::app::{Application, Mailbox};
use crate::config::Config;
use bytes::Bytes;
use commonware_consensus::{Reporter as Rp, elector::RoundRobin, minimmit};
use commonware_cryptography::{Sha256, sha256::Digest};
use commonware_p2p::{Blocker, Receiver, Sender};
use commonware_parallel::Sequential;
use commonware_runtime::{Clock, Handle, Metrics, Spawner, Storage};
use futures::channel::mpsc;
use hellas_types::{Activity, PublicKey, Scheme};
use rand_core::CryptoRngCore;

pub struct Engine<E, B, R>
where
    E: Clock + CryptoRngCore + Spawner + Storage + Metrics,
    B: Blocker<PublicKey = PublicKey>,
    R: Rp<Activity = Activity>,
{
    inner:
        minimmit::Engine<E, Scheme, RoundRobin<Sha256>, B, Digest, Mailbox, Mailbox, R, Sequential>,
    #[allow(dead_code)]
    app_handle: Handle<()>,
}

impl<E, B, R> Engine<E, B, R>
where
    E: Clock + CryptoRngCore + Spawner + Storage + Metrics,
    B: Blocker<PublicKey = PublicKey>,
    R: Rp<Activity = Activity>,
{
    pub fn new(
        context: E,
        config: Config,
        scheme: Scheme,
        blocker: B,
        broadcast_tx: mpsc::UnboundedSender<(Digest, Bytes)>,
        broadcast_rx: mpsc::UnboundedReceiver<(Digest, Bytes)>,
        me: &PublicKey,
        reporter: R,
    ) -> Self {
        let (app, mailbox) =
            Application::new(context.with_label("app"), broadcast_tx, broadcast_rx);
        let app_handle = app.start(me.clone());

        let cfg = config.into_minimmit(scheme, blocker, mailbox.clone(), mailbox, reporter, me);
        let inner = minimmit::Engine::new(context, cfg);

        Self { inner, app_handle }
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
