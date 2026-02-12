use crate::object::Coin;
use crate::object::{ObjectId, Transaction};

// We currently use actor `ingress!` only. ServiceBuilder is deferred while
// minimmit and actor depend on different `commonware-runtime` lines.
use commonware_actor::{ingress, mailbox::Mailbox as ActorMailbox};
use commonware_consensus::{Automaton, Relay, types::Epoch};
use commonware_cryptography::sha256::Digest;
use futures::channel::oneshot;
use hellas_types::Context;
use tokio::sync::mpsc;

/// Opaque proof returned by `get_proof()`.
pub type ProofResponse = commonware_storage::qmdb::current::proof::OperationProof<Digest, 32>;

ingress! {
    AppMailbox,

    tell Genesis {
        epoch: Epoch,
        response: oneshot::Sender<Digest>,
    };
    tell Propose {
        context: Context,
        response: oneshot::Sender<Digest>,
    };
    tell Verify {
        context: Context,
        payload: Digest,
        response: oneshot::Sender<bool>,
    };
    tell Broadcast {
        payload: Digest,
    };
    tell SubmitTx {
        tx: Transaction,
    };
    ask read_write GetCoin {
        payload: Digest,
        object: ObjectId,
    } -> Option<Coin>;
    pub ask GetStateRoot -> Option<Digest>;
    pub ask GetProof { object: ObjectId } -> Option<ProofResponse>;
}

impl AppMailbox {
    pub(super) fn new(sender: mpsc::Sender<AppMailboxMessage>) -> Self {
        Self::from(ActorMailbox::new(sender))
    }

    pub async fn submit_tx(&self, tx: Transaction) {
        let _ = self.0.tell_lossy(SubmitTx { tx }).await;
    }

    #[cfg(debug_assertions)]
    pub async fn get_coin(&self, payload: Digest, object: ObjectId) -> Option<Coin> {
        self.0
            .ask(GetCoin { payload, object })
            .await
            .unwrap_or(None)
    }
}

impl Automaton for AppMailbox {
    type Digest = Digest;
    type Context = Context;

    async fn genesis(&mut self, epoch: Epoch) -> Self::Digest {
        let (response, receiver) = oneshot::channel();
        if let Err(err) = self.0.tell(Genesis { epoch, response }).await {
            error!(?err, "failed to enqueue genesis request; aborting");
            std::process::abort();
        }
        match receiver.await {
            Ok(digest) => digest,
            Err(err) => {
                error!(
                    ?err,
                    "genesis response channel closed unexpectedly; aborting"
                );
                std::process::abort();
            }
        }
    }

    async fn propose(&mut self, context: Self::Context) -> oneshot::Receiver<Self::Digest> {
        let (response, receiver) = oneshot::channel();
        if let Err(err) = self.0.tell(Propose { context, response }).await {
            error!(?err, "failed to enqueue propose request; aborting");
            std::process::abort();
        }
        receiver
    }

    async fn verify(
        &mut self,
        context: Self::Context,
        payload: Self::Digest,
    ) -> oneshot::Receiver<bool> {
        let (response, receiver) = oneshot::channel();
        if let Err(err) = self
            .0
            .tell(Verify {
                context,
                payload,
                response,
            })
            .await
        {
            error!(?err, "failed to enqueue verify request; aborting");
            std::process::abort();
        }
        receiver
    }
}

impl Relay for AppMailbox {
    type Digest = Digest;

    async fn broadcast(&mut self, payload: Self::Digest) {
        if let Err(err) = self.0.tell(Broadcast { payload }).await {
            error!(?err, "failed to enqueue broadcast request; aborting");
            std::process::abort();
        }
    }
}
