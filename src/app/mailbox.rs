use crate::object::Transaction;
#[cfg(debug_assertions)]
use crate::object::{Coin, ObjectId};
use commonware_consensus::{Automaton, Relay, types::Epoch};
use commonware_cryptography::sha256::Digest;
use commonware_utils::channels::fallible::AsyncFallibleExt;
use futures::channel::{mpsc, oneshot};
use hellas_types::Context;

pub(super) enum Message {
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
    SubmitTx {
        tx: Transaction,
    },
    #[cfg(debug_assertions)]
    GetCoin {
        payload: Digest,
        object: ObjectId,
        response: oneshot::Sender<Option<Coin>>,
    },
}

#[derive(Clone)]
pub struct Mailbox {
    sender: mpsc::Sender<Message>,
}

impl Mailbox {
    pub(super) fn new(sender: mpsc::Sender<Message>) -> Self {
        Self { sender }
    }

    pub async fn submit_tx(&mut self, tx: Transaction) {
        self.sender.send_lossy(Message::SubmitTx { tx }).await;
    }

    #[cfg(debug_assertions)]
    pub async fn get_coin(&mut self, payload: Digest, object: ObjectId) -> Option<Coin> {
        let (response, receiver) = oneshot::channel();
        self.sender
            .send_lossy(Message::GetCoin {
                payload,
                object,
                response,
            })
            .await;
        receiver.await.unwrap_or(None)
    }
}

impl Automaton for Mailbox {
    type Digest = Digest;
    type Context = Context;

    async fn genesis(&mut self, epoch: Epoch) -> Self::Digest {
        let (response, receiver) = oneshot::channel();
        self.sender
            .send_lossy(Message::Genesis { epoch, response })
            .await;
        match receiver.await {
            Ok(digest) => digest,
            Err(err) => {
                error!(?err, "genesis response channel closed");
                Digest::from([0u8; 32])
            }
        }
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

impl Relay for Mailbox {
    type Digest = Digest;

    async fn broadcast(&mut self, payload: Self::Digest) {
        self.sender.send_lossy(Message::Broadcast { payload }).await;
    }
}
