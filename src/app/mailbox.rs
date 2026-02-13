#![allow(private_interfaces)]

use crate::object::Coin;
use crate::object::{ObjectId, Transaction};
use crate::shard::protocol::ShardMessage;

use super::FinalizationNotice;
use commonware_actor::ingress;
use commonware_consensus::{Automaton, Relay, types::Epoch};
use commonware_cryptography::sha256::Digest;
use commonware_utils::channel::oneshot;
use hellas_types::Context;

/// Opaque proof returned by `get_proof()`.
pub type ProofResponse = commonware_storage::qmdb::current::proof::OperationProof<Digest, 32>;
/// Opaque encoded finalization certificate bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinalizationResponse(Vec<u8>);

impl FinalizationResponse {
    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl From<Vec<u8>> for FinalizationResponse {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

impl From<FinalizationResponse> for Vec<u8> {
    fn from(value: FinalizationResponse) -> Self {
        value.0
    }
}

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
    tell ShardEvent {
        message: ShardMessage,
    };
    tell FinalizationEvent {
        notice: FinalizationNotice,
    };
    tell Persisted {
        payload: Digest,
        root: Digest,
    };
    tell MaintenanceTick;
    ask read_write GetCoin {
        payload: Digest,
        object: ObjectId,
    } -> Option<Coin>;
    pub ask read_write GetStateRoot -> Option<Digest>;
    pub ask read_write GetProof { object: ObjectId } -> Option<ProofResponse>;
    pub ask read_write GetFinalization { payload: Digest } -> Option<FinalizationResponse>;
}

impl AppMailboxReadWriteMessage {
    pub(super) fn kind(&self) -> &'static str {
        match self {
            Self::Genesis { .. } => "genesis",
            Self::Propose { .. } => "propose",
            Self::Verify { .. } => "verify",
            Self::Broadcast { .. } => "broadcast",
            Self::SubmitTx { .. } => "submit_tx",
            Self::MaintenanceTick => "maintenance_tick",
            Self::ShardEvent { .. } => "shard_event",
            Self::FinalizationEvent { .. } => "finalization_event",
            Self::Persisted { .. } => "persisted",
            Self::GetCoin { .. } => "get_coin",
            Self::GetStateRoot { .. } => "get_state_root",
            Self::GetProof { .. } => "get_proof",
            Self::GetFinalization { .. } => "get_finalization",
        }
    }
}

impl AppMailbox {
    pub async fn submit_tx(&self, tx: Transaction) {
        let _ = self.0.tell_lossy(SubmitTx { tx }).await;
    }

    pub(crate) async fn finalize(&self, notice: FinalizationNotice) {
        if let Err(err) = self.0.tell(FinalizationEvent { notice }).await {
            error!(?err, "failed to enqueue finalization; aborting");
            std::process::abort();
        }
    }

    pub(super) async fn tell_shard_event(&self, message: ShardMessage) -> bool {
        self.0.tell(ShardEvent { message }).await.is_ok()
    }

    pub(super) async fn tell_persisted(&self, payload: Digest, root: Digest) -> bool {
        self.0.tell(Persisted { payload, root }).await.is_ok()
    }

    pub(super) async fn tell_maintenance_tick(&self) -> bool {
        self.0.tell(MaintenanceTick).await.is_ok()
    }

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
