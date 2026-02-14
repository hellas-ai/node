//! Local implementation of the light-client query interface.
//!
//! [`LocalLightClient`] wraps an [`AppMailbox`] and implements the
//! [`LightClient`] trait from `hellas_types::rpc`. Proof and finalization
//! responses are encoded to opaque bytes before returning.

use crate::app::{ProofResponse, AppMailbox};
use bytes::BytesMut;
use commonware_codec::{Read as _, ReadExt as _, Write as _};
use commonware_cryptography::sha256::Digest;
use commonware_storage::mmr::{Location, Proof};
use commonware_storage::qmdb::current::proof::{OperationProof, RangeProof};
use hellas_types::{ObjectId, Transaction};
use hellas_types::rpc::{LatestBlock, LightClient, QueryError};

/// Encode an [`OperationProof`] to opaque bytes by writing each public field
/// using its existing commonware-codec `Write` impl.
pub fn encode_proof(proof: &ProofResponse) -> Vec<u8> {
    let mut buf = BytesMut::new();
    proof.loc.write(&mut buf);
    proof.chunk.write(&mut buf);
    proof.range_proof.proof.write(&mut buf);
    proof.range_proof.partial_chunk_digest.write(&mut buf);
    buf.to_vec()
}

/// Decode opaque bytes back into an [`OperationProof`].
pub fn decode_proof(data: &[u8]) -> Result<ProofResponse, commonware_codec::Error> {
    let mut buf = &data[..];
    let loc = Location::read(&mut buf)?;
    let chunk = <[u8; 32]>::read(&mut buf)?;
    // max_items=1: a single key-value proof; allows up to
    // MAX_PROOF_DIGESTS_PER_ELEMENT (122) digests.
    let proof = Proof::<Digest>::read_cfg(&mut buf, &1)?;
    let partial_chunk_digest = Option::<Digest>::read(&mut buf)?;
    Ok(OperationProof {
        loc,
        chunk,
        range_proof: RangeProof {
            proof,
            partial_chunk_digest,
        },
    })
}

/// In-process [`LightClient`] backed by the application actor mailbox.
#[derive(Clone)]
pub struct LocalLightClient {
    mailbox: AppMailbox,
}

impl LocalLightClient {
    /// Wraps an existing [`AppMailbox`] as a light-client query handle.
    pub fn new(mailbox: AppMailbox) -> Self {
        Self { mailbox }
    }
}

impl LightClient for LocalLightClient {
    async fn get_state_root(&self) -> Result<Option<Digest>, QueryError> {
        self.mailbox
            .get_state_root()
            .await
            .map_err(|_| QueryError::ChannelClosed)
    }

    async fn get_proof(
        &self,
        object_id: ObjectId,
    ) -> Result<Option<Vec<u8>>, QueryError> {
        let proof = self
            .mailbox
            .get_proof(object_id)
            .await
            .map_err(|_| QueryError::ChannelClosed)?;
        Ok(proof.map(|p| encode_proof(&p)))
    }

    async fn get_finalization(
        &self,
        payload: Digest,
    ) -> Result<Option<Vec<u8>>, QueryError> {
        let cert = self
            .mailbox
            .get_finalization(payload)
            .await
            .map_err(|_| QueryError::ChannelClosed)?;
        Ok(cert.map(Vec::from))
    }

    async fn get_latest_block(&self) -> Result<Option<LatestBlock>, QueryError> {
        self.mailbox
            .get_latest_block()
            .await
            .map_err(|_| QueryError::ChannelClosed)
    }

    async fn submit_tx(&self, tx: Transaction) -> Result<(), QueryError> {
        self.mailbox.submit_tx(tx).await;
        Ok(())
    }
}
