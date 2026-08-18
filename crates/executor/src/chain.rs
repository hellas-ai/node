//! Chain observation seam.
//!
//! The executor runs in its own process by default; [`ChainView`] is
//! the narrow chain surface it needs — the finalized height,
//! transaction submission, and edge reads. Any
//! [`hellas_chain::LightClient`] satisfies it through the blanket impl,
//! so one executor composes over either topology: connect out to a
//! relay/indexer/validator with a remote light client, or co-host a
//! node in-process and hand its client here.
//!
//! [`kernel_signer`] is the identity bridge: the provider's on-chain
//! party key IS its RPC producer identity, one secp256k1 scalar read
//! through two primitive crates.

use hellas_chain::domain::{ObjectId, Transaction};
use hellas_chain::{EdgeState, LightClient, QueryError};
use hellas_kernel::{BlockHeight, Secp256k1Signer};
use hellas_rpc::ProducerSigningKey;

/// Decodes a fixed-width byte field, naming it in the failure.
///
/// The crate's one copy of this: `state` and `evaluate` wrap it in
/// their own error type rather than restating the conversion.
pub(crate) fn fixed<const N: usize>(field: &str, bytes: &[u8]) -> Result<[u8; N], String> {
    bytes
        .try_into()
        .map_err(|_| format!("{field} must be {N} bytes, got {}", bytes.len()))
}

/// Kernel signer sharing the producer identity's secp256k1 scalar: the
/// provider's on-chain party key IS its RPC identity.
///
/// Same curve, same 32-byte scalar, same 33-byte compressed public key
/// and 64-byte low-S compact signature — only the primitive crate
/// differs (k256 here, libsecp256k1 in the kernel), and the wire bytes
/// are interoperable.
#[must_use]
pub fn kernel_signer(producer: &ProducerSigningKey) -> Secp256k1Signer {
    Secp256k1Signer::from_secret_scalar(producer.to_secret_bytes())
        .expect("producer keys are valid secp256k1 scalars")
}

/// The chain surface the executor needs, and nothing more.
#[async_trait::async_trait]
pub trait ChainView: Send + Sync + 'static {
    /// Highest finalized block height, `None` before the first
    /// finalization is observed.
    async fn finalized_height(&self) -> Result<Option<BlockHeight>, QueryError>;

    /// Submits a transaction to the chain mempool.
    async fn submit(&self, tx: Transaction) -> Result<(), QueryError>;

    /// Reads a live edge at the latest finalized state. `None` when no
    /// block is finalized yet or the edge does not exist there.
    async fn edge(&self, id: ObjectId) -> Result<Option<EdgeState>, QueryError>;
}

#[async_trait::async_trait]
impl<L: LightClient> ChainView for L {
    async fn finalized_height(&self) -> Result<Option<BlockHeight>, QueryError> {
        Ok(self
            .get_latest_block()
            .await?
            .map(|block| BlockHeight::new(block.height)))
    }

    async fn submit(&self, tx: Transaction) -> Result<(), QueryError> {
        self.submit_tx(tx).await
    }

    async fn edge(&self, id: ObjectId) -> Result<Option<EdgeState>, QueryError> {
        let Some(latest) = self.get_latest_block().await? else {
            return Ok(None);
        };
        Ok(self
            .get_edge(latest.payload, id)
            .await?
            .and_then(|lookup| lookup.edge))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hellas_rpc::PublicKey;

    #[test]
    fn kernel_signer_shares_the_producer_identity() {
        let producer = ProducerSigningKey::from_secret_bytes([7; 32])
            .expect("non-zero scalar is a valid producer key");
        let signer = kernel_signer(&producer);
        let PublicKey::Secp256k1(compressed) = producer.public_key() else {
            panic!("producer keys are secp256k1");
        };
        assert_eq!(signer.party_key().as_bytes(), &compressed);
    }
}
