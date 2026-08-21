//! Handing finalized blocks to a paid endpoint's watcher.
//!
//! # Why an adapter and not a blanket impl
//!
//! The watcher's block source is `hellas_rpc::work_close::FinalizedBlocks`
//! and a light client is `crate::LightClient`. Both are foreign to each
//! other, so nothing can implement the first for every one of the
//! second; [`WorkBlocks`] is the one type that owns that pairing. It
//! adds no policy — every decision it could make is made by
//! [`FinalizedBlockView::decode`] above it or by the journal below it.
//!
//! # What crosses
//!
//! One block, checked. `decode` is what turns a bag of bytes beside a
//! finalization certificate into a block: it hashes the bytes against
//! the payload the certificate names, decodes them with the validator's
//! own codec, and checks the height and state root. Only then are the
//! transactions in it facts.
//!
//! They cross in consensus order, and the non-kernel ones are dropped
//! rather than reordered. That is not a projection the watcher has to
//! trust: a transfer or a merge cannot open a contest or close an edge,
//! so the relative order of everything that *can* is exactly the
//! validator's.

use hellas_rpc::work_close::{BlockSourceError, FinalizedBlocks, FinalizedWork};

use crate::block_view::FinalizedBlockView;
use crate::domain::{Digest, Transaction};
use crate::light_client::{FinalizedBlockQuery, LightClient};

/// One light client, as a paid endpoint's block source.
#[derive(Clone, Debug)]
pub struct WorkBlocks<C>(C);

impl<C: LightClient> WorkBlocks<C> {
    /// Reads finalized blocks for a watcher through `client`.
    pub const fn new(client: C) -> Self {
        Self(client)
    }
}

/// Returns a payload digest as the 32 bytes a journal records.
///
/// Copied field by field rather than by a fallible conversion because
/// the two widths are the same width: a Sha256 digest is 32 bytes, and
/// this is only ever called on one. There is no shorter-digest case to
/// report, so there is no error here to swallow.
fn bytes(digest: &Digest) -> [u8; 32] {
    let mut out = [0_u8; 32];
    let source: &[u8] = digest;
    for (slot, byte) in out.iter_mut().zip(source) {
        *slot = *byte;
    }
    out
}

impl<C: LightClient> FinalizedBlocks for WorkBlocks<C> {
    async fn latest_height(&self) -> Result<Option<u64>, BlockSourceError> {
        Ok(self
            .0
            .get_latest_block()
            .await
            .map_err(|error| BlockSourceError::new(error.to_string()))?
            .map(|block| block.height))
    }

    async fn block_at(&self, height: u64) -> Result<Option<FinalizedWork>, BlockSourceError> {
        let Some(finalized) = self
            .0
            .get_finalized_block(FinalizedBlockQuery::Height(height))
            .await
            .map_err(|error| BlockSourceError::new(error.to_string()))?
        else {
            return Ok(None);
        };
        let view = FinalizedBlockView::decode(&finalized)
            .map_err(|error| BlockSourceError::new(error.to_string()))?;
        // The height a caller asked for, against the height the block
        // itself carries. `decode` has already tied the block to its own
        // snapshot; this is what ties that snapshot to the question.
        if view.height() != height {
            return Err(BlockSourceError::new(format!(
                "asked for finalized block {height} and was given {}",
                view.height(),
            )));
        }
        Ok(Some(FinalizedWork {
            height,
            parent: bytes(&view.parent()),
            payload: bytes(&view.payload()),
            txs: view
                .txs()
                .iter()
                .filter_map(|tx| match tx {
                    Transaction::Kernel(kernel) => Some(kernel.clone()),
                    _ => None,
                })
                .collect(),
        }))
    }
}
