mod finalized;
mod speculative;
pub mod store;
mod transition;

use hellas_types::{Coin, ObjectId};

/// The created/deleted diffs produced by executing a block.
///
/// Always present for finalized payloads; vectors may be empty for
/// blocks that carry no transactions.
#[derive(Clone, Debug)]
pub(crate) struct FinalizationDiffs {
    pub created: Vec<(ObjectId, Coin)>,
    pub deleted: Vec<ObjectId>,
}

pub(crate) use finalized::FinalizationTracker;
pub(crate) use speculative::SpeculativeExecutionStore;
pub(crate) use transition::ObjectState;
pub(crate) use transition::execute_transaction;
pub use transition::{ExecutionError, execute_block, genesis_state};
