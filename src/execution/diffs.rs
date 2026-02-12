use crate::object::{Coin, ObjectId};

/// The created/deleted diffs produced by executing a block.
///
/// Always present for finalized payloads; vectors may be empty for
/// blocks that carry no transactions.
#[derive(Clone, Debug)]
pub(crate) struct FinalizationDiffs {
    pub created: Vec<(ObjectId, Coin)>,
    pub deleted: Vec<ObjectId>,
}
