//! Ordered operation batches.
//!
//! Abstract counterpart: the sequential `step` execution in
//! `models/l1.qnt`. The model has no explicit "block" — sequential action
//! application is the model. [`Block`] is the kernel's concrete carrier
//! for one such ordered batch plus the [`Context`] under which it applies,
//! and `models/deps/assumptions.qnt` documents the consensus assumption
//! that finalized blocks arrive in a deterministic order.

use crate::{
    context::{Context, Cost},
    list::List,
    op::Op,
};

/// Ordered kernel operation batch with explicit block context.
#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub struct Block<const N: usize> {
    context: Context,
    ops: List<Op, N>,
}

impl<const N: usize> Block<N> {
    /// Creates an ordered block transition input.
    #[must_use]
    pub const fn new(context: Context, ops: List<Op, N>) -> Self {
        Self { context, ops }
    }

    /// Returns the block context.
    #[must_use]
    pub const fn context(&self) -> Context {
        self.context
    }

    /// Returns the ordered operations.
    #[must_use]
    pub const fn ops(&self) -> &List<Op, N> {
        &self.ops
    }

    /// Returns the total deterministic resource cost of the block.
    #[must_use]
    pub fn cost(&self) -> Option<Cost> {
        let mut cost = Cost::ZERO;

        for op in &self.ops {
            cost = cost.checked_add(op.cost())?;
        }

        Some(cost)
    }

    /// Returns the fee charged by this block's context.
    #[must_use]
    pub fn fee(&self) -> Option<u64> {
        self.context.fee(self.cost()?)
    }

    /// Returns true if the block cost fits within `budget`.
    #[must_use]
    pub fn fits(&self, budget: Cost) -> bool {
        self.cost().is_some_and(|cost| cost.fits(budget))
    }
}
