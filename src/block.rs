//! Ordered operation batches.

use crate::{
    context::{Context, Cost},
    list::List,
    op::Op,
};

/// Ordered kernel operation batch with explicit block context.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
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

        for op in self.ops.iter() {
            cost = cost.checked_add(op.cost())?;
        }

        Some(cost)
    }

    /// Returns the fee charged by this block's context.
    #[must_use]
    pub fn fee(&self) -> Option<u64> {
        self.context.fee(self.cost()?)
    }

    /// Returns true if any two operations in the block touch the same state
    /// slot.
    #[must_use]
    pub fn conflicts(&self) -> bool {
        let ops = self.ops.as_slice();
        let mut left = 0;

        while left < ops.len() {
            let mut right = left + 1;
            while right < ops.len() {
                if ops[left].conflicts(&ops[right]) {
                    return true;
                }
                right += 1;
            }
            left += 1;
        }

        false
    }
}
