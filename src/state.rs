//! Kernel state surface: the apply driver over a concrete [`Store`].

use crate::{
    block::Block,
    context::Context,
    error::{BatchError, InsertError, KernelResult},
    event::{Diff, Event},
    list::List,
    object::Genesis,
    op::Op,
    store::{Store, Tx},
    view::{Snapshot, View},
};

/// Kernel state over a concrete object store.
///
/// Once a [`Store`] is wrapped in a `State`, mutation only happens through
/// [`State::apply`] or [`State::apply_all`]. The store can be observed
/// read-only via [`State::store`] and reclaimed via
/// [`State::into_store`].
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub struct State<S> {
    store: S,
}

impl<S> State<S> {
    /// Returns the backing object store.
    #[must_use]
    pub const fn store(&self) -> &S {
        &self.store
    }

    /// Consumes the kernel state and returns the backing object store.
    #[must_use]
    pub fn into_store(self) -> S {
        self.store
    }

    /// Returns an abstract view of the backing store.
    #[must_use]
    pub fn view<const C: usize, const E: usize>(&self) -> View<C, E>
    where
        S: Snapshot<C, E>,
    {
        self.store.view()
    }
}

impl<S: Store> State<S> {
    /// Populates an object store with genesis seeds and wraps it as state.
    ///
    /// # Errors
    ///
    /// Returns [`InsertError`] if the backing store rejects a seed insertion.
    pub fn genesis(mut store: S, seeds: &[Genesis]) -> KernelResult<Self, InsertError> {
        let mut tx = store.begin();

        for seed in seeds {
            seed.insert(&mut tx)?;
        }

        tx.commit();
        Ok(Self { store })
    }

    /// Applies one ordered operation to the object store.
    ///
    /// Validation runs read-only against the staged transaction. If validation
    /// succeeds, the resulting event is folded into the transaction and
    /// committed. A failing apply leaves the backing store unchanged.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ApplyError`] if the operation is not valid for the
    /// current store contents or if the backing store rejects an insertion.
    pub fn apply(&mut self, context: Context, operation: &Op) -> KernelResult<Event> {
        let mut tx = self.store.begin();
        let change = operation.apply(context, &tx)?;
        change.fold(&mut tx)?;
        tx.commit();
        Ok(change.event())
    }

    /// Applies an ordered operation batch atomically and returns its diff.
    ///
    /// Validation and folding share one staged transaction across the batch. If
    /// any operation fails, the transaction is dropped and the backing store is
    /// unchanged.
    ///
    /// # Errors
    ///
    /// Returns [`BatchError`] with the failed operation index and source error.
    pub fn apply_all<const N: usize>(
        &mut self,
        context: Context,
        operations: &List<Op, N>,
    ) -> KernelResult<Diff<N>, BatchError> {
        let mut tx = self.store.begin();
        let mut diff = Diff::empty();

        for (index, operation) in operations.iter().enumerate() {
            let change = operation
                .apply(context, &tx)
                .map_err(|source| BatchError::new(index, source))?;
            change
                .fold(&mut tx)
                .map_err(|source| BatchError::new(index, source))?;
            diff.push(&change.event());
        }

        tx.commit();
        Ok(diff)
    }

    /// Applies one ordered block atomically and returns its diff.
    ///
    /// # Errors
    ///
    /// Returns [`BatchError`] with the failed operation index and source error.
    pub fn apply_block<const N: usize>(
        &mut self,
        block: &Block<N>,
    ) -> KernelResult<Diff<N>, BatchError> {
        self.apply_all(block.context(), block.ops())
    }
}
