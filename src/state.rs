//! Kernel state surface: the apply driver over a concrete [`Store`].
//!
//! Abstract counterpart: `models/l1.qnt`. The Quint module owns the same state
//! vars (`coins`, `edges`, `liveCoins`, `liveEdges`, `height`) and dispatches
//! through a `step` relation; here `apply` / `apply_all` / `apply_block` play
//! the same role over a concrete [`Store`].

use crate::{
    block::Block,
    context::Context,
    error::{BatchError, InsertError, KernelResult},
    event::{Change, Diff, Event},
    list::List,
    object::Genesis,
    op::Op,
    store::{Store, Tx},
    verifier::Verifier,
    view::Snapshot,
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
    pub fn view(&self) -> S::View
    where
        S: Snapshot,
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
    pub fn apply<V: Verifier + ?Sized>(
        &mut self,
        context: Context,
        verifier: &V,
        operation: &Op,
    ) -> KernelResult<Event> {
        let mut tx = self.store.begin();
        let event = Self::fold_one(&mut tx, context, verifier, operation)?;
        tx.commit();
        Ok(event)
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
    pub fn apply_all<V: Verifier + ?Sized, const N: usize>(
        &mut self,
        context: Context,
        verifier: &V,
        operations: &List<Op, N>,
    ) -> KernelResult<Diff<N>, BatchError> {
        let mut tx = self.store.begin();
        let mut diff = Diff::empty();

        for (index, operation) in operations.iter().enumerate() {
            let event = Self::fold_one(&mut tx, context, verifier, operation)
                .map_err(|source| BatchError::new(index, source))?;
            diff.push(&event);
        }

        tx.commit();
        Ok(diff)
    }

    /// Applies one ordered block atomically and returns its diff.
    ///
    /// # Errors
    ///
    /// Returns [`BatchError`] with the failed operation index and source error.
    pub fn apply_block<V: Verifier + ?Sized, const N: usize>(
        &mut self,
        verifier: &V,
        block: &Block<N>,
    ) -> KernelResult<Diff<N>, BatchError> {
        self.apply_all(block.context(), verifier, block.ops())
    }

    fn fold_one<T: Tx, V: Verifier + ?Sized>(
        tx: &mut T,
        context: Context,
        verifier: &V,
        operation: &Op,
    ) -> KernelResult<Event> {
        let change = operation.apply(context, verifier, tx)?;
        Self::fold_change(tx, &change)
    }

    fn fold_change<T: Tx>(tx: &mut T, change: &Change) -> KernelResult<Event> {
        change.fold(tx)?;
        Ok(change.event().clone())
    }
}
