//! Kernel state surface: the apply driver over a concrete [`Store`].
//!
//! Abstract counterpart: `models/l1.qnt`. The Quint module owns the same state
//! vars (`coins`, `edges`, `liveCoins`, `liveEdges`, `height`) and dispatches
//! through a `step` relation; here `apply` / `apply_all` / `apply_block` play
//! the same role over a concrete [`Store`].

use core::borrow::Borrow;

use crate::{
    block::Block,
    context::Context,
    error::{BatchError, InsertError, KernelResult},
    event::{Change, Diff, Event},
    list::List,
    object::Genesis,
    store::{Batch, Store},
    tx::Tx,
    verifier::{SealVerifier, SigVerifier},
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
    /// Wraps an already-populated object store as kernel state.
    ///
    /// For genesis bootstrap use [`State::genesis`], which seeds an empty
    /// store and then wraps it. `new` is for callers that manage their
    /// own store population — e.g. restoring from durable storage, or a
    /// host (like `hellas-alto`) that has pre-loaded the block's
    /// referenced objects into a sync working set before invoking the
    /// kernel. The kernel makes no claim about the store's contents; it
    /// just begins applying ordered operations against whatever is
    /// there.
    #[must_use]
    pub const fn new(store: S) -> Self {
        Self { store }
    }

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
    pub fn apply<V: SigVerifier + SealVerifier + ?Sized>(
        &mut self,
        context: Context,
        verifier: &V,
        operation: &Tx,
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
    pub fn apply_all<V: SigVerifier + SealVerifier + ?Sized, const N: usize>(
        &mut self,
        context: Context,
        verifier: &V,
        operations: &List<Tx, N>,
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
    pub fn apply_block<V: SigVerifier + SealVerifier + ?Sized, const N: usize>(
        &mut self,
        verifier: &V,
        block: &Block<N>,
    ) -> KernelResult<Diff<N>, BatchError> {
        self.apply_all(block.context(), verifier, block.ops())
    }

    /// Applies an ordered, dynamically-sized operation batch atomically.
    ///
    /// Equivalent to [`Self::apply_all`] but for callers whose batch size is
    /// not known at the type level. The operation iterator may yield owned
    /// transactions or borrowed transactions. Validation and folding share one
    /// staged transaction; the closure receives each emitted [`Event`] as the
    /// batch progresses, so callers who only need to observe events without
    /// allocating an event vector can do so. If any operation fails the
    /// transaction is dropped, the closure is not called for the failed or
    /// any subsequent operations, and the backing store is unchanged.
    ///
    /// # Pre-commit event emission
    ///
    /// `on_event` fires *before* the batch commits. If operation _k_ succeeds
    /// the closure is called for it; if a later operation in the same batch
    /// fails, the whole transaction is rolled back — but the closure has
    /// already observed event _k_. Consumers that index events to external
    /// systems (RPC subscribers, log indexers, side-channel notifiers) must
    /// **buffer events and only emit downstream after this function returns
    /// `Ok`**, otherwise they will publish events for operations that never
    /// actually committed to the store.
    ///
    /// # Errors
    ///
    /// Returns [`BatchError`] with the failed operation index and source error.
    pub fn apply_iter<V, F, I, B>(
        &mut self,
        context: Context,
        verifier: &V,
        operations: I,
        mut on_event: F,
    ) -> KernelResult<(), BatchError>
    where
        V: SigVerifier + SealVerifier + ?Sized,
        I: IntoIterator<Item = B>,
        B: Borrow<Tx>,
        F: FnMut(usize, &Event),
    {
        let mut tx = self.store.begin();

        for (index, operation) in operations.into_iter().enumerate() {
            let event = Self::fold_one(&mut tx, context, verifier, operation.borrow())
                .map_err(|source| BatchError::new(index, source))?;
            on_event(index, &event);
        }

        tx.commit();
        Ok(())
    }

    fn fold_one<B: Batch, V: SigVerifier + SealVerifier + ?Sized>(
        batch: &mut B,
        context: Context,
        verifier: &V,
        operation: &Tx,
    ) -> KernelResult<Event> {
        let change = operation.apply(context, verifier, batch)?;
        Self::fold_change(batch, &change)
    }

    fn fold_change<B: Batch>(batch: &mut B, change: &Change) -> KernelResult<Event> {
        change.fold(batch)?;
        Ok(change.event().clone())
    }
}
