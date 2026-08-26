//! Posting the two Opens: the driver that turns a completed handshake
//! into a channel on chain.
//!
//! # What was missing
//!
//! [`SetupState::decide`] is §6's five-way recovery machine and it has
//! been complete for a while. What it never had was anything to drive
//! it: something that reads one coherent finalized state, asks it what
//! to do, records that step before taking it, and reads the blocks back
//! to find out whether it landed. [`advance_setup`] is that, and it adds
//! no decision of its own — every branch below is a `SetupDecision`, and
//! the two it does not act on say so.
//!
//! # Durable before broadcast
//!
//! The same rule [`crate::work_close`] obeys for a close, in the same
//! order: the marker is committed and fsynced, and only then is the
//! transaction handed to a sink. A crash between the two leaves a
//! journal that says the bond was submitted when it may not have been,
//! and that is the safe half — the next run re-decides from the chain,
//! sees no bond, and submits the *retained* bytes again. A resubmission
//! is the same Open and not a second one: `apply_open` refuses it twice
//! over, once because the funding coins the first one consumed are gone
//! and once with `ApplyError::EdgeExists` for the edge already there.
//!
//! The other order is the one that cannot be recovered from: broadcast
//! first, crash, and the journal has no record that a transaction
//! carrying this provider's signature is in flight.
//!
//! # Where the channel begins
//!
//! [`SetupRecord::Complete`] carries the block the payment Open landed
//! in — its height, its payload, and its parent's payload, which is the
//! cursor a channel watcher starts from. None of those three can be
//! derived from the objects: a live edge says the Open was accepted, not
//! where. So [`advance_setup`] reads finalized blocks until it finds the
//! one whose accepted transactions contain an Open deriving this payment
//! edge.
//!
//! `origin_floor` is where that scan starts and it is a cost, not a
//! premise. An Open consumes its funding coins, so the whole chain holds
//! at most one block containing it: a floor below the origin finds the
//! same block a floor of zero would, and a floor above it finds nothing
//! and returns [`SetupDriveError::OriginNotFound`] rather than recording
//! a cursor it guessed. Nothing in the setup journal retains a scan
//! position, so a driver that has restarted and has no floor of its own
//! passes zero and pays for it in reads.
//!
//! # What it does not do
//!
//! It does not take an unleased bond's Timeout back.
//! [`SetupDecision::TimeoutBond`] is returned to the caller as
//! [`SetupProgress::TimeoutBond`] and nothing here submits it: the
//! journal has no record with which to mark that submission, and this
//! module submits nothing it cannot write down first. Nothing else in
//! this workspace submits one either — `Tx::timeout_close` has no caller
//! outside tests — so a provider whose setup ends there gets its stake
//! back only by an operator building and sending that transaction.
//!
//! It does not exchange revisions with the peer. That is
//! [`crate::work_handshake::exchange_setup`], and a caller runs the two
//! in the obvious order: exchange until the bundle is complete, then
//! drive until the journals record it.

use std::collections::BTreeSet;

use hellas_kernel::{CoinId, Edge, EdgeId, LeaseSlots, SigVerifier, Tx};

use crate::work_close::{BlockSourceError, FinalizedBlocks, TxSink};
use crate::work_store::{
    ObservedSetup, SetupAbort, SetupDecision, SetupEnd, SetupFault, SetupOrigin, SetupRecord,
    SetupState, SetupStore, WorkStoreError,
};

/// Which channel a setup read answers for, and which coins it must
/// answer for at the same state.
///
/// The coins are the two retained Opens' funding, and they are part of
/// the question rather than a second call for the reason
/// [`SetupState::decide`] takes them in one struct: the branch that
/// locks a provider's stake has their liveness as a premise, and a
/// premise read at a different state than the edges is a premise about
/// a state the decision is not being made at.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetupQuery {
    /// The tag-4 work-stake bond this setup opens.
    pub bond_edge: EdgeId,
    /// The tag-2 payment edge it opens over that bond.
    pub payment_edge: EdgeId,
    /// Every coin the two retained Opens spend.
    pub funding: BTreeSet<CoinId>,
}

/// One coherent finalized read a setup decision is made from.
///
/// Owned, where [`ObservedSetup`] borrows, because this is what crosses
/// the trait boundary from whatever holds the chain. [`Self::observed`]
/// is the only way to turn it into a decision's input, so the height
/// the edges came from and the height the coins came from cannot be two
/// heights.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinalizedSetup {
    /// Finalized height every field below was read at.
    pub height: u64,
    /// The bond edge, or its absence.
    pub bond: Option<Edge>,
    /// The payment edge, or its absence.
    pub payment: Option<Edge>,
    /// What the bond's lease slots held.
    pub lease: LeaseSlots,
    /// Which of the query's coins are still live.
    pub live_funding: BTreeSet<CoinId>,
}

impl FinalizedSetup {
    /// Returns this read as the decision's input.
    #[must_use]
    pub fn observed(&self) -> ObservedSetup<'_> {
        ObservedSetup {
            height: self.height,
            bond: self.bond.as_ref(),
            payment: self.payment.as_ref(),
            lease: self.lease,
            live_funding: &self.live_funding,
        }
    }
}

/// Where a setup decision's finalized state comes from.
///
/// Narrow, and in this crate rather than in the chain crate, for
/// [`FinalizedBlocks`]'s reason: this is the whole of what driving a
/// setup needs from a chain, and an endpoint that does paid work should
/// not have to be handed an activity stream and a mempool to get it.
pub trait SetupView {
    /// Returns one coherent read of this setup, at one finalized block.
    ///
    /// `Ok(None)` means the source has no finalized state to answer
    /// from at all — not that the channel is absent. An existing setup
    /// whose objects are all missing at a real finalized block is
    /// `Ok(Some(..))` with absent objects, and those are different
    /// facts.
    ///
    /// The implementation owes the coherence, exactly as
    /// [`ObservedSetup`]'s caller does: every field must come from one
    /// state, and `live_funding` must be a subset of `query.funding`
    /// read at that same state.
    fn finalized_setup(
        &self,
        query: SetupQuery,
    ) -> impl core::future::Future<Output = Result<Option<FinalizedSetup>, BlockSourceError>> + Send;
}

/// Which of the two Opens was handed to consensus.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetupStep {
    /// The provider's tag-4 stake bond.
    Bond,
    /// The client's tag-2 payment channel over it.
    Payment,
}

/// How far one step of the driver got.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetupProgress {
    /// Both edges and this channel's lease are finalized, and the
    /// journal now records where.
    Complete(SetupOrigin),
    /// A retained Open was journaled and handed to consensus. It is not
    /// included until a block says so.
    Submitted {
        /// Which of the two.
        step: SetupStep,
        /// What the node did with the transaction.
        outcome: crate::SubmitTxOutcome,
    },
    /// Nothing for this endpoint to do: the other party has not
    /// produced the next revision, or the transaction being waited on
    /// is not this endpoint's to send.
    AwaitingCounterparty,
    /// The source has no finalized state to decide from yet.
    AwaitingFinalizedState,
    /// The bond is live and unleased and this channel cannot use it.
    /// Its Timeout is immediate, and nothing here sends one.
    TimeoutBond,
    /// Setup stopped with the provider's coins unspent, and the journal
    /// records it.
    Aborted(SetupAbort),
    /// Setup stopped in a state no automatic step can leave, and the
    /// journal records it.
    Faulted(SetupFault),
}

/// Why one step of the driver did not finish.
#[derive(Debug, thiserror::Error)]
pub enum SetupDriveError {
    /// The finalized state or the block source failed.
    #[error(transparent)]
    Source(#[from] BlockSourceError),
    /// A step could not be made durable, or the journal refused it.
    #[error(transparent)]
    Store(#[from] WorkStoreError),
    /// A block inside the origin scan could not be read, so where the
    /// channel begins is still unknown.
    #[error("finalized block {height} is not available, so the channel's origin is unread")]
    OriginUnreadable {
        /// Height that could not be read.
        height: u64,
    },
    /// No finalized block above the floor carries the payment Open.
    ///
    /// Reached by a floor above the block that does carry it, and by a
    /// source that is missing history it claims to have. Either way
    /// nothing is recorded: an origin is a watcher's starting cursor,
    /// and a guessed one skips every block before it.
    #[error("no finalized block in {floor}..={tip} opened payment edge {edge:?}")]
    OriginNotFound {
        /// Height the scan started above.
        floor: u64,
        /// Highest finalized height the source reported.
        tip: u64,
        /// Edge the scan was looking for.
        edge: EdgeId,
    },
    /// The journal has no executable transaction for a step it just
    /// accepted a marker for.
    ///
    /// Unreachable through [`advance_setup`]: `decide` proposes neither
    /// submission before both Opens are executable, and
    /// `SetupStore::commit` refuses both markers for the same reason.
    /// Named so the match is total; no test reaches it, and none claims
    /// to.
    #[error("the journal retains no {step:?} open to submit")]
    NothingRetained {
        /// Step whose transaction was missing.
        step: SetupStep,
    },
}

/// Takes one step of the setup this journal holds.
///
/// One step, not a loop, for [`crate::work_close::advance_close`]'s
/// reason: nothing in this crate has a clock, and a loop written here
/// would spin against a chain that finalizes at its own rate. What the
/// step gives a caller with one is the whole answer —
/// [`SetupProgress`] says whether to call again, and the three terminal
/// values are the three ways a setup ends.
///
/// Called on either endpoint. There is no role argument, because
/// `decide` reads the role out of the journal and answers a client with
/// [`SetupDecision::AwaitingCounterparty`] for every step that is the
/// provider's to take — while still answering both parties with
/// [`SetupDecision::Complete`], which is why both journals can record
/// the same origin.
///
/// # Errors
///
/// [`SetupDriveError::Source`] when the finalized read or a block read
/// fails, [`SetupDriveError::Store`] when a record is refused or cannot
/// be made durable, and the two origin errors when completion cannot be
/// tied to the block that produced it.
pub async fn advance_setup<W, B, T, V>(
    view: &W,
    blocks: &B,
    sink: &T,
    store: &mut SetupStore,
    verifier: &V,
    origin_floor: u64,
) -> Result<SetupProgress, SetupDriveError>
where
    W: SetupView + ?Sized,
    B: FinalizedBlocks + ?Sized,
    T: TxSink + ?Sized,
    V: SigVerifier,
{
    // A setup that has already ended is answered from the journal. Not
    // a second copy of `decide`'s first branch — that branch answers
    // the same question and would answer it the same way — but the one
    // shortcut that keeps a finished setup from reading the chain
    // forever, and the only place the recorded origin is still in hand.
    if let Some(origin) = store.state().origin() {
        return Ok(SetupProgress::Complete(origin));
    }
    match store.state().end() {
        Some(SetupEnd::Aborted(abort)) => return Ok(SetupProgress::Aborted(abort)),
        Some(SetupEnd::Faulted(fault)) => return Ok(SetupProgress::Faulted(fault)),
        // `Complete` is the origin above, which was `None`.
        Some(SetupEnd::Complete) | None => {}
    }

    let Some(query) = query_of(store.state()) else {
        // No payment leg has been proposed, so this setup names no
        // payment edge and there is no channel on chain to read for.
        return Ok(SetupProgress::AwaitingCounterparty);
    };
    let payment_edge = query.payment_edge;
    let Some(finalized) = view.finalized_setup(query).await? else {
        return Ok(SetupProgress::AwaitingFinalizedState);
    };

    match store.state().decide(&finalized.observed()) {
        SetupDecision::SubmitBond => submit(store, sink, verifier, SetupStep::Bond).await,
        SetupDecision::SubmitPayment => submit(store, sink, verifier, SetupStep::Payment).await,
        SetupDecision::Complete => {
            let origin = find_origin(blocks, payment_edge, origin_floor).await?;
            store.commit(
                SetupRecord::Complete {
                    payment_edge: origin.payment_edge,
                    origin_height: origin.height,
                    origin_payload: origin.payload,
                    origin_parent: origin.parent,
                },
                verifier,
            )?;
            Ok(SetupProgress::Complete(origin))
        }
        SetupDecision::Abort(abort) => {
            store.commit(
                SetupRecord::Ended {
                    outcome: SetupEnd::Aborted(abort),
                },
                verifier,
            )?;
            Ok(SetupProgress::Aborted(abort))
        }
        SetupDecision::Fault(fault) => {
            store.commit(
                SetupRecord::Ended {
                    outcome: SetupEnd::Faulted(fault),
                },
                verifier,
            )?;
            Ok(SetupProgress::Faulted(fault))
        }
        SetupDecision::TimeoutBond => Ok(SetupProgress::TimeoutBond),
        SetupDecision::AwaitingCounterparty => Ok(SetupProgress::AwaitingCounterparty),
    }
}

/// Returns what to read for this setup, once it names a payment edge.
///
/// The coins come from [`SetupState::funding_coins`], which derives them
/// from the retained transactions. A caller cannot ask about a coin set
/// the signed bytes do not name, and the preflight cannot be run against
/// a convenient one.
fn query_of(state: &SetupState) -> Option<SetupQuery> {
    Some(SetupQuery {
        bond_edge: state.bond_edge(),
        payment_edge: state.payment_edge()?,
        funding: state.funding_coins(),
    })
}

/// Journals one submission marker and then broadcasts the retained
/// Open.
///
/// The commit is first and the `?` on it is what makes that binding: a
/// journal that will not take the marker is a journal this endpoint
/// does not broadcast from.
async fn submit<T, V>(
    store: &mut SetupStore,
    sink: &T,
    verifier: &V,
    step: SetupStep,
) -> Result<SetupProgress, SetupDriveError>
where
    T: TxSink + ?Sized,
    V: SigVerifier,
{
    let record = match step {
        SetupStep::Bond => SetupRecord::BondSubmitted,
        SetupStep::Payment => SetupRecord::PaymentSubmitted,
    };
    let state = store.commit(record, verifier)?;
    let tx = match step {
        SetupStep::Bond => state.bond_open(),
        SetupStep::Payment => state.payment_open(),
    }
    .ok_or(SetupDriveError::NothingRetained { step })?;
    let outcome = sink.submit(tx).await?;
    Ok(SetupProgress::Submitted { step, outcome })
}

/// Finds the finalized block whose accepted transactions opened
/// `payment_edge`.
///
/// The match is on the edge id the kernel derives from an Open's own
/// funding and terms, not on the retained bytes: the edge is what the
/// snapshot established is live, and it is what the journal's completion
/// record is keyed to.
async fn find_origin<B>(
    blocks: &B,
    payment_edge: EdgeId,
    floor: u64,
) -> Result<SetupOrigin, SetupDriveError>
where
    B: FinalizedBlocks + ?Sized,
{
    let tip = blocks.latest_height().await?.unwrap_or(0);
    let mut height = floor.saturating_add(1);
    while height <= tip {
        let block = blocks
            .block_at(height)
            .await?
            .ok_or(SetupDriveError::OriginUnreadable { height })?;
        if block.txs.iter().any(|tx| opens(tx, payment_edge)) {
            return Ok(SetupOrigin {
                payment_edge,
                height: block.height,
                payload: block.payload,
                parent: block.parent,
            });
        }
        height = height.saturating_add(1);
    }
    Err(SetupDriveError::OriginNotFound {
        floor,
        tip,
        edge: payment_edge,
    })
}

/// Returns whether this transaction is the Open that produces `edge`.
fn opens(tx: &Tx, edge: EdgeId) -> bool {
    match tx {
        Tx::Open { funding, terms, .. } => Tx::edge_id_of(funding, terms) == edge,
        _ => false,
    }
}
