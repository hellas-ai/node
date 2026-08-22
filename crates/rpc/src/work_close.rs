//! Spending the certificate: the finalized cursor, and the two
//! transactions that turn a signed scalar into coins.
//!
//! # Why the cursor is the load-bearing part
//!
//! Five rules elsewhere in this crate are decided against a height —
//! whether a receipt is timely, whether a payment is timely, whether a
//! job's deadlines are still reachable, whether plaintext released now
//! can still arrive, and whether a readiness decision may be acted on.
//! Every one of them reads
//! [`ChannelState::cursor`](crate::work_store::ChannelState::cursor). Until this module
//! there was no writer for it outside tests, and a cursor that never
//! moves makes every one of those rules pass: a receipt three hundred
//! blocks late reads as timely against a height that stopped.
//!
//! So the cursor is not the plumbing around the close. It is what makes
//! the deadlines mean anything, and [`observe`] is the only thing that
//! moves it.
//!
//! # Contiguous, or not at all
//!
//! [`observe`] takes one block and commits one
//! [`ChannelRecord::CursorAdvanced`], and that record refuses anything
//! but the next height whose parent is the block already held. A
//! notification that the chain has reached height 900 is a wake-up; it
//! is not evidence that this endpoint read 880 through 899, and the
//! close and the deadline those blocks may have carried are exactly
//! what it would be missing.
//!
//! [`catch_up`] is therefore a loop and not a jump. A block the source
//! cannot supply stops it, and the cursor stays where it was — which
//! makes every gate above fail closed rather than pass on a stale
//! height.
//!
//! # What a watcher looks for
//!
//! Two things, both on this channel's own payment edge. An accepted
//! [`Move::StartPaymentClose`](hellas_kernel::Move::StartPaymentClose) means a contest is live, and the height
//! that accepted it is the only place the contest's identifier can come
//! from — the kernel derives [`StartId`](hellas_kernel::StartId) from the start
//! digest *and*
//! the inclusion height, so no retained signature determines it. An
//! accepted [`Tx::Close`] means the edge is gone, and what it paid is
//! read out of the transaction consensus admitted.
//!
//! # Non-destructive broadcast
//!
//! Nothing here consumes evidence to produce a transaction.
//!
//! - [`close_start`] builds and signs; [`crate::work::ProviderEndpoint`]
//!   commits the exact bytes before they are handed to a chain. A crash
//!   between signing and that commit loses a signature nobody has, and
//!   the retry signs again at whatever height the cursor has reached. A
//!   crash after it leaves bytes that are re-sent verbatim, and the
//!   kernel admits at most one contest per edge — so a resubmission is
//!   not a second close, it is the same one.
//! - The certificate the start carries stays in the journal it was
//!   admitted into. The start holds a copy; it never becomes the only
//!   copy.
//! - [`adjudicated_close`] is derived, not retained: its payouts come
//!   from the contest record consensus itself holds, so it can be
//!   rebuilt after any crash from a fresh finalized read. What cannot be
//!   rebuilt after the edge is consumed is the exact close *bytes* — and
//!   nothing needs them, because [`observe`] recognises settlement by
//!   the edge being closed rather than by matching bytes it kept.
//!
//! # What this module does not do
//!
//! It signs no cooperative freeze. That exit needs both parties'
//! signatures over one amount and no exchange in this crate negotiates
//! them; a freeze built here would be a transaction with one signature
//! and a place to put the other.

use hellas_kernel::{
    EarnedCertificate, List, MAX_EDGE_OUTPUTS, Party, PayloadHash, PaymentCloseResponse,
    PaymentCloseStart, Payout, PendingPaymentClose, Proof, Secp256k1Signer, Sig, SigVerifier,
    StartId, Terms, Tx, WorkPaymentSettlement, adjudicated_payouts, no_earned_digest,
};

use crate::protocol::work::PaidChannel;
use crate::work_store::{
    Applied, ChannelRecord, ChannelStore, JobEnd, JobPhase, Role, WorkStoreError,
};

/// One finalized block, as a watcher must see it.
///
/// The transactions are this block's accepted kernel transactions in
/// consensus order — the order `HellasBlock::txs()` exposes, not a set
/// and not a key-sorted projection. Two transactions in one block can
/// be a start and the close that ends it, and reversing them is two
/// different histories.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinalizedWork {
    /// Finalized height of this block.
    pub height: u64,
    /// Payload digest this block names as its parent.
    pub parent: [u8; 32],
    /// This block's own payload digest.
    pub payload: [u8; 32],
    /// The kernel transactions this block accepted, in block order.
    pub txs: Vec<Tx>,
}

/// Why a finalized block could not be read.
///
/// Opaque, like [`crate::work::BackendFault`]: a watcher does the same
/// thing for every one of them, which is stop and leave the cursor
/// where it was.
#[derive(Clone, Debug, thiserror::Error)]
#[error("the finalized block source failed: {0}")]
pub struct BlockSourceError(String);

impl BlockSourceError {
    /// Reports a source failure.
    #[must_use]
    pub fn new(reason: impl Into<String>) -> Self {
        Self(reason.into())
    }
}

/// Where a watcher gets its finalized blocks.
///
/// Narrow on purpose, and in this crate rather than in the chain crate,
/// because both endpoints need exactly this and neither needs a
/// mempool, a coin query, or an activity stream to get it. It is also
/// what lets the loop below be tested against a history a test writes
/// down rather than a validator it runs.
pub trait FinalizedBlocks {
    /// Returns the highest finalized height, or `None` before anything
    /// is finalized.
    fn latest_height(
        &self,
    ) -> impl core::future::Future<Output = Result<Option<u64>, BlockSourceError>> + Send;

    /// Returns the finalized block at `height`.
    ///
    /// `Ok(None)` means this source cannot supply that height — it is
    /// not finalized, or it has been pruned. Both stop a scan; neither
    /// is a reason to skip it.
    fn block_at(
        &self,
        height: u64,
    ) -> impl core::future::Future<Output = Result<Option<FinalizedWork>, BlockSourceError>> + Send;
}

/// Why a close could not be built.
#[derive(Debug, thiserror::Error)]
pub enum CloseError {
    /// The terms fix a zero-block start window, so no signature could
    /// ever be included.
    #[error("the payment terms admit no start validity window")]
    NoValidityWindow,
    /// The window arithmetic left the representable range.
    #[error("the start validity window overflows past height {height}")]
    WindowOverflow {
        /// Height the window was anchored at.
        height: u64,
    },
    /// A contest is live on this edge and it is not the one this
    /// endpoint opened.
    #[error("the live contest is not the one this endpoint started")]
    OtherContest,
    /// No finalized contest is open for this endpoint's start.
    #[error("no finalized contest is open on this payment edge")]
    NoContest,
    /// The provider's response window has not run out, so consensus
    /// would refuse this close.
    #[error("the response window is open until height {deadline}, and the cursor is at {height}")]
    ResponseWindowOpen {
        /// Finalized height the endpoint has reached.
        height: u64,
        /// Height at which the window shuts.
        deadline: u64,
    },
    /// The contest has already been answered, and there is one answer.
    #[error("this contest has already been answered")]
    AlreadyResponded,
    /// The response window has shut, so consensus would refuse an
    /// answer.
    #[error("the response window shut at height {deadline}, and the read is at {height}")]
    ResponseWindowClosed {
        /// Finalized height the read was taken at.
        height: u64,
        /// Height at which the window shut.
        deadline: u64,
    },
    /// This endpoint holds nothing the contest does not already settle.
    ///
    /// Not a fault. An answer has to strictly advance the amount, so a
    /// contest already at this endpoint's own high-water is one there
    /// is nothing to say about — and saying it would spend the one
    /// answer the window admits.
    #[error("the contest already settles {settled}, and this endpoint holds {held}")]
    NothingToAdd {
        /// Largest certificate this endpoint holds.
        held: u64,
        /// Amount the contest currently settles at.
        settled: u64,
    },
    /// The payouts this contest settles do not fit what the edge
    /// distributes.
    #[error("the contest settles more than this edge's adjudicated route distributes")]
    Unpayable,
    /// The step could not be made durable, or the journal refused it.
    #[error(transparent)]
    Store(#[from] WorkStoreError),
}

/// Why a catch-up did not finish.
#[derive(Debug, thiserror::Error)]
pub enum CatchUpError {
    /// The block source failed.
    #[error(transparent)]
    Source(#[from] BlockSourceError),
    /// A block inside the range this endpoint must read is not
    /// available. The cursor stays where it was.
    #[error("finalized block {height} is not available, so the cursor stays behind")]
    Missing {
        /// Height that could not be read.
        height: u64,
    },
    /// A block was refused by the journal.
    #[error(transparent)]
    Store(#[from] WorkStoreError),
}

/// Returns the digest a close opener signs for `start`.
///
/// One spelling on this side of the wire. The kernel builds the same
/// digest from the *edge* it reads, so a start whose terms are not the
/// edge's is refused there before any signature is checked; here the
/// terms are the channel's own, and every start this is called on is
/// one on this channel's payment edge.
#[must_use]
pub fn start_body_digest(channel: &PaidChannel, start: &PaymentCloseStart) -> PayloadHash {
    let earned = match start.certificate() {
        None => no_earned_digest(channel.payment_edge(), channel.payment_terms_hash()),
        Some((certificate, _)) => certificate.digest(channel.network()),
    };
    hellas_kernel::start_digest(
        channel.network(),
        channel.payment_edge(),
        channel.payment_terms_hash(),
        start.opener_role(),
        (start.valid_from_height(), start.valid_through_height()),
        earned,
    )
}

/// Builds and signs one close start at finalized height `height`.
///
/// The window is `[height + 1, height + start_validity_blocks]`, and
/// the two ends are the kernel's own inclusive interpretation: the next
/// block is the first one that can carry a signature made now, and the
/// span of a one-block window is one. Both additions are checked, so a
/// height within one window of the ceiling refuses to sign rather than
/// wrapping into a window that has already shut.
///
/// A zero-amount certificate has no representation here and needs none:
/// a journal only ever retains a certificate that exceeded what it
/// already held, and nothing exceeds zero. An opener with nothing to
/// claim passes `None`, which is the kernel's one spelling for it.
///
/// # Errors
///
/// [`CloseError::NoValidityWindow`] when the terms fix a zero-block
/// window, and [`CloseError::WindowOverflow`] when either addition
/// leaves the representable range.
pub fn close_start(
    channel: &PaidChannel,
    opener_role: Party,
    height: u64,
    certificate: Option<(EarnedCertificate, Sig)>,
    signer: &Secp256k1Signer,
) -> Result<PaymentCloseStart, CloseError> {
    let span = channel.payment_terms().start_validity_blocks;
    if span == 0 {
        return Err(CloseError::NoValidityWindow);
    }
    let valid_from = height
        .checked_add(1)
        .ok_or(CloseError::WindowOverflow { height })?;
    let valid_through = valid_from
        .checked_add(span - 1)
        .ok_or(CloseError::WindowOverflow { height })?;

    // Built once with a placeholder signature, so the digest is taken
    // from exactly the body that will carry it. The action signature is
    // not part of what it covers, which is what makes this safe rather
    // than circular.
    let unsigned = PaymentCloseStart::new(
        channel.payment_edge(),
        Terms::work_payment(channel.payment_terms().clone()),
        opener_role,
        (valid_from, valid_through),
        certificate,
        Sig::from_bytes([0_u8; Sig::LENGTH]),
    );
    let action_sig = signer.sign(start_body_digest(channel, &unsigned));
    Ok(PaymentCloseStart::new(
        channel.payment_edge(),
        Terms::work_payment(channel.payment_terms().clone()),
        opener_role,
        (valid_from, valid_through),
        unsigned.certificate().copied(),
        action_sig,
    ))
}

/// Builds the provider's one answer to a contest opened below what it
/// holds.
///
/// The certificate is the client's own, already on this endpoint's disk
/// — an answer reveals no new evidence, it spends evidence the client
/// signed and the opener left out. That is why nothing is journaled
/// before it: the write-ahead step this answer needs is the watcher's
/// [`ChannelRecord::CloseOpened`], which is on the disk before anything
/// can be built from it and is what shuts this channel to new work.
#[must_use]
pub fn close_response(
    channel: &PaidChannel,
    start_id: StartId,
    certificate: (EarnedCertificate, Sig),
    signer: &Secp256k1Signer,
) -> PaymentCloseResponse {
    let earned = certificate.0.digest(channel.network());
    let digest = hellas_kernel::response_digest(
        channel.network(),
        channel.payment_edge(),
        channel.payment_terms_hash(),
        start_id,
        Party::Taker,
        earned,
    );
    PaymentCloseResponse::new(
        channel.payment_edge(),
        start_id,
        Party::Taker,
        certificate,
        signer.sign(digest),
    )
}

/// Builds the close that pays out whatever the contest ended on.
///
/// The amounts are not this endpoint's opinion: `pending` is the record
/// consensus itself holds, and the two payouts come from the kernel's
/// own [`adjudicated_payouts`]. That is why this needs no retained
/// bytes — after any crash it is rebuilt from one finalized read, and
/// it is the same transaction.
///
/// There is no signature on it at all. The amounts were authorized when
/// the certificates behind them were signed, and the window has shut on
/// any further evidence.
///
/// `settlement` is what the *funded* edge distributes, taken from the
/// finalized read that established the channel is live. A close built
/// against an expectation rather than that read would name a total the
/// edge does not hold.
///
/// # Errors
///
/// [`CloseError::Unpayable`] when the settled total does not fit the
/// adjudicated route.
pub fn adjudicated_close(
    channel: &PaidChannel,
    settlement: WorkPaymentSettlement,
    pending: &PendingPaymentClose,
) -> Result<Tx, CloseError> {
    let payouts = adjudicated_payouts(
        settlement,
        channel.payment_terms().parties(),
        pending.final_cumulative(),
        pending.penalty_due(),
    )
    .map_err(|_| CloseError::Unpayable)?;
    let mut outputs = [Payout::default(); MAX_EDGE_OUTPUTS];
    for (slot, payout) in outputs.iter_mut().zip(payouts) {
        *slot = payout;
    }
    Ok(Tx::close(
        channel.payment_edge(),
        Proof::adjudicated(pending.contest_commitment(
            channel.network(),
            channel.payment_edge(),
            channel.payment_terms_hash(),
        )),
        List::take(outputs, payouts.len()),
    ))
}

/// Applies one finalized block to one channel's journal.
///
/// # Nothing is written for a block this journal may not read
///
/// The height and the parent are checked first, against
/// [`ChannelState::reading`](crate::work_store::ChannelState) — the
/// same rule the cursor record itself applies, asked before any of the
/// block's meaning reaches the disk. It has to be first. The
/// transitions below move money and shut the channel, and a block that
/// is not this journal's next one is a block whose contents are not
/// facts: a forged or merely out-of-order `h + 2` would otherwise end a
/// job, record a contest, and only then be refused by the cursor.
///
/// A block this journal has already read is [`Applied::Redundant`] and
/// returns here, having written nothing. Everything it meant is already
/// on the disk.
///
/// # Then the order a crash must be able to stop in
///
/// Everything the block *means* is committed before the cursor that
/// says the block was read, so a process that dies between them
/// re-reads the same block and re-commits the same records — which the
/// journal answers as the retries they are. The other order would
/// advance past a block whose close it had not recorded, and no later
/// scan would go back for it.
///
/// # Errors
///
/// [`WorkStoreError`] when the block is not the contiguous next one —
/// before anything is written — and when a record is refused or cannot
/// be made durable. The cursor is the last thing written, so a refusal
/// anywhere leaves this endpoint still behind this block.
pub fn observe<V: SigVerifier>(
    store: &mut ChannelStore,
    block: &FinalizedWork,
    verifier: &V,
) -> Result<(), WorkStoreError> {
    if store
        .state()
        .reading(block.height, &block.parent, &block.payload)?
        == Applied::Redundant
    {
        return Ok(());
    }
    let channel = store.state().channel().clone();
    let edge = channel.payment_edge();

    if let Some(ending) = expiry_at(store.state(), block.height) {
        store.commit(ChannelRecord::JobEnded { reason: ending }, verifier)?;
    }

    for tx in &block.txs {
        match tx {
            Tx::Move {
                action: hellas_kernel::Move::StartPaymentClose(start),
            } if start.payment_edge() == edge => {
                // A contest on this edge is the cutoff, and the open
                // job does not survive it: no payment will be credited
                // after this record, so a job still in flight is a job
                // that can no longer be paid for. Who bears it is the
                // opener's to answer — a counterparty that cut this
                // endpoint off owes for what it took, and an endpoint
                // that cut itself off owes nobody anything.
                if store.state().job().is_some() {
                    let reason = if start.opener_role() == opposite(store.state().role()) {
                        JobEnd::Expired
                    } else {
                        JobEnd::Failed
                    };
                    store.commit(ChannelRecord::JobEnded { reason }, verifier)?;
                }
                store.commit(
                    ChannelRecord::CloseOpened {
                        start_id: hellas_kernel::start_id(
                            start_body_digest(&channel, start),
                            block.height,
                        ),
                        opener: start.opener_role(),
                    },
                    verifier,
                )?;
            }
            Tx::Close { input, outputs, .. } if *input == edge => {
                let provider_payout = outputs
                    .as_slice()
                    .iter()
                    .find(|payout| payout.owner() == channel.provider_key())
                    .map_or(0, |payout| payout.value());
                if store.state().job().is_some() {
                    store.commit(
                        ChannelRecord::JobEnded {
                            reason: JobEnd::Expired,
                        },
                        verifier,
                    )?;
                }
                store.commit(
                    ChannelRecord::CloseSettled {
                        height: block.height,
                        payload: block.payload,
                        provider_payout,
                    },
                    verifier,
                )?;
            }
            _ => {}
        }
    }

    store.commit(
        ChannelRecord::CursorAdvanced {
            height: block.height,
            parent: block.parent,
            payload: block.payload,
        },
        verifier,
    )?;
    Ok(())
}

/// Returns the party on the other side of the channel from `role`.
const fn opposite(role: Role) -> Party {
    match role {
        Role::Client => Party::Taker,
        Role::Provider => Party::Maker,
    }
}

/// Returns why the open job is over at `height`, if it is.
///
/// Three deadlines, and each says a different thing about who failed.
///
/// - **Acceptance.** A proposal the provider never co-signed cannot be
///   co-signed now, so the job is over and its reservation goes back.
///   Nobody produced anything and nobody owes for it.
/// - **Terminal.** Past it there is no result either party can use: the
///   client's own journal refuses a receipt, so a result signed now
///   could never be paid for. A job that reached this height without
///   one is the provider's own side not finishing, and
///   [`JobEnd::Failed`] is what says the client is not charged for it.
/// - **Payment.** A result exists, it was in time, and the height the
///   client signed to pay by has passed. That is the one ending this
///   counterparty is charged for, and what it costs is
///   `ChannelState::loss_of`'s to decide from how far the job got.
///
/// Only a provider applies them. A client's own journal has no loss
/// ledger to move and no reservation to release, and ending a job it
/// might still be paying for would be a client deciding against itself.
fn expiry_at(state: &crate::work_store::ChannelState, height: u64) -> Option<JobEnd> {
    if state.role() != Role::Provider {
        return None;
    }
    let job = state.job()?;
    let authorization = job.authorization();
    if height > authorization.payment_deadline {
        return Some(JobEnd::Expired);
    }
    if height > authorization.terminal_deadline && job.result().is_none() {
        return Some(JobEnd::Failed);
    }
    if height > authorization.acceptance_deadline && job.phase() == JobPhase::HalfSigned {
        return Some(JobEnd::Expired);
    }
    None
}

/// Reads every finalized block this journal has not seen, in order.
///
/// There is no anchoring step and no height this may start at other
/// than the one after the cursor: the store was opened at the block
/// that opened the channel, so "everything this journal has not seen"
/// is everything that has ever happened to this edge. A scan that
/// chose its own starting height would skip the blocks between the
/// channel opening and the first catch-up, and a close settled in one
/// of them is a close this endpoint would never learn about.
///
/// Returns the height the cursor reached.
///
/// # Errors
///
/// [`CatchUpError::Missing`] when a block inside the range cannot be
/// read — the scan stops there and the cursor keeps the last height it
/// did read — plus the source's own failures and the journal's.
pub async fn catch_up<S, V>(
    source: &S,
    store: &mut ChannelStore,
    verifier: &V,
) -> Result<u64, CatchUpError>
where
    S: FinalizedBlocks + ?Sized,
    V: SigVerifier,
{
    let Some(latest) = source.latest_height().await? else {
        return Ok(store.state().cursor().0);
    };
    let mut next = store.state().cursor().0.saturating_add(1);
    while next <= latest {
        let block = source
            .block_at(next)
            .await?
            .ok_or(CatchUpError::Missing { height: next })?;
        observe(store, &block, verifier)?;
        next = next.saturating_add(1);
    }
    Ok(store.state().cursor().0)
}
