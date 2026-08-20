//! The client half of a paid job, from a co-signed authorization to a
//! result this client has checked itself.
//!
//! # The one thing this module is for
//!
//! Everything before it moves authenticated bytes. This is where the
//! client decides the bytes are *right*, and it is the difference
//! between paying for a verified result and paying for a signature.
//!
//! # The order, and why it is this order
//!
//! 1. **Fetch.** One unary call, whose answer the endpoint journals
//!    before returning it. The journal is where the delivered result is
//!    rebuilt from the delivered transcript, checked against the
//!    provider's key, and timed against the terminal deadline; none of
//!    those is spelled again here.
//! 2. **Reexecute.** The oracle is handed the bundle the *journal*
//!    holds — not the one the response carried, and not one this module
//!    reassembled — because that bundle's digest is inside the
//!    authorization both parties signed and is re-checked every time
//!    the journal is opened.
//! 3. **Record.** The verdict is fsynced. Only after that is the job in
//!    a phase its own journal will issue an invoice from.
//!
//! Reversed, the third step would be a claim about a check that had not
//! finished, and the second would be a check of bytes nothing durable
//! bound to the job.
//!
//! # What a passed check means, and what it does not
//!
//! It means: an engine this client chose, given the inputs this client
//! signed for, produced the answer the provider signed — the same
//! tokens in the same order, stopping for the same reason, with the same
//! output artifact and the same usage. It does not mean the provider
//! computed rather than recalled that answer, and it is no stronger than
//! the engine behind [`Reexecution`]. See `hellas_compute_oracle`.
//!
//! # What is not here
//!
//! No retry loop and no deadline timer. Both need a running finalized
//! cursor to be bounded by, and nothing in this tree advances one yet;
//! a loop written now would poll until it was killed. What this module
//! gives a caller instead is the provider's own answer about whether
//! asking again could help — [`CollectOutcome::NotReady`] — so the
//! policy that owns a clock can be written over a signal rather than a
//! guess.

use hellas_compute_oracle::{OracleFault, Reexecution};
use hellas_rpc::protocol::artifacts::PreparedPaidInputV1;
use hellas_rpc::protocol::work::PaidJobResultV1;
use hellas_rpc::protocol::work_setup::ReadyChannel;
use hellas_rpc::work::{ClientEndpoint, DeliverError, fetch_result};
use hellas_rpc::work_store::journal::MAX_RECORD_BYTES;
use hellas_wire::StreamTransport;

/// One job's answer, checked and durably recorded as checked.
///
/// What P7 will build an invoice request from. The transcript rides with
/// it because it is the answer the user asked for; the result is what
/// the payment chain names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckedResult {
    /// The provider's signed result.
    pub result: PaidJobResultV1,
    /// The signed events it summarises, as delivered.
    pub transcript: Vec<u8>,
}

/// What one attempt to collect a job's answer found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CollectOutcome {
    /// The answer arrived, reproduced, and the verdict is on the disk.
    Checked(CheckedResult),
    /// The provider cannot answer yet. The identical call may be made
    /// again, and nothing was recorded.
    NotReady {
        /// The provider's diagnostic text. Nothing decides on it.
        reason: String,
    },
}

/// Why one attempt to collect a job's answer failed.
///
/// The three shapes a caller must tell apart: a delivery that did not
/// happen or was refused, a check that could not be made, and a check
/// that was made and *failed*. Only the last is evidence about the
/// provider.
#[derive(Debug, thiserror::Error)]
pub enum CollectError {
    /// The delivery did not complete, or was refused permanently.
    #[error(transparent)]
    Deliver(#[from] DeliverError),
    /// The journal holds a bundle that does not parse.
    ///
    /// Unreachable through an honest path: the bundle was parsed and
    /// hashed before the job was ever proposed, and again whenever the
    /// journal is opened. It is a refusal rather than a panic because
    /// nothing in this crate panics on stored bytes.
    #[error("the stored prepared input does not parse: {0}")]
    Bundle(String),
    /// The reexecution could not be performed.
    ///
    /// The check did not happen. It is not evidence that the provider
    /// was wrong, and a caller must not treat it as either verdict.
    #[error("the independent check could not be made: {0}")]
    Unchecked(OracleFault),
    /// The reexecution was performed and did not reproduce the answer.
    ///
    /// No invoice may be requested for this job. The result stays on
    /// the disk as evidence, unverified.
    #[error("the independent check refused this result: {0}")]
    Refuted(OracleFault),
}

/// Fetches one accepted job's answer, checks it independently, and
/// records the verdict.
///
/// Idempotent in every step, so a caller whose process died anywhere in
/// it may call this again with the same `work_id`: the delivery is
/// answered from the provider's spool at no second credit cost, the
/// journal takes the same result as one, the oracle is deterministic,
/// and a repeated verdict is the same verdict.
///
/// # Errors
///
/// [`CollectError::Deliver`] when the answer did not arrive or the
/// journal refused it — which is what it does for a late receipt or a
/// transcript that does not rebuild the result — and
/// [`CollectError::Unchecked`] or [`CollectError::Refuted`] for the two
/// halves of the check itself. Nothing is recorded as checked unless
/// this returns [`CollectOutcome::Checked`].
pub async fn collect_checked_result<T, E>(
    transport: T,
    endpoint: &mut ClientEndpoint,
    ready: &ReadyChannel,
    engine: &E,
    work_id: hellas_rpc::protocol::Digest,
) -> Result<CollectOutcome, CollectError>
where
    T: StreamTransport + Sync,
    T::Error: std::error::Error + Send + Sync + 'static,
    T::Stream: 'static,
    E: Reexecution + ?Sized,
{
    let delivery = match fetch_result(transport, endpoint, ready, work_id).await {
        Ok(delivery) => delivery,
        Err(DeliverError::Refused { refusal, reason }) if refusal.is_retryable() => {
            return Ok(CollectOutcome::NotReady { reason });
        }
        Err(error) => return Err(error.into()),
    };

    // The bundle the journal holds, not the one any response carried.
    let Some(job) = endpoint.state().job() else {
        return Err(CollectError::Deliver(DeliverError::NoSuchJob));
    };
    let bundle = PreparedPaidInputV1::decode(job.prepared_input(), MAX_RECORD_BYTES)
        .map_err(|error| CollectError::Bundle(error.to_string()))?;
    let network = endpoint.state().channel().network();

    match hellas_compute_oracle::verify(engine, network, work_id, &bundle, &delivery.result) {
        Ok(()) => {}
        Err(fault @ OracleFault::Mismatch) => return Err(CollectError::Refuted(fault)),
        Err(fault) => return Err(CollectError::Unchecked(fault)),
    }

    endpoint.verified(work_id)?;
    Ok(CollectOutcome::Checked(CheckedResult {
        result: delivery.result,
        transcript: delivery.transcript,
    }))
}
