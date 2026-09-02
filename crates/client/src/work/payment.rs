//! Turning a checked answer into a payment the provider has admitted.
//!
//! # The order, and why it is this order
//!
//! 1. **Sign.** The client, holding the durable match its own
//!    re-execution reached, derives the amount itself — its own credited
//!    total plus the price its own authorization fixed — and signs the
//!    certificate and the binding that says what that certificate
//!    bought. Both are fsynced, through the ledger that says this job
//!    has not been paid for before, before either leaves the process.
//! 2. **Admit.** The provider fsyncs the same pair, deriving the same
//!    amount from its own ledger, and that record is also what retires
//!    this job's compute and delivery credit. Only then does it
//!    acknowledge, and the number it acknowledges must be the one this
//!    client signed.
//!
//! There is no invoice step in front of these, and no provider
//! signature over a price. The provider has already co-signed the
//! authorization that fixes the price and signed the result that earns
//! it; a third signature restating those two numbers would add no
//! authority and would be a second place for the price to disagree with
//! itself.
//!
//! Reversed at step 1, the client would have sent a signature its own
//! ledger had not yet accounted for, and a crash there is a job that
//! could be paid for twice. Reversed at step 2, the provider would have
//! acknowledged a payment its disk does not hold.
//!
//! # What a crash costs here
//!
//! A round trip, at every point. Before the certificate is journaled,
//! the job is still a delivered, unpaid job and calling this again
//! signs the same payment from the same ledger position. After it, the
//! payment is durable whether or not the provider ever saw it, and
//! calling this again re-sends exactly those bytes. Only a machine that
//! loses the journal file loses more than a round trip; see
//! [`hellas_rpc::work_store`].
//!
//! # What is not here
//!
//! No retry loop and no clock, for the reason [`super`] gives. Nor a
//! close: the certificate this leaves on both disks is what a
//! settlement watcher will spend, and nothing here spends it.

use hellas_rpc::protocol::Digest;
use hellas_rpc::services::work::WorkClientImpl;
use hellas_rpc::work::{ClientEndpoint, PaymentError, admit_payment};
use hellas_wire::StreamTransport;

/// Signs one checked job's payment and gets it admitted.
///
/// What comes back is the cumulative amount the provider acknowledged
/// crediting, which this client has already required to be the amount
/// it signed.
///
/// There is no wait to report here, unlike [`super::collect_checked_result`].
/// A client that has an answer to pay for has already taken it, so the
/// provider holds a delivered result and has nothing left to be
/// not-ready about; a refusal on this path is a disagreement rather
/// than a delay.
///
/// Idempotent, so a caller whose process died anywhere in it may call
/// this again with the same `work_id`: the certificate is signed at
/// most once per job, and re-sending it credits nothing further. A job
/// this channel has already paid for is past having a result to price —
/// the payment closed it — so that call goes straight to re-sending the
/// bytes the journal holds.
///
/// # Errors
///
/// [`PaymentError`] for a refusal, for a journal that refuses the step
/// — which is what it does for a job this client has not checked, or a
/// payment past its deadline — and for an acknowledgement that does not
/// name the amount this client signed.
pub async fn pay_for_checked_result<T>(
    transport: T,
    endpoint: &mut ClientEndpoint,
    work_id: Digest,
) -> Result<u64, PaymentError>
where
    T: StreamTransport + Sync,
    T::Error: std::error::Error + Send + Sync + 'static,
    T::Stream: 'static,
{
    admit_payment(&WorkClientImpl::new(transport), endpoint, work_id).await
}
