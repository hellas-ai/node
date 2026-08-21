//! Turning a checked answer into a payment the provider has admitted.
//!
//! # The order, and why it is this order
//!
//! 1. **Invoice.** The client asks for the entry that prices the job it
//!    has checked. The provider builds that entry from its own ledger;
//!    this client's journal rebuilds the one entry *its* ledger allows
//!    and takes the provider's signature only over that. A price, a
//!    sequence, or a cumulative the client did not arrive at itself is
//!    refused here, before anything is signed.
//! 2. **Sign.** The certificate is built for exactly the entry's
//!    `cumulative_after`, and the private allocation says so. Both
//!    signatures are fsynced — through the ledger that says this job has
//!    not been paid for before — before either leaves the process.
//! 3. **Admit.** The provider fsyncs the certificate, which is also what
//!    retires this job's compute and delivery credit, and only then
//!    acknowledges. The number it acknowledges must be the one this
//!    client signed.
//!
//! Reversed at step 2, the client would have sent a signature its own
//! ledger had not yet accounted for, and a crash there is a job that
//! could be paid for twice. Reversed at step 3, the provider would have
//! acknowledged a payment its disk does not hold.
//!
//! # What a crash costs here
//!
//! A round trip, at every point. Before the invoice is journaled, the
//! job is still a checked, unbilled job and asking again re-issues the
//! same entry. Between the invoice and the certificate, the job is
//! billed and unpaid: the invoice is the provider's own retained bytes
//! and the client is offered them again. After the certificate is
//! journaled, the payment is durable whether or not the provider ever
//! saw it, and calling this again re-sends exactly those bytes. Only a
//! machine that loses the journal file loses more than a round trip;
//! see [`hellas_rpc::work_store`].
//!
//! # What is not here
//!
//! No retry loop and no clock, for the reason [`super`] gives. Nor a
//! close: the certificate this leaves on both disks is what a
//! settlement watcher will spend, and nothing here spends it.

use hellas_rpc::protocol::Digest;
use hellas_rpc::services::work::WorkClientImpl;
use hellas_rpc::work::{ClientEndpoint, PaymentError, admit_payment, request_invoice};
use hellas_wire::StreamTransport;

/// Invoices one checked job, signs its certificate, and gets it
/// admitted.
///
/// Both calls go over one connection, so the peer that priced the job
/// is the peer that is paid. What comes back is the cumulative amount
/// the provider acknowledged crediting, which this client has already
/// required to be the amount it signed.
///
/// There is no wait to report here, unlike [`super::collect_checked_result`].
/// A client that has a verdict to invoice from has already taken this
/// job's answer, so the provider holds a delivered result and has
/// nothing left to be not-ready about; a refusal on this path is a
/// disagreement rather than a delay.
///
/// Idempotent in every step, so a caller whose process died anywhere in
/// it may call this again with the same `work_id`: the invoice is
/// re-issued from the provider's retained bytes and taken as one, the
/// certificate is signed at most once per job, and re-sending it
/// credits nothing further. A job this channel has already paid for is
/// past having an invoice to ask about — the payment closed it — so
/// that call goes straight to re-sending the bytes the journal holds.
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
    let client = WorkClientImpl::new(transport);
    let signed_already = endpoint
        .state()
        .last_payment()
        .is_some_and(|payment| payment.work_id == work_id);
    if !signed_already {
        request_invoice(&client, endpoint, work_id).await?;
    }
    admit_payment(&client, endpoint, work_id).await
}
