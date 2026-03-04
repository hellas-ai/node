use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::stream::{FuturesUnordered, Stream};
use tonic::transport::Channel;

use crate::commands::common::GRPC_MESSAGE_LIMIT;
use hellas_rpc::pb::hellas::execute_client::ExecuteClient;
use hellas_rpc::pb::hellas::{GetQuoteRequest, GetQuoteResponse};
use tonic_iroh_transport::swarm::Locator;

/// An accepted quote: the gRPC client and the quote response.
pub type AcceptedQuote = (ExecuteClient<Channel>, GetQuoteResponse);

/// Errors surfaced by the quote stream.
pub enum QuoteError {
    /// Provider declined the quote request.
    Declined(tonic::Status),
    /// Could not connect to a discovered peer.
    ConnectFailed(tonic_iroh_transport::Error),
}

impl std::fmt::Display for QuoteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QuoteError::Declined(status) => write!(f, "quote declined: {status}"),
            QuoteError::ConnectFailed(e) => write!(f, "connect failed: {e}"),
        }
    }
}

// ── Types ──

type QuoteFuture = Pin<Box<dyn Future<Output = Result<AcceptedQuote, QuoteError>> + Send>>;
type QuoterFn = Box<dyn Fn(Channel) -> QuoteFuture + Send + Sync>;

// ── Builder ──

pub struct QuoteStreamBuilder {
    quote_req: GetQuoteRequest,
    backup_target: usize,
}

impl QuoteStreamBuilder {
    pub fn new(quote_req: GetQuoteRequest) -> Self {
        Self {
            quote_req,
            backup_target: 2,
        }
    }

    pub fn backup_quotes(mut self, n: usize) -> Self {
        self.backup_target = n;
        self
    }

    /// Consume the builder and a started `Locator` to produce a `QuoteStream`.
    pub fn start(self, locator: Locator) -> QuoteStream<Locator> {
        let req = self.quote_req;
        QuoteStream::new(
            locator,
            Box::new(move |channel| {
                let req = req.clone();
                Box::pin(try_quote(channel, req))
            }),
            self.backup_target,
        )
    }
}

// ── Stream ──

/// Races quote requests across discovered providers, buffering accepted quotes.
///
/// Generic over the locator stream type `S` for testability.
pub struct QuoteStream<S> {
    locator: S,
    quoter: QuoterFn,
    pending: FuturesUnordered<QuoteFuture>,
    ready: VecDeque<AcceptedQuote>,
    backup_target: usize,
    discovery_done: bool,
}

impl<S> QuoteStream<S> {
    fn new(locator: S, quoter: QuoterFn, backup_target: usize) -> Self {
        Self {
            locator,
            quoter,
            pending: FuturesUnordered::new(),
            ready: VecDeque::new(),
            backup_target,
            discovery_done: false,
        }
    }
}

impl<S> Stream for QuoteStream<S>
where
    S: Stream<Item = tonic_iroh_transport::Result<Channel>> + Unpin,
{
    type Item = Result<AcceptedQuote, QuoteError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        // Fast path: enough accepted quotes buffered — yield one.
        if this.ready.len() > this.backup_target {
            return Poll::Ready(Some(Ok(this.ready.pop_front().unwrap())));
        }

        loop {
            // 1. Poll pending quote RPCs.
            let pending_progress = if !this.pending.is_empty() {
                match Pin::new(&mut this.pending).poll_next(cx) {
                    Poll::Ready(Some(Ok(accepted))) => {
                        this.ready.push_back(accepted);
                        if this.ready.len() > this.backup_target {
                            return Poll::Ready(Some(Ok(this.ready.pop_front().unwrap())));
                        }
                        true
                    }
                    Poll::Ready(Some(Err(e))) => {
                        return Poll::Ready(Some(Err(e)));
                    }
                    Poll::Ready(None) => false,
                    Poll::Pending => false,
                }
            } else {
                false
            };

            // 2. Poll locator for new discovered channels.
            let locator_progress = if !this.discovery_done {
                match Pin::new(&mut this.locator).poll_next(cx) {
                    Poll::Ready(Some(Ok(channel))) => {
                        this.pending.push((this.quoter)(channel));
                        true
                    }
                    Poll::Ready(Some(Err(e))) => {
                        return Poll::Ready(Some(Err(QuoteError::ConnectFailed(e))));
                    }
                    Poll::Ready(None) => {
                        this.discovery_done = true;
                        true
                    }
                    Poll::Pending => false,
                }
            } else {
                false
            };

            // 3. No progress on either side — check if fully exhausted or pending.
            if !pending_progress && !locator_progress {
                if this.discovery_done && this.pending.is_empty() {
                    // Drain remaining buffered quotes, then signal end.
                    return Poll::Ready(this.ready.pop_front().map(Ok));
                }
                return Poll::Pending;
            }
        }
    }
}

async fn try_quote(
    channel: Channel,
    req: GetQuoteRequest,
) -> Result<AcceptedQuote, QuoteError> {
    let mut client = ExecuteClient::new(channel)
        .max_decoding_message_size(GRPC_MESSAGE_LIMIT)
        .max_encoding_message_size(GRPC_MESSAGE_LIMIT);
    match client.get_quote(req).await {
        Ok(resp) => Ok((client, resp.into_inner())),
        Err(status) => Err(QuoteError::Declined(status)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt;

    fn mock_channel() -> Channel {
        tonic::transport::Endpoint::from_static("http://[::1]:1").connect_lazy()
    }

    fn mock_accepted() -> AcceptedQuote {
        let client = ExecuteClient::new(mock_channel())
            .max_decoding_message_size(GRPC_MESSAGE_LIMIT)
            .max_encoding_message_size(GRPC_MESSAGE_LIMIT);
        let quote = GetQuoteResponse {
            quote_id: "test".into(),
            ..Default::default()
        };
        (client, quote)
    }

    /// Create a QuoteStream from a mock locator stream and a mock quoter.
    fn mock_quote_stream<I>(
        items: I,
        quoter: QuoterFn,
        backup_target: usize,
    ) -> QuoteStream<futures::stream::Iter<std::vec::IntoIter<tonic_iroh_transport::Result<Channel>>>>
    where
        I: IntoIterator<Item = tonic_iroh_transport::Result<Channel>>,
    {
        let stream = futures::stream::iter(items.into_iter().collect::<Vec<_>>());
        QuoteStream::new(stream, quoter, backup_target)
    }

    fn always_accept() -> QuoterFn {
        Box::new(|_ch| Box::pin(async { Ok(mock_accepted()) }))
    }

    fn always_decline() -> QuoterFn {
        Box::new(|_ch| {
            Box::pin(async {
                Err(QuoteError::Declined(tonic::Status::permission_denied(
                    "declined",
                )))
            })
        })
    }

    #[tokio::test]
    async fn empty_stream_yields_none() {
        let mut qs = mock_quote_stream(vec![], always_accept(), 0);
        assert!(qs.next().await.is_none());
    }

    #[tokio::test]
    async fn single_accepted_quote() {
        let mut qs = mock_quote_stream(vec![Ok(mock_channel())], always_accept(), 0);
        let item = qs.next().await;
        assert!(item.is_some());
        assert!(item.unwrap().is_ok());
        assert!(qs.next().await.is_none());
    }

    #[tokio::test]
    async fn connect_errors_forwarded() {
        let items = vec![Err(tonic_iroh_transport::Error::connection("test error"))];
        let mut qs = mock_quote_stream(items, always_accept(), 0);
        let item = qs.next().await;
        assert!(item.is_some());
        assert!(matches!(item.unwrap(), Err(QuoteError::ConnectFailed(_))));
        assert!(qs.next().await.is_none());
    }

    #[tokio::test]
    async fn declines_forwarded_as_errors() {
        let mut qs = mock_quote_stream(vec![Ok(mock_channel())], always_decline(), 0);
        let item = qs.next().await;
        assert!(item.is_some());
        assert!(matches!(item.unwrap(), Err(QuoteError::Declined(_))));
        assert!(qs.next().await.is_none());
    }

    #[tokio::test]
    async fn backup_buffering_waits_for_target() {
        // With backup_target=2, we need 3 accepted quotes before the first yields.
        // Provide exactly 3 channels that all accept.
        let items = vec![
            Ok(mock_channel()),
            Ok(mock_channel()),
            Ok(mock_channel()),
        ];
        let mut qs = mock_quote_stream(items, always_accept(), 2);

        // Should get all 3 as Ok items (stream drains buffer after exhaustion).
        let r1 = qs.next().await;
        assert!(r1.is_some() && r1.unwrap().is_ok());
        let r2 = qs.next().await;
        assert!(r2.is_some() && r2.unwrap().is_ok());
        let r3 = qs.next().await;
        assert!(r3.is_some() && r3.unwrap().is_ok());
        assert!(qs.next().await.is_none());
    }

    #[tokio::test]
    async fn backup_drains_partial_when_exhausted() {
        // backup_target=2 but only 1 channel available — should still yield it.
        let mut qs = mock_quote_stream(vec![Ok(mock_channel())], always_accept(), 2);
        let item = qs.next().await;
        assert!(item.is_some() && item.unwrap().is_ok());
        assert!(qs.next().await.is_none());
    }

    #[tokio::test]
    async fn mixed_accept_and_decline() {
        // Alternate: accept, decline, accept.
        let call_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = call_count.clone();
        let quoter: QuoterFn = Box::new(move |_ch| {
            let n = counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async move {
                if n % 2 == 0 {
                    Ok(mock_accepted())
                } else {
                    Err(QuoteError::Declined(tonic::Status::permission_denied(
                        "no",
                    )))
                }
            })
        });

        let items = vec![
            Ok(mock_channel()),
            Ok(mock_channel()),
            Ok(mock_channel()),
        ];
        let mut qs = mock_quote_stream(items, quoter, 0);

        let mut accepted = 0;
        let mut declined = 0;
        while let Some(result) = qs.next().await {
            match result {
                Ok(_) => accepted += 1,
                Err(QuoteError::Declined(_)) => declined += 1,
                Err(QuoteError::ConnectFailed(_)) => panic!("unexpected connect error"),
            }
        }
        assert_eq!(accepted, 2);
        assert_eq!(declined, 1);
    }
}
