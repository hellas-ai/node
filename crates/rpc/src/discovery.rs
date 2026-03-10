use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::stream::{FuturesUnordered, Stream};
use pkarr::Client as PkarrClient;
use tonic::transport::Channel;
use tonic_iroh_transport::iroh::address_lookup::pkarr::{
    N0_DNS_PKARR_RELAY_PROD, N0_DNS_PKARR_RELAY_STAGING,
};
use tonic_iroh_transport::swarm::Locator;

use crate::pb::hellas::execute_client::ExecuteClient;
use crate::pb::hellas::{GetQuoteRequest, GetQuoteResponse};
use crate::GRPC_MESSAGE_LIMIT;

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

type QuoteFuture = Pin<Box<dyn Future<Output = Result<AcceptedQuote, QuoteError>> + Send>>;
type QuoterFn = Box<dyn Fn(Channel) -> QuoteFuture + Send + Sync>;

pub struct QuoteStreamBuilder {
    quote_req: GetQuoteRequest,
}

impl QuoteStreamBuilder {
    pub fn new(quote_req: GetQuoteRequest) -> Self {
        Self { quote_req }
    }

    pub fn start(self, locator: Locator) -> QuoteStream<Locator> {
        let req = self.quote_req;
        QuoteStream::new(
            locator,
            Box::new(move |channel| {
                let req = req.clone();
                Box::pin(try_quote(channel, req))
            }),
        )
    }
}

/// Races quote requests across discovered providers and yields accepted quotes as they arrive.
pub struct QuoteStream<S> {
    locator: S,
    quoter: QuoterFn,
    pending: FuturesUnordered<QuoteFuture>,
    discovery_done: bool,
}

impl<S> QuoteStream<S> {
    fn new(locator: S, quoter: QuoterFn) -> Self {
        Self {
            locator,
            quoter,
            pending: FuturesUnordered::new(),
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

        loop {
            match Pin::new(&mut this.pending).poll_next(cx) {
                Poll::Ready(Some(Ok(accepted))) => return Poll::Ready(Some(Ok(accepted))),
                Poll::Ready(Some(Err(err))) => return Poll::Ready(Some(Err(err))),
                Poll::Ready(None) | Poll::Pending => {}
            }

            let mut progressed = false;

            if !this.discovery_done {
                match Pin::new(&mut this.locator).poll_next(cx) {
                    Poll::Ready(Some(Ok(channel))) => {
                        this.pending.push((this.quoter)(channel));
                        progressed = true;
                    }
                    Poll::Ready(Some(Err(err))) => {
                        return Poll::Ready(Some(Err(QuoteError::ConnectFailed(err))));
                    }
                    Poll::Ready(None) => {
                        this.discovery_done = true;
                        progressed = true;
                    }
                    Poll::Pending => {}
                }
            }

            if !progressed {
                return if this.discovery_done && this.pending.is_empty() {
                    Poll::Ready(None)
                } else {
                    Poll::Pending
                };
            }
        }
    }
}

fn n0_pkarr_relay() -> &'static str {
    if std::env::var_os("IROH_FORCE_STAGING_RELAYS").is_some() {
        N0_DNS_PKARR_RELAY_STAGING
    } else {
        N0_DNS_PKARR_RELAY_PROD
    }
}

pub fn shared_pkarr_client() -> anyhow::Result<PkarrClient> {
    let mut builder = PkarrClient::builder();
    builder.no_default_network();
    builder.dht(|dht| dht);
    builder
        .relays(&[n0_pkarr_relay()])
        .map_err(|err| anyhow::anyhow!("failed to configure pkarr relay: {err}"))?;
    builder
        .build()
        .map_err(|err| anyhow::anyhow!("failed to build pkarr client: {err}"))
}

async fn try_quote(channel: Channel, req: GetQuoteRequest) -> Result<AcceptedQuote, QuoteError> {
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

    fn mock_quote_stream<I>(
        items: I,
        quoter: QuoterFn,
    ) -> QuoteStream<futures::stream::Iter<std::vec::IntoIter<tonic_iroh_transport::Result<Channel>>>>
    where
        I: IntoIterator<Item = tonic_iroh_transport::Result<Channel>>,
    {
        let stream = futures::stream::iter(items.into_iter().collect::<Vec<_>>());
        QuoteStream::new(stream, quoter)
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
        let mut qs = mock_quote_stream(vec![], always_accept());
        assert!(qs.next().await.is_none());
    }

    #[tokio::test]
    async fn single_accepted_quote() {
        let mut qs = mock_quote_stream(vec![Ok(mock_channel())], always_accept());
        let item = qs.next().await;
        assert!(item.is_some());
        assert!(item.unwrap().is_ok());
        assert!(qs.next().await.is_none());
    }

    #[tokio::test]
    async fn connect_errors_forwarded() {
        let items = vec![Err(tonic_iroh_transport::Error::connection("test error"))];
        let mut qs = mock_quote_stream(items, always_accept());
        let item = qs.next().await;
        assert!(item.is_some());
        assert!(matches!(item.unwrap(), Err(QuoteError::ConnectFailed(_))));
        assert!(qs.next().await.is_none());
    }

    #[tokio::test]
    async fn declines_forwarded_as_errors() {
        let mut qs = mock_quote_stream(vec![Ok(mock_channel())], always_decline());
        let item = qs.next().await;
        assert!(item.is_some());
        assert!(matches!(item.unwrap(), Err(QuoteError::Declined(_))));
        assert!(qs.next().await.is_none());
    }

    #[tokio::test]
    async fn mixed_accept_and_decline() {
        let call_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = call_count.clone();
        let quoter: QuoterFn = Box::new(move |_ch| {
            let n = counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async move {
                if n % 2 == 0 {
                    Ok(mock_accepted())
                } else {
                    Err(QuoteError::Declined(tonic::Status::permission_denied("no")))
                }
            })
        });

        let items = vec![Ok(mock_channel()), Ok(mock_channel()), Ok(mock_channel())];
        let mut qs = mock_quote_stream(items, quoter);

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
