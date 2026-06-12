use futures::StreamExt;
use hellas_executor::{FetchProviderError, FetchProviderStream};
use reqwest::Url;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};

pub(super) async fn execute_responses_request(
    client: &reqwest::Client,
    endpoint: Url,
    bearer_token: &str,
    body: Vec<u8>,
    label: &str,
) -> Result<FetchProviderStream, FetchProviderError> {
    let upstream = client
        .post(endpoint)
        .header(CONTENT_TYPE, "application/json")
        .header(AUTHORIZATION, format!("Bearer {bearer_token}"))
        .body(body)
        .send()
        .await
        .map_err(|source| {
            FetchProviderError::failed(format!("{label} request failed: {source}"))
        })?;

    let status = upstream.status();
    if !status.is_success() {
        let body = upstream.text().await.unwrap_or_default();
        return Err(FetchProviderError::failed(format!(
            "{label} returned HTTP {status}: {body}"
        )));
    }

    Ok(Box::pin(stream_response(upstream, label.to_string())))
}

fn stream_response(
    upstream: reqwest::Response,
    label: String,
) -> impl futures::Stream<Item = Result<Vec<u8>, FetchProviderError>> + Send + 'static {
    async_stream::try_stream! {
        let mut chunks = upstream.bytes_stream();

        while let Some(chunk) = chunks.next().await {
            let chunk = chunk.map_err(|source| {
                FetchProviderError::failed(format!("{label} stream failed: {source}"))
            })?;
            yield chunk.to_vec();
        }
    }
}
