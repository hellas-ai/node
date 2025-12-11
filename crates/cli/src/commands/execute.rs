use crate::commands::CliResult;
use anyhow::Context;
use hellas_rpc::pb::hellas::execute_client::ExecuteClient;
use hellas_rpc::pb::hellas::execute_server::ExecuteServer;
use hellas_rpc::pb::hellas::{
    get_quote_request, ExecuteRequest, ExecuteResultRequest, ExecuteStatusRequest, GetQuoteRequest,
    LlmpQuoteRequest,
};
use tokio_stream::StreamExt;
use tonic_iroh_transport::iroh::{Endpoint, EndpointId};
use tonic_iroh_transport::IrohConnect;

const GRPC_MESSAGE_LIMIT: usize = 32 * 1024 * 1024;

pub async fn run(
    node_id: EndpointId,
    model: String,
    prompt: String,
    max_seq: u32,
) -> CliResult<()> {
    let endpoint = Endpoint::builder()
        .bind()
        .await
        .context("failed to create iroh endpoint")?;

    let channel = ExecuteServer::<()>::connect(&endpoint, node_id.into())
        .await
        .with_context(|| format!("failed to connect to node {node_id}"))?;

    let mut client = ExecuteClient::new(channel)
        .max_decoding_message_size(GRPC_MESSAGE_LIMIT)
        .max_encoding_message_size(GRPC_MESSAGE_LIMIT);

    // 1. Get quote
    let req = GetQuoteRequest {
        payload: Some(get_quote_request::Payload::LlmPrompt(LlmpQuoteRequest {
            huggingface_model_id: model.clone(),
            revision: String::new(),
            prompt: prompt.clone(),
            max_seq,
        })),
    };
    info!("Getting quote... {req:?}");
    let quote = client
        .get_quote(req)
        .await
        .context("GetQuote RPC failed")?
        .into_inner();

    info!("Got quote: {quote:?}");

    // 2. Execute
    let req = ExecuteRequest {
        quote_id: quote.quote_id.as_bytes().to_vec(),
    };
    info!("Req: {req:?}");
    let exec = client
        .execute(req)
        .await
        .context("Execute RPC failed")?
        .into_inner();
    info!("Executing: {exec:?}");

    // 3. Stream status until completed
    let mut req = ExecuteStatusRequest {
        execution_id: exec.execution_id.clone(),
    };
    info!("\nStreaming status: {req:?}");
    let mut stream = client
        .execute_stream(req)
        .await
        .context("ExecuteStream RPC failed")?
        .into_inner();

    while let Some(diff) = stream.next().await {
        let diff = diff.context("ExecuteStream RPC diff failed")?;
        if diff.decoded.is_empty() {
            info!("Status: {}", diff.status);
        } else {
            info!("Status: {} | Decoded: {}", diff.status, diff.decoded);
        }
        if diff.status == "completed" || diff.status == "failed" {
            break;
        }
    }

    // 4. Get result
    info!("\nGetting result...");
    let result = client
        .execute_result(ExecuteResultRequest {
            execution_id: exec.execution_id.clone(),
        })
        .await
        .context("ExecuteResult RPC failed")?
        .into_inner();
    if !result.decoded.is_empty() {
        println!("{}", result.decoded);
    }
    println!("Result: {}", result.result);

    Ok(())
}
