use crate::commands::CliResult;
use anyhow::Context;
use hellas_executor::catgrad_support::dump_graph_for_model;
use hellas_rpc::pb::hellas::execute_client::ExecuteClient;
use hellas_rpc::pb::hellas::execute_server::ExecuteServer;
use hellas_rpc::pb::hellas::{
    ExecuteRequest, ExecuteResultRequest, ExecuteStatusRequest, GetQuoteRequest, WeightsHint,
};
use tokio::time::{sleep, Duration};
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

    let graph_bytes = dump_graph_for_model(&model, &prompt, max_seq, None)
        .context("failed to build catgrad graph")?;

    // 1. Get quote
    println!("Getting quote...");
    let quote = client
        .get_quote(GetQuoteRequest {
            graph: graph_bytes,
            weights_hint: Some(WeightsHint {
                huggingface_model_id: model,
                revision: String::new(),
            }),
            max_seq,
            prompt,
        })
        .await
        .context("GetQuote RPC failed")?
        .into_inner();
    println!("Quote ID: {}", quote.quote_id);
    println!("Graph ID: {}", quote.graph_id);
    println!("Amount: {}", quote.amount);

    // 2. Execute
    println!("\nExecuting...");
    let exec = client
        .execute(ExecuteRequest {
            quote_id: quote.quote_id.as_bytes().to_vec(),
        })
        .await
        .context("Execute RPC failed")?
        .into_inner();
    println!("Execution ID: {}", exec.execution_id);

    // 3. Poll status until completed
    println!("\nPolling status...");
    loop {
        let status = client
            .execute_status(ExecuteStatusRequest {
                execution_id: exec.execution_id.clone(),
            })
            .await
            .context("ExecuteStatus RPC failed")?
            .into_inner();
        println!("Status: {}", status.status);

        if status.status == "completed" || status.status == "failed" {
            break;
        }
        sleep(Duration::from_millis(500)).await;
    }

    // 4. Get result
    println!("\nGetting result...");
    let result = client
        .execute_result(ExecuteResultRequest {
            execution_id: exec.execution_id.clone(),
        })
        .await
        .context("ExecuteResult RPC failed")?
        .into_inner();
    println!("Result: {}", result.result);

    Ok(())
}
