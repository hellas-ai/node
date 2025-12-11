use hellas_rpc::pb::hellas::execute_client::ExecuteClient;
use hellas_rpc::pb::hellas::execute_server::ExecuteServer;
use hellas_rpc::pb::hellas::{ExecuteRequest, ExecuteStatusRequest, ExecuteResultRequest, GetQuoteRequest};
use tokio::time::{sleep, Duration};
use tonic_iroh_transport::iroh::{Endpoint, EndpointId};
use tonic_iroh_transport::IrohConnect;

pub async fn run(node_id: EndpointId) {
    let endpoint = Endpoint::builder()
        .bind()
        .await
        .expect("Failed to create iroh endpoint");

    let channel = ExecuteServer::<()>::connect(&endpoint, node_id.into())
        .await
        .expect("Failed to connect");

    let mut client = ExecuteClient::new(channel);

    // 1. Get quote
    println!("Getting quote...");
    let quote = client
        .get_quote(GetQuoteRequest {
            graph: b"test-graph".to_vec(),
        })
        .await
        .expect("GetQuote failed")
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
        .expect("Execute failed")
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
            .expect("ExecuteStatus failed")
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
        .expect("ExecuteResult failed")
        .into_inner();
    println!("Result: {}", result.result);
}
