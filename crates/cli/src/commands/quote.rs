use hellas_rpc::pb::hellas::quote_client::QuoteClient;
use hellas_rpc::pb::hellas::quote_server::QuoteServer;
use hellas_rpc::pb::hellas::GetQuoteRequest;
use tonic_iroh_transport::iroh::{Endpoint, EndpointId};
use tonic_iroh_transport::IrohConnect;

pub async fn run(node_id: EndpointId) {
    let endpoint = Endpoint::builder()
        .bind()
        .await
        .expect("Failed to create iroh endpoint");

    let channel = QuoteServer::<()>::connect(&endpoint, node_id.into())
        .await
        .expect("Failed to connect");

    let mut client = QuoteClient::new(channel);
    let response = client
        .get_quote(GetQuoteRequest { graph: vec![] })
        .await
        .expect("Get quote failed")
        .into_inner();

    println!("Quote ID: {}", response.quote_id);
    println!("Graph ID: {}", response.graph_id);
    println!("Amount: {}", response.amount);
}
