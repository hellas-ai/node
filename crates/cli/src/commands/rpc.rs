//! `hellas rpc` subcommand — query node info from a remote peer.
//!
//! Dials the peer directly (no discovery / pool race) over the
//! Node service ALPN and prints the response.

use std::net::SocketAddr;

use anyhow::Context;
use hellas_rpc::pb::swarm::GetNodeInfoRequest;
use hellas_rpc::services::node::NodeClientImpl;
use hellas_wire::iroh::IrohTransport;
use hellas_wire::ServiceMarker;
use iroh::endpoint::presets;
use iroh::{Endpoint, EndpointAddr, EndpointId, SecretKey, TransportAddr};

use crate::commands::CliResult;

pub async fn run(
    node_id: EndpointId,
    node_addrs: Vec<SocketAddr>,
    secret_key: SecretKey,
) -> CliResult<()> {
    let endpoint = Endpoint::builder(presets::N0)
        .secret_key(secret_key)
        .alpns(vec![hellas_rpc::services::node::Node::ALPN
            .as_bytes()
            .to_vec()])
        .bind()
        .await
        .context("failed to bind iroh endpoint")?;

    let endpoint_addr = EndpointAddr::from_parts(
        node_id,
        node_addrs.into_iter().map(TransportAddr::Ip),
    );

    let connection = endpoint
        .connect(
            endpoint_addr,
            hellas_rpc::services::node::Node::ALPN.as_bytes(),
        )
        .await
        .with_context(|| format!("failed to connect to {node_id}"))?;

    let transport = IrohTransport::new(connection);
    let client = NodeClientImpl::new(transport);

    let response = client
        .get_node_info(GetNodeInfoRequest {})
        .await
        .map_err(|e| anyhow::anyhow!("get_node_info: {e}"))?;

    println!("Node ID:  {}", response.node_id);
    println!("Version:  {}", response.version);
    println!("Build:    {}", response.build);
    println!("OS:       {}", response.os);
    println!("Uptime:   {}s", response.uptime_seconds);
    println!("Graffiti: {}", String::from_utf8_lossy(&response.graffiti));

    Ok(())
}
