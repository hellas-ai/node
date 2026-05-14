//! `hellas rpc` subcommand — query node info from a remote peer.
//!
//! NOTE (hellas-wire v2 cutover): the dial path used
//! `hellas_rpc::peers::IrohTransport` / `DiscoveryEndpoint`, which were
//! tonic-iroh-transport wrappers. Until those modules are ported, this
//! subcommand returns `unimplemented!()`. See CUTOVER_FINDINGS #5.

use crate::commands::CliResult;
use iroh::{EndpointId, SecretKey};
use std::net::SocketAddr;

pub async fn run(
    _node_id: EndpointId,
    _node_addrs: Vec<SocketAddr>,
    _secret_key: SecretKey,
) -> CliResult<()> {
    unimplemented!(
        "rpc subcommand pending hellas-wire discovery/pool port — see CUTOVER_FINDINGS.md"
    )
}
