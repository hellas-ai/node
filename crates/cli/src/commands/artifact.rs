//! `hellas artifact` subcommand — put/get canonical artifact bytes.
//!
//! NOTE (hellas-wire v2 cutover): the dial path used
//! `hellas_rpc::peers::{IrohTransport, IrohPeerHandle}` /
//! `DiscoveryEndpoint`, which were tonic-iroh-transport wrappers. Until
//! those modules are ported, this subcommand returns
//! `unimplemented!()`. See CUTOVER_FINDINGS #5.

use crate::commands::CliResult;
use clap::Subcommand;
use iroh::{EndpointId, SecretKey};
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Debug, Subcommand)]
pub enum ArtifactCommand {
    /// Store exact canonical artifact bytes on a provider and print the CID
    Put {
        /// Node ID of the provider to store on
        node_id: EndpointId,
        /// Direct UDP address hint for the provider. Repeat or use commas.
        #[arg(long = "node-addr", value_delimiter = ',')]
        node_addrs: Vec<SocketAddr>,
        /// File containing exact canonical artifact bytes
        path: PathBuf,
    },
    /// Fetch canonical artifact bytes by CID from a provider
    Get {
        /// Node ID of the provider to fetch from
        node_id: EndpointId,
        /// Direct UDP address hint for the provider. Repeat or use commas.
        #[arg(long = "node-addr", value_delimiter = ',')]
        node_addrs: Vec<SocketAddr>,
        /// 32-byte artifact CID as hex
        cid: String,
        /// File to write the fetched canonical artifact bytes
        #[arg(short = 'o', long = "output")]
        output: PathBuf,
    },
}

pub async fn run(_command: ArtifactCommand, _secret_key: SecretKey) -> CliResult<()> {
    unimplemented!(
        "artifact subcommand pending hellas-wire discovery/pool port — see CUTOVER_FINDINGS.md"
    )
}
