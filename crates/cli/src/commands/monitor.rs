//! Discovery / peer-interrogation monitor.
//!
//! `monitor` raced peer-discovery feeds (DHT + mDNS + peer-exchange) and
//! interrogated each peer over the Node service. `hellas_wire::iroh::swarm`
//! has the trait surface (`ServiceRegistry`, `Discovery`, `PeerExchangeBackend`,
//! `StaticBackend`) but the actual DHT and mDNS backends are scope-deferred
//! stubs. Until they land, this subcommand prints a guidance message and
//! exits 0; use `hellas rpc <node-id> --node-addr <addr>` to query a known
//! peer directly. See CUTOVER_FINDINGS #5.

use crate::commands::CliResult;
use iroh::SecretKey;

pub async fn run(
    _timeout_secs: Option<u64>,
    _interrogate: bool,
    _secret_key: SecretKey,
) -> CliResult<()> {
    eprintln!(
        "monitor: discovery backends (DHT, mDNS) are pending — \
         hellas_wire::iroh::swarm::{{dht, mdns}} modules are scope-deferred stubs."
    );
    eprintln!(
        "Use `hellas rpc <node-id> --node-addr <ip:port>` to query a known peer directly."
    );
    Ok(())
}
