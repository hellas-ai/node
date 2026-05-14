//! Discovery / peer-interrogation monitor.
//!
//! NOTE (hellas-wire v2 cutover): `run` returns `unimplemented!()` until
//! the discovery + pool port lands. The old implementation depended on
//! `tonic-iroh-transport::swarm::{ServiceRegistry, DhtBackend,
//! MdnsBackend, PeerExchangeBackend}` plus the per-peer
//! `hellas_rpc::peers::IrohTransport`, neither of which has a
//! `hellas-wire` equivalent yet. The CLI subcommand surface (`run`'s
//! signature) is preserved so the binary still type-checks. See
//! `HELLAS_WIRE_CUTOVER_FINDINGS.md` finding #5.

use crate::commands::CliResult;
use iroh::SecretKey;

pub async fn run(
    _timeout_secs: Option<u64>,
    _interrogate: bool,
    _secret_key: SecretKey,
) -> CliResult<()> {
    unimplemented!(
        "monitor pending hellas-wire discovery/pool port — see CUTOVER_FINDINGS.md"
    )
}
