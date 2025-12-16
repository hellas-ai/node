use tonic_iroh_transport::iroh::EndpointId;

// Hardcoded bootstrap peers for gossip discovery.
//
// These should be stable public nodes that publish their addresses (e.g. via pkarr/DHT),
// so we can dial them by `EndpointId` without having to discover them on the LAN.
const BOOTSTRAP_PEERS: &[&str] =
    &["bad6b59cd14afc9c15ab944ce3cc699d50ecaa56241882f85c111b546feea410"];

pub fn bootstrap_peer_ids() -> Vec<EndpointId> {
    BOOTSTRAP_PEERS
        .iter()
        .filter_map(|s| s.parse::<EndpointId>().ok())
        .collect()
}
