use anyhow::Context;
use hellas_rpc::peers::{
    DiscoverySource, PeerId, RequestKind, RpcObservation, RpcPermitGuard, TransportSecurity,
};
use tonic_iroh_transport::iroh::EndpointId;

pub(crate) use hellas_rpc::peers::PeerManager;

pub(crate) fn acquire_iroh_rpc(
    registry: &PeerManager,
    peer_id: EndpointId,
    service: &'static str,
    method: &'static str,
    cost: f32,
) -> anyhow::Result<RpcPermitGuard> {
    registry
        .acquire_rpc(
            peer_id_from_endpoint(peer_id),
            RequestKind::new(service, method),
            cost,
            RpcObservation::authenticated_transport("iroh"),
        )
        .with_context(|| format!("RPC admission denied for {peer_id} {service}/{method}"))
}

pub(crate) fn observe_iroh_discovered_service(
    registry: &PeerManager,
    peer_id: EndpointId,
    service: &'static str,
) {
    let _ = registry.observe_discovered_service(
        peer_id_from_endpoint(peer_id),
        DiscoverySource::Transport("discovery"),
        service,
        TransportSecurity::Untrusted,
    );
}

fn peer_id_from_endpoint(peer_id: EndpointId) -> PeerId {
    PeerId::from(*peer_id.as_bytes())
}
