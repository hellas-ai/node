use anyhow::Context;
use hellas_rpc::peers::{
    DiscoverySource, MethodKey, PeerId, RpcObservation, RpcPermitGuard, ServiceKey,
    TransportSecurity,
};
use tonic_iroh_transport::iroh::EndpointId;

pub(crate) use hellas_rpc::peers::PeerManager;

pub(crate) fn acquire_iroh_method<M: MethodKey>(
    registry: &PeerManager,
    peer_id: EndpointId,
    cost: f32,
) -> anyhow::Result<RpcPermitGuard> {
    registry
        .service_session::<<M as MethodKey>::Service>(peer_id_from_endpoint(peer_id))
        .acquire_method::<M>(cost, RpcObservation::authenticated_transport("iroh"))
        .with_context(|| {
            format!(
                "RPC admission denied for {peer_id} {}/{}",
                <M::Service as ServiceKey>::NAME,
                M::NAME
            )
        })
}

pub(crate) fn observe_iroh_service<S: ServiceKey>(
    registry: &PeerManager,
    peer_id: EndpointId,
) -> bool {
    registry
        .service_session::<S>(peer_id_from_endpoint(peer_id))
        .observe_discovered(
            DiscoverySource::Transport("discovery"),
            TransportSecurity::Untrusted,
        )
        .map_or(true, |observation| observation.service_inserted)
}

fn peer_id_from_endpoint(peer_id: EndpointId) -> PeerId {
    PeerId::from(*peer_id.as_bytes())
}
