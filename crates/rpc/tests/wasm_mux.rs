#![cfg(target_arch = "wasm32")]

use std::fmt;
use std::future::Future;
use std::pin::Pin;

use bytes::Bytes;
use futures_util::future;
use hellas_rpc::call::WithTrailer;
use hellas_rpc::pb::swarm::{
    GetKnownPeersRequest, GetKnownPeersResponse, GetNodeInfoRequest, GetNodeInfoResponse,
};
use hellas_rpc::services::node::{NodeClientImpl, NodeHandler, NodeServer};
use hellas_wire::mux::{MessagePipe, MuxConfig, MuxStream, MuxTransport, Role};
use hellas_wire::{DefaultClock, Dispatcher, StreamTransport, WireStatus};
use tokio::sync::mpsc;
use wasm_bindgen_test::wasm_bindgen_test;

#[derive(Debug)]
struct PipeClosed;

impl fmt::Display for PipeClosed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("pipe closed")
    }
}

impl std::error::Error for PipeClosed {}

struct ChannelPipe {
    tx: mpsc::UnboundedSender<Bytes>,
    rx: mpsc::UnboundedReceiver<Bytes>,
}

impl MessagePipe for ChannelPipe {
    async fn send_message(&mut self, bytes: Bytes) -> Result<(), Self::SendError> {
        self.tx.send(bytes).map_err(|_| PipeClosed)
    }

    async fn recv_message(&mut self) -> Result<Option<Bytes>, Self::RecvError> {
        Ok(self.rx.recv().await)
    }

    type SendError = PipeClosed;
    type RecvError = PipeClosed;
}

fn spawn_local(fut: Pin<Box<dyn Future<Output = ()> + Send + 'static>>) {
    wasm_bindgen_futures::spawn_local(fut);
}

fn mux_pair() -> (MuxTransport, MuxTransport) {
    let (client_tx, server_rx) = mpsc::unbounded_channel();
    let (server_tx, client_rx) = mpsc::unbounded_channel();
    let client = MuxTransport::spawn_with::<8, DefaultClock, _, _>(
        Role::Client,
        DefaultClock,
        MuxConfig::default(),
        ChannelPipe {
            tx: client_tx,
            rx: client_rx,
        },
        None,
        spawn_local,
    );
    let server = MuxTransport::spawn_with::<8, DefaultClock, _, _>(
        Role::Server,
        DefaultClock,
        MuxConfig::default(),
        ChannelPipe {
            tx: server_tx,
            rx: server_rx,
        },
        None,
        spawn_local,
    );
    (client, server)
}

#[derive(Clone)]
struct WasmNode;

#[allow(refining_impl_trait)]
impl NodeHandler for WasmNode {
    async fn get_node_info(
        &self,
        _request: GetNodeInfoRequest,
    ) -> Result<WithTrailer<GetNodeInfoResponse>, WireStatus> {
        Ok(WithTrailer::new(GetNodeInfoResponse {
            node_id: "wasm-node".to_string(),
            uptime_seconds: 7,
            version: "test".to_string(),
            build: "wasm".to_string(),
            os: "wasm32-unknown-unknown".to_string(),
            graffiti: b"rpc-mux-wasm".to_vec(),
        }))
    }

    async fn get_known_peers(
        &self,
        _request: GetKnownPeersRequest,
    ) -> Result<WithTrailer<GetKnownPeersResponse>, WireStatus> {
        Ok(WithTrailer::new(GetKnownPeersResponse {
            peer_ids: Vec::new(),
        }))
    }
}

async fn dispatch_mux<S>(server: &S, inbound: hellas_wire::Inbound<MuxStream>)
where
    S: Dispatcher<MuxTransport>,
    S::Error: fmt::Debug,
{
    server.dispatch(inbound).await.expect("dispatch");
}

#[wasm_bindgen_test(async)]
async fn node_unary_round_trips_over_mux_without_iroh() {
    let (client_transport, server_transport) = mux_pair();

    let server = NodeServer(WasmNode);
    let server_task = async move {
        let inbound = server_transport
            .accept()
            .await
            .expect("server accept")
            .expect("inbound stream");
        dispatch_mux(&server, inbound).await;
    };

    let client_task = async move {
        NodeClientImpl::new(client_transport)
            .get_node_info(GetNodeInfoRequest {})
            .await
    };

    let ((), response) = future::join(server_task, client_task).await;
    let response = response.expect("get_node_info");

    assert_eq!(response.node_id, "wasm-node");
    assert_eq!(response.graffiti, b"rpc-mux-wasm");
}
