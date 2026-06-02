use crate::{
    ConsensusActivity, LatestBlock, LightClient as LightClientApi, ProposalInfo,
    methods::LIGHT_CLIENT_METHODS,
    pb::hellas::{
        self as pb, ActivityEvent, CoinEntry, FinalizationEvent, FinalizedSnapshot,
        GetCoinResponse, GetCoinsByOwnerResponse, GetFinalizationResponse, GetLatestBlockResponse,
        GetProofResponse, GetRelayInfoResponse, GetStateRootResponse, GetValidatorsResponse,
        MergeCoinTx, NotarizationEvent, NotarizeEvent, NullificationEvent, NullifyEvent,
        SubmitTxResponse, TransferTx, WebAuthnSignature as ProtoWebAuthnSignature, activity_event,
        light_client_server, submit_tx_request,
    },
};
use futures_util::{SinkExt as _, StreamExt as _};
use hellas_kernel::List;
use hellas_kernel::domain::{
    Address, Coin, DecodeExt, Digest, Encode, MAX_MERGE_INPUTS, ObjectId, Transaction,
    UserPublicKey, UserSignature, WebAuthnSignature,
};
use hellas_rpc::mux::MuxServiceDispatch;
use p256::ecdsa::Signature as P256Signature;
use std::{io, net::SocketAddr, pin::Pin, sync::Arc};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{Mutex, broadcast},
    task::JoinHandle,
};
use tokio_stream::{Stream, wrappers::BroadcastStream};
use tokio_tungstenite::{WebSocketStream, accept_async, tungstenite::Message};
use tonic::{Request, Response, Status};
use tracing::{info, warn};

type WsStream = WebSocketStream<TcpStream>;
type WsWrite = futures_util::stream::SplitSink<WsStream, Message>;
type WsRead = futures_util::stream::SplitStream<WsStream>;
type ActivityStream = Pin<Box<dyn Stream<Item = Result<ActivityEvent, Status>> + Send + 'static>>;

#[derive(Clone)]
pub struct LightClientRpc<T> {
    client: T,
    activity_tx: broadcast::Sender<ConsensusActivity>,
}

impl<T> LightClientRpc<T> {
    pub fn new(client: T, activity_tx: broadcast::Sender<ConsensusActivity>) -> Self {
        Self {
            client,
            activity_tx,
        }
    }
}

pub async fn spawn_light_client_server<T>(
    addr: SocketAddr,
    client: T,
    activity_tx: broadcast::Sender<ConsensusActivity>,
) -> io::Result<JoinHandle<()>>
where
    T: LightClientApi,
{
    let listener = TcpListener::bind(addr).await?;
    Ok(tokio::spawn(async move {
        info!(%addr, "light client rpc server started");
        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(connection) => connection,
                Err(err) => {
                    warn!(?err, "light client rpc accept failed");
                    continue;
                }
            };
            let service = LightClientRpc::new(client.clone(), activity_tx.clone());
            tokio::spawn(async move {
                if let Err(err) = serve_connection(stream, peer, service).await {
                    warn!(?err, %peer, "light client rpc connection failed");
                }
            });
        }
    }))
}

async fn serve_connection<T>(
    stream: TcpStream,
    _peer: SocketAddr,
    service: LightClientRpc<T>,
) -> Result<(), hellas_rpc::ws_mux::Error>
where
    T: LightClientApi,
{
    let ws = accept_async(stream)
        .await
        .map_err(|err| hellas_rpc::ws_mux::Error::Io(io::Error::other(err)))?;
    let (write, read) = ws.split();
    let sink = MuxWsSink::new(write);
    let recv = MuxWsRecv::new(read);
    let service = light_client_server::LightClientServer::new(service);
    let dispatch = MuxServiceDispatch::new(service, LIGHT_CLIENT_METHODS);
    hellas_rpc::ws_mux::serve(dispatch, recv, sink).await
}

#[derive(Clone)]
struct MuxWsSink {
    write: Arc<Mutex<WsWrite>>,
}

impl MuxWsSink {
    fn new(write: WsWrite) -> Self {
        Self {
            write: Arc::new(Mutex::new(write)),
        }
    }
}

impl hellas_rpc::ws_mux::WsSink for MuxWsSink {
    async fn send(&self, data: Vec<u8>) -> Result<(), hellas_rpc::ws_mux::Error> {
        self.write
            .lock()
            .await
            .send(Message::Binary(data.into()))
            .await
            .map_err(|err| hellas_rpc::ws_mux::Error::Io(io::Error::other(err)))
    }
}

struct MuxWsRecv {
    read: WsRead,
}

impl MuxWsRecv {
    fn new(read: WsRead) -> Self {
        Self { read }
    }
}

impl hellas_rpc::ws_mux::WsRecv for MuxWsRecv {
    async fn recv(&mut self) -> Result<Option<Vec<u8>>, hellas_rpc::ws_mux::Error> {
        loop {
            match self.read.next().await {
                Some(Ok(Message::Binary(data))) => return Ok(Some(data.into())),
                Some(Ok(Message::Close(_))) | None => return Ok(None),
                Some(Ok(Message::Ping(_)))
                | Some(Ok(Message::Pong(_)))
                | Some(Ok(Message::Text(_)))
                | Some(Ok(Message::Frame(_))) => continue,
                Some(Err(err)) => {
                    return Err(hellas_rpc::ws_mux::Error::Io(io::Error::other(err)));
                }
            }
        }
    }
}

#[tonic::async_trait]
impl<T> light_client_server::LightClient for LightClientRpc<T>
where
    T: LightClientApi,
{
    async fn get_state_root(
        &self,
        _request: Request<pb::GetStateRootRequest>,
    ) -> Result<Response<GetStateRootResponse>, Status> {
        let state_root = self.client.get_state_root().await.map_err(Status::from)?;
        Ok(Response::new(GetStateRootResponse {
            state_root: state_root.map(|root| root.to_vec()),
        }))
    }

    async fn get_proof(
        &self,
        request: Request<pb::GetProofRequest>,
    ) -> Result<Response<GetProofResponse>, Status> {
        let object_id = digest_from_bytes(request.into_inner().object_id, "object_id")?;
        let proof = self
            .client
            .get_proof(object_id)
            .await
            .map_err(Status::from)?;
        Ok(Response::new(GetProofResponse { proof }))
    }

    async fn get_coin(
        &self,
        request: Request<pb::GetCoinRequest>,
    ) -> Result<Response<GetCoinResponse>, Status> {
        let request = request.into_inner();
        let payload = digest_from_bytes(request.payload, "payload")?;
        let object_id = digest_from_bytes(request.object_id, "object_id")?;
        let coin = self
            .client
            .get_coin(payload, object_id)
            .await
            .map_err(Status::from)?;
        Ok(Response::new(coin_response(coin)))
    }

    async fn get_finalization(
        &self,
        request: Request<pb::GetFinalizationRequest>,
    ) -> Result<Response<GetFinalizationResponse>, Status> {
        let payload = digest_from_bytes(request.into_inner().payload, "payload")?;
        let certificate = self
            .client
            .get_finalization(payload)
            .await
            .map_err(Status::from)?;
        Ok(Response::new(GetFinalizationResponse { certificate }))
    }

    async fn get_latest_block(
        &self,
        _request: Request<pb::GetLatestBlockRequest>,
    ) -> Result<Response<GetLatestBlockResponse>, Status> {
        let latest = self.client.get_latest_block().await.map_err(Status::from)?;
        Ok(Response::new(latest_block_response(latest)))
    }

    async fn submit_tx(
        &self,
        request: Request<pb::SubmitTxRequest>,
    ) -> Result<Response<SubmitTxResponse>, Status> {
        let tx = transaction_from_proto(request.into_inner())?;
        self.client.submit_tx(tx).await.map_err(Status::from)?;
        Ok(Response::new(SubmitTxResponse {}))
    }

    type SubscribeActivityStream = ActivityStream;

    async fn subscribe_activity(
        &self,
        request: Request<pb::SubscribeActivityRequest>,
    ) -> Result<Response<Self::SubscribeActivityStream>, Status> {
        let urgent_events = request.into_inner().urgent_events;
        let stream = BroadcastStream::new(self.activity_tx.subscribe()).filter_map(move |event| {
            let urgent_events = urgent_events.clone();
            async move {
                match event {
                    Ok(activity) if activity_is_requested(&urgent_events, &activity) => {
                        Some(Ok(activity_to_proto(activity)))
                    }
                    Ok(_) => None,
                    Err(err) => Some(Err(Status::unavailable(format!(
                        "activity stream lagged: {err}"
                    )))),
                }
            }
        });
        Ok(Response::new(Box::pin(stream)))
    }

    async fn get_validators(
        &self,
        _request: Request<pb::GetValidatorsRequest>,
    ) -> Result<Response<GetValidatorsResponse>, Status> {
        let validators = self.client.get_validators().await.map_err(Status::from)?;
        Ok(Response::new(GetValidatorsResponse { validators }))
    }

    async fn get_coins_by_owner(
        &self,
        request: Request<pb::GetCoinsByOwnerRequest>,
    ) -> Result<Response<GetCoinsByOwnerResponse>, Status> {
        let owner = address_from_bytes(request.into_inner().owner, "owner")?;
        let response = match self
            .client
            .get_coins_by_owner(owner)
            .await
            .map_err(Status::from)?
        {
            Some(owner_coins) => GetCoinsByOwnerResponse {
                snapshot: Some(latest_block_to_proto(owner_coins.snapshot)),
                coins: owner_coins
                    .coins
                    .into_iter()
                    .map(|(object_id, value)| CoinEntry {
                        object_id: object_id.to_vec(),
                        value,
                    })
                    .collect(),
            },
            None => GetCoinsByOwnerResponse {
                snapshot: None,
                coins: Vec::new(),
            },
        };
        Ok(Response::new(response))
    }

    async fn get_relay_info(
        &self,
        _request: Request<pb::GetRelayInfoRequest>,
    ) -> Result<Response<GetRelayInfoResponse>, Status> {
        Ok(Response::new(GetRelayInfoResponse {
            relay_version: String::new(),
            relay_rev: String::new(),
            node_rpc_version: env!("CARGO_PKG_VERSION").to_string(),
            node_rpc_rev: option_env!("GIT_REV").unwrap_or("unknown").to_string(),
        }))
    }
}

fn digest_from_bytes(bytes: Vec<u8>, field: &'static str) -> Result<Digest, Status> {
    let len = bytes.len();
    let raw: [u8; 32] = bytes
        .try_into()
        .map_err(|_| Status::invalid_argument(format!("{field} must be 32 bytes, got {len}")))?;
    Ok(Digest::from(raw))
}

fn address_from_bytes(bytes: Vec<u8>, field: &'static str) -> Result<Address, Status> {
    UserPublicKey::decode(bytes.as_slice())
        .map(Address::from)
        .map_err(|_| Status::invalid_argument(format!("{field} must be a valid public key")))
}

fn user_signature_from_der(bytes: &[u8]) -> Result<UserSignature, Status> {
    let signature = P256Signature::from_der(bytes)
        .map_err(|_| Status::invalid_argument("signature must be valid DER-encoded P-256 ECDSA"))?;
    let normalized = signature.normalize_s().unwrap_or(signature);
    UserSignature::decode(normalized.to_bytes().as_ref())
        .map_err(|_| Status::invalid_argument("signature must be a valid low-S P-256 signature"))
}

fn webauthn_signature_from_proto(
    signature: Option<ProtoWebAuthnSignature>,
) -> Result<WebAuthnSignature, Status> {
    let signature =
        signature.ok_or_else(|| Status::invalid_argument("missing WebAuthn signature"))?;
    let user_signature = user_signature_from_der(&signature.ecdsa_signature)?;
    WebAuthnSignature::new(
        user_signature,
        &signature.authenticator_data,
        &signature.client_data_json,
    )
    .ok_or_else(|| Status::invalid_argument("invalid WebAuthn signature payload"))
}

fn transaction_from_proto(request: pb::SubmitTxRequest) -> Result<Transaction, Status> {
    match request
        .tx
        .ok_or_else(|| Status::invalid_argument("missing transaction"))?
    {
        submit_tx_request::Tx::Transfer(tx) => transfer_from_proto(tx),
        submit_tx_request::Tx::MergeCoin(tx) => merge_from_proto(tx),
    }
}

fn transfer_from_proto(tx: TransferTx) -> Result<Transaction, Status> {
    Ok(Transaction::Transfer {
        input: digest_from_bytes(tx.input, "input")?,
        recipient: address_from_bytes(tx.recipient, "recipient")?,
        amount: tx.amount,
        signature: webauthn_signature_from_proto(tx.signature)?,
    })
}

fn merge_from_proto(tx: MergeCoinTx) -> Result<Transaction, Status> {
    if tx.inputs.len() < 2 {
        return Err(Status::invalid_argument("merge requires at least 2 inputs"));
    }
    if tx.inputs.len() > MAX_MERGE_INPUTS {
        return Err(Status::invalid_argument(format!(
            "merge supports at most {MAX_MERGE_INPUTS} inputs"
        )));
    }
    let len = tx.inputs.len();
    let mut inputs = [ObjectId::from([0; 32]); MAX_MERGE_INPUTS];
    for (index, input) in tx.inputs.into_iter().enumerate() {
        inputs[index] = digest_from_bytes(input, "input")?;
    }
    let inputs = List::new(inputs, len)
        .ok_or_else(|| Status::invalid_argument("merge input count exceeds capacity"))?;
    Ok(Transaction::MergeCoin {
        inputs,
        signature: webauthn_signature_from_proto(tx.signature)?,
    })
}

fn coin_response(coin: Option<Coin>) -> GetCoinResponse {
    match coin {
        Some(Coin { owner, value }) => GetCoinResponse {
            owner: Some(owner.public_key().encode().to_vec()),
            value: Some(value),
        },
        None => GetCoinResponse {
            owner: None,
            value: None,
        },
    }
}

fn latest_block_response(latest: Option<LatestBlock>) -> GetLatestBlockResponse {
    GetLatestBlockResponse {
        latest: latest.map(latest_block_to_proto),
    }
}

fn latest_block_to_proto(latest: LatestBlock) -> FinalizedSnapshot {
    FinalizedSnapshot {
        height: latest.height,
        payload: latest.payload.to_vec(),
        state_root: latest.state_root.to_vec(),
        finalization: latest.finalization,
    }
}

fn proposal_to_proto(proposal: ProposalInfo) -> pb::ProposalInfo {
    pb::ProposalInfo {
        epoch: proposal.epoch,
        view: proposal.view,
        parent_view: proposal.parent_view,
        parent_payload: proposal.parent_payload.to_vec(),
        payload: proposal.payload.to_vec(),
    }
}

fn activity_kind(activity: &ConsensusActivity) -> i32 {
    match activity {
        ConsensusActivity::Notarize { .. } => pb::ActivityEventKind::Notarize as i32,
        ConsensusActivity::Notarization { .. } => pb::ActivityEventKind::Notarization as i32,
        ConsensusActivity::Nullify { .. } => pb::ActivityEventKind::Nullify as i32,
        ConsensusActivity::Nullification { .. } => pb::ActivityEventKind::Nullification as i32,
        ConsensusActivity::Finalization { .. } => pb::ActivityEventKind::Finalization as i32,
    }
}

fn activity_is_requested(urgent_events: &[i32], activity: &ConsensusActivity) -> bool {
    urgent_events.is_empty() || urgent_events.contains(&activity_kind(activity))
}

fn activity_to_proto(activity: ConsensusActivity) -> ActivityEvent {
    let event = match activity {
        ConsensusActivity::Notarize {
            proposal,
            signer,
            signature,
        } => activity_event::Event::Notarize(NotarizeEvent {
            proposal: Some(proposal_to_proto(proposal)),
            signer,
            signature,
        }),
        ConsensusActivity::Notarization {
            proposal,
            signers,
            certificate,
        } => activity_event::Event::Notarization(NotarizationEvent {
            proposal: Some(proposal_to_proto(proposal)),
            signers,
            certificate,
        }),
        ConsensusActivity::Nullify {
            epoch,
            view,
            signer,
            signature,
        } => activity_event::Event::Nullify(NullifyEvent {
            epoch,
            view,
            signer,
            signature,
        }),
        ConsensusActivity::Nullification {
            epoch,
            view,
            signers,
            certificate,
        } => activity_event::Event::Nullification(NullificationEvent {
            epoch,
            view,
            signers,
            certificate,
        }),
        ConsensusActivity::Finalization {
            proposal,
            signers,
            certificate,
        } => activity_event::Event::Finalization(FinalizationEvent {
            proposal: Some(proposal_to_proto(proposal)),
            signers,
            certificate,
        }),
    };
    ActivityEvent {
        event: Some(event),
        relay_timestamps: Vec::new(),
        edge_colo: String::new(),
    }
}
