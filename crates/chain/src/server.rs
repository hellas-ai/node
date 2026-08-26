use crate::domain::Bounded;
use crate::domain::{
    Address, Coin, DecodeExt, Digest, MAX_MERGE_INPUTS, ObjectId, SettlementKey, Transaction,
    UserPublicKey, UserSignature, WebAuthnSignature,
};
use crate::work_view::{FinalizedWorkView, WorkChannelQuery, WorkChannelSnapshot};
use crate::{
    ConsensusActivity, ConsensusInfo, EdgeLookup, EdgeState, FinalizedBlock, FinalizedBlockQuery,
    LatestBlock, LightClient as LightClientApi, MAX_CANONICAL_TRANSACTION_BYTES, OwnerEdges,
    ProposalInfo,
};
use futures_util::{Stream, StreamExt as _};
use hellas_kernel::{Decode as _, EdgeId, Tx as KernelTx};
use hellas_rpc::SubmitTxOutcome;
use hellas_rpc::pb::{
    chain::{
        self as pb, ActivityEvent, CoinEntry, EdgeEntry, EdgeState as ProtoEdgeState,
        FinalizationEvent, FinalizedBlock as ProtoFinalizedBlock, FinalizedSnapshot,
        GetCoinResponse, GetCoinsByOwnerResponse, GetConsensusInfoResponse, GetEdgeResponse,
        GetEdgesByOwnerResponse, GetFinalizationResponse, GetFinalizedBlockResponse,
        GetLatestBlockResponse, GetProofResponse, GetRelayInfoResponse, GetStateRootResponse,
        GetValidatorsResponse, GetWorkChannelSnapshotResponse, KernelFees, MergeCoinTx,
        NotarizationEvent, NotarizeEvent, NullificationEvent, NullifyEvent, RegistrySlot,
        SubmitTxOutcome as ProtoSubmitTxOutcome, SubmitTxResponse, TransferTx,
        WebAuthnSignature as ProtoWebAuthnSignature, activity_event, submit_tx_request,
    },
    services::light_client::{LightClientHandler, LightClientServer},
};
use hellas_wire::{Dispatcher, StreamTransport, WireCode, WireStatus};
use p256::ecdsa::Signature as P256Signature;
use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::broadcast,
    task::JoinHandle,
};
use tokio_stream::wrappers::BroadcastStream;
use tokio_tungstenite::accept_async;
use tracing::{info, warn};

type ActivityStream =
    Pin<Box<dyn Stream<Item = Result<ActivityEvent, WireStatus>> + Send + 'static>>;
pub type LightClientServerError = Box<dyn std::error::Error + Send + Sync + 'static>;

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
    T: LightClientApi + FinalizedWorkView,
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
                if let Err(err) = serve_connection(stream, service).await {
                    warn!(?err, %peer, "light client rpc connection failed");
                }
            });
        }
    }))
}

async fn serve_connection<T>(
    stream: TcpStream,
    service: LightClientRpc<T>,
) -> Result<(), LightClientServerError>
where
    T: LightClientApi + FinalizedWorkView,
{
    let ws = accept_async(stream).await?;
    let transport = hellas_wire::ws::accept_upgraded(ws, None);
    serve_light_client_transport(transport, service).await
}

/// Serve the typed light-client API over any inbound-stream transport.
///
/// Each RPC is dispatched in its own task. Server-streaming calls can remain
/// open indefinitely and must not block unary calls on other mux streams.
pub async fn serve_light_client_transport<T, C>(
    transport: T,
    service: LightClientRpc<C>,
) -> Result<(), LightClientServerError>
where
    T: StreamTransport + Send + Sync + 'static,
    T::Stream: 'static,
    <T::Stream as hellas_wire::Stream>::RecvHalf: 'static,
    <T::Stream as hellas_wire::Stream>::SendHalf: 'static,
    C: LightClientApi + FinalizedWorkView,
{
    let mut calls = tokio::task::JoinSet::new();
    while let Some(inbound) = transport.accept().await? {
        let dispatch = LightClientServer(service.clone());
        calls.spawn(async move {
            <LightClientServer<LightClientRpc<C>> as Dispatcher<T>>::dispatch(&dispatch, inbound)
                .await
        });

        while let Some(result) = calls.try_join_next() {
            match result {
                Ok(Ok(())) => {}
                Ok(Err(error)) => warn!(%error, "light client rpc failed"),
                Err(error) => warn!(%error, "light client rpc task failed"),
            }
        }
    }

    calls.abort_all();
    while let Some(result) = calls.join_next().await {
        match result {
            Ok(Ok(())) => {}
            Ok(Err(error)) => warn!(%error, "light client rpc failed"),
            Err(error) if error.is_cancelled() => {}
            Err(error) => warn!(%error, "light client rpc task failed"),
        }
    }
    Ok(())
}

#[allow(refining_impl_trait)]
impl<T> LightClientHandler for LightClientRpc<T>
where
    T: LightClientApi + FinalizedWorkView,
{
    fn get_state_root(
        &self,
        _request: pb::GetStateRootRequest,
    ) -> impl Future<Output = Result<GetStateRootResponse, WireStatus>> + Send {
        let client = self.client.clone();
        async move {
            let state_root = client.get_state_root().await.map_err(WireStatus::from)?;
            Ok(GetStateRootResponse {
                state_root: state_root.map(|root| root.to_vec()),
            })
        }
    }

    fn get_proof(
        &self,
        request: pb::GetProofRequest,
    ) -> impl Future<Output = Result<GetProofResponse, WireStatus>> + Send {
        let client = self.client.clone();
        async move {
            let object_id = digest_from_bytes(request.object_id, "object_id")?;
            let proof = client
                .get_proof(object_id)
                .await
                .map_err(WireStatus::from)?;
            Ok(GetProofResponse { proof })
        }
    }

    fn get_coin(
        &self,
        request: pb::GetCoinRequest,
    ) -> impl Future<Output = Result<GetCoinResponse, WireStatus>> + Send {
        let client = self.client.clone();
        async move {
            let payload = digest_from_bytes(request.payload, "payload")?;
            let object_id = digest_from_bytes(request.object_id, "object_id")?;
            let coin = client
                .get_coin(payload, object_id)
                .await
                .map_err(WireStatus::from)?;
            Ok(coin_response(coin))
        }
    }

    fn get_edge(
        &self,
        request: pb::GetEdgeRequest,
    ) -> impl Future<Output = Result<GetEdgeResponse, WireStatus>> + Send {
        let client = self.client.clone();
        async move {
            let payload = digest_from_bytes(request.payload, "payload")?;
            let object_id = digest_from_bytes(request.object_id, "object_id")?;
            let edge = client
                .get_edge(payload, object_id)
                .await
                .map_err(WireStatus::from)?;
            Ok(edge_response(edge))
        }
    }

    fn get_work_channel_snapshot(
        &self,
        request: pb::GetWorkChannelSnapshotRequest,
    ) -> impl Future<Output = Result<GetWorkChannelSnapshotResponse, WireStatus>> + Send {
        let client = self.client.clone();
        async move {
            let mut funding = std::collections::BTreeSet::new();
            for bytes in request.funding_coins {
                funding.insert(coin_id_from_bytes(bytes, "funding_coins")?);
            }
            let query = WorkChannelQuery {
                bond_edge: edge_id_from_bytes(request.bond_edge, "bond_edge")?,
                payment_edge: edge_id_from_bytes(request.payment_edge, "payment_edge")?,
                funding,
            };
            let snapshot = client
                .work_channel_snapshot(query)
                .await
                .map_err(WireStatus::from)?;
            Ok(work_channel_snapshot_response(snapshot))
        }
    }

    fn get_finalization(
        &self,
        request: pb::GetFinalizationRequest,
    ) -> impl Future<Output = Result<GetFinalizationResponse, WireStatus>> + Send {
        let client = self.client.clone();
        async move {
            let payload = digest_from_bytes(request.payload, "payload")?;
            let certificate = client
                .get_finalization(payload)
                .await
                .map_err(WireStatus::from)?;
            Ok(GetFinalizationResponse { certificate })
        }
    }

    fn get_latest_block(
        &self,
        _request: pb::GetLatestBlockRequest,
    ) -> impl Future<Output = Result<GetLatestBlockResponse, WireStatus>> + Send {
        let client = self.client.clone();
        async move {
            let latest = client.get_latest_block().await.map_err(WireStatus::from)?;
            Ok(latest_block_response(latest))
        }
    }

    fn get_finalized_block(
        &self,
        request: pb::GetFinalizedBlockRequest,
    ) -> impl Future<Output = Result<GetFinalizedBlockResponse, WireStatus>> + Send {
        let client = self.client.clone();
        async move {
            let query = finalized_block_query_from_proto(request)?;
            let block = client
                .get_finalized_block(query)
                .await
                .map_err(WireStatus::from)?;
            Ok(finalized_block_response(block))
        }
    }

    fn submit_tx(
        &self,
        request: pb::SubmitTxRequest,
    ) -> impl Future<Output = Result<SubmitTxResponse, WireStatus>> + Send {
        let client = self.client.clone();
        async move {
            let tx = transaction_from_proto(request)?;
            if crate::light_client::canonical_submission_size(&tx) > MAX_CANONICAL_TRANSACTION_BYTES
            {
                return Err(WireStatus::new(
                    WireCode::InvalidArgument,
                    format!(
                        "canonical transaction exceeds {MAX_CANONICAL_TRANSACTION_BYTES} bytes"
                    ),
                ));
            }
            let outcome = client.submit_tx(tx).await.map_err(WireStatus::from)?;
            Ok(SubmitTxResponse {
                outcome: submit_tx_outcome_to_proto(outcome) as i32,
            })
        }
    }

    fn subscribe_activity(
        &self,
        request: pb::SubscribeActivityRequest,
    ) -> impl Future<Output = Result<ActivityStream, WireStatus>> + Send {
        let activity_tx = self.activity_tx.clone();
        async move {
            let urgent_events = request.urgent_events;
            let stream = BroadcastStream::new(activity_tx.subscribe()).filter_map(move |event| {
                let urgent_events = urgent_events.clone();
                async move {
                    match event {
                        Ok(activity) if activity_is_requested(&urgent_events, &activity) => {
                            Some(Ok(activity_to_proto(activity)))
                        }
                        Ok(_) => None,
                        Err(err) => Some(Err(WireStatus::new(
                            WireCode::Unavailable,
                            format!("activity stream lagged: {err}"),
                        ))),
                    }
                }
            });
            Ok(Box::pin(stream) as ActivityStream)
        }
    }

    fn get_validators(
        &self,
        _request: pb::GetValidatorsRequest,
    ) -> impl Future<Output = Result<GetValidatorsResponse, WireStatus>> + Send {
        let client = self.client.clone();
        async move {
            let validators = client.get_validators().await.map_err(WireStatus::from)?;
            Ok(GetValidatorsResponse { validators })
        }
    }

    fn get_coins_by_owner(
        &self,
        request: pb::GetCoinsByOwnerRequest,
    ) -> impl Future<Output = Result<GetCoinsByOwnerResponse, WireStatus>> + Send {
        let client = self.client.clone();
        async move {
            let owner = settlement_key_from_bytes(request.owner, "owner")?;
            let response = match client
                .get_coins_by_owner(owner)
                .await
                .map_err(WireStatus::from)?
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
            Ok(response)
        }
    }

    fn get_edges_by_owner(
        &self,
        request: pb::GetEdgesByOwnerRequest,
    ) -> impl Future<Output = Result<GetEdgesByOwnerResponse, WireStatus>> + Send {
        let client = self.client.clone();
        async move {
            let owner = settlement_key_from_bytes(request.owner, "owner")?;
            let response = client
                .get_edges_by_owner(owner)
                .await
                .map_err(WireStatus::from)?;
            Ok(edges_by_owner_response(response))
        }
    }

    async fn get_relay_info(
        &self,
        _request: pb::GetRelayInfoRequest,
    ) -> Result<GetRelayInfoResponse, WireStatus> {
        Ok(GetRelayInfoResponse {
            relay_version: String::new(),
            relay_rev: String::new(),
            node_rpc_version: env!("CARGO_PKG_VERSION").to_string(),
            node_rpc_rev: option_env!("GIT_REV").unwrap_or("unknown").to_string(),
        })
    }

    fn get_consensus_info(
        &self,
        _request: pb::GetConsensusInfoRequest,
    ) -> impl Future<Output = Result<GetConsensusInfoResponse, WireStatus>> + Send {
        let client = self.client.clone();
        async move {
            let info = client
                .get_consensus_info()
                .await
                .map_err(WireStatus::from)?;
            Ok(consensus_info_response(info))
        }
    }
}

fn consensus_info_response(info: ConsensusInfo) -> GetConsensusInfoResponse {
    GetConsensusInfoResponse {
        validators: info.validators,
        threshold_identity: info.threshold_identity,
        network_id: info.network_id,
    }
}

fn digest_from_bytes(bytes: Vec<u8>, field: &'static str) -> Result<Digest, WireStatus> {
    let len = bytes.len();
    let raw: [u8; 32] = bytes.try_into().map_err(|_| {
        WireStatus::new(
            WireCode::InvalidArgument,
            format!("{field} must be 32 bytes, got {len}"),
        )
    })?;
    Ok(Digest::from(raw))
}

fn address_from_bytes(bytes: Vec<u8>, field: &'static str) -> Result<Address, WireStatus> {
    UserPublicKey::decode(bytes.as_slice())
        .map(Address::from)
        .map_err(|_| {
            WireStatus::new(
                WireCode::InvalidArgument,
                format!("{field} must be a valid public key"),
            )
        })
}

fn settlement_key_from_bytes(
    bytes: Vec<u8>,
    field: &'static str,
) -> Result<SettlementKey, WireStatus> {
    let len = bytes.len();
    let raw: [u8; SettlementKey::LENGTH] = bytes.try_into().map_err(|_| {
        WireStatus::new(
            WireCode::InvalidArgument,
            format!("{field} must be {} bytes, got {len}", SettlementKey::LENGTH),
        )
    })?;
    Ok(SettlementKey::from_bytes(raw))
}

fn user_signature_from_der(bytes: &[u8]) -> Result<UserSignature, WireStatus> {
    let signature = P256Signature::from_der(bytes).map_err(|_| {
        WireStatus::new(
            WireCode::InvalidArgument,
            "signature must be valid DER-encoded P-256 ECDSA",
        )
    })?;
    let normalized = signature.normalize_s();
    UserSignature::decode(normalized.to_bytes().as_ref()).map_err(|_| {
        WireStatus::new(
            WireCode::InvalidArgument,
            "signature must be a valid low-S P-256 signature",
        )
    })
}

fn webauthn_signature_from_proto(
    signature: Option<ProtoWebAuthnSignature>,
) -> Result<WebAuthnSignature, WireStatus> {
    let signature = signature
        .ok_or_else(|| WireStatus::new(WireCode::InvalidArgument, "missing WebAuthn signature"))?;
    let user_signature = user_signature_from_der(&signature.ecdsa_signature)?;
    WebAuthnSignature::new(
        user_signature,
        &signature.authenticator_data,
        &signature.client_data_json,
    )
    .ok_or_else(|| {
        WireStatus::new(
            WireCode::InvalidArgument,
            "invalid WebAuthn signature payload",
        )
    })
}

fn submit_tx_outcome_to_proto(outcome: SubmitTxOutcome) -> ProtoSubmitTxOutcome {
    match outcome {
        SubmitTxOutcome::Enqueued => ProtoSubmitTxOutcome::Enqueued,
        SubmitTxOutcome::Duplicate => ProtoSubmitTxOutcome::Duplicate,
        SubmitTxOutcome::Full => ProtoSubmitTxOutcome::Full,
        SubmitTxOutcome::ValidationRejected => ProtoSubmitTxOutcome::ValidationRejected,
    }
}

fn transaction_from_proto(request: pb::SubmitTxRequest) -> Result<Transaction, WireStatus> {
    match request
        .tx
        .ok_or_else(|| WireStatus::new(WireCode::InvalidArgument, "missing transaction"))?
    {
        submit_tx_request::Tx::Transfer(tx) => transfer_from_proto(tx),
        submit_tx_request::Tx::MergeCoin(tx) => merge_from_proto(tx),
        submit_tx_request::Tx::KernelTx(bytes) => kernel_from_proto(&bytes),
    }
}

fn kernel_from_proto(bytes: &[u8]) -> Result<Transaction, WireStatus> {
    KernelTx::decode_exact(bytes)
        .map(Transaction::Kernel)
        .map_err(|_| {
            WireStatus::new(
                WireCode::InvalidArgument,
                "invalid canonical kernel transaction",
            )
        })
}

fn transfer_from_proto(tx: TransferTx) -> Result<Transaction, WireStatus> {
    Ok(Transaction::Transfer {
        input: digest_from_bytes(tx.input, "input")?,
        recipient: address_from_bytes(tx.recipient, "recipient")?,
        amount: tx.amount,
        signature: webauthn_signature_from_proto(tx.signature)?,
    })
}

fn merge_from_proto(tx: MergeCoinTx) -> Result<Transaction, WireStatus> {
    if tx.inputs.len() < 2 {
        return Err(WireStatus::new(
            WireCode::InvalidArgument,
            "merge requires at least 2 inputs",
        ));
    }
    if tx.inputs.len() > MAX_MERGE_INPUTS {
        return Err(WireStatus::new(
            WireCode::InvalidArgument,
            format!("merge supports at most {MAX_MERGE_INPUTS} inputs"),
        ));
    }
    let len = tx.inputs.len();
    let mut inputs = [ObjectId::from([0; 32]); MAX_MERGE_INPUTS];
    for (index, input) in tx.inputs.into_iter().enumerate() {
        inputs[index] = digest_from_bytes(input, "input")?;
    }
    let inputs = Bounded::new(inputs, len).ok_or_else(|| {
        WireStatus::new(
            WireCode::InvalidArgument,
            "merge input count exceeds capacity",
        )
    })?;
    Ok(Transaction::MergeCoin {
        inputs,
        signature: webauthn_signature_from_proto(tx.signature)?,
    })
}

fn coin_response(coin: Option<Coin>) -> GetCoinResponse {
    match coin {
        Some(Coin { owner, value }) => GetCoinResponse {
            owner: Some(owner.to_bytes().to_vec()),
            value: Some(value),
        },
        None => GetCoinResponse {
            owner: None,
            value: None,
        },
    }
}

fn edge_response(lookup: Option<EdgeLookup>) -> GetEdgeResponse {
    match lookup {
        Some(EdgeLookup { state_root, edge }) => GetEdgeResponse {
            edge: edge.map(edge_state_to_proto),
            state_root: Some(state_root.to_vec()),
        },
        None => GetEdgeResponse {
            edge: None,
            state_root: None,
        },
    }
}

pub(crate) fn work_channel_snapshot_response(
    snapshot: Option<WorkChannelSnapshot>,
) -> GetWorkChannelSnapshotResponse {
    match snapshot {
        Some(snapshot) => GetWorkChannelSnapshotResponse {
            snapshot: Some(latest_block_to_proto(snapshot.block().clone())),
            bond_edge: snapshot.bond().map(kernel_bytes),
            payment_edge: snapshot.payment().map(kernel_bytes),
            lease_slots: snapshot
                .lease_slots()
                .iter()
                .map(|slot| RegistrySlot {
                    chunk: slot.as_ref().map(kernel_bytes),
                })
                .collect(),
            pending_slot: Some(RegistrySlot {
                chunk: snapshot.pending_slot().as_ref().map(kernel_bytes),
            }),
            live_funding: snapshot
                .live_funding()
                .iter()
                .map(|coin| coin.to_bytes().to_vec())
                .collect(),
        },
        None => GetWorkChannelSnapshotResponse {
            snapshot: None,
            bond_edge: None,
            payment_edge: None,
            lease_slots: Vec::new(),
            pending_slot: None,
            live_funding: Vec::new(),
        },
    }
}

/// Returns one kernel object's canonical bytes.
///
/// The wire carries exactly what consensus stored rather than a
/// re-spelling of its fields, so a caller decodes the object with the
/// kernel's own decoder and there is no second definition of an edge on
/// this path.
fn kernel_bytes<E: hellas_kernel::Encode>(value: &E) -> Vec<u8> {
    let mut buf = vec![0_u8; value.encoded_size()];
    let written = value.write_to(&mut buf);
    buf.truncate(written);
    buf
}

fn coin_id_from_bytes(
    bytes: Vec<u8>,
    field: &'static str,
) -> Result<hellas_kernel::CoinId, WireStatus> {
    hellas_kernel::CoinId::decode_exact(&bytes).map_err(|_| {
        WireStatus::new(
            WireCode::InvalidArgument,
            format!(
                "{field} was not {} canonical bytes",
                hellas_kernel::CoinId::LENGTH
            ),
        )
    })
}

fn edge_id_from_bytes(bytes: Vec<u8>, field: &'static str) -> Result<EdgeId, WireStatus> {
    EdgeId::decode_exact(&bytes).map_err(|_| {
        WireStatus::new(
            WireCode::InvalidArgument,
            format!("{field} was not {} canonical bytes", EdgeId::LENGTH),
        )
    })
}

fn edge_state_to_proto(edge: EdgeState) -> ProtoEdgeState {
    ProtoEdgeState {
        value: edge.value,
        reserve: edge.reserve,
        close_fees: Some(KernelFees {
            base: edge.close_fees.base(),
            slot: edge.close_fees.slot(),
            proof: edge.close_fees.proof(),
            lifetime: edge.close_fees.lifetime(),
        }),
        timeout: edge.timeout.get(),
        maker: edge.maker.to_bytes().to_vec(),
        taker: edge.taker.to_bytes().to_vec(),
        terms_hash: edge.terms_hash.to_bytes().to_vec(),
    }
}

fn edges_by_owner_response(edges: Option<OwnerEdges>) -> GetEdgesByOwnerResponse {
    match edges {
        Some(owner_edges) => GetEdgesByOwnerResponse {
            snapshot: Some(latest_block_to_proto(owner_edges.snapshot)),
            edges: owner_edges
                .edges
                .into_iter()
                .map(|edge| EdgeEntry {
                    object_id: edge.object_id.to_vec(),
                    maker: edge.maker.to_bytes().to_vec(),
                    taker: edge.taker.to_bytes().to_vec(),
                })
                .collect(),
        },
        None => GetEdgesByOwnerResponse {
            snapshot: None,
            edges: Vec::new(),
        },
    }
}

fn latest_block_response(latest: Option<LatestBlock>) -> GetLatestBlockResponse {
    GetLatestBlockResponse {
        latest: latest.map(latest_block_to_proto),
    }
}

fn finalized_block_query_from_proto(
    request: pb::GetFinalizedBlockRequest,
) -> Result<FinalizedBlockQuery, WireStatus> {
    match request.query {
        Some(pb::get_finalized_block_request::Query::Height(height)) => {
            Ok(FinalizedBlockQuery::Height(height))
        }
        Some(pb::get_finalized_block_request::Query::Payload(payload)) => Ok(
            FinalizedBlockQuery::Payload(digest_from_bytes(payload, "payload")?),
        ),
        None => Ok(FinalizedBlockQuery::Latest),
    }
}

fn finalized_block_response(block: Option<FinalizedBlock>) -> GetFinalizedBlockResponse {
    GetFinalizedBlockResponse {
        block: block.map(finalized_block_to_proto),
    }
}

fn finalized_block_to_proto(block: FinalizedBlock) -> ProtoFinalizedBlock {
    ProtoFinalizedBlock {
        snapshot: Some(latest_block_to_proto(block.snapshot)),
        block: block.block,
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

fn unix_time_ms() -> u64 {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    u64::try_from(millis).unwrap_or(u64::MAX)
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
        // The validator is the first observer in the transport path. Relays
        // may append later observations, preserving this source timestamp.
        relay_timestamps: vec![unix_time_ms()],
        edge_colo: String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Mempool, OwnerCoins, light_client::QueryError};
    use hellas_kernel::Encode as _;
    use hellas_kernel::test_support::valid_open_tx;
    use std::time::Duration;

    #[derive(Clone, Default)]
    struct MempoolClient {
        mempool: Mempool,
        edge_result: Option<Result<Option<EdgeLookup>, QueryError>>,
        owner_edges_result: Option<Result<Option<OwnerEdges>, QueryError>>,
        snapshot_result: Option<WorkChannelSnapshot>,
    }

    impl FinalizedWorkView for MempoolClient {
        async fn work_channel_snapshot(
            &self,
            _query: WorkChannelQuery,
        ) -> Result<Option<WorkChannelSnapshot>, QueryError> {
            Ok(self.snapshot_result.clone())
        }
    }

    impl LightClientApi for MempoolClient {
        async fn get_state_root(&self) -> Result<Option<Digest>, QueryError> {
            panic!("unused test method")
        }

        async fn get_proof(&self, _object_id: ObjectId) -> Result<Option<Vec<u8>>, QueryError> {
            panic!("unused test method")
        }

        async fn get_coin(
            &self,
            _payload: Digest,
            _object_id: ObjectId,
        ) -> Result<Option<Coin>, QueryError> {
            panic!("unused test method")
        }

        async fn get_edge(
            &self,
            _payload: Digest,
            _object_id: ObjectId,
        ) -> Result<Option<EdgeLookup>, QueryError> {
            self.edge_result.clone().unwrap_or(Ok(None))
        }

        async fn get_finalization(&self, _payload: Digest) -> Result<Option<Vec<u8>>, QueryError> {
            panic!("unused test method")
        }

        async fn get_latest_block(&self) -> Result<Option<LatestBlock>, QueryError> {
            panic!("unused test method")
        }

        async fn get_finalized_block(
            &self,
            _query: FinalizedBlockQuery,
        ) -> Result<Option<FinalizedBlock>, QueryError> {
            panic!("unused test method")
        }

        async fn submit_tx(&self, tx: Transaction) -> Result<SubmitTxOutcome, QueryError> {
            Ok(self.mempool.submit(tx).await)
        }

        async fn get_validators(&self) -> Result<Vec<String>, QueryError> {
            Ok(vec!["validator-a".to_string()])
        }

        async fn get_consensus_info(&self) -> Result<ConsensusInfo, QueryError> {
            panic!("unused test method")
        }

        async fn get_coins_by_owner(
            &self,
            _owner: SettlementKey,
        ) -> Result<Option<OwnerCoins>, QueryError> {
            panic!("unused test method")
        }

        async fn get_edges_by_owner(
            &self,
            _owner: SettlementKey,
        ) -> Result<Option<OwnerEdges>, QueryError> {
            self.owner_edges_result.clone().unwrap_or(Ok(None))
        }
    }

    fn kernel_request(bytes: Vec<u8>) -> pb::SubmitTxRequest {
        pb::SubmitTxRequest {
            tx: Some(submit_tx_request::Tx::KernelTx(bytes)),
        }
    }

    /// The endpoint's two boundary answers: an argument that is not an
    /// edge id, and a node with no finalized state to answer from.
    ///
    /// Absence is reported as an absent snapshot rather than an empty
    /// one, because an empty snapshot would read as "this channel does
    /// not exist" — a different fact, and the one that would let an
    /// endpoint conclude a live lease was gone.
    #[tokio::test]
    async fn work_channel_snapshot_endpoint_separates_a_bad_argument_from_no_state() {
        let rpc = LightClientRpc::new(MempoolClient::default(), broadcast::channel(4).0);
        let ok = EdgeId::from_bytes([0x11; EdgeId::LENGTH])
            .to_bytes()
            .to_vec();

        let short = LightClientHandler::get_work_channel_snapshot(
            &rpc,
            pb::GetWorkChannelSnapshotRequest {
                bond_edge: ok[..EdgeId::LENGTH - 1].to_vec(),
                payment_edge: ok.clone(),
                funding_coins: Vec::new(),
            },
        )
        .await
        .expect_err("a 31-byte edge id is not an edge id");
        assert_eq!(short.code(), WireCode::InvalidArgument);

        let absent = LightClientHandler::get_work_channel_snapshot(
            &rpc,
            pb::GetWorkChannelSnapshotRequest {
                bond_edge: ok.clone(),
                payment_edge: ok,
                funding_coins: Vec::new(),
            },
        )
        .await
        .expect("an absent snapshot is an answer");
        assert!(absent.snapshot.is_none());
        assert!(absent.lease_slots.is_empty());
        assert!(absent.pending_slot.is_none());
    }

    #[tokio::test]
    async fn kernel_submit_boundary_accepts_only_exact_bounded_canonical_bytes() {
        let client = MempoolClient::default();
        let mempool = client.mempool.clone();
        let (activity_tx, _activity_rx) = broadcast::channel(1);
        let rpc = LightClientRpc::new(client, activity_tx);
        let tx = valid_open_tx().expect("valid kernel open fixture");
        let mut canonical = vec![0; KernelTx::MAX_ENCODED_SIZE];
        let encoded_len = tx.write_to(&mut canonical);
        canonical.truncate(encoded_len);

        let response = LightClientHandler::submit_tx(&rpc, kernel_request(canonical.clone()))
            .await
            .expect("canonical kernel transaction is accepted");
        assert_eq!(response.outcome, ProtoSubmitTxOutcome::Enqueued as i32);
        let pending = mempool.snapshot().await;
        assert_eq!(pending.len(), 1);
        let Transaction::Kernel(pending_tx) = &pending[0] else {
            panic!("pending transaction was not a kernel transaction")
        };
        assert_eq!(pending_tx, &tx);

        let mut trailing = canonical;
        trailing.push(0);
        for invalid in [
            vec![0xff],
            trailing,
            vec![0; KernelTx::MAX_ENCODED_SIZE + 1],
        ] {
            let error = LightClientHandler::submit_tx(&rpc, kernel_request(invalid))
                .await
                .expect_err("invalid kernel transaction is rejected");
            assert_eq!(error.code(), WireCode::InvalidArgument);
        }
        assert_eq!(mempool.snapshot().await.len(), 1);
    }

    #[tokio::test]
    async fn round2_full_is_observable() {
        use crate::execution::test_support::kernel_fixture_at;

        let client = MempoolClient::default();
        let mut first = None;
        for index in 0..crate::GENERAL_MEMPOOL_CAPACITY {
            let fixture = kernel_fixture_at(10, (index * 2) as u16, 7, 8)
                .expect("distinct valid kernel fixture");
            let tx = Transaction::Kernel(fixture.open);
            first.get_or_insert_with(|| tx.clone());
            assert_eq!(client.mempool.submit(tx).await, SubmitTxOutcome::Enqueued);
        }
        assert_eq!(
            client
                .mempool
                .submit(first.expect("the capacity is non-zero"))
                .await,
            SubmitTxOutcome::Duplicate,
            "a resident digest stays duplicate even when the mempool is full",
        );

        let (activity_tx, _activity_rx) = broadcast::channel(1);
        let rpc = LightClientRpc::new(client, activity_tx);
        let fixture = kernel_fixture_at(10, 400, 7, 8).expect("overflow fixture");
        let mut canonical = vec![0; KernelTx::MAX_ENCODED_SIZE];
        let encoded_len = fixture.open.write_to(&mut canonical);
        canonical.truncate(encoded_len);

        let response = LightClientHandler::submit_tx(&rpc, kernel_request(canonical))
            .await
            .expect("a full mempool is an observable submission outcome");
        assert_eq!(response.outcome, ProtoSubmitTxOutcome::Full as i32);
    }

    #[cfg(feature = "client")]
    #[tokio::test]
    async fn activity_stream_does_not_block_unary_requests() {
        use crate::{LightClient as _, client::RemoteLightClient};

        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = probe.local_addr().unwrap();
        drop(probe);

        let (activity_tx, _activity_rx) = broadcast::channel(8);
        let server = spawn_light_client_server(addr, MempoolClient::default(), activity_tx)
            .await
            .unwrap();
        let client = RemoteLightClient::connect(format!("ws://{addr}"))
            .await
            .unwrap();
        let _activity = client.subscribe_activity(Vec::new()).await.unwrap();

        let validators = tokio::time::timeout(Duration::from_secs(1), client.get_validators())
            .await
            .expect("unary request was blocked behind activity stream")
            .unwrap();
        assert_eq!(validators, ["validator-a"]);

        server.abort();
    }

    #[tokio::test]
    async fn get_edge_endpoint_preserves_full_state_root_absence_and_wrong_kind() {
        let open = valid_open_tx().expect("valid kernel open fixture");
        let KernelTx::Open { terms, .. } = open else {
            panic!("fixture must be an open")
        };
        let parties = terms.parties();
        let state_root = Digest::from([0x31; 32]);
        let edge = EdgeState {
            value: 101,
            reserve: 9,
            close_fees: hellas_kernel::Fees::new(1, 2, 3, 4),
            timeout: hellas_kernel::BlockHeight::new(55),
            maker: SettlementKey::from(parties.maker()),
            taker: SettlementKey::from(parties.taker()),
            terms_hash: terms.hash(),
        };
        let (activity_tx, _activity_rx) = broadcast::channel(1);
        let found_rpc = LightClientRpc::new(
            MempoolClient {
                edge_result: Some(Ok(Some(EdgeLookup {
                    state_root,
                    edge: Some(edge),
                }))),
                ..MempoolClient::default()
            },
            activity_tx.clone(),
        );
        let request = pb::GetEdgeRequest {
            payload: vec![0x11; 32],
            object_id: vec![0x22; 32],
        };
        let response = LightClientHandler::get_edge(&found_rpc, request.clone())
            .await
            .expect("edge response");
        assert_eq!(response.state_root, Some(state_root.to_vec()));
        let response_edge = response.edge.expect("full edge state");
        assert_eq!(response_edge.value, edge.value);
        assert_eq!(response_edge.reserve, edge.reserve);
        assert_eq!(response_edge.timeout, edge.timeout.get());
        assert_eq!(response_edge.maker, edge.maker.to_bytes());
        assert_eq!(response_edge.taker, edge.taker.to_bytes());
        assert_eq!(response_edge.terms_hash, edge.terms_hash.to_bytes());
        assert_eq!(
            response_edge.close_fees,
            Some(KernelFees {
                base: 1,
                slot: 2,
                proof: 3,
                lifetime: 4,
            })
        );

        let absent_rpc = LightClientRpc::new(MempoolClient::default(), activity_tx.clone());
        let absent = LightClientHandler::get_edge(&absent_rpc, request.clone())
            .await
            .expect("absent edge response");
        assert_eq!(absent.edge, None);
        assert_eq!(absent.state_root, None);

        let wrong_kind_rpc = LightClientRpc::new(
            MempoolClient {
                edge_result: Some(Err(QueryError::WrongObjectKind {
                    expected: crate::domain::ObjectKind::Edge,
                    actual: crate::domain::ObjectKind::Coin,
                })),
                ..MempoolClient::default()
            },
            activity_tx,
        );
        let error = LightClientHandler::get_edge(&wrong_kind_rpc, request)
            .await
            .expect_err("coin in edge slot is typed");
        assert!(matches!(
            QueryError::from(error),
            QueryError::WrongObjectKind {
                expected: crate::domain::ObjectKind::Edge,
                actual: crate::domain::ObjectKind::Coin,
            }
        ));
    }

    #[cfg(feature = "validator")]
    #[tokio::test]
    async fn get_edges_by_owner_endpoint_tracks_open_close_and_empty_owner() {
        use crate::execution::test_support::{index_block, index_genesis, kernel_fixture};
        use crate::owner_index::ApplyOutcome;
        use commonware_cryptography::Digestible as _;

        fn response_from_index(
            index: &crate::OwnerIndex,
            owner: SettlementKey,
            finalization: Vec<u8>,
        ) -> OwnerEdges {
            let (cursor, edges) = index.get_edges_by_owner_snapshot(&owner);
            OwnerEdges {
                snapshot: LatestBlock {
                    height: cursor.height,
                    payload: cursor.payload,
                    state_root: cursor.state_root,
                    finalization,
                },
                edges: edges
                    .into_iter()
                    .map(|(object_id, edge)| crate::EdgeRecord {
                        object_id,
                        maker: edge.maker,
                        taker: edge.taker,
                    })
                    .collect(),
            }
        }

        fn rpc_with_owner_edges(owner_edges: OwnerEdges) -> LightClientRpc<MempoolClient> {
            let (activity_tx, _activity_rx) = broadcast::channel(1);
            LightClientRpc::new(
                MempoolClient {
                    owner_edges_result: Some(Ok(Some(owner_edges))),
                    ..MempoolClient::default()
                },
                activity_tx,
            )
        }

        let genesis = index_genesis();
        let fixture = kernel_fixture(10).expect("kernel fixture");
        let index = crate::OwnerIndex::new(
            crate::domain::TEST_NETWORK,
            &genesis,
            fixture.allocations.clone(),
        );
        let finalization = vec![0xfa, 0xce];
        let request = pb::GetEdgesByOwnerRequest {
            owner: fixture.maker.to_bytes().to_vec(),
        };

        let open_block = index_block(
            &genesis,
            Digest::from([0x41; 32]),
            vec![Transaction::Kernel(fixture.open.clone())],
        );
        assert_eq!(
            index.apply_finalized(&open_block),
            Ok(ApplyOutcome::Applied)
        );
        let open_rpc = rpc_with_owner_edges(response_from_index(
            &index,
            fixture.maker,
            finalization.clone(),
        ));
        let open_response = LightClientHandler::get_edges_by_owner(&open_rpc, request.clone())
            .await
            .expect("open owner listing");
        let open_snapshot = open_response.snapshot.expect("indexed snapshot");
        assert_eq!(open_snapshot.finalization, finalization);
        assert_eq!(open_snapshot.payload, open_block.digest().to_vec());
        assert!(matches!(
            open_response.edges.as_slice(),
            [edge] if edge.object_id == crate::domain::edge_object_id(fixture.edge).to_vec()
                && edge.maker == fixture.maker.to_bytes()
        ));

        let empty_owner = SettlementKey::from_bytes([0x99; SettlementKey::LENGTH]);
        let empty_rpc = rpc_with_owner_edges(response_from_index(
            &index,
            empty_owner,
            finalization.clone(),
        ));
        let empty_response = LightClientHandler::get_edges_by_owner(
            &empty_rpc,
            pb::GetEdgesByOwnerRequest {
                owner: empty_owner.to_bytes().to_vec(),
            },
        )
        .await
        .expect("empty owner listing");
        assert!(empty_response.snapshot.is_some());
        assert!(empty_response.edges.is_empty());

        let close_block = index_block(
            &open_block,
            Digest::from([0x42; 32]),
            vec![Transaction::Kernel(fixture.mutual_close)],
        );
        assert_eq!(
            index.apply_finalized(&close_block),
            Ok(ApplyOutcome::Applied)
        );
        let close_rpc =
            rpc_with_owner_edges(response_from_index(&index, fixture.maker, finalization));
        let close_response = LightClientHandler::get_edges_by_owner(&close_rpc, request)
            .await
            .expect("closed owner listing");
        let close_snapshot = close_response.snapshot.expect("indexed snapshot");
        assert_eq!(close_snapshot.finalization, vec![0xfa, 0xce]);
        assert_eq!(close_snapshot.payload, close_block.digest().to_vec());
        assert!(close_response.edges.is_empty());
    }

    #[test]
    fn owner_query_accepts_raw_non_p256_settlement_key() {
        let raw = vec![0xa5; SettlementKey::LENGTH];
        let key = settlement_key_from_bytes(raw.clone(), "owner").expect("raw settlement key");
        assert_eq!(key.as_bytes().as_slice(), raw.as_slice());
        assert!(Address::try_from(key).is_err());
    }

    #[test]
    fn owner_query_rejects_wrong_settlement_key_length() {
        let err = settlement_key_from_bytes(vec![0; SettlementKey::LENGTH - 1], "owner")
            .expect_err("short settlement key");
        assert_eq!(err.code(), WireCode::InvalidArgument);
    }

    #[test]
    fn activity_event_contains_validator_observation_timestamp() {
        let before = unix_time_ms();
        let event = activity_to_proto(ConsensusActivity::Nullify {
            epoch: 1,
            view: 2,
            signer: 3,
            signature: vec![4],
        });
        let after = unix_time_ms();

        assert_eq!(event.relay_timestamps.len(), 1);
        assert!((before..=after).contains(&event.relay_timestamps[0]));
    }
}
