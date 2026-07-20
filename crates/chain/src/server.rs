use crate::domain::Bounded;
use crate::domain::{
    Address, Coin, DecodeExt, Digest, MAX_MERGE_INPUTS, ObjectId, SettlementKey, Transaction,
    UserPublicKey, UserSignature, WebAuthnSignature,
};
use crate::{
    ConsensusActivity, ConsensusInfo, FinalizedBlock, FinalizedBlockQuery, LatestBlock,
    LightClient as LightClientApi, ProposalInfo,
};
use futures_util::{Stream, StreamExt as _};
use hellas_rpc::pb::{
    chain::{
        self as pb, ActivityEvent, CoinEntry, FinalizationEvent,
        FinalizedBlock as ProtoFinalizedBlock, FinalizedSnapshot, GetCoinResponse,
        GetCoinsByOwnerResponse, GetConsensusInfoResponse, GetFinalizationResponse,
        GetFinalizedBlockResponse, GetLatestBlockResponse, GetProofResponse, GetRelayInfoResponse,
        GetStateRootResponse, GetValidatorsResponse, MergeCoinTx, NotarizationEvent, NotarizeEvent,
        NullificationEvent, NullifyEvent, SubmitTxResponse, TransferTx,
        WebAuthnSignature as ProtoWebAuthnSignature, activity_event, submit_tx_request,
    },
    services::light_client::{LightClientHandler, LightClientServer},
};
use hellas_wire::{Dispatcher, StreamTransport, WireCode, WireStatus, mux::MuxTransport};
use p256::ecdsa::Signature as P256Signature;
use std::{io, net::SocketAddr, pin::Pin};
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
type ServerError = Box<dyn std::error::Error + Send + Sync + 'static>;

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
) -> Result<(), ServerError>
where
    T: LightClientApi,
{
    let ws = accept_async(stream).await?;
    let transport = hellas_wire::ws::accept_upgraded(ws, None);
    let dispatch = LightClientServer(service);
    while let Some(inbound) = transport.accept().await? {
        <LightClientServer<LightClientRpc<T>> as Dispatcher<MuxTransport>>::dispatch(
            &dispatch, inbound,
        )
        .await?;
    }
    Ok(())
}

#[allow(refining_impl_trait)]
impl<T> LightClientHandler for LightClientRpc<T>
where
    T: LightClientApi,
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
            client.submit_tx(tx).await.map_err(WireStatus::from)?;
            Ok(SubmitTxResponse {})
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
    let normalized = signature.normalize_s().unwrap_or(signature);
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

fn transaction_from_proto(request: pb::SubmitTxRequest) -> Result<Transaction, WireStatus> {
    match request
        .tx
        .ok_or_else(|| WireStatus::new(WireCode::InvalidArgument, "missing transaction"))?
    {
        submit_tx_request::Tx::Transfer(tx) => transfer_from_proto(tx),
        submit_tx_request::Tx::MergeCoin(tx) => merge_from_proto(tx),
    }
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

fn latest_block_response(latest: Option<LatestBlock>) -> GetLatestBlockResponse {
    GetLatestBlockResponse {
        latest: latest.map(latest_block_to_proto),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
