//! Local implementation of the light-client query interface.
//!
//! [`LocalLightClient`] wraps the local database/mempool handles and implements the
//! [`LightClient`] trait from `hellas_types::rpc`.

use crate::{
    app::{MarshalMailbox, Mempool},
    execution::store::{UtxoDatabase, get as utxo_get, root as utxo_root},
};
use commonware_consensus::{Heightable, marshal::Identifier as MarshalIdentifier};
use commonware_cryptography::{Digestible, sha256::Digest};
use hellas_rpc::pb::hellas::light_client_server::{self, LightClientServer};
use hellas_rpc::pb::hellas::*;
use hellas_types::rpc::{
    ConsensusActivity, LatestBlock, LightClient, ProposalInfo as TypesProposalInfo, QueryError,
};
use hellas_types::{
    Coin, DecodeExt, Encode, MAX_AUTHENTICATOR_DATA_LEN, MAX_CLIENT_DATA_JSON_LEN,
    MAX_MERGE_INPUTS, MIN_AUTHENTICATOR_DATA_LEN, ObjectId, Transaction, UserPublicKey,
    UserSignature, WebAuthnSignature,
};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::broadcast;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::BroadcastStream;

/// In-process [`LightClient`] backed by the local application handle.
#[derive(Clone)]
pub struct LocalLightClient {
    databases: UtxoDatabase<commonware_runtime::tokio::Context>,
    mempool: Mempool,
    marshal: MarshalMailbox,
    validators: Vec<String>,
}

impl LocalLightClient {
    pub fn new(
        databases: UtxoDatabase<commonware_runtime::tokio::Context>,
        mempool: Mempool,
        marshal: MarshalMailbox,
        validators: Vec<String>,
    ) -> Self {
        Self {
            databases,
            mempool,
            marshal,
            validators,
        }
    }
}

impl LightClient for LocalLightClient {
    async fn get_state_root(&self) -> Result<Option<Digest>, QueryError> {
        Ok(Some(utxo_root(&self.databases).await))
    }

    async fn get_proof(&self, object_id: ObjectId) -> Result<Option<Vec<u8>>, QueryError> {
        let _ = object_id;
        Err(QueryError::StateUnavailable(
            "key proofs are disabled in the glue cutover".to_string(),
        ))
    }

    async fn get_coin(
        &self,
        payload: Digest,
        object_id: ObjectId,
    ) -> Result<Option<Coin>, QueryError> {
        let latest = self.get_latest_block().await?;
        let Some(latest) = latest else {
            return Ok(None);
        };
        if latest.payload != payload {
            return Err(QueryError::StateUnavailable(
                "coin queries only support the latest payload".to_string(),
            ));
        }
        Ok(utxo_get(&self.databases, &object_id).await)
    }

    async fn get_finalization(&self, payload: Digest) -> Result<Option<Vec<u8>>, QueryError> {
        let Some((height, _)) = self.marshal.get_info(&payload).await else {
            return Ok(None);
        };
        Ok(self
            .marshal
            .get_finalization(height)
            .await
            .map(|finalization| finalization.encode().to_vec()))
    }

    async fn get_latest_block(&self) -> Result<Option<LatestBlock>, QueryError> {
        let block = self.marshal.get_block(MarshalIdentifier::Latest).await;
        Ok(block.map(|block| LatestBlock {
            height: block.height().get(),
            payload: block.digest(),
            state_root: block.state_root(),
        }))
    }

    async fn submit_tx(&self, tx: Transaction) -> Result<(), QueryError> {
        self.mempool.submit(tx).await;
        Ok(())
    }

    async fn get_validators(&self) -> Result<Vec<String>, QueryError> {
        Ok(self.validators.clone())
    }

    async fn get_coins_by_owner(
        &self,
        owner: hellas_types::Address,
    ) -> Result<Vec<(ObjectId, u64)>, QueryError> {
        let _ = owner;
        Err(QueryError::StateUnavailable(
            "owner scans are disabled in the glue cutover".to_string(),
        ))
    }
}

/// gRPC server that wraps a local [`LightClient`] implementation.
pub struct LightClientGrpcServer<L> {
    inner: L,
    activity_tx: broadcast::Sender<ConsensusActivity>,
}

impl<L: LightClient> LightClientGrpcServer<L> {
    pub fn new(inner: L, activity_tx: broadcast::Sender<ConsensusActivity>) -> Self {
        Self { inner, activity_tx }
    }

    /// Convert into a tonic service ready to be added to a `Server`.
    pub fn into_service(self) -> LightClientServer<Self> {
        LightClientServer::new(self)
    }
}

#[tonic::async_trait]
impl<L: LightClient> light_client_server::LightClient for LightClientGrpcServer<L> {
    async fn get_state_root(
        &self,
        _request: tonic::Request<GetStateRootRequest>,
    ) -> Result<tonic::Response<GetStateRootResponse>, tonic::Status> {
        let result = self.inner.get_state_root().await?;
        Ok(tonic::Response::new(GetStateRootResponse {
            state_root: result.map(|d| d.to_vec()),
        }))
    }

    async fn get_proof(
        &self,
        request: tonic::Request<GetProofRequest>,
    ) -> Result<tonic::Response<GetProofResponse>, tonic::Status> {
        let req = request.into_inner();
        let object_id = parse_digest(&req.object_id, "object_id")?;
        let result = self.inner.get_proof(object_id).await?;
        Ok(tonic::Response::new(GetProofResponse { proof: result }))
    }

    async fn get_coin(
        &self,
        request: tonic::Request<GetCoinRequest>,
    ) -> Result<tonic::Response<GetCoinResponse>, tonic::Status> {
        let req = request.into_inner();
        let payload = parse_digest(&req.payload, "payload")?;
        let object_id = parse_digest(&req.object_id, "object_id")?;
        let result = self.inner.get_coin(payload, object_id).await?;
        match result {
            Some(coin) => Ok(tonic::Response::new(GetCoinResponse {
                owner: Some(coin.owner.public_key().encode().to_vec()),
                value: Some(coin.value),
            })),
            None => Ok(tonic::Response::new(GetCoinResponse {
                owner: None,
                value: None,
            })),
        }
    }

    async fn get_finalization(
        &self,
        request: tonic::Request<GetFinalizationRequest>,
    ) -> Result<tonic::Response<GetFinalizationResponse>, tonic::Status> {
        let req = request.into_inner();
        let payload = parse_digest(&req.payload, "payload")?;
        let result = self.inner.get_finalization(payload).await?;
        Ok(tonic::Response::new(GetFinalizationResponse {
            certificate: result,
        }))
    }

    async fn get_latest_block(
        &self,
        _request: tonic::Request<GetLatestBlockRequest>,
    ) -> Result<tonic::Response<GetLatestBlockResponse>, tonic::Status> {
        let result = self.inner.get_latest_block().await?;
        let (height, payload, state_root) = match result {
            Some(LatestBlock {
                height,
                payload,
                state_root,
            }) => (
                Some(height),
                Some(payload.to_vec()),
                Some(state_root.to_vec()),
            ),
            None => (None, None, None),
        };
        Ok(tonic::Response::new(GetLatestBlockResponse {
            height,
            payload,
            state_root,
        }))
    }

    async fn submit_tx(
        &self,
        request: tonic::Request<SubmitTxRequest>,
    ) -> Result<tonic::Response<SubmitTxResponse>, tonic::Status> {
        let tx = parse_transaction(request.into_inner())?;
        self.inner.submit_tx(tx).await?;
        Ok(tonic::Response::new(SubmitTxResponse {}))
    }

    type SubscribeActivityStream = std::pin::Pin<
        Box<dyn tokio_stream::Stream<Item = Result<ActivityEvent, tonic::Status>> + Send + 'static>,
    >;

    async fn subscribe_activity(
        &self,
        _request: tonic::Request<SubscribeActivityRequest>,
    ) -> Result<tonic::Response<Self::SubscribeActivityStream>, tonic::Status> {
        let rx = self.activity_tx.subscribe();
        let stream = BroadcastStream::new(rx).filter_map(|result| match result {
            Ok(activity) => Some(Ok(consensus_activity_to_proto(activity))),
            Err(_) => None,
        });
        Ok(tonic::Response::new(Box::pin(stream)))
    }

    async fn get_validators(
        &self,
        _request: tonic::Request<GetValidatorsRequest>,
    ) -> Result<tonic::Response<GetValidatorsResponse>, tonic::Status> {
        let validators = self.inner.get_validators().await?;
        Ok(tonic::Response::new(GetValidatorsResponse { validators }))
    }

    async fn get_relay_info(
        &self,
        _request: tonic::Request<GetRelayInfoRequest>,
    ) -> Result<tonic::Response<GetRelayInfoResponse>, tonic::Status> {
        // Relay info is only meaningful when served by the relay.
        // Validators return their own node-rpc version as a fallback.
        Ok(tonic::Response::new(GetRelayInfoResponse {
            relay_version: String::new(),
            relay_rev: String::new(),
            node_rpc_version: hellas_rpc::VERSION.into(),
            node_rpc_rev: hellas_rpc::GIT_REV.into(),
        }))
    }

    async fn get_coins_by_owner(
        &self,
        request: tonic::Request<GetCoinsByOwnerRequest>,
    ) -> Result<tonic::Response<GetCoinsByOwnerResponse>, tonic::Status> {
        let req = request.into_inner();
        let address = parse_address(&req.owner, "owner")?;
        let coins = self.inner.get_coins_by_owner(address).await?;
        let entries = coins
            .into_iter()
            .map(|(object_id, value)| CoinEntry {
                object_id: object_id.to_vec(),
                value,
            })
            .collect();
        Ok(tonic::Response::new(GetCoinsByOwnerResponse {
            coins: entries,
        }))
    }
}

fn proposal_info_to_proto(p: TypesProposalInfo) -> ProposalInfo {
    ProposalInfo {
        epoch: p.epoch,
        view: p.view,
        parent_view: p.parent_view,
        parent_payload: p.parent_payload.to_vec(),
        payload: p.payload.to_vec(),
    }
}

pub fn consensus_activity_to_proto(activity: ConsensusActivity) -> ActivityEvent {
    let validator_ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0_u64, |d| d.as_millis() as u64);
    let event = match activity {
        ConsensusActivity::Notarize {
            proposal,
            signer,
            signature,
        } => activity_event::Event::Notarize(NotarizeEvent {
            proposal: Some(proposal_info_to_proto(proposal)),
            signer,
            signature,
        }),
        ConsensusActivity::Notarization {
            proposal,
            signers,
            certificate,
        } => activity_event::Event::Notarization(NotarizationEvent {
            proposal: Some(proposal_info_to_proto(proposal)),
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
            proposal: Some(proposal_info_to_proto(proposal)),
            signers,
            certificate,
        }),
    };
    ActivityEvent {
        event: Some(event),
        relay_timestamps: vec![validator_ts],
        edge_colo: String::new(),
    }
}

fn parse_digest(bytes: &[u8], field: &str) -> Result<Digest, tonic::Status> {
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| tonic::Status::invalid_argument(format!("{field} must be 32 bytes")))?;
    Ok(Digest::from(arr))
}

fn parse_address(bytes: &[u8], field: &str) -> Result<hellas_types::Address, tonic::Status> {
    let pk = UserPublicKey::decode(bytes).map_err(|_| {
        tonic::Status::invalid_argument(format!("{field} must be a valid secp256r1 public key"))
    })?;
    Ok(hellas_types::Address::from(pk))
}

fn parse_webauthn_signature(
    sig: Option<hellas_rpc::pb::hellas::WebAuthnSignature>,
    field: &str,
) -> Result<WebAuthnSignature, tonic::Status> {
    const MAX_DER_SIGNATURE_LEN: usize = 80;

    let sig = sig.ok_or_else(|| tonic::Status::invalid_argument(format!("{field} is required")))?;

    if sig.ecdsa_signature.is_empty() || sig.ecdsa_signature.len() > MAX_DER_SIGNATURE_LEN {
        return Err(tonic::Status::invalid_argument(format!(
            "{field}.ecdsa_signature must be DER-encoded and at most {MAX_DER_SIGNATURE_LEN} bytes"
        )));
    }

    if sig.authenticator_data.len() < MIN_AUTHENTICATOR_DATA_LEN
        || sig.authenticator_data.len() > MAX_AUTHENTICATOR_DATA_LEN
    {
        return Err(tonic::Status::invalid_argument(format!(
            "{field}.authenticator_data must be between {MIN_AUTHENTICATOR_DATA_LEN} and {MAX_AUTHENTICATOR_DATA_LEN} bytes"
        )));
    }

    if sig.client_data_json.is_empty() || sig.client_data_json.len() > MAX_CLIENT_DATA_JSON_LEN {
        return Err(tonic::Status::invalid_argument(format!(
            "{field}.client_data_json must be between 1 and {MAX_CLIENT_DATA_JSON_LEN} bytes"
        )));
    }

    let parsed = p256::ecdsa::Signature::from_der(&sig.ecdsa_signature).map_err(|_| {
        tonic::Status::invalid_argument(format!(
            "{field}.ecdsa_signature must be a valid DER-encoded ECDSA signature"
        ))
    })?;
    let normalized = parsed.normalize_s().unwrap_or(parsed);
    let canonical = UserSignature::decode(normalized.to_bytes().as_ref()).map_err(|_| {
        tonic::Status::invalid_argument(format!(
            "{field}.ecdsa_signature is not a valid canonical secp256r1 signature"
        ))
    })?;

    Ok(WebAuthnSignature {
        signature: canonical,
        authenticator_data: sig.authenticator_data,
        client_data_json: sig.client_data_json,
    })
}

pub fn parse_transaction(req: SubmitTxRequest) -> Result<Transaction, tonic::Status> {
    let tx_oneof = req
        .tx
        .ok_or_else(|| tonic::Status::invalid_argument("tx is required"))?;
    match tx_oneof {
        submit_tx_request::Tx::Transfer(t) => {
            let input = parse_digest(&t.input, "input")?;
            let recipient = parse_address(&t.recipient, "recipient")?;
            let signature = parse_webauthn_signature(t.signature, "signature")?;
            Ok(Transaction::Transfer {
                input,
                recipient,
                amount: t.amount,
                signature,
            })
        }
        submit_tx_request::Tx::MergeCoin(m) => {
            if m.inputs.len() > MAX_MERGE_INPUTS {
                return Err(tonic::Status::invalid_argument(format!(
                    "inputs must contain at most {MAX_MERGE_INPUTS} entries"
                )));
            }
            let inputs = m
                .inputs
                .iter()
                .enumerate()
                .map(|(i, b)| parse_digest(b, &format!("inputs[{i}]")))
                .collect::<Result<Vec<_>, _>>()?;
            let signature = parse_webauthn_signature(m.signature, "signature")?;
            Ok(Transaction::MergeCoin { inputs, signature })
        }
    }
}
