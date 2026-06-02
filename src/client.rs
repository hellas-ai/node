#[cfg(not(target_arch = "wasm32"))]
use crate::methods::{LIGHT_CLIENT_METHODS, METHOD_SUBSCRIBE_ACTIVITY};
#[cfg(not(target_arch = "wasm32"))]
use crate::pb::hellas::light_client_client::LightClientClient;
#[cfg(not(target_arch = "wasm32"))]
use crate::pb::hellas::*;
#[cfg(not(target_arch = "wasm32"))]
use crate::{LatestBlock, LightClient, QueryError};
#[cfg(not(target_arch = "wasm32"))]
use hellas_kernel::domain::{
    Address, Coin, DecodeExt, Digest, Encode, ObjectId, Transaction, UserPublicKey,
    WebAuthnSignature as DomainWebAuthnSignature,
};
#[cfg(not(target_arch = "wasm32"))]
use hellas_rpc::mux::MuxGrpcService;
use hellas_rpc::ws_mux;
#[cfg(not(target_arch = "wasm32"))]
use p256::ecdsa::Signature as P256Signature;

/// ws-mux backed light client that connects to a remote validator or mux relay.
#[derive(Clone)]
pub struct RemoteLightClient {
    #[cfg(not(target_arch = "wasm32"))]
    client: LightClientClient<MuxGrpcService>,
    #[cfg(not(target_arch = "wasm32"))]
    channel: ws_mux::MuxChannel,
}

impl RemoteLightClient {
    /// Create a client from a pre-built [`ws_mux::MuxChannel`].
    #[cfg(not(target_arch = "wasm32"))]
    pub fn new(channel: ws_mux::MuxChannel) -> Self {
        let svc = MuxGrpcService::new(channel.clone(), LIGHT_CLIENT_METHODS);
        Self {
            client: LightClientClient::new(svc),
            channel,
        }
    }

    /// wasm builds don't expose the native tonic-backed client API.
    #[cfg(target_arch = "wasm32")]
    pub fn new(_channel: ws_mux::MuxChannel) -> Self {
        Self {}
    }

    /// Connect to a ws-mux endpoint over WebSocket.
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn connect(addr: impl Into<String>) -> Result<Self, QueryError> {
        let channel = ws_mux::MuxChannel::connect(&addr.into())
            .await
            .map_err(|e| QueryError::Connect(e.to_string()))?;
        Ok(Self::new(channel))
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl LightClient for RemoteLightClient {
    fn get_state_root(&self) -> impl Future<Output = Result<Option<Digest>, QueryError>> + Send {
        let mut client = self.client.clone();
        async move {
            let response = client
                .get_state_root(GetStateRootRequest {})
                .await
                .map_err(QueryError::from)?
                .into_inner();
            match response.state_root {
                Some(bytes) => {
                    let arr: [u8; 32] = bytes.try_into().map_err(|_| {
                        QueryError::Remote("state_root was not 32 bytes".to_string())
                    })?;
                    Ok(Some(Digest::from(arr)))
                }
                None => Ok(None),
            }
        }
    }

    fn get_proof(
        &self,
        object_id: ObjectId,
    ) -> impl Future<Output = Result<Option<Vec<u8>>, QueryError>> + Send {
        let mut client = self.client.clone();
        async move {
            let response = client
                .get_proof(GetProofRequest {
                    object_id: object_id.to_vec(),
                })
                .await
                .map_err(QueryError::from)?
                .into_inner();
            Ok(response.proof)
        }
    }

    fn get_coin(
        &self,
        payload: Digest,
        object_id: ObjectId,
    ) -> impl Future<Output = Result<Option<Coin>, QueryError>> + Send {
        let mut client = self.client.clone();
        async move {
            let response = client
                .get_coin(GetCoinRequest {
                    payload: payload.to_vec(),
                    object_id: object_id.to_vec(),
                })
                .await
                .map_err(QueryError::from)?
                .into_inner();
            match (response.owner, response.value) {
                (Some(owner_bytes), Some(value)) => {
                    let pk = UserPublicKey::decode(owner_bytes.as_slice())
                        .map_err(|_| QueryError::Remote("invalid owner key".to_string()))?;
                    Ok(Some(Coin {
                        owner: Address::from(pk),
                        value,
                    }))
                }
                _ => Ok(None),
            }
        }
    }

    fn get_finalization(
        &self,
        payload: Digest,
    ) -> impl Future<Output = Result<Option<Vec<u8>>, QueryError>> + Send {
        let mut client = self.client.clone();
        async move {
            let response = client
                .get_finalization(GetFinalizationRequest {
                    payload: payload.to_vec(),
                })
                .await
                .map_err(QueryError::from)?
                .into_inner();
            Ok(response.certificate)
        }
    }

    fn get_latest_block(
        &self,
    ) -> impl Future<Output = Result<Option<LatestBlock>, QueryError>> + Send {
        let mut client = self.client.clone();
        async move {
            let response = client
                .get_latest_block(GetLatestBlockRequest {})
                .await
                .map_err(QueryError::from)?
                .into_inner();
            let (height, payload_bytes, root_bytes) =
                match (response.height, response.payload, response.state_root) {
                    (None, None, None) => return Ok(None),
                    (Some(h), Some(p), Some(r)) => (h, p, r),
                    _ => {
                        return Err(QueryError::Remote(
                            "partial GetLatestBlockResponse: expected all or no fields".to_string(),
                        ));
                    }
                };
            let payload: [u8; 32] = payload_bytes
                .try_into()
                .map_err(|_| QueryError::Remote("payload was not 32 bytes".to_string()))?;
            let state_root: [u8; 32] = root_bytes
                .try_into()
                .map_err(|_| QueryError::Remote("state_root was not 32 bytes".to_string()))?;
            Ok(Some(LatestBlock {
                height,
                payload: Digest::from(payload),
                state_root: Digest::from(state_root),
            }))
        }
    }

    fn submit_tx(&self, tx: Transaction) -> impl Future<Output = Result<(), QueryError>> + Send {
        let mut client = self.client.clone();
        async move {
            let req = transaction_to_proto(tx);
            client.submit_tx(req).await.map_err(QueryError::from)?;
            Ok(())
        }
    }

    fn get_validators(&self) -> impl Future<Output = Result<Vec<String>, QueryError>> + Send {
        let mut client = self.client.clone();
        async move {
            let resp = client
                .get_validators(GetValidatorsRequest {})
                .await
                .map_err(QueryError::from)?
                .into_inner();
            Ok(resp.validators)
        }
    }

    fn get_coins_by_owner(
        &self,
        owner: Address,
    ) -> impl Future<Output = Result<Vec<(ObjectId, u64)>, QueryError>> + Send {
        let mut client = self.client.clone();
        async move {
            let resp = client
                .get_coins_by_owner(GetCoinsByOwnerRequest {
                    owner: owner.public_key().encode().to_vec(),
                })
                .await
                .map_err(QueryError::from)?
                .into_inner();
            let coins = resp
                .coins
                .into_iter()
                .map(|entry| {
                    let arr: [u8; 32] = entry.object_id.try_into().map_err(|_| {
                        QueryError::Remote("object_id was not 32 bytes".to_string())
                    })?;
                    Ok((Digest::from(arr), entry.value))
                })
                .collect::<Result<Vec<_>, QueryError>>()?;
            Ok(coins)
        }
    }
}

impl RemoteLightClient {
    /// Subscribe to the consensus activity stream.
    ///
    /// Uses the underlying ws-mux channel directly since server-streaming
    /// RPCs bypass the tonic client for simplicity.
    /// `urgent_events` lists kinds the relay should forward immediately. Empty means every event is
    /// urgent.
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn subscribe_activity(
        &self,
        urgent_events: Vec<ActivityEventKind>,
    ) -> Result<ws_mux::Streaming, QueryError> {
        self.channel
            .server_streaming(
                METHOD_SUBSCRIBE_ACTIVITY,
                &SubscribeActivityRequest {
                    urgent_events: urgent_events.into_iter().map(|k| k as i32).collect(),
                },
            )
            .await
            .map_err(|e| QueryError::Remote(e.to_string()))
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn transaction_to_proto(tx: Transaction) -> SubmitTxRequest {
    let signature_to_der = |signature: &DomainWebAuthnSignature| {
        let raw = signature.signature.encode();
        let parsed = P256Signature::from_slice(raw.as_ref())
            .expect("internal transaction signature should always be canonical 64-byte secp256r1");
        parsed.to_der().as_bytes().to_vec()
    };

    let tx_oneof = match tx {
        Transaction::Transfer {
            input,
            recipient,
            amount,
            signature,
        } => submit_tx_request::Tx::Transfer(TransferTx {
            input: input.to_vec(),
            recipient: recipient.encode().to_vec(),
            amount,
            signature: Some(WebAuthnSignature {
                ecdsa_signature: signature_to_der(&signature),
                authenticator_data: signature.authenticator_data.as_slice().to_vec(),
                client_data_json: signature.client_data_json.as_slice().to_vec(),
            }),
        }),
        Transaction::MergeCoin { inputs, signature } => {
            submit_tx_request::Tx::MergeCoin(MergeCoinTx {
                inputs: inputs.iter().map(|i| i.to_vec()).collect(),
                signature: Some(WebAuthnSignature {
                    ecdsa_signature: signature_to_der(&signature),
                    authenticator_data: signature.authenticator_data.as_slice().to_vec(),
                    client_data_json: signature.client_data_json.as_slice().to_vec(),
                }),
            })
        }
    };
    SubmitTxRequest { tx: Some(tx_oneof) }
}
