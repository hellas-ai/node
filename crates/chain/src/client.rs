use crate::{
    ConsensusInfo, ConsensusVerifier, FinalizedBlock, FinalizedBlockQuery, LatestBlock,
    LightClient, OwnerCoins, QueryError,
};
use commonware_cryptography::{Hasher, Sha256};
use hellas_kernel::domain::{
    Address, Coin, DecodeExt, Digest, Encode, ObjectId, Transaction, UserPublicKey,
    WebAuthnSignature as DomainWebAuthnSignature,
};
use hellas_rpc::{
    call::StreamingCall,
    pb::{chain::*, services::light_client::LightClientClientImpl},
};
use hellas_wire::mux::MuxTransport;
use p256::ecdsa::Signature as P256Signature;

/// Wire-backed light client that connects to a remote validator or relay.
#[derive(Clone)]
pub struct RemoteLightClient {
    client: LightClientClientImpl<MuxTransport>,
    verifier: Option<ConsensusVerifier>,
}

impl RemoteLightClient {
    pub fn new(transport: MuxTransport) -> Self {
        Self {
            client: LightClientClientImpl::new(transport),
            verifier: None,
        }
    }

    /// Connect to a WebSocket endpoint.
    pub async fn connect(addr: impl Into<String>) -> Result<Self, QueryError> {
        let addr = addr.into();
        #[cfg(not(target_family = "wasm"))]
        let transport = hellas_wire::ws::connect(&addr)
            .await
            .map_err(|e| QueryError::Connect(e.to_string()))?;
        #[cfg(target_family = "wasm")]
        let transport = hellas_wire::ws::wasm::connect(&addr)
            .await
            .map_err(|e| QueryError::Connect(e.to_string()))?;
        Ok(Self::new(transport))
    }

    /// Configure this client to verify finalized snapshots.
    pub fn with_consensus_info(mut self, info: &ConsensusInfo) -> Result<Self, QueryError> {
        self.verifier = Some(ConsensusVerifier::new(info).map_err(QueryError::from)?);
        Ok(self)
    }

    /// Subscribe to the consensus activity stream.
    pub async fn subscribe_activity(
        &self,
        urgent_events: Vec<ActivityEventKind>,
    ) -> Result<StreamingCall<ActivityEvent>, QueryError> {
        self.client
            .subscribe_activity(SubscribeActivityRequest {
                urgent_events: urgent_events.into_iter().map(|k| k as i32).collect(),
            })
            .await
            .map_err(QueryError::from)
    }
}

impl LightClient for RemoteLightClient {
    fn get_state_root(&self) -> impl Future<Output = Result<Option<Digest>, QueryError>> + Send {
        let client = self.client.clone();
        async move {
            let response = client
                .get_state_root(GetStateRootRequest {})
                .await
                .map_err(QueryError::from)?;
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
        let client = self.client.clone();
        async move {
            let response = client
                .get_proof(GetProofRequest {
                    object_id: object_id.to_vec(),
                })
                .await
                .map_err(QueryError::from)?;
            Ok(response.proof)
        }
    }

    fn get_coin(
        &self,
        payload: Digest,
        object_id: ObjectId,
    ) -> impl Future<Output = Result<Option<Coin>, QueryError>> + Send {
        let client = self.client.clone();
        async move {
            let response = client
                .get_coin(GetCoinRequest {
                    payload: payload.to_vec(),
                    object_id: object_id.to_vec(),
                })
                .await
                .map_err(QueryError::from)?;
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
        let client = self.client.clone();
        async move {
            let response = client
                .get_finalization(GetFinalizationRequest {
                    payload: payload.to_vec(),
                })
                .await
                .map_err(QueryError::from)?;
            Ok(response.certificate)
        }
    }

    fn get_latest_block(
        &self,
    ) -> impl Future<Output = Result<Option<LatestBlock>, QueryError>> + Send {
        let client = self.client.clone();
        let verifier = self.verifier.clone();
        async move {
            let response = client
                .get_latest_block(GetLatestBlockRequest {})
                .await
                .map_err(QueryError::from)?;
            response
                .latest
                .map(|snapshot| verified_latest_block_from_proto(snapshot, verifier.as_ref()))
                .transpose()
        }
    }

    fn get_finalized_block(
        &self,
        query: FinalizedBlockQuery,
    ) -> impl Future<Output = Result<Option<FinalizedBlock>, QueryError>> + Send {
        let client = self.client.clone();
        let verifier = self.verifier.clone();
        async move {
            let response = client
                .get_finalized_block(finalized_block_query_to_proto(query))
                .await
                .map_err(QueryError::from)?;
            response
                .block
                .map(|block| verified_finalized_block_from_proto(block, verifier.as_ref()))
                .transpose()
        }
    }

    fn submit_tx(&self, tx: Transaction) -> impl Future<Output = Result<(), QueryError>> + Send {
        let client = self.client.clone();
        async move {
            let req = transaction_to_proto(tx);
            client.submit_tx(req).await.map_err(QueryError::from)?;
            Ok(())
        }
    }

    fn get_validators(&self) -> impl Future<Output = Result<Vec<String>, QueryError>> + Send {
        let client = self.client.clone();
        async move {
            let resp = client
                .get_validators(GetValidatorsRequest {})
                .await
                .map_err(QueryError::from)?;
            Ok(resp.validators)
        }
    }

    fn get_consensus_info(&self) -> impl Future<Output = Result<ConsensusInfo, QueryError>> + Send {
        let client = self.client.clone();
        async move {
            let resp = client
                .get_consensus_info(GetConsensusInfoRequest {})
                .await
                .map_err(QueryError::from)?;
            if resp.threshold_identity.is_empty() {
                return Err(QueryError::Remote(
                    "threshold identity was empty".to_string(),
                ));
            }
            Ok(ConsensusInfo {
                validators: resp.validators,
                threshold_identity: resp.threshold_identity,
            })
        }
    }

    fn get_coins_by_owner(
        &self,
        owner: Address,
    ) -> impl Future<Output = Result<Option<OwnerCoins>, QueryError>> + Send {
        let client = self.client.clone();
        let verifier = self.verifier.clone();
        async move {
            let resp = client
                .get_coins_by_owner(GetCoinsByOwnerRequest {
                    owner: owner.public_key().encode().to_vec(),
                })
                .await
                .map_err(QueryError::from)?;
            let Some(snapshot) = resp.snapshot else {
                if resp.coins.is_empty() {
                    return Ok(None);
                }
                return Err(QueryError::Remote(
                    "GetCoinsByOwnerResponse had coins without a snapshot".to_string(),
                ));
            };
            let snapshot = verified_latest_block_from_proto(snapshot, verifier.as_ref())?;
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
            Ok(Some(OwnerCoins { snapshot, coins }))
        }
    }
}

fn verified_latest_block_from_proto(
    snapshot: FinalizedSnapshot,
    verifier: Option<&ConsensusVerifier>,
) -> Result<LatestBlock, QueryError> {
    let latest = latest_block_from_proto(snapshot)?;
    if let Some(verifier) = verifier {
        verifier
            .verify_snapshot(&latest)
            .map_err(QueryError::from)?;
    }
    Ok(latest)
}

fn verified_finalized_block_from_proto(
    block: hellas_rpc::pb::chain::FinalizedBlock,
    verifier: Option<&ConsensusVerifier>,
) -> Result<FinalizedBlock, QueryError> {
    let Some(snapshot) = block.snapshot else {
        return Err(QueryError::Remote(
            "FinalizedBlock had no snapshot".to_string(),
        ));
    };
    let snapshot = verified_latest_block_from_proto(snapshot, verifier)?;
    if Sha256::hash(&block.block) != snapshot.payload {
        return Err(QueryError::Remote(
            "block bytes did not match finalized payload".to_string(),
        ));
    }
    Ok(FinalizedBlock {
        snapshot,
        block: block.block,
    })
}

fn finalized_block_query_to_proto(query: FinalizedBlockQuery) -> GetFinalizedBlockRequest {
    let query = match query {
        FinalizedBlockQuery::Latest => None,
        FinalizedBlockQuery::Height(height) => {
            Some(get_finalized_block_request::Query::Height(height))
        }
        FinalizedBlockQuery::Payload(payload) => Some(get_finalized_block_request::Query::Payload(
            payload.to_vec(),
        )),
    };
    GetFinalizedBlockRequest { query }
}

fn latest_block_from_proto(snapshot: FinalizedSnapshot) -> Result<LatestBlock, QueryError> {
    let payload: [u8; 32] = snapshot
        .payload
        .try_into()
        .map_err(|_| QueryError::Remote("payload was not 32 bytes".to_string()))?;
    let state_root: [u8; 32] = snapshot
        .state_root
        .try_into()
        .map_err(|_| QueryError::Remote("state_root was not 32 bytes".to_string()))?;
    if snapshot.finalization.is_empty() {
        return Err(QueryError::Remote("finalization was empty".to_string()));
    }
    Ok(LatestBlock {
        height: snapshot.height,
        payload: Digest::from(payload),
        state_root: Digest::from(state_root),
        finalization: snapshot.finalization,
    })
}

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

#[cfg(test)]
mod tests {
    use super::*;

    fn proto_block(block: Vec<u8>, payload: Digest) -> hellas_rpc::pb::chain::FinalizedBlock {
        hellas_rpc::pb::chain::FinalizedBlock {
            snapshot: Some(FinalizedSnapshot {
                height: 7,
                payload: payload.to_vec(),
                state_root: Digest::from([1u8; 32]).to_vec(),
                finalization: vec![1],
            }),
            block,
        }
    }

    #[test]
    fn finalized_block_verification_checks_block_bytes() {
        let block = b"encoded-block".to_vec();
        let payload = Sha256::hash(&block);

        let verified =
            verified_finalized_block_from_proto(proto_block(block.clone(), payload), None).expect(
                "matching block bytes should verify without a configured certificate verifier",
            );
        assert_eq!(verified.snapshot.payload, payload);
        assert_eq!(verified.block, block);

        let mismatched_payload = Sha256::hash(b"different-block");
        assert!(
            verified_finalized_block_from_proto(
                proto_block(b"encoded-block".to_vec(), mismatched_payload),
                None
            )
            .is_err()
        );
    }
}
