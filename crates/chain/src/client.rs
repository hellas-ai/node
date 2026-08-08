use crate::domain::{
    Coin, Digest, Encode, ObjectId, SettlementKey, Transaction,
    WebAuthnSignature as DomainWebAuthnSignature,
};
use crate::{
    ConsensusInfo, ConsensusVerifier, EdgeLookup, EdgeRecord, EdgeState, FinalizedBlock,
    FinalizedBlockQuery, LatestBlock, LightClient, OwnerCoins, OwnerEdges, QueryError,
};
use commonware_cryptography::{Hasher, Sha256};
use hellas_kernel::{Decode as _, Encode as _};
use hellas_rpc::{
    call::StreamingCall,
    pb::{chain::*, services::light_client::LightClientClientImpl},
};
use hellas_wire::mux::MuxTransport;
use p256::ecdsa::Signature as P256Signature;
use std::collections::BTreeSet;

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
        #[cfg(target_family = "wasm")]
        {
            let transport = hellas_wire::ws::wasm::connect(&addr)
                .await
                .map_err(|e| QueryError::Connect(e.to_string()))?;
            Ok(Self::new(transport))
        }
        #[cfg(all(not(target_family = "wasm"), feature = "client"))]
        {
            let transport = hellas_wire::ws::connect(&addr)
                .await
                .map_err(|e| QueryError::Connect(e.to_string()))?;
            Ok(Self::new(transport))
        }
        #[cfg(all(not(target_family = "wasm"), not(feature = "client")))]
        {
            let _ = addr;
            Err(QueryError::Connect(
                "the wasm-client feature can only connect on a wasm target".to_string(),
            ))
        }
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

    /// Fetch transport/version metadata from the connected validator path.
    pub async fn get_relay_info(&self) -> Result<GetRelayInfoResponse, QueryError> {
        self.client
            .get_relay_info(GetRelayInfoRequest {})
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
                    let actual = owner_bytes.len();
                    let raw: [u8; SettlementKey::LENGTH] =
                        owner_bytes.try_into().map_err(|_| {
                            QueryError::Remote(format!(
                                "owner settlement key was {} bytes, got {actual}",
                                SettlementKey::LENGTH
                            ))
                        })?;
                    Ok(Some(Coin {
                        owner: SettlementKey::from_bytes(raw),
                        value,
                    }))
                }
                _ => Ok(None),
            }
        }
    }

    fn get_edge(
        &self,
        payload: Digest,
        object_id: ObjectId,
    ) -> impl Future<Output = Result<Option<EdgeLookup>, QueryError>> + Send {
        let client = self.client.clone();
        async move {
            let response = client
                .get_edge(GetEdgeRequest {
                    payload: payload.to_vec(),
                    object_id: object_id.to_vec(),
                })
                .await
                .map_err(QueryError::from)?;
            edge_lookup_from_proto(response)
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
            let req = transaction_to_proto(tx)?;
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
            if resp.network_id.is_empty() {
                return Err(QueryError::Remote("network id was empty".to_string()));
            }
            Ok(ConsensusInfo {
                validators: resp.validators,
                threshold_identity: resp.threshold_identity,
                network_id: resp.network_id,
            })
        }
    }

    fn get_coins_by_owner(
        &self,
        owner: SettlementKey,
    ) -> impl Future<Output = Result<Option<OwnerCoins>, QueryError>> + Send {
        let client = self.client.clone();
        let verifier = self.verifier.clone();
        async move {
            let resp = client
                .get_coins_by_owner(GetCoinsByOwnerRequest {
                    owner: owner.to_bytes().to_vec(),
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

    fn get_edges_by_owner(
        &self,
        owner: SettlementKey,
    ) -> impl Future<Output = Result<Option<OwnerEdges>, QueryError>> + Send {
        let client = self.client.clone();
        let verifier = self.verifier.clone();
        async move {
            let resp = client
                .get_edges_by_owner(GetEdgesByOwnerRequest {
                    owner: owner.to_bytes().to_vec(),
                })
                .await
                .map_err(QueryError::from)?;
            owner_edges_from_proto(owner, resp, verifier.as_ref())
        }
    }
}

fn edge_lookup_from_proto(response: GetEdgeResponse) -> Result<Option<EdgeLookup>, QueryError> {
    match response.state_root {
        Some(state_root) => Ok(Some(EdgeLookup {
            state_root: digest_from_wire(state_root, "state_root")?,
            edge: response.edge.map(edge_state_from_proto).transpose()?,
        })),
        None if response.edge.is_none() => Ok(None),
        None => Err(QueryError::Remote(
            "GetEdgeResponse had an edge without a state root".to_string(),
        )),
    }
}

fn owner_edges_from_proto(
    owner: SettlementKey,
    response: GetEdgesByOwnerResponse,
    verifier: Option<&ConsensusVerifier>,
) -> Result<Option<OwnerEdges>, QueryError> {
    let Some(snapshot) = response.snapshot else {
        if response.edges.is_empty() {
            return Ok(None);
        }
        return Err(QueryError::Remote(
            "GetEdgesByOwnerResponse had edges without a snapshot".to_string(),
        ));
    };
    let snapshot = verified_latest_block_from_proto(snapshot, verifier)?;
    let mut seen = BTreeSet::new();
    let mut edges = Vec::with_capacity(response.edges.len());
    for edge in response.edges {
        let edge = EdgeRecord {
            object_id: digest_from_wire(edge.object_id, "object_id")?,
            maker: settlement_key_from_wire(edge.maker, "maker")?,
            taker: settlement_key_from_wire(edge.taker, "taker")?,
        };
        if edge.maker != owner && edge.taker != owner {
            return Err(QueryError::Remote(
                "GetEdgesByOwnerResponse contained an edge unrelated to the requested owner"
                    .to_string(),
            ));
        }
        if !seen.insert(edge.object_id) {
            return Err(QueryError::Remote(
                "GetEdgesByOwnerResponse contained a duplicate object_id".to_string(),
            ));
        }
        edges.push(edge);
    }
    Ok(Some(OwnerEdges { snapshot, edges }))
}

fn digest_from_wire(bytes: Vec<u8>, field: &'static str) -> Result<Digest, QueryError> {
    let actual = bytes.len();
    let raw: [u8; 32] = bytes.try_into().map_err(|_| {
        QueryError::Remote(format!("{field} was expected to be 32 bytes, got {actual}"))
    })?;
    Ok(Digest::from(raw))
}

fn settlement_key_from_wire(
    bytes: Vec<u8>,
    field: &'static str,
) -> Result<SettlementKey, QueryError> {
    let actual = bytes.len();
    let raw: [u8; SettlementKey::LENGTH] = bytes.try_into().map_err(|_| {
        QueryError::Remote(format!(
            "{field} settlement key was expected to be {} bytes, got {actual}",
            SettlementKey::LENGTH
        ))
    })?;
    Ok(SettlementKey::from_bytes(raw))
}

fn edge_state_from_proto(edge: hellas_rpc::pb::chain::EdgeState) -> Result<EdgeState, QueryError> {
    let fees = edge
        .close_fees
        .ok_or_else(|| QueryError::Remote("edge close_fees were missing".to_string()))?;
    let terms_hash = hellas_kernel::TermsHash::decode_exact(&edge.terms_hash)
        .map_err(|_| QueryError::Remote("terms_hash was not 32 canonical bytes".to_string()))?;
    Ok(EdgeState {
        value: edge.value,
        reserve: edge.reserve,
        close_fees: hellas_kernel::Fees::new(fees.base, fees.slot, fees.proof, fees.lifetime),
        timeout: hellas_kernel::BlockHeight::new(edge.timeout),
        maker: settlement_key_from_wire(edge.maker, "maker")?,
        taker: settlement_key_from_wire(edge.taker, "taker")?,
        terms_hash,
    })
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

fn transaction_to_proto(tx: Transaction) -> Result<SubmitTxRequest, QueryError> {
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
        Transaction::Kernel(tx) => {
            let mut bytes = vec![0_u8; hellas_kernel::Tx::MAX_ENCODED_SIZE];
            let written = tx.write_to(&mut bytes);
            bytes.truncate(written);
            submit_tx_request::Tx::KernelTx(bytes)
        }
    };
    Ok(SubmitTxRequest { tx: Some(tx_oneof) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hellas_kernel::test_support::valid_open_tx;

    fn proto_snapshot() -> FinalizedSnapshot {
        FinalizedSnapshot {
            height: 7,
            payload: Digest::from([2u8; 32]).to_vec(),
            state_root: Digest::from([1u8; 32]).to_vec(),
            finalization: vec![1],
        }
    }

    fn proto_block(block: Vec<u8>, payload: Digest) -> hellas_rpc::pb::chain::FinalizedBlock {
        hellas_rpc::pb::chain::FinalizedBlock {
            snapshot: Some(FinalizedSnapshot {
                payload: payload.to_vec(),
                ..proto_snapshot()
            }),
            block,
        }
    }

    fn proto_edge_state() -> hellas_rpc::pb::chain::EdgeState {
        hellas_rpc::pb::chain::EdgeState {
            value: 100,
            reserve: 4,
            close_fees: Some(KernelFees {
                base: 1,
                slot: 2,
                proof: 3,
                lifetime: 4,
            }),
            timeout: 9,
            maker: vec![3; SettlementKey::LENGTH],
            taker: vec![4; SettlementKey::LENGTH],
            terms_hash: vec![5; hellas_kernel::TermsHash::LENGTH],
        }
    }

    fn proto_edge_record(object_id: u8, maker: SettlementKey, taker: SettlementKey) -> EdgeEntry {
        EdgeEntry {
            object_id: vec![object_id; 32],
            maker: maker.to_bytes().to_vec(),
            taker: taker.to_bytes().to_vec(),
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

    #[test]
    fn kernel_transaction_uses_canonical_submit_payload() {
        let kernel = valid_open_tx().expect("valid kernel open fixture");
        let request = transaction_to_proto(Transaction::Kernel(kernel.clone()))
            .expect("kernel transaction encodes");
        let Some(submit_tx_request::Tx::KernelTx(bytes)) = request.tx else {
            panic!("expected kernel transaction arm")
        };
        assert_eq!(hellas_kernel::Tx::decode_exact(&bytes), Ok(kernel));
    }

    #[test]
    fn remote_edge_decode_rejects_malformed_presence_and_required_fields() {
        assert!(
            edge_lookup_from_proto(GetEdgeResponse {
                edge: None,
                state_root: Some(vec![0; 31]),
            })
            .is_err()
        );

        let mut missing_fees = proto_edge_state();
        missing_fees.close_fees = None;
        assert!(
            edge_lookup_from_proto(GetEdgeResponse {
                edge: Some(missing_fees),
                state_root: Some(vec![0; 32]),
            })
            .is_err()
        );

        assert!(
            edge_lookup_from_proto(GetEdgeResponse {
                edge: Some(proto_edge_state()),
                state_root: None,
            })
            .is_err()
        );
    }

    #[test]
    fn remote_owner_edges_decode_records_and_reject_malformed_keys() {
        let owner = SettlementKey::from_bytes([7; SettlementKey::LENGTH]);
        let taker = SettlementKey::from_bytes([8; SettlementKey::LENGTH]);
        let decoded = owner_edges_from_proto(
            owner,
            GetEdgesByOwnerResponse {
                snapshot: Some(proto_snapshot()),
                edges: vec![proto_edge_record(9, owner, taker)],
            },
            None,
        )
        .expect("valid owner edge response")
        .expect("snapshot is present");
        assert_eq!(
            decoded.edges,
            vec![EdgeRecord {
                object_id: Digest::from([9; 32]),
                maker: owner,
                taker,
            }]
        );

        let mut malformed_maker = proto_edge_record(9, owner, taker);
        malformed_maker.maker.pop();
        let mut malformed_taker = proto_edge_record(9, owner, taker);
        malformed_taker.taker.pop();
        for malformed in [malformed_maker, malformed_taker] {
            assert!(
                owner_edges_from_proto(
                    owner,
                    GetEdgesByOwnerResponse {
                        snapshot: Some(proto_snapshot()),
                        edges: vec![malformed],
                    },
                    None,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn remote_owner_edges_reject_duplicates_and_unrelated_records() {
        let owner = SettlementKey::from_bytes([7; SettlementKey::LENGTH]);
        let taker = SettlementKey::from_bytes([8; SettlementKey::LENGTH]);
        let duplicate = proto_edge_record(9, owner, taker);
        assert!(
            owner_edges_from_proto(
                owner,
                GetEdgesByOwnerResponse {
                    snapshot: Some(proto_snapshot()),
                    edges: vec![duplicate.clone(), duplicate],
                },
                None,
            )
            .is_err()
        );

        let maker = SettlementKey::from_bytes([6; SettlementKey::LENGTH]);
        assert!(
            owner_edges_from_proto(
                owner,
                GetEdgesByOwnerResponse {
                    snapshot: Some(proto_snapshot()),
                    edges: vec![proto_edge_record(9, maker, taker)],
                },
                None,
            )
            .is_err()
        );
    }
}
