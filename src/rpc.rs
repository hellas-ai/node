//! Local implementation of the light-client query interface.
//!
//! [`LocalLightClient`] wraps the local database/mempool handles and implements the
//! [`LightClient`] trait from `hellas_types::rpc`.
//!
//! NOTE: the tonic-based `LightClientGrpcServer` that used to expose this
//! over gRPC/WebSocket is currently stubbed. The hellas-wire / hellas-rpc
//! cutover does not yet codegen a `LightClient` service (only the executor
//! / courtesy / swarm proto packages), so the chain crate no longer has a
//! transport-layer server. Once the LightClient proto lands in the new
//! `hellas-rpc` codegen, the gRPC dispatcher here can be reinstated using
//! `hellas_wire::Dispatcher` + the typed `LightClientServer<H>` stub.

use crate::{
    app::{MarshalMailbox, Mempool},
    execution::store::{UtxoDatabase, get as utxo_get, root as utxo_root},
};
use commonware_consensus::{Heightable, marshal::Identifier as MarshalIdentifier};
use commonware_cryptography::{Digestible, sha256::Digest};
use hellas_types::rpc::{ConsensusActivity, LatestBlock, LightClient, QueryError};
use hellas_types::{Coin, Encode, ObjectId, Transaction};
use tokio::sync::broadcast;

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

/// Placeholder wrapper around a [`LightClient`] implementation.
///
/// Historically this was a tonic gRPC service that wrapped a [`LightClient`]
/// implementation and exposed it over WebSocket via `tonic::transport::Server`
/// plus over the explorer relay via `ws-mux`. The hellas-wire / hellas-rpc
/// cutover deferred this: the `LightClient` proto is not yet part of the new
/// `hellas-rpc` codegen, so any attempt to dial / serve via this struct
/// currently panics with `unimplemented!()`.
///
/// `LocalLightClient` itself is unaffected — callers that want to query the
/// chain in-process should use it directly.
pub struct LightClientGrpcServer<L> {
    _inner: L,
    _activity_tx: broadcast::Sender<ConsensusActivity>,
}

impl<L: LightClient> LightClientGrpcServer<L> {
    pub fn new(inner: L, activity_tx: broadcast::Sender<ConsensusActivity>) -> Self {
        Self {
            _inner: inner,
            _activity_tx: activity_tx,
        }
    }

    /// Convert into a wire-layer service ready to be added to a server.
    ///
    /// Currently unimplemented — see the module docs.
    pub fn into_service(self) -> LightClientServerStub {
        LightClientServerStub
    }
}

/// Placeholder for the codegen-emitted service handle that used to live in
/// `hellas_rpc::pb::hellas::light_client_server::LightClientServer`.
///
/// The new `hellas-rpc` codegen does not yet emit a service for the
/// LightClient proto; once it does, this stub should be replaced by the
/// generated `LightClientServer<H>` (or whatever the new helper is named).
#[derive(Clone)]
pub struct LightClientServerStub;

// Cheap impl<L> Clone — kept so the existing validator wiring (which clones
// the service handle into the ws-server / relay spawns) still compiles.
impl<L: Clone> Clone for LightClientGrpcServer<L> {
    fn clone(&self) -> Self {
        Self {
            _inner: self._inner.clone(),
            _activity_tx: self._activity_tx.clone(),
        }
    }
}
