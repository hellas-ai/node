//! Content-addressed artifact boundary for symbolic execution.
//!
//! Symbolic protocol requests name only CIDs. This module is the executor-local
//! boundary that verifies bytes against those CIDs before any future resolver
//! (iroh-blobs, local disk, HTTP, etc.) hands them to catgrad.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::sync::{Arc, Mutex};

use catgrad::category::core::{Dtype, Shape};
use hellas_core::Digest;
#[cfg(test)]
use hellas_core::SymbolicRequest;
use iroh_blobs::Hash as IrohBlobHash;
use serde::Deserialize;

const PROGRAM_BINDING_SCHEMA: &str = "hellas.program_binding.v1";
const TENSOR_SCHEMA: &str = "hellas.tensor.v1";

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct ArtifactId(Digest);

impl ArtifactId {
    pub(crate) const fn from_digest(digest: Digest) -> Self {
        Self(digest)
    }

    pub(crate) fn from_bytes(bytes: &[u8]) -> Self {
        Self(Digest::hash(bytes))
    }

    #[cfg(test)]
    pub(crate) const fn digest(self) -> Digest {
        self.0
    }

    pub(crate) const fn as_bytes(&self) -> &[u8; Digest::LEN] {
        self.0.as_bytes()
    }

    #[allow(dead_code)]
    pub(crate) fn to_iroh_hash(self) -> IrohBlobHash {
        IrohBlobHash::from_bytes(self.0.into_bytes())
    }

    #[allow(dead_code)]
    pub(crate) fn from_iroh_hash(hash: IrohBlobHash) -> Self {
        Self(Digest::from_bytes(*hash.as_bytes()))
    }
}

impl fmt::Debug for ArtifactId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for ArtifactId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0.as_bytes() {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Artifact {
    id: ArtifactId,
    bytes: Arc<[u8]>,
}

impl Artifact {
    pub(crate) fn from_verified_bytes(
        expected: ArtifactId,
        bytes: impl Into<Vec<u8>>,
    ) -> Result<Self, ArtifactError> {
        let bytes = bytes.into();
        let actual = ArtifactId::from_bytes(&bytes);
        if actual != expected {
            return Err(ArtifactError::HashMismatch { expected, actual });
        }
        Ok(Self {
            id: expected,
            bytes: Arc::from(bytes.into_boxed_slice()),
        })
    }

    pub(crate) const fn id(&self) -> ArtifactId {
        self.id
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ArtifactError {
    #[error("artifact {id} is missing")]
    Missing { id: ArtifactId },
    #[error("artifact hash mismatch: expected {expected}, got {actual}")]
    HashMismatch {
        expected: ArtifactId,
        actual: ArtifactId,
    },
    #[error("artifact store error: {0}")]
    Store(String),
    #[error("invalid artifact {id}: {reason}")]
    Invalid { id: ArtifactId, reason: String },
}

pub(crate) trait ArtifactResolver: Send + Sync {
    fn resolve(&self, id: ArtifactId) -> Result<Artifact, ArtifactError>;
}

#[derive(Clone, Default)]
pub(crate) struct InMemoryArtifactStore {
    inner: Arc<Mutex<HashMap<ArtifactId, Arc<[u8]>>>>,
}

impl InMemoryArtifactStore {
    pub(crate) fn insert_verified_bytes(
        &self,
        expected: ArtifactId,
        bytes: impl Into<Vec<u8>>,
    ) -> Result<ArtifactId, ArtifactError> {
        let artifact = Artifact::from_verified_bytes(expected, bytes)?;
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| ArtifactError::Store("artifact store lock poisoned".to_string()))?;
        inner.insert(artifact.id, artifact.bytes);
        Ok(expected)
    }

    pub(crate) fn contains(&self, id: ArtifactId) -> Result<bool, ArtifactError> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| ArtifactError::Store("artifact store lock poisoned".to_string()))?;
        Ok(inner.contains_key(&id))
    }

    #[cfg(test)]
    pub(crate) fn missing_for_symbolic_request(
        &self,
        request: &SymbolicRequest,
    ) -> Result<Vec<ArtifactId>, ArtifactError> {
        let mut missing = Vec::new();
        for id in symbolic_request_artifacts(request) {
            if !self.contains(id)? {
                missing.push(id);
            }
        }
        Ok(missing)
    }

    #[cfg(test)]
    pub(crate) fn missing_for_symbolic_request_transitive(
        &self,
        request: &SymbolicRequest,
    ) -> Result<Vec<ArtifactId>, ArtifactError> {
        use std::collections::BTreeSet;

        let mut required = BTreeSet::new();
        for id in symbolic_request_artifacts(request) {
            required.insert(id);
        }

        for binding_id in symbolic_request_binding_artifacts(request) {
            let Ok(binding_artifact) = self.resolve(binding_id) else {
                continue;
            };
            let binding = decode_program_binding_artifact(&binding_artifact)?;
            required.insert(binding.program);
            required.extend(binding.parameters.values().copied());
        }

        let mut missing = Vec::new();
        for id in required {
            if !self.contains(id)? {
                missing.push(id);
            }
        }
        Ok(missing)
    }
}

impl ArtifactResolver for InMemoryArtifactStore {
    fn resolve(&self, id: ArtifactId) -> Result<Artifact, ArtifactError> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| ArtifactError::Store("artifact store lock poisoned".to_string()))?;
        let bytes = inner
            .get(&id)
            .cloned()
            .ok_or(ArtifactError::Missing { id })?;
        Ok(Artifact { id, bytes })
    }
}

#[cfg(test)]
pub(crate) fn symbolic_request_artifacts(request: &SymbolicRequest) -> Vec<ArtifactId> {
    use std::collections::BTreeSet;

    let mut ids = BTreeSet::new();
    match request {
        SymbolicRequest::Genesis(genesis) => {
            ids.insert(ArtifactId::from_digest(genesis.binding_cid));
        }
        SymbolicRequest::Step(step) => {
            ids.insert(ArtifactId::from_digest(step.binding_cid));
            ids.insert(ArtifactId::from_digest(step.input_tokens_cid));
        }
    }
    ids.into_iter().collect()
}

#[cfg(test)]
fn symbolic_request_binding_artifacts(request: &SymbolicRequest) -> Vec<ArtifactId> {
    use std::collections::BTreeSet;

    let mut ids = BTreeSet::new();
    match request {
        SymbolicRequest::Genesis(genesis) => {
            ids.insert(ArtifactId::from_digest(genesis.binding_cid));
        }
        SymbolicRequest::Step(step) => {
            ids.insert(ArtifactId::from_digest(step.binding_cid));
        }
    }
    ids.into_iter().collect()
}

#[derive(Debug, Clone)]
pub(crate) struct ProgramBindingArtifact {
    pub(crate) program: ArtifactId,
    pub(crate) parameters: BTreeMap<String, ArtifactId>,
}

#[derive(Debug, Clone)]
pub(crate) struct TensorArtifact {
    pub(crate) dtype: Dtype,
    pub(crate) shape: Shape,
    pub(crate) data: Vec<u8>,
}

#[derive(Deserialize)]
struct ProgramBindingWire(
    String,
    #[serde(with = "serde_bytes")] Vec<u8>,
    Vec<ProgramBindingParameterWire>,
);

#[derive(Deserialize)]
struct ProgramBindingParameterWire(String, #[serde(with = "serde_bytes")] Vec<u8>);

#[derive(Deserialize)]
struct TensorWire(
    String,
    String,
    Vec<u64>,
    #[serde(with = "serde_bytes")] Vec<u8>,
);

pub(crate) fn decode_program_binding_artifact(
    artifact: &Artifact,
) -> Result<ProgramBindingArtifact, ArtifactError> {
    let ProgramBindingWire(schema, program, parameters) =
        serde_ipld_dagcbor::from_slice(artifact.bytes()).map_err(|error| {
            ArtifactError::Invalid {
                id: artifact.id(),
                reason: format!("invalid program binding DAG-CBOR: {error}"),
            }
        })?;
    if schema != PROGRAM_BINDING_SCHEMA {
        return Err(ArtifactError::Invalid {
            id: artifact.id(),
            reason: format!("unknown program binding schema {schema:?}"),
        });
    }
    let program = artifact_id_from_wire_cid(artifact.id(), "program", program)?;
    let mut parameter_map = BTreeMap::new();
    for ProgramBindingParameterWire(path, tensor) in parameters {
        let tensor = artifact_id_from_wire_cid(artifact.id(), "parameter tensor", tensor)?;
        if parameter_map.insert(path.clone(), tensor).is_some() {
            return Err(ArtifactError::Invalid {
                id: artifact.id(),
                reason: format!("duplicate parameter path {path:?}"),
            });
        }
    }
    Ok(ProgramBindingArtifact {
        program,
        parameters: parameter_map,
    })
}

pub(crate) fn decode_tensor_artifact(artifact: &Artifact) -> Result<TensorArtifact, ArtifactError> {
    let TensorWire(schema, dtype, shape, data) = serde_ipld_dagcbor::from_slice(artifact.bytes())
        .map_err(|error| ArtifactError::Invalid {
        id: artifact.id(),
        reason: format!("invalid tensor DAG-CBOR: {error}"),
    })?;
    if schema != TENSOR_SCHEMA {
        return Err(ArtifactError::Invalid {
            id: artifact.id(),
            reason: format!("unknown tensor schema {schema:?}"),
        });
    }
    let dtype = dtype.parse().map_err(|reason| ArtifactError::Invalid {
        id: artifact.id(),
        reason,
    })?;
    let shape = shape
        .into_iter()
        .map(|dim| {
            usize::try_from(dim).map_err(|error| ArtifactError::Invalid {
                id: artifact.id(),
                reason: format!("tensor dimension {dim} does not fit usize: {error}"),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(TensorArtifact {
        dtype,
        shape: Shape(shape),
        data,
    })
}

fn artifact_id_from_wire_cid(
    source: ArtifactId,
    field: &str,
    bytes: Vec<u8>,
) -> Result<ArtifactId, ArtifactError> {
    let digest = bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| ArtifactError::Invalid {
            id: source,
            reason: format!("{field} CID must be 32 bytes, got {}", bytes.len()),
        })?;
    Ok(ArtifactId::from_digest(Digest::from_bytes(digest)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use catgrad::cid::{Cid, Tensor, tensor_dag_cbor_bytes};
    use catgrad::path::path;
    use catgrad::prelude::Dtype;
    use catgrad::runtime::{Program, ProgramBinding};
    use hellas_core::{SymbolicGenesisRequest, SymbolicStepRequest};

    #[test]
    fn artifact_id_matches_iroh_blob_hash() {
        let bytes = b"canonical artifact bytes";
        let id = ArtifactId::from_bytes(bytes);
        let iroh = IrohBlobHash::new(bytes);

        assert_eq!(id.to_iroh_hash(), iroh);
        assert_eq!(ArtifactId::from_iroh_hash(iroh), id);
    }

    #[test]
    fn store_rejects_hash_mismatches() {
        let store = InMemoryArtifactStore::default();
        let expected = ArtifactId::from_digest(Digest::from_bytes([1; 32]));
        let err = store
            .insert_verified_bytes(expected, b"not those bytes".to_vec())
            .expect_err("hash mismatch should be rejected");

        assert!(matches!(err, ArtifactError::HashMismatch { .. }));
    }

    #[test]
    fn symbolic_artifact_list_is_deduplicated() {
        let request = SymbolicRequest::Step(SymbolicStepRequest {
            binding_cid: Digest::from_bytes([1; 32]),
            previous_execution_cid: Digest::from_bytes([2; 32]),
            input_tokens_cid: Digest::from_bytes([3; 32]),
            policy: hellas_core::SymbolicPolicy::new(4, vec![1, 2]),
        });

        let ids = symbolic_request_artifacts(&request);
        assert_eq!(ids.len(), 2);
    }

    #[test]
    fn missing_for_symbolic_request_reports_absent_cids() {
        let present = Digest::hash(b"present");
        let missing = Digest::from_bytes([9; 32]);
        let store = InMemoryArtifactStore::default();
        store
            .insert_verified_bytes(ArtifactId::from_digest(present), b"present".to_vec())
            .unwrap();

        let request = SymbolicRequest::Genesis(SymbolicGenesisRequest {
            binding_cid: missing,
        });

        assert_eq!(
            store.missing_for_symbolic_request(&request).unwrap(),
            vec![ArtifactId::from_digest(missing)]
        );
    }

    #[test]
    fn transitive_missing_includes_program_and_parameter_cids_from_binding() {
        let mut parameters = BTreeMap::new();
        let parameter = Cid::<Tensor>::from_bytes([3; 32]);
        parameters.insert(path(vec!["layer", "weight"]).unwrap(), parameter);
        let binding = ProgramBinding::new(Cid::<Program>::from_bytes([2; 32]), parameters);
        let binding_bytes = binding.to_dag_cbor_bytes();
        let binding_id = ArtifactId::from_bytes(&binding_bytes);
        let store = InMemoryArtifactStore::default();
        store
            .insert_verified_bytes(binding_id, binding_bytes)
            .expect("binding insert");

        let request = SymbolicRequest::Genesis(SymbolicGenesisRequest {
            binding_cid: binding_id.digest(),
        });
        let missing = store
            .missing_for_symbolic_request_transitive(&request)
            .expect("transitive lookup");

        assert_eq!(
            missing,
            vec![
                ArtifactId::from_digest(Digest::from_bytes([2; 32])),
                ArtifactId::from_digest(Digest::from_bytes([3; 32])),
            ]
        );
    }

    #[test]
    fn decode_tensor_artifact_reads_canonical_tensor_blob() {
        let mut raw = Vec::new();
        raw.extend_from_slice(&7_u32.to_le_bytes());
        raw.extend_from_slice(&9_u32.to_le_bytes());
        let bytes = tensor_dag_cbor_bytes(Dtype::U32, &Shape(vec![1, 2]), &raw);
        let artifact = Artifact::from_verified_bytes(ArtifactId::from_bytes(&bytes), bytes)
            .expect("verified tensor");

        let tensor = decode_tensor_artifact(&artifact).expect("decode tensor");
        assert_eq!(tensor.dtype, Dtype::U32);
        assert_eq!(tensor.shape, Shape(vec![1, 2]));
        assert_eq!(tensor.data, raw);
    }
}
