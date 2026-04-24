use crate::backend::ExecBackend;
use hellas_rpc::spec::ModelSpec;
use catgrad::interpreter;
use catgrad::typecheck;
use thiserror::Error;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct WeightsLocator {
    pub model_id: String,
    pub revision: String,
}

impl std::fmt::Display for WeightsLocator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}@{}", self.model_id, self.revision)
    }
}

impl From<ModelSpec> for WeightsLocator {
    fn from(spec: ModelSpec) -> Self {
        Self {
            model_id: spec.id,
            revision: spec.revision,
        }
    }
}

#[derive(Clone)]
pub(crate) struct WeightsBundle {
    pub parameter_values: interpreter::Parameters<ExecBackend>,
    pub parameter_types: typecheck::Parameters,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum EnsureDisposition {
    Ready,
    Queued,
    InFlight,
    Failed(String),
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub(crate) enum WeightsError {
    #[error("weights not ready")]
    NotReady,
    #[error("weights failed: {0}")]
    Failed(String),
    #[error("unknown weights key")]
    UnknownKey,
}
