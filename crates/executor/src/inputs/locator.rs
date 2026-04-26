use catgrad::prelude::Dtype;
use hellas_rpc::spec::ModelSpec;

/// Pre-load address: a HuggingFace model + revision, plus the dtype to load
/// it at.
///
/// `dtype` is intentionally a concrete value, not `Option<Dtype>` or an
/// `Auto` variant. Tensors load dtype-specifically, and silently reusing an
/// F32-loaded bundle when an F16 graph is requested (or vice versa) would
/// return wrong outputs.
///
/// Future cache sources (e.g. resolution by `Cid<InputsManifest>` over
/// iroh-blobs) would be sibling locator types in this module.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct HuggingFaceLocator {
    pub model_id: String,
    pub revision: String,
    pub dtype: Dtype,
}

impl HuggingFaceLocator {
    pub fn new(model_id: String, revision: String, dtype: Dtype) -> Self {
        Self {
            model_id,
            revision,
            dtype,
        }
    }

    pub fn from_spec(spec: ModelSpec, dtype: Dtype) -> Self {
        Self::new(spec.id, spec.revision, dtype)
    }
}

impl std::fmt::Display for HuggingFaceLocator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}@{}:{:?}", self.model_id, self.revision, self.dtype)
    }
}
