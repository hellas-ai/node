use crate::backend::ExecBackend;
use catgrad::interpreter;

/// Materialized parameter tensors loaded for a [`super::HuggingFaceLocator`].
/// Reused across every quote that runs against this weight set; sharing
/// via `Arc` avoids ever cloning the multi-GB tensor interior.
///
/// Per-tensor CIDs are derived at bind time inside
/// [`hellas_runtime::graph::BoundProgram::bind`] and cached on the resulting
/// [`hellas_runtime::graph::BoundProgram`] — the bundle itself is CID-free.
#[derive(Clone)]
pub(crate) struct Bundle {
    pub inputs: interpreter::Parameters<ExecBackend>,
}
