use crate::backend::ExecBackend;
use catgrad::runtime::Inputs;

/// [`Inputs`] loaded for a [`super::HuggingFaceLocator`], with tensor CIDs
/// already computed at load time (catgrad does this inside `Inputs::new`).
/// Reused across every quote that runs against this weight set; sharing
/// via `Arc` avoids ever cloning the multi-GB tensor interior.
#[derive(Clone)]
pub(crate) struct Bundle {
    pub inputs: Inputs<ExecBackend>,
}
