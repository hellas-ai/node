//! Wire-status mapping for model-asset errors. Lives here (not in the
//! executor's error module) because `ModelAssetsError` is ours and the
//! orphan rule requires the `From<_> for WireStatus` impl to sit beside it.

use hellas_wire::{WireCode, WireStatus};

use crate::ModelAssetsError;

/// Maps a model-asset error to its wire status code.
pub fn model_assets_wire_code(err: &ModelAssetsError) -> WireCode {
    match err {
        ModelAssetsError::Spec(_)
        | ModelAssetsError::Model(_)
        | ModelAssetsError::ParseModelMetadata { .. }
        | ModelAssetsError::InvalidModelIndex
        | ModelAssetsError::InvalidProgramGraph
        | ModelAssetsError::UnresolvedRevision
        | ModelAssetsError::MissingChatTemplate
        | ModelAssetsError::NegativeStopTokenId { .. }
        | ModelAssetsError::TokenBytes { .. } => WireCode::InvalidArgument,
        // Not the caller's fault and not a server fault: a state of this
        // node the operator can change. A client may legitimately retry
        // after asking for the model to be made available.
        ModelAssetsError::NotMaterialized { .. } => WireCode::FailedPrecondition,
        _ => WireCode::Internal,
    }
}

impl From<ModelAssetsError> for WireStatus {
    fn from(err: ModelAssetsError) -> Self {
        WireStatus::new(model_assets_wire_code(&err), err.to_string())
    }
}
