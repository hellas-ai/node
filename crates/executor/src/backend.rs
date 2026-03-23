use catgrad::interpreter::backend::candle::CandleBackend;
use std::any::Any;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::OnceLock;
use thiserror::Error;
use tracing::info;

pub type ExecBackend = CandleBackend;

#[derive(Clone, Debug, Error)]
#[error("{message}")]
pub struct BackendInitError {
    message: String,
}

static EXEC_BACKEND: OnceLock<Result<ExecBackend, BackendInitError>> = OnceLock::new();

fn init_backend() -> Result<ExecBackend, BackendInitError> {
    let backend = catch_unwind(AssertUnwindSafe(|| {
        #[cfg(any(feature = "candle-cuda", feature = "candle-metal"))]
        {
            CandleBackend::new_accel(true)
        }

        #[cfg(not(any(feature = "candle-cuda", feature = "candle-metal")))]
        {
            CandleBackend::new()
        }
    }))
    .map_err(|panic| BackendInitError {
        message: format!(
            "failed to initialize executor backend: {}",
            panic_message(&panic)
        ),
    })?;

    info!(?backend, "executor backend selected");
    Ok(backend)
}

pub fn create_backend() -> Result<ExecBackend, BackendInitError> {
    EXEC_BACKEND.get_or_init(init_backend).clone()
}

fn panic_message(panic: &(dyn Any + Send)) -> String {
    if let Some(message) = panic.downcast_ref::<&'static str>() {
        (*message).to_string()
    } else if let Some(message) = panic.downcast_ref::<String>() {
        message.clone()
    } else {
        "unknown panic".to_string()
    }
}
