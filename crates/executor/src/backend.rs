use crate::BackendInitError;
use catgrad::interpreter::backend::candle::CandleBackend;
use std::any::Any;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::OnceLock;
use tracing::info;

pub type ExecBackend = CandleBackend;

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
    .map_err(|panic| {
        BackendInitError::new(format!(
            "failed to initialize executor backend: {}",
            panic_message(&panic)
        ))
    })?;

    info!(?backend, "executor backend selected");
    Ok(backend)
}

pub fn create_backend() -> Result<ExecBackend, BackendInitError> {
    EXEC_BACKEND.get_or_init(init_backend).clone()
}

/// Which of `requested` the backend that was actually selected can run.
///
/// The build features say which backend was *compiled in*, not which
/// device is here. `CandleBackend::new_accel(true)` falls back to the CPU
/// device when no CUDA or Metal device is present, so a `candle-cuda`
/// build on a host without a GPU runs on the CPU — while everything that
/// derives a dtype capability from `cfg!` still says BF16.
///
/// Candle does not merely refuse BF16 on a CPU device, it **panics**
/// (`BF16 is only supported by Candle on CUDA/Metal devices`,
/// catgrad `interpreter/backend/candle.rs`). The executor catches that
/// panic and fails the job, so the shape of the bug is not a crash: it is
/// a capability advertised that every accepted job fails to honour, after
/// reading gigabytes. Under the staked flow that is work a provider
/// committed to and can never deliver.
///
/// So the advertisement is filtered by the device, at startup, once.
#[must_use]
pub(crate) fn runnable_dtypes(
    backend: &ExecBackend,
    requested: &[hellas_rpc::Dtype],
) -> Vec<hellas_rpc::Dtype> {
    requested
        .iter()
        .copied()
        .filter(|dtype| match dtype {
            hellas_rpc::Dtype::BF16 => backend.device().supports_bf16(),
            _ => true,
        })
        .collect()
}

pub(crate) fn panic_message(panic: &(dyn Any + Send)) -> String {
    if let Some(message) = panic.downcast_ref::<&'static str>() {
        (*message).to_string()
    } else if let Some(message) = panic.downcast_ref::<String>() {
        message.clone()
    } else {
        "unknown panic".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hellas_rpc::Dtype;

    /// `CandleBackend::new()` is the CPU device by construction, so this
    /// holds on every build — including a `candle-cuda` one, which is
    /// exactly the build that gets this device on a host with no GPU.
    ///
    /// The other two dtypes are the control: a filter that dropped
    /// everything would satisfy the first claim and serve nothing.
    #[test]
    fn a_cpu_device_serves_everything_except_bf16() {
        let cpu = CandleBackend::new();
        assert_eq!(
            runnable_dtypes(&cpu, &[Dtype::BF16, Dtype::F32, Dtype::F16]),
            vec![Dtype::F32, Dtype::F16],
        );
        assert_eq!(runnable_dtypes(&cpu, &[Dtype::BF16]), Vec::new());
    }
}
