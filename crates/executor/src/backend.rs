use catgrad::interpreter::backend::candle::CandleBackend;
use std::sync::OnceLock;
use tracing::info;

pub type ExecBackend = CandleBackend;

static EXEC_BACKEND: OnceLock<ExecBackend> = OnceLock::new();

fn init_backend() -> ExecBackend {
    #[cfg(any(feature = "candle-cuda", feature = "candle-metal"))]
    {
        let backend = CandleBackend::new_accel(true);
        info!(?backend, "executor backend selected");
        return backend;
    }

    #[cfg(not(any(feature = "candle-cuda", feature = "candle-metal")))]
    {
        let backend = CandleBackend::new();
        info!(?backend, "executor backend selected");
        backend
    }
}

pub fn create_backend() -> ExecBackend {
    EXEC_BACKEND.get_or_init(init_backend).clone()
}
