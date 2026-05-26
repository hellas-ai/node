//! WebSocket transports — share the sans-io `mux` state machine and
//! differ only in their I/O glue.
//!
//! - `native` (feature `ws`): tokio-tungstenite adapter for native hosts.
//! - `wasm` (feature `ws-wasm`): ws_stream_wasm adapter for browsers.
//! - `cf_do` (feature `ws-cf-do`): callback driver for Cloudflare
//!   Durable Objects; hibernation-safe via attachment serialization.

#[cfg(all(feature = "ws", not(target_family = "wasm")))]
pub mod native;

#[cfg(all(feature = "ws", not(target_family = "wasm")))]
pub use native::{WsError, WsPipe, accept_upgraded, connect};

#[cfg(all(feature = "ws-wasm", target_family = "wasm"))]
pub mod wasm;

#[cfg(feature = "ws-cf-do")]
pub mod cf_do;

/// WebSocket transport handle. Just a `MuxTransport`; the WS-specific
/// adapter feeds the mux's I/O driver via the [`crate::mux::MessagePipe`]
/// trait. Created via [`native::connect`] / [`native::accept_upgraded`].
/// (Wasm32 callers — including CF Durable Objects — use the callback
/// driver in `cf_do`, not this alias.)
#[cfg(all(feature = "mux", not(target_family = "wasm")))]
pub type WsTransport = crate::mux::MuxTransport;
