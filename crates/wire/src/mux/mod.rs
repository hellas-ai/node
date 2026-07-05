//! Sans-io multiplexer state machine.
//!
//! One `Multiplexer<N, C>` per underlying byte pipe. Slot index doubles
//! as stream id. Per-slot `gen: u16` defeats stale-frame races across
//! re-use. Credit-based per-stream flow control. Single pending wire
//! write so applications drive their own outbound queues.
//!
//! `recv(bytes) -> Vec<Event>` and `poll_send() -> Option<EncodedFrame>`
//! are the entire I/O-shaped surface; transports glue them to actual
//! sockets.

pub(crate) mod slot;
mod state;
mod wire;

pub mod stream;
pub mod transport;

pub use slot::{Role, SlotIndex, SlotState, StreamSlot};
pub use state::{Event, Multiplexer, MuxConfig, MuxError};
pub use stream::{MuxRecvHalf, MuxSendHalf, MuxStream, MuxStreamError};
pub use transport::{MessagePipe, MuxTransport, MuxTransportError};
pub use wire::{KeyedFrame, StreamKey, decode_keyed_frame, encode_keyed_frame};

/// Default body-frame max in bytes. Configurable per-transport.
pub const DEFAULT_BODY_FRAME_MAX: usize = 1024 * 1024; // 1 MiB

/// Default initial credit per direction per stream.
pub const DEFAULT_INITIAL_CREDIT: u32 = 64 * 1024; // 64 KiB

/// Default credit-update threshold: replenish when `local_recv_credit`
/// drops below half of initial.
pub const DEFAULT_CREDIT_REFILL_RATIO: u32 = 2;
