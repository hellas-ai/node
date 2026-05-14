//! Per-slot stream state.

use bytes::Bytes;
use web_time::Instant;

use crate::frame::Frame;

/// Slot index = wire stream_id. u16 on the wire.
pub type SlotIndex = u16;

/// Which side allocated the underlying transport connection. The role
/// determines which slot indices we may allocate locally:
/// `Client` -> even indices; `Server` -> odd indices.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    Client,
    Server,
}

impl Role {
    pub const fn parity(self) -> u16 {
        match self {
            Self::Client => 0,
            Self::Server => 1,
        }
    }

    pub const fn peer(self) -> Self {
        match self {
            Self::Client => Self::Server,
            Self::Server => Self::Client,
        }
    }

    pub const fn owns_slot(self, idx: SlotIndex) -> bool {
        (idx & 1) == self.parity()
    }
}

/// Lifecycle states for a slot. Transitions defined by the state
/// machine in `state.rs`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SlotState {
    /// We sent OPEN; awaiting first inbound activity from peer.
    OpenLocal,
    /// Peer sent OPEN; awaiting first outbound from us.
    OpenRemote,
    /// Both directions live.
    Open,
    /// We closed send; can still receive.
    HalfClosedLocal,
    /// Peer closed send; we can still send.
    HalfClosedRemote,
    /// Both ends closed.
    Closed,
}

pub struct StreamSlot {
    pub generation: u16,
    pub state: SlotState,
    pub method_id: u32,
    pub opened_at: Instant,
    pub deadline: Option<Instant>,
    /// Bytes the peer is willing to receive from us. Decremented on
    /// outbound Body; replenished on inbound Credit.
    pub peer_recv_credit: u32,
    /// Bytes we are willing to receive from peer. Decremented on
    /// inbound Body; replenished by sending Credit frames.
    pub local_recv_credit: u32,
    /// Initial local recv credit (used to decide when to refill).
    pub local_credit_high_water: u32,
    /// Per-slot single-frame outbound staging. `None` means slot is
    /// not currently asking for a write slot.
    pub send_queued: Option<Frame>,
    /// Whether we've observed the peer's terminal frame (End or Reset).
    pub peer_terminal: bool,
    /// Whether we've sent our terminal frame (End or Reset).
    pub local_terminal: bool,
    /// Recv-side buffer of in-flight Body bytes pending application
    /// consumption. Plain `VecDeque<Bytes>` so we don't merge across
    /// allocations.
    pub recv_buf: std::collections::VecDeque<Bytes>,
    /// Trailer captured from inbound End / synthesized from Reset.
    pub recv_trailer: Option<crate::metadata::Trailer>,
}

impl StreamSlot {
    pub fn open_local(method_id: u32, opened_at: Instant, initial_credit: u32) -> Self {
        Self {
            generation: 0, // bumped by the allocator before construction-and-publish
            state: SlotState::OpenLocal,
            method_id,
            opened_at,
            deadline: None,
            peer_recv_credit: initial_credit,
            local_recv_credit: initial_credit,
            local_credit_high_water: initial_credit,
            send_queued: None,
            peer_terminal: false,
            local_terminal: false,
            recv_buf: Default::default(),
            recv_trailer: None,
        }
    }

    pub fn open_remote(method_id: u32, opened_at: Instant, initial_credit: u32) -> Self {
        Self {
            generation: 0,
            state: SlotState::OpenRemote,
            method_id,
            opened_at,
            deadline: None,
            peer_recv_credit: initial_credit,
            local_recv_credit: initial_credit,
            local_credit_high_water: initial_credit,
            send_queued: None,
            peer_terminal: false,
            local_terminal: false,
            recv_buf: Default::default(),
            recv_trailer: None,
        }
    }

    pub fn is_closed(&self) -> bool {
        self.peer_terminal && self.local_terminal
    }
}
