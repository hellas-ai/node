//! Per-slot stream state.

use web_time::Instant;

use crate::frame::Frame;

/// Slot index = wire stream_id. u16 on the wire.
pub type SlotIndex = u16;

/// Bounded send-queue depth per slot. The SendHalf API only ever
/// queues ONE Body frame at a time (single-frame backpressure
/// contract), so the queue exists to layer in-band control frames
/// (Credit, End, Reset) on top. Bounded at 4 to give headroom; the
/// state machine errors if pushing would exceed it.
pub(crate) const SLOT_QUEUE_CAP: usize = 4;

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

    pub const fn owns_slot(self, idx: SlotIndex) -> bool {
        (idx & 1) == self.parity()
    }
}

/// Lifecycle view of a slot, computed from its two terminal flags by
/// [`StreamSlot::state`]. Not stored — the flags are the source of truth,
/// so state and flags can never disagree.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SlotState {
    /// Neither side has sent its terminal frame.
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
    /// Per-slot outbound staging queue. Bounded at SLOT_QUEUE_CAP.
    /// Credit frames are pushed to the FRONT so they ship ahead of
    /// any queued Body frames — otherwise a slot with a backed-up
    /// send queue can perpetually defer its Credit frame and let the
    /// peer stall at zero credit.
    ///
    /// Body sends still respect the single-frame backpressure contract
    /// on the `SendHalf` API: `send_body()` blocks if a Body is
    /// already queued. The queue exists so the state machine can layer
    /// internal control frames (Credit, End, Reset) on top without
    /// stomping the in-flight Body.
    pub send_queue: std::collections::VecDeque<Frame>,
    /// Whether we've observed the peer's terminal frame (End or Reset).
    pub peer_terminal: bool,
    /// Whether we've sent our terminal frame (End or Reset).
    pub local_terminal: bool,
}

impl StreamSlot {
    /// A freshly-opened slot. Local vs remote origin is not tracked — it
    /// drives no logic and never survived hibernation. `generation` is
    /// bumped by the allocator before the slot is published.
    pub fn open(method_id: u32, opened_at: Instant, initial_credit: u32) -> Self {
        Self {
            generation: 0,
            method_id,
            opened_at,
            deadline: None,
            peer_recv_credit: initial_credit,
            local_recv_credit: initial_credit,
            local_credit_high_water: initial_credit,
            send_queue: std::collections::VecDeque::with_capacity(SLOT_QUEUE_CAP),
            peer_terminal: false,
            local_terminal: false,
        }
    }

    /// Lifecycle view derived from the two terminal flags.
    pub fn state(&self) -> SlotState {
        match (self.local_terminal, self.peer_terminal) {
            (false, false) => SlotState::Open,
            (true, false) => SlotState::HalfClosedLocal,
            (false, true) => SlotState::HalfClosedRemote,
            (true, true) => SlotState::Closed,
        }
    }

    pub fn is_closed(&self) -> bool {
        self.peer_terminal && self.local_terminal
    }
}
