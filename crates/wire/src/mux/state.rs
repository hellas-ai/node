//! `Multiplexer` — the sans-io state machine.

use bytes::Bytes;

use crate::clock::Clock;
use crate::frame::{CreditFrame, EndFrame, Frame, OpenFrame, ResetFrame};
use crate::metadata::{Metadata, Trailer};
use crate::status::WireCode;

use super::slot::{Role, SlotIndex, SlotState, StreamSlot};
use super::wire::{decode_keyed_frame, encode_keyed_frame, StreamKey};

#[derive(Clone, Copy, Debug)]
pub struct MuxConfig {
    pub initial_credit: u32,
    pub credit_refill_ratio: u32,
    pub body_frame_max: usize,
}

impl Default for MuxConfig {
    fn default() -> Self {
        Self {
            initial_credit: super::DEFAULT_INITIAL_CREDIT,
            credit_refill_ratio: super::DEFAULT_CREDIT_REFILL_RATIO,
            body_frame_max: super::DEFAULT_BODY_FRAME_MAX,
        }
    }
}

/// Events surfaced by `recv()` to the application driver. Each event
/// corresponds to a state-machine-validated incoming frame.
#[derive(Clone, Debug)]
pub enum Event {
    NewIncomingStream {
        slot: SlotIndex,
        method_id: u32,
        headers: Metadata,
    },
    BodyChunk {
        slot: SlotIndex,
        payload: Bytes,
    },
    EndStream {
        slot: SlotIndex,
        trailer: Trailer,
    },
    ResetStream {
        slot: SlotIndex,
        code: WireCode,
    },
    /// Peer added more credit; outbound flow may resume on this slot.
    PeerCredit {
        slot: SlotIndex,
        additional_bytes: u32,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum MuxError {
    #[error("at capacity (no free slot of our parity)")]
    AtCapacity,
    #[error("slot {0} is closed")]
    SlotClosed(SlotIndex),
    #[error("slot {0} has insufficient credit")]
    NoCredit(SlotIndex),
    #[error("payload {len} exceeds body-frame max {limit}")]
    BodyTooLarge { len: usize, limit: usize },
    #[error("frame: {0}")]
    Frame(#[from] crate::frame::FrameError),
    #[error("protocol error: {0}")]
    Protocol(&'static str),
}

pub struct Multiplexer<const N: usize, C: Clock> {
    streams: [Option<StreamSlot>; N],
    /// Bitmap of free slot indices. `1` = free. One u64 word per 64 slots;
    /// allocated on construction since stable Rust can't size this as a
    /// const-generic array.
    free_mask: Vec<u64>,
    role: Role,
    /// At most one outbound frame is "currently being shipped" to the
    /// wire. Application driver polls `next_outbound` to drain.
    pending_write: Option<Bytes>,
    /// Round-robin pointer for scheduling outbound from slots.
    rr: u16,
    clock: C,
    config: MuxConfig,
}

impl<const N: usize, C: Clock> Multiplexer<N, C> {
    pub fn new(role: Role, clock: C, config: MuxConfig) -> Self {
        let mut free_mask = vec![0u64; (N + 63) / 64];
        // Mark all parity-owned slots free, others as not-our-domain.
        // We track ALL slots; just keep peer-owned slots out of the
        // free mask (we never allocate them; peer does).
        for i in 0..N as u16 {
            if role.owns_slot(i) {
                free_mask[(i / 64) as usize] |= 1u64 << (i % 64);
            }
        }
        Self {
            streams: [const { None }; N],
            free_mask,
            role,
            pending_write: None,
            rr: 0,
            clock,
            config,
        }
    }

    pub fn role(&self) -> Role {
        self.role
    }

    pub fn config(&self) -> &MuxConfig {
        &self.config
    }

    fn lowest_free(&self) -> Option<SlotIndex> {
        for (word_idx, word) in self.free_mask.iter().enumerate() {
            if *word != 0 {
                let bit = word.trailing_zeros() as u16;
                return Some(word_idx as u16 * 64 + bit);
            }
        }
        None
    }

    fn mark_used(&mut self, idx: SlotIndex) {
        let word = idx / 64;
        let bit = idx % 64;
        self.free_mask[word as usize] &= !(1u64 << bit);
    }

    fn mark_free(&mut self, idx: SlotIndex) {
        // Only mark free if we own this parity; otherwise the peer
        // owns the slot and we shouldn't claim it.
        if self.role.owns_slot(idx) {
            let word = idx / 64;
            let bit = idx % 64;
            self.free_mask[word as usize] |= 1u64 << bit;
        }
    }

    fn slot(&self, idx: SlotIndex) -> Option<&StreamSlot> {
        self.streams.get(idx as usize)?.as_ref()
    }

    fn slot_mut(&mut self, idx: SlotIndex) -> Option<&mut StreamSlot> {
        self.streams.get_mut(idx as usize)?.as_mut()
    }

    // -- Local actions -------------------------------------------------------

    /// Allocate a slot and queue an OPEN frame. Returns the slot index.
    pub fn open(&mut self, method_id: u32, headers: Metadata) -> Result<SlotIndex, MuxError> {
        let idx = self.lowest_free().ok_or(MuxError::AtCapacity)?;
        // Compute new generation from any prior occupant (we keep a
        // generation counter even when slot is Empty by carrying it forward
        // through the Option<StreamSlot>'s prior values; for simplicity
        // we just start at generation=0 first time and bump on each reuse).
        let prev_gen = self
            .streams
            .get(idx as usize)
            .and_then(|s| s.as_ref().map(|s| s.generation))
            .unwrap_or(0u16);
        let next_gen = prev_gen.wrapping_add(1);

        let now = self.clock.now();
        let mut slot = StreamSlot::open_local(method_id, now, self.config.initial_credit);
        slot.generation = next_gen;
        // Queue the OPEN frame for scheduler.
        slot.send_queued = Some(Frame::Open(OpenFrame {
            method_id,
            headers,
        }));
        self.streams[idx as usize] = Some(slot);
        self.mark_used(idx);
        Ok(idx)
    }

    /// Queue a body chunk on this slot. Decrements peer-credit. Errors
    /// if slot is closed, send-half is closed, or insufficient credit.
    pub fn send_body(&mut self, idx: SlotIndex, payload: Bytes) -> Result<(), MuxError> {
        if payload.len() > self.config.body_frame_max {
            return Err(MuxError::BodyTooLarge {
                len: payload.len(),
                limit: self.config.body_frame_max,
            });
        }
        let limit = self.config.body_frame_max;
        let slot = self
            .slot_mut(idx)
            .ok_or(MuxError::Protocol("send on empty slot"))?;
        if matches!(
            slot.state,
            SlotState::HalfClosedLocal | SlotState::Closed
        ) || slot.local_terminal
        {
            return Err(MuxError::SlotClosed(idx));
        }
        if (slot.peer_recv_credit as usize) < payload.len() {
            return Err(MuxError::NoCredit(idx));
        }
        if slot.send_queued.is_some() {
            // Per-slot single staged frame. Caller is expected to wait
            // for poll_ready.
            return Err(MuxError::Protocol("send while previous frame still queued"));
        }
        slot.peer_recv_credit -= payload.len() as u32;
        slot.send_queued = Some(Frame::Body(payload));
        let _ = limit;
        Ok(())
    }

    /// Close the send side. Optionally with a trailer.
    pub fn close_send(
        &mut self,
        idx: SlotIndex,
        trailer: Option<Trailer>,
    ) -> Result<(), MuxError> {
        let slot = self
            .slot_mut(idx)
            .ok_or(MuxError::Protocol("close on empty slot"))?;
        if slot.local_terminal {
            return Ok(());
        }
        if slot.send_queued.is_some() {
            return Err(MuxError::Protocol("close while previous frame still queued"));
        }
        let trailer = trailer.unwrap_or_default();
        let end = EndFrame {
            status: trailer.status,
            trailer,
        };
        slot.local_terminal = true;
        slot.state = match slot.state {
            SlotState::OpenLocal => SlotState::HalfClosedLocal,
            SlotState::Open => SlotState::HalfClosedLocal,
            SlotState::HalfClosedRemote => SlotState::Closed,
            other => other,
        };
        slot.send_queued = Some(Frame::End(end));
        Ok(())
    }

    /// Cancel both directions. Idempotent.
    pub fn reset(&mut self, idx: SlotIndex, code: WireCode) {
        let Some(slot) = self.slot_mut(idx) else {
            return;
        };
        if slot.local_terminal && slot.peer_terminal {
            return;
        }
        slot.local_terminal = true;
        slot.peer_terminal = true;
        slot.state = SlotState::Closed;
        slot.send_queued = Some(Frame::Reset(ResetFrame { code }));
    }

    /// Pull buffered body chunks off the slot for the application.
    pub fn drain_recv(&mut self, idx: SlotIndex) -> Vec<Bytes> {
        let Some(slot) = self.slot_mut(idx) else {
            return Vec::new();
        };
        let drained: Vec<Bytes> = slot.recv_buf.drain(..).collect();
        // Replenish local credit if we've drained below the refill ratio.
        let drained_bytes: u32 = drained.iter().map(|b| b.len() as u32).sum();
        slot.local_recv_credit = slot
            .local_recv_credit
            .saturating_add(drained_bytes)
            .min(slot.local_credit_high_water);
        // Note: a Credit frame is emitted on demand by `prepare_credit_updates`.
        drained
    }

    /// Examine slots and queue Credit frames where local_recv_credit has
    /// fallen below threshold. Returns the slots that were credited.
    pub fn prepare_credit_updates(&mut self) -> Vec<SlotIndex> {
        let mut updated = Vec::new();
        let refill_ratio = self.config.credit_refill_ratio;
        for idx in 0..N {
            let Some(slot) = self.streams[idx].as_mut() else {
                continue;
            };
            if slot.is_closed() || slot.send_queued.is_some() {
                continue;
            }
            let threshold = slot.local_credit_high_water / refill_ratio;
            if slot.local_recv_credit < threshold {
                let add = slot.local_credit_high_water - slot.local_recv_credit;
                slot.local_recv_credit = slot.local_credit_high_water;
                slot.send_queued = Some(Frame::Credit(CreditFrame {
                    additional_bytes: add,
                }));
                updated.push(idx as SlotIndex);
            }
        }
        updated
    }

    // -- I/O surface ---------------------------------------------------------

    /// Drain the next outbound encoded frame. Returns `Some(bytes)` to
    /// ship; `None` if nothing pending.
    ///
    /// Round-robins through slots; honors the single-pending invariant.
    pub fn next_outbound(&mut self) -> Option<Bytes> {
        if let Some(pending) = self.pending_write.take() {
            return Some(pending);
        }
        let start = self.rr;
        for _ in 0..N {
            let idx = self.rr;
            self.rr = (self.rr + 1) % (N as u16);
            let Some(slot) = self.streams.get_mut(idx as usize).and_then(|s| s.as_mut())
            else {
                continue;
            };
            if let Some(frame) = slot.send_queued.take() {
                let key = StreamKey {
                    stream_id: idx,
                    generation: slot.generation,
                };
                let was_terminal = matches!(frame, Frame::End(_) | Frame::Reset(_));
                let bytes = encode_keyed_frame(key, &frame);
                if was_terminal {
                    self.maybe_free_slot(idx);
                }
                return Some(bytes);
            }
        }
        let _ = start;
        None
    }

    fn maybe_free_slot(&mut self, idx: SlotIndex) {
        let Some(slot) = self.slot(idx) else { return };
        if slot.peer_terminal && slot.local_terminal {
            // Keep the generation counter by leaving the slot inhabited but
            // mark it free for reuse and clear buffers.
            if let Some(s) = self.streams.get_mut(idx as usize).and_then(|s| s.as_mut()) {
                s.state = SlotState::Closed;
                s.recv_buf.clear();
                s.send_queued = None;
            }
            self.mark_free(idx);
        }
    }

    /// Feed an inbound keyed-frame's bytes. Validates, applies state
    /// transitions, returns observable events. Stale-generation frames are
    /// discarded with no event.
    pub fn recv(&mut self, bytes: &[u8]) -> Result<Vec<Event>, MuxError> {
        let keyed = decode_keyed_frame(bytes)?;
        let idx = keyed.key.stream_id;
        if idx as usize >= N {
            return Err(MuxError::Protocol("stream id out of range"));
        }
        let mut events = Vec::new();

        // Handle Open specially — slot may be Empty (legitimate fresh open)
        // or in some terminal/transitional state.
        if let Frame::Open(open) = &keyed.frame {
            // Open from peer: must be peer-owned parity.
            if self.role.owns_slot(idx) {
                return Err(MuxError::Protocol(
                    "peer opened a slot owned by our parity",
                ));
            }
            // Stale-generation check: if slot exists, compare gens.
            if let Some(existing) = self.slot(idx) {
                if !existing.is_closed() {
                    return Err(MuxError::Protocol("peer re-opened active slot"));
                }
                // Slot closed; peer can reuse but must bump generation.
                if keyed.key.generation == existing.generation {
                    return Err(MuxError::Protocol(
                        "peer reused slot without bumping generation",
                    ));
                }
            }
            let now = self.clock.now();
            let mut slot =
                StreamSlot::open_remote(open.method_id, now, self.config.initial_credit);
            slot.generation = keyed.key.generation;
            self.streams[idx as usize] = Some(slot);
            events.push(Event::NewIncomingStream {
                slot: idx,
                method_id: open.method_id,
                headers: open.headers.clone(),
            });
            return Ok(events);
        }

        // Non-Open frames: slot must exist with matching generation.
        let slot = match self.slot_mut(idx) {
            Some(s) => s,
            None => return Ok(events), // stale; drop silently
        };
        if slot.generation != keyed.key.generation {
            return Ok(events); // stale-generation drop
        }
        if slot.peer_terminal {
            return Ok(events); // peer already terminal; drop late frames
        }

        match keyed.frame {
            Frame::Open(_) => unreachable!("handled above"),
            Frame::Body(payload) => {
                let n = payload.len() as u32;
                if n > slot.local_recv_credit {
                    // Peer overran our credit. Reset their stream.
                    let code = WireCode::ResourceExhausted;
                    slot.peer_terminal = true;
                    slot.local_terminal = true;
                    slot.state = SlotState::Closed;
                    slot.send_queued = Some(Frame::Reset(ResetFrame { code }));
                    events.push(Event::ResetStream { slot: idx, code });
                    return Ok(events);
                }
                slot.local_recv_credit -= n;
                slot.recv_buf.push_back(payload.clone());
                events.push(Event::BodyChunk {
                    slot: idx,
                    payload,
                });
            }
            Frame::End(end) => {
                slot.peer_terminal = true;
                slot.recv_trailer = Some(end.trailer.clone());
                slot.state = match slot.state {
                    SlotState::OpenRemote => SlotState::HalfClosedRemote,
                    SlotState::Open => SlotState::HalfClosedRemote,
                    SlotState::HalfClosedLocal => SlotState::Closed,
                    other => other,
                };
                events.push(Event::EndStream {
                    slot: idx,
                    trailer: end.trailer,
                });
                self.maybe_free_slot(idx);
            }
            Frame::Reset(r) => {
                slot.peer_terminal = true;
                slot.local_terminal = true;
                slot.state = SlotState::Closed;
                events.push(Event::ResetStream {
                    slot: idx,
                    code: r.code,
                });
                self.maybe_free_slot(idx);
            }
            Frame::Credit(c) => {
                slot.peer_recv_credit =
                    slot.peer_recv_credit.saturating_add(c.additional_bytes);
                events.push(Event::PeerCredit {
                    slot: idx,
                    additional_bytes: c.additional_bytes,
                });
            }
        }
        Ok(events)
    }

    /// Inspect a slot's current peer-receive credit. Useful for the
    /// SendHalf to decide whether `poll_ready` should return Ready.
    pub fn peer_credit(&self, idx: SlotIndex) -> u32 {
        self.slot(idx).map(|s| s.peer_recv_credit).unwrap_or(0)
    }

    /// Whether this slot is ready to accept another `send_body` /
    /// `close_send`. `false` means a frame is already queued and the
    /// caller must wait for `next_outbound` to drain it.
    pub fn send_ready(&self, idx: SlotIndex) -> bool {
        self.slot(idx)
            .map(|s| s.send_queued.is_none())
            .unwrap_or(false)
    }

    /// Whether this slot has any pending recv chunks for the app.
    pub fn recv_pending(&self, idx: SlotIndex) -> bool {
        self.slot(idx)
            .map(|s| !s.recv_buf.is_empty())
            .unwrap_or(false)
    }

    /// Trailer captured from inbound End / Reset, if any.
    pub fn recv_trailer(&self, idx: SlotIndex) -> Option<Trailer> {
        self.slot(idx).and_then(|s| s.recv_trailer.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::DefaultClock;

    fn pair<const N: usize>() -> (Multiplexer<N, DefaultClock>, Multiplexer<N, DefaultClock>) {
        let cfg = MuxConfig::default();
        (
            Multiplexer::<N, _>::new(Role::Client, DefaultClock, cfg),
            Multiplexer::<N, _>::new(Role::Server, DefaultClock, cfg),
        )
    }

    fn drain<const N: usize>(
        from: &mut Multiplexer<N, DefaultClock>,
        to: &mut Multiplexer<N, DefaultClock>,
    ) -> Vec<Event> {
        let mut all_events = Vec::new();
        while let Some(bytes) = from.next_outbound() {
            let events = to.recv(&bytes).unwrap();
            all_events.extend(events);
        }
        all_events
    }

    #[test]
    fn open_send_close_roundtrip() {
        let (mut client, mut server) = pair::<32>();
        let slot = client.open(0xCAFEBABE, Metadata::new()).unwrap();
        assert_eq!(slot, 0); // client owns even, lowest is 0

        let events = drain(&mut client, &mut server);
        assert_eq!(events.len(), 1);
        match &events[0] {
            Event::NewIncomingStream {
                slot: s,
                method_id,
                ..
            } => {
                assert_eq!(*s, 0);
                assert_eq!(*method_id, 0xCAFEBABE);
            }
            _ => panic!("expected NewIncomingStream"),
        }

        client
            .send_body(slot, Bytes::from_static(b"hello"))
            .unwrap();
        let events = drain(&mut client, &mut server);
        match &events[0] {
            Event::BodyChunk { slot: s, payload } => {
                assert_eq!(*s, 0);
                assert_eq!(payload.as_ref(), b"hello");
            }
            _ => panic!("expected BodyChunk"),
        }

        client.close_send(slot, None).unwrap();
        let events = drain(&mut client, &mut server);
        match &events[0] {
            Event::EndStream { slot: s, .. } => assert_eq!(*s, 0),
            _ => panic!("expected EndStream"),
        }
    }

    #[test]
    fn parity_ownership() {
        let mut server: Multiplexer<32, _> =
            Multiplexer::new(Role::Server, DefaultClock, MuxConfig::default());
        let slot = server.open(0x1, Metadata::new()).unwrap();
        assert_eq!(slot & 1, 1); // server owns odd
        assert_eq!(slot, 1);
    }

    #[test]
    fn stale_gen_discarded() {
        let (mut client, mut server) = pair::<32>();
        let s1 = client.open(0x1, Metadata::new()).unwrap();
        // Drain the open so server knows about the slot.
        drain(&mut client, &mut server);

        // Send a body, encode it, but withhold delivery to server.
        client.send_body(s1, Bytes::from_static(b"x")).unwrap();
        let stale_bytes = client.next_outbound().unwrap();

        // Now reset and reuse the slot.
        client.reset(s1, WireCode::Cancelled);
        // Deliver the reset to server.
        let reset_bytes = client.next_outbound().unwrap();
        let _ = server.recv(&reset_bytes).unwrap();

        // Re-open: same slot index, new generation.
        let s2 = client.open(0x2, Metadata::new()).unwrap();
        assert_eq!(s2, s1);
        // Drain the new open.
        let open_bytes = client.next_outbound().unwrap();
        let _ = server.recv(&open_bytes).unwrap();

        // NOW deliver the stale body. Should be discarded.
        let events = server.recv(&stale_bytes).unwrap();
        assert!(
            events.is_empty(),
            "stale-generation body should produce no events"
        );
    }
}
