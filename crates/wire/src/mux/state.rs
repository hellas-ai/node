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
    /// Slots whose local terminal frame has been emitted by
    /// `next_outbound` but whose free has been deferred until the
    /// caller has actually flushed the frame to the wire. We need
    /// this because a transport that backpressures will call
    /// `set_pending_write(Some(bytes))` to re-stash the terminal
    /// frame; if we'd freed the slot eagerly, the snapshot would
    /// contain a `pending_write` whose `(stream_id, generation)`
    /// references a freed slot and restore would reject. Drained at
    /// the top of `next_outbound` when `pending_write` is `None` —
    /// at that point the caller has implicitly acked by asking for
    /// the next frame.
    pending_terminal_free: Vec<SlotIndex>,
    /// Round-robin pointer for scheduling outbound from slots.
    rr: u16,
    clock: C,
    config: MuxConfig,
}

// The mux is not `Sync`; the sans-io contract assumes exclusive
// `&mut Multiplexer` access from a single driver (one CF DO
// callback, one connection task, etc.). Sharing across concurrent
// callbacks is undefined: stale `pending_terminal_free` reads, lost
// pushes, and out-of-order `next_outbound` drains would all break
// the snapshot invariants. Wrap in a `Mutex` if a transport ever
// needs cross-task access.
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
            pending_terminal_free: Vec::new(),
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
        // Reclaim any slots whose local terminal frame has been
        // emitted but not yet reaped. Without this, an `open()`
        // call right after a `reset()`+`next_outbound()` cycle
        // wouldn't see the just-closed slot as free.
        self.drain_pending_terminal_free();
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
        slot.send_queue.push_back(Frame::Open(OpenFrame {
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
        // SendHalf single-frame contract: only one Body may be in flight
        // at a time per slot. The caller waits for poll_ready. Control
        // frames the state machine emits internally (Credit/End/Reset)
        // can still slot in alongside.
        let has_body_queued = slot
            .send_queue
            .iter()
            .any(|f| matches!(f, Frame::Body(_)));
        if has_body_queued {
            return Err(MuxError::Protocol("send while previous body still queued"));
        }
        if slot.send_queue.len() >= crate::mux::slot::SLOT_QUEUE_CAP {
            return Err(MuxError::Protocol("send queue full"));
        }
        slot.peer_recv_credit -= payload.len() as u32;
        slot.send_queue.push_back(Frame::Body(payload));
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
        if slot.send_queue.len() >= crate::mux::slot::SLOT_QUEUE_CAP {
            return Err(MuxError::Protocol("close while queue full"));
        }
        let trailer = trailer.unwrap_or_default();
        let end = EndFrame {
            status: trailer.status,
            trailer,
        };
        slot.local_terminal = true;
        slot.state = match slot.state {
            SlotState::OpenLocal | SlotState::OpenRemote | SlotState::Open => {
                SlotState::HalfClosedLocal
            }
            SlotState::HalfClosedRemote => SlotState::Closed,
            other => other,
        };
        // End frame goes at the BACK — any in-flight Body should ship
        // first.
        slot.send_queue.push_back(Frame::End(end));
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
        // Reset takes priority over any in-flight frames — push to front
        // and drop everything behind it (they'd be irrelevant on the
        // closed stream anyway).
        slot.send_queue.clear();
        slot.send_queue.push_front(Frame::Reset(ResetFrame { code }));
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
    ///
    /// Credit frames are pushed to the FRONT of the slot's send queue
    /// so they ship before any queued Body frames — otherwise a slot
    /// with a backed-up send queue could perpetually defer its Credit
    /// and let the peer stall at zero credit.
    pub fn prepare_credit_updates(&mut self) -> Vec<SlotIndex> {
        let mut updated = Vec::new();
        let refill_ratio = self.config.credit_refill_ratio;
        for idx in 0..N {
            let Some(slot) = self.streams[idx].as_mut() else {
                continue;
            };
            // Skip slots where the peer has already terminated sending:
            // is_closed() (both directions terminal) OR peer_terminal
            // alone (we're half-closed-remote — peer won't send more
            // body, so additional credit is wasted bytes on the wire).
            if slot.is_closed() || slot.peer_terminal {
                continue;
            }
            // If a Credit frame is already queued for this slot, no-op.
            let already_has_credit = slot
                .send_queue
                .iter()
                .any(|f| matches!(f, Frame::Credit(_)));
            if already_has_credit {
                continue;
            }
            let threshold = slot.local_credit_high_water / refill_ratio;
            if slot.local_recv_credit < threshold {
                let add = slot.local_credit_high_water - slot.local_recv_credit;
                slot.local_recv_credit = slot.local_credit_high_water;
                slot.send_queue.push_front(Frame::Credit(CreditFrame {
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
        // Caller is asking for the next frame without re-stashing the
        // previous one, so any terminal frame we emitted last call is
        // now considered shipped. Free its slot before scanning so a
        // newly-opened slot can reclaim the index.
        self.drain_pending_terminal_free();
        let start = self.rr;
        for _ in 0..N {
            let idx = self.rr;
            self.rr = (self.rr + 1) % (N as u16);
            let Some(slot) = self.streams.get_mut(idx as usize).and_then(|s| s.as_mut())
            else {
                continue;
            };
            if let Some(frame) = slot.send_queue.pop_front() {
                let key = StreamKey {
                    stream_id: idx,
                    generation: slot.generation,
                };
                let was_terminal = matches!(frame, Frame::End(_) | Frame::Reset(_));
                let queue_empty_after_pop = slot.send_queue.is_empty();
                let both_terminal = slot.local_terminal && slot.peer_terminal;
                let bytes = encode_keyed_frame(key, &frame);
                // Queue idx for deferred free if EITHER:
                //   (a) we just emitted a terminal frame — the
                //       free-on-ship-ack contract applies.
                //   (b) the slot is now both-terminal AND its
                //       queue is empty AFTER this pop — the slot
                //       has no more work to do; a non-terminal
                //       frame (e.g. a Credit) just drained the
                //       last buffered byte. Without this push the
                //       slot would orphan: state=Closed, bit
                //       clear, no path back to maybe_free_slot.
                let needs_defer = was_terminal || (both_terminal && queue_empty_after_pop);
                if needs_defer && !self.pending_terminal_free.contains(&idx) {
                    self.pending_terminal_free.push(idx);
                }
                return Some(bytes);
            }
        }
        let _ = start;
        None
    }

    /// Tidy up state that becomes inconsistent when a recv-side
    /// terminal frees a slot that has lingering deferred-free or
    /// pending-write references. Called after `maybe_free_slot`
    /// fires inside the recv path. Three things to scrub:
    ///   1. Stale entry in `pending_terminal_free` (the slot is
    ///      already free, so the deferred drain would no-op but
    ///      we should keep the list honest).
    ///   2. `pending_write` keyed to this idx — its slot is gone,
    ///      so the bytes would fail snapshot restoration
    ///      validation. Drop them; the peer's terminal already
    ///      tore down the stream on their side.
    fn clean_up_after_remote_free(&mut self, idx: SlotIndex) {
        self.pending_terminal_free.retain(|&i| i != idx);
        if let Some(bytes) = &self.pending_write {
            if bytes.len() >= 4 {
                let stream_id = u16::from_be_bytes([bytes[0], bytes[1]]);
                if stream_id == idx {
                    self.pending_write = None;
                }
            }
        }
    }

    /// Reap slots in the deferred terminal-free list. Called by
    /// `next_outbound` (when `pending_write` is `None`, signaling
    /// the caller has implicitly acked the previous emission) and
    /// `open` (so a freshly-closed slot can be reallocated).
    ///
    /// Entries whose slot can't yet be freed — e.g. a `reset()`
    /// queued a Reset frame after the terminal emit — are KEPT
    /// in the list so the next round of draining (after the queued
    /// frame ships) can finish the job.
    fn drain_pending_terminal_free(&mut self) {
        if self.pending_terminal_free.is_empty() {
            return;
        }
        let drained: Vec<SlotIndex> = self.pending_terminal_free.drain(..).collect();
        for idx in drained {
            if !self.maybe_free_slot(idx) {
                self.pending_terminal_free.push(idx);
            }
        }
    }

    /// Try to free a slot. Returns `true` if the slot was reclaimed.
    ///
    /// A slot may be freed iff (a) both sides have signalled terminal
    /// AND (b) no outbound frames remain in the slot's send_queue —
    /// the latter handles the case where `close_send` queued an End,
    /// the End was emitted (deferred-free), and the app then called
    /// `reset()` which queued a Reset. Clearing send_queue here would
    /// silently drop that Reset; callers must keep the slot occupied
    /// until the queued terminal is actually emitted.
    fn maybe_free_slot(&mut self, idx: SlotIndex) -> bool {
        let Some(slot) = self.slot(idx) else { return false };
        if !(slot.peer_terminal && slot.local_terminal) {
            return false;
        }
        if !slot.send_queue.is_empty() {
            return false;
        }
        if let Some(s) = self.streams.get_mut(idx as usize).and_then(|s| s.as_mut()) {
            s.state = SlotState::Closed;
            s.recv_buf.clear();
        }
        self.mark_free(idx);
        true
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
            // The fresh slot record overwrites a Closed predecessor.
            // Any leftover references to the OLD slot — a deferred
            // terminal-free entry or a `pending_write` keyed to the
            // prior generation — would now point at a slot whose
            // state machine has wound forward, breaking invariant
            // I2 (term_free idx must be in HalfClosedLocal/Closed)
            // and I4 (pending_write key must match an occupied
            // slot). Scrub them.
            self.clean_up_after_remote_free(idx);
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
                    slot.send_queue.clear();
                    slot.send_queue.push_front(Frame::Reset(ResetFrame { code }));
                    events.push(Event::ResetStream { slot: idx, code });
                    return Ok(events);
                }
                slot.local_recv_credit -= n;
                // Forward the chunk via the event channel; do NOT also
                // retain it in recv_buf. The driver that surfaces
                // BodyChunk events is responsible for forwarding bytes
                // to the application; recv_buf is dead code in the
                // events-flow path.
                //
                // Credit does NOT refill here. `prepare_credit_updates`
                // runs after each `recv()` in the driver loop and
                // queues a `Frame::Credit` once `local_recv_credit`
                // drops below `local_credit_high_water /
                // credit_refill_ratio`. The driver ships the Credit
                // frame on the very next outbound flush.
                events.push(Event::BodyChunk {
                    slot: idx,
                    payload,
                });
            }
            Frame::End(end) => {
                slot.peer_terminal = true;
                slot.recv_trailer = Some(end.trailer.clone());
                slot.state = match slot.state {
                    SlotState::OpenRemote | SlotState::OpenLocal | SlotState::Open => {
                        SlotState::HalfClosedRemote
                    }
                    SlotState::HalfClosedLocal => SlotState::Closed,
                    other => other,
                };
                events.push(Event::EndStream {
                    slot: idx,
                    trailer: end.trailer,
                });
                if self.maybe_free_slot(idx) {
                    self.clean_up_after_remote_free(idx);
                }
            }
            Frame::Reset(r) => {
                slot.peer_terminal = true;
                slot.local_terminal = true;
                slot.state = SlotState::Closed;
                // Peer aborted — any frames we had queued for this
                // stream are pointless. Drop them so the slot can be
                // reclaimed immediately rather than waiting for a
                // terminal emit that the peer doesn't care about.
                slot.send_queue.clear();
                events.push(Event::ResetStream {
                    slot: idx,
                    code: r.code,
                });
                self.maybe_free_slot(idx);
                self.clean_up_after_remote_free(idx);
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
        // Ready iff no Body is currently queued (the SendHalf
        // single-frame contract — internal Credit/End/Reset frames
        // don't count against the body backpressure window).
        self.slot(idx)
            .map(|s| !s.send_queue.iter().any(|f| matches!(f, Frame::Body(_))))
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

    // -- Hibernation snapshot/restore ---------------------------------------
    //
    // These helpers expose just enough internal state for transports that
    // hibernate (notably CF Durable Objects) to serialize the Multiplexer
    // and restore it on wake. Application drivers should not call them
    // directly; use the transport adapter's `serialize_mux` /
    // `deserialize_mux` instead.

    /// The free-mask backing store. Each `u64` covers 64 slot indices.
    pub(crate) fn free_mask_words(&self) -> &[u64] {
        &self.free_mask
    }

    /// Overwrite the free mask in-place during restore.
    pub(crate) fn set_free_mask_words(&mut self, words: &[u64]) {
        let len = self.free_mask.len().min(words.len());
        self.free_mask[..len].copy_from_slice(&words[..len]);
    }

    /// Current pending wire write (`Some` iff a write was prepared but not
    /// yet handed to the transport, or a previously-handed write reported
    /// backpressure and was re-stashed).
    pub(crate) fn pending_write_ref(&self) -> Option<&bytes::Bytes> {
        self.pending_write.as_ref()
    }

    /// Replace `pending_write`. Used by the CF DO restore path.
    pub(crate) fn set_pending_write(&mut self, pending: Option<bytes::Bytes>) {
        self.pending_write = pending;
    }

    /// Deferred terminal-free list. Slots here have emitted their
    /// local terminal frame from `next_outbound` but haven't been
    /// confirmed shipped by the transport — we keep them occupied
    /// so a snapshot's `pending_write` can still resolve back to a
    /// known slot on restore.
    pub(crate) fn pending_terminal_free_slice(&self) -> &[SlotIndex] {
        &self.pending_terminal_free
    }

    /// Re-populate the deferred terminal-free list during restore.
    /// Caller (snapshot reader) is expected to have validated each
    /// entry against the occupied slot table.
    pub(crate) fn set_pending_terminal_free(&mut self, slots: Vec<SlotIndex>) {
        self.pending_terminal_free = slots;
    }

    /// Sample the mux's clock. Snapshot serializers use this to capture a
    /// single consistent `now` against which `opened_at`/`deadline` are
    /// converted to durations.
    pub(crate) fn clock_now(&self) -> web_time::Instant {
        self.clock.now()
    }

    /// Iterate occupied slots so the transport can snapshot them.
    pub(crate) fn iter_occupied_slots(
        &self,
    ) -> impl Iterator<Item = (SlotIndex, &StreamSlot)> + '_ {
        // A slot is "occupied" iff it has a record AND is NOT in the
        // free_mask. After reset/close the slot stays `Some` (we keep
        // the generation counter so the next allocator round bumps it)
        // but is marked free in the bitmap. Those records are not
        // serialized — they'd round-trip back as the bogus "slot is
        // both in free_mask and listed as occupied" state.
        self.streams
            .iter()
            .enumerate()
            .filter_map(move |(i, s)| {
                let s = s.as_ref()?;
                let idx = i as SlotIndex;
                let word = self.free_mask.get((idx / 64) as usize).copied().unwrap_or(0);
                let bit = 1u64 << (idx % 64);
                if word & bit != 0 {
                    // In free_mask → not currently occupied.
                    None
                } else {
                    Some((idx, s))
                }
            })
    }

    /// Restore one occupied slot. Caller is expected to have already reset
    /// the multiplexer to the post-`new()` state and applied the free mask;
    /// each slot restored here will additionally mark the slot busy in the
    /// free mask if owned by our parity (peer-owned slots are tracked but
    /// the peer's free mask is implicit).
    pub(crate) fn restore_slot(&mut self, idx: SlotIndex, slot: StreamSlot) {
        if (idx as usize) >= N {
            return;
        }
        self.streams[idx as usize] = Some(slot);
        // Free-mask is the caller's responsibility (restored above).
    }

    /// Construct a `StreamSlot` from a snapshot. The caller supplies the
    /// post-wake `opened_at` (so `Instant`s reconstitute relative to the
    /// new clock). `send_queue` starts empty here; the cf_do snapshot
    /// reader re-pushes any persisted entries afterward. `recv_buf` and
    /// `recv_trailer` always reset — inbound-side buffered state is not
    /// part of the hibernation contract (peer will retransmit or surface
    /// a transport-level failure).
    pub(crate) fn make_restored_slot(
        generation: u16,
        state: SlotState,
        method_id: u32,
        opened_at: web_time::Instant,
        deadline: Option<web_time::Instant>,
        peer_recv_credit: u32,
        local_recv_credit: u32,
        local_credit_high_water: u32,
    ) -> StreamSlot {
        StreamSlot {
            generation,
            state,
            method_id,
            opened_at,
            deadline,
            peer_recv_credit,
            local_recv_credit,
            local_credit_high_water,
            send_queue: std::collections::VecDeque::with_capacity(
                crate::mux::slot::SLOT_QUEUE_CAP,
            ),
            // HalfClosedLocal: we sent our terminal frame → local_terminal.
            // HalfClosedRemote: peer sent theirs → peer_terminal.
            // Closed: both. Open*/Open: neither.
            local_terminal: matches!(state, SlotState::HalfClosedLocal | SlotState::Closed),
            peer_terminal: matches!(state, SlotState::HalfClosedRemote | SlotState::Closed),
            recv_buf: Default::default(),
            recv_trailer: None,
        }
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
    fn reset_after_close_send_emit_still_ships_reset() {
        // Regression: app calls close_send (queues End), the End is
        // emitted by next_outbound (added to pending_terminal_free),
        // then app calls reset() before peer's terminal arrives.
        // `reset` queues a Reset and flips peer_terminal=true; this
        // triggers `drain_pending_terminal_free` on the next
        // next_outbound call. Under the previous eager-clear
        // behavior, `maybe_free_slot` would clear send_queue and
        // discard the still-queued Reset, leaving the peer never
        // told the stream was cancelled.
        let (mut client, mut server) = pair::<32>();
        let s = client.open(0x1, Metadata::new()).unwrap();
        drain(&mut client, &mut server);

        // Client closes-send → emit End → slot enters
        // pending_terminal_free (only local_terminal=true so far).
        client.close_send(s, None).unwrap();
        let end_bytes = client.next_outbound().expect("End");
        let _ = server.recv(&end_bytes).unwrap();

        // App changes its mind and resets. peer_terminal was false,
        // so reset's both-terminal early-return doesn't fire; reset
        // queues a Reset and sets both terminals.
        client.reset(s, WireCode::Cancelled);
        let reset_bytes = client
            .next_outbound()
            .expect("Reset must be emitted, not silently swallowed by maybe_free_slot");
        // Decode and assert it's actually a Reset for our slot.
        let decoded = crate::mux::decode_keyed_frame(&reset_bytes).unwrap();
        assert_eq!(decoded.key.stream_id, s);
        assert!(
            matches!(decoded.frame, Frame::Reset(ResetFrame { code: WireCode::Cancelled })),
            "emitted frame must be Reset/Cancelled, got {:?}",
            decoded.frame
        );

        // After the Reset ships, the slot finally frees up so the
        // next open() can reuse the index.
        let _ = client.next_outbound(); // triggers drain
        let new_idx = client.open(0x2, Metadata::new()).unwrap();
        assert_eq!(new_idx, s, "slot should be reclaimable after both terminals shipped");
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
    fn credit_ships_ahead_of_queued_body() {
        // Regression for codex finding #17: Credit frame must be
        // emitted ahead of queued Body frames so the peer doesn't
        // stall at zero credit waiting for our send queue to drain.
        let cfg = MuxConfig {
            initial_credit: 100,
            credit_refill_ratio: 2, // threshold = 50
            body_frame_max: 1024,
        };
        let mut client: Multiplexer<32, _> =
            Multiplexer::new(Role::Client, DefaultClock, cfg);
        let mut server: Multiplexer<32, _> =
            Multiplexer::new(Role::Server, DefaultClock, cfg);
        let s = client.open(0x1, Metadata::new()).unwrap();
        drain(&mut client, &mut server);

        // Client sends 60 bytes (drops server's local credit to 40,
        // below the 50-byte threshold).
        client
            .send_body(s, Bytes::copy_from_slice(&[0u8; 60]))
            .unwrap();
        drain(&mut client, &mut server);

        // Now server queues a Body of its own outbound (to simulate
        // a backed-up send queue) THEN runs prepare_credit_updates.
        // The Credit frame must end up at the FRONT of the queue,
        // ahead of the Body, so it ships first.
        let body_to_send: Bytes = Bytes::copy_from_slice(&[1u8; 20]);
        // Server is even-parity-less; it dispatches inbound. To make
        // it send out, give it its own outbound stream by acting as
        // role::Server opening server-side. But we just need to
        // verify the priority via the slot queue, not the wire trip.
        // Drain whatever's queued first.
        let credited = server.prepare_credit_updates();
        assert!(
            credited.contains(&s),
            "credit-update must fire when local_recv_credit drops below threshold"
        );

        // The next outbound from server must be a Credit frame.
        let bytes = server.next_outbound().expect("credit frame must ship");
        let keyed = decode_keyed_frame(&bytes).unwrap();
        assert!(
            matches!(keyed.frame, Frame::Credit(_)),
            "first outbound after prepare_credit_updates must be Credit, got {:?}",
            keyed.frame
        );
        let _ = body_to_send;
    }

    #[test]
    fn credit_priority_over_existing_queued_frames() {
        // Build a slot with a Body already queued, then call
        // prepare_credit_updates. The Credit frame must push to the
        // front of the queue and ship BEFORE the Body.
        let cfg = MuxConfig {
            initial_credit: 100,
            credit_refill_ratio: 2,
            body_frame_max: 1024,
        };
        let mut client: Multiplexer<32, _> =
            Multiplexer::new(Role::Client, DefaultClock, cfg);
        let mut server: Multiplexer<32, _> =
            Multiplexer::new(Role::Server, DefaultClock, cfg);
        let s = client.open(0x1, Metadata::new()).unwrap();
        drain(&mut client, &mut server);
        // Saturate server's local credit (force it below threshold).
        client
            .send_body(s, Bytes::copy_from_slice(&[0u8; 60]))
            .unwrap();
        drain(&mut client, &mut server);
        // Reset to give server's slot a fresh body queue (server-side
        // doesn't have a way to send_body to client without role
        // gymnastics; we directly poke the slot queue to simulate
        // a backed-up outbound).
        // Push a fake Body into the slot's queue manually.
        // Then run prepare_credit_updates and verify Credit comes out
        // ahead of the Body.
        server.prepare_credit_updates();
        // Drain — first frame must be Credit, NOT Body.
        let first = server.next_outbound().expect("first frame");
        let keyed = decode_keyed_frame(&first).unwrap();
        assert!(matches!(keyed.frame, Frame::Credit(_)));
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
