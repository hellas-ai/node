//! Cloudflare Durable Object WebSocket driver.
//!
//! CF DOs run on workerd's hibernation-aware runtime: the
//! `websocket_message(ws, msg)` callback is invoked once per inbound WS
//! frame and *the DO itself may be evicted from memory between calls*.
//! When that happens, only state persisted via
//! `ws.serialize_attachment(...)` survives.
//!
//! This module wires the sans-io `Multiplexer` into that callback model:
//!
//! - [`handle_websocket_message`] decodes one inbound WS frame, feeds it
//!   to the mux, and pushes any frames the mux wants to emit back onto
//!   the same WebSocket — one mux frame per WS message, matching the
//!   "one Frame ≤ one WebSocket message" invariant.
//! - [`serialize_mux`] / [`deserialize_mux`] round-trip the
//!   `Multiplexer`'s slot table + free mask + pending-write into a flat
//!   byte buffer suitable for `ws.serialize_attachment(...)`.
//!
//! Caller-side concerns (acceptWebSocket registration, attachment
//! load/store, dispatch on per-WS tag) live in the DO worker; see
//! `HELLAS_WIRE_PLAN_v2.md` "CF Durable Object specifics".

use bytes::Bytes;
use worker::{WebSocket, WebSocketIncomingMessage};

use crate::clock::Clock;
use crate::frame::FrameError;
use crate::mux::{Event, Multiplexer, MuxConfig, MuxError, Role, SlotIndex, SlotState, StreamSlot};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Batch of mux events surfaced from a single inbound WS message,
/// returned by [`handle_websocket_message`] for the caller to dispatch.
#[derive(Debug, Default)]
pub struct MuxEventBatch {
    pub events: Vec<Event>,
    /// Set if `ws.send(...)` reported backpressure during the drain. The
    /// outbound frame remains in the mux's `pending_write` slot and will
    /// be retried on the next call. Callers should still re-serialize the
    /// attachment so that the pending frame survives hibernation.
    pub send_backpressured: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum CfDoError {
    #[error("mux: {0}")]
    Mux(#[from] MuxError),
    #[error("frame: {0}")]
    Frame(#[from] FrameError),
    #[error("worker: {0}")]
    Worker(String),
    #[error("snapshot too short")]
    SnapshotTooShort,
    #[error("snapshot corrupt: {0}")]
    SnapshotCorrupt(&'static str),
    #[error("unknown slot state tag: {0}")]
    UnknownStateTag(u8),
    #[error("unknown role tag: {0}")]
    UnknownRoleTag(u8),
}

impl From<worker::Error> for CfDoError {
    fn from(e: worker::Error) -> Self {
        Self::Worker(format!("{e}"))
    }
}

// ---------------------------------------------------------------------------
// Callback driver
// ---------------------------------------------------------------------------

/// Drive one inbound WebSocket message through the mux.
///
/// The flow per call (mirrors the "CF Durable Object specifics" section
/// of the wire plan):
///
/// 1. Decode the inbound message bytes. Strings are accepted but treated
///    as empty (the mux speaks binary only); this matches the prior-art
///    `ws-mux` driver behavior.
/// 2. Feed bytes into `mux.recv(...)` and collect the resulting events.
/// 3. Drain `mux.next_outbound()` and ship each frame as a separate
///    `Message::Binary`. The mux already produced exactly one keyed
///    frame per call to `next_outbound`, so one frame = one WS message.
/// 4. Return the event batch; the caller dispatches it.
///
/// **The caller is responsible** for persisting the mux state via
/// [`serialize_mux`] + `ws.serialize_attachment(...)` before returning
/// from `websocket_message`. We deliberately don't do it here because
/// most DOs hold multiple WebSockets and want to choose when to flush.
pub fn handle_websocket_message<const N: usize, C: Clock>(
    ws: &WebSocket,
    message: WebSocketIncomingMessage,
    mux: &mut Multiplexer<N, C>,
) -> Result<MuxEventBatch, CfDoError> {
    let mut batch = MuxEventBatch::default();

    // 1. Decode inbound. String frames are not part of the mux protocol;
    //    drop them so a stray ping or app-level text doesn't crash us.
    let bytes = match message {
        WebSocketIncomingMessage::Binary(b) => b,
        WebSocketIncomingMessage::String(_) => Vec::new(),
    };

    // 2. Feed into the state machine. `recv` returns events to dispatch.
    if !bytes.is_empty() {
        let events = mux.recv(&bytes)?;
        batch.events = events;
    }

    // 2a. Refill peer-side credit on slots that drained below the
    //     threshold. This queues `Frame::Credit` frames into the slot's
    //     send queue; they ship in step 3 below.
    let _credited = mux.prepare_credit_updates();

    // 3. Drain outbound. Each frame is its own WS message.
    while let Some(frame_bytes) = mux.next_outbound() {
        match ws.send_with_bytes(&frame_bytes[..]) {
            Ok(()) => {}
            Err(e) => {
                // Re-stash the frame in pending_write so it survives the
                // upcoming serialize_attachment and is retried next call.
                mux.set_pending_write(Some(frame_bytes));
                batch.send_backpressured = true;
                tracing::warn!("cf_do ws.send_with_bytes: {e}");
                break;
            }
        }
    }

    Ok(batch)
}

// ---------------------------------------------------------------------------
// Hibernation snapshot
// ---------------------------------------------------------------------------
//
// Wire format (see HELLAS_WIRE_PLAN_v2.md, "CF Durable Object specifics"
// + Mux hibernation invariants):
//
//   [magic: u8 = 0xA1]           // version tag; bumpable
//   [role: u8]                   // 0 = Client, 1 = Server
//   [n_words: u16 LE]            // length of free_mask in u64 words
//   [free_mask: n_words * u64 LE]
//   [count: varint]              // occupied slots
//   for each:
//     [slot_idx: u16 LE]
//     [generation: u16 LE]
//     [state_tag: u8]            // SlotState variant
//     [method_id: u32 LE]
//     [peer_recv_credit: u32 LE]
//     [local_recv_credit: u32 LE]
//     [local_credit_high_water: u32 LE]
//     [opened_age_ns: u64 LE]
//     [deadline_flag: u8]        // 0 = None, 1 = Some
//     [deadline_remaining_ns: u64 LE]?   // present iff flag == 1
//     [send_queue_len: u8]       // bounded by SLOT_QUEUE_CAP
//     for each queued frame:
//       [frame_len: varint]
//       [frame_bytes]            // encoded `Frame` (keyless)
//   [has_pending: u8]
//   [pending_len: varint]?       // present iff has_pending == 1
//   [pending_bytes]?
//   [pending_terminal_free_len: u8]
//   [terminal_free_idx: u16 LE]* // present pending_terminal_free_len times
//
// `Instant`s are captured as deltas relative to the clock's `now()` at
// serialize time, and re-anchored relative to `now()` at deserialize
// time — `Instant` is opaque and not stable across hibernation.

// 0xA1 → 0xA2: added per-slot send_queue persistence + the
// `pending_terminal_free` deferred-free list at the snapshot tail.
const SNAPSHOT_MAGIC: u8 = 0xA2;

const ROLE_CLIENT: u8 = 0;
const ROLE_SERVER: u8 = 1;

const STATE_OPEN_LOCAL: u8 = 0;
const STATE_OPEN_REMOTE: u8 = 1;
const STATE_OPEN: u8 = 2;
const STATE_HALF_CLOSED_LOCAL: u8 = 3;
const STATE_HALF_CLOSED_REMOTE: u8 = 4;
const STATE_CLOSED: u8 = 5;

fn role_tag(r: Role) -> u8 {
    match r {
        Role::Client => ROLE_CLIENT,
        Role::Server => ROLE_SERVER,
    }
}

fn role_from_tag(t: u8) -> Result<Role, CfDoError> {
    match t {
        ROLE_CLIENT => Ok(Role::Client),
        ROLE_SERVER => Ok(Role::Server),
        other => Err(CfDoError::UnknownRoleTag(other)),
    }
}

fn state_tag(s: SlotState) -> u8 {
    match s {
        SlotState::OpenLocal => STATE_OPEN_LOCAL,
        SlotState::OpenRemote => STATE_OPEN_REMOTE,
        SlotState::Open => STATE_OPEN,
        SlotState::HalfClosedLocal => STATE_HALF_CLOSED_LOCAL,
        SlotState::HalfClosedRemote => STATE_HALF_CLOSED_REMOTE,
        SlotState::Closed => STATE_CLOSED,
    }
}

fn state_from_tag(t: u8) -> Result<SlotState, CfDoError> {
    match t {
        STATE_OPEN_LOCAL => Ok(SlotState::OpenLocal),
        STATE_OPEN_REMOTE => Ok(SlotState::OpenRemote),
        STATE_OPEN => Ok(SlotState::Open),
        STATE_HALF_CLOSED_LOCAL => Ok(SlotState::HalfClosedLocal),
        STATE_HALF_CLOSED_REMOTE => Ok(SlotState::HalfClosedRemote),
        STATE_CLOSED => Ok(SlotState::Closed),
        other => Err(CfDoError::UnknownStateTag(other)),
    }
}

// -- varint (LEB128, matches frame.rs) --------------------------------------

fn write_varint(mut v: u64, out: &mut Vec<u8>) {
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

fn read_varint(buf: &[u8]) -> Result<(u64, usize), CfDoError> {
    let mut result: u64 = 0;
    let mut shift = 0;
    for (i, byte) in buf.iter().take(10).enumerate() {
        result |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok((result, i + 1));
        }
        shift += 7;
    }
    Err(CfDoError::SnapshotCorrupt("varint too long"))
}

// -- Encode -----------------------------------------------------------------

/// Serialize a `Multiplexer` to a byte buffer suitable for
/// `ws.serialize_attachment(...)`. See module docs for the wire format.
pub fn serialize_mux<const N: usize, C: Clock>(mux: &Multiplexer<N, C>) -> Vec<u8> {
    let now = mux_clock_now(mux);
    let mut out = Vec::with_capacity(64);

    out.push(SNAPSHOT_MAGIC);
    out.push(role_tag(mux.role()));

    let words = mux.free_mask_words();
    let n_words = words.len() as u16;
    out.extend_from_slice(&n_words.to_le_bytes());
    for w in words {
        out.extend_from_slice(&w.to_le_bytes());
    }

    // Collect occupied slots so we can write the count varint first.
    let occupied: Vec<(SlotIndex, &StreamSlot)> = mux.iter_occupied_slots().collect();
    write_varint(occupied.len() as u64, &mut out);

    for (idx, slot) in occupied {
        out.extend_from_slice(&idx.to_le_bytes());
        out.extend_from_slice(&slot.generation.to_le_bytes());
        out.push(state_tag(slot.state));
        out.extend_from_slice(&slot.method_id.to_le_bytes());
        out.extend_from_slice(&slot.peer_recv_credit.to_le_bytes());
        out.extend_from_slice(&slot.local_recv_credit.to_le_bytes());
        out.extend_from_slice(&slot.local_credit_high_water.to_le_bytes());

        // opened_age_ns: how long ago this slot was opened relative to now.
        // Saturate to 0 if (somehow) opened_at is in the future.
        let opened_age_ns = now
            .checked_duration_since(slot.opened_at)
            .map(|d| d.as_nanos().min(u128::from(u64::MAX)) as u64)
            .unwrap_or(0);
        out.extend_from_slice(&opened_age_ns.to_le_bytes());

        match slot.deadline {
            Some(d) => {
                out.push(1);
                // deadline_remaining_ns: time until deadline. Clamp to 0
                // for already-expired deadlines.
                let remaining_ns = d
                    .checked_duration_since(now)
                    .map(|dur| dur.as_nanos().min(u128::from(u64::MAX)) as u64)
                    .unwrap_or(0);
                out.extend_from_slice(&remaining_ns.to_le_bytes());
            }
            None => {
                out.push(0);
            }
        }

        // Per-slot send_queue: persist all queued frames in order.
        // Without this, a backed-up queue (e.g. Credit + Body waiting
        // behind a backpressured send) would be silently dropped on
        // restore. Each queue entry is `[len: varint] [Frame bytes]`;
        // the encoded Frame is keyless (the slot index + generation
        // come from the slot record itself).
        out.push(slot.send_queue.len() as u8);
        let mut tmp = bytes::BytesMut::new();
        for frame in &slot.send_queue {
            tmp.clear();
            crate::frame::encode_frame(frame, &mut tmp);
            write_varint(tmp.len() as u64, &mut out);
            out.extend_from_slice(&tmp);
        }
    }

    match mux.pending_write_ref() {
        Some(pending) => {
            out.push(1);
            write_varint(pending.len() as u64, &mut out);
            out.extend_from_slice(pending);
        }
        None => out.push(0),
    }

    // Deferred terminal-free list. Each entry is a slot index whose
    // local terminal frame has been emitted by `next_outbound` but
    // not yet confirmed shipped. Bounded by N (one entry per slot
    // at most), and in practice ≤ 1 because each emit cycle drains
    // the previous entry before pushing the next — the u8 length
    // prefix accommodates this with margin. The debug assert
    // guards against future invariant drift (e.g. if next_outbound
    // ever batches multiple terminal emits per call).
    let term_free = mux.pending_terminal_free_slice();
    debug_assert!(
        term_free.len() <= u8::MAX as usize,
        "pending_terminal_free length {} exceeds u8 prefix capacity",
        term_free.len()
    );
    out.push(term_free.len() as u8);
    for idx in term_free {
        out.extend_from_slice(&idx.to_le_bytes());
    }

    out
}

// -- Decode -----------------------------------------------------------------

/// Restore a `Multiplexer` from bytes produced by [`serialize_mux`].
///
/// `clock` is the post-wake clock; `Instant`s in the snapshot are
/// reconstructed relative to its current time. The mux's `MuxConfig` is
/// not part of the snapshot — pass the same config the original side
/// used (or accept that `initial_credit` / `body_frame_max` defaults
/// take effect for new slots).
pub fn deserialize_mux<const N: usize, C: Clock>(
    bytes: &[u8],
    clock: C,
    config: MuxConfig,
) -> Result<Multiplexer<N, C>, CfDoError> {
    // Compile-time bound: pending_write must fit in the attachment
    // budget. We cap at 16 KiB per the plan; the snapshot itself is
    // bounded by N * sizeof(slot record) + this.
    const PENDING_WRITE_MAX: usize = 16 * 1024;
    // Free-mask word count must match what the in-memory representation
    // would produce for this `N`. Caller-supplied N drives the
    // expected word count; a mismatch means the snapshot was taken with
    // a different mux size and is unsafe to restore.
    let expected_words = (N + 63) / 64;

    let mut cur = Cursor::new(bytes);

    let magic = cur.take_u8()?;
    if magic != SNAPSHOT_MAGIC {
        return Err(CfDoError::SnapshotCorrupt("bad magic"));
    }
    let role = role_from_tag(cur.take_u8()?)?;
    let now = clock.now();

    // Reconstruct mux with default state, then overwrite.
    let mut mux = Multiplexer::<N, C>::new(role, clock, config);
    let mux_config = *mux.config();

    let n_words = cur.take_u16()? as usize;
    if n_words != expected_words {
        return Err(CfDoError::SnapshotCorrupt("free_mask word count mismatch"));
    }
    let mut words = Vec::with_capacity(n_words);
    for _ in 0..n_words {
        words.push(cur.take_u64()?);
    }
    // The free_mask must only have bits set for slots of our parity.
    // A poisoned snapshot that marks peer-parity slots "free" would
    // let our allocator hand out slots in the peer's domain.
    // Also: NO bits beyond N may be set — `lowest_free()` doesn't
    // bound its index against N, so a tail bit would let `open()`
    // index out of range and panic.
    let peer_parity_mask: u64 = if role.parity() == 0 {
        0xAAAA_AAAA_AAAA_AAAA
    } else {
        0x5555_5555_5555_5555
    };
    for (word_idx, word) in words.iter().enumerate() {
        let valid_bits: u64 = {
            let start_bit = word_idx * 64;
            if start_bit >= N {
                0
            } else if start_bit + 64 <= N {
                u64::MAX
            } else {
                (1u64 << (N - start_bit)) - 1
            }
        };
        if word & !valid_bits != 0 {
            return Err(CfDoError::SnapshotCorrupt("free_mask sets a bit beyond N"));
        }
        if word & peer_parity_mask & valid_bits != 0 {
            return Err(CfDoError::SnapshotCorrupt(
                "free_mask sets a bit owned by peer parity",
            ));
        }
    }
    mux.set_free_mask_words(&words);

    let (count, _) = cur.take_varint()?;
    if count > N as u64 {
        return Err(CfDoError::SnapshotCorrupt("occupied count exceeds N"));
    }

    // Track which slot indices we've seen so we can detect duplicates
    // and cross-check against the free_mask.
    let mut seen_slots = std::collections::HashSet::with_capacity(count as usize);

    for _ in 0..count {
        let idx = cur.take_u16()?;
        if (idx as usize) >= N {
            return Err(CfDoError::SnapshotCorrupt("slot idx out of range"));
        }
        if !seen_slots.insert(idx) {
            return Err(CfDoError::SnapshotCorrupt("duplicate slot idx"));
        }
        // An occupied slot must NOT also be in the free_mask. If it is,
        // someone fabricated a snapshot to hand the same slot out
        // twice — first as "free" (so we'd allocate it) and second as
        // "open" (so frames arriving on it dispatch to the planted
        // state). We reject the snapshot rather than try to repair it.
        let word = words[(idx / 64) as usize];
        let bit = 1u64 << (idx % 64);
        if word & bit != 0 {
            return Err(CfDoError::SnapshotCorrupt(
                "slot listed as occupied is also in free_mask",
            ));
        }

        let generation = cur.take_u16()?;
        let state = state_from_tag(cur.take_u8()?)?;
        let method_id = cur.take_u32()?;
        let peer_recv_credit = cur.take_u32()?;
        let local_recv_credit = cur.take_u32()?;
        let local_credit_high_water = cur.take_u32()?;
        if local_recv_credit > local_credit_high_water {
            return Err(CfDoError::SnapshotCorrupt("local_recv_credit > high_water"));
        }
        // high_water itself must not exceed the configured initial
        // credit — otherwise a forged snapshot could persuade us to
        // mint enormous Credit frames on prepare_credit_updates.
        if local_credit_high_water > mux_config.initial_credit {
            return Err(CfDoError::SnapshotCorrupt(
                "high_water > config.initial_credit",
            ));
        }
        // Sanity: peer_recv_credit shouldn't exceed config's initial
        // credit (the peer wouldn't have advertised more than they
        // were ever willing to receive).
        if peer_recv_credit > mux_config.initial_credit {
            return Err(CfDoError::SnapshotCorrupt("peer_recv_credit > initial"));
        }
        let opened_age_ns = cur.take_u64()?;

        let deadline_flag = cur.take_u8()?;
        let deadline = match deadline_flag {
            0 => None,
            1 => {
                let remaining_ns = cur.take_u64()?;
                now.checked_add(std::time::Duration::from_nanos(remaining_ns))
            }
            _ => return Err(CfDoError::SnapshotCorrupt("bad deadline flag")),
        };

        let opened_at = now
            .checked_sub(std::time::Duration::from_nanos(opened_age_ns))
            .unwrap_or(now);

        let mut slot = Multiplexer::<N, C>::make_restored_slot(
            generation,
            state,
            method_id,
            opened_at,
            deadline,
            peer_recv_credit,
            local_recv_credit,
            local_credit_high_water,
        );

        // Per-slot send_queue: restore frames in order.
        let queue_len = cur.take_u8()? as usize;
        if queue_len > crate::mux::slot::SLOT_QUEUE_CAP {
            return Err(CfDoError::SnapshotCorrupt("slot send_queue exceeds cap"));
        }
        for _ in 0..queue_len {
            let (frame_len, _) = cur.take_varint()?;
            let frame_len = frame_len as usize;
            // Each frame must fit within the per-frame body cap so a
            // poisoned snapshot can't allocate a huge frame per slot
            // and bloat the attachment past budget.
            if frame_len > mux_config.body_frame_max {
                return Err(CfDoError::SnapshotCorrupt(
                    "queued frame exceeds body_frame_max",
                ));
            }
            let bytes = cur.take_bytes(frame_len)?;
            let frame = crate::frame::decode_frame(bytes)
                .map_err(|_| CfDoError::SnapshotCorrupt("queued frame fails decode"))?;
            slot.send_queue.push_back(frame);
        }

        mux.restore_slot(idx, slot);
    }

    let has_pending = cur.take_u8()?;
    match has_pending {
        0 => mux.set_pending_write(None),
        1 => {
            let (len, _) = cur.take_varint()?;
            let len = len as usize;
            if len > PENDING_WRITE_MAX {
                return Err(CfDoError::SnapshotCorrupt("pending_write exceeds budget"));
            }
            let bytes = cur.take_bytes(len)?;
            // pending_write is one outbound mux frame that didn't make
            // it to the wire before suspension. Decode it and validate
            // its (stream_id, generation) matches a known slot. A
            // poisoned attachment that injected arbitrary bytes here
            // would let the DO ship one attacker-controlled frame on
            // wake; the decode guards against that.
            let keyed = crate::mux::decode_keyed_frame(bytes)
                .map_err(|_| CfDoError::SnapshotCorrupt("pending_write not a valid keyed frame"))?;
            if (keyed.key.stream_id as usize) >= N {
                return Err(CfDoError::SnapshotCorrupt(
                    "pending_write stream_id out of range",
                ));
            }
            // The frame must reference a slot we already restored, and
            // the slot's generation must match.
            let slot_match = mux
                .iter_occupied_slots()
                .find(|(idx, _)| *idx == keyed.key.stream_id)
                .map(|(_, slot)| slot.generation == keyed.key.generation)
                .unwrap_or(false);
            if !slot_match {
                return Err(CfDoError::SnapshotCorrupt(
                    "pending_write key does not match any restored slot",
                ));
            }
            mux.set_pending_write(Some(Bytes::copy_from_slice(bytes)));
        }
        _ => return Err(CfDoError::SnapshotCorrupt("bad has_pending flag")),
    }

    // Deferred terminal-free list. Each entry must reference a slot
    // currently occupied — that's the entire purpose of deferring
    // the free in the first place. A poisoned attachment could
    // claim a freed slot is "in-flight terminal" to confuse the
    // free-on-next-emit logic; reject any idx not in the occupied
    // table. We also require local_terminal=true (i.e. state ∈
    // {HalfClosedLocal, Closed}); otherwise the list entry is
    // nonsensical (we couldn't have emitted a terminal frame from
    // a slot that hasn't yet observed its own close_send / reset).
    let term_free_len = cur.take_u8()? as usize;
    if term_free_len > N {
        return Err(CfDoError::SnapshotCorrupt(
            "pending_terminal_free exceeds N",
        ));
    }
    let mut term_free: Vec<SlotIndex> = Vec::with_capacity(term_free_len);
    for _ in 0..term_free_len {
        let idx = cur.take_u16()?;
        if (idx as usize) >= N {
            return Err(CfDoError::SnapshotCorrupt(
                "pending_terminal_free idx out of range",
            ));
        }
        let slot_state = mux
            .iter_occupied_slots()
            .find(|(occ_idx, _)| *occ_idx == idx)
            .map(|(_, slot)| slot.state);
        let slot_state = match slot_state {
            Some(s) => s,
            None => {
                return Err(CfDoError::SnapshotCorrupt(
                    "pending_terminal_free idx is not occupied",
                ));
            }
        };
        if !matches!(slot_state, SlotState::HalfClosedLocal | SlotState::Closed) {
            return Err(CfDoError::SnapshotCorrupt(
                "pending_terminal_free idx slot is not local-terminal",
            ));
        }
        if term_free.contains(&idx) {
            return Err(CfDoError::SnapshotCorrupt(
                "pending_terminal_free has duplicate idx",
            ));
        }
        term_free.push(idx);
    }

    // Any "occupied" slot we OWN that's in state=Closed must reach
    // a path that eventually frees it. Three legitimate ways:
    //   (a) idx in pending_terminal_free — its terminal frame was
    //       emitted and the deferred-free drain will reclaim it.
    //   (b) send_queue is non-empty — there's still a frame to ship
    //       (e.g. a Reset queued by `reset()` from a non-terminal
    //       state, or by the body-overrun handler). The next
    //       `next_outbound` will emit it and queue the idx into
    //       pending_terminal_free; the call after that frees it.
    //   (c) NEITHER → permanent leak. `lowest_free` ignores the
    //       slot (bit clear); recv won't re-fire `maybe_free_slot`
    //       (already Closed); `next_outbound` never adds it. Fail
    //       closed.
    //
    // Peer-parity slots stay `Some` with state=Closed indefinitely
    // after the peer's terminal — `mark_free` only sets bits we
    // own, so the slot record is retained for generation-rollover
    // tracking. They are not orphans; the peer governs their
    // lifecycle. Scope the check to our parity.
    let our_role = mux.role();
    let closed_orphans: Vec<SlotIndex> = mux
        .iter_occupied_slots()
        .filter(|(idx, slot)| {
            our_role.owns_slot(*idx)
                && slot.state == SlotState::Closed
                && slot.send_queue.is_empty()
        })
        .map(|(idx, _)| idx)
        .filter(|idx| !term_free.contains(idx))
        .collect();
    if !closed_orphans.is_empty() {
        return Err(CfDoError::SnapshotCorrupt(
            "closed slot not queued in pending_terminal_free",
        ));
    }
    mux.set_pending_terminal_free(term_free);

    // Trailing-bytes check: the snapshot must be exactly the right
    // length. Extra bytes mean someone appended a payload we don't
    // know how to parse — reject.
    if cur.pos != bytes.len() {
        return Err(CfDoError::SnapshotCorrupt("trailing bytes after snapshot"));
    }

    Ok(mux)
}

// -- Cursor helper ----------------------------------------------------------

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take_bytes(&mut self, n: usize) -> Result<&'a [u8], CfDoError> {
        if self.pos + n > self.buf.len() {
            return Err(CfDoError::SnapshotTooShort);
        }
        let out = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    fn take_u8(&mut self) -> Result<u8, CfDoError> {
        Ok(self.take_bytes(1)?[0])
    }

    fn take_u16(&mut self) -> Result<u16, CfDoError> {
        let b = self.take_bytes(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    fn take_u32(&mut self) -> Result<u32, CfDoError> {
        let b = self.take_bytes(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn take_u64(&mut self) -> Result<u64, CfDoError> {
        let b = self.take_bytes(8)?;
        Ok(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    fn take_varint(&mut self) -> Result<(u64, usize), CfDoError> {
        let (v, n) = read_varint(&self.buf[self.pos..])?;
        self.pos += n;
        Ok((v, n))
    }
}

// -- Clock access helper ----------------------------------------------------
//
// `Multiplexer.clock` is private; we go through the `pub(crate)`
// `clock_now()` accessor added in `mux/state.rs`. Snapshot captures
// `Instant`s as durations relative to this single `now` reading.

fn mux_clock_now<const N: usize, C: Clock>(mux: &Multiplexer<N, C>) -> web_time::Instant {
    mux.clock_now()
}

// ---------------------------------------------------------------------------
// Tests — pure-Rust, no worker runtime
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::DefaultClock;
    use crate::metadata::Metadata;

    #[test]
    fn varint_roundtrip() {
        for v in [0u64, 1, 127, 128, 300, 16384, u32::MAX as u64, u64::MAX] {
            let mut buf = Vec::new();
            write_varint(v, &mut buf);
            let (decoded, _) = read_varint(&buf).unwrap();
            assert_eq!(v, decoded);
        }
    }

    #[test]
    fn snapshot_roundtrip_empty() {
        let mux: Multiplexer<32, _> =
            Multiplexer::new(Role::Client, DefaultClock, MuxConfig::default());
        let bytes = serialize_mux(&mux);
        let restored: Multiplexer<32, _> =
            deserialize_mux(&bytes, DefaultClock, MuxConfig::default()).unwrap();
        assert_eq!(restored.role(), Role::Client);
    }

    #[test]
    fn snapshot_roundtrip_with_open_slot() {
        let mut mux: Multiplexer<32, _> =
            Multiplexer::new(Role::Client, DefaultClock, MuxConfig::default());
        let slot = mux.open(0xDEAD_BEEF, Metadata::new()).unwrap();
        assert_eq!(slot, 0);
        // Drain the OPEN frame so pending_write is exercised at least
        // once; then re-stash one to test pending-write persistence.
        let pending = mux.next_outbound().unwrap();
        mux.set_pending_write(Some(pending));

        let bytes = serialize_mux(&mux);
        let restored: Multiplexer<32, _> =
            deserialize_mux(&bytes, DefaultClock, MuxConfig::default()).unwrap();
        assert_eq!(restored.role(), Role::Client);
        assert!(
            restored.pending_write_ref().is_some(),
            "pending_write should survive round-trip"
        );
    }

    // ----------------------------------------------------------------
    // Adversarial / failure-mode tests for hibernation.
    //
    // The DO's attachment is peer-controllable in adversarial models
    // (a compromised storage tier, a tampered re-serialize, a stale
    // attachment from a different code version). Every code path that
    // restores trusted state from the attachment must reject obvious
    // tampering with `SnapshotCorrupt` rather than mis-attribute slots,
    // hand out the same slot twice, or replay arbitrary bytes.
    //
    // These tests cover:
    //   - drop-then-fresh-start (no snapshot path)
    //   - worker dies mid-callback (partial write of attachment)
    //   - magic-byte mismatch (version upgrade or bit flip)
    //   - truncation at every byte offset
    //   - inflated occupancy count
    //   - parity violation (client claims to own odd slot)
    //   - duplicate slot index
    //   - free-mask vs occupied list contradiction
    //   - credit > high_water
    //   - pending_write claims absurd length
    //   - trailing bytes appended past the snapshot
    // ----------------------------------------------------------------

    fn client_with_open_slot() -> (Multiplexer<32, DefaultClock>, Vec<u8>) {
        let mut mux: Multiplexer<32, _> =
            Multiplexer::new(Role::Client, DefaultClock, MuxConfig::default());
        mux.open(0xCAFEBABE, Metadata::new()).unwrap();
        let bytes = serialize_mux(&mux);
        (mux, bytes)
    }

    #[test]
    fn drop_and_fresh_start_is_a_fresh_mux() {
        // No snapshot path: caller never calls deserialize_mux, just
        // constructs a new Multiplexer. This is the cache-eviction /
        // version-upgrade / first-boot path; must work as if nothing
        // ever existed.
        let fresh: Multiplexer<32, _> =
            Multiplexer::new(Role::Client, DefaultClock, MuxConfig::default());
        assert_eq!(fresh.role(), Role::Client);
        assert!(fresh.pending_write_ref().is_none());
        // No slots are occupied yet.
        assert_eq!(fresh.iter_occupied_slots().count(), 0);
    }

    #[test]
    fn worker_dies_mid_callback_partial_attachment() {
        // Worker died after `mux.recv` but BEFORE
        // `serialize_attachment` finished writing. The next callback
        // sees a truncated attachment. Every prefix must reject.
        let (_, full) = client_with_open_slot();
        for prefix_len in 0..full.len() {
            let truncated = &full[..prefix_len];
            let res = deserialize_mux::<32, _>(truncated, DefaultClock, MuxConfig::default());
            // Any prefix should hit SnapshotTooShort, SnapshotCorrupt,
            // or one of the named tag errors. None should succeed.
            assert!(
                res.is_err(),
                "truncation at byte {prefix_len} should reject"
            );
        }
    }

    #[test]
    fn bit_flipped_magic_byte_rejected() {
        let (_, mut bytes) = client_with_open_slot();
        bytes[0] = bytes[0].wrapping_add(1);
        let err = deserialize_mux::<32, _>(&bytes, DefaultClock, MuxConfig::default())
            .err()
            .expect("bad magic must reject");
        assert!(matches!(err, CfDoError::SnapshotCorrupt("bad magic")));
    }

    #[test]
    fn future_magic_byte_rejected_with_named_error() {
        // Version-upgrade scenario: a future DO writes a snapshot with
        // a newer magic byte. The current code must reject it clearly.
        let (_, mut bytes) = client_with_open_slot();
        bytes[0] = 0xA3;
        assert!(matches!(
            deserialize_mux::<32, _>(&bytes, DefaultClock, MuxConfig::default()),
            Err(CfDoError::SnapshotCorrupt("bad magic"))
        ));
    }

    #[test]
    fn inflated_occupancy_count_rejected() {
        // The count varint is one byte at position
        //   1 (magic) + 1 (role) + 2 (n_words) + n_words*8 (words) = ...
        // For N=32: n_words = 1, so count is at offset 1+1+2+8 = 12.
        // We rewrite the count to claim 33 slots (> N).
        let (_, mut bytes) = client_with_open_slot();
        // Find the count varint position by re-encoding our way there.
        let count_offset = 1 + 1 + 2 + 8;
        bytes[count_offset] = 33; // single-byte varint
        let err = deserialize_mux::<32, _>(&bytes, DefaultClock, MuxConfig::default())
            .err()
            .expect("count > N must reject");
        assert!(matches!(
            err,
            CfDoError::SnapshotCorrupt("occupied count exceeds N")
        ));
    }

    #[test]
    fn duplicate_slot_index_rejected() {
        // Open two slots, then craft a snapshot that lists slot 0
        // twice (instead of slot 0 and slot 2).
        let mut mux: Multiplexer<32, _> =
            Multiplexer::new(Role::Client, DefaultClock, MuxConfig::default());
        mux.open(0x1, Metadata::new()).unwrap();
        mux.open(0x2, Metadata::new()).unwrap();
        let mut bytes = serialize_mux(&mux);
        // Slot record stride: 2 (idx) + 2 (gen) + 1 (state) + 4 (mid)
        //                   + 4 (peer_credit) + 4 (local_credit)
        //                   + 4 (high_water) + 8 (opened_age)
        //                   + 1 (deadline_flag) [+8 if Some]
        //                   = 30 bytes, deadline=None case.
        // First slot record starts at:
        //   1 (magic) + 1 (role) + 2 (n_words) + 8 (one u64 word) + 1 (count varint)
        //   = 13
        let first_record_start = 13;
        let second_record_start = first_record_start + 30; // each record is 30 bytes (no deadline)
        // Overwrite the idx of the second record with the idx of the first (0).
        bytes[second_record_start..second_record_start + 2].copy_from_slice(&0u16.to_le_bytes());
        let err = deserialize_mux::<32, _>(&bytes, DefaultClock, MuxConfig::default())
            .err()
            .expect("duplicate slot idx must reject");
        assert!(matches!(
            err,
            CfDoError::SnapshotCorrupt("duplicate slot idx")
        ));
    }

    #[test]
    fn slot_in_both_free_mask_and_occupied_list_rejected() {
        // Client owns slot 0 (parity even). Open it, then poison the
        // free_mask to ALSO claim slot 0 is free. A restored mux that
        // accepted both would happily hand slot 0 to a new caller
        // while the existing slot record is also live — same slot
        // dispatched twice.
        let (_, mut bytes) = client_with_open_slot();
        // free_mask occupies offset 1+1+2 .. 1+1+2+8 = 4..12. Set bit 0
        // (lowest of word 0) → slot 0 marked free.
        bytes[4] |= 1;
        let err = deserialize_mux::<32, _>(&bytes, DefaultClock, MuxConfig::default())
            .err()
            .expect("slot occupied AND in free_mask must reject");
        assert!(matches!(
            err,
            CfDoError::SnapshotCorrupt("slot listed as occupied is also in free_mask")
        ));
    }

    #[test]
    fn peer_parity_in_our_free_mask_rejected() {
        // Client role: we own even indices. A poisoned free_mask
        // claiming an odd slot (1) is free would let our `open()`
        // hand out a peer-domain slot.
        let mux: Multiplexer<32, _> =
            Multiplexer::new(Role::Client, DefaultClock, MuxConfig::default());
        let mut bytes = serialize_mux(&mux);
        // Mark slot 1 (odd, peer-owned) as free.
        bytes[4] |= 0b10;
        let err = deserialize_mux::<32, _>(&bytes, DefaultClock, MuxConfig::default())
            .err()
            .expect("peer-parity slot in our free_mask must reject");
        assert!(matches!(
            err,
            CfDoError::SnapshotCorrupt("free_mask sets a bit owned by peer parity")
        ));
    }

    #[test]
    fn credit_exceeds_high_water_rejected() {
        let mut mux: Multiplexer<32, _> =
            Multiplexer::new(Role::Client, DefaultClock, MuxConfig::default());
        mux.open(0x1, Metadata::new()).unwrap();
        let mut bytes = serialize_mux(&mux);
        // local_recv_credit field is at offset:
        //   13 (free_mask + count) + 2 (idx) + 2 (gen) + 1 (state)
        //   + 4 (mid) + 4 (peer_credit) = 26
        let local_credit_offset = 13 + 2 + 2 + 1 + 4 + 4;
        // Overwrite local_recv_credit with 0xFFFF_FFFF.
        bytes[local_credit_offset..local_credit_offset + 4]
            .copy_from_slice(&u32::MAX.to_le_bytes());
        let err = deserialize_mux::<32, _>(&bytes, DefaultClock, MuxConfig::default())
            .err()
            .expect("local_recv_credit > high_water must reject");
        assert!(matches!(
            err,
            CfDoError::SnapshotCorrupt("local_recv_credit > high_water")
                | CfDoError::SnapshotCorrupt("peer_recv_credit > initial")
        ));
    }

    #[test]
    fn pending_write_oversized_rejected() {
        // Construct a snapshot with has_pending=1 and a 1 MiB pending
        // frame. The 16 KiB budget should reject.
        let mux: Multiplexer<32, _> =
            Multiplexer::new(Role::Client, DefaultClock, MuxConfig::default());
        let mut bytes = serialize_mux(&mux);
        // Snapshot tail layout for an empty mux with no pending_write
        // and no deferred terminal-free entries:
        //   ... [has_pending=0] [terminal_free_len=0]
        // We want to flip has_pending → 1 and inject an oversized
        // pending_len. Truncate the trailing [terminal_free_len=0]
        // first, then overwrite the has_pending byte.
        assert_eq!(*bytes.last().unwrap(), 0); // terminal_free_len=0
        bytes.pop();
        assert_eq!(*bytes.last().unwrap(), 0); // has_pending=0
        let last = bytes.len() - 1;
        bytes[last] = 1;
        let mut len_varint = Vec::new();
        write_varint(1 * 1024 * 1024, &mut len_varint);
        bytes.extend(len_varint);
        // We don't even need the trailing bytes — the check fires on length.
        let err = deserialize_mux::<32, _>(&bytes, DefaultClock, MuxConfig::default())
            .err()
            .expect("oversized pending_write must reject");
        assert!(matches!(
            err,
            CfDoError::SnapshotCorrupt("pending_write exceeds budget")
        ));
    }

    #[test]
    fn trailing_bytes_appended_rejected() {
        let (_, mut bytes) = client_with_open_slot();
        bytes.extend_from_slice(b"\xde\xad\xbe\xef");
        let err = deserialize_mux::<32, _>(&bytes, DefaultClock, MuxConfig::default())
            .err()
            .expect("trailing bytes must reject");
        assert!(matches!(
            err,
            CfDoError::SnapshotCorrupt("trailing bytes after snapshot")
        ));
    }

    #[test]
    fn n_word_count_mismatch_rejected() {
        // Snapshot was taken with N=64 (n_words=1, same as N=32). But
        // if N=128 it'd be n_words=2. Test that the deserializer with
        // a different N rejects mismatched counts.
        // We serialize for N=32 (n_words=1) and try to deserialize
        // into N=128 (expected n_words=2).
        let mux: Multiplexer<32, _> =
            Multiplexer::new(Role::Client, DefaultClock, MuxConfig::default());
        let bytes = serialize_mux(&mux);
        let err = deserialize_mux::<128, _>(&bytes, DefaultClock, MuxConfig::default())
            .err()
            .expect("mismatched N must reject");
        assert!(matches!(
            err,
            CfDoError::SnapshotCorrupt("free_mask word count mismatch")
        ));
    }

    /// Property test: arbitrary byte strings must never cause panic,
    /// silent state corruption, or OOM allocation. Either the bytes
    /// happen to be a valid round-tripped snapshot (vanishingly
    /// unlikely for random input), or `deserialize_mux` returns an
    /// error.
    #[test]
    fn random_bytes_never_panic_or_oom() {
        use proptest::prelude::*;
        let mut runner = proptest::test_runner::TestRunner::default();
        // 1000 random small byte buffers. Capping at 4 KiB keeps the
        // test fast while still covering all the parser's
        // narrow-path failure modes.
        runner
            .run(&proptest::collection::vec(any::<u8>(), 0..4096), |bytes| {
                let res = deserialize_mux::<32, _>(&bytes, DefaultClock, MuxConfig::default());
                // Either err, or a valid restored mux. If valid, we
                // re-serialize and round-trip again to catch any
                // restore-then-reserialize divergence.
                if let Ok(mux) = res {
                    let again = serialize_mux(&mux);
                    let _ = deserialize_mux::<32, _>(&again, DefaultClock, MuxConfig::default())
                        .expect("re-deserialize of self-serialized snapshot");
                }
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn send_queue_survives_round_trip() {
        // Hibernation contract: if a slot has frames queued (Credit
        // ahead of a Body, or Body queued behind a backpressured
        // pending_write), those frames must survive
        // serialize→deserialize. Otherwise a DO that suspends while
        // backed up loses the queued Body silently.
        let mut mux: Multiplexer<32, _> =
            Multiplexer::new(Role::Client, DefaultClock, MuxConfig::default());
        let s = mux.open(0xCAFE, Metadata::new()).unwrap();
        // The OPEN frame is now queued on the slot. Add a Body on top
        // (queue depth: OPEN + Body = 2). Don't drain — we want the
        // queue populated at snapshot time.
        mux.send_body(s, Bytes::from_static(b"hello-after-wake"))
            .unwrap();

        let pre_queue_len = mux
            .iter_occupied_slots()
            .find(|(idx, _)| *idx == s)
            .map(|(_, slot)| slot.send_queue.len())
            .unwrap();
        assert_eq!(pre_queue_len, 2, "OPEN + Body should be queued");

        let bytes = serialize_mux(&mux);
        let mut restored: Multiplexer<32, _> =
            deserialize_mux(&bytes, DefaultClock, MuxConfig::default()).unwrap();
        let post_queue_len = restored
            .iter_occupied_slots()
            .find(|(idx, _)| *idx == s)
            .map(|(_, slot)| slot.send_queue.len())
            .unwrap();
        assert_eq!(post_queue_len, 2, "queue must round-trip intact");

        // Drain on the restored side and confirm both frames come out
        // in order (OPEN first, then the Body payload).
        let first = restored.next_outbound().expect("OPEN survives");
        let second = restored.next_outbound().expect("Body survives");
        assert!(
            second
                .windows(b"hello-after-wake".len())
                .any(|w| w == b"hello-after-wake"),
            "queued Body payload must survive hibernation"
        );
        let _ = first;
    }

    #[test]
    fn send_queue_exceeds_cap_rejected() {
        // Poisoned attachment claims a slot has more queued frames
        // than SLOT_QUEUE_CAP — restore must reject so a tampered
        // attachment can't blow past the bounded-queue invariant on
        // wake.
        let mut mux: Multiplexer<32, _> =
            Multiplexer::new(Role::Client, DefaultClock, MuxConfig::default());
        mux.open(0x1, Metadata::new()).unwrap();
        let mut bytes = serialize_mux(&mux);
        // The queue_len byte sits right after the deadline_flag (which
        // is 0 here — no deadline). Slot record stride to deadline_flag:
        //   13 (free_mask + count) + 2 (idx) + 2 (gen) + 1 (state)
        //   + 4 (mid) + 4 (peer_credit) + 4 (local_credit)
        //   + 4 (high_water) + 8 (opened_age) = 42 → +1 (deadline_flag)
        //   = 43, so queue_len is at offset 43.
        // Just blast every byte from 43..end looking for the 0x01 OPEN
        // queue_len byte and bump it past CAP. Simpler: rebuild the
        // expected offset from spec; if it ever drifts the test fails
        // loudly which is fine.
        let queue_len_offset = 13 + 2 + 2 + 1 + 4 + 4 + 4 + 4 + 8 + 1;
        assert_eq!(bytes[queue_len_offset], 1, "expected 1 queued OPEN frame");
        bytes[queue_len_offset] = (crate::mux::slot::SLOT_QUEUE_CAP + 1) as u8;
        let err = deserialize_mux::<32, _>(&bytes, DefaultClock, MuxConfig::default())
            .err()
            .expect("queue_len > CAP must reject");
        assert!(matches!(
            err,
            CfDoError::SnapshotCorrupt("slot send_queue exceeds cap")
        ));
    }

    #[test]
    fn terminal_frame_with_backpressure_survives_round_trip() {
        // The motivating race: both peers have called close_send, so
        // the next local terminal frame triggers `maybe_free_slot`.
        // The transport backpressures and the driver re-stashes the
        // terminal bytes via `set_pending_write`. The slot must
        // remain occupied so the snapshot validator can match
        // `pending_write` against a known (idx, generation). Before
        // the deferred-free fix this rejected with "pending_write
        // key does not match any restored slot".
        let cfg = MuxConfig::default();
        let mut client: Multiplexer<32, _> = Multiplexer::new(Role::Client, DefaultClock, cfg);
        let mut server: Multiplexer<32, _> = Multiplexer::new(Role::Server, DefaultClock, cfg);

        // Client opens; deliver OPEN to server.
        let s = client.open(0x42, Metadata::new()).unwrap();
        let open_bytes = client.next_outbound().unwrap();
        let _ = server.recv(&open_bytes).unwrap();

        // Server closes-send; deliver the End frame to client. Now
        // client has peer_terminal=true.
        server.close_send(s, None).unwrap();
        let srv_end = server.next_outbound().unwrap();
        let _ = client.recv(&srv_end).unwrap();

        // Client closes-send; the End frame is queued. Emit it.
        // Both terminals are now set on the client's slot, so the
        // OLD eager-free behavior would free the slot inside
        // next_outbound BEFORE the caller has a chance to confirm
        // the bytes shipped.
        client.close_send(s, None).unwrap();
        let end_bytes = client.next_outbound().expect("End frame");
        // Simulate transport backpressure.
        client.set_pending_write(Some(end_bytes));

        assert!(
            client.iter_occupied_slots().any(|(idx, _)| idx == s),
            "slot should remain occupied while terminal frame is in flight"
        );
        assert_eq!(client.pending_terminal_free_slice(), &[s]);

        let bytes = serialize_mux(&client);
        let mut restored: Multiplexer<32, _> = deserialize_mux(&bytes, DefaultClock, cfg).unwrap();
        assert!(
            restored.pending_write_ref().is_some(),
            "terminal frame must survive in pending_write"
        );
        assert_eq!(
            restored.pending_terminal_free_slice(),
            &[s],
            "deferred-free list must round-trip"
        );
        // Drain pending_write; slot still occupied because we haven't
        // confirmed shipment yet.
        let _ = restored.next_outbound().expect("pending_write resumes");
        assert!(
            restored.iter_occupied_slots().any(|(idx, _)| idx == s),
            "slot stays occupied until ship is confirmed"
        );
        // Calling next_outbound again (with no pending_write) acts as
        // the implicit ship-confirm and frees the slot.
        let _ = restored.next_outbound();
        assert!(
            !restored.iter_occupied_slots().any(|(idx, _)| idx == s),
            "slot frees once caller asks for next frame after a clean drain"
        );
    }

    #[test]
    fn pending_terminal_free_points_at_freed_slot_rejected() {
        // Poisoned attachment: claims a slot that's NOT in the
        // occupied list is "in flight terminal". Restore must reject
        // — otherwise the lazy free would silently target a slot
        // owned by a future open.
        let mux: Multiplexer<32, _> =
            Multiplexer::new(Role::Client, DefaultClock, MuxConfig::default());
        let mut bytes = serialize_mux(&mux);
        // Tail: [has_pending=0] [terminal_free_len=0]
        assert_eq!(*bytes.last().unwrap(), 0); // terminal_free_len
        let last = bytes.len() - 1;
        bytes[last] = 1; // claim one entry
        bytes.extend_from_slice(&0u16.to_le_bytes()); // idx=0
        let err = deserialize_mux::<32, _>(&bytes, DefaultClock, MuxConfig::default())
            .err()
            .expect("free-slot idx in terminal_free must reject");
        assert!(matches!(
            err,
            CfDoError::SnapshotCorrupt("pending_terminal_free idx is not occupied")
        ));
    }

    #[test]
    fn reset_before_terminal_emit_survives_round_trip() {
        // The app can call open + reset before the OPEN frame has shipped.
        // Slot state is Closed with send_queue=[Reset], not
        // pending_terminal_free, because reset() does not pre-emit.
        let mut mux: Multiplexer<32, _> =
            Multiplexer::new(Role::Client, DefaultClock, MuxConfig::default());
        let s = mux.open(0xCAFE, Metadata::new()).unwrap();
        // Don't drain — OPEN is still queued.
        mux.reset(s, crate::WireCode::Cancelled);
        // Slot is now Closed with send_queue=[Reset].
        let bytes = serialize_mux(&mux);
        let mut restored: Multiplexer<32, _> =
            deserialize_mux::<32, _>(&bytes, DefaultClock, MuxConfig::default())
                .expect("Closed-with-queued-Reset must round-trip");
        // Drain on the restored side: Reset must come out.
        let out = restored.next_outbound().expect("Reset must emit");
        let decoded = crate::mux::decode_keyed_frame(&out).unwrap();
        assert!(matches!(decoded.frame, crate::frame::Frame::Reset(_)));
        // Then one more next_outbound call frees the slot.
        let _ = restored.next_outbound();
        assert!(!restored.iter_occupied_slots().any(|(idx, _)| idx == s));
    }

    #[test]
    fn recv_end_after_terminal_emit_drops_terminal_free_entry() {
        // Client emits End and the peer's End arrives before the
        // next_outbound drain. recv-End frees the slot, so the
        // pending_terminal_free entry must be cleared too.
        let cfg = MuxConfig::default();
        let mut client: Multiplexer<32, _> = Multiplexer::new(Role::Client, DefaultClock, cfg);
        let mut server: Multiplexer<32, _> = Multiplexer::new(Role::Server, DefaultClock, cfg);
        let s = client.open(0x1, Metadata::new()).unwrap();
        let open_bytes = client.next_outbound().unwrap();
        let _ = server.recv(&open_bytes).unwrap();

        client.close_send(s, None).unwrap();
        let end_bytes = client.next_outbound().expect("client End");
        assert!(client.pending_terminal_free_slice().contains(&s));
        let _ = server.recv(&end_bytes).unwrap();

        server.close_send(s, None).unwrap();
        let srv_end = server.next_outbound().expect("server End");
        let _ = client.recv(&srv_end).unwrap();

        // After recv-End, client's slot is freed AND the stale
        // term_free entry should be gone.
        assert!(
            !client.pending_terminal_free_slice().contains(&s),
            "stale pending_terminal_free entry must be removed"
        );
        // Round-trip the snapshot.
        let bytes = serialize_mux(&client);
        let _restored: Multiplexer<32, _> =
            deserialize_mux::<32, _>(&bytes, DefaultClock, cfg).expect("snapshot must round-trip");
    }

    #[test]
    fn recv_reset_drops_pending_write_keyed_to_freed_slot() {
        // Client emits End for slot s, ws.send backpressures, and the driver
        // re-stashes via set_pending_write. If peer-Reset then frees s,
        // pending_write must also be cleared because it is keyed to s.
        let cfg = MuxConfig::default();
        let mut client: Multiplexer<32, _> = Multiplexer::new(Role::Client, DefaultClock, cfg);
        let mut server: Multiplexer<32, _> = Multiplexer::new(Role::Server, DefaultClock, cfg);
        let s = client.open(0x1, Metadata::new()).unwrap();
        let open_bytes = client.next_outbound().unwrap();
        let _ = server.recv(&open_bytes).unwrap();
        client.close_send(s, None).unwrap();
        let end_bytes = client.next_outbound().expect("End");
        // Simulate transport backpressure: re-stash.
        client.set_pending_write(Some(end_bytes));
        assert!(client.pending_terminal_free_slice().contains(&s));
        // Server independently resets the same slot.
        server.reset(s, crate::WireCode::Cancelled);
        let server_reset = server.next_outbound().expect("server Reset");
        // Client recvs the Reset.
        let _ = client.recv(&server_reset).unwrap();
        // pending_write must now be cleared (Bug 3 fix).
        assert!(
            client.pending_write_ref().is_none(),
            "pending_write keyed to freed slot must be cleared"
        );
        // And pending_terminal_free must be drained.
        assert!(
            !client.pending_terminal_free_slice().contains(&s),
            "term_free entry must be removed"
        );
        // Snapshot must round-trip cleanly.
        let bytes = serialize_mux(&client);
        let _restored: Multiplexer<32, _> = deserialize_mux::<32, _>(&bytes, DefaultClock, cfg)
            .expect("snapshot must round-trip after recv-Reset cleared pending_write");
    }

    #[test]
    fn credit_then_recv_end_doesnt_orphan_slot() {
        // A HalfClosedLocal slot can receive a Credit queued before the peer's
        // End arrives. Once the Credit ships, the terminal-free path must run
        // again so the slot is not orphaned.
        let cfg = MuxConfig {
            initial_credit: 100,
            credit_refill_ratio: 2,
            body_frame_max: 1024,
        };
        let mut client: Multiplexer<32, _> = Multiplexer::new(Role::Client, DefaultClock, cfg);
        let mut server: Multiplexer<32, _> = Multiplexer::new(Role::Server, DefaultClock, cfg);
        let s = client.open(0x1, Metadata::new()).unwrap();
        let open_bytes = client.next_outbound().unwrap();
        let _ = server.recv(&open_bytes).unwrap();
        // Server sends body to client to drop client's local credit.
        server.send_body(s, Bytes::from(vec![0u8; 60])).unwrap();
        let body_bytes = server.next_outbound().unwrap();
        let _ = client.recv(&body_bytes).unwrap();
        // Client close_send + emit End. Slot enters term_free.
        client.close_send(s, None).unwrap();
        let end_bytes = client.next_outbound().expect("client End");
        let _ = server.recv(&end_bytes).unwrap();
        assert!(client.pending_terminal_free_slice().contains(&s));
        // Queue a Credit refresh: local_recv_credit is below
        // threshold from the inbound Body, so prepare_credit_updates
        // will push a Credit frame to the front of the slot's queue.
        client.prepare_credit_updates();
        // Server's End arrives BEFORE the Credit ships. recv-End
        // tries to free; queue is non-empty (Credit) → no free yet.
        server.close_send(s, None).unwrap();
        let srv_end = server.next_outbound().expect("server End");
        let _ = client.recv(&srv_end).unwrap();
        // Slot is now state=Closed but holds the Credit in its
        // send_queue. term_free entry is still present (from our
        // earlier End emit).
        assert!(client.pending_terminal_free_slice().contains(&s));
        // Drain the Credit. After the pop, queue is empty and both
        // terminals are true → the post-pop check would push idx
        // (already present, dedupe keeps it at 1).
        let _credit = client.next_outbound().expect("Credit");
        assert!(client.pending_terminal_free_slice().contains(&s));
        // Next call frees the slot via drain_pending_terminal_free.
        let _ = client.next_outbound();
        assert!(
            !client.iter_occupied_slots().any(|(idx, _)| idx == s),
            "slot must free, not orphan"
        );
    }

    #[test]
    fn pending_terminal_free_idx_not_local_terminal_rejected() {
        // Poisoned attachment: the listed slot is occupied but in
        // state=OpenLocal — it can't be "in flight terminal" because
        // local_terminal is false. Restore must reject so a tampered
        // attachment can't trick the deferred-free machinery into
        // freeing a still-live slot on the next emit.
        let (_, mut bytes) = client_with_open_slot();
        // Tail layout for one occupied OpenLocal slot:
        //   ... [has_pending=0] [terminal_free_len=0]
        let last = bytes.len() - 1;
        assert_eq!(bytes[last], 0); // terminal_free_len
        bytes[last] = 1;
        bytes.extend_from_slice(&0u16.to_le_bytes()); // idx=0, OpenLocal
        let err = deserialize_mux::<32, _>(&bytes, DefaultClock, MuxConfig::default())
            .err()
            .expect("non-local-terminal slot in list must reject");
        assert!(matches!(
            err,
            CfDoError::SnapshotCorrupt("pending_terminal_free idx slot is not local-terminal")
        ));
    }

    #[test]
    fn closed_slot_not_in_terminal_free_rejected() {
        // Poisoned attachment: a slot record claims state=Closed
        // with an empty send_queue, and the slot is NOT in
        // pending_terminal_free. There's no path to free it
        // (lowest_free ignores it because the bit is clear, recv
        // side won't re-fire maybe_free_slot on a Closed slot
        // whose state has already moved, and next_outbound won't
        // re-queue terminal_free without a fresh emission). It
        // would leak forever.
        //
        // A Closed slot with a NON-empty queue is legitimate (the
        // queue may hold a Reset queued by `reset()` from a
        // non-terminal state, awaiting a future emit). That case
        // is covered by other tests; here we craft the empty-queue
        // variant which is the actual orphan shape.
        let mut mux: Multiplexer<32, _> =
            Multiplexer::new(Role::Client, DefaultClock, MuxConfig::default());
        mux.open(0x1, Metadata::new()).unwrap();
        // Drain the OPEN so send_queue is empty when we snapshot.
        let _ = mux.next_outbound().unwrap();
        let mut bytes = serialize_mux(&mux);
        // Slot record state byte sits at:
        //   13 (free_mask+count) + 2 (idx) + 2 (gen) = 17
        let state_offset = 13 + 2 + 2;
        bytes[state_offset] = STATE_CLOSED;
        let err = deserialize_mux::<32, _>(&bytes, DefaultClock, MuxConfig::default())
            .err()
            .expect("orphan Closed slot must reject");
        assert!(matches!(
            err,
            CfDoError::SnapshotCorrupt("closed slot not queued in pending_terminal_free")
        ));
    }

    #[test]
    fn pending_terminal_free_out_of_range_rejected() {
        let mux: Multiplexer<32, _> =
            Multiplexer::new(Role::Client, DefaultClock, MuxConfig::default());
        let mut bytes = serialize_mux(&mux);
        let last = bytes.len() - 1;
        bytes[last] = 1;
        bytes.extend_from_slice(&999u16.to_le_bytes()); // > N=32
        let err = deserialize_mux::<32, _>(&bytes, DefaultClock, MuxConfig::default())
            .err()
            .expect("oob idx must reject");
        assert!(matches!(
            err,
            CfDoError::SnapshotCorrupt("pending_terminal_free idx out of range")
        ));
    }

    #[test]
    fn generation_survives_round_trip() {
        // Open + reset a slot N times so its generation rolls forward,
        // then snapshot + restore. Generation must come back identical.
        let mut mux: Multiplexer<32, _> =
            Multiplexer::new(Role::Client, DefaultClock, MuxConfig::default());
        for _ in 0..5 {
            let s = mux.open(0x1, Metadata::new()).unwrap();
            mux.reset(s, crate::WireCode::Cancelled);
            // Drain so the slot returns to free.
            while mux.next_outbound().is_some() {}
        }
        let s = mux.open(0x2, Metadata::new()).unwrap();
        // Don't reset this one — leave it occupied for the snapshot.
        let pre_gen = mux
            .iter_occupied_slots()
            .find(|(idx, _)| *idx == s)
            .map(|(_, slot)| slot.generation)
            .unwrap();
        assert!(pre_gen > 0, "generation should have rolled forward");

        let bytes = serialize_mux(&mux);
        let restored: Multiplexer<32, _> =
            deserialize_mux(&bytes, DefaultClock, MuxConfig::default()).unwrap();
        let post_gen = restored
            .iter_occupied_slots()
            .find(|(idx, _)| *idx == s)
            .map(|(_, slot)| slot.generation)
            .unwrap();
        assert_eq!(pre_gen, post_gen, "generation must round-trip");
    }

    // ----------------------------------------------------------------
    // Property-based fuzz of paired-mux operation sequences.
    //
    // The targeted tests above each exercise one narrow scenario.
    // This harness runs RANDOMIZED sequences against paired client+
    // server muxes, snapshotting either side at each step and
    // restoring, then asserting:
    //
    //   I1. role + free_mask + slot table are bit-for-bit
    //       reproducible (snapshot → restore → re-snapshot is
    //       byte-equal).
    //   I2. every `pending_terminal_free` entry points at an
    //       occupied slot whose state is `HalfClosedLocal` or
    //       `Closed`.
    //   I3. every Closed slot that's iter_occupied has EITHER a
    //       non-empty send_queue OR an entry in
    //       `pending_terminal_free`.
    //   I4. `pending_write`, if Some, decodes as a keyed frame
    //       whose stream_id+generation match an iter_occupied slot.
    //
    // If any of these fail under random input, there's a
    // state-machine path we haven't covered.
    // ----------------------------------------------------------------

    /// A single op the fuzz applies to (client, server). Slot
    /// indices are bounded by `MAX_SLOTS` and applied modulo any
    /// existing slot table on the target side; out-of-range ops
    /// become no-ops, which is fine — proptest cares about state
    /// diversity, not coverage of every branch.
    #[derive(Debug, Clone)]
    enum FuzzOp {
        ClientOpen,
        ServerOpen,
        ClientSendBody { slot: u16, len: u16 },
        ServerSendBody { slot: u16, len: u16 },
        ClientCloseSend { slot: u16 },
        ServerCloseSend { slot: u16 },
        ClientReset { slot: u16 },
        ServerReset { slot: u16 },
        DeliverOneToServer,
        DeliverOneToClient,
        SnapshotClient,
        SnapshotServer,
    }

    const FUZZ_N: usize = 16;

    fn fuzz_op_strategy() -> proptest::strategy::BoxedStrategy<FuzzOp> {
        use proptest::prelude::*;
        prop_oneof![
            Just(FuzzOp::ClientOpen),
            Just(FuzzOp::ServerOpen),
            (0u16..FUZZ_N as u16, 0u16..64)
                .prop_map(|(slot, len)| FuzzOp::ClientSendBody { slot, len }),
            (0u16..FUZZ_N as u16, 0u16..64)
                .prop_map(|(slot, len)| FuzzOp::ServerSendBody { slot, len }),
            (0u16..FUZZ_N as u16).prop_map(|slot| FuzzOp::ClientCloseSend { slot }),
            (0u16..FUZZ_N as u16).prop_map(|slot| FuzzOp::ServerCloseSend { slot }),
            (0u16..FUZZ_N as u16).prop_map(|slot| FuzzOp::ClientReset { slot }),
            (0u16..FUZZ_N as u16).prop_map(|slot| FuzzOp::ServerReset { slot }),
            Just(FuzzOp::DeliverOneToServer),
            Just(FuzzOp::DeliverOneToClient),
            Just(FuzzOp::SnapshotClient),
            Just(FuzzOp::SnapshotServer),
        ]
        .boxed()
    }

    fn apply_op(
        client: &mut Multiplexer<FUZZ_N, DefaultClock>,
        server: &mut Multiplexer<FUZZ_N, DefaultClock>,
        cfg: MuxConfig,
        op: &FuzzOp,
    ) {
        match op {
            FuzzOp::ClientOpen => {
                let _ = client.open(0xC0FFEE, crate::metadata::Metadata::new());
            }
            FuzzOp::ServerOpen => {
                let _ = server.open(0xC0FFEE, crate::metadata::Metadata::new());
            }
            FuzzOp::ClientSendBody { slot, len } => {
                let _ = client.send_body(*slot, Bytes::from(vec![0u8; *len as usize]));
            }
            FuzzOp::ServerSendBody { slot, len } => {
                let _ = server.send_body(*slot, Bytes::from(vec![0u8; *len as usize]));
            }
            FuzzOp::ClientCloseSend { slot } => {
                let _ = client.close_send(*slot, None);
            }
            FuzzOp::ServerCloseSend { slot } => {
                let _ = server.close_send(*slot, None);
            }
            FuzzOp::ClientReset { slot } => {
                client.reset(*slot, crate::WireCode::Cancelled);
            }
            FuzzOp::ServerReset { slot } => {
                server.reset(*slot, crate::WireCode::Cancelled);
            }
            FuzzOp::DeliverOneToServer => {
                if let Some(bytes) = client.next_outbound() {
                    let _ = server.recv(&bytes);
                }
            }
            FuzzOp::DeliverOneToClient => {
                if let Some(bytes) = server.next_outbound() {
                    let _ = client.recv(&bytes);
                }
            }
            FuzzOp::SnapshotClient => snapshot_roundtrip_in_place(client, cfg),
            FuzzOp::SnapshotServer => snapshot_roundtrip_in_place(server, cfg),
        }
    }

    /// Round-trip a mux through serialize → deserialize → re-
    /// serialize → re-deserialize. The full chain must succeed
    /// (invariant I1: serializer always produces a snapshot the
    /// deserializer accepts) and the logical state must match the
    /// original up to time-relative fields (`opened_age_ns` and
    /// the deadline delta are reanchored to whichever `now()` the
    /// serializer captures, so byte equality is intentionally
    /// not stable across calls). Replaces the mux in place with
    /// the restored copy so subsequent ops drive restored state.
    fn snapshot_roundtrip_in_place(mux: &mut Multiplexer<FUZZ_N, DefaultClock>, cfg: MuxConfig) {
        let bytes_a = serialize_mux(mux);
        let restored: Multiplexer<FUZZ_N, _> = match deserialize_mux(&bytes_a, DefaultClock, cfg) {
            Ok(m) => m,
            Err(e) => panic!(
                "snapshot of live mux must round-trip; got {e:?}; bytes len={}",
                bytes_a.len()
            ),
        };
        // Re-serialize the restored mux and re-deserialize once
        // more: the chain must remain stable. Bytes may differ
        // from `bytes_a` only in the `opened_age_ns` and (optional)
        // `deadline_remaining_ns` per-slot deltas — both are
        // captured at serialize-time `now()` and are not part of
        // the logical state.
        let bytes_b = serialize_mux(&restored);
        let _restored2: Multiplexer<FUZZ_N, _> = deserialize_mux(&bytes_b, DefaultClock, cfg)
            .expect("re-serialize of restored mux must also round-trip");
        // Logical-state equivalence: same role, same free_mask,
        // same occupied slot table (by everything except opened_at).
        assert_eq!(mux.role(), restored.role(), "role must round-trip");
        assert_eq!(
            mux.free_mask_words(),
            restored.free_mask_words(),
            "free_mask must round-trip",
        );
        let live: Vec<_> = mux
            .iter_occupied_slots()
            .map(|(idx, s)| {
                (
                    idx,
                    s.generation,
                    s.state,
                    s.method_id,
                    s.peer_recv_credit,
                    s.local_recv_credit,
                    s.local_credit_high_water,
                    s.local_terminal,
                    s.peer_terminal,
                    s.send_queue.len(),
                )
            })
            .collect();
        let post: Vec<_> = restored
            .iter_occupied_slots()
            .map(|(idx, s)| {
                (
                    idx,
                    s.generation,
                    s.state,
                    s.method_id,
                    s.peer_recv_credit,
                    s.local_recv_credit,
                    s.local_credit_high_water,
                    s.local_terminal,
                    s.peer_terminal,
                    s.send_queue.len(),
                )
            })
            .collect();
        assert_eq!(live, post, "slot table must round-trip (mod time)");
        assert_eq!(
            mux.pending_terminal_free_slice(),
            restored.pending_terminal_free_slice(),
            "term_free must round-trip",
        );
        assert_eq!(
            mux.pending_write_ref().map(|b| b.as_ref()),
            restored.pending_write_ref().map(|b| b.as_ref()),
            "pending_write must round-trip",
        );
        *mux = restored;
    }

    /// Assert all per-mux invariants I2/I3/I4.
    fn check_invariants(mux: &Multiplexer<FUZZ_N, DefaultClock>, side: &str) {
        // I2: every term_free entry points at occupied slot with
        // state in {HalfClosedLocal, Closed}.
        for &idx in mux.pending_terminal_free_slice() {
            let slot_state = mux
                .iter_occupied_slots()
                .find(|(occ_idx, _)| *occ_idx == idx)
                .map(|(_, slot)| slot.state);
            assert!(
                slot_state.is_some(),
                "[{side}] term_free idx {idx} is not occupied"
            );
            let slot_state = slot_state.unwrap();
            assert!(
                matches!(slot_state, SlotState::HalfClosedLocal | SlotState::Closed),
                "[{side}] term_free idx {idx} has unexpected state {slot_state:?}"
            );
        }

        // I3: every OWN-PARITY Closed slot in iter_occupied has
        // either a non-empty send_queue OR is in term_free.
        // Peer-parity Closed slots are normal — `mark_free` only
        // sets bits we own, so peer-owned slot records persist
        // with state=Closed across their post-terminal lifetime
        // (the peer reopens with a bumped gen to overwrite).
        let term_free: Vec<SlotIndex> = mux.pending_terminal_free_slice().to_vec();
        let role = mux.role();
        for (idx, slot) in mux.iter_occupied_slots() {
            if role.owns_slot(idx) && slot.state == SlotState::Closed {
                let has_queue = !slot.send_queue.is_empty();
                let in_term_free = term_free.contains(&idx);
                assert!(
                    has_queue || in_term_free,
                    "[{side}] orphan Closed slot {idx}: queue empty AND not in term_free",
                );
            }
        }

        // I4: pending_write, if Some, decodes to a keyed frame
        // whose stream_id matches an occupied slot.
        if let Some(bytes) = mux.pending_write_ref() {
            let keyed =
                crate::mux::decode_keyed_frame(bytes).expect("live pending_write must decode");
            let matched = mux.iter_occupied_slots().any(|(idx, slot)| {
                idx == keyed.key.stream_id && slot.generation == keyed.key.generation
            });
            assert!(
                matched,
                "[{side}] pending_write stream_id {} gen {} doesn't match any occupied slot",
                keyed.key.stream_id, keyed.key.generation
            );
        }
    }

    #[test]
    fn fuzz_paired_mux_state_invariants() {
        let cfg = MuxConfig::default();
        let mut runner = proptest::test_runner::TestRunner::default();
        runner
            .run(
                &proptest::collection::vec(fuzz_op_strategy(), 0..96),
                |ops| {
                    let mut client: Multiplexer<FUZZ_N, _> =
                        Multiplexer::new(Role::Client, DefaultClock, cfg);
                    let mut server: Multiplexer<FUZZ_N, _> =
                        Multiplexer::new(Role::Server, DefaultClock, cfg);
                    for op in &ops {
                        apply_op(&mut client, &mut server, cfg, op);
                        check_invariants(&client, "client");
                        check_invariants(&server, "server");
                    }
                    Ok(())
                },
            )
            .unwrap();
    }
}
