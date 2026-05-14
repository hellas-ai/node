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
use crate::mux::{Event, MuxConfig, MuxError, Multiplexer, Role, SlotIndex, SlotState, StreamSlot};

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
//   [has_pending: u8]
//   [pending_len: varint]?       // present iff has_pending == 1
//   [pending_bytes]?
//
// `Instant`s are captured as deltas relative to the clock's `now()` at
// serialize time, and re-anchored relative to `now()` at deserialize
// time — `Instant` is opaque and not stable across hibernation.

const SNAPSHOT_MAGIC: u8 = 0xA1;

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
    }

    match mux.pending_write_ref() {
        Some(pending) => {
            out.push(1);
            write_varint(pending.len() as u64, &mut out);
            out.extend_from_slice(pending);
        }
        None => out.push(0),
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
    let mut cur = Cursor::new(bytes);

    let magic = cur.take_u8()?;
    if magic != SNAPSHOT_MAGIC {
        return Err(CfDoError::SnapshotCorrupt("bad magic"));
    }
    let role = role_from_tag(cur.take_u8()?)?;
    let now = clock.now();

    // Reconstruct mux with default state, then overwrite.
    let mut mux = Multiplexer::<N, C>::new(role, clock, config);

    let n_words = cur.take_u16()? as usize;
    let mut words = Vec::with_capacity(n_words);
    for _ in 0..n_words {
        words.push(cur.take_u64()?);
    }
    mux.set_free_mask_words(&words);

    let (count, _) = cur.take_varint()?;
    for _ in 0..count {
        let idx = cur.take_u16()?;
        let generation = cur.take_u16()?;
        let state = state_from_tag(cur.take_u8()?)?;
        let method_id = cur.take_u32()?;
        let peer_recv_credit = cur.take_u32()?;
        let local_recv_credit = cur.take_u32()?;
        let local_credit_high_water = cur.take_u32()?;
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

        let slot = Multiplexer::<N, C>::make_restored_slot(
            generation,
            state,
            method_id,
            opened_at,
            deadline,
            peer_recv_credit,
            local_recv_credit,
            local_credit_high_water,
        );
        mux.restore_slot(idx, slot);
    }

    let has_pending = cur.take_u8()?;
    match has_pending {
        0 => mux.set_pending_write(None),
        1 => {
            let (len, _) = cur.take_varint()?;
            let bytes = cur.take_bytes(len as usize)?;
            mux.set_pending_write(Some(Bytes::copy_from_slice(bytes)));
        }
        _ => return Err(CfDoError::SnapshotCorrupt("bad has_pending flag")),
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

fn mux_clock_now<const N: usize, C: Clock>(
    mux: &Multiplexer<N, C>,
) -> web_time::Instant {
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
}
