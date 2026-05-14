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
    let peer_parity_mask: u64 = if role.parity() == 0 { 0xAAAA_AAAA_AAAA_AAAA } else { 0x5555_5555_5555_5555 };
    for (word_idx, word) in words.iter().enumerate() {
        if word & peer_parity_mask != 0 {
            // Allow leniency on the LAST word: bits beyond N are masked off below.
            let tail_bits_in_word = (word_idx + 1) * 64;
            if tail_bits_in_word <= N || (word & peer_parity_mask) & ((1u64 << (N - word_idx * 64)) - 1) != 0 {
                return Err(CfDoError::SnapshotCorrupt(
                    "free_mask sets a bit owned by peer parity",
                ));
            }
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
            return Err(CfDoError::SnapshotCorrupt(
                "local_recv_credit > high_water",
            ));
        }
        // Sanity: peer_recv_credit shouldn't exceed config's initial
        // credit (the peer wouldn't have advertised more than they
        // were ever willing to receive).
        if peer_recv_credit > mux_config.initial_credit {
            return Err(CfDoError::SnapshotCorrupt(
                "peer_recv_credit > initial",
            ));
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
            let len = len as usize;
            if len > PENDING_WRITE_MAX {
                return Err(CfDoError::SnapshotCorrupt(
                    "pending_write exceeds budget",
                ));
            }
            let bytes = cur.take_bytes(len)?;
            mux.set_pending_write(Some(Bytes::copy_from_slice(bytes)));
        }
        _ => return Err(CfDoError::SnapshotCorrupt("bad has_pending flag")),
    }

    // Trailing-bytes check: the snapshot must be exactly the right
    // length. Extra bytes mean someone appended a payload we don't
    // know how to parse — reject.
    if cur.pos != bytes.len() {
        return Err(CfDoError::SnapshotCorrupt(
            "trailing bytes after snapshot",
        ));
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
            let res = deserialize_mux::<32, _>(
                truncated,
                DefaultClock,
                MuxConfig::default(),
            );
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
            .err().expect("bad magic must reject");
        assert!(matches!(err, CfDoError::SnapshotCorrupt("bad magic")));
    }

    #[test]
    fn future_magic_byte_rejected_with_named_error() {
        // Version-upgrade scenario: a future DO writes a snapshot with
        // a newer magic byte. The current code must NOT silently parse
        // it as the legacy format.
        let (_, mut bytes) = client_with_open_slot();
        bytes[0] = 0xA2;
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
            .err().expect("count > N must reject");
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
            .err().expect("duplicate slot idx must reject");
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
            .err().expect("slot occupied AND in free_mask must reject");
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
            .err().expect("peer-parity slot in our free_mask must reject");
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
            .err().expect("local_recv_credit > high_water must reject");
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
        // Replace the has_pending=0 trailer with has_pending=1 + 1 MiB.
        // The has_pending byte is the LAST byte before any pending data.
        // Find and overwrite.
        assert_eq!(*bytes.last().unwrap(), 0); // pending=None
        let last = bytes.len() - 1;
        bytes[last] = 1;
        let mut len_varint = Vec::new();
        write_varint(1 * 1024 * 1024, &mut len_varint);
        bytes.extend(len_varint);
        // We don't even need the trailing bytes — the check fires on length.
        let err = deserialize_mux::<32, _>(&bytes, DefaultClock, MuxConfig::default())
            .err().expect("oversized pending_write must reject");
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
            .err().expect("trailing bytes must reject");
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
            .err().expect("mismatched N must reject");
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
                let res = deserialize_mux::<32, _>(
                    &bytes,
                    DefaultClock,
                    MuxConfig::default(),
                );
                // Either err, or a valid restored mux. If valid, we
                // re-serialize and round-trip again to catch any
                // restore-then-reserialize divergence.
                if let Ok(mux) = res {
                    let again = serialize_mux(&mux);
                    let _ = deserialize_mux::<32, _>(
                        &again,
                        DefaultClock,
                        MuxConfig::default(),
                    )
                    .expect("re-deserialize of self-serialized snapshot");
                }
                Ok(())
            })
            .unwrap();
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
}
