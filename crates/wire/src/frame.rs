//! Frame format. One `Frame` type, two wire wrappers (mux prepends
//! stream_key + gen; iroh omits both).

use bytes::Bytes;

use crate::metadata::{Metadata, Trailer};
use crate::status::WireCode;

#[derive(Clone, Debug)]
pub enum Frame {
    Open(OpenFrame),
    Body(Bytes),
    End(EndFrame),
    Reset(ResetFrame),
    Credit(CreditFrame),
}

#[derive(Clone, Debug)]
pub struct OpenFrame {
    pub method_id: u32,
    pub headers: Metadata,
}

#[derive(Clone, Debug)]
pub struct EndFrame {
    pub status: WireCode,
    pub trailer: Trailer,
}

#[derive(Clone, Copy, Debug)]
pub struct ResetFrame {
    pub code: WireCode,
}

#[derive(Clone, Copy, Debug)]
pub struct CreditFrame {
    pub additional_bytes: u32,
}

// -- Frame discriminator -----------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum FrameKind {
    Open = 0,
    Body = 1,
    End = 2,
    Reset = 3,
    Credit = 4,
}

impl FrameKind {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Open),
            1 => Some(Self::Body),
            2 => Some(Self::End),
            3 => Some(Self::Reset),
            4 => Some(Self::Credit),
            _ => None,
        }
    }

    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

impl Frame {
    pub fn kind(&self) -> FrameKind {
        match self {
            Self::Open(_) => FrameKind::Open,
            Self::Body(_) => FrameKind::Body,
            Self::End(_) => FrameKind::End,
            Self::Reset(_) => FrameKind::Reset,
            Self::Credit(_) => FrameKind::Credit,
        }
    }
}

// -- Decode error ------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("frame too short: need {needed} bytes, got {got}")]
    Short { needed: usize, got: usize },
    #[error("unknown frame kind: {0}")]
    UnknownKind(u8),
    #[error("unknown wire code: {0}")]
    UnknownCode(u8),
    #[error("frame body exceeds limit: {len} > {limit}")]
    BodyTooLarge { len: usize, limit: usize },
    #[error("metadata key not utf-8")]
    BadKeyUtf8,
    #[error("metadata value not utf-8")]
    BadValueUtf8,
    #[error("varint too long")]
    BadVarint,
}

// -- Wire codec --------------------------------------------------------------
//
// Self-describing frame body layout per kind:
//
//   Open:   [method_id: u32 LE] [metadata]
//   Body:   [payload bytes (rest)]
//   End:    [status: u8] [message_len: varint] [message_bytes] [metadata]
//   Reset:  [code: u8]
//   Credit: [additional_bytes: u32 LE]
//
// Metadata layout:
//   [count: varint]
//   for each entry:
//     [key_len: varint] [key_utf8]
//     [tag: u8]  // 0 = text, 1 = bytes
//     [value_len: varint]
//     [value_bytes]
//
// Frame on the wire is `[kind: u8] [body...]`. Mux transports prepend
// `[stream_id: u16 BE] [gen: u16 BE] [length: varint]` outside this.

pub fn encode_body_bytes(payload: Bytes) -> Bytes {
    // Body's body is just the payload — kind byte + payload bytes. Caller
    // is expected to prepend the kind byte. We expose this helper for
    // zero-copy assembly at the transport layer; see encode_frame for
    // the general case.
    payload
}

pub fn encode_frame(frame: &Frame, out: &mut bytes::BytesMut) {
    out.extend_from_slice(&[frame.kind().as_u8()]);
    match frame {
        Frame::Open(open) => {
            out.extend_from_slice(&open.method_id.to_le_bytes());
            encode_metadata(&open.headers, out);
        }
        Frame::Body(payload) => {
            out.extend_from_slice(payload);
        }
        Frame::End(end) => {
            out.extend_from_slice(&[end.trailer.status.as_u8()]);
            write_varint(end.trailer.message.len() as u64, out);
            out.extend_from_slice(end.trailer.message.as_bytes());
            encode_metadata(&end.trailer.metadata, out);
            let _ = end.status; // EndFrame.status is redundant with trailer.status;
        }
        Frame::Reset(r) => {
            out.extend_from_slice(&[r.code.as_u8()]);
        }
        Frame::Credit(c) => {
            out.extend_from_slice(&c.additional_bytes.to_le_bytes());
        }
    }
}

pub fn decode_frame(buf: &[u8]) -> Result<Frame, FrameError> {
    if buf.is_empty() {
        return Err(FrameError::Short {
            needed: 1,
            got: 0,
        });
    }
    let kind = FrameKind::from_u8(buf[0]).ok_or(FrameError::UnknownKind(buf[0]))?;
    let body = &buf[1..];
    match kind {
        FrameKind::Open => {
            if body.len() < 4 {
                return Err(FrameError::Short {
                    needed: 4,
                    got: body.len(),
                });
            }
            let method_id = u32::from_le_bytes([body[0], body[1], body[2], body[3]]);
            let headers = decode_metadata(&body[4..])?.0;
            Ok(Frame::Open(OpenFrame { method_id, headers }))
        }
        FrameKind::Body => Ok(Frame::Body(Bytes::copy_from_slice(body))),
        FrameKind::End => {
            if body.is_empty() {
                return Err(FrameError::Short {
                    needed: 1,
                    got: 0,
                });
            }
            let status =
                WireCode::from_u8(body[0]).ok_or(FrameError::UnknownCode(body[0]))?;
            let (msg_len, msg_consumed) = read_varint(&body[1..])?;
            let msg_len = msg_len as usize;
            let msg_start = 1 + msg_consumed;
            if body.len() < msg_start + msg_len {
                return Err(FrameError::Short {
                    needed: msg_start + msg_len,
                    got: body.len(),
                });
            }
            let message = std::str::from_utf8(&body[msg_start..msg_start + msg_len])
                .map_err(|_| FrameError::BadValueUtf8)?
                .into();
            let metadata = decode_metadata(&body[msg_start + msg_len..])?.0;
            Ok(Frame::End(EndFrame {
                status,
                trailer: Trailer {
                    status,
                    message,
                    metadata,
                },
            }))
        }
        FrameKind::Reset => {
            if body.is_empty() {
                return Err(FrameError::Short {
                    needed: 1,
                    got: 0,
                });
            }
            let code =
                WireCode::from_u8(body[0]).ok_or(FrameError::UnknownCode(body[0]))?;
            Ok(Frame::Reset(ResetFrame { code }))
        }
        FrameKind::Credit => {
            if body.len() < 4 {
                return Err(FrameError::Short {
                    needed: 4,
                    got: body.len(),
                });
            }
            let additional_bytes =
                u32::from_le_bytes([body[0], body[1], body[2], body[3]]);
            Ok(Frame::Credit(CreditFrame { additional_bytes }))
        }
    }
}

// -- Metadata codec ----------------------------------------------------------

fn encode_metadata(meta: &Metadata, out: &mut bytes::BytesMut) {
    write_varint(meta.len() as u64, out);
    for (key, value) in meta.iter() {
        write_varint(key.len() as u64, out);
        out.extend_from_slice(key.as_bytes());
        match value {
            crate::metadata::MetadataValue::Text(s) => {
                out.extend_from_slice(&[0]);
                write_varint(s.len() as u64, out);
                out.extend_from_slice(s.as_bytes());
            }
            crate::metadata::MetadataValue::Bytes(b) => {
                out.extend_from_slice(&[1]);
                write_varint(b.len() as u64, out);
                out.extend_from_slice(b);
            }
        }
    }
}

fn decode_metadata(buf: &[u8]) -> Result<(Metadata, usize), FrameError> {
    let (count, consumed) = read_varint(buf)?;
    let mut pos = consumed;
    let mut meta = Metadata::with_capacity(count as usize);
    for _ in 0..count {
        let (key_len, c) = read_varint(&buf[pos..])?;
        pos += c;
        let key_len = key_len as usize;
        if buf.len() < pos + key_len {
            return Err(FrameError::Short {
                needed: pos + key_len,
                got: buf.len(),
            });
        }
        let key = std::str::from_utf8(&buf[pos..pos + key_len])
            .map_err(|_| FrameError::BadKeyUtf8)?
            .to_string();
        pos += key_len;
        if buf.len() < pos + 1 {
            return Err(FrameError::Short {
                needed: pos + 1,
                got: buf.len(),
            });
        }
        let tag = buf[pos];
        pos += 1;
        let (val_len, c) = read_varint(&buf[pos..])?;
        pos += c;
        let val_len = val_len as usize;
        if buf.len() < pos + val_len {
            return Err(FrameError::Short {
                needed: pos + val_len,
                got: buf.len(),
            });
        }
        let value = match tag {
            0 => {
                let s = std::str::from_utf8(&buf[pos..pos + val_len])
                    .map_err(|_| FrameError::BadValueUtf8)?;
                crate::metadata::MetadataValue::Text(s.into())
            }
            1 => crate::metadata::MetadataValue::Bytes(Bytes::copy_from_slice(
                &buf[pos..pos + val_len],
            )),
            other => return Err(FrameError::UnknownKind(other)),
        };
        pos += val_len;
        meta.insert(key, value);
    }
    Ok((meta, pos))
}

// -- Varint ------------------------------------------------------------------

pub(crate) fn write_varint(mut v: u64, out: &mut bytes::BytesMut) {
    while v >= 0x80 {
        out.extend_from_slice(&[(v as u8) | 0x80]);
        v >>= 7;
    }
    out.extend_from_slice(&[v as u8]);
}

pub(crate) fn read_varint(buf: &[u8]) -> Result<(u64, usize), FrameError> {
    let mut result: u64 = 0;
    let mut shift = 0;
    for (i, byte) in buf.iter().take(10).enumerate() {
        result |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok((result, i + 1));
        }
        shift += 7;
    }
    Err(FrameError::BadVarint)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_roundtrip() {
        for v in [0u64, 1, 127, 128, 300, 16384, u64::MAX] {
            let mut buf = bytes::BytesMut::new();
            write_varint(v, &mut buf);
            let (decoded, _) = read_varint(&buf).unwrap();
            assert_eq!(v, decoded);
        }
    }

    #[test]
    fn open_frame_roundtrip() {
        let mut headers = Metadata::new();
        headers.insert_text("k1", "v1");
        headers.insert_bytes("k2-bin", Bytes::from_static(b"\x01\x02\x03"));
        let frame = Frame::Open(OpenFrame {
            method_id: 0xDEAD_BEEF,
            headers,
        });
        let mut buf = bytes::BytesMut::new();
        encode_frame(&frame, &mut buf);
        let decoded = decode_frame(&buf).unwrap();
        match decoded {
            Frame::Open(o) => {
                assert_eq!(o.method_id, 0xDEAD_BEEF);
                assert_eq!(o.headers.get("k1").unwrap().as_text(), Some("v1"));
                assert_eq!(
                    o.headers.get("k2-bin").unwrap().as_bytes(),
                    Some(&b"\x01\x02\x03"[..])
                );
            }
            _ => panic!("expected Open"),
        }
    }

    #[test]
    fn end_frame_roundtrip() {
        let frame = Frame::End(EndFrame {
            status: WireCode::Ok,
            trailer: Trailer::from_status(WireCode::Ok, "done"),
        });
        let mut buf = bytes::BytesMut::new();
        encode_frame(&frame, &mut buf);
        let decoded = decode_frame(&buf).unwrap();
        match decoded {
            Frame::End(e) => {
                assert_eq!(e.trailer.status, WireCode::Ok);
                assert_eq!(e.trailer.message.as_str(), "done");
            }
            _ => panic!("expected End"),
        }
    }
}
