//! `Stream` impl over an iroh QUIC substream (Send + Recv).

use std::pin::Pin;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::task::{Context, Poll};

use bytes::{Bytes, BytesMut};
use futures_core::Stream as FuturesStream;
use iroh::endpoint::{RecvStream, SendStream};

use crate::frame::{
    decode_frame, encode_frame, read_varint_partial, write_varint, EndFrame, Frame, FrameError,
    OpenFrame, MAX_FRAME_BYTES,
};
use crate::metadata::{Metadata, Trailer};
use crate::status::WireCode;

const STREAM_ERROR_CODE: u32 = 1;

/// Bidi RPC stream over an iroh substream. Frames inside use a
/// `[varint len][frame_kind][body]` framing because iroh streams
/// are byte-oriented (not message-oriented).
pub struct IrohStream {
    send: Option<SendStream>,
    recv: Option<RecvStream>,
    /// Bytes already read off the wire that haven't been consumed yet —
    /// happens when the OPEN frame and the first Body frame arrive in
    /// the same TCP segment and the accept loop reads past OPEN.
    prefix: BytesMut,
    reset_flag: Arc<AtomicBool>,
}

impl IrohStream {
    pub(crate) fn new(send: SendStream, recv: RecvStream) -> Self {
        Self {
            send: Some(send),
            recv: Some(recv),
            prefix: BytesMut::new(),
            reset_flag: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Construct with bytes already pre-read off the wire. The recv-half
    /// will yield these bytes before pulling anything new from the
    /// underlying RecvStream.
    pub(crate) fn with_prefix(send: SendStream, recv: RecvStream, prefix: BytesMut) -> Self {
        Self {
            send: Some(send),
            recv: Some(recv),
            prefix,
            reset_flag: Arc::new(AtomicBool::new(false)),
        }
    }

    pub(crate) async fn write_open(
        &mut self,
        method_id: u32,
        headers: Metadata,
    ) -> std::io::Result<()> {
        let mut buf = BytesMut::with_capacity(128);
        encode_frame(&Frame::Open(OpenFrame { method_id, headers }), &mut buf);
        self.write_framed(&buf).await
    }

    async fn write_framed(&mut self, frame_bytes: &[u8]) -> std::io::Result<()> {
        let mut len_buf = BytesMut::with_capacity(10);
        write_varint(frame_bytes.len() as u64, &mut len_buf);
        let send = self
            .send
            .as_mut()
            .ok_or_else(|| std::io::Error::other("send half closed"))?;
        send.write_all(&len_buf).await?;
        send.write_all(frame_bytes).await?;
        Ok(())
    }
}

impl crate::transport::Stream for IrohStream {
    type SendError = std::io::Error;
    type RecvError = std::io::Error;

    type SendHalf = IrohSendHalf;
    type RecvHalf = IrohRecvHalf;

    fn split(mut self) -> (Self::SendHalf, Self::RecvHalf) {
        let send = self.send.take().expect("send already taken");
        let recv = self.recv.take().expect("recv already taken");
        let flag = self.reset_flag.clone();
        let flag2 = self.reset_flag.clone();
        (
            IrohSendHalf {
                send: Some(send),
                reset_flag: flag,
            },
            IrohRecvHalf {
                recv: Some(recv),
                read_buf: std::mem::take(&mut self.prefix),
                trailer: None,
                reset_flag: flag2,
                done: false,
            },
        )
    }

    fn reset(&mut self, _code: WireCode) {
        if let Some(mut s) = self.send.take() {
            let _ = s.reset(STREAM_ERROR_CODE.into());
        }
        if let Some(mut r) = self.recv.take() {
            let _ = r.stop(STREAM_ERROR_CODE.into());
        }
        self.reset_flag.store(true, Ordering::Release);
    }
}

pub struct IrohSendHalf {
    send: Option<SendStream>,
    reset_flag: Arc<AtomicBool>,
}

impl IrohSendHalf {
    async fn write_framed(&mut self, frame_bytes: &[u8]) -> std::io::Result<()> {
        let send = self
            .send
            .as_mut()
            .ok_or_else(|| std::io::Error::other("send half closed"))?;
        let mut len_buf = BytesMut::with_capacity(10);
        write_varint(frame_bytes.len() as u64, &mut len_buf);
        send.write_all(&len_buf).await?;
        send.write_all(frame_bytes).await?;
        Ok(())
    }
}

impl crate::transport::SendHalf for IrohSendHalf {
    type Error = std::io::Error;

    async fn send_body(&mut self, payload: Bytes) -> Result<(), Self::Error> {
        let mut buf = BytesMut::with_capacity(payload.len() + 16);
        encode_frame(&Frame::Body(payload), &mut buf);
        self.write_framed(&buf).await
    }

    async fn close_send(&mut self, trailer: Option<Trailer>) -> Result<(), Self::Error> {
        let trailer = trailer.unwrap_or_default();
        let mut buf = BytesMut::with_capacity(64);
        encode_frame(
            &Frame::End(EndFrame {
                status: trailer.status,
                trailer,
            }),
            &mut buf,
        );
        self.write_framed(&buf).await?;
        if let Some(mut s) = self.send.take() {
            let _ = s.finish();
        }
        Ok(())
    }

    fn reset(&mut self, _code: WireCode) {
        if let Some(mut s) = self.send.take() {
            let _ = s.reset(STREAM_ERROR_CODE.into());
        }
        self.reset_flag.store(true, Ordering::Release);
    }
}

pub struct IrohRecvHalf {
    recv: Option<RecvStream>,
    read_buf: BytesMut,
    trailer: Option<Trailer>,
    reset_flag: Arc<AtomicBool>,
    done: bool,
}

impl FuturesStream for IrohRecvHalf {
    type Item = Result<Bytes, std::io::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // Drive a manual state machine reading framed bytes from the iroh
        // recv stream. We use a simple loop with futures::pin_mut on the
        // recv future.
        // For simplicity we use tokio::io read_buf via the AsyncReadExt
        // helpers, polling in a future-driving block.
        let this = self.get_mut();
        loop {
            if this.done {
                return Poll::Ready(None);
            }
            // Try to decode a frame from the buffer.
            match try_pop_frame(&mut this.read_buf) {
                Ok(Some(frame)) => match frame {
                    Frame::Body(b) => return Poll::Ready(Some(Ok(b))),
                    Frame::End(end) => {
                        this.trailer = Some(end.trailer);
                        this.done = true;
                        return Poll::Ready(None);
                    }
                    Frame::Reset(r) => {
                        this.trailer = Some(Trailer::from_status(r.code, "reset"));
                        this.done = true;
                        return Poll::Ready(None);
                    }
                    Frame::Open(_) | Frame::Credit(_) => {
                        // Open shouldn't arrive mid-stream on iroh;
                        // Credit isn't used on iroh (QUIC has flow
                        // control). Skip with a protocol error.
                        return Poll::Ready(Some(Err(std::io::Error::other(
                            "unexpected frame on iroh stream",
                        ))));
                    }
                },
                Ok(None) => { /* fall through to read more bytes */ }
                Err(e) => {
                    // Fatal parse error (malformed varint, oversized
                    // length, decode failure). The wire is poisoned;
                    // stop reading, signal end, and stash a synthetic
                    // trailer so trailer-aware consumers see the
                    // protocol failure rather than a silent close.
                    this.done = true;
                    if let Some(mut r) = this.recv.take() {
                        let _ = r.stop(STREAM_ERROR_CODE.into());
                    }
                    if this.trailer.is_none() {
                        this.trailer = Some(Trailer::from_status(
                            WireCode::Internal,
                            "frame decode error",
                        ));
                    }
                    return Poll::Ready(Some(Err(std::io::Error::other(format!(
                        "frame decode: {e}"
                    )))));
                }
            }

            let recv = match this.recv.as_mut() {
                Some(r) => r,
                None => {
                    this.done = true;
                    return Poll::Ready(None);
                }
            };
            // Read more bytes via a BytesMut-extending API to avoid
            // splitting borrow of `tmp` and the future at once.
            let mut tmp_box: Box<[u8; 8192]> = Box::new([0u8; 8192]);
            let n;
            {
                let read_fut = recv.read(&mut *tmp_box);
                tokio::pin!(read_fut);
                match read_fut.as_mut().poll(cx) {
                    Poll::Ready(Ok(Some(read_n))) => n = read_n,
                    Poll::Ready(Ok(None)) => {
                        this.done = true;
                        return Poll::Ready(None);
                    }
                    Poll::Ready(Err(e)) => {
                        this.done = true;
                        return Poll::Ready(Some(Err(std::io::Error::other(format!(
                            "iroh recv: {e}"
                        )))));
                    }
                    Poll::Pending => return Poll::Pending,
                }
            }
            this.read_buf.extend_from_slice(&tmp_box[..n]);
        }
    }
}

impl crate::transport::RecvHalf for IrohRecvHalf {
    type Error = std::io::Error;

    fn trailer(&self) -> Option<&Trailer> {
        self.trailer.as_ref()
    }

    fn reset(&mut self, _code: WireCode) {
        if let Some(mut r) = self.recv.take() {
            let _ = r.stop(STREAM_ERROR_CODE.into());
        }
        self.reset_flag.store(true, Ordering::Release);
        self.done = true;
        if self.trailer.is_none() {
            self.trailer = Some(Trailer::from_status(WireCode::Cancelled, "local reset"));
        }
    }
}

/// Tri-state parse of the next length-prefixed frame.
///
/// - `Ok(Some(frame))` — decoded; the bytes have been split off `buf`.
/// - `Ok(None)` — need more bytes; varint or body is truncated.
/// - `Err(_)` — fatal: corrupt varint or oversized announced length.
///   Caller must abort the stream; buffering more bytes cannot recover.
fn try_pop_frame(buf: &mut BytesMut) -> Result<Option<Frame>, FrameError> {
    let (len, consumed) = match read_varint_partial(buf)? {
        Some(v) => v,
        None => return Ok(None),
    };
    let len = len as usize;
    if len > MAX_FRAME_BYTES {
        return Err(FrameError::OversizedFrame {
            len,
            cap: MAX_FRAME_BYTES,
        });
    }
    if buf.len() < consumed + len {
        return Ok(None);
    }
    let frame_bytes = buf.split_to(consumed + len);
    let frame = decode_frame(&frame_bytes[consumed..])?;
    Ok(Some(frame))
}

#[cfg(test)]
mod parse_tests {
    use super::*;

    #[test]
    fn malformed_varint_is_fatal_not_buffer_growth() {
        // Old behaviour: every varint error collapsed to Ok(None), so
        // the recv loop kept extending the read buffer waiting for
        // more bytes — a peer could send 0xFF repeatedly and OOM us.
        // New behaviour: 10 continuation bytes is fatal.
        let mut buf = BytesMut::from(&[0xFFu8; 10][..]);
        let err = try_pop_frame(&mut buf).unwrap_err();
        assert!(matches!(err, FrameError::BadVarint));
        // Buffer is NOT consumed on fatal error — the caller decides
        // to abort, no point in advancing.
        assert_eq!(buf.len(), 10);
    }

    #[test]
    fn oversized_announced_length_is_fatal_before_buffering() {
        // A peer announces u64::MAX as the frame length. We must reject
        // BEFORE attempting to wait for that many bytes.
        let mut buf = BytesMut::new();
        write_varint(u64::MAX, &mut buf);
        let err = try_pop_frame(&mut buf).unwrap_err();
        assert!(matches!(
            err,
            FrameError::OversizedFrame { len: _, cap: _ }
        ));
    }

    #[test]
    fn truncated_varint_is_recoverable() {
        // A varint can legitimately straddle a TCP/QUIC read boundary.
        // ≤ 9 continuation bytes is "need more bytes", not fatal.
        for n in 1usize..=9 {
            let buf_data = vec![0xFFu8; n];
            let mut buf = BytesMut::from(&buf_data[..]);
            let out = try_pop_frame(&mut buf).unwrap();
            assert!(out.is_none(), "n={n} should be recoverable");
            // Buffer is preserved across the partial read.
            assert_eq!(buf.len(), n);
        }
    }
}
