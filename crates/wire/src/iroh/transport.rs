//! `StreamTransport` impl over an iroh `Connection`.

use std::sync::Arc;

use bytes::BytesMut;
use iroh::endpoint::Connection;
use tokio::sync::Mutex;

use crate::frame::{decode_frame, read_varint, Frame, OpenFrame};
use crate::metadata::Metadata;
use crate::transport::{
    AuthLevel, Inbound, PeerIdentity, StreamTransport, TransportContext,
};

use super::stream::IrohStream;

pub struct IrohTransport {
    connection: Arc<Connection>,
    accept_lock: Arc<Mutex<()>>,
}

impl IrohTransport {
    pub fn new(connection: Connection) -> Self {
        Self {
            connection: Arc::new(connection),
            accept_lock: Arc::new(Mutex::new(())),
        }
    }

    pub fn connection(&self) -> &Connection {
        &self.connection
    }

    fn peer_identity(&self) -> Option<PeerIdentity> {
        Some(PeerIdentity(
            self.connection.remote_id().to_string().into(),
        ))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum IrohTransportError {
    #[error("connection: {0}")]
    Connection(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("frame: {0}")]
    Frame(#[from] crate::frame::FrameError),
    #[error("unexpected first frame")]
    UnexpectedFirstFrame,
}

impl StreamTransport for IrohTransport {
    type Stream = IrohStream;
    type Error = IrohTransportError;

    async fn open(
        &self,
        method_id: u32,
        headers: Metadata,
    ) -> Result<Self::Stream, Self::Error> {
        let (send, recv) = self
            .connection
            .open_bi()
            .await
            .map_err(|e| IrohTransportError::Connection(e.to_string()))?;
        let mut stream = IrohStream::new(send, recv);
        stream.write_open(method_id, headers).await?;
        Ok(stream)
    }

    async fn accept(&self) -> Result<Option<Inbound<Self::Stream>>, Self::Error> {
        let _guard = self.accept_lock.lock().await;
        let (send, mut recv) = match self.connection.accept_bi().await {
            Ok(pair) => pair,
            Err(e) => {
                return Err(IrohTransportError::Connection(e.to_string()));
            }
        };

        // Read the OpenFrame off the wire to populate Inbound metadata.
        let mut read_buf = BytesMut::new();
        let (method_id, headers) = loop {
            // Try to pop OpenFrame
            if !read_buf.is_empty() {
                match try_peek_open(&read_buf) {
                    Ok(Some((mid, hdr, _consumed))) => {
                        break (mid, hdr);
                    }
                    Ok(None) => {}
                    Err(e) => return Err(e.into()),
                }
            }
            let mut tmp = [0u8; 4096];
            match recv.read(&mut tmp).await {
                Ok(Some(0)) | Ok(None) => return Ok(None),
                Ok(Some(n)) => read_buf.extend_from_slice(&tmp[..n]),
                Err(e) => return Err(IrohTransportError::Connection(e.to_string())),
            }
        };

        // We've peeked the open frame from `read_buf`; the rest of
        // read_buf is body data the recv-half will continue from.
        // To keep this simple, re-construct an IrohStream and stash
        // residual bytes via a prefix-channel pattern. For the first
        // pass, we re-encode the residual via a small wrapper... but
        // iroh::endpoint::RecvStream doesn't support unread. We
        // accept this limitation by requiring writers to flush the
        // OPEN frame before sending body bytes (most code paths do
        // this naturally).
        //
        // Therefore: after pop-up, we need to ensure any leftover
        // bytes (a body chunk that already arrived) is replayed to
        // the IrohStream's recv half. Approach: use a small wrapper
        // recv that yields residual bytes first, then defers.

        let residual = read_buf.freeze();
        let stream = if residual.is_empty() {
            IrohStream::new(send, recv)
        } else {
            // Writers MUST flush OPEN before sending body bytes so we
            // don't have to buffer residual. Surface this as a
            // protocol error rather than silently dropping or
            // mis-routing bytes.
            return Err(IrohTransportError::Connection(
                "OPEN frame must be flushed before body bytes".to_string(),
            ));
        };

        Ok(Some(Inbound {
            method_id,
            headers,
            stream,
            context: TransportContext {
                peer: self.peer_identity(),
                rtt_ms: None, // iroh's rtt() requires a PathId; surface later via a helper
                auth_level: AuthLevel::Vouched,
            },
        }))
    }
}

fn try_peek_open(
    buf: &[u8],
) -> Result<Option<(u32, Metadata, usize)>, crate::frame::FrameError> {
    if buf.is_empty() {
        return Ok(None);
    }
    let (len, consumed) = match read_varint(buf) {
        Ok(v) => v,
        Err(_) => return Ok(None),
    };
    let len = len as usize;
    if buf.len() < consumed + len {
        return Ok(None);
    }
    let frame = decode_frame(&buf[consumed..consumed + len])?;
    match frame {
        Frame::Open(OpenFrame { method_id, headers }) => {
            Ok(Some((method_id, headers, consumed + len)))
        }
        _ => Err(crate::frame::FrameError::UnknownKind(0)),
    }
}
