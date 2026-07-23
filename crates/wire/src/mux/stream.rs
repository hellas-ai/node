//! `MuxStream`: per-RPC view on top of a driver-owned `Multiplexer`.
//! Halves communicate with the driver via command channels.

use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use futures_core::Stream as FuturesStream;
use tokio::sync::{mpsc, oneshot};

use crate::metadata::Trailer;
use crate::status::WireCode;

use super::slot::SlotIndex;
use super::state::MuxError;
use super::transport::Command;

pub struct MuxStream {
    slot: SlotIndex,
    cmd_tx: mpsc::UnboundedSender<Command>,
    recv_rx: Option<mpsc::UnboundedReceiver<Result<Bytes, std::io::Error>>>,
    trailer_rx: Option<oneshot::Receiver<Trailer>>,
}

impl MuxStream {
    pub(crate) fn new(
        slot: SlotIndex,
        cmd_tx: mpsc::UnboundedSender<Command>,
        recv_rx: mpsc::UnboundedReceiver<Result<Bytes, std::io::Error>>,
        trailer_rx: oneshot::Receiver<Trailer>,
    ) -> Self {
        Self {
            slot,
            cmd_tx,
            recv_rx: Some(recv_rx),
            trailer_rx: Some(trailer_rx),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum MuxStreamError {
    #[error("mux: {0}")]
    Mux(#[from] MuxError),
    #[error("transport closed")]
    Closed,
}

impl crate::transport::Stream for MuxStream {
    type SendError = MuxStreamError;
    type RecvError = std::io::Error;

    type SendHalf = MuxSendHalf;
    type RecvHalf = MuxRecvHalf;

    fn split(mut self) -> (Self::SendHalf, Self::RecvHalf) {
        let recv_rx = self.recv_rx.take().expect("recv already taken");
        let trailer_rx = self.trailer_rx.take().expect("trailer already taken");
        (
            MuxSendHalf {
                slot: self.slot,
                cmd_tx: self.cmd_tx.clone(),
            },
            MuxRecvHalf {
                slot: self.slot,
                cmd_tx: self.cmd_tx,
                recv_rx,
                trailer_rx: Some(trailer_rx),
                trailer: None,
                done: false,
            },
        )
    }

    fn reset(&mut self, code: WireCode) {
        let _ = self.cmd_tx.send(Command::Reset {
            slot: self.slot,
            code,
        });
    }
}

pub struct MuxSendHalf {
    slot: SlotIndex,
    cmd_tx: mpsc::UnboundedSender<Command>,
}

impl crate::transport::SendHalf for MuxSendHalf {
    type Error = MuxStreamError;

    async fn send_body(&mut self, payload: Bytes) -> Result<(), Self::Error> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(Command::SendBody {
                slot: self.slot,
                payload,
                reply: tx,
            })
            .map_err(|_| MuxStreamError::Closed)?;
        rx.await
            .map_err(|_| MuxStreamError::Closed)?
            .map_err(Into::into)
    }

    async fn close_send(&mut self, trailer: Option<Trailer>) -> Result<(), Self::Error> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(Command::CloseSend {
                slot: self.slot,
                trailer,
                reply: tx,
            })
            .map_err(|_| MuxStreamError::Closed)?;
        rx.await
            .map_err(|_| MuxStreamError::Closed)?
            .map_err(Into::into)
    }

    fn reset(&mut self, code: WireCode) {
        let _ = self.cmd_tx.send(Command::Reset {
            slot: self.slot,
            code,
        });
    }
}

pub struct MuxRecvHalf {
    slot: SlotIndex,
    cmd_tx: mpsc::UnboundedSender<Command>,
    recv_rx: mpsc::UnboundedReceiver<Result<Bytes, std::io::Error>>,
    trailer_rx: Option<oneshot::Receiver<Trailer>>,
    trailer: Option<Trailer>,
    done: bool,
}

impl Drop for MuxRecvHalf {
    fn drop(&mut self) {
        if !self.done {
            let _ = self.cmd_tx.send(Command::Reset {
                slot: self.slot,
                code: WireCode::Cancelled,
            });
        }
    }
}

impl FuturesStream for MuxRecvHalf {
    type Item = Result<Bytes, std::io::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.done {
            return Poll::Ready(None);
        }
        match this.recv_rx.poll_recv(cx) {
            Poll::Ready(Some(Ok(bytes))) => {
                let consumed = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
                let _ = this.cmd_tx.send(Command::Consumed {
                    slot: this.slot,
                    bytes: consumed,
                });
                Poll::Ready(Some(Ok(bytes)))
            }
            Poll::Ready(Some(Err(error))) => Poll::Ready(Some(Err(error))),
            Poll::Ready(None) => {
                // Channel closed — trailer should arrive on trailer_rx.
                this.done = true;
                if let Some(mut rx) = this.trailer_rx.take()
                    && let Ok(t) = rx.try_recv()
                {
                    this.trailer = Some(t);
                }
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl crate::transport::RecvHalf for MuxRecvHalf {
    type Error = std::io::Error;

    fn trailer(&self) -> Option<&Trailer> {
        self.trailer.as_ref()
    }

    fn reset(&mut self, code: WireCode) {
        let _ = self.cmd_tx.send(Command::Reset {
            slot: self.slot,
            code,
        });
        self.done = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dropping_a_live_receive_half_cancels_its_mux_slot() {
        let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel();
        let (_recv_tx, recv_rx) = mpsc::unbounded_channel();
        let (_trailer_tx, trailer_rx) = oneshot::channel();
        let recv = MuxRecvHalf {
            slot: 6,
            cmd_tx,
            recv_rx,
            trailer_rx: Some(trailer_rx),
            trailer: None,
            done: false,
        };

        drop(recv);
        assert!(matches!(
            cmd_rx.try_recv(),
            Ok(Command::Reset {
                slot: 6,
                code: WireCode::Cancelled,
            })
        ));
    }
}
