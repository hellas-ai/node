//! `MuxTransport`: glues the sans-io `Multiplexer` to a concrete bidi
//! byte pipe + spawns the I/O loop. Used by `ws::native` (tokio spawn)
//! and `ws::wasm` (wasm_bindgen spawn_local). The CF DO flavor drives
//! the mux directly without this wrapper (callback I/O).

use std::sync::Arc;

use bytes::Bytes;
use tokio::sync::{Mutex, mpsc, oneshot};

use crate::clock::Clock;
use crate::metadata::Metadata;
use crate::status::WireCode;
use crate::transport::{AuthLevel, Inbound, PeerIdentity, StreamTransport, TransportContext};

use super::slot::{Role, SlotIndex};
use super::state::{Event, Multiplexer, MuxConfig, MuxError};
use super::stream::MuxStream;

/// Trait for the underlying message-oriented byte pipe (one WS message
/// = one mux frame). Implemented by ws-native + ws-cf-do adapters.
pub trait MessagePipe: Send + 'static {
    type SendError: std::error::Error + Send + Sync + 'static;
    type RecvError: std::error::Error + Send + Sync + 'static;

    fn send_message(
        &mut self,
        bytes: Bytes,
    ) -> impl std::future::Future<Output = Result<(), Self::SendError>> + Send;

    fn recv_message(
        &mut self,
    ) -> impl std::future::Future<Output = Result<Option<Bytes>, Self::RecvError>> + Send;
}

/// Commands the I/O loop accepts. The MuxTransport's public API funnels
/// through these so `Multiplexer` can stay sans-io.
pub(crate) enum Command {
    Open {
        method_id: u32,
        headers: Metadata,
        reply: oneshot::Sender<Result<MuxStream, MuxError>>,
    },
    SendBody {
        slot: SlotIndex,
        payload: Bytes,
        reply: oneshot::Sender<Result<(), MuxError>>,
    },
    CloseSend {
        slot: SlotIndex,
        trailer: Option<crate::metadata::Trailer>,
        reply: oneshot::Sender<Result<(), MuxError>>,
    },
    Reset {
        slot: SlotIndex,
        code: WireCode,
    },
}

#[derive(Clone)]
pub struct MuxTransport {
    cmd_tx: mpsc::UnboundedSender<Command>,
    inbound_rx: Arc<Mutex<mpsc::UnboundedReceiver<Inbound<MuxStream>>>>,
}

#[derive(Debug, thiserror::Error)]
pub enum MuxTransportError {
    #[error("mux: {0}")]
    Mux(#[from] MuxError),
    #[error("transport closed")]
    Closed,
}

impl MuxTransport {
    /// Spawn the I/O loop using the default native spawn (tokio).
    /// Wasm callers use `spawn_with` instead, passing
    /// `wasm_bindgen_futures::spawn_local`.
    #[cfg(not(target_family = "wasm"))]
    pub fn spawn<const N: usize, C: Clock + Clone, P: MessagePipe>(
        role: Role,
        clock: C,
        config: MuxConfig,
        pipe: P,
        peer: Option<PeerIdentity>,
    ) -> Self {
        Self::spawn_with::<N, C, P, _>(role, clock, config, pipe, peer, |fut| {
            tokio::spawn(fut);
        })
    }

    /// Spawn the I/O loop using a caller-provided spawn function.
    /// Native callers pass `tokio::spawn`; wasm callers pass
    /// `wasm_bindgen_futures::spawn_local`.
    ///
    /// The spawn function MUST poll the future to completion in
    /// the background — it should not block.
    pub fn spawn_with<const N: usize, C: Clock + Clone, P: MessagePipe, F>(
        role: Role,
        clock: C,
        config: MuxConfig,
        pipe: P,
        peer: Option<PeerIdentity>,
        spawn: F,
    ) -> Self
    where
        F: FnOnce(std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'static>>),
    {
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();

        let mux = Multiplexer::<N, C>::new(role, clock, config);
        let driver = MuxDriver::<N, C, P> {
            mux,
            pipe,
            cmd_rx,
            cmd_tx: cmd_tx.clone(),
            inbound_tx,
            slot_to_chans: Default::default(),
            peer,
        };
        spawn(Box::pin(driver.run()));

        Self {
            cmd_tx,
            inbound_rx: Arc::new(Mutex::new(inbound_rx)),
        }
    }
}

impl StreamTransport for MuxTransport {
    type Stream = MuxStream;
    type Error = MuxTransportError;

    async fn open(&self, method_id: u32, headers: Metadata) -> Result<Self::Stream, Self::Error> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(Command::Open {
                method_id,
                headers,
                reply: tx,
            })
            .map_err(|_| MuxTransportError::Closed)?;
        rx.await
            .map_err(|_| MuxTransportError::Closed)?
            .map_err(Into::into)
    }

    async fn accept(&self) -> Result<Option<Inbound<Self::Stream>>, Self::Error> {
        let mut rx = self.inbound_rx.lock().await;
        Ok(rx.recv().await)
    }
}

struct MuxDriver<const N: usize, C: Clock + Clone, P: MessagePipe> {
    mux: Multiplexer<N, C>,
    pipe: P,
    cmd_rx: mpsc::UnboundedReceiver<Command>,
    cmd_tx: mpsc::UnboundedSender<Command>,
    inbound_tx: mpsc::UnboundedSender<Inbound<MuxStream>>,
    /// Per-slot channels owned by application halves. `Body`/`End`/
    /// `Reset` events are forwarded into the slot's recv channel; the
    /// I/O loop sends Body acks to the slot's send-side oneshots.
    slot_to_chans: std::collections::HashMap<SlotIndex, SlotChannels>,
    peer: Option<PeerIdentity>,
}

struct SlotChannels {
    recv_tx: mpsc::UnboundedSender<Result<Bytes, std::io::Error>>,
    trailer_tx: Option<oneshot::Sender<crate::metadata::Trailer>>,
}

impl<const N: usize, C: Clock + Clone, P: MessagePipe> MuxDriver<N, C, P> {
    async fn run(mut self) {
        loop {
            tokio::select! {
                cmd = self.cmd_rx.recv() => match cmd {
                    Some(c) => self.handle_command(c).await,
                    None => break,
                },
                msg = self.pipe.recv_message() => match msg {
                    Ok(Some(bytes)) => self.handle_inbound(bytes).await,
                    Ok(None) | Err(_) => break,
                },
            }
            self.flush_outbound().await;
        }
    }

    async fn handle_command(&mut self, cmd: Command) {
        match cmd {
            Command::Open {
                method_id,
                headers,
                reply,
            } => {
                let result = self.mux.open(method_id, headers).map(|slot| {
                    let (recv_tx, recv_rx) = mpsc::unbounded_channel();
                    let (trailer_tx, trailer_rx) = oneshot::channel();
                    self.slot_to_chans.insert(
                        slot,
                        SlotChannels {
                            recv_tx,
                            trailer_tx: Some(trailer_tx),
                        },
                    );
                    MuxStream::new(slot, self.cmd_tx_clone(), recv_rx, trailer_rx)
                });
                let _ = reply.send(result);
            }
            Command::SendBody {
                slot,
                payload,
                reply,
            } => {
                let r = self.mux.send_body(slot, payload);
                let _ = reply.send(r);
            }
            Command::CloseSend {
                slot,
                trailer,
                reply,
            } => {
                let r = self.mux.close_send(slot, trailer);
                let _ = reply.send(r);
            }
            Command::Reset { slot, code } => {
                self.mux.reset(slot, code);
            }
        }
    }

    fn cmd_tx_clone(&self) -> mpsc::UnboundedSender<Command> {
        self.cmd_tx.clone()
    }

    async fn handle_inbound(&mut self, bytes: Bytes) {
        match self.mux.recv(&bytes) {
            Ok(events) => {
                for ev in events {
                    self.dispatch_event(ev);
                }
            }
            Err(e) => {
                tracing::warn!("mux recv error: {e}");
            }
        }
    }

    fn dispatch_event(&mut self, ev: Event) {
        match ev {
            Event::NewIncomingStream {
                slot,
                method_id,
                headers,
            } => {
                let (recv_tx, recv_rx) = mpsc::unbounded_channel();
                let (trailer_tx, trailer_rx) = oneshot::channel();
                self.slot_to_chans.insert(
                    slot,
                    SlotChannels {
                        recv_tx,
                        trailer_tx: Some(trailer_tx),
                    },
                );
                let stream = MuxStream::new(slot, self.cmd_tx_clone(), recv_rx, trailer_rx);
                let inbound = Inbound {
                    method_id,
                    headers,
                    stream,
                    context: TransportContext {
                        peer: self.peer,
                        rtt_ms: None,
                        auth_level: if self.peer.is_some() {
                            AuthLevel::Vouched
                        } else {
                            AuthLevel::None
                        },
                    },
                };
                let _ = self.inbound_tx.send(inbound);
            }
            Event::BodyChunk { slot, payload } => {
                if let Some(chans) = self.slot_to_chans.get(&slot) {
                    let _ = chans.recv_tx.send(Ok(payload));
                }
            }
            Event::EndStream { slot, trailer } => {
                if let Some(mut chans) = self.slot_to_chans.remove(&slot)
                    && let Some(t) = chans.trailer_tx.take()
                {
                    let _ = t.send(trailer);
                }
            }
            Event::ResetStream { slot, code } => {
                if let Some(mut chans) = self.slot_to_chans.remove(&slot)
                    && let Some(t) = chans.trailer_tx.take()
                {
                    let _ = t.send(crate::metadata::Trailer::from_status(code, "reset"));
                }
            }
            Event::PeerCredit { .. } => {
                // Credit replenishment is internal flow control; the
                // mux state machine already records it. Body sends
                // that were blocked retry via the SendBody command
                // path (caller polls).
            }
        }
    }

    async fn flush_outbound(&mut self) {
        // Replenish credit BEFORE draining outbound so the Credit
        // frames ship in this same flush. (Doing this after the drain
        // would defer the Credit frame to the next inbound activity.)
        let _credit_slots = self.mux.prepare_credit_updates();
        while let Some(bytes) = self.mux.next_outbound() {
            if let Err(e) = self.pipe.send_message(bytes).await {
                tracing::warn!("pipe send: {e}");
                break;
            }
        }
    }
}
