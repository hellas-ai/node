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
/// = one mux frame). Implemented by the ws-native + ws-wasm adapters.
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
    Consumed {
        slot: SlotIndex,
        bytes: u32,
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
            cmd_tx: cmd_tx.downgrade(),
            inbound_tx,
            slot_to_chans: Default::default(),
            pending_sends: Default::default(),
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
    /// Weak by design: the driver must not keep its own command channel
    /// alive. Real transport/stream owners hold the strong senders.
    cmd_tx: mpsc::WeakUnboundedSender<Command>,
    inbound_tx: mpsc::UnboundedSender<Inbound<MuxStream>>,
    /// Per-slot channels owned by application halves. `Body`/`End`/
    /// `Reset` events are forwarded into the slot's recv channel; the
    /// I/O loop sends Body acks to the slot's send-side oneshots.
    slot_to_chans: std::collections::HashMap<SlotIndex, SlotChannels>,
    /// At most one blocked send per slot; `SendHalf::send_body` takes
    /// `&mut self`, so well-formed callers cannot create a second one.
    pending_sends: std::collections::HashMap<SlotIndex, PendingSend>,
    peer: Option<PeerIdentity>,
}

struct PendingSend {
    payload: Bytes,
    reply: oneshot::Sender<Result<(), MuxError>>,
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
            if !self.flush_outbound().await {
                break;
            }
        }
    }

    async fn handle_command(&mut self, cmd: Command) {
        match cmd {
            Command::Open {
                method_id,
                headers,
                reply,
            } => {
                let result = self
                    .cmd_tx_clone()
                    .ok_or(MuxError::Protocol(
                        "transport owner disappeared while opening stream",
                    ))
                    .and_then(|cmd_tx| {
                        self.mux.open(method_id, headers).map(|slot| {
                            let (recv_tx, recv_rx) = mpsc::unbounded_channel();
                            let (trailer_tx, trailer_rx) = oneshot::channel();
                            self.slot_to_chans.insert(
                                slot,
                                SlotChannels {
                                    recv_tx,
                                    trailer_tx: Some(trailer_tx),
                                },
                            );
                            MuxStream::new(slot, cmd_tx, recv_rx, trailer_rx)
                        })
                    });
                let _ = reply.send(result);
            }
            Command::SendBody {
                slot,
                payload,
                reply,
            } => {
                self.start_send(slot, payload, reply);
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
                self.fail_pending_send(slot);
                self.mux.reset(slot, code);
            }
            Command::Consumed { slot, bytes } => {
                if let Err(error) = self.mux.consume(slot, bytes) {
                    tracing::warn!("mux consume error: {error}");
                }
            }
        }
    }

    fn cmd_tx_clone(&self) -> Option<mpsc::UnboundedSender<Command>> {
        self.cmd_tx.upgrade()
    }

    fn start_send(
        &mut self,
        slot: SlotIndex,
        payload: Bytes,
        reply: oneshot::Sender<Result<(), MuxError>>,
    ) {
        if self.pending_sends.contains_key(&slot) {
            let _ = reply.send(Err(MuxError::Protocol(
                "concurrent send_body calls on one stream",
            )));
            return;
        }
        match self.mux.try_send_body(slot, payload) {
            Ok(super::state::SendBodyOutcome::Accepted) => {
                let _ = reply.send(Ok(()));
            }
            Ok(super::state::SendBodyOutcome::Blocked(payload)) => {
                self.pending_sends
                    .insert(slot, PendingSend { payload, reply });
            }
            Err(error) => {
                let _ = reply.send(Err(error));
            }
        }
    }

    /// Retry one send after peer credit arrives or the staged Body drains.
    /// Returns true when a new Body was accepted and needs flushing.
    fn retry_pending_send(&mut self, slot: SlotIndex) -> bool {
        let Some(pending) = self.pending_sends.remove(&slot) else {
            return false;
        };
        match self.mux.try_send_body(slot, pending.payload) {
            Ok(super::state::SendBodyOutcome::Accepted) => {
                let _ = pending.reply.send(Ok(()));
                true
            }
            Ok(super::state::SendBodyOutcome::Blocked(payload)) => {
                self.pending_sends.insert(
                    slot,
                    PendingSend {
                        payload,
                        reply: pending.reply,
                    },
                );
                false
            }
            Err(error) => {
                let _ = pending.reply.send(Err(error));
                false
            }
        }
    }

    fn retry_pending_sends(&mut self) -> bool {
        let slots: Vec<_> = self.pending_sends.keys().copied().collect();
        let mut accepted = false;
        for slot in slots {
            accepted |= self.retry_pending_send(slot);
        }
        accepted
    }

    fn fail_pending_send(&mut self, slot: SlotIndex) {
        if let Some(pending) = self.pending_sends.remove(&slot) {
            let _ = pending.reply.send(Err(MuxError::SlotClosed(slot)));
        }
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
                let Some(cmd_tx) = self.cmd_tx_clone() else {
                    self.mux.reset(slot, WireCode::Cancelled);
                    return;
                };
                let (recv_tx, recv_rx) = mpsc::unbounded_channel();
                let (trailer_tx, trailer_rx) = oneshot::channel();
                self.slot_to_chans.insert(
                    slot,
                    SlotChannels {
                        recv_tx,
                        trailer_tx: Some(trailer_tx),
                    },
                );
                let stream = MuxStream::new(slot, cmd_tx, recv_rx, trailer_rx);
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
                        open_exporter: None,
                    },
                };
                let _ = self.inbound_tx.send(inbound);
            }
            Event::BodyChunk { slot, payload } => {
                let delivered = self
                    .slot_to_chans
                    .get(&slot)
                    .is_some_and(|chans| chans.recv_tx.send(Ok(payload)).is_ok());
                if !delivered {
                    self.slot_to_chans.remove(&slot);
                    self.fail_pending_send(slot);
                    self.mux.reset(slot, WireCode::Cancelled);
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
                self.fail_pending_send(slot);
                if let Some(mut chans) = self.slot_to_chans.remove(&slot)
                    && let Some(t) = chans.trailer_tx.take()
                {
                    let _ = t.send(crate::metadata::Trailer::from_status(code, "reset"));
                }
            }
            Event::PeerCredit { slot, .. } => {
                self.retry_pending_send(slot);
            }
        }
    }

    /// Flush staged frames, then retry sends that were waiting only for the
    /// one-frame staging slot to drain. Credit-blocked sends remain pending
    /// until their peer's Credit event arrives.
    async fn flush_outbound(&mut self) -> bool {
        loop {
            while let Some(bytes) = self.mux.next_outbound() {
                if let Err(e) = self.pipe.send_message(bytes).await {
                    tracing::warn!("pipe send: {e}");
                    return false;
                }
            }
            if !self.retry_pending_sends() {
                return true;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::DefaultClock;
    use crate::frame::{CreditFrame, Frame};
    use crate::mux::{SendBodyOutcome, StreamKey, encode_keyed_frame};

    struct IdlePipe {
        recv_rx: mpsc::UnboundedReceiver<Bytes>,
        dropped: Option<oneshot::Sender<()>>,
    }

    impl MessagePipe for IdlePipe {
        type SendError = std::io::Error;
        type RecvError = std::io::Error;

        async fn send_message(&mut self, _bytes: Bytes) -> Result<(), Self::SendError> {
            Ok(())
        }

        async fn recv_message(&mut self) -> Result<Option<Bytes>, Self::RecvError> {
            Ok(self.recv_rx.recv().await)
        }
    }

    impl Drop for IdlePipe {
        fn drop(&mut self) {
            if let Some(dropped) = self.dropped.take() {
                let _ = dropped.send(());
            }
        }
    }

    #[tokio::test]
    async fn blocked_send_resumes_when_peer_credit_arrives() {
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let (inbound_tx, _inbound_rx) = mpsc::unbounded_channel();
        let (_wire_tx, wire_rx) = mpsc::unbounded_channel();
        let mut driver = MuxDriver::<8, _, _> {
            mux: Multiplexer::new(Role::Client, DefaultClock, MuxConfig { stream_window: 8 }),
            pipe: IdlePipe {
                recv_rx: wire_rx,
                dropped: None,
            },
            cmd_rx,
            cmd_tx: cmd_tx.downgrade(),
            inbound_tx,
            slot_to_chans: Default::default(),
            pending_sends: Default::default(),
            peer: None,
        };

        let slot = driver.mux.open(7, Metadata::new()).unwrap();
        driver.mux.next_outbound().expect("open frame");
        assert!(matches!(
            driver
                .mux
                .try_send_body(slot, Bytes::from_static(b"123456")),
            Ok(SendBodyOutcome::Accepted)
        ));
        driver.mux.next_outbound().expect("first body");

        let (reply_tx, mut reply_rx) = oneshot::channel();
        driver.start_send(slot, Bytes::from_static(b"abcdef"), reply_tx);
        assert!(matches!(
            reply_rx.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));

        let credit = encode_keyed_frame(
            StreamKey::new(slot, 1),
            &Frame::Credit(CreditFrame {
                additional_bytes: 6,
            }),
        );
        driver.handle_inbound(credit).await;
        assert!(reply_rx.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn dropping_last_transport_owner_drops_the_pipe() {
        let (_wire_tx, wire_rx) = mpsc::unbounded_channel();
        let (dropped_tx, dropped_rx) = oneshot::channel();
        let transport = MuxTransport::spawn::<8, _, _>(
            Role::Client,
            DefaultClock,
            MuxConfig::default(),
            IdlePipe {
                recv_rx: wire_rx,
                dropped: Some(dropped_tx),
            },
            None,
        );

        drop(transport);
        dropped_rx
            .await
            .expect("driver must terminate when its final owner disappears");
    }
}
