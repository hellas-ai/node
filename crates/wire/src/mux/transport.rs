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
use crate::transport::{Inbound, StreamTransport, TransportContext};

use super::slot::{Role, SlotIndex};
use super::state::{Event, Multiplexer, MuxConfig, MuxError};
use super::stream::MuxStream;
use super::wire::StreamKey;

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
///
/// Everything but `Open` names an existing stream, and names it by the
/// same `StreamKey` the wire uses. A bare slot index would not do: a
/// command travels a channel and is served later, by which time the peer
/// may have seated a different stream in that index.
pub(crate) enum Command {
    Open {
        method_id: u32,
        headers: Metadata,
        reply: oneshot::Sender<Result<MuxStream, MuxError>>,
    },
    SendBody {
        key: StreamKey,
        payload: Bytes,
        reply: oneshot::Sender<Result<(), MuxError>>,
    },
    CloseSend {
        key: StreamKey,
        trailer: Option<crate::metadata::Trailer>,
        reply: oneshot::Sender<Result<(), MuxError>>,
    },
    Reset {
        key: StreamKey,
        code: WireCode,
    },
    Consumed {
        key: StreamKey,
        bytes: u32,
    },
}

#[derive(Clone)]
pub struct MuxTransport {
    cmd_tx: mpsc::UnboundedSender<Command>,
    inbound_rx: Arc<Mutex<mpsc::UnboundedReceiver<Inbound<MuxStream>>>>,
    /// What the enclosing session vouches for: the peer it authenticated,
    /// and the keying material it can export. A mux is carried by
    /// something else — a WebSocket, a QUIC connection — and only that
    /// carrier knows either. It is held here as well as in the driver so
    /// outbound callers read the same facts inbound ones are handed.
    context: TransportContext,
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
        context: TransportContext,
    ) -> Self {
        Self::spawn_with::<N, C, P, _>(role, clock, config, pipe, context, |fut| {
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
        context: TransportContext,
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
            context: context.clone(),
        };
        spawn(Box::pin(driver.run()));

        Self {
            cmd_tx,
            inbound_rx: Arc::new(Mutex::new(inbound_rx)),
            context,
        }
    }
}

impl StreamTransport for MuxTransport {
    type Stream = MuxStream;
    type Error = MuxTransportError;

    fn context(&self) -> TransportContext {
        self.context.clone()
    }

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
    context: TransportContext,
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
                        self.mux
                            .open(method_id, headers)
                            .and_then(|slot| self.register_stream(slot, cmd_tx))
                    });
                let _ = reply.send(result);
            }
            Command::SendBody {
                key,
                payload,
                reply,
            } => match self.live(key) {
                Some(slot) => self.start_send(slot, payload, reply),
                None => {
                    let _ = reply.send(Err(MuxError::SlotClosed(key.stream_id)));
                }
            },
            Command::CloseSend {
                key,
                trailer,
                reply,
            } => {
                let result = match self.live(key) {
                    Some(slot) => self.mux.close_send(slot, trailer),
                    None => Err(MuxError::SlotClosed(key.stream_id)),
                };
                let _ = reply.send(result);
            }
            Command::Reset { key, code } => {
                if let Some(slot) = self.live(key) {
                    self.fail_pending_send(slot);
                    self.mux.reset(slot, code);
                }
            }
            Command::Consumed { key, bytes } => {
                if let Some(slot) = self.live(key)
                    && let Err(error) = self.mux.consume(slot, bytes)
                {
                    tracing::warn!("mux consume error: {error}");
                }
            }
        }
    }

    /// Resolve a command's stream key to the slot it may act on.
    ///
    /// A command is written when its stream is alive and served some time
    /// later, and `MuxRecvHalf`'s drop writes one after the caller has
    /// finished with the stream entirely. If the index has since been
    /// re-seated — a fresh `open`, or a peer's `Open` on an index whose
    /// terminals have both crossed — the stream the command names no
    /// longer exists, and the one occupying its index belongs to someone
    /// else. Refuse rather than act on the wrong stream.
    fn live(&self, key: StreamKey) -> Option<SlotIndex> {
        (self.mux.generation(key.stream_id) == Some(key.generation)).then_some(key.stream_id)
    }

    /// Wire a freshly-seated slot to a `MuxStream`: the driver keeps the
    /// sending ends, the stream keeps the receiving ends and the key that
    /// names it for as long as it lives.
    ///
    /// The generation is read back from the mux rather than assumed, so a
    /// stream can only ever be handed a key the state machine agrees with.
    fn register_stream(
        &mut self,
        slot: SlotIndex,
        cmd_tx: mpsc::UnboundedSender<Command>,
    ) -> Result<MuxStream, MuxError> {
        let generation = self
            .mux
            .generation(slot)
            .ok_or(MuxError::Protocol("mux seated no stream in this slot"))?;
        let (recv_tx, recv_rx) = mpsc::unbounded_channel();
        let (trailer_tx, trailer_rx) = oneshot::channel();
        self.slot_to_chans.insert(
            slot,
            SlotChannels {
                recv_tx,
                trailer_tx: Some(trailer_tx),
            },
        );
        Ok(MuxStream::new(
            StreamKey::new(slot, generation),
            cmd_tx,
            recv_rx,
            trailer_rx,
        ))
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
                let Some(stream) = self
                    .cmd_tx_clone()
                    .and_then(|cmd_tx| self.register_stream(slot, cmd_tx).ok())
                else {
                    self.mux.reset(slot, WireCode::Cancelled);
                    return;
                };
                let inbound = Inbound {
                    method_id,
                    headers,
                    stream,
                    context: self.context.clone(),
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
    use crate::frame::{CreditFrame, EndFrame, Frame, OpenFrame};
    use crate::metadata::Trailer;
    use crate::mux::{SendBodyOutcome, StreamKey, decode_keyed_frame, encode_keyed_frame};

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

    /// A pipe that keeps every frame the driver ships, so a test can ask
    /// what actually went out rather than what the driver meant to send.
    struct RecordingPipe {
        recv_rx: mpsc::UnboundedReceiver<Bytes>,
        sent: mpsc::UnboundedSender<Bytes>,
    }

    impl MessagePipe for RecordingPipe {
        type SendError = std::io::Error;
        type RecvError = std::io::Error;

        async fn send_message(&mut self, bytes: Bytes) -> Result<(), Self::SendError> {
            let _ = self.sent.send(bytes);
            Ok(())
        }

        async fn recv_message(&mut self) -> Result<Option<Bytes>, Self::RecvError> {
            Ok(self.recv_rx.recv().await)
        }
    }

    fn open_frame(slot: SlotIndex, generation: u16, method_id: u32) -> Bytes {
        encode_keyed_frame(
            StreamKey::new(slot, generation),
            &Frame::Open(OpenFrame {
                method_id,
                headers: Metadata::new(),
            }),
        )
    }

    fn body_frame(slot: SlotIndex, generation: u16, payload: &'static [u8]) -> Bytes {
        encode_keyed_frame(
            StreamKey::new(slot, generation),
            &Frame::Body(Bytes::from_static(payload)),
        )
    }

    fn end_frame(slot: SlotIndex, generation: u16) -> Bytes {
        encode_keyed_frame(
            StreamKey::new(slot, generation),
            &Frame::End(EndFrame {
                status: WireCode::Ok,
                trailer: Trailer::ok(),
            }),
        )
    }

    /// A slot index is a seat, not a name. A half that lets go of a
    /// finished stream cancels that stream and no other — even when the
    /// peer has already seated a new stream in the same index.
    ///
    /// The sequence is the one a unary server dispatch produces: it reads
    /// one body and never drains to EOF, so its recv half is still "live"
    /// when it drops and asks the driver to reset. The peer, meanwhile, is
    /// free to reuse the index the moment both terminals have crossed.
    #[tokio::test]
    async fn a_finished_stream_s_reset_cannot_cancel_the_slot_s_next_tenant() {
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let (inbound_tx, mut inbound_rx) = mpsc::unbounded_channel();
        let (_wire_tx, wire_rx) = mpsc::unbounded_channel();
        let (sent_tx, mut sent_rx) = mpsc::unbounded_channel();
        let mut driver = MuxDriver::<8, _, _> {
            mux: Multiplexer::new(Role::Server, DefaultClock, MuxConfig::default()),
            pipe: RecordingPipe {
                recv_rx: wire_rx,
                sent: sent_tx,
            },
            cmd_rx,
            cmd_tx: cmd_tx.downgrade(),
            inbound_tx,
            slot_to_chans: Default::default(),
            pending_sends: Default::default(),
            context: TransportContext::default(),
        };

        // The peer opens slot 0 generation 1 and completes its request.
        driver.handle_inbound(open_frame(0, 1, 7)).await;
        let first = inbound_rx.try_recv().expect("first inbound stream");
        let (_send, recv) = crate::transport::Stream::split(first.stream);
        driver.handle_inbound(body_frame(0, 1, b"one")).await;
        driver.handle_inbound(end_frame(0, 1)).await;

        // We answer and close. Both terminals have now crossed on
        // generation 1, which is precisely what entitles the peer to
        // reuse the index.
        let (reply, _replied) = oneshot::channel();
        driver
            .handle_command(Command::CloseSend {
                key: StreamKey::new(0, 1),
                trailer: None,
                reply,
            })
            .await;
        assert!(driver.flush_outbound().await);

        // The handler drops a recv half it never drained, which asks the
        // driver to reset the stream it was reading.
        drop(recv);

        // Before that command is served, the peer seats a new stream in
        // the freed index.
        driver.handle_inbound(open_frame(0, 2, 9)).await;
        let second = inbound_rx.try_recv().expect("second inbound stream");
        let (_send, recv) = crate::transport::Stream::split(second.stream);

        let stale = driver
            .cmd_rx
            .try_recv()
            .expect("dropping an undrained recv half resets its slot");
        assert!(matches!(
            stale,
            Command::Reset {
                key: StreamKey {
                    stream_id: 0,
                    generation: 1,
                },
                code: WireCode::Cancelled,
            }
        ));
        driver.handle_command(stale).await;
        assert!(driver.flush_outbound().await);

        // Nothing may have gone out cancelling the new tenant.
        while let Ok(bytes) = sent_rx.try_recv() {
            let decoded = decode_keyed_frame(&bytes).expect("driver ships decodable frames");
            assert!(
                !(decoded.key == StreamKey::new(0, 2) && matches!(decoded.frame, Frame::Reset(_))),
                "generation 1's reset was applied to generation 2"
            );
        }

        // And the new tenant's request body must still reach it.
        driver.handle_inbound(body_frame(0, 2, b"two")).await;
        let mut recv = std::pin::pin!(recv);
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        match futures_core::Stream::poll_next(recv.as_mut(), &mut cx) {
            std::task::Poll::Ready(Some(Ok(bytes))) => assert_eq!(&bytes[..], b"two"),
            other => panic!("the new tenant lost its request body: {other:?}"),
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
            context: TransportContext::default(),
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
            TransportContext::default(),
        );

        drop(transport);
        dropped_rx
            .await
            .expect("driver must terminate when its final owner disappears");
    }
}
