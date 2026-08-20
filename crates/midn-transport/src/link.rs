// crates/midn-transport/src/link.rs
//! [`SctpLink`] — one SCTP association over UDP, driven on a background
//! Tokio task. See the crate root doc for the overall design and the two
//! `rtc_sctp` compatibility gaps this implementation works around.
//!
//! `rtc_sctp` API surface used here was verified against the actual
//! published source (`rtc-sctp` 0.20.3, `association/mod.rs`,
//! `endpoint/mod.rs`) during this session, not guessed from method
//! signatures alone — in particular `Association::poll_transmit`'s exact
//! `TransportMessage { now, transport: TransportContext { peer_addr, .. },
//! message: Payload::RawEncode(Vec<Bytes>) }` shape, and that
//! `open_stream` never puts a packet on the wire.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use rtc_sctp::{
    Association, AssociationHandle, ClientConfig, DatagramEvent, Endpoint, EndpointConfig,
    Event, Payload, PayloadProtocolIdentifier, ServerConfig, StreamEvent, StreamId,
    TransportConfig,
};
use rtc_shared::TransportProtocol;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

/// Every message midn sends over an `SctpLink` rides on this one SCTP
/// stream. See the crate doc's "What this crate does NOT do yet" for why
/// a single stream is enough for now.
pub const DEFAULT_STREAM_ID: StreamId = 0;

const RECV_BUF_LEN: usize = 65536;
/// `Chunks::to_payload`'s bound — matches `RECV_BUF_LEN`, since nothing
/// this crate carries (S1AP/NGAP PDUs) approaches 64KiB.
const MAX_MESSAGE_LEN: usize = RECV_BUF_LEN;

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("SCTP connect error: {0}")]
    Connect(#[from] rtc_sctp::ConnectError),
    #[error("SCTP error: {0}")]
    Sctp(#[from] rtc_shared::error::Error),
    /// `send()` was called before the driver processed `Event::Connected`
    /// (and therefore before `DEFAULT_STREAM_ID` exists). Not a real
    /// failure — wait for `LinkEvent::Connected` from `recv()` first.
    #[error("link is not established yet")]
    NotReady,
    /// The driver task is gone (association drained, or `SctpLink` itself
    /// was dropped from another handle in a scenario that shares one).
    #[error("link driver task is gone")]
    Closed,
}

/// Events surfaced from the driver task to the application.
#[derive(Debug)]
pub enum LinkEvent {
    /// SCTP handshake completed — `DEFAULT_STREAM_ID` is open on both
    /// sides and `send`/`recv` are usable.
    Connected,
    /// A complete SCTP user message arrived on `DEFAULT_STREAM_ID`.
    Message(Bytes),
    /// The association is gone — peer closed it, or a transport error
    /// closed it locally. No more `Message`s will follow; the driver task
    /// exits right after sending this.
    Lost { reason: String },
}

struct Outbound {
    data: Bytes,
    reply: oneshot::Sender<Result<(), TransportError>>,
}

/// One SCTP association, over UDP, driven on a background Tokio task.
///
/// `connect`/`accept` each spawn the driver and return once the
/// association object exists locally — NOT once the handshake completes.
/// Wait for [`LinkEvent::Connected`] from [`SctpLink::recv`] before
/// calling [`SctpLink::send`] (sending earlier returns
/// [`TransportError::NotReady`] rather than blocking or panicking).
pub struct SctpLink {
    outbound_tx: mpsc::UnboundedSender<Outbound>,
    inbound_rx: mpsc::UnboundedReceiver<LinkEvent>,
    _driver: JoinHandle<()>,
}

impl SctpLink {
    /// Bind `bind_addr` and initiate an association to `remote_addr`.
    /// "Client" here is purely an RFC 4960 INIT/INIT-ACK role, not a 3GPP
    /// one — real deployments have the RAN (gNB/eNB) initiate toward the
    /// core network, so this is the method a simulated RAN would call.
    pub async fn connect(bind_addr: SocketAddr, remote_addr: SocketAddr) -> Result<Self, TransportError> {
        let socket = UdpSocket::bind(bind_addr).await?;
        let local_addr = socket.local_addr()?;

        let mut endpoint = Endpoint::new(
            local_addr,
            TransportProtocol::UDP,
            Arc::new(EndpointConfig::new()),
            None,
        );
        let (handle, association) = endpoint.connect(ClientConfig::default(), remote_addr)?;

        Ok(Self::spawn(socket, endpoint, association, handle))
    }

    /// Bind `bind_addr` and wait for one incoming association. Blocks
    /// (async) until the first datagram from a peer actually creates an
    /// `Association` — `rtc_sctp::Endpoint` has no concept of "listening"
    /// independent of an inbound datagram triggering `DatagramEvent::
    /// NewAssociation`, so there is no association object to hand to the
    /// driver task until then.
    pub async fn accept(bind_addr: SocketAddr) -> Result<Self, TransportError> {
        let socket = UdpSocket::bind(bind_addr).await?;
        let local_addr = socket.local_addr()?;

        let server_config = Arc::new(ServerConfig::new(TransportConfig::default()));
        let mut endpoint = Endpoint::new(
            local_addr,
            TransportProtocol::UDP,
            Arc::new(EndpointConfig::new()),
            Some(server_config),
        );

        let mut buf = vec![0u8; RECV_BUF_LEN];
        let (handle, association) = loop {
            let (n, from) = socket.recv_from(&mut buf).await?;
            let data = Bytes::copy_from_slice(&buf[..n]);
            match endpoint.handle(Instant::now(), from, None, data) {
                Some((handle, DatagramEvent::NewAssociation(assoc))) => break (handle, assoc),
                // Anything else this early (a stray AssociationEvent with
                // no Association yet to route it to) has nothing to go
                // to — drop it and keep waiting for a real INIT.
                _ => continue,
            }
        };

        Ok(Self::spawn(socket, endpoint, association, handle))
    }

    fn spawn(
        socket: UdpSocket,
        endpoint: Endpoint,
        association: Association,
        handle: AssociationHandle,
    ) -> Self {
        let (outbound_tx, outbound_rx) = mpsc::unbounded_channel();
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();

        let driver = tokio::spawn(drive(socket, endpoint, association, handle, outbound_rx, inbound_tx));

        Self { outbound_tx, inbound_rx, _driver: driver }
    }

    /// Send one SCTP user message on `DEFAULT_STREAM_ID`.
    pub async fn send(&self, data: Bytes) -> Result<(), TransportError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.outbound_tx
            .send(Outbound { data, reply: reply_tx })
            .map_err(|_| TransportError::Closed)?;
        reply_rx.await.map_err(|_| TransportError::Closed)?
    }

    /// Wait for the next event. Returns `None` once the driver task has
    /// exited (always preceded by a `LinkEvent::Lost`, unless the
    /// `SctpLink` itself was dropped first).
    pub async fn recv(&mut self) -> Option<LinkEvent> {
        self.inbound_rx.recv().await
    }
}

/// The actual Sans-IO pump loop. Mirrors the exact contract `rtc_sctp`'s
/// own doc lays out for `Association`: after `handle_event`,
/// `handle_timeout`, or local I/O (the outbound-channel branch here),
/// drain `poll()`, `poll_endpoint_event()`, and `poll_transmit()` before
/// doing anything else.
async fn drive(
    socket: UdpSocket,
    mut endpoint: Endpoint,
    mut association: Association,
    handle: AssociationHandle,
    mut outbound_rx: mpsc::UnboundedReceiver<Outbound>,
    inbound_tx: mpsc::UnboundedSender<LinkEvent>,
) {
    let mut recv_buf = vec![0u8; RECV_BUF_LEN];
    let mut stream_ready = false;

    // Flush whatever the association queued at construction time — for
    // the client side this is the INIT chunk (Association::new sends it
    // immediately, before this loop's first select! iteration would
    // otherwise notice).
    pump(&mut association, &mut endpoint, handle, &socket, &inbound_tx, &mut stream_ready).await;

    loop {
        if association.is_drained() {
            return;
        }

        let deadline = association.poll_timeout();

        tokio::select! {
            res = socket.recv_from(&mut recv_buf) => {
                let (n, from) = match res {
                    Ok(v) => v,
                    Err(e) => {
                        let _ = inbound_tx.send(LinkEvent::Lost { reason: format!("socket recv error: {e}") });
                        return;
                    }
                };
                let data = Bytes::copy_from_slice(&recv_buf[..n]);
                // Every datagram this socket receives belongs to the one
                // association this `SctpLink` manages (one socket, one
                // peer, one association — see crate doc's "What this
                // crate does NOT do yet"), so there's no need to check
                // the returned handle against the stored one. The only
                // other case `Endpoint::handle` can report is a stray
                // peer trying to INIT a second, unrelated association on
                // this socket — out of scope, dropped.
                if let Some((_ev_handle, DatagramEvent::AssociationEvent(ev))) =
                    endpoint.handle(Instant::now(), from, None, data)
                {
                    association.handle_event(ev);
                }
            }

            _ = sleep_until_opt(deadline) => {
                association.handle_timeout(Instant::now());
            }

            maybe_out = outbound_rx.recv() => {
                match maybe_out {
                    Some(out) => {
                        let result = if !stream_ready {
                            Err(TransportError::NotReady)
                        } else {
                            association.stream(DEFAULT_STREAM_ID)
                                .and_then(|mut s| s.write_with_ppi(&out.data, PayloadProtocolIdentifier::Unknown))
                                .map(|_| ())
                                .map_err(TransportError::from)
                        };
                        let _ = out.reply.send(result);
                    }
                    // SctpLink was dropped — no more sends possible, and
                    // nobody can observe further LinkEvents either.
                    None => return,
                }
            }
        }

        pump(&mut association, &mut endpoint, handle, &socket, &inbound_tx, &mut stream_ready).await;
    }
}

/// Drain every pending application event, endpoint event, and outbound
/// transmit — the "after any stimulus, pump until empty" step
/// `Association`'s own doc requires before the caller does anything else.
async fn pump(
    association: &mut Association,
    endpoint: &mut Endpoint,
    handle: AssociationHandle,
    socket: &UdpSocket,
    inbound_tx: &mpsc::UnboundedSender<LinkEvent>,
    stream_ready: &mut bool,
) {
    while let Some(event) = association.poll() {
        match event {
            Event::Connected => {
                // Both peers open the SAME stream id independently — pure
                // local bookkeeping in this crate (see crate doc's
                // "compatibility gaps" #2), no coordination needed.
                if association.open_stream(DEFAULT_STREAM_ID, PayloadProtocolIdentifier::Unknown).is_ok() {
                    *stream_ready = true;
                }
                let _ = inbound_tx.send(LinkEvent::Connected);
            }
            Event::AssociationLost { reason, .. } => {
                let _ = inbound_tx.send(LinkEvent::Lost { reason: reason.to_string() });
            }
            Event::HandshakeFailed { reason } => {
                let _ = inbound_tx.send(LinkEvent::Lost { reason: format!("handshake failed: {reason}") });
            }
            Event::Stream(StreamEvent::Readable { id }) => {
                if let Ok(mut s) = association.stream(id) {
                    while let Ok(Some(chunks)) = s.read_sctp() {
                        if let Ok(buf) = chunks.to_payload(MAX_MESSAGE_LEN) {
                            let _ = inbound_tx.send(LinkEvent::Message(buf.freeze()));
                        }
                    }
                }
            }
            // Writable/Opened/BufferedAmount*/Stopped: no action needed —
            // this crate never blocks on backpressure yet (see crate doc).
            Event::Stream(_) => {}
            Event::DatagramReceived => {}
            // Event is #[non_exhaustive] — future rtc_sctp versions may
            // add variants; ignore rather than fail to compile.
            #[allow(unreachable_patterns)]
            _ => {}
        }
    }

    while let Some(ep_event) = association.poll_endpoint_event() {
        endpoint.handle_event(handle, ep_event);
    }

    let now = Instant::now();
    while let Some(transmit) = association.poll_transmit(now) {
        if let Payload::RawEncode(bufs) = transmit.message {
            for buf in bufs {
                let _ = socket.send_to(&buf, transmit.transport.peer_addr).await;
            }
        }
    }
}

/// `tokio::time::sleep_until` needs a `tokio::time::Instant`, but
/// `rtc_sctp::Association::poll_timeout` returns `std::time::Instant` —
/// convert, or sleep forever (never resolves) when there's no pending
/// timer, so this `select!` branch simply never fires that iteration.
async fn sleep_until_opt(deadline: Option<Instant>) {
    match deadline {
        Some(when) => tokio::time::sleep_until(tokio::time::Instant::from_std(when)).await,
        None => std::future::pending().await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// Drives two `rtc_sctp::Endpoint`s by hand — no socket, no Tokio —
    /// feeding each side's `poll_transmit` output straight into the
    /// other's `Endpoint::handle`. This is exactly what the crate's own
    /// doc means by "testable without a network": it exercises the real
    /// SCTP handshake (INIT/INIT-ACK/COOKIE-ECHO/COOKIE-ACK), the local
    /// `open_stream` bookkeeping, and a real DATA/SACK exchange, using
    /// nothing this workspace's own code wrote — only `rtc_sctp` itself.
    /// If this test is wrong, the bug is in this file's understanding of
    /// `rtc_sctp`'s contract, not in an assumption about UDP or Tokio.
    #[test]
    fn two_endpoints_handshake_and_exchange_data_fully_offline() {
        let client_addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let server_addr: SocketAddr = "127.0.0.1:2".parse().unwrap();

        let mut client_ep = Endpoint::new(
            client_addr, TransportProtocol::UDP, Arc::new(EndpointConfig::new()), None,
        );
        let mut server_ep = Endpoint::new(
            server_addr, TransportProtocol::UDP, Arc::new(EndpointConfig::new()),
            Some(Arc::new(ServerConfig::new(TransportConfig::default()))),
        );

        let (_client_handle, mut client_assoc) =
            client_ep.connect(ClientConfig::default(), server_addr).expect("connect");
        let mut server_assoc: Option<Association> = None;

        let mut now = Instant::now();
        let mut client_connected = false;
        let mut server_connected = false;
        let mut client_stream_opened = false;
        let mut received_on_server: Option<Bytes> = None;

        for _round in 0..200 {
            // client -> server
            while let Some(tm) = client_assoc.poll_transmit(now) {
                if let Payload::RawEncode(bufs) = tm.message {
                    for b in bufs {
                        if let Some((_h, ev)) = server_ep.handle(now, client_addr, None, b) {
                            match ev {
                                DatagramEvent::NewAssociation(assoc) => server_assoc = Some(assoc),
                                DatagramEvent::AssociationEvent(e) => {
                                    if let Some(a) = server_assoc.as_mut() { a.handle_event(e); }
                                }
                            }
                        }
                    }
                }
            }

            // server -> client
            if let Some(a) = server_assoc.as_mut() {
                while let Some(tm) = a.poll_transmit(now) {
                    if let Payload::RawEncode(bufs) = tm.message {
                        for b in bufs {
                            if let Some((_h, DatagramEvent::AssociationEvent(e))) =
                                client_ep.handle(now, server_addr, None, b)
                            {
                                client_assoc.handle_event(e);
                            }
                        }
                    }
                }
            }

            while let Some(event) = client_assoc.poll() {
                if let Event::Connected = event { client_connected = true; }
            }
            if let Some(a) = server_assoc.as_mut() {
                while let Some(event) = a.poll() {
                    match event {
                        Event::Connected => server_connected = true,
                        Event::Stream(StreamEvent::Readable { id }) => {
                            if let Ok(mut s) = a.stream(id) {
                                if let Ok(Some(chunks)) = s.read_sctp() {
                                    received_on_server =
                                        Some(chunks.to_payload(4096).unwrap().freeze());
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }

            if client_connected && server_connected && !client_stream_opened {
                client_assoc.open_stream(DEFAULT_STREAM_ID, PayloadProtocolIdentifier::Unknown)
                    .expect("open_stream");
                client_assoc.stream(DEFAULT_STREAM_ID).unwrap()
                    .write_with_ppi(b"hello from client", PayloadProtocolIdentifier::Unknown)
                    .expect("write_with_ppi");
                client_stream_opened = true;
            }

            now += Duration::from_millis(20);
            if received_on_server.is_some() { break; }
        }

        assert!(client_connected, "client never observed Event::Connected");
        assert!(server_connected, "server never observed Event::Connected");
        assert_eq!(
            received_on_server.as_deref(),
            Some(&b"hello from client"[..]),
            "server never reassembled the client's message",
        );
    }
}
