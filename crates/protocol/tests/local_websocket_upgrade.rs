// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Exercise a locally accepted upgrade through Pingora's borrowed proxy session.
#![cfg(feature = "managed-websocket")]
#![forbid(unsafe_code)]
#![expect(clippy::unwrap_used, reason = "fixture setup and test I/O must succeed")]

#[cfg(test)]
mod tests {
    use std::{
        future::ready,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use bytes::Bytes;
    use pingora_core::{
        apps::HttpServerApp as _,
        protocols::{http::ServerSession, l4::stream::Stream},
        upstreams::peer::HttpPeer,
    };
    use pingora_proxy::{HttpProxy, ProxyHttp, Session};
    use praxis_protocol::http::pingora::local_upgrade::{LocalWebSocket, PreparedLocalWebSocket};
    use tokio::{
        io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader},
        net::{TcpListener, TcpStream},
    };

    /// One TCP write with the RFC example challenge and a masked empty text frame.
    const OFFER: &[u8] = b"GET / HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n\x81\x80abcd";
    /// Read exactly one wire fixture, allowing arbitrary transport chunk boundaries.
    async fn receive(session: &mut LocalWebSocket<'_>, expected: &[u8]) {
        let mut received = Vec::new();
        while received.len() < expected.len() {
            received.extend_from_slice(&session.read().await.unwrap().unwrap());
        }
        assert_eq!(received, expected);
    }

    /// A pending read yields to an application write, then resumes for the peer's close.
    async fn drive(session: &mut Session) {
        let mut session = LocalWebSocket::commit(session).await.unwrap();
        receive(&mut session, b"\x81\x80abcd").await;
        let input = tokio::select! {
            biased;
            read = session.read() => Some(read),
            () = ready(()) => None,
        };
        assert!(input.is_none(), "unexpected client input: {input:?}");
        session.write(Bytes::from_static(b"\x81\x01x\x88\x00")).await.unwrap();
        receive(&mut session, b"\x88\x80abcd").await;
    }

    /// Decode the prefetched frame and handle control frames with the production codec.
    async fn drive_messages(session: &mut Session) {
        use praxis_protocol::http::pingora::websocket_session::WebSocketSession;
        use tungstenite::Message;

        let offer = PreparedLocalWebSocket::prepare(session).unwrap();
        let transport = offer.commit(session).await.unwrap();
        let mut messages = WebSocketSession::new(transport);
        assert_eq!(messages.receive().await.unwrap(), Some(Message::text("ab")));
        let oversized = Message::Binary(Bytes::from(vec![0; 1_048_577]));
        assert!(messages.send(oversized).await.is_err());
        messages.send(Message::text("x")).await.unwrap();
        assert_eq!(messages.receive().await.unwrap(), None);
    }

    /// A test-only terminal request hook with no upstream configured.
    struct LocalUpgrade(Arc<AtomicUsize>, bool);

    #[async_trait::async_trait]
    impl ProxyHttp for LocalUpgrade {
        type CTX = ();

        fn new_ctx(&self) {}

        async fn request_filter(&self, session: &mut Session, (): &mut ()) -> pingora_core::Result<bool> {
            if self.1 {
                drive_messages(session).await;
            } else {
                drive(session).await;
            }
            Ok(true)
        }

        async fn upstream_peer(&self, _: &mut Session, (): &mut ()) -> pingora_core::Result<Box<HttpPeer>> {
            unreachable!("local upgrade must finish before upstream selection")
        }

        async fn logging(&self, _: &mut Session, error: Option<&pingora_core::Error>, (): &mut ()) {
            assert!(error.is_none());
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Wait for the server's unsolicited message and close before sending anything else.
    async fn client(socket: TcpStream) {
        let mut socket = BufReader::new(socket);
        let mut head = String::new();
        while !head.ends_with("\r\n\r\n") {
            assert_ne!(socket.read_line(&mut head).await.unwrap(), 0);
        }
        assert!(head.starts_with("HTTP/1.1 101 Switching Protocols\r\n"));
        assert!(head.contains("s3pPLMBiTxaQ9kYGzzhZRbK+xOo="));
        let mut reply = [0; 5];
        socket.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"\x81\x01x\x88\x00");
        socket.get_mut().write_all(b"\x88\x80abcd").await.unwrap();
        assert_eq!(socket.read(&mut reply).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn prepared_offer_refuses_changed_negotiation_before_switching() {
        let (mut peer, socket) = tokio::io::duplex(1024);
        peer.write_all(OFFER).await.unwrap();
        let mut session = Session::new_h1(Box::new(socket));
        assert!(session.read_request().await.unwrap());
        let offer = PreparedLocalWebSocket::prepare(&session).unwrap();
        session
            .req_header_mut()
            .insert_header("sec-websocket-protocol", "new-protocol")
            .unwrap();
        assert_eq!(
            offer.commit(&mut session).await.err().unwrap().etype,
            pingora_core::ErrorType::InternalError
        );
        assert!(session.response_written().is_none());
    }

    #[tokio::test]
    async fn prepared_offer_refuses_changed_request_target() {
        let (mut peer, socket) = tokio::io::duplex(1024);
        peer.write_all(OFFER).await.unwrap();
        let mut session = Session::new_h1(Box::new(socket));
        assert!(session.read_request().await.unwrap());
        let offer = PreparedLocalWebSocket::prepare(&session).unwrap();
        session.req_header_mut().set_uri(http::Uri::from_static("/other"));
        assert_eq!(
            offer.commit(&mut session).await.err().unwrap().etype,
            pingora_core::ErrorType::InternalError
        );
        assert!(session.response_written().is_none());
    }

    #[tokio::test]
    async fn prepared_offer_refuses_changed_virtual_host() {
        let (mut peer, socket) = tokio::io::duplex(1024);
        peer.write_all(OFFER).await.unwrap();
        let mut session = Session::new_h1(Box::new(socket));
        assert!(session.read_request().await.unwrap());
        let offer = PreparedLocalWebSocket::prepare(&session).unwrap();
        session.req_header_mut().insert_header("host", "other.example").unwrap();
        assert_eq!(
            offer.commit(&mut session).await.err().unwrap().etype,
            pingora_core::ErrorType::InternalError
        );
        assert!(session.response_written().is_none());
    }

    #[tokio::test]
    async fn prepared_offer_compares_wire_target_even_when_parsed_uris_match() {
        let (mut peer, socket) = tokio::io::duplex(1024);
        peer.write_all(OFFER).await.unwrap();
        let mut session = Session::new_h1(Box::new(socket));
        assert!(session.read_request().await.unwrap());
        session.req_header_mut().set_raw_path(b"/\xff").unwrap();
        let original = session.req_header().uri.clone();
        let offer = PreparedLocalWebSocket::prepare(&session).unwrap();
        session.req_header_mut().set_raw_path(b"/\xfe").unwrap();
        assert_eq!(session.req_header().uri, original);
        assert_eq!(
            offer.commit(&mut session).await.err().unwrap().etype,
            pingora_core::ErrorType::InternalError
        );
        assert!(session.response_written().is_none());
    }

    #[tokio::test]
    async fn invalid_challenge_does_not_commit_a_switch() {
        let (mut peer, socket) = tokio::io::duplex(1024);
        peer.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: invalid\r\n\r\n").await.unwrap();
        let mut session = Session::new_h1(Box::new(socket));
        assert!(session.read_request().await.unwrap());
        assert!(LocalWebSocket::commit(&mut session).await.is_err());
        assert!(session.response_written().is_none());
        drop(session);
        let mut response = Vec::new();
        peer.read_to_end(&mut response).await.unwrap();
        assert!(response.is_empty());
    }

    #[tokio::test]
    async fn framed_request_is_rejected_before_the_switch() {
        let (mut peer, socket) = tokio::io::duplex(1024);
        let head = OFFER.strip_suffix(b"\r\n\x81\x80abcd").unwrap();
        peer.write_all(&[head, b"Content-Length: 1\r\n\r\nx"].concat())
            .await
            .unwrap();
        let mut session = Session::new_h1(Box::new(socket));
        assert!(session.read_request().await.unwrap());
        assert!(LocalWebSocket::commit(&mut session).await.is_err());
        assert!(session.response_written().is_none());
        drop(session);
        let mut response = Vec::new();
        peer.read_to_end(&mut response).await.unwrap();
        assert!(response.is_empty());
    }

    #[tokio::test]
    async fn oversized_inbound_frame_terminates_the_session() {
        use praxis_protocol::http::pingora::websocket_session::WebSocketSession;
        use tungstenite::{Error, Message};

        let (mut peer, socket) = tokio::io::duplex(1024);
        let head = OFFER.strip_suffix(b"\x81\x80abcd").unwrap();
        peer.write_all(head).await.unwrap();
        peer.write_all(b"\x82\xff\0\0\0\0\0\x10\0\x01\0\0\0\0").await.unwrap();
        let mut session = Session::new_h1(Box::new(socket));
        assert!(session.read_request().await.unwrap());
        let transport = LocalWebSocket::commit(&mut session).await.unwrap();
        let mut messages = WebSocketSession::new(transport);
        assert!(matches!(messages.receive().await, Err(Error::Capacity(_))));
        assert!(matches!(
            messages.send(Message::text("x")).await,
            Err(Error::AlreadyClosed)
        ));
    }

    /// Verify the server control replies and the assembled message response.
    async fn message_client(peer: TcpStream) {
        let mut peer = BufReader::new(peer);
        let mut head = String::new();
        while !head.ends_with("\r\n\r\n") {
            assert_ne!(peer.read_line(&mut head).await.unwrap(), 0);
        }
        let mut reply = [0; 6];
        peer.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"\x8a\x01p\x81\x01x");
        peer.get_mut().write_all(b"\x88\x80abcd").await.unwrap();
        let mut close = Vec::new();
        peer.read_to_end(&mut close).await.unwrap();
        assert_eq!(close, b"\x88\x00");
    }

    #[tokio::test]
    async fn bounded_session_reassembles_fragments_and_replies_to_controls() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut peer = TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
            let head = OFFER.strip_suffix(b"\x81\x80abcd").unwrap();
            let frames = b"\x01\x81\0\0\0\0a\x89\x81\0\0\0\0p\x80\x81\0\0\0\0b";
            peer.write_all(&[head, frames].concat()).await.unwrap();
            let (socket, _) = listener.accept().await.unwrap();
            let completed = Arc::new(AtomicUsize::default());
            praxis_tls::provider::install();
            let mut proxy = HttpProxy::new(LocalUpgrade(Arc::clone(&completed), true), Arc::default());
            proxy.handle_init_modules();
            let proxy = Arc::new(proxy);
            let (_signal, shutdown) = tokio::sync::watch::channel(false);
            let session = ServerSession::new_http1(Box::new(Stream::from(socket)));
            let ((), reusable) = tokio::join!(message_client(peer), proxy.process_new_http(session, &shutdown));
            assert!(reusable.is_none());
            assert_eq!(completed.load(Ordering::Relaxed), 1);
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn local_upgrade_drives_both_directions_without_an_upstream() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut peer = TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
            peer.write_all(OFFER).await.unwrap();
            let (socket, _) = listener.accept().await.unwrap();
            let completed = Arc::new(AtomicUsize::default());
            praxis_tls::provider::install();
            let mut proxy = HttpProxy::new(LocalUpgrade(Arc::clone(&completed), false), Arc::default());
            proxy.handle_init_modules();
            let proxy = Arc::new(proxy);
            let (_signal, shutdown) = tokio::sync::watch::channel(false);
            let session = ServerSession::new_http1(Box::new(Stream::from(socket)));
            let ((), reusable) = tokio::join!(client(peer), proxy.process_new_http(session, &shutdown));
            assert!(reusable.is_none());
            assert_eq!(completed.load(Ordering::Relaxed), 1);
        })
        .await
        .unwrap();
    }
}
