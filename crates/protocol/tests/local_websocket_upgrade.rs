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
    use praxis_protocol::http::pingora::local_upgrade::LocalWebSocket;
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
        let accept = http::HeaderValue::from_static("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
        let mut session = LocalWebSocket::commit(session, accept).await.unwrap();
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

    /// A test-only terminal request hook with no upstream configured.
    struct LocalUpgrade(Arc<AtomicUsize>);

    #[async_trait::async_trait]
    impl ProxyHttp for LocalUpgrade {
        type CTX = ();

        fn new_ctx(&self) {}

        async fn request_filter(&self, session: &mut Session, (): &mut ()) -> pingora_core::Result<bool> {
            drive(session).await;
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
    async fn framed_request_is_rejected_before_the_switch() {
        let (mut peer, socket) = tokio::io::duplex(1024);
        peer.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nContent-Length: 1\r\n\r\nx").await.unwrap();
        let mut session = Session::new_h1(Box::new(socket));
        assert!(session.read_request().await.unwrap());
        let accept = http::HeaderValue::from_static("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
        assert!(LocalWebSocket::commit(&mut session, accept).await.is_err());
        assert!(session.response_written().is_none());
        drop(session);
        let mut response = Vec::new();
        peer.read_to_end(&mut response).await.unwrap();
        assert!(response.is_empty());
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
            let mut proxy = HttpProxy::new(LocalUpgrade(Arc::clone(&completed)), Arc::default());
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
