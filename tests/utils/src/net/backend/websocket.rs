// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! `WebSocket` echo backend for integration testing.

use std::net::SocketAddr;

use futures::{SinkExt as _, StreamExt as _};
use tokio::net::TcpListener;
use tokio_tungstenite::accept_async;
use tracing::debug;

use crate::net::port::free_port;

// ---------------------------------------------------------------------------
// `WebSocket` Echo Backend
// ---------------------------------------------------------------------------

/// RAII guard for an async `WebSocket` echo backend.
///
/// The server shuts down when the guard is dropped.
pub struct WsBackendGuard {
    /// The port the backend is listening on.
    port: u16,

    /// Shutdown signal sender.
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,

    /// Task handle for cleanup.
    handle: Option<tokio::task::JoinHandle<()>>,
}

impl WsBackendGuard {
    /// The allocated port number.
    pub fn port(&self) -> u16 {
        self.port
    }
}

impl Drop for WsBackendGuard {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _sent = tx.send(());
        }
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

/// Start a `WebSocket` echo server that reflects each message
/// back to the client.
///
/// Returns a [`WsBackendGuard`] whose [`port()`] method
/// gives the listen port.
///
/// # Panics
///
/// Panics if the server fails to bind.
///
/// [`port()`]: WsBackendGuard::port
pub async fn start_websocket_echo_backend() -> WsBackendGuard {
    let port = free_port();
    let addr: SocketAddr = ([127, 0, 0, 1], port).into();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    let listener = TcpListener::bind(addr).await.unwrap();
    debug!(port, "websocket echo backend listening");

    let handle = tokio::spawn(async move {
        tokio::select! {
            _ = accept_loop(&listener) => {},
            _ = shutdown_rx => {
                debug!("websocket echo backend shutting down");
            },
        }
    });

    WsBackendGuard {
        port,
        shutdown: Some(shutdown_tx),
        handle: Some(handle),
    }
}

/// Accept `WebSocket` connections in a loop.
#[expect(clippy::infinite_loop, reason = "server accept loop runs until task cancellation")]
async fn accept_loop(listener: &TcpListener) {
    loop {
        let Ok((stream, peer)) = listener.accept().await else {
            continue;
        };
        debug!(%peer, "websocket echo backend accepted connection");
        tokio::spawn(async move {
            let Ok(ws) = accept_async(stream).await else {
                return;
            };
            echo_messages(ws).await;
        });
    }
}

/// Echo every message back until the client disconnects.
async fn echo_messages(ws: tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>) {
    let (mut sink, mut stream) = ws.split();
    while let Some(Ok(msg)) = stream.next().await {
        if msg.is_close() {
            break;
        }
        if sink.send(msg).await.is_err() {
            break;
        }
    }
}
