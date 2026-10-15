// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Separate-process loopback responder so heap totals count only the client.

use std::{
    fmt::Write as _,
    io::Write as _,
    net::SocketAddr,
    process::{Child, Command, Stdio},
    time::Duration,
};

use bytes::Bytes;
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener, TcpStream},
};

use super::BODY;

/// Child responder and its ephemeral listening address.
pub(crate) struct Backend {
    child: Child,
    address: SocketAddr,
}

impl Backend {
    /// The already-bound loopback address announced by the responder.
    pub(crate) fn address(&self) -> SocketAddr {
        self.address
    }

    /// Start the same binary as a responder and bound its readiness wait.
    ///
    /// # Panics
    ///
    /// Panics if the child cannot start or announce its address within ten seconds.
    #[must_use]
    pub(crate) fn start(protocol: &str, headers: usize) -> Self {
        use std::io::{BufRead as _, BufReader};

        let child = Command::new(std::env::current_exe().unwrap())
            .args(["--backend", protocol, &headers.to_string()])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let mut backend = Self {
            child,
            address: "127.0.0.1:0".parse().unwrap(),
        };
        let stdout = backend.child.stdout.take().unwrap();
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let reader = std::thread::spawn(move || {
            let mut line = String::new();
            BufReader::new(stdout).read_line(&mut line).unwrap();
            let _sent = sender.send(line);
        });
        backend.address = receiver
            .recv_timeout(Duration::from_secs(10))
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        reader.join().unwrap();
        backend
    }
}

impl Drop for Backend {
    fn drop(&mut self) {
        drop(self.child.stdin.take());
        let _killed = self.child.kill();
        let _reaped = self.child.wait();
    }
}

/// Serve until the parent closes its stdin pipe, including on parent death.
///
/// # Panics
///
/// Panics if the loopback listener cannot bind or accept a connection.
pub(crate) async fn serve(protocol: &str, headers: usize) {
    use std::io::Read as _;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    println!("{}", listener.local_addr().unwrap());
    std::io::stdout().flush().unwrap();
    let (sender, mut shutdown) = tokio::sync::oneshot::channel();
    std::thread::spawn(move || {
        let mut byte = [0_u8; 1];
        #[expect(
            clippy::disallowed_methods,
            reason = "benchmark child reads its parent lifetime pipe, not interactive input"
        )]
        let _eof = std::io::stdin().read(&mut byte);
        let _sent = sender.send(());
    });
    let mut connection = 0_u64;
    loop {
        let (socket, _) = tokio::select! {
            result = listener.accept() => result.unwrap(),
            _ = &mut shutdown => break,
        };
        socket.set_nodelay(true).unwrap();
        connection = connection.checked_add(1).unwrap();
        let http2 = protocol == "h2";
        tokio::spawn(async move {
            if http2 {
                serve_h2(socket, headers, connection).await;
            } else {
                serve_h1(socket, headers, connection).await;
            }
        });
    }
}

/// Serve bodyless, non-pipelined HTTP/1.1 benchmark requests on one connection.
async fn serve_h1(mut socket: TcpStream, headers: usize, connection: u64) {
    let mut response_head = format!("HTTP/1.1 200 OK\r\nContent-Length: 64\r\nX-Bench-Connection: {connection}\r\n");
    for index in 0..headers {
        write!(
            &mut response_head,
            "X-Bench-{index:03}: 0123456789abcdef0123456789abcdef\r\n"
        )
        .unwrap();
    }
    response_head.push_str("\r\n");
    let mut response_bytes = response_head.into_bytes();
    response_bytes.extend_from_slice(&BODY);
    let mut request = Vec::with_capacity(4096);
    loop {
        request.clear();
        while !request.ends_with(b"\r\n\r\n") {
            match socket.read_buf(&mut request).await {
                Ok(0) | Err(_) => return,
                Ok(_) => assert!(request.len() <= 65_536, "unexpected request size"),
            }
        }
        if socket.write_all(&response_bytes).await.is_err() {
            return;
        }
    }
}

/// Serve HTTP/2 requests, retaining one connection for sequential or paired calls.
async fn serve_h2(socket: TcpStream, headers: usize, connection: u64) {
    let mut response_builder = http::Response::builder()
        .status(200)
        .header("content-length", "64")
        .header("x-bench-connection", connection.to_string());
    for index in 0..headers {
        response_builder = response_builder.header(format!("x-bench-{index:03}"), "0123456789abcdef0123456789abcdef");
    }
    let response_template = response_builder.body(()).unwrap();
    let mut session = h2::server::handshake(socket).await.unwrap();
    while let Some(request) = session.accept().await {
        let Ok((_request, mut respond)) = request else { return };
        let Ok(mut body) = respond.send_response(response_template.clone(), false) else {
            return;
        };
        if body.send_data(Bytes::from_static(&BODY), true).is_err() {
            return;
        }
    }
}
