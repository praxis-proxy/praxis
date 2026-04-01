//! Port allocation and readiness utilities.

use std::{
    collections::HashSet,
    net::{TcpListener, TcpStream},
    sync::{LazyLock, Mutex, PoisonError},
    time::Duration,
};

// -----------------------------------------------------------------------------
// Statics
// -----------------------------------------------------------------------------

/// Process-wide set of allocated ports.
static ALLOCATED_PORTS: LazyLock<Mutex<HashSet<u16>>> = LazyLock::new(|| Mutex::new(HashSet::new()));

// -----------------------------------------------------------------------------
// Port Allocation
// -----------------------------------------------------------------------------

/// Bind to an OS-assigned port that is not already in the
/// process-wide allocation set, then register it.
pub fn bind_unique_port() -> (TcpListener, u16) {
    for _ in 0..256 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        if ALLOCATED_PORTS
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(port)
        {
            return (listener, port);
        }
    }
    panic!("failed to bind a unique port after 256 attempts");
}

/// A held port that keeps its [`TcpListener`] open until
/// dropped, preventing TOCTOU races where another process
/// grabs the port between allocation and use.
///
/// Call [`release`] to drop the listener and obtain the raw
/// port number just before starting the server under test.
///
/// [`release`]: PortGuard::release
pub struct PortGuard {
    /// The allocated port number.
    port: u16,
    /// Held listener that prevents port reuse until dropped.
    _listener: TcpListener,
}

impl PortGuard {
    /// The allocated port number.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Consume the guard, releasing the held listener so the
    /// port can be rebound by the server under test.
    pub fn release(self) -> u16 {
        self.port
    }
}

impl std::fmt::Display for PortGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.port)
    }
}

/// Allocate a free port using OS-assigned binding.
pub fn free_port() -> u16 {
    let (_listener, port) = bind_unique_port();
    port
}

/// Like [`free_port`] but returns a [`PortGuard`] that keeps
/// the listener open until dropped or [`release`]d. Useful
/// when there is meaningful setup work between port
/// allocation and server start.
///
/// [`release`]: PortGuard::release
pub fn free_port_guard() -> PortGuard {
    let (listener, port) = bind_unique_port();
    PortGuard {
        port,
        _listener: listener,
    }
}

// -----------------------------------------------------------------------------
// Readiness Checks
// -----------------------------------------------------------------------------

/// Block until a TCP connection to `addr` succeeds, or panic after 2 seconds.
pub fn wait_for_tcp(addr: &str) {
    for _ in 0..200 {
        if TcpStream::connect(addr).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("server at {addr} did not become ready within 2s");
}

/// Block until an HTTP request to `addr` gets a valid
/// response, or panic after 5 seconds.
///
/// Drains the full response so the server completes its
/// response cycle (including upstream connection cleanup)
/// before the caller proceeds.
pub fn wait_for_http(addr: &str) {
    use std::io::{Read, Write};

    let request = b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";

    for _ in 0..500 {
        if let Ok(mut stream) = TcpStream::connect(addr) {
            stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
            stream.set_write_timeout(Some(Duration::from_secs(2))).ok();
            if stream.write_all(request).is_ok() {
                let mut buf = [0u8; 16];
                if let Ok(n) = stream.read(&mut buf)
                    && n >= 5
                    && buf.starts_with(b"HTTP/")
                {
                    let mut drain = [0u8; 4096];
                    while stream.read(&mut drain).unwrap_or(0) > 0 {}
                    return;
                }
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("HTTP server at {addr} did not become ready within 5s");
}

/// Block until a full HTTP/2 handshake with `addr` completes, or panic after 5 seconds.
pub fn wait_for_http2(addr: &str) {
    use std::io::{Read, Write};

    /// HTTP/2 connection preface ([RFC 9113 Section 3.4]).
    ///
    /// [RFC 9113 Section 3.4]: https://datatracker.ietf.org/doc/html/rfc9113#section-3.4
    const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

    /// Empty SETTINGS frame: length=0, type=0x04, flags=0, stream=0.
    const SETTINGS: &[u8] = &[0, 0, 0, 4, 0, 0, 0, 0, 0];

    /// SETTINGS ACK frame: length=0, type=0x04, flags=0x01 (ACK), stream=0.
    const SETTINGS_ACK: &[u8] = &[0, 0, 0, 4, 1, 0, 0, 0, 0];

    /// GOAWAY frame: `length=8`, `type=0x07`, `flags=0`, `stream=0`, `last_stream_id=0`, `error_code=0` (`NO_ERROR`).
    const GOAWAY: &[u8] = &[0, 0, 8, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    for _ in 0..500 {
        if let Ok(mut stream) = TcpStream::connect(addr) {
            stream.set_read_timeout(Some(Duration::from_secs(1))).ok();
            stream.set_write_timeout(Some(Duration::from_secs(1))).ok();
            if stream.write_all(PREFACE).is_ok() && stream.write_all(SETTINGS).is_ok() {
                let mut buf = [0u8; 64];
                if let Ok(n) = stream.read(&mut buf)
                    && n >= 9
                    && buf[3] == 0x04
                {
                    let _ = stream.write_all(SETTINGS_ACK);
                    let _ = stream.write_all(GOAWAY);
                    let mut drain = [0u8; 256];
                    while stream.read(&mut drain).unwrap_or(0) > 0 {}
                    drop(stream);
                    std::thread::sleep(Duration::from_millis(100));
                    return;
                }
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("HTTP/2 server at {addr} did not become ready within 5s");
}
