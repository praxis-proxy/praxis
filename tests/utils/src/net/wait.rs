// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Readiness check utilities for integration tests.

use std::{
    io::{self, Read as _, Write as _},
    net::TcpStream,
    time::{Duration, Instant},
};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Environment variable overriding the readiness deadline, in milliseconds.
///
/// When set to a positive integer it replaces the default deadline of every
/// `wait_for_*` utility. Coverage runs and heavily loaded CI runners set it so
/// slow server startup under instrumentation does not read as a test failure.
/// Unset, empty, zero, or unparseable values leave each utility on its default.
pub(crate) const READY_TIMEOUT_ENV_VAR: &str = "PRAXIS_TEST_READY_TIMEOUT_MS";

/// Default readiness deadline for a bare TCP connect.
const DEFAULT_TCP_TIMEOUT: Duration = Duration::from_secs(2);

/// Default readiness deadline for an HTTP or HTTP/2 handshake.
pub(crate) const DEFAULT_HTTP_TIMEOUT: Duration = Duration::from_secs(5);

/// Interval between readiness poll attempts.
const POLL_INTERVAL: Duration = Duration::from_millis(10);

/// HTTP/2 connection preface ([RFC 9113 Section 3.4]).
///
/// [RFC 9113 Section 3.4]: https://datatracker.ietf.org/doc/html/rfc9113#section-3.4
const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Empty SETTINGS frame: length=0, type=0x04, flags=0, stream=0.
const SETTINGS: &[u8] = &[0, 0, 0, 4, 0, 0, 0, 0, 0];

/// SETTINGS ACK frame: length=0, type=0x04, flags=0x01 (ACK), stream=0.
const SETTINGS_ACK: &[u8] = &[0, 0, 0, 4, 1, 0, 0, 0, 0];

/// GOAWAY frame: `length=8`, `type=0x07`, `flags=0`, `stream=0`,
/// `last_stream_id=0`, `error_code=0` (`NO_ERROR`).
const GOAWAY: &[u8] = &[0, 0, 8, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

// -----------------------------------------------------------------------------
// Deadline Resolution
// -----------------------------------------------------------------------------

/// Resolve the readiness deadline, honoring `READY_TIMEOUT_ENV_VAR`.
///
/// Returns the env-var override when it parses to a positive number of
/// milliseconds; otherwise returns `default`.
pub(crate) fn ready_timeout(default: Duration) -> Duration {
    resolve_ready_timeout(std::env::var(READY_TIMEOUT_ENV_VAR).ok().as_deref(), default)
}

/// Poll `is_ready` until it returns `true` or `timeout` elapses.
///
/// Returns `true` on readiness and `false` once the deadline passes. Always
/// makes at least one attempt, even when `timeout` is zero.
pub(crate) fn poll_until_ready(timeout: Duration, mut is_ready: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;

    loop {
        if is_ready() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

/// Resolve a readiness deadline from a raw override string.
///
/// A value that trims to a positive integer becomes the deadline in
/// milliseconds; anything else (absent, empty, non-numeric, or zero) falls
/// back to `default`.
fn resolve_ready_timeout(raw: Option<&str>, default: Duration) -> Duration {
    raw.map(str::trim)
        .filter(|value| !value.is_empty())
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|ms| *ms > 0)
        .map_or(default, Duration::from_millis)
}

// -----------------------------------------------------------------------------
// Readiness Checks
// -----------------------------------------------------------------------------

/// Block until a TCP connection to `addr` succeeds, or panic once the
/// readiness deadline (default 2 seconds) passes.
///
/// Override the deadline with `READY_TIMEOUT_ENV_VAR`.
///
/// # Panics
///
/// Panics if the server does not become ready before the deadline.
pub fn wait_for_tcp(addr: &str) {
    let timeout = ready_timeout(DEFAULT_TCP_TIMEOUT);

    assert!(
        poll_until_ready(timeout, || TcpStream::connect(addr).is_ok()),
        "server at {addr} did not become ready within {timeout:?}"
    );
}

/// Block until an HTTP request to `addr` gets a valid response, or panic once
/// the readiness deadline (default 5 seconds) passes.
///
/// Override the deadline with `READY_TIMEOUT_ENV_VAR`.
///
/// # Panics
///
/// Panics if the server does not become ready before the deadline.
pub fn wait_for_http(addr: &str) {
    let request = b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    let timeout = ready_timeout(DEFAULT_HTTP_TIMEOUT);
    let ready = poll_until_ready(timeout, || {
        let Ok(mut stream) = TcpStream::connect(addr) else {
            return false;
        };
        drop(stream.set_read_timeout(Some(Duration::from_secs(5))));
        drop(stream.set_write_timeout(Some(Duration::from_secs(2))));
        if stream.write_all(request).is_err() {
            return false;
        }
        let mut buf = [0_u8; 16];
        if let Ok(count) = stream.read(&mut buf)
            && count >= 5
            && buf.starts_with(b"HTTP/")
        {
            let mut drain = [0_u8; 4096];
            while stream.read(&mut drain).unwrap_or(0) > 0 {}
            return true;
        }
        false
    });
    assert!(ready, "HTTP server at {addr} did not become ready within {timeout:?}");
}

/// Block until `addr` returns a complete initial HTTP/2 SETTINGS frame, or
/// panic once the readiness deadline (default 5 seconds) passes.
///
/// Override the deadline with `READY_TIMEOUT_ENV_VAR`.
///
/// # Panics
///
/// Panics if the server does not become ready before the deadline.
pub fn wait_for_http2(addr: &str) {
    let timeout = ready_timeout(DEFAULT_HTTP_TIMEOUT);
    let ready = poll_until_ready(timeout, || {
        http2_settings_exchange(addr, Duration::from_secs(1)).is_ok()
    });

    assert!(ready, "HTTP/2 server at {addr} did not become ready within {timeout:?}");

    std::thread::sleep(Duration::from_millis(100));
}

/// Exchange connection prefaces and validate the peer's first SETTINGS frame.
fn http2_settings_exchange(addr: &str, timeout: Duration) -> io::Result<()> {
    http2_settings_exchange_with_read_limit(addr, timeout, usize::MAX)
}

/// Cap individual reads so tests force fragmentation independently of TCP coalescing.
fn http2_settings_exchange_with_read_limit(addr: &str, timeout: Duration, max_read: usize) -> io::Result<()> {
    let mut stream = TcpStream::connect(addr)?;
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "readiness deadline overflow"))?;
    write_all_until(&mut stream, PREFACE, deadline)?;
    write_all_until(&mut stream, SETTINGS, deadline)?;

    let mut header = [0_u8; 9];
    read_exact_until(&mut stream, &mut header, deadline, max_read)?;
    let length = usize::try_from(u32::from_be_bytes([0, header[0], header[1], header[2]]))
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let stream_id = u32::from_be_bytes([header[5] & 0x7F, header[6], header[7], header[8]]);
    if header[3] != 4 || header[4] & 1 != 0 || stream_id != 0 || length > 16_384 || length % 6 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid initial SETTINGS frame",
        ));
    }
    let mut payload = vec![0_u8; length];
    read_exact_until(&mut stream, &mut payload, deadline, max_read)?;
    validate_settings(&payload)?;
    write_all_until(&mut stream, SETTINGS_ACK, deadline)?;
    write_all_until(&mut stream, GOAWAY, deadline)
}

/// Keep every blocking write inside the same readiness attempt deadline.
fn write_all_until(stream: &mut TcpStream, mut bytes: &[u8], deadline: Instant) -> io::Result<()> {
    while !bytes.is_empty() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "SETTINGS write timed out"));
        }
        stream.set_write_timeout(Some(remaining))?;
        let count = stream.write(bytes)?;
        if count == 0 {
            return Err(io::Error::from(io::ErrorKind::WriteZero));
        }
        bytes = &bytes[count..];
    }
    Ok(())
}

/// Keep every blocking read inside the same readiness attempt deadline.
fn read_exact_until(stream: &mut TcpStream, bytes: &mut [u8], deadline: Instant, max_read: usize) -> io::Result<()> {
    let mut remaining_bytes = bytes;
    while !remaining_bytes.is_empty() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "SETTINGS read timed out"));
        }
        stream.set_read_timeout(Some(remaining))?;
        let amount = remaining_bytes.len().min(max_read);
        let count = stream.read(&mut remaining_bytes[..amount])?;
        if count == 0 {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }
        remaining_bytes = &mut remaining_bytes[count..];
    }
    Ok(())
}

/// Validate the constrained values of standard SETTINGS entries.
fn validate_settings(payload: &[u8]) -> io::Result<()> {
    for setting in payload.chunks_exact(6) {
        let id = u16::from_be_bytes([setting[0], setting[1]]);
        let value = u32::from_be_bytes([setting[2], setting[3], setting[4], setting[5]]);
        let valid = match id {
            2 => value <= 1,
            4 => value <= 2_147_483_647,
            5 => (16_384..=16_777_215).contains(&value),
            _ => true,
        };
        if !valid {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid SETTINGS value"));
        }
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http2_readiness_handles_fragmented_settings() {
        let frame = [0, 0, 6, 4, 0, 0, 0, 0, 0, 0, 4, 0, 0, 255, 255];
        for max_read in [1, 3, usize::MAX] {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("listen");
            let addr = listener.local_addr().expect("address").to_string();
            let server = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().expect("accept");
                let mut preface = [0_u8; 33];
                stream.read_exact(&mut preface).expect("client preface and SETTINGS");
                stream.write_all(&frame).expect("SETTINGS frame");
                let mut ack = [0_u8; 9];
                stream.read_exact(&mut ack).expect("SETTINGS ACK");
                assert_eq!(ack, SETTINGS_ACK, "client must acknowledge server settings");
                let mut goaway = [0_u8; 17];
                stream.read_exact(&mut goaway).expect("GOAWAY");
                assert_eq!(goaway, GOAWAY, "readiness closes the probe connection");
            });
            http2_settings_exchange_with_read_limit(&addr, Duration::from_secs(1), max_read)
                .expect("fragmented SETTINGS should complete");
            server.join().expect("server");
        }
    }

    #[test]
    fn http2_readiness_rejects_invalid_settings() {
        for frame in [
            vec![0, 0, 0, 4, 0, 0, 0, 0, 1],
            vec![0, 0, 6, 4, 0, 0, 0, 0, 0],
            vec![0, 0, 1, 4, 0, 0, 0, 0, 0, 0],
            vec![0, 0, 0, 4, 1, 0, 0, 0, 0],
        ] {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("listen");
            let addr = listener.local_addr().expect("address").to_string();
            let server = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().expect("accept");
                let mut preface = [0_u8; 33];
                stream.read_exact(&mut preface).expect("client preface and SETTINGS");
                stream.write_all(&frame).expect("invalid SETTINGS");
            });
            http2_settings_exchange(&addr, Duration::from_millis(300))
                .expect_err("invalid or truncated initial SETTINGS must fail");
            server.join().expect("server");
        }
    }

    #[test]
    fn resolve_ready_timeout_uses_default_when_absent() {
        assert_eq!(
            resolve_ready_timeout(None, DEFAULT_TCP_TIMEOUT),
            DEFAULT_TCP_TIMEOUT,
            "an absent override should keep the default deadline"
        );
    }

    #[test]
    fn resolve_ready_timeout_parses_positive_override() {
        assert_eq!(
            resolve_ready_timeout(Some("1500"), DEFAULT_TCP_TIMEOUT),
            Duration::from_millis(1500),
            "a positive override should replace the default deadline"
        );
    }

    #[test]
    fn resolve_ready_timeout_trims_surrounding_whitespace() {
        assert_eq!(
            resolve_ready_timeout(Some("  250  "), DEFAULT_HTTP_TIMEOUT),
            Duration::from_millis(250),
            "surrounding whitespace should be ignored"
        );
    }

    #[test]
    fn resolve_ready_timeout_rejects_empty_and_unparseable() {
        for raw in ["", "   ", "abc", "-5", "1.5", "12ms"] {
            assert_eq!(
                resolve_ready_timeout(Some(raw), DEFAULT_HTTP_TIMEOUT),
                DEFAULT_HTTP_TIMEOUT,
                "invalid override {raw:?} should fall back to the default"
            );
        }
    }

    #[test]
    fn resolve_ready_timeout_rejects_zero() {
        assert_eq!(
            resolve_ready_timeout(Some("0"), DEFAULT_TCP_TIMEOUT),
            DEFAULT_TCP_TIMEOUT,
            "a zero override is nonsensical and should fall back to the default"
        );
    }

    #[test]
    fn poll_until_ready_returns_true_on_first_success() {
        let mut attempts = 0_u32;

        let ready = poll_until_ready(Duration::from_secs(60), || {
            attempts += 1;
            true
        });

        assert!(ready, "an immediately-ready probe should succeed");
        assert_eq!(attempts, 1, "success on the first probe should not retry");
    }

    #[test]
    fn poll_until_ready_retries_until_success() {
        let mut attempts = 0_u32;

        let ready = poll_until_ready(Duration::from_secs(60), || {
            attempts += 1;
            attempts >= 3
        });

        assert!(ready, "the probe should eventually report ready");
        assert_eq!(attempts, 3, "the poller should retry until the probe succeeds");
    }

    #[test]
    fn poll_until_ready_attempts_once_even_with_zero_timeout() {
        let mut attempts = 0_u32;

        let ready = poll_until_ready(Duration::from_millis(0), || {
            attempts += 1;
            false
        });

        assert!(!ready, "a never-ready probe should report not ready");
        assert_eq!(attempts, 1, "even a zero deadline must probe at least once");
    }

    #[test]
    fn poll_until_ready_honors_wall_clock_deadline() {
        let start = Instant::now();

        let ready = poll_until_ready(Duration::from_millis(80), || false);
        let elapsed = start.elapsed();

        assert!(!ready, "a never-ready probe should time out");
        assert!(
            elapsed >= Duration::from_millis(80),
            "the poller must wait for the full deadline, waited {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_secs(1),
            "the poller must stop near the deadline, not run for the 2s/5s defaults, waited {elapsed:?}"
        );
    }
}
