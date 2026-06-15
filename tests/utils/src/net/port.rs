// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Port allocation utilities for integration tests.

use std::{
    collections::HashSet,
    net::TcpListener,
    sync::{LazyLock, Mutex, PoisonError},
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
///
/// # Panics
///
/// Panics if a unique port cannot be bound after 256 attempts.
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

/// A held port that keeps its [`TcpListener`] open until dropped or released.
///
/// Call [`release`] to drop the listener and obtain the
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

/// Like [`free_port`] but returns a [`PortGuard`].
pub fn free_port_guard() -> PortGuard {
    let (listener, port) = bind_unique_port();
    PortGuard {
        port,
        _listener: listener,
    }
}

// -----------------------------------------------------------------------------
// IPv6
// -----------------------------------------------------------------------------

/// Attempt to bind to `[::1]:0`. Returns `true` if IPv6
/// loopback is available in this environment.
pub fn ipv6_available() -> bool {
    TcpListener::bind("[::1]:0").is_ok()
}

/// Allocate a free port on the IPv6 loopback interface.
///
/// # Panics
///
/// Panics if binding to `[::1]:0` fails (caller must check
/// [`ipv6_available`] first).
pub fn free_port_v6() -> u16 {
    TcpListener::bind("[::1]:0").unwrap().local_addr().unwrap().port()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn bind_unique_port_returns_distinct_ports() {
        let (listener_a, port_a) = bind_unique_port();
        let (listener_b, port_b) = bind_unique_port();

        assert_ne!(port_a, 0, "first port should be non-zero");
        assert_ne!(port_b, 0, "second port should be non-zero");
        assert_ne!(port_a, port_b, "two calls should return distinct ports");

        assert_ne!(
            listener_a.local_addr().unwrap().port(),
            0,
            "first listener should be bound to a valid port"
        );
        assert_ne!(
            listener_b.local_addr().unwrap().port(),
            0,
            "second listener should be bound to a valid port"
        );
    }
}
