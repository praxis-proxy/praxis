//! Port availability utilities for dev commands.

use std::net::TcpListener;

// -----------------------------------------------------------------------------
// Port Resolution
// -----------------------------------------------------------------------------

/// Resolve an address to one with an available port.
///
/// If the port in `address` is already free, returns it unchanged.
/// Otherwise increments the port until a free one is found.
///
/// # Panics
///
/// Panics if `address` has no `:port` suffix, the port is not a
/// valid `u16`, or no port is available before overflow.
pub(crate) fn resolve_available(address: &str) -> String {
    let (host, port_str) = address.rsplit_once(':').expect("address must contain ':'");
    let original: u16 = port_str.parse().expect("invalid port");
    let mut port = original;
    loop {
        let candidate = format!("{host}:{port}");
        if TcpListener::bind(&candidate).is_ok() {
            if port != original {
                tracing::info!("port {original} in use, using {port}");
            }
            return candidate;
        }
        port = port.checked_add(1).expect("no available port found");
    }
}
