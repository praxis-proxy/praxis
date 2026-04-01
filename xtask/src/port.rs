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

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::net::TcpListener;

    use super::*;

    #[test]
    fn resolves_free_port_unchanged() {
        let addr = resolve_available("127.0.0.1:0");
        assert!(
            addr.starts_with("127.0.0.1:"),
            "resolved address should retain the host"
        );
    }

    #[test]
    fn resolves_occupied_port_to_next() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        let bound_port = listener.local_addr().unwrap().port();
        let addr = format!("127.0.0.1:{bound_port}");

        let resolved = resolve_available(&addr);
        let resolved_port: u16 = resolved.rsplit_once(':').unwrap().1.parse().unwrap();

        assert!(
            resolved_port > bound_port,
            "resolved port ({resolved_port}) should be higher than occupied port ({bound_port})"
        );
    }

    #[test]
    fn preserves_host_part() {
        let resolved = resolve_available("0.0.0.0:0");
        assert!(resolved.starts_with("0.0.0.0:"), "host part should be preserved");
    }

    #[test]
    #[should_panic(expected = "address must contain ':'")]
    fn panics_on_missing_colon() {
        resolve_available("no-port");
    }

    #[test]
    #[should_panic(expected = "invalid port")]
    fn panics_on_invalid_port() {
        resolve_available("127.0.0.1:notaport");
    }
}
