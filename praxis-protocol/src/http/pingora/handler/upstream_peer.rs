//! Upstream peer selection: converts the filter pipeline's [`Upstream`]
//! into a Pingora `HttpPeer`, with retry support.
//!
//! [`Upstream`]: praxis_core::connectivity::Upstream

use pingora_core::{Result, upstreams::peer::HttpPeer};
use praxis_core::connectivity::Upstream;

use super::super::{context::RequestCtx, convert::apply_connection_options};

// -----------------------------------------------------------------------------
// Execution/Conversion
// -----------------------------------------------------------------------------

/// Convert the pipeline's upstream selection into a Pingora `HttpPeer`.
pub(super) fn execute(ctx: &mut RequestCtx) -> Result<Box<HttpPeer>> {
    // On first call, take the upstream: move the original into retry
    // storage and clone for the peer builder (saves one clone since
    // build_peer transforms and discards the value anyway).
    // On retry, restore from the saved copy.
    let upstream = if let Some(u) = ctx.upstream.take() {
        let peer_upstream = u.clone();
        ctx.upstream_for_retry = Some(u);
        peer_upstream
    } else if let Some(ref saved) = ctx.upstream_for_retry {
        saved.clone()
    } else {
        return Err(pingora_core::Error::explain(
            pingora_core::ErrorType::InternalError,
            "no upstream selected by filter pipeline (is a load_balancer filter configured?)",
        ));
    };

    build_peer(upstream)
}

/// Parse the upstream address and build an `HttpPeer` with TLS/SNI config.
fn build_peer(upstream: Upstream) -> Result<Box<HttpPeer>> {
    let addr: std::net::SocketAddr = upstream.address.parse().map_err(|e| {
        pingora_core::Error::explain(
            pingora_core::ErrorType::InternalError,
            format!("invalid upstream address '{}': {e}", upstream.address),
        )
    })?;

    let mut peer = HttpPeer::new(addr, upstream.tls, upstream.sni);
    apply_connection_options(&mut peer, &upstream.connection);
    Ok(Box::new(peer))
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use praxis_core::connectivity::{ConnectionOptions, Upstream};

    use super::*;

    fn make_upstream(address: &str) -> Upstream {
        Upstream {
            address: address.into(),
            tls: false,
            sni: String::new(),
            connection: ConnectionOptions::default(),
        }
    }

    #[test]
    fn valid_address_builds_peer() {
        assert!(build_peer(make_upstream("127.0.0.1:8080")).is_ok());
    }

    #[test]
    fn invalid_address_returns_error() {
        assert!(build_peer(make_upstream("not-an-address")).is_err());
    }

    #[test]
    fn missing_port_returns_error() {
        assert!(build_peer(make_upstream("127.0.0.1")).is_err());
    }
}
