// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Transport peer construction and failure classification.

use pingora_core::upstreams::peer::HttpPeer;
use praxis_core::subrequest::SubRequestError;

use super::TransportFailure;
use crate::StreamTerminationCause;

/// Convert a Praxis [`Upstream`] to a Pingora [`HttpPeer`].
///
/// Applies TLS settings (CA, client cert, verify toggle) and
/// connection options (timeouts) from the upstream config. Derives
/// SNI from the address hostname when not explicitly configured.
///
/// Resolution goes through [`resolve_address_checked`], so a sub-request
/// upstream hostname that resolves into a private or reserved range is
/// refused unless `allow_private` (`insecure_options.allow_private_upstreams`)
/// is set.
///
/// [`Upstream`]: praxis_core::connectivity::Upstream
/// [`resolve_address_checked`]: praxis_core::connectivity::peer::resolve_address_checked
pub(super) async fn build_peer(
    upstream: &praxis_core::connectivity::Upstream,
    allow_private: bool,
) -> Result<HttpPeer, praxis_core::connectivity::peer::AddressResolutionError> {
    use praxis_core::connectivity::peer as peer_utils;

    let addr: &str = &upstream.address;
    let socket_addr = peer_utils::resolve_address_checked(addr, allow_private).await?;
    let tls_enabled = upstream.tls.is_some();
    let sni = upstream
        .tls
        .as_ref()
        .and_then(|t| t.sni().map(str::to_owned))
        .unwrap_or_else(|| {
            if tls_enabled {
                peer_utils::derive_sni(addr)
            } else {
                String::new()
            }
        });

    let mut peer = HttpPeer::new(socket_addr, tls_enabled, sni);
    peer_utils::apply_connection_options(&mut peer, &upstream.connection);

    if let Some(tls) = &upstream.tls {
        peer_utils::apply_cached_tls(&mut peer, tls, addr);
    }

    Ok(peer)
}

/// Convert transport failures into a gateway status and error classification.
pub(super) fn classify_transport_failure(error: &SubRequestError) -> (u16, TransportFailure) {
    match error {
        SubRequestError::AdmissionTimeout { .. } => (503, TransportFailure::AdmissionTimeout),
        SubRequestError::CircuitOpen { .. } => (503, TransportFailure::CircuitOpen),
        SubRequestError::Connect(_) => (502, TransportFailure::Connect),
        SubRequestError::DeadlineExceeded => (504, TransportFailure::DeadlineExceeded),
        SubRequestError::ResponseTooLarge { .. } => (502, TransportFailure::ResponseTooLarge),
        _ => (502, TransportFailure::Io),
    }
}

/// Convert transition-level transport metadata into completion-hook metadata.
pub(super) fn stream_termination_cause(kind: TransportFailure) -> StreamTerminationCause {
    match kind {
        TransportFailure::AdmissionTimeout => StreamTerminationCause::AdmissionTimeout,
        TransportFailure::CircuitOpen => StreamTerminationCause::CircuitOpen,
        TransportFailure::Connect => StreamTerminationCause::Connect,
        TransportFailure::Io => StreamTerminationCause::Io,
        TransportFailure::DeadlineExceeded => StreamTerminationCause::DeadlineExceeded,
        TransportFailure::ResponseTooLarge => StreamTerminationCause::ResponseTooLarge,
    }
}

/// Map transport detail to the provider-neutral completion classification.
pub(super) fn termination_cause(error: &SubRequestError) -> StreamTerminationCause {
    match error {
        SubRequestError::AdmissionTimeout { .. } => StreamTerminationCause::AdmissionTimeout,
        SubRequestError::CircuitOpen { .. } => StreamTerminationCause::CircuitOpen,
        SubRequestError::Connect(_) => StreamTerminationCause::Connect,
        SubRequestError::DeadlineExceeded => StreamTerminationCause::DeadlineExceeded,
        SubRequestError::StreamIdleTimeout { .. } => StreamTerminationCause::IdleTimeout,
        SubRequestError::ResponseTooLarge { .. } => StreamTerminationCause::ResponseTooLarge,
        _ => StreamTerminationCause::Io,
    }
}
