// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Transport peer construction and failure classification.

use pingora_core::upstreams::peer::HttpPeer;
use praxis_core::{
    connectivity::peer::{AddressResolutionError, MissingServerName},
    subrequest::SubRequestError,
};

use super::TransportFailure;
use crate::StreamTerminationCause;

/// Why a sub-request transport peer could not be built.
#[derive(Debug, thiserror::Error)]
pub(super) enum PeerError {
    /// The upstream address failed to resolve or was refused.
    #[error(transparent)]
    Resolve(#[from] AddressResolutionError),

    /// TLS is on but there is no server name to verify the certificate against.
    #[error(transparent)]
    MissingServerName(#[from] MissingServerName),
}

/// Convert a Praxis [`Upstream`] to a Pingora [`HttpPeer`].
///
/// Applies TLS settings (CA, client cert, verify toggle) and
/// connection options (timeouts) from the upstream config. Derives
/// SNI from the address (hostname, or IP for IP SAN verification) when
/// not explicitly configured, and refuses a TLS peer left with no name.
///
/// Resolution goes through [`resolve_upstream_checked`], so a sub-request
/// upstream hostname that resolves into a private or reserved range is
/// refused unless `allow_private` (`insecure_options.allow_private_upstreams`)
/// is set or the host is trusted.
///
/// [`Upstream`]: praxis_core::connectivity::Upstream
/// [`resolve_upstream_checked`]: praxis_core::connectivity::peer::resolve_upstream_checked
pub(super) async fn build_peer(
    upstream: &praxis_core::connectivity::Upstream,
    allow_private: bool,
) -> Result<HttpPeer, PeerError> {
    use praxis_core::connectivity::peer as peer_utils;

    let addr: &str = &upstream.address;
    let socket_addr = peer_utils::resolve_upstream_checked(upstream, allow_private).await?;
    let tls_enabled = upstream.tls.is_some();
    let sni = upstream
        .tls
        .as_ref()
        .map(|tls| peer_utils::tls_server_name(tls, addr))
        .transpose()?
        .unwrap_or_default();

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
        SubRequestError::ResponseTooLarge { actual, limit } => (
            502,
            TransportFailure::ResponseTooLarge {
                actual: *actual,
                limit: *limit,
            },
        ),
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
        TransportFailure::ResponseTooLarge { .. } => StreamTerminationCause::ResponseTooLarge,
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
