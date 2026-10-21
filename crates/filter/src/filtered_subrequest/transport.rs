// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Transport peer construction and failure classification.

use praxis_core::{
    egress::{PeerSpec, UpstreamPeerError},
    subrequest::SubRequestError,
};

use super::TransportFailure;
use crate::StreamTerminationCause;

/// Resolve a Praxis [`Upstream`] into a dialable [`PeerSpec`].
///
/// The spec carries the upstream's TLS material (CA, client cert, verify
/// toggle) and connection options (timeouts). The server name comes from
/// the cluster config or is derived from the address (hostname, or IP for IP
/// SAN verification), and a TLS peer left with no name is refused.
///
/// A sub-request upstream hostname that resolves into a private or reserved
/// range is refused unless `allow_private`
/// (`insecure_options.allow_private_upstreams`) is set or the host is
/// trusted.
///
/// [`Upstream`]: praxis_core::connectivity::Upstream
pub(super) async fn build_peer(
    upstream: &praxis_core::connectivity::Upstream,
    allow_private: bool,
) -> Result<PeerSpec, UpstreamPeerError> {
    PeerSpec::from_upstream(upstream, allow_private).await
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
