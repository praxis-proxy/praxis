// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Transport peer construction and failure classification.

use std::{sync::Arc, time::Instant};

use praxis_core::{
    connectivity::Upstream,
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
pub(super) async fn build_peer(upstream: &Upstream, allow_private: bool) -> Result<PeerSpec, UpstreamPeerError> {
    PeerSpec::from_upstream(upstream, allow_private).await
}

/// One transport peer paired with the address it dials.
pub(super) type BuiltPeer = (Arc<str>, Result<PeerSpec, UpstreamPeerError>);

/// Build one peer per staged fallback address, or the single peer for
/// `upstream`, before `attempt_deadline`, each paired with the address it
/// dials.
///
/// Each fallback peer reuses `upstream`'s authority, TLS, and connection
/// options; only the transport socket address varies. Peer construction may
/// resolve a hostname, so it counts against the attempt: `None` when the
/// deadline passes first.
pub(super) async fn build_peers(
    upstream: &Upstream,
    fallback_addresses: &[std::net::SocketAddr],
    allow_private: bool,
    attempt_deadline: Instant,
) -> Option<Vec<BuiltPeer>> {
    build_peers_with(upstream, fallback_addresses, attempt_deadline, |target| async move {
        build_peer(&target, allow_private).await
    })
    .await
}

/// [`build_peers`] with the per-address peer construction supplied by
/// `build`.
pub(super) async fn build_peers_with<Build, Built>(
    upstream: &Upstream,
    fallback_addresses: &[std::net::SocketAddr],
    attempt_deadline: Instant,
    build: Build,
) -> Option<Vec<BuiltPeer>>
where
    Build: Fn(Upstream) -> Built + Sync,
    Built: Future<Output = Result<PeerSpec, UpstreamPeerError>> + Send,
{
    let all = async {
        if fallback_addresses.len() <= 1 {
            return vec![(Arc::clone(&upstream.address), build(upstream.clone()).await)];
        }
        let mut built = Vec::with_capacity(fallback_addresses.len());
        for address in fallback_addresses {
            let mut target = upstream.clone();
            target.address = Arc::from(address.to_string());
            built.push((Arc::clone(&target.address), build(target).await));
        }
        built
    };
    tokio::time::timeout_at(attempt_deadline.into(), all).await.ok()
}

/// Convert transport failures into a gateway status and error classification.
pub(super) fn classify_transport_failure(error: &SubRequestError) -> (u16, TransportFailure) {
    match error {
        SubRequestError::AdmissionTimeout { .. } => (503, TransportFailure::AdmissionTimeout),
        SubRequestError::CircuitOpen { .. } => (503, TransportFailure::CircuitOpen),
        SubRequestError::Connect(_) => (502, TransportFailure::Connect),
        SubRequestError::InvalidRequest(_) => (502, TransportFailure::InvalidRequest),
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
        TransportFailure::Io | TransportFailure::InvalidRequest => StreamTerminationCause::Io,
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

/// Publish only the current attempt's observed forwarding, including cancellation.
pub(super) fn publish_forwarding(
    ctx: &mut crate::HttpFilterContext<'_>,
    forwarding: Option<&(Arc<str>, praxis_core::subrequest::RequestProgress)>,
) {
    ctx.extensions.remove::<crate::UpstreamForwardedEndpoint>();
    if let Some((endpoint, progress)) = forwarding
        && progress.forwarded()
    {
        ctx.extensions
            .insert(crate::UpstreamForwardedEndpoint(Arc::clone(endpoint)));
    }
}
