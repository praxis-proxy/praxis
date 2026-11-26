// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Backend-neutral egress: how Praxis opens one HTTP exchange to a peer.
//!
//! A network backend supplies a [`Connector`] that turns a [`PeerSpec`]
//! into a live [`Session`]. The sub-request client, the filters that dial
//! callouts, and the policy engine's transport speak only these types, so
//! swapping the backend never touches them. The Pingora and hyper
//! implementations live in the `pingora` and `hyper` submodules behind the
//! features of the same names; [`Unavailable`] stands in when no backend is
//! compiled in.
//!
//! [`Connector`]: crate::egress::Connector
//! [`PeerSpec`]: crate::egress::PeerSpec
//! [`Session`]: crate::egress::Session
//! [`Unavailable`]: crate::egress::Unavailable

/// The hyper backend's connector, sessions and connection pool.
#[cfg(feature = "hyper")]
pub mod hyper;
/// Where to connect: the backend-neutral description of one peer.
mod peer;
/// The Pingora backend's connector and session.
#[cfg(feature = "pingora")]
pub mod pingora;
/// The connection contract a backend implements.
mod session;
/// The stand-in for a build with no backend.
mod unavailable;

pub use peer::{DEFAULT_POOL_GROUP, PeerSpec, UpstreamPeerError};
pub use session::{Completion, Connector, EgressError, RequestHead, ResponseHead, Session};
pub use unavailable::{Unavailable, UnavailableSession};

/// Map a failed exchange onto [`EgressError`], keeping the HTTP/2 reason.
///
/// Mirrors the main proxy's retry classification: only `REFUSED_STREAM`
/// proves the peer did not process the request, a GOAWAY or an HTTP/2 I/O
/// failure is a plain I/O error, and any other stream or connection error
/// (an `INTERNAL_ERROR`, for one) may follow a processed request.
#[cfg(any(feature = "pingora", feature = "hyper"))]
pub(crate) fn exchange_error(h2_error: Option<&h2::Error>, message: String) -> EgressError {
    match h2_error {
        Some(error) if error.reason() == Some(h2::Reason::REFUSED_STREAM) => EgressError::Refused(message),
        Some(error) if !error.is_go_away() && !error.is_io() => EgressError::Aborted(message),
        Some(_) | None => EgressError::Io(message),
    }
}
