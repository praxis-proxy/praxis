// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Backend-neutral egress: how Praxis opens one HTTP exchange to a peer.
//!
//! A network backend supplies a [`Connector`] that turns a [`PeerSpec`]
//! into a live [`Session`]. The sub-request client, the filters that dial
//! callouts, and the policy engine's transport speak only these types, so
//! swapping the backend never touches them. The Pingora implementation
//! lives in the `pingora` submodule behind the feature of the same name;
//! [`Unavailable`] stands in when no backend is compiled in.
//!
//! [`Connector`]: crate::egress::Connector
//! [`PeerSpec`]: crate::egress::PeerSpec
//! [`Session`]: crate::egress::Session
//! [`Unavailable`]: crate::egress::Unavailable

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
