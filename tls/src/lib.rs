// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

#![deny(unreachable_pub)]
#![expect(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::min_ident_chars,
    reason = "TODO(conventions-sync): fix violations and remove"
)]

//! TLS configuration types for the Praxis proxy.
//!
//! `praxis-tls` is the deepest crate in the dependency flow
//! `server -> protocol -> filter -> core -> tls`: it has no Praxis
//! dependencies and is consumed by `praxis_core` and the layers above
//! it. Isolating TLS types here keeps certificate and SNI handling in
//! one place so listener and upstream configuration can share a single
//! representation.
//!
//! Responsibilities:
//! - TLS configuration types for listeners and upstream clusters ([`ListenerTls`], [`ClusterTls`], [`CertKeyPair`],
//!   [`CaConfig`], [`TlsVersion`], [`CipherSuiteId`], [`ClientCertMode`]).
//! - SNI resolution, including wildcard matching ([`sni`], [`sni_name`]).
//! - Certificate and key loading with cached materials ([`setup`], [`CachedClusterTls`], [`CachedCaCerts`],
//!   [`CachedClientCert`]).
//! - Peer identity extracted from client certificates ([`TlsPeerIdentity`]).
//!
//! Certificate hot-reload support (the [`reload`] and [`watcher`]
//! modules) is gated behind the `hot-reload` feature.

mod cached;
mod client_auth;
mod config;
pub mod dns;
mod error;
mod identity;
#[cfg(feature = "hot-reload")]
pub mod reload;
pub mod setup;
pub mod sni;
pub mod sni_name;
#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, reason = "test utilities")]
mod test_utils;
#[cfg(feature = "hot-reload")]
pub mod watcher;

pub use cached::{CachedCaCerts, CachedClientCert, CachedClusterTls};
pub use config::{CaConfig, CertKeyPair, CipherSuiteId, ClientCertMode, ClusterTls, ListenerTls, TlsVersion};
pub use error::TlsError;
pub use identity::TlsPeerIdentity;
pub use sni_name::{SniNameError, validate as validate_sni_name};
