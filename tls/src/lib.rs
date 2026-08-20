// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

#![deny(unreachable_pub)]
#![expect(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::impl_trait_in_params,
    clippy::min_ident_chars,
    clippy::mod_module_files,
    reason = "TODO(conventions-sync): fix violations and remove"
)]

//! TLS configuration types for the Praxis proxy.

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
