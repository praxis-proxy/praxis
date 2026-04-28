// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

#![deny(unsafe_code)]
#![deny(unreachable_pub)]

//! TLS configuration types for the Praxis proxy.

mod cached;
mod client_auth;
mod config;
mod error;
#[cfg(feature = "hot-reload")]
pub mod reload;
pub mod setup;
pub mod sni;
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, reason = "test utilities")]
mod test_utils;
#[cfg(feature = "hot-reload")]
pub mod watcher;

pub use cached::{CachedCaCerts, CachedClientCert, CachedClusterTls};
pub use config::{CaConfig, CertKeyPair, CipherSuiteId, ClientCertMode, ClusterTls, ListenerTls, TlsVersion};
pub use error::TlsError;
