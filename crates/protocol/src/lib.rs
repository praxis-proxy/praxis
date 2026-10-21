// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

#![forbid(unsafe_code)]
#![deny(unreachable_pub)]
#![expect(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::iter_over_hash_type,
    clippy::min_ident_chars,
    clippy::mod_module_files,
    clippy::partial_pub_fields,
    clippy::pub_underscore_fields,
    clippy::shadow_unrelated,
    clippy::single_char_lifetime_names,
    clippy::wildcard_enum_match_arm,
    reason = "TODO(conventions-sync): fix violations and remove"
)]

//! Protocol adapters for Praxis.
//!
//! `praxis-protocol` sits below `server` and above `filter` in the
//! crate dependency flow `server -> protocol -> filter -> core -> tls`.
//! It binds the [`praxis_filter`] pipeline engine to the network backend's
//! HTTP and TCP services, so that inbound connections are served, filters
//! run at the right lifecycle points, and requests are forwarded to
//! upstream clusters.
//!
//! Responsibilities:
//! - HTTP protocol implementations and the backend adapters ([`http`]).
//! - Raw TCP/L4 forwarding ([`tcp`]).
//! - Active health-check probes and admin/observability endpoints.
//! - TLS listener setup (the `tls_setup` module), plus holding the certificate hot-reload watcher shutdown handles so
//!   those watchers can be stopped early ([`CertWatcherShutdowns`]).
//! - The build's selected backend behind [`backend`]: its protocol adapters and admin-surface registration.
//!
//! Boundary with the backend (Pingora today): the backend owns
//! request-smuggling prevention, HTTP/2 backpressure, connection-pool
//! safety, and HTTP/1.1 upgrade detection with bidirectional forwarding
//! (WebSocket and similar). Praxis code in this crate and in
//! [`praxis_filter`] owns hop-by-hop header stripping (with conditional
//! preservation for upgrade requests), Host validation, `X-Forwarded-*`
//! injection, and retry logic. See `docs/developing/adding-backends.md`
//! for what a backend provides.

mod cert_watcher_shutdowns;
pub use cert_watcher_shutdowns::CertWatcherShutdowns;

mod pipelines;
pub use pipelines::ListenerPipelines;

mod protocol;
pub use protocol::Protocol;

/// Process-wide connection limit.
pub mod connections;
/// HTTP protocol implementations.
pub mod http;
/// Raw TCP/L4 forwarding protocol.
pub mod tcp;

/// Shared TLS settings builder for HTTP and TCP listeners.
pub mod tls_setup;

// -----------------------------------------------------------------------------
// Backend Selection
// -----------------------------------------------------------------------------

/// The protocol adapters and admin surface of the build's network backend.
///
/// Together with [`praxis_core::backend`], this is every name the server
/// bootstrap and the test harness need from a backend: `Http` and `Tcp`
/// implement [`Protocol`] and bind listeners onto the runtime, and
/// [`admin`] registers the management, health and metrics listeners. Under
/// the `pingora` feature they resolve to the Pingora adapters. A build with
/// no backend feature has none of them, so nothing can bind a listener; see
/// `docs/developing/adding-backends.md` for what a new backend supplies.
///
/// [`admin`]: crate::backend::admin
/// [`praxis_core::backend`]: praxis_core::backend
/// [`Protocol`]: crate::Protocol
pub mod backend {
    /// The HTTP protocol adapter.
    #[cfg(feature = "pingora")]
    pub use crate::http::pingora::PingoraHttp as Http;
    /// The raw TCP/L4 protocol adapter.
    #[cfg(feature = "pingora")]
    pub use crate::tcp::PingoraTcp as Tcp;

    /// Management, health and metrics listeners on the backend runtime.
    ///
    /// The handlers behind these listeners are backend-neutral (see
    /// [`AdminRequest`]); a backend only parses the request and serves the
    /// response.
    ///
    /// [`AdminRequest`]: crate::http::health::AdminRequest
    #[cfg(feature = "admin-api")]
    pub mod admin {
        pub use crate::http::pingora::health::{
            AdminEndpointOptions, PrometheusAdminRecorder, StatsAdminState, install_prometheus_admin_recorder,
        };
        #[cfg(feature = "pingora")]
        pub use crate::http::pingora::health::{
            add_admin_api, add_health_endpoint, add_health_endpoint_with_pipelines, add_prometheus_upkeep,
        };
    }
}
