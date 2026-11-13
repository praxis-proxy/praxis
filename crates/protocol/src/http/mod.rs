// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! HTTP protocol implementation.
//!
//! The backend-neutral parts (health probes and metadata, Prometheus
//! metrics, the admin and KV handlers) are reachable at [`health`],
//! [`metrics`] and `kv`; the Pingora adapter around them lives in
//! [`pingora`] and the hyper adapter in the `hyper` module, each behind
//! the feature of the same name.
//!
//! [`health`]: crate::http::health
//! [`metrics`]: crate::http::metrics
//! [`pingora`]: crate::http::pingora

/// Shared request-body size admission and rejection diagnostics.
#[cfg(any(feature = "pingora", feature = "hyper"))]
mod body_limit;
/// hyper-backed HTTP implementation: listeners, the proxy service and the
/// admin glue.
#[cfg(feature = "hyper")]
pub mod hyper;
/// Pingora-backed HTTP implementation, plus the backend-neutral health,
/// metrics and admin modules it grew up around.
pub mod pingora;

#[cfg(feature = "hyper")]
pub use hyper::HyperHttp;
#[cfg(feature = "admin-api")]
pub use pingora::health::PingoraHealthService;
#[cfg(feature = "admin-api")]
pub use pingora::kv;
#[cfg(feature = "pingora")]
pub use pingora::{PingoraHttp, handler::load_http_handler};
pub use pingora::{health, metrics};

/// Whether a method is eligible for automatic retries and hedged requests.
///
/// QUERY is safe and idempotent under RFC 10008. The other methods retain
/// Praxis's conservative replay policy; PUT, DELETE and TRACE need explicit
/// retry opt-in even though HTTP defines them as idempotent.
#[cfg(any(feature = "pingora", feature = "hyper"))]
pub(crate) fn permits_automatic_replay(method: &http::Method) -> bool {
    matches!(
        *method,
        http::Method::GET | http::Method::HEAD | http::Method::OPTIONS | http::Method::QUERY
    )
}

#[cfg(test)]
#[cfg(any(feature = "pingora", feature = "hyper"))]
mod tests {
    use http::Method;

    #[test]
    fn automatic_replay_includes_query_and_preserves_other_method_restrictions()
    -> Result<(), http::method::InvalidMethod> {
        for (method, eligible) in [
            (Method::GET, true),
            (Method::HEAD, true),
            (Method::OPTIONS, true),
            (Method::QUERY, true),
            (Method::POST, false),
            (Method::PUT, false),
            (Method::DELETE, false),
            (Method::PATCH, false),
            (Method::TRACE, false),
            (Method::CONNECT, false),
            (Method::from_bytes(b"CUSTOM")?, false),
            (Method::from_bytes(b"query")?, false),
        ] {
            assert_eq!(
                super::permits_automatic_replay(&method),
                eligible,
                "{method} replay eligibility"
            );
        }
        Ok(())
    }
}
