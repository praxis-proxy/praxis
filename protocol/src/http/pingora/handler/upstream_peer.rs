// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Upstream peer selection: converts the filter pipeline's [`Upstream`] into a Pingora `HttpPeer`.
//!
//! [`Upstream`]: praxis_core::connectivity::Upstream

use std::sync::Arc;

use pingora_core::{Result, upstreams::peer::HttpPeer};
use praxis_core::connectivity::Upstream;

use super::super::{context::PingoraRequestCtx, convert::apply_connection_options};

// -----------------------------------------------------------------------------
// Execution/Conversion
// -----------------------------------------------------------------------------

/// Convert the pipeline's upstream selection into a Pingora `HttpPeer`.
///
/// On the first call, moves the upstream from `ctx.upstream` into
/// `ctx.upstream_for_retry` and borrows it. On retries, borrows the
/// saved copy directly. No clone is performed.
pub(super) fn execute(ctx: &mut PingoraRequestCtx) -> Result<Box<HttpPeer>> {
    if ctx.upstream_for_retry.is_none() {
        ctx.upstream_for_retry = ctx.upstream.take();
    }

    let upstream = ctx.upstream_for_retry.as_ref().ok_or_else(|| {
        let cluster = &ctx.cluster;
        pingora_core::Error::explain(
            pingora_core::ErrorType::InternalError,
            format!("no upstream selected (cluster: {cluster:?}); is a load_balancer configured?"),
        )
    })?;

    build_peer(upstream)
}

/// Parse the upstream address and build an [`HttpPeer`] with TLS/SNI config.
///
/// TLS certificates are already pre-parsed in the [`CachedClusterTls`]
/// attached to the upstream. This function converts the cached DER
/// bytes into Pingora types without any filesystem I/O.
///
/// When `sni` is `None`, derives it from the upstream address hostname
/// (unless it is an IP address).
///
/// [`HttpPeer`]: pingora_core::upstreams::peer::HttpPeer
/// [`CachedClusterTls`]: praxis_tls::CachedClusterTls
fn build_peer(upstream: &Upstream) -> Result<Box<HttpPeer>> {
    let addr: std::net::SocketAddr = upstream.address.parse().map_err(|e| {
        tracing::warn!(address = %upstream.address, error = %e, "failed to parse upstream address");
        pingora_core::Error::explain(
            pingora_core::ErrorType::InternalError,
            "upstream address resolution failed".to_owned(),
        )
    })?;

    let tls_enabled = upstream.tls.is_some();
    let sni = upstream
        .tls
        .as_ref()
        .and_then(|t| t.sni().map(str::to_owned))
        .unwrap_or_else(|| {
            if tls_enabled {
                derive_sni(&upstream.address)
            } else {
                String::new()
            }
        });

    let mut peer = HttpPeer::new(addr, tls_enabled, sni);
    apply_connection_options(&mut peer, &upstream.connection);

    if let Some(ref tls) = upstream.tls {
        apply_cached_tls(&mut peer, tls, &upstream.address);
    }

    Ok(Box::new(peer))
}

/// Apply pre-cached TLS settings to an [`HttpPeer`].
///
/// [`HttpPeer`]: pingora_core::upstreams::peer::HttpPeer
fn apply_cached_tls(peer: &mut HttpPeer, tls: &praxis_tls::CachedClusterTls, address: &str) {
    if !tls.verify() {
        tracing::debug!(upstream = %address, "upstream TLS verification disabled for this peer");
        peer.options.verify_cert = false;
        peer.options.verify_hostname = false;
    }

    if let Some(ca) = tls.ca() {
        peer.options.ca = Some(Arc::from(ca_from_cached(ca)));
    }

    if let Some(client) = tls.client_cert() {
        peer.client_cert_key = Some(Arc::new(client_cert_from_cached(client)));
    }
}

/// Convert cached CA DER bytes into [`WrappedX509`] values.
///
/// [`WrappedX509`]: pingora_core::utils::tls::WrappedX509
fn ca_from_cached(cached: &praxis_tls::CachedCaCerts) -> Vec<pingora_core::utils::tls::WrappedX509> {
    cached
        .der_certs()
        .iter()
        .map(|der| pingora_core::utils::tls::WrappedX509::parse(der.clone()))
        .collect()
}

/// Convert cached client cert/key DER bytes into a [`CertKey`].
///
/// [`CertKey`]: pingora_core::utils::tls::CertKey
fn client_cert_from_cached(cached: &praxis_tls::CachedClientCert) -> pingora_core::utils::tls::CertKey {
    pingora_core::utils::tls::CertKey::new(cached.cert_der().to_vec(), cached.key_der().to_vec())
}

/// Derive an SNI hostname from an `address` string in `host:port` form.
///
/// Returns the host portion if it is a DNS name. Returns an empty string
/// if the host is an IP address (IP-based SNI is not standard per [RFC 6066]).
///
/// [RFC 6066]: https://datatracker.ietf.org/doc/html/rfc6066
fn derive_sni(address: &str) -> String {
    let host = address.rsplit_once(':').map_or(address, |(h, _)| h);
    if host.parse::<std::net::IpAddr>().is_ok() {
        tracing::debug!(address, "upstream address is an IP; SNI left empty");
        return String::new();
    }
    tracing::debug!(address, sni = host, "derived SNI from upstream address");
    host.to_owned()
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::field_reassign_with_default,
    clippy::too_many_lines,
    clippy::significant_drop_tightening,
    reason = "tests"
)]
mod tests {
    use std::sync::Arc;

    use praxis_core::connectivity::{ConnectionOptions, Upstream};
    use praxis_tls::{CachedClusterTls, ClusterTls};

    use super::*;

    #[test]
    fn valid_address_builds_peer() {
        assert!(
            build_peer(&make_upstream("127.0.0.1:8080")).is_ok(),
            "valid address should build peer"
        );
    }

    #[test]
    fn build_peer_with_tls_enabled() {
        let tls = ClusterTls {
            sni: Some("api.example.com".to_owned()),
            ..ClusterTls::default()
        };
        let upstream = Upstream {
            address: Arc::from("127.0.0.1:8443"),
            connection: Arc::new(ConnectionOptions::default()),
            tls: Some(CachedClusterTls::try_from_config(&tls).unwrap()),
        };
        let peer = build_peer(&upstream).expect("should build TLS peer");
        assert!(!peer.sni.is_empty(), "TLS peer should have a non-empty SNI");
        assert_eq!(peer.sni, "api.example.com", "peer SNI should match configured value");
    }

    #[test]
    fn sni_not_set_with_hostname_address_derives_sni() {
        let sni = derive_sni("backend.example.com:8443");
        assert_eq!(
            sni, "backend.example.com",
            "SNI should be derived from hostname address"
        );
    }

    #[test]
    fn sni_not_set_with_ip_address_leaves_sni_empty() {
        let sni = derive_sni("127.0.0.1:8443");
        assert_eq!(sni, "", "SNI should be empty for IP address");
    }

    #[test]
    fn build_peer_without_tls() {
        let upstream = Upstream {
            address: Arc::from("127.0.0.1:8080"),
            connection: Arc::new(ConnectionOptions::default()),
            tls: None,
        };
        let peer = build_peer(&upstream).expect("should build plain peer");
        assert_eq!(peer.sni, "", "plain peer should have empty SNI");
    }

    #[test]
    fn build_peer_with_tls_verify_disabled() {
        let tls = ClusterTls {
            sni: Some("self-signed.local".to_owned()),
            verify: false,
            ..ClusterTls::default()
        };
        let upstream = Upstream {
            address: Arc::from("127.0.0.1:8443"),
            connection: Arc::new(ConnectionOptions::default()),
            tls: Some(CachedClusterTls::try_from_config(&tls).unwrap()),
        };
        let peer = build_peer(&upstream).expect("should build peer with verification disabled");
        assert!(
            !peer.options.verify_cert,
            "verify_cert should be false when verify is disabled"
        );
        assert!(
            !peer.options.verify_hostname,
            "verify_hostname should be false when verify is disabled"
        );
    }

    #[test]
    fn build_peer_with_tls_verify_enabled() {
        let tls = ClusterTls {
            sni: Some("api.example.com".to_owned()),
            ..ClusterTls::default()
        };
        let upstream = Upstream {
            address: Arc::from("127.0.0.1:8443"),
            connection: Arc::new(ConnectionOptions::default()),
            tls: Some(CachedClusterTls::try_from_config(&tls).unwrap()),
        };
        let peer = build_peer(&upstream).expect("should build peer with verification enabled");
        assert!(
            peer.options.verify_cert,
            "verify_cert should be true (default) when verify is enabled"
        );
        assert!(
            peer.options.verify_hostname,
            "verify_hostname should be true (default) when verify is enabled"
        );
    }

    #[test]
    fn invalid_address_returns_error() {
        assert!(
            build_peer(&make_upstream("not-an-address")).is_err(),
            "invalid address should return error"
        );
    }

    #[test]
    fn missing_port_returns_error() {
        assert!(
            build_peer(&make_upstream("127.0.0.1")).is_err(),
            "address without port should return error"
        );
    }

    #[test]
    fn execute_first_call_moves_upstream_to_retry() {
        let mut ctx = PingoraRequestCtx::default();
        ctx.upstream = Some(make_upstream("127.0.0.1:8080"));
        let result = execute(&mut ctx);
        assert!(result.is_ok(), "first execute should succeed");
        assert!(ctx.upstream.is_none(), "upstream should be consumed");
        assert!(ctx.upstream_for_retry.is_some(), "should save for retry");
        assert_eq!(
            &*ctx.upstream_for_retry.as_ref().unwrap().address,
            "127.0.0.1:8080",
            "saved retry address should match original"
        );
    }

    #[test]
    fn execute_retry_reuses_saved_upstream() {
        let mut ctx = PingoraRequestCtx::default();
        ctx.upstream = None;
        ctx.upstream_for_retry = Some(make_upstream("127.0.0.1:9090"));
        let result = execute(&mut ctx);
        assert!(result.is_ok(), "retry execute should succeed");
        assert!(
            ctx.upstream_for_retry.is_some(),
            "retry upstream should remain for further retries"
        );
    }

    #[test]
    fn execute_no_upstream_no_retry_returns_error() {
        let mut ctx = PingoraRequestCtx::default();
        ctx.upstream = None;
        ctx.upstream_for_retry = None;
        let result = execute(&mut ctx);
        assert!(result.is_err(), "execute with no upstream should return error");
        let err = result.unwrap_err().to_string();
        assert!(err.contains("no upstream selected"), "unexpected error message: {err}");
        assert!(
            err.contains("is a load_balancer configured?"),
            "error should mention load_balancer: {err}"
        );
    }

    #[test]
    fn execute_no_upstream_error_includes_cluster_name() {
        let mut ctx = PingoraRequestCtx::default();
        ctx.cluster = Some(Arc::from("my-api"));
        ctx.upstream = None;
        ctx.upstream_for_retry = None;
        let result = execute(&mut ctx);
        assert!(result.is_err(), "execute with no upstream should return error");
        let err = result.unwrap_err().to_string();
        assert!(err.contains("my-api"), "error should include cluster name: {err}");
    }

    #[test]
    fn build_peer_with_cached_ca() {
        let ca = gen_ca_file();
        let ca_path = ca.ca_path.to_str().expect("ca path should be valid UTF-8");

        let tls = ClusterTls {
            ca: Some(praxis_tls::CaConfig {
                ca_path: ca_path.to_owned(),
            }),
            sni: Some("api.example.com".to_owned()),
            ..ClusterTls::default()
        };
        let upstream = Upstream {
            address: Arc::from("127.0.0.1:8443"),
            connection: Arc::new(ConnectionOptions::default()),
            tls: Some(CachedClusterTls::try_from_config(&tls).unwrap()),
        };
        let peer = build_peer(&upstream).expect("should build peer with cached CA");
        assert!(peer.options.ca.is_some(), "peer should have custom CA set from cache");
    }

    #[test]
    fn ca_from_cached_produces_wrapped_x509() {
        let ca = gen_ca_file();
        let ca_path = ca.ca_path.to_str().expect("ca path should be valid UTF-8");

        let cached = praxis_tls::CachedCaCerts::from_pem_file(ca_path).expect("valid CA should parse");
        let wrapped = ca_from_cached(&cached);
        assert_eq!(wrapped.len(), 1, "should produce one WrappedX509");
    }

    #[test]
    fn client_cert_from_cached_produces_cert_key() {
        let pair = gen_cert_key_files();
        let cert_path = pair.cert_path.to_str().expect("cert path should be valid UTF-8");
        let key_path = pair.key_path.to_str().expect("key path should be valid UTF-8");

        let cached =
            praxis_tls::CachedClientCert::from_pem_files(cert_path, key_path).expect("valid cert+key should parse");
        let _cert_key = client_cert_from_cached(&cached);
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// Create a test upstream with the given address (no TLS).
    fn make_upstream(address: &str) -> Upstream {
        Upstream {
            address: Arc::from(address),
            connection: Arc::new(ConnectionOptions::default()),
            tls: None,
        }
    }

    /// Generated CA certificate file with temp dir lifetime.
    struct TestCa {
        /// Path to the CA certificate PEM file.
        ca_path: std::path::PathBuf,

        /// Temp directory holding the cert file.
        _temp_dir: tempfile::TempDir,
    }

    /// Generated cert + key files with temp dir lifetime.
    struct TestCertKey {
        /// Path to the certificate PEM file.
        cert_path: std::path::PathBuf,

        /// Path to the private key PEM file.
        key_path: std::path::PathBuf,

        /// Temp directory holding the files.
        _temp_dir: tempfile::TempDir,
    }

    /// Generate a self-signed CA certificate file for testing.
    fn gen_ca_file() -> TestCa {
        use rcgen::{CertificateParams, DnType, IsCa, KeyPair};

        let ca_key = KeyPair::generate().expect("CA key generation should succeed");
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("CA params should be valid");
        ca_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.distinguished_name.push(DnType::CommonName, "Test CA");
        let ca_cert = ca_params.self_signed(&ca_key).expect("CA self-sign should succeed");

        let temp_dir = tempfile::TempDir::new().expect("tempdir creation should succeed");
        let ca_path = temp_dir.path().join("ca.pem");
        std::fs::write(&ca_path, ca_cert.pem()).expect("write CA PEM should succeed");

        TestCa {
            ca_path,
            _temp_dir: temp_dir,
        }
    }

    /// Generate a self-signed cert + key pair for testing.
    fn gen_cert_key_files() -> TestCertKey {
        use rcgen::{CertificateParams, DnType, KeyPair};

        let key = KeyPair::generate().expect("key generation should succeed");
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("params should be valid");
        params.distinguished_name.push(DnType::CommonName, "Test Cert");
        let cert = params.self_signed(&key).expect("self-sign should succeed");

        let temp_dir = tempfile::TempDir::new().expect("tempdir creation should succeed");
        let cert_path = temp_dir.path().join("cert.pem");
        let key_path = temp_dir.path().join("key.pem");
        std::fs::write(&cert_path, cert.pem()).expect("write cert PEM should succeed");
        std::fs::write(&key_path, key.serialize_pem()).expect("write key PEM should succeed");

        TestCertKey {
            cert_path,
            key_path,
            _temp_dir: temp_dir,
        }
    }
}
