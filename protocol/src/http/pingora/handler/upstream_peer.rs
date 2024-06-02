// SPDX-License-Identifier: LGPL-3.0-only
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

/// Parse the upstream address and build an `HttpPeer` with TLS/SNI config.
///
/// When TLS is configured (`upstream.tls` is `Some`), applies SNI, verify
/// settings, and optional client cert for upstream mTLS. When `sni` is
/// `None`, derives it from the upstream address hostname (unless it is
/// an IP address, since IP-based SNI is not standard).
#[allow(clippy::too_many_lines, reason = "sequential TLS branches")]
fn build_peer(upstream: &Upstream) -> Result<Box<HttpPeer>> {
    let addr: std::net::SocketAddr = upstream.address.parse().map_err(|e| {
        tracing::warn!(address = %upstream.address, error = %e, "failed to parse upstream address");
        pingora_core::Error::explain(
            pingora_core::ErrorType::InternalError,
            "upstream address resolution failed".to_owned(),
        )
    })?;

    let tls_enabled = upstream.tls.is_some();
    let sni = upstream.tls.as_ref().and_then(|t| t.sni.clone()).unwrap_or_else(|| {
        if tls_enabled {
            derive_sni(&upstream.address)
        } else {
            String::new()
        }
    });

    let mut peer = HttpPeer::new(addr, tls_enabled, sni);
    apply_connection_options(&mut peer, &upstream.connection);

    if let Some(ref tls) = upstream.tls {
        if !tls.verify {
            tracing::debug!(
                upstream = %upstream.address,
                "upstream TLS verification disabled for this peer"
            );
            peer.options.verify_cert = false;
            peer.options.verify_hostname = false;
        }

        if let Some(ref ca) = tls.ca {
            let wrapped = load_ca_certs(&ca.ca_path)
                .map_err(|e| pingora_core::Error::explain(pingora_core::ErrorType::InternalError, e))?;
            peer.options.ca = Some(Arc::from(wrapped));
        }

        if let Some(ref client_cert) = tls.client_cert {
            let cert_key = load_upstream_client_cert(&client_cert.cert_path, &client_cert.key_path)
                .map_err(|e| pingora_core::Error::explain(pingora_core::ErrorType::InternalError, e))?;
            peer.client_cert_key = Some(Arc::new(cert_key));
        }
    }

    Ok(Box::new(peer))
}

/// Load client certificate and key PEM files for upstream mTLS.
fn load_upstream_client_cert(
    cert_path: &str,
    key_path: &str,
) -> std::result::Result<pingora_core::utils::tls::CertKey, String> {
    let cert_pem = std::fs::read(cert_path).map_err(|e| format!("failed to read client cert {cert_path}: {e}"))?;
    let key_pem = std::fs::read(key_path).map_err(|e| format!("failed to read client key {key_path}: {e}"))?;

    let certs: Vec<Vec<u8>> = rustls_pemfile::certs(&mut &cert_pem[..])
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| format!("failed to parse client cert PEM {cert_path}: {e}"))?
        .into_iter()
        .map(|c| c.to_vec())
        .collect();
    let key: Vec<u8> = rustls_pemfile::private_key(&mut &key_pem[..])
        .map_err(|e| format!("failed to parse client key PEM {key_path}: {e}"))?
        .ok_or_else(|| format!("no private key found in {key_path}"))?
        .secret_der()
        .to_vec();

    Ok(pingora_core::utils::tls::CertKey::new(certs, key))
}

/// Load CA certificates from a PEM file into [`WrappedX509`] values for per-peer verification.
///
/// [`WrappedX509`]: pingora_core::utils::tls::WrappedX509
fn load_ca_certs(ca_path: &str) -> std::result::Result<Vec<pingora_core::utils::tls::WrappedX509>, String> {
    let ca_pem = std::fs::read(ca_path).map_err(|e| format!("failed to read CA {ca_path}: {e}"))?;
    let certs: Vec<Vec<u8>> = rustls_pemfile::certs(&mut &ca_pem[..])
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| format!("failed to parse CA PEM {ca_path}: {e}"))?
        .into_iter()
        .map(|c| c.to_vec())
        .collect();
    if certs.is_empty() {
        return Err(format!("no certificates found in CA file {ca_path}"));
    }
    Ok(certs
        .into_iter()
        .map(|der| pingora_core::utils::tls::WrappedX509::new(der, pingora_core::utils::tls::parse_x509))
        .collect())
}

/// Derive an SNI hostname from an `address` string in `host:port` form.
///
/// Returns the host portion if it is a DNS name. Returns an empty string
/// if the host is an IP address (IP-based SNI is not standard per RFC 6066).
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
mod tests {
    use std::sync::Arc;

    use praxis_core::connectivity::{ConnectionOptions, Upstream};
    use praxis_tls::ClusterTls;

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
        let upstream = Upstream {
            address: Arc::from("127.0.0.1:8443"),
            tls: Some(ClusterTls {
                sni: Some("api.example.com".to_owned()),
                ..ClusterTls::default()
            }),
            connection: Arc::new(ConnectionOptions::default()),
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
            tls: None,
            connection: Arc::new(ConnectionOptions::default()),
        };
        let peer = build_peer(&upstream).expect("should build plain peer");
        assert_eq!(peer.sni, "", "plain peer should have empty SNI");
    }

    #[test]
    fn build_peer_with_tls_verify_disabled() {
        let upstream = Upstream {
            address: Arc::from("127.0.0.1:8443"),
            tls: Some(ClusterTls {
                verify: false,
                sni: Some("self-signed.local".to_owned()),
                ..ClusterTls::default()
            }),
            connection: Arc::new(ConnectionOptions::default()),
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
        let upstream = Upstream {
            address: Arc::from("127.0.0.1:8443"),
            tls: Some(ClusterTls {
                sni: Some("api.example.com".to_owned()),
                ..ClusterTls::default()
            }),
            connection: Arc::new(ConnectionOptions::default()),
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
    fn load_ca_certs_with_valid_ca() {
        let ca = gen_ca_file();
        let ca_path = ca.ca_path.to_str().expect("ca path should be valid UTF-8");

        let certs = load_ca_certs(ca_path).expect("valid CA file should load");
        assert_eq!(certs.len(), 1, "should load exactly one CA cert");
    }

    #[test]
    fn load_ca_certs_nonexistent_file_returns_error() {
        let err = load_ca_certs("/nonexistent/ca.pem").expect_err("nonexistent file should fail");
        assert!(
            err.contains("failed to read CA"),
            "error should mention read failure: {err}"
        );
    }

    #[test]
    fn load_ca_certs_empty_pem_returns_error() {
        let temp_dir = tempfile::TempDir::new().expect("tempdir creation should succeed");
        let empty_path = temp_dir.path().join("empty.pem");
        std::fs::write(&empty_path, "").expect("write empty PEM should succeed");

        let err =
            load_ca_certs(empty_path.to_str().expect("path should be valid UTF-8")).expect_err("empty PEM should fail");
        assert!(
            err.contains("no certificates found"),
            "error should mention no certificates: {err}"
        );
    }

    #[test]
    fn build_peer_with_ca_applies_custom_ca() {
        let ca = gen_ca_file();
        let ca_path = ca.ca_path.to_str().expect("ca path should be valid UTF-8");

        let upstream = Upstream {
            address: Arc::from("127.0.0.1:8443"),
            tls: Some(ClusterTls {
                ca: Some(praxis_tls::CaConfig {
                    ca_path: ca_path.to_owned(),
                }),
                sni: Some("api.example.com".to_owned()),
                ..ClusterTls::default()
            }),
            connection: Arc::new(ConnectionOptions::default()),
        };
        let peer = build_peer(&upstream).expect("should build peer with custom CA");
        assert!(peer.options.ca.is_some(), "peer should have custom CA set");
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// Create a test upstream with the given address.
    fn make_upstream(address: &str) -> Upstream {
        Upstream {
            address: Arc::from(address),
            tls: None,
            connection: Arc::new(ConnectionOptions::default()),
        }
    }

    /// Generated CA certificate file with temp dir lifetime.
    struct TestCa {
        /// Path to the CA certificate PEM file.
        ca_path: std::path::PathBuf,

        /// Temp directory holding the cert file.
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
}
