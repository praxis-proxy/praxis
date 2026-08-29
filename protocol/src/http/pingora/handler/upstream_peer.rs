// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Upstream peer selection: converts the filter pipeline's [`Upstream`] into a Pingora `HttpPeer`.
//!
//! [`Upstream`]: praxis_core::connectivity::Upstream

use std::{
    net::SocketAddr,
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};

use pingora_core::{Result, upstreams::peer::HttpPeer};
use praxis_core::connectivity::{Upstream, peer as peer_utils};
use tracing::debug;

use super::super::context::PingoraRequestCtx;

// -----------------------------------------------------------------------------
// Test hooks
// -----------------------------------------------------------------------------

/// Test-only: when armed, upstream connect retries park until released.
static UPSTREAM_RETRY_GATE_ARMED: AtomicBool = AtomicBool::new(false);
/// Park mutex for the test retry gate.
static UPSTREAM_RETRY_GATE_PARK: Mutex<()> = Mutex::new(());
/// Condvar for the test retry gate.
static UPSTREAM_RETRY_GATE_CV: Condvar = Condvar::new();
/// Serializes tests that arm the retry gate.
static UPSTREAM_RETRY_GATE_TEST_LOCK: Mutex<()> = Mutex::new(());

/// Serializes integration tests that arm the upstream retry gate.
///
/// # Panics
///
/// Panics if the lock mutex is poisoned.
#[doc(hidden)]
pub fn lock_upstream_retry_gate_tests() -> std::sync::MutexGuard<'static, ()> {
    #[expect(clippy::expect_used, reason = "poisoned mutex is unrecoverable")]
    UPSTREAM_RETRY_GATE_TEST_LOCK
        .lock()
        .expect("upstream retry gate test lock")
}

/// Releases an armed upstream-retry wait (see [`arm_upstream_retry_gate`]).
///
/// The gate clears automatically on drop.
#[doc(hidden)]
pub struct UpstreamRetryGateRelease;

impl Drop for UpstreamRetryGateRelease {
    fn drop(&mut self) {
        clear_upstream_retry_gate_wait();
    }
}

/// Clear the armed flag and wake parked retries.
fn clear_upstream_retry_gate_wait() {
    UPSTREAM_RETRY_GATE_ARMED.store(false, Ordering::SeqCst);
    UPSTREAM_RETRY_GATE_CV.notify_all();
}

/// Arm the test gate that blocks upstream connect retries until released.
///
/// # Panics
///
/// Panics if the test-lock mutex is poisoned.
#[doc(hidden)]
pub fn arm_upstream_retry_gate() -> (std::sync::MutexGuard<'static, ()>, UpstreamRetryGateRelease) {
    let guard = lock_upstream_retry_gate_tests();
    UPSTREAM_RETRY_GATE_ARMED.store(true, Ordering::SeqCst);
    (guard, UpstreamRetryGateRelease)
}

// -----------------------------------------------------------------------------
// Execution/Conversion
// -----------------------------------------------------------------------------

/// Convert the pipeline's upstream selection into a Pingora `HttpPeer`.
///
/// On the first call, moves the upstream from `ctx.upstream` into
/// `ctx.upstream_for_retry` and borrows it. On retries with
/// `reselect_on_retry`, asks the `EndpointReselector` for an
/// alternate host (after applying any pending backoff).
#[expect(clippy::too_many_lines, reason = "retry orchestration reads clearer as one function")]
pub(super) async fn execute(ctx: &mut PingoraRequestCtx) -> Result<Box<HttpPeer>> {
    if ctx.retries > 0 && UPSTREAM_RETRY_GATE_ARMED.load(Ordering::SeqCst) {
        #[expect(clippy::expect_used, reason = "poisoned mutex/condvar is unrecoverable")]
        {
            let mut park = UPSTREAM_RETRY_GATE_PARK.lock().expect("upstream retry gate park lock");
            while UPSTREAM_RETRY_GATE_ARMED.load(Ordering::SeqCst) {
                park = UPSTREAM_RETRY_GATE_CV.wait(park).expect("upstream retry gate wait");
            }
            drop(park);
        }
    }

    if let Some(backoff) = ctx.pending_backoff.take()
        && !backoff.is_zero()
    {
        debug!(?backoff, "applying retry backoff");
        tokio::time::sleep(backoff).await;
    }

    if ctx.reselect_on_retry {
        ctx.reselect_on_retry = false;
        if let Some(reselector) = ctx.endpoint_reselector.clone() {
            let health = ctx
                .pinned_pipeline
                .as_ref()
                .and_then(|p| p.health_registry())
                .and_then(|reg| ctx.cluster.as_deref().and_then(|c| reg.get(c)));
            if let Some(addr) = reselector.select_address(health, &ctx.attempted_endpoints) {
                debug!(upstream = %addr, "selected alternate host for retry");
                if let Some(prev) = ctx.upstream_for_retry.as_ref() {
                    reselector.release(&prev.address);
                }
                if !ctx.attempted_endpoints.iter().any(|e| e.as_ref() == addr.as_ref()) {
                    ctx.attempted_endpoints.push(Arc::clone(&addr));
                }
                ctx.selected_endpoint_index = Some(reselected_endpoint_index(health, &addr));
                let mut upstream = reselector.build_upstream(addr);
                apply_per_try_timeout(ctx, &mut upstream);
                ctx.upstream_for_retry = Some(upstream);
            } else {
                debug!("no alternate host available; reusing previous upstream if present");
            }
        }
    }

    ctx.upstream_connect_start = Some(Instant::now());

    if ctx.upstream_for_retry.is_none() {
        let mut upstream = ctx.upstream.take();
        if let Some(ref mut u) = upstream {
            apply_per_try_timeout(ctx, u);
        }
        ctx.upstream_for_retry = upstream;
    }

    let upstream = ctx.upstream_for_retry.as_ref().ok_or_else(|| {
        let cluster = &ctx.cluster;
        pingora_core::Error::explain(
            pingora_core::ErrorType::InternalError,
            format!("no upstream selected (cluster: {cluster:?}); is a load_balancer configured?"),
        )
    })?;

    build_peer(upstream).await
}

/// Resolve the passive-health endpoint index for a reselected address.
///
/// Passive health records the final attempt's outcome against
/// `selected_endpoint_index`, so after reselection it must name the endpoint
/// that actually served the request, not the originally selected one.
/// Mirrors the `load_balancer`'s initial selection: `usize::MAX` (address not
/// in the registry) makes `record_passive_health` a no-op rather than
/// crediting or faulting the wrong index.
fn reselected_endpoint_index(health: Option<&praxis_core::health::ClusterHealthState>, addr: &str) -> usize {
    health.and_then(|h| h.endpoint_index(addr)).unwrap_or(usize::MAX)
}

/// Override connection/read timeouts with the policy's per-try timeout when set.
fn apply_per_try_timeout(ctx: &PingoraRequestCtx, upstream: &mut Upstream) {
    let Some(policy) = ctx.retry_policy.as_ref() else {
        return;
    };
    let Some(per_try_ms) = policy.per_try_timeout_ms else {
        return;
    };
    let opts = Arc::make_mut(&mut upstream.connection);
    let timeout = std::time::Duration::from_millis(per_try_ms);
    opts.connection_timeout = Some(timeout);
    opts.total_connection_timeout = Some(timeout);
    opts.read_timeout = Some(timeout);
    opts.write_timeout = Some(timeout);
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
async fn build_peer(upstream: &Upstream) -> Result<Box<HttpPeer>> {
    let addr: SocketAddr = resolve_address(&upstream.address).await?;

    let tls_enabled = upstream.tls.is_some();
    let sni = upstream
        .tls
        .as_ref()
        .and_then(|t| t.sni().map(str::to_owned))
        .unwrap_or_else(|| {
            if tls_enabled {
                peer_utils::derive_sni(&upstream.address)
            } else {
                String::new()
            }
        });

    let mut peer = HttpPeer::new(addr, tls_enabled, sni);
    peer_utils::apply_connection_options(&mut peer, &upstream.connection);

    if let Some(tls) = &upstream.tls {
        peer_utils::apply_cached_tls(&mut peer, tls, &upstream.address);
    }

    Ok(Box::new(peer))
}

// -----------------------------------------------------------------------------
// Resolution
// -----------------------------------------------------------------------------

/// Resolve an upstream address to a [`SocketAddr`] with caching.
///
/// Tries direct [`SocketAddr`] parsing first (no allocation, no I/O).
/// For hostname addresses, checks a process-wide cache (60 s TTL)
/// before falling back to DNS via [`spawn_blocking`].
///
/// When DNS returns multiple records, prefers IPv4 to avoid
/// connectivity issues in dual-stack environments.
///
/// [`SocketAddr`]: std::net::SocketAddr
/// [`spawn_blocking`]: tokio::task::spawn_blocking
async fn resolve_address(address: &str) -> Result<SocketAddr> {
    peer_utils::resolve_address(address)
        .await
        .map_err(|error| pingora_core::Error::explain(pingora_core::ErrorType::InternalError, error.to_string()))
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::field_reassign_with_default,
    clippy::too_many_lines,
    clippy::significant_drop_tightening,
    clippy::print_stderr,
    reason = "tests"
)]
mod tests {
    use praxis_core::connectivity::ConnectionOptions;
    use praxis_tls::{CachedClusterTls, ClusterTls};

    use super::*;

    #[tokio::test]
    async fn valid_address_builds_peer() {
        assert!(
            build_peer(&make_upstream("127.0.0.1:8080")).await.is_ok(),
            "valid address should build peer"
        );
    }

    #[tokio::test]
    async fn build_peer_with_tls_enabled() {
        let tls = ClusterTls {
            sni: Some("api.example.com".to_owned()),
            ..ClusterTls::default()
        };
        let upstream = Upstream {
            address: Arc::from("127.0.0.1:8443"),
            authority: None,
            connection: Arc::new(ConnectionOptions::default()),
            tls: Some(CachedClusterTls::try_from_config(&tls).unwrap()),
        };
        let peer = build_peer(&upstream).await.expect("should build TLS peer");
        assert!(!peer.sni.is_empty(), "TLS peer should have a non-empty SNI");
        assert_eq!(peer.sni, "api.example.com", "peer SNI should match configured value");
    }

    #[test]
    fn sni_not_set_with_hostname_address_derives_sni() {
        let sni = peer_utils::derive_sni("backend.example.com:8443");
        assert_eq!(
            sni, "backend.example.com",
            "SNI should be derived from hostname address"
        );
    }

    #[test]
    fn sni_not_set_with_ip_address_leaves_sni_empty() {
        let sni = peer_utils::derive_sni("127.0.0.1:8443");
        assert_eq!(sni, "", "SNI should be empty for IP address");
    }

    #[tokio::test]
    async fn build_peer_without_tls() {
        let upstream = Upstream {
            address: Arc::from("127.0.0.1:8080"),
            authority: None,
            connection: Arc::new(ConnectionOptions::default()),
            tls: None,
        };
        let peer = build_peer(&upstream).await.expect("should build plain peer");
        assert_eq!(peer.sni, "", "plain peer should have empty SNI");
    }

    #[tokio::test]
    async fn build_peer_with_tls_verify_disabled() {
        let tls = ClusterTls {
            sni: Some("self-signed.local".to_owned()),
            verify: false,
            ..ClusterTls::default()
        };
        let upstream = Upstream {
            address: Arc::from("127.0.0.1:8443"),
            authority: None,
            connection: Arc::new(ConnectionOptions::default()),
            tls: Some(CachedClusterTls::try_from_config(&tls).unwrap()),
        };
        let peer = build_peer(&upstream)
            .await
            .expect("should build peer with verification disabled");
        assert!(
            !peer.options.verify_cert,
            "verify_cert should be false when verify is disabled"
        );
        assert!(
            !peer.options.verify_hostname,
            "verify_hostname should be false when verify is disabled"
        );
    }

    #[tokio::test]
    async fn build_peer_with_tls_verify_enabled() {
        let tls = ClusterTls {
            sni: Some("api.example.com".to_owned()),
            ..ClusterTls::default()
        };
        let upstream = Upstream {
            address: Arc::from("127.0.0.1:8443"),
            authority: None,
            connection: Arc::new(ConnectionOptions::default()),
            tls: Some(CachedClusterTls::try_from_config(&tls).unwrap()),
        };
        let peer = build_peer(&upstream)
            .await
            .expect("should build peer with verification enabled");
        assert!(
            peer.options.verify_cert,
            "verify_cert should be true (default) when verify is enabled"
        );
        assert!(
            peer.options.verify_hostname,
            "verify_hostname should be true (default) when verify is enabled"
        );
    }

    #[tokio::test]
    async fn resolve_address_parses_socket_addr() {
        let addr = resolve_address("127.0.0.1:8080")
            .await
            .expect("socket addr should parse");
        assert_eq!(addr.port(), 8080, "port should match");
    }

    #[tokio::test]
    async fn resolve_address_resolves_localhost() {
        if !localhost_resolution_available() {
            eprintln!("skipping: localhost did not resolve in this environment");
            return;
        }
        let addr = resolve_address("localhost:8080")
            .await
            .expect("localhost should resolve");
        assert_eq!(addr.port(), 8080, "port should match");
    }

    #[tokio::test]
    async fn resolve_address_fails_for_no_port() {
        assert!(
            resolve_address("127.0.0.1").await.is_err(),
            "address without port should return error"
        );
    }

    #[tokio::test]
    async fn hostname_address_builds_peer() {
        if !localhost_resolution_available() {
            eprintln!("skipping: localhost did not resolve in this environment");
            return;
        }
        assert!(
            build_peer(&make_upstream("localhost:8080")).await.is_ok(),
            "hostname address should build peer via DNS resolution"
        );
    }

    #[tokio::test]
    async fn invalid_address_returns_error() {
        assert!(
            build_peer(&make_upstream("invalid host:8080")).await.is_err(),
            "syntactically invalid address should return error"
        );
    }

    #[tokio::test]
    async fn missing_port_returns_error() {
        assert!(
            build_peer(&make_upstream("127.0.0.1")).await.is_err(),
            "address without port should return error"
        );
    }

    #[test]
    fn reselected_endpoint_index_points_at_new_address() {
        use praxis_core::health::{ClusterHealthEntry, ClusterHealthState, EndpointHealth};

        let entry = ClusterHealthEntry::new(
            vec![EndpointHealth::default(), EndpointHealth::default()],
            vec![Arc::from("127.0.0.1:3001"), Arc::from("127.0.0.1:3002")],
            Some(3),
            Some(2),
        );
        let health: ClusterHealthState = Arc::new(entry);

        // A reselection to the second endpoint must re-point the
        // passive-health index at it, or the final outcome is
        // credited/faulted against the originally selected endpoint.
        assert_eq!(
            reselected_endpoint_index(Some(&health), "127.0.0.1:3002"),
            1,
            "reselection must resolve the reselected address's index"
        );

        // An address the registry does not know maps to usize::MAX, which
        // makes record_passive_health a no-op instead of a wrong attribution.
        assert_eq!(
            reselected_endpoint_index(Some(&health), "10.0.0.9:9999"),
            usize::MAX,
            "unknown address is a no-op index"
        );

        // No registry at all also degrades to the no-op index.
        assert_eq!(
            reselected_endpoint_index(None, "127.0.0.1:3001"),
            usize::MAX,
            "missing registry is a no-op index"
        );
    }

    #[tokio::test]
    async fn execute_first_call_moves_upstream_to_retry() {
        let mut ctx = PingoraRequestCtx::default();
        ctx.upstream = Some(make_upstream("127.0.0.1:8080"));
        let result = execute(&mut ctx).await;
        assert!(result.is_ok(), "first execute should succeed");
        assert!(ctx.upstream.is_none(), "upstream should be consumed");
        assert!(ctx.upstream_for_retry.is_some(), "should save for retry");
        assert_eq!(
            &*ctx.upstream_for_retry.as_ref().unwrap().address,
            "127.0.0.1:8080",
            "saved retry address should match original"
        );
    }

    #[tokio::test]
    async fn execute_retry_reuses_saved_upstream() {
        let mut ctx = PingoraRequestCtx::default();
        ctx.upstream = None;
        ctx.upstream_for_retry = Some(make_upstream("127.0.0.1:9090"));
        let result = execute(&mut ctx).await;
        assert!(result.is_ok(), "retry execute should succeed");
        assert!(
            ctx.upstream_for_retry.is_some(),
            "retry upstream should remain for further retries"
        );
    }

    #[tokio::test]
    async fn execute_no_upstream_no_retry_returns_error() {
        let mut ctx = PingoraRequestCtx::default();
        ctx.upstream = None;
        ctx.upstream_for_retry = None;
        let result = execute(&mut ctx).await;
        assert!(result.is_err(), "execute with no upstream should return error");
        let err = result.unwrap_err().to_string();
        assert!(err.contains("no upstream selected"), "unexpected error message: {err}");
        assert!(
            err.contains("is a load_balancer configured?"),
            "error should mention load_balancer: {err}"
        );
    }

    #[tokio::test]
    async fn execute_no_upstream_error_includes_cluster_name() {
        let mut ctx = PingoraRequestCtx::default();
        ctx.cluster = Some(Arc::from("my-api"));
        ctx.upstream = None;
        ctx.upstream_for_retry = None;
        let result = execute(&mut ctx).await;
        assert!(result.is_err(), "execute with no upstream should return error");
        let err = result.unwrap_err().to_string();
        assert!(err.contains("my-api"), "error should include cluster name: {err}");
    }

    #[tokio::test]
    async fn build_peer_with_cached_ca() {
        let ca = gen_ca_file();
        let ca_path = ca.ca_path.to_str().expect("ca path should be valid UTF-8");

        let tls = ClusterTls {
            ca: Some(praxis_tls::CaConfig {
                ca_path: ca_path.to_owned(),
                crl_paths: Vec::new(),
            }),
            sni: Some("api.example.com".to_owned()),
            ..ClusterTls::default()
        };
        let upstream = Upstream {
            address: Arc::from("127.0.0.1:8443"),
            authority: None,
            connection: Arc::new(ConnectionOptions::default()),
            tls: Some(CachedClusterTls::try_from_config(&tls).unwrap()),
        };
        let peer = build_peer(&upstream).await.expect("should build peer with cached CA");
        assert!(peer.options.ca.is_some(), "peer should have custom CA set from cache");
    }

    #[test]
    fn ca_from_cached_produces_wrapped_x509() {
        let ca = gen_ca_file();
        let ca_path = ca.ca_path.to_str().expect("ca path should be valid UTF-8");

        let cached = praxis_tls::CachedCaCerts::from_pem_file(ca_path).expect("valid CA should parse");
        let wrapped = peer_utils::ca_from_cached(&cached);
        assert_eq!(wrapped.len(), 1, "should produce one WrappedX509");
    }

    #[test]
    fn client_cert_from_cached_produces_cert_key() {
        let pair = gen_cert_key_files();
        let cert_path = pair.cert_path.to_str().expect("cert path should be valid UTF-8");
        let key_path = pair.key_path.to_str().expect("key path should be valid UTF-8");

        let cached =
            praxis_tls::CachedClientCert::from_pem_files(cert_path, key_path).expect("valid cert+key should parse");
        let _cert_key = peer_utils::client_cert_from_cached(&cached);
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// Check whether `localhost` DNS resolution is available in this environment.
    fn localhost_resolution_available() -> bool {
        use std::net::ToSocketAddrs as _;
        "localhost:8080"
            .to_socket_addrs()
            .is_ok_and(|mut addrs| addrs.next().is_some())
    }

    /// Create a test upstream with the given address (no TLS).
    fn make_upstream(address: &str) -> Upstream {
        Upstream {
            address: Arc::from(address),
            authority: None,
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
