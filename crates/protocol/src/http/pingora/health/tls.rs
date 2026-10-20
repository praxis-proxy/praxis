// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Pingora transport for TLS and HTTPS health probes.

use std::{net::Ipv6Addr, sync::Arc, time::Duration};

use pingora_core::tls::TlsConnector;
use praxis_core::{
    config::{Cluster, HealthCheckType, UpstreamAuthority, UpstreamHttpVersion},
    connectivity::peer::tls_server_name,
};
use praxis_tls::{CachedCaCerts, CachedClusterTls};
use tokio::io::AsyncWriteExt as _;

/// Configured certificate-verification exception using rustls signature checks.
mod verify;

/// TLS material and application settings for one health-check generation.
pub(super) struct TlsProbe {
    /// HTTP authority policy, independent of certificate verification names.
    authority: Option<UpstreamAuthority>,
    /// Cached TLS configuration with session resumption disabled.
    connector: TlsConnector,
    /// Optional HTTPS path and expected status; absent for handshake probes.
    http: Option<(String, u16)>,
    /// Validated cluster certificate material.
    tls: CachedClusterTls,
}

impl TlsProbe {
    /// Cache cluster settings, failing closed if certificate files cannot load.
    pub(super) fn new(cluster: &Cluster, upstream_ca: Option<&CachedCaCerts>) -> Result<Self, String> {
        let tls = cached_tls(cluster)?;
        let http = cluster
            .health_check
            .as_ref()
            .filter(|hc| hc.check_type == HealthCheckType::Http)
            .map(|hc| (hc.path.clone(), hc.expected_status));
        Ok(Self {
            authority: cluster.http.authority.clone(),
            connector: build_connector(
                &tls,
                upstream_ca,
                if http.is_some() {
                    UpstreamHttpVersion::H1
                } else {
                    cluster.http.version
                },
            )?,
            http,
            tls,
        })
    }

    /// Probe under one deadline for DNS, connection, handshake, HTTP and close.
    pub(super) async fn probe(&self, address: &str, timeout: Duration) -> bool {
        match tokio::time::timeout(timeout, self.exchange(address)).await {
            Ok(Ok(healthy)) => healthy,
            Ok(Err(error)) => {
                tracing::debug!(address, %error, "TLS health probe failed");
                false
            },
            Err(_) => {
                tracing::debug!(address, "TLS health probe timed out");
                false
            },
        }
    }

    /// Exchange over a new connection with session resumption disabled.
    async fn exchange(&self, address: &str) -> Result<bool, String> {
        let name = tls_server_name(&self.tls, address).map_err(|error| error.to_string())?;
        let mut stream = self.connect(address, name.clone()).await?;
        let healthy = if let Some((path, expected)) = &self.http {
            let host = self.host(address, &name)?;
            let request = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
            super::probe::http_exchange(&mut stream, address, &request, *expected).await
        } else {
            true
        };
        Ok(finish_probe(&mut stream, address, healthy).await)
    }

    /// Connect with the upstream resolver and a full, non-resumed handshake.
    async fn connect(
        &self,
        address: &str,
        name: String,
    ) -> Result<pingora_core::tls::ClientTlsStream<tokio::net::TcpStream>, String> {
        let socket = praxis_core::connectivity::peer::resolve_address(address)
            .await
            .map_err(|error| error.to_string())?;
        let stream = tokio::net::TcpStream::connect(socket)
            .await
            .map_err(|error| error.to_string())?;
        let name = rustls::pki_types::ServerName::try_from(name).map_err(|error| error.to_string())?;
        self.connector
            .connect(name, stream)
            .await
            .map_err(|error| error.to_string())
    }

    /// Select an HTTP Host from configured authority, SNI, or the endpoint.
    fn host(&self, address: &str, name: &str) -> Result<String, String> {
        let host = match &self.authority {
            Some(UpstreamAuthority::Literal(authority)) => authority.to_string(),
            None if self.tls.sni().is_some() => bracket_ipv6(name),
            Some(UpstreamAuthority::Derived { .. }) | None => endpoint_authority(address)?,
        };
        http::header::HeaderValue::from_str(&host).map_err(|error| error.to_string())?;
        Ok(host)
    }
}

/// Preserve the probe verdict when the peer already closed its connection.
async fn finish_probe<Stream: tokio::io::AsyncWrite + Unpin>(
    stream: &mut Stream,
    address: &str,
    healthy: bool,
) -> bool {
    if let Err(error) = stream.shutdown().await {
        tracing::trace!(address, %error, "TLS health probe close_notify failed");
    }
    healthy
}

/// Resolve the fixed authority fallback without overriding explicit SNI.
fn cached_tls(cluster: &Cluster) -> Result<CachedClusterTls, String> {
    let config = cluster.tls.as_ref().ok_or("TLS probe requires cluster.tls")?;
    let mut tls = CachedClusterTls::try_from_config(config).map_err(|error| error.to_string())?;
    if tls.sni().is_none()
        && let Some(authority) = cluster.http.authority.as_ref().and_then(UpstreamAuthority::literal)
    {
        let parsed: http::uri::Authority = authority
            .parse()
            .map_err(|error: http::uri::InvalidUri| error.to_string())?;
        tls.set_sni(praxis_core::connectivity::peer::derive_sni(&format!(
            "{}:443",
            parsed.host()
        )));
    }
    Ok(tls)
}

/// Configure rustls with cached replacement trust and no TLS session resumption.
fn build_connector(
    tls: &CachedClusterTls,
    runtime_ca: Option<&CachedCaCerts>,
    version: UpstreamHttpVersion,
) -> Result<TlsConnector, String> {
    let roots = Arc::new(trust_store(tls.ca().map(AsRef::as_ref).or(runtime_ca))?);
    let provider = rustls::crypto::CryptoProvider::get_default()
        .cloned()
        .ok_or("TLS crypto provider is not installed")?;
    let mut config = client_config(tls, roots, provider)?;
    config.require_ems = true;
    config.resumption = rustls::client::Resumption::disabled();
    config.alpn_protocols = match version {
        UpstreamHttpVersion::H1 => vec![b"http/1.1".to_vec()],
        UpstreamHttpVersion::H2 => vec![b"h2".to_vec()],
        UpstreamHttpVersion::Auto => vec![b"h2".to_vec(), b"http/1.1".to_vec()],
    };
    if praxis_tls::provider::required() && !config.fips() {
        return Err("TLS health probe configuration does not meet required FIPS policy".to_owned());
    }
    Ok(TlsConnector::from(Arc::new(config)))
}

/// Configure trusted server identities and optional client authentication.
fn client_config(
    tls: &CachedClusterTls,
    roots: Arc<rustls::RootCertStore>,
    provider: Arc<rustls::crypto::CryptoProvider>,
) -> Result<rustls::ClientConfig, String> {
    let builder = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&rustls::version::TLS12, &rustls::version::TLS13])
        .map_err(|error| error.to_string())?
        .with_root_certificates(Arc::clone(&roots));
    let mut config = match tls.client_cert() {
        Some(client) => builder
            .with_client_auth_cert(
                client
                    .cert_der()
                    .iter()
                    .cloned()
                    .map(rustls::pki_types::CertificateDer::from)
                    .collect(),
                rustls::pki_types::PrivateKeyDer::try_from(client.key_der().to_vec()).map_err(str::to_owned)?,
            )
            .map_err(|error| error.to_string())?,
        None => builder.with_no_client_auth(),
    };
    if !tls.verify() {
        skip_identity_verification(&mut config, roots, provider)?;
    }
    Ok(config)
}

/// Apply the explicit verification exception without bypassing signatures.
fn skip_identity_verification(
    config: &mut rustls::ClientConfig,
    roots: Arc<rustls::RootCertStore>,
    provider: Arc<rustls::crypto::CryptoProvider>,
) -> Result<(), String> {
    let delegate = rustls::client::WebPkiServerVerifier::builder_with_provider(roots, provider)
        .build()
        .map_err(|error| error.to_string())?;
    config
        .dangerous()
        .set_certificate_verifier(Arc::new(verify::SkipServerIdentity::new(delegate)));
    Ok(())
}

/// Use cluster/runtime roots exclusively, loading system trust only when absent.
fn trust_store(ca: Option<&CachedCaCerts>) -> Result<rustls::RootCertStore, String> {
    let mut roots = rustls::RootCertStore::empty();
    if let Some(ca) = ca {
        for der in ca.der_certs() {
            roots
                .add(rustls::pki_types::CertificateDer::from(der.clone()))
                .map_err(|error| error.to_string())?;
        }
    } else {
        pingora_core::tls::load_platform_certs_incl_env_into_store(&mut roots).map_err(|error| error.to_string())?;
    }
    Ok(roots)
}

/// Format an endpoint authority, omitting HTTPS's default port.
fn endpoint_authority(address: &str) -> Result<String, String> {
    let (host, port) = address.rsplit_once(':').ok_or("health endpoint requires host:port")?;
    let port: u16 = port
        .parse()
        .map_err(|error: std::num::ParseIntError| error.to_string())?;
    let host = bracket_ipv6(host);
    let authority = if port == 443 { host } else { format!("{host}:{port}") };
    authority
        .parse::<http::uri::Authority>()
        .map_err(|error| error.to_string())?;
    Ok(authority)
}

/// Bracket a bare IPv6 address for use in HTTP Host.
fn bracket_ipv6(host: &str) -> String {
    host.parse::<Ipv6Addr>()
        .map_or_else(|_| host.to_owned(), |ip| format!("[{ip}]"))
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::{
        pin::Pin,
        task::{Context, Poll},
    };

    use super::*;

    #[tokio::test]
    async fn failed_shutdown_preserves_successful_and_failed_probe_verdicts() {
        for healthy in [true, false] {
            assert_eq!(
                finish_probe(&mut FailedShutdown, "example.com:443", healthy).await,
                healthy,
                "a peer closing the connection must not replace the probe verdict"
            );
        }
    }

    #[test]
    fn tls_config_preserves_ems_and_alpn_policy() -> Result<(), Box<dyn std::error::Error>> {
        praxis_tls::provider::install();
        let tls = CachedClusterTls::try_from_config(&praxis_tls::ClusterTls::default())?;
        for (version, protocols) in [
            (UpstreamHttpVersion::H1, vec![b"http/1.1".to_vec()]),
            (UpstreamHttpVersion::H2, vec![b"h2".to_vec()]),
            (UpstreamHttpVersion::Auto, vec![b"h2".to_vec(), b"http/1.1".to_vec()]),
        ] {
            let connector = build_connector(&tls, None, version)?;
            assert!(
                connector.config().require_ems,
                "TLS 1.2 must require Extended Master Secret like upstream connections"
            );
            assert_eq!(
                connector.config().alpn_protocols,
                protocols,
                "ALPN follows the configured HTTP version"
            );
        }
        Ok(())
    }

    #[test]
    fn ipv6_authorities_preserve_brackets_and_nondefault_ports() -> Result<(), String> {
        assert_eq!(
            endpoint_authority("[::1]:443")?,
            "[::1]",
            "HTTPS default port is omitted"
        );
        assert_eq!(
            endpoint_authority("::1:8443")?,
            "[::1]:8443",
            "bare IPv6 endpoint gets brackets"
        );
        assert_eq!(bracket_ipv6("::1"), "[::1]", "IPv6 SNI used as Host must be bracketed");
        Ok(())
    }

    #[test]
    fn empty_server_name_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
        praxis_tls::provider::install();
        let cluster: Cluster = serde_yaml::from_str(
            "name: secure\nendpoints: ['example.com:443']\ntls: { sni: example.com }\nhealth_check: { type: tls }",
        )?;
        let mut probe = TlsProbe::new(&cluster, None)?;
        probe.tls.set_sni("");
        assert!(
            tls_server_name(&probe.tls, "example.com:443").is_err(),
            "empty SNI cannot disable certificate verification"
        );
        Ok(())
    }

    /// A peer that accepts writes but has closed before shutdown.
    struct FailedShutdown;

    impl tokio::io::AsyncWrite for FailedShutdown {
        fn poll_write(self: Pin<&mut Self>, _context: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()))
        }
    }
}
