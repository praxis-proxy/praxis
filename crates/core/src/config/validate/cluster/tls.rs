// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! TLS settings and SNI hostname validation for clusters.

use tracing::warn;

use super::health_check::extract_host;
use crate::{
    config::{Cluster, Endpoint, InsecureOptions, UpstreamAuthority},
    connectivity::peer::is_ip_literal,
    errors::ProxyError,
};

// -----------------------------------------------------------------------------
// TLS Settings Validation
// -----------------------------------------------------------------------------

/// Validate cluster TLS settings: SNI presence, verify flag, path traversal.
///
/// Path traversal validation is handled by `ClusterTls` during deserialization,
/// but SNI-without-verify checks are done here since they depend on
/// [`InsecureOptions`].
///
/// [`InsecureOptions`]: crate::config::InsecureOptions
pub(super) fn validate_tls_settings(cluster: &Cluster, insecure_options: &InsecureOptions) -> Result<(), ProxyError> {
    let Some(tls) = &cluster.tls else {
        return Ok(());
    };

    if let Some(sni) = &tls.sni {
        praxis_tls::validate_sni_name(sni)
            .map_err(|err| ProxyError::Config(format!("cluster '{}': sni {err}", cluster.name)))?;
    }

    let sni = if tls.sni.is_some() {
        SniSource::Configured
    } else {
        endpoint_sni(cluster)
    };
    check_sni_verify_requirement(sni, tls.verify, &cluster.name, insecure_options)?;
    check_no_verify_requirement(tls.verify, &cluster.name, insecure_options)?;
    check_no_upstream_crls(tls.ca.as_ref(), &cluster.name)?;

    Ok(())
}

/// Where a TLS cluster's SNI comes from, as far as config validation can tell.
#[derive(Clone, Copy, Debug)]
enum SniSource<'cfg> {
    /// `tls.sni` is set.
    Configured,

    /// `authority: { from: endpoint }` with only hostname endpoints, so each
    /// attempt names its own endpoint.
    Endpoint,

    /// `authority: { from: endpoint }`, but this endpoint is an IP literal
    /// and has no name to send.
    IpEndpoint(&'cfg str),

    /// No SNI known at config time.
    Missing,
}

/// The SNI an endpoint-derived authority provides, or [`SniSource::Missing`]
/// for any other authority mode.
fn endpoint_sni(cluster: &Cluster) -> SniSource<'_> {
    if !cluster
        .http
        .authority
        .as_ref()
        .is_some_and(UpstreamAuthority::follows_endpoint)
    {
        return SniSource::Missing;
    }
    cluster
        .endpoints
        .iter()
        .map(Endpoint::address)
        .find(|address| is_ip_literal(extract_host(address)))
        .map_or(SniSource::Endpoint, SniSource::IpEndpoint)
}

/// Require SNI when verification is enabled, unless explicitly opted out.
fn check_sni_verify_requirement(
    sni: SniSource<'_>,
    verify: bool,
    cluster_name: &str,
    insecure_options: &InsecureOptions,
) -> Result<(), ProxyError> {
    let ip_endpoint = match sni {
        SniSource::Configured | SniSource::Endpoint => return Ok(()),
        SniSource::IpEndpoint(address) => Some(address),
        SniSource::Missing => None,
    };
    if !verify {
        return Ok(());
    }
    if insecure_options.allow_tls_without_sni {
        warn!(
            cluster = %cluster_name,
            "upstream TLS enabled without SNI; hostname verification will be degraded \
             (allowed by insecure_options.allow_tls_without_sni)"
        );
        return Ok(());
    }
    let reason = ip_endpoint.map_or_else(
        || "no sni configured".to_owned(),
        |address| {
            format!("no sni configured, and endpoint '{address}' is an IP address with no name to derive one from")
        },
    );
    Err(ProxyError::Config(format!(
        "cluster '{cluster_name}': upstream TLS with verification enabled but {reason}; \
         set tls.sni or set insecure_options.allow_tls_without_sni: true to allow degraded verification"
    )))
}

/// Reject `verify: false` unless explicitly opted in via [`InsecureOptions`].
///
/// [`InsecureOptions`]: crate::config::InsecureOptions
fn check_no_verify_requirement(
    verify: bool,
    cluster_name: &str,
    insecure_options: &InsecureOptions,
) -> Result<(), ProxyError> {
    if verify {
        return Ok(());
    }
    if insecure_options.allow_tls_no_verify {
        warn!(
            cluster = %cluster_name,
            "upstream TLS certificate verification is disabled \
             (allowed by insecure_options.allow_tls_no_verify)"
        );
        return Ok(());
    }
    Err(ProxyError::Config(format!(
        "cluster '{cluster_name}': upstream TLS certificate verification is disabled (verify: false); \
         set insecure_options.allow_tls_no_verify: true to allow this"
    )))
}

/// Reject `crl_paths` on a cluster CA.
///
/// CRL enforcement is implemented only for the listener-side client
/// verifier; on a cluster the field would be accepted and silently
/// ignored, giving a false sense of upstream revocation checking.
fn check_no_upstream_crls(ca: Option<&praxis_tls::CaConfig>, cluster_name: &str) -> Result<(), ProxyError> {
    if ca.is_some_and(|ca| !ca.crl_paths.is_empty()) {
        return Err(ProxyError::Config(format!(
            "cluster '{cluster_name}': tls.ca.crl_paths is not supported for upstream connections \
             (CRL checking is only available for listener client authentication); remove it"
        )));
    }
    Ok(())
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
    clippy::needless_raw_strings,
    clippy::needless_raw_string_hashes,
    reason = "tests use unwrap/expect/indexing/raw strings for brevity"
)]
mod tests {
    use praxis_tls::{CaConfig, ClusterTls};

    use super::super::validate_clusters;
    use crate::config::{AuthoritySource, Cluster, ClusterHttpOptions, InsecureOptions, UpstreamAuthority};

    #[test]
    fn reject_empty_sni() {
        let clusters = vec![Cluster {
            tls: Some(ClusterTls {
                sni: Some(String::new()),
                ..ClusterTls::default()
            }),
            ..Cluster::with_defaults("web", vec!["10.0.0.1:443".into()])
        }];
        let err = validate_clusters(&clusters, &InsecureOptions::default()).unwrap_err();
        assert!(err.to_string().contains("empty"), "got: {err}");
    }

    #[test]
    fn reject_overlong_sni() {
        let long_sni = format!("{}.example.com", "a".repeat(250));
        let clusters = vec![Cluster {
            tls: Some(ClusterTls {
                sni: Some(long_sni),
                ..ClusterTls::default()
            }),
            ..Cluster::with_defaults("web", vec!["10.0.0.1:443".into()])
        }];
        let err = validate_clusters(&clusters, &InsecureOptions::default()).unwrap_err();
        assert!(err.to_string().contains("253"), "got: {err}");
    }

    #[test]
    fn reject_sni_with_invalid_chars() {
        let clusters = vec![Cluster {
            tls: Some(ClusterTls {
                sni: Some("api.exam ple.com".into()),
                ..ClusterTls::default()
            }),
            ..Cluster::with_defaults("web", vec!["10.0.0.1:443".into()])
        }];
        let err = validate_clusters(&clusters, &InsecureOptions::default()).unwrap_err();
        assert!(err.to_string().contains("invalid characters"), "got: {err}");
    }

    #[test]
    fn accept_valid_sni() {
        let clusters = vec![Cluster {
            tls: Some(ClusterTls {
                sni: Some("api.example.com".into()),
                ..ClusterTls::default()
            }),
            ..Cluster::with_defaults("web", vec!["10.0.0.1:443".into()])
        }];
        validate_clusters(&clusters, &InsecureOptions::default()).unwrap();
    }

    #[test]
    fn reject_sni_ipv4_address() {
        let clusters = vec![Cluster {
            tls: Some(ClusterTls {
                sni: Some("192.168.1.1".into()),
                ..ClusterTls::default()
            }),
            ..Cluster::with_defaults("web", vec!["10.0.0.1:443".into()])
        }];
        let err = validate_clusters(&clusters, &InsecureOptions::default()).unwrap_err();
        assert!(err.to_string().contains("IP address"), "got: {err}");
    }

    #[test]
    fn reject_sni_ipv4_loopback() {
        let clusters = vec![Cluster {
            tls: Some(ClusterTls {
                sni: Some("127.0.0.1".into()),
                ..ClusterTls::default()
            }),
            ..Cluster::with_defaults("web", vec!["10.0.0.1:443".into()])
        }];
        let err = validate_clusters(&clusters, &InsecureOptions::default()).unwrap_err();
        assert!(err.to_string().contains("IP address"), "got: {err}");
    }

    #[test]
    fn reject_sni_ipv6_loopback() {
        let clusters = vec![Cluster {
            tls: Some(ClusterTls {
                sni: Some("::1".into()),
                ..ClusterTls::default()
            }),
            ..Cluster::with_defaults("web", vec!["10.0.0.1:443".into()])
        }];
        let err = validate_clusters(&clusters, &InsecureOptions::default()).unwrap_err();
        assert!(err.to_string().contains("IP address"), "got: {err}");
    }

    #[test]
    fn reject_sni_ipv6_full() {
        let clusters = vec![Cluster {
            tls: Some(ClusterTls {
                sni: Some("2001:db8::1".into()),
                ..ClusterTls::default()
            }),
            ..Cluster::with_defaults("web", vec!["10.0.0.1:443".into()])
        }];
        let err = validate_clusters(&clusters, &InsecureOptions::default()).unwrap_err();
        assert!(err.to_string().contains("IP address"), "got: {err}");
    }

    #[test]
    fn reject_partial_wildcard_sni() {
        let clusters = vec![Cluster {
            tls: Some(ClusterTls {
                sni: Some("a*b.example.com".into()),
                ..ClusterTls::default()
            }),
            ..Cluster::with_defaults("web", vec!["10.0.0.1:443".into()])
        }];
        let err = validate_clusters(&clusters, &InsecureOptions::default()).unwrap_err();
        assert!(err.to_string().contains("wildcard"), "got: {err}");
    }

    #[test]
    fn reject_nested_wildcard_sni() {
        let clusters = vec![Cluster {
            tls: Some(ClusterTls {
                sni: Some("*.*.example.com".into()),
                ..ClusterTls::default()
            }),
            ..Cluster::with_defaults("web", vec!["10.0.0.1:443".into()])
        }];
        let err = validate_clusters(&clusters, &InsecureOptions::default()).unwrap_err();
        assert!(err.to_string().contains("wildcard"), "got: {err}");
    }

    #[test]
    fn reject_non_leftmost_wildcard_sni() {
        let clusters = vec![Cluster {
            tls: Some(ClusterTls {
                sni: Some("foo.*.example.com".into()),
                ..ClusterTls::default()
            }),
            ..Cluster::with_defaults("web", vec!["10.0.0.1:443".into()])
        }];
        let err = validate_clusters(&clusters, &InsecureOptions::default()).unwrap_err();
        assert!(err.to_string().contains("wildcard"), "got: {err}");
    }

    #[test]
    fn accept_wildcard_sni() {
        let clusters = vec![Cluster {
            tls: Some(ClusterTls {
                sni: Some("*.example.com".into()),
                ..ClusterTls::default()
            }),
            ..Cluster::with_defaults("web", vec!["10.0.0.1:443".into()])
        }];
        validate_clusters(&clusters, &InsecureOptions::default()).unwrap();
    }

    #[test]
    fn reject_sni_with_overlong_label() {
        let long_label = "a".repeat(64);
        let sni = format!("{long_label}.example.com");
        let clusters = vec![Cluster {
            tls: Some(ClusterTls {
                sni: Some(sni),
                ..ClusterTls::default()
            }),
            ..Cluster::with_defaults("web", vec!["10.0.0.1:443".into()])
        }];
        let err = validate_clusters(&clusters, &InsecureOptions::default()).unwrap_err();
        assert!(
            err.to_string().contains("label exceeds 63 characters"),
            "label >63 chars should be rejected: {err}"
        );
    }

    #[test]
    fn accept_sni_with_exact_63_char_label() {
        let label = "a".repeat(63);
        let sni = format!("{label}.example.com");
        let clusters = vec![Cluster {
            tls: Some(ClusterTls {
                sni: Some(sni),
                ..ClusterTls::default()
            }),
            ..Cluster::with_defaults("web", vec!["10.0.0.1:443".into()])
        }];
        validate_clusters(&clusters, &InsecureOptions::default()).expect("63-char label should be valid");
    }

    #[test]
    fn reject_sni_with_empty_label() {
        let clusters = vec![Cluster {
            tls: Some(ClusterTls {
                sni: Some("api..example.com".into()),
                ..ClusterTls::default()
            }),
            ..Cluster::with_defaults("web", vec!["10.0.0.1:443".into()])
        }];
        let err = validate_clusters(&clusters, &InsecureOptions::default()).unwrap_err();
        assert!(
            err.to_string().contains("label is empty"),
            "empty label (consecutive dots) should be rejected: {err}"
        );
    }

    #[test]
    fn reject_sni_with_underscore() {
        let clusters = vec![Cluster {
            tls: Some(ClusterTls {
                sni: Some("api_server.example.com".into()),
                ..ClusterTls::default()
            }),
            ..Cluster::with_defaults("web", vec!["10.0.0.1:443".into()])
        }];
        let err = validate_clusters(&clusters, &InsecureOptions::default()).unwrap_err();
        assert!(
            err.to_string().contains("invalid characters"),
            "underscore in SNI label should be rejected: {err}"
        );
    }

    #[test]
    fn accept_sni_with_hyphen() {
        let clusters = vec![Cluster {
            tls: Some(ClusterTls {
                sni: Some("api-server.example.com".into()),
                ..ClusterTls::default()
            }),
            ..Cluster::with_defaults("web", vec!["10.0.0.1:443".into()])
        }];
        validate_clusters(&clusters, &InsecureOptions::default()).expect("hyphen in SNI label should be valid");
    }

    #[test]
    fn reject_sni_at_254_chars() {
        let sni = format!(
            "{}.{}.{}.{}.com",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(63),
        );
        assert!(sni.len() > 253, "test SNI should exceed 253 chars");
        let clusters = vec![Cluster {
            tls: Some(ClusterTls {
                sni: Some(sni),
                ..ClusterTls::default()
            }),
            ..Cluster::with_defaults("web", vec!["10.0.0.1:443".into()])
        }];
        let err = validate_clusters(&clusters, &InsecureOptions::default()).unwrap_err();
        assert!(
            err.to_string().contains("253"),
            "SNI >253 chars should be rejected: {err}"
        );
    }

    #[test]
    fn reject_tls_without_sni() {
        let clusters = vec![Cluster {
            tls: Some(ClusterTls::default()),
            ..Cluster::with_defaults("web", vec!["10.0.0.1:443".into()])
        }];
        let err = validate_clusters(&clusters, &InsecureOptions::default()).unwrap_err();
        assert!(
            err.to_string().contains("no sni configured"),
            "should reject TLS+verify without SNI: {err}"
        );
    }

    #[test]
    fn allow_tls_without_sni_override() {
        let clusters = vec![Cluster {
            tls: Some(ClusterTls::default()),
            ..Cluster::with_defaults("web", vec!["10.0.0.1:443".into()])
        }];
        let opts = InsecureOptions {
            allow_tls_without_sni: true,
            ..InsecureOptions::default()
        };
        validate_clusters(&clusters, &opts).expect("allow_tls_without_sni should demote error to warning");
    }

    #[test]
    fn accept_verify_without_sni_when_authority_follows_hostname_endpoints() {
        let clusters = vec![endpoint_authority_cluster(&[
            "api-a.example.com:443",
            "api-b.example.com:443",
        ])];
        validate_clusters(&clusters, &InsecureOptions::default())
            .expect("each attempt can name its own hostname endpoint in SNI, so verify needs no tls.sni");
    }

    #[test]
    fn reject_verify_without_sni_when_authority_follows_an_ip_endpoint() {
        let clusters = vec![endpoint_authority_cluster(&["api-a.example.com:443", "10.0.0.2:443"])];
        let err = validate_clusters(&clusters, &InsecureOptions::default()).unwrap_err();
        assert!(
            err.to_string().contains("endpoint '10.0.0.2:443' is an IP address"),
            "an IP endpoint has no name to send as SNI, so the error should name it: {err}"
        );
    }

    #[test]
    fn reject_verify_without_sni_when_authority_follows_an_ipv6_endpoint() {
        let clusters = vec![endpoint_authority_cluster(&["[2001:db8::1]:443"])];
        let err = validate_clusters(&clusters, &InsecureOptions::default()).unwrap_err();
        assert!(
            err.to_string().contains("'[2001:db8::1]:443' is an IP address"),
            "a bracketed IPv6 endpoint has no name to send as SNI: {err}"
        );
    }

    #[test]
    fn allow_tls_without_sni_covers_an_ip_endpoint_with_endpoint_authority() {
        let clusters = vec![endpoint_authority_cluster(&["10.0.0.2:443"])];
        let opts = InsecureOptions {
            allow_tls_without_sni: true,
            ..InsecureOptions::default()
        };
        validate_clusters(&clusters, &opts).expect("allow_tls_without_sni should still demote the error");
    }

    #[test]
    fn reject_verify_without_sni_for_a_fixed_authority_with_hostname_endpoints() {
        let clusters = vec![Cluster {
            http: ClusterHttpOptions {
                authority: Some("api.example.com".into()),
                ..ClusterHttpOptions::default()
            },
            tls: Some(ClusterTls::default()),
            ..Cluster::with_defaults("web", vec!["api-a.example.com:443".into()])
        }];
        let err = validate_clusters(&clusters, &InsecureOptions::default()).unwrap_err();
        assert!(
            err.to_string().contains("no sni configured;"),
            "a fixed authority leaves SNI to the downstream Host, so tls.sni is still required: {err}"
        );
    }

    #[test]
    fn reject_tls_no_verify_without_insecure_option() {
        let clusters = vec![Cluster {
            tls: Some(ClusterTls {
                verify: false,
                ..ClusterTls::default()
            }),
            ..Cluster::with_defaults("web", vec!["10.0.0.1:443".into()])
        }];
        let err = validate_clusters(&clusters, &InsecureOptions::default()).unwrap_err();
        assert!(
            err.to_string().contains("verify: false"),
            "should reject verify: false without insecure option: {err}"
        );
        assert!(
            err.to_string().contains("allow_tls_no_verify"),
            "error should mention allow_tls_no_verify: {err}"
        );
    }

    #[test]
    fn allow_tls_no_verify_with_insecure_option() {
        let clusters = vec![Cluster {
            tls: Some(ClusterTls {
                verify: false,
                ..ClusterTls::default()
            }),
            ..Cluster::with_defaults("web", vec!["10.0.0.1:443".into()])
        }];
        let opts = InsecureOptions {
            allow_tls_no_verify: true,
            ..InsecureOptions::default()
        };
        validate_clusters(&clusters, &opts).expect("allow_tls_no_verify should demote error to warning");
    }

    #[test]
    fn tls_no_verify_not_blocked_by_sni_check() {
        let clusters = vec![Cluster {
            tls: Some(ClusterTls {
                verify: false,
                ..ClusterTls::default()
            }),
            ..Cluster::with_defaults("web", vec!["10.0.0.1:443".into()])
        }];
        let opts = InsecureOptions {
            allow_tls_no_verify: true,
            ..InsecureOptions::default()
        };
        validate_clusters(&clusters, &opts).expect("TLS without verify should not require SNI");
    }

    #[test]
    fn reject_cluster_crl_paths() {
        let clusters = vec![Cluster {
            tls: Some(ClusterTls {
                sni: Some("api.example.com".into()),
                ca: Some(CaConfig {
                    ca_path: "/etc/ssl/ca.pem".into(),
                    crl_paths: vec!["/etc/ssl/crl.pem".into()],
                }),
                ..ClusterTls::default()
            }),
            ..Cluster::with_defaults("web", vec!["10.0.0.1:443".into()])
        }];
        let err = validate_clusters(&clusters, &InsecureOptions::default()).unwrap_err();
        assert!(err.to_string().contains("crl_paths"), "got: {err}");
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// A verifying TLS cluster with no `tls.sni` whose `Host` follows the endpoint.
    fn endpoint_authority_cluster(endpoints: &[&str]) -> Cluster {
        Cluster {
            http: ClusterHttpOptions {
                authority: Some(UpstreamAuthority::Derived {
                    from: AuthoritySource::Endpoint,
                }),
                ..ClusterHttpOptions::default()
            },
            tls: Some(ClusterTls::default()),
            ..Cluster::with_defaults("web", endpoints.iter().map(|&address| address.into()).collect())
        }
    }
}
