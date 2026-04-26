// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! TLS settings and SNI hostname validation for clusters.

use tracing::warn;

use crate::{
    config::{Cluster, InsecureOptions},
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
    let Some(ref tls) = cluster.tls else {
        return Ok(());
    };

    if let Some(ref sni) = tls.sni {
        validate_sni(sni, &cluster.name)?;
    }

    if tls.sni.is_none() && tls.verify {
        if insecure_options.allow_tls_without_sni {
            warn!(
                cluster = %cluster.name,
                "upstream TLS enabled without SNI; hostname verification will be degraded \
                 (allowed by insecure_options.allow_tls_without_sni)"
            );
        } else {
            return Err(ProxyError::Config(format!(
                "cluster '{}': upstream TLS with verification enabled but no sni configured; \
                 set tls.sni or set insecure_options.allow_tls_without_sni: true to allow degraded verification",
                cluster.name
            )));
        }
    }

    if !tls.verify {
        warn!(
            cluster = %cluster.name,
            "upstream TLS certificate verification is disabled; use only in dev/test environments"
        );
    }

    Ok(())
}

// -----------------------------------------------------------------------------
// SNI Validation
// -----------------------------------------------------------------------------

/// Validates that an SNI hostname is a legal DNS name.
fn validate_sni(sni: &str, cluster_name: &str) -> Result<(), ProxyError> {
    validate_sni_length(sni, cluster_name)?;
    validate_sni_labels(sni, cluster_name)
}

/// Reject empty or overlong SNI hostnames.
fn validate_sni_length(sni: &str, cluster_name: &str) -> Result<(), ProxyError> {
    if sni.is_empty() {
        return Err(ProxyError::Config(format!("cluster '{cluster_name}': sni is empty")));
    }
    if sni.len() > 253 {
        return Err(ProxyError::Config(format!(
            "cluster '{cluster_name}': sni exceeds 253 characters"
        )));
    }
    Ok(())
}

/// Validate each DNS label in the SNI hostname.
///
/// Wildcard validation follows [RFC 6125]: `*` is only valid as
/// the complete leftmost label (e.g. `*.example.com`).
///
/// [RFC 6125]: https://datatracker.ietf.org/doc/html/rfc6125
fn validate_sni_labels(sni: &str, cluster_name: &str) -> Result<(), ProxyError> {
    for (i, label) in sni.split('.').enumerate() {
        if label.is_empty() || label.len() > 63 {
            return Err(ProxyError::Config(format!(
                "cluster '{cluster_name}': sni has invalid label length"
            )));
        }
        if label.contains('*') {
            if label != "*" || i != 0 {
                return Err(ProxyError::Config(format!(
                    "cluster '{cluster_name}': sni wildcard is only \
                     permitted as the complete leftmost label (e.g. *.example.com)"
                )));
            }
            continue;
        }
        if !label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
            return Err(ProxyError::Config(format!(
                "cluster '{cluster_name}': sni contains invalid characters"
            )));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(ProxyError::Config(format!(
                "cluster '{cluster_name}': sni label must not start or end with a hyphen"
            )));
        }
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::needless_raw_strings,
    clippy::needless_raw_string_hashes,
    reason = "tests use unwrap/expect/indexing/raw strings for brevity"
)]
mod tests {
    use praxis_tls::ClusterTls;

    use super::super::validate_clusters;
    use crate::config::{Cluster, InsecureOptions};

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
            err.to_string().contains("invalid label length"),
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
            err.to_string().contains("invalid label length"),
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
    fn tls_no_verify_not_blocked_by_sni_check() {
        let clusters = vec![Cluster {
            tls: Some(ClusterTls {
                verify: false,
                ..ClusterTls::default()
            }),
            ..Cluster::with_defaults("web", vec!["10.0.0.1:443".into()])
        }];
        validate_clusters(&clusters, &InsecureOptions::default()).expect("TLS without verify should not require SNI");
    }
}
