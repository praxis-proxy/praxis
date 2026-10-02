// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Per-attempt upstream `Host` for a cluster: none, a fixed override, or the
//! selected endpoint's own address.

use std::{collections::HashMap, net::Ipv6Addr, str::FromStr as _, sync::Arc};

use http::{header::HeaderValue, uri::Authority};
use praxis_core::config::{AuthoritySource, Cluster, UpstreamAuthority};
use tracing::debug;

use crate::FilterError;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Default port for a plaintext cluster, left out of a derived authority.
const HTTP_DEFAULT_PORT: u16 = 80;

/// Default port for a `tls` cluster, left out of a derived authority.
const HTTPS_DEFAULT_PORT: u16 = 443;

// -----------------------------------------------------------------------------
// AuthorityResolver
// -----------------------------------------------------------------------------

/// Picks the upstream `Host` for each attempt to a cluster.
///
/// Both the first selection and every retry reselection ask the same
/// resolver, so a retry to a different endpoint never reverts to the
/// downstream `Host` or keeps the previous endpoint's name.
#[derive(Clone, Debug)]
pub(super) enum AuthorityResolver {
    /// Forward the downstream `Host` (`None`) or always send this value.
    Fixed(Option<HeaderValue>),

    /// Send the selected endpoint's address.
    Endpoint(Arc<EndpointAuthorities>),
}

impl AuthorityResolver {
    /// Build the resolver for a cluster, pre-parsing every value it can send.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] when a fixed authority is invalid, or when an
    /// endpoint address cannot be turned into an HTTP authority.
    pub(super) fn build(cluster: &Cluster) -> Result<Self, FilterError> {
        match &cluster.http.authority {
            None => Ok(Self::Fixed(None)),
            Some(UpstreamAuthority::Literal(authority)) => fixed_authority(cluster, authority).map(Self::Fixed),
            Some(UpstreamAuthority::Derived {
                from: AuthoritySource::Endpoint,
            }) => EndpointAuthorities::build(cluster).map(|table| Self::Endpoint(Arc::new(table))),
        }
    }

    /// The `Host` to send to `address`, or `None` to forward the downstream one.
    pub(super) fn for_address(&self, address: &str) -> Option<HeaderValue> {
        match self {
            Self::Fixed(authority) => authority.clone(),
            Self::Endpoint(table) => table.get(address),
        }
    }

    /// Whether each attempt names its own endpoint, which also means a
    /// missing `tls.sni` must not be filled from the downstream `Host`.
    pub(super) fn follows_endpoint(&self) -> bool {
        match self {
            Self::Fixed(_) => false,
            Self::Endpoint(_) => true,
        }
    }
}

/// Pre-built `Host` values for every configured endpoint of a cluster.
#[derive(Debug)]
pub(super) struct EndpointAuthorities {
    /// `Host` value per endpoint address.
    by_address: HashMap<Arc<str>, HeaderValue>,

    /// Scheme default port, left out of the authority.
    default_port: u16,
}

impl EndpointAuthorities {
    /// Pre-build the `Host` value for each endpoint of `cluster`.
    fn build(cluster: &Cluster) -> Result<Self, FilterError> {
        let default_port = if cluster.tls.is_some() {
            HTTPS_DEFAULT_PORT
        } else {
            HTTP_DEFAULT_PORT
        };
        let by_address = cluster
            .endpoints
            .iter()
            .map(|endpoint| {
                let address = endpoint.address();
                endpoint_authority(address, default_port)
                    .map(|authority| (Arc::from(address), authority))
                    .map_err(|reason| -> FilterError {
                        format!(
                            "cluster '{}': endpoint '{address}' cannot be used as the upstream authority: {reason}",
                            cluster.name
                        )
                        .into()
                    })
            })
            .collect::<Result<_, _>>()?;
        Ok(Self {
            by_address,
            default_port,
        })
    }

    /// The `Host` value for `address`.
    ///
    /// An address outside the configured set (a session-affinity pin to an
    /// endpoint a reload removed) is derived on the spot, so it still names
    /// itself instead of sending the downstream `Host`.
    fn get(&self, address: &str) -> Option<HeaderValue> {
        if let Some(authority) = self.by_address.get(address) {
            return Some(authority.clone());
        }
        endpoint_authority(address, self.default_port)
            .inspect_err(|reason| debug!(address, %reason, "cannot derive an upstream authority for this address"))
            .ok()
    }
}

// -----------------------------------------------------------------------------
// Utilities
// -----------------------------------------------------------------------------

/// Validate and pre-parse a fixed authority override.
///
/// Fails instead of silently dropping the override, so programmatic callers
/// of `LoadBalancerFilter::new` cannot accidentally forward the caller's
/// original `Host` header.
fn fixed_authority(cluster: &Cluster, authority: &str) -> Result<Option<HeaderValue>, FilterError> {
    cluster.validate_authority().map_err(|e| e.to_string())?;
    HeaderValue::from_str(authority).map(Some).map_err(|e| {
        format!(
            "cluster '{}': authority '{authority}' is not a valid HTTP header value: {e}",
            cluster.name,
        )
        .into()
    })
}

/// The HTTP authority for an endpoint `host:port` address: the host, plus the
/// port unless it is `default_port`.
///
/// An IPv6 host written without brackets (endpoint validation accepts
/// `2001:db8::1:80`) gets them, since an authority cannot carry it bare.
fn endpoint_authority(address: &str, default_port: u16) -> Result<HeaderValue, String> {
    let (host, port) = address
        .rsplit_once(':')
        .ok_or_else(|| "expected 'host:port'".to_owned())?;
    let port: u16 = port.parse().map_err(|e| format!("invalid port: {e}"))?;
    let host = host
        .parse::<Ipv6Addr>()
        .map_or_else(|_| host.to_owned(), |ip| format!("[{ip}]"));
    let authority = if port == default_port {
        host
    } else {
        format!("{host}:{port}")
    };
    let parsed = Authority::from_str(&authority).map_err(|e| format!("not a valid HTTP authority: {e}"))?;
    HeaderValue::from_str(parsed.as_str()).map_err(|e| format!("not a valid HTTP header value: {e}"))
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]
mod tests {
    use praxis_core::config::ClusterTls;

    use super::*;

    #[test]
    fn endpoint_authority_drops_the_default_port() {
        let cases = [
            ("api.example.com:80", HTTP_DEFAULT_PORT, "api.example.com"),
            ("api.example.com:443", HTTPS_DEFAULT_PORT, "api.example.com"),
            ("10.0.0.1:443", HTTPS_DEFAULT_PORT, "10.0.0.1"),
            ("[2001:db8::1]:80", HTTP_DEFAULT_PORT, "[2001:db8::1]"),
            ("api.example.com:080", HTTP_DEFAULT_PORT, "api.example.com"),
        ];
        for (address, default_port, want) in cases {
            assert_eq!(
                endpoint_authority(address, default_port).unwrap(),
                want,
                "{address} with default port {default_port}"
            );
        }
    }

    #[test]
    fn endpoint_authority_keeps_a_non_default_port() {
        let cases = [
            ("api.example.com:8443", HTTPS_DEFAULT_PORT, "api.example.com:8443"),
            ("api.example.com:443", HTTP_DEFAULT_PORT, "api.example.com:443"),
            ("10.0.0.1:8443", HTTPS_DEFAULT_PORT, "10.0.0.1:8443"),
            ("[2001:db8::1]:8080", HTTP_DEFAULT_PORT, "[2001:db8::1]:8080"),
            ("2001:db8::1:8080", HTTP_DEFAULT_PORT, "[2001:db8::1]:8080"),
        ];
        for (address, default_port, want) in cases {
            assert_eq!(
                endpoint_authority(address, default_port).unwrap(),
                want,
                "{address} with default port {default_port}"
            );
        }
    }

    #[test]
    fn endpoint_authority_rejects_unusable_addresses() {
        for address in ["api.example.com", "api.example.com:http", "api example.com:80", ":80"] {
            assert!(
                endpoint_authority(address, HTTP_DEFAULT_PORT).is_err(),
                "{address:?} should not produce an authority"
            );
        }
    }

    #[test]
    fn resolver_uses_the_tls_default_port() {
        let cluster = Cluster {
            tls: Some(ClusterTls::default()),
            ..endpoint_cluster(&["a.example.com:443", "b.example.com:8443"])
        };
        let resolver = AuthorityResolver::build(&cluster).unwrap();
        assert_eq!(
            resolver.for_address("a.example.com:443").unwrap(),
            "a.example.com",
            "443 is the default on a TLS cluster"
        );
        assert_eq!(
            resolver.for_address("b.example.com:8443").unwrap(),
            "b.example.com:8443",
            "a non-default port stays in the authority"
        );
    }

    #[test]
    fn resolver_derives_an_address_outside_the_configured_set() {
        let resolver = AuthorityResolver::build(&endpoint_cluster(&["a.example.com:80"])).unwrap();
        assert_eq!(
            resolver.for_address("removed.example.com:8080").unwrap(),
            "removed.example.com:8080",
            "a pinned address a reload removed should still name itself"
        );
        assert!(
            resolver.for_address("not an address").is_none(),
            "an address that cannot be an authority yields no override"
        );
    }

    #[test]
    fn build_rejects_an_endpoint_that_cannot_be_an_authority() {
        let err = AuthorityResolver::build(&endpoint_cluster(&["bad host:80"])).unwrap_err();
        assert!(
            err.to_string()
                .contains("endpoint 'bad host:80' cannot be used as the upstream authority"),
            "the error should name the endpoint: {err}"
        );
    }

    #[test]
    fn fixed_and_absent_resolvers_ignore_the_address() {
        let fixed = AuthorityResolver::build(&Cluster {
            http: praxis_core::config::ClusterHttpOptions {
                authority: Some("api.example.com".into()),
                ..praxis_core::config::ClusterHttpOptions::default()
            },
            ..Cluster::with_defaults("fixed", vec!["10.0.0.1:80".into()])
        })
        .unwrap();
        assert_eq!(
            fixed.for_address("10.0.0.1:80").unwrap(),
            "api.example.com",
            "a fixed authority is sent whatever the endpoint"
        );
        assert!(
            !fixed.follows_endpoint(),
            "a fixed authority does not follow the endpoint"
        );

        let absent = AuthorityResolver::build(&Cluster::with_defaults("plain", vec!["10.0.0.1:80".into()])).unwrap();
        assert!(
            absent.for_address("10.0.0.1:80").is_none(),
            "no authority means the downstream Host is forwarded"
        );
        assert!(!absent.follows_endpoint(), "no authority does not follow the endpoint");
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// A plaintext cluster whose `Host` follows the selected endpoint.
    fn endpoint_cluster(endpoints: &[&str]) -> Cluster {
        Cluster {
            http: praxis_core::config::ClusterHttpOptions {
                authority: Some(UpstreamAuthority::Derived {
                    from: AuthoritySource::Endpoint,
                }),
                ..praxis_core::config::ClusterHttpOptions::default()
            },
            ..Cluster::with_defaults("mixed", endpoints.iter().map(|&address| address.into()).collect())
        }
    }
}
