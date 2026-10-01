// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Where a cluster's upstream `Host` header comes from.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

// -----------------------------------------------------------------------------
// UpstreamAuthority
// -----------------------------------------------------------------------------

/// The upstream `Host` a cluster sends in place of the downstream one.
///
/// Written either as a plain `host[:port]` string, sent unchanged on every
/// request, or as `{ from: endpoint }`, which sends the address of the
/// endpoint the load balancer picked for each attempt.
///
/// Serializes untagged (a bare string or the `{ from: ... }` mapping), so a
/// config dump reads back as the same value. Deserialization dispatches on
/// the YAML shape by hand, like [`LoadBalancerStrategy`]: an untagged derive
/// would report a typo in the mapping form only as "data did not match any
/// variant", where this names the bad key or value.
///
/// ```
/// use praxis_core::config::{AuthoritySource, UpstreamAuthority};
///
/// let fixed: UpstreamAuthority = serde_yaml::from_str("api.example.com").unwrap();
/// assert_eq!(fixed.literal(), Some("api.example.com"));
/// assert!(!fixed.follows_endpoint());
///
/// let derived: UpstreamAuthority = serde_yaml::from_str("{ from: endpoint }").unwrap();
/// assert_eq!(
///     derived,
///     UpstreamAuthority::Derived {
///         from: AuthoritySource::Endpoint
///     }
/// );
/// assert!(derived.follows_endpoint());
///
/// let typo = serde_yaml::from_str::<UpstreamAuthority>("{ frm: endpoint }").unwrap_err();
/// assert!(typo.to_string().contains("frm"));
/// ```
///
/// [`LoadBalancerStrategy`]: super::LoadBalancerStrategy
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(untagged)]
pub enum UpstreamAuthority {
    /// A fixed `host[:port]` sent on every request.
    Literal(Arc<str>),

    /// An authority taken from the request's own upstream selection.
    Derived {
        /// What the authority is taken from. `endpoint` sends the selected
        /// endpoint's `host:port`, leaving out the port when it is the
        /// scheme default (80, or 443 when the cluster sets `tls`).
        from: AuthoritySource,
    },
}

impl UpstreamAuthority {
    /// The fixed authority, when this is one.
    ///
    /// ```
    /// use praxis_core::config::UpstreamAuthority;
    ///
    /// assert_eq!(
    ///     UpstreamAuthority::from("api.example.com:8443").literal(),
    ///     Some("api.example.com:8443")
    /// );
    /// ```
    pub fn literal(&self) -> Option<&str> {
        match self {
            Self::Literal(authority) => Some(authority),
            Self::Derived { .. } => None,
        }
    }

    /// Whether each attempt sends the address of its own selected endpoint.
    ///
    /// ```
    /// use praxis_core::config::{AuthoritySource, UpstreamAuthority};
    ///
    /// let derived = UpstreamAuthority::Derived {
    ///     from: AuthoritySource::Endpoint,
    /// };
    /// assert!(derived.follows_endpoint());
    /// assert!(!UpstreamAuthority::from("api.example.com").follows_endpoint());
    /// ```
    pub fn follows_endpoint(&self) -> bool {
        match self {
            Self::Derived {
                from: AuthoritySource::Endpoint,
            } => true,
            Self::Literal(_) => false,
        }
    }
}

impl From<&str> for UpstreamAuthority {
    fn from(authority: &str) -> Self {
        Self::Literal(Arc::from(authority))
    }
}

impl<'de> Deserialize<'de> for UpstreamAuthority {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error as _;

        match serde_yaml::Value::deserialize(deserializer)? {
            serde_yaml::Value::String(authority) => Ok(Self::Literal(Arc::from(authority))),
            mapping @ serde_yaml::Value::Mapping(_) => DerivedAuthority::deserialize(mapping)
                .map(|derived| Self::Derived { from: derived.from })
                .map_err(D::Error::custom),
            serde_yaml::Value::Null
            | serde_yaml::Value::Bool(_)
            | serde_yaml::Value::Number(_)
            | serde_yaml::Value::Sequence(_)
            | serde_yaml::Value::Tagged(_) => Err(D::Error::custom(
                "authority must be a host[:port] string or { from: endpoint }",
            )),
        }
    }
}

/// Request-time sources an [`UpstreamAuthority`] can be taken from.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthoritySource {
    /// The endpoint the load balancer selected for the attempt.
    Endpoint,
}

/// Mapping form of [`UpstreamAuthority::Derived`], parsed on its own so an
/// unknown key is rejected by name.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DerivedAuthority {
    /// What the authority is taken from.
    from: AuthoritySource,
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn string_parses_as_literal() {
        let authority: UpstreamAuthority = serde_yaml::from_str("\"api.example.com:8443\"").unwrap();
        assert_eq!(
            authority,
            UpstreamAuthority::Literal(Arc::from("api.example.com:8443")),
            "a string should parse as a fixed authority"
        );
    }

    #[test]
    fn mapping_parses_as_derived_from_endpoint() {
        let authority: UpstreamAuthority = serde_yaml::from_str("from: endpoint").unwrap();
        assert_eq!(
            authority,
            UpstreamAuthority::Derived {
                from: AuthoritySource::Endpoint
            },
            "{{from: endpoint}} should parse as the endpoint-derived form"
        );
    }

    #[test]
    fn unknown_source_is_named_in_the_error() {
        let err = serde_yaml::from_str::<UpstreamAuthority>("from: nonsense").unwrap_err();
        let message = err.to_string();
        assert!(
            message.contains("nonsense"),
            "error should name the bad value: {message}"
        );
        assert!(
            message.contains("endpoint"),
            "error should list the valid value: {message}"
        );
    }

    #[test]
    fn unknown_key_is_named_in_the_error() {
        let err = serde_yaml::from_str::<UpstreamAuthority>("frm: endpoint").unwrap_err();
        let message = err.to_string();
        assert!(message.contains("frm"), "error should name the unknown key: {message}");
        assert!(
            message.contains("from"),
            "error should name the expected key: {message}"
        );
    }

    #[test]
    fn mapping_without_source_is_rejected() {
        let err = serde_yaml::from_str::<UpstreamAuthority>("{}").unwrap_err();
        assert!(
            err.to_string().contains("from"),
            "an empty mapping should report the missing key: {err}"
        );
    }

    #[test]
    fn other_shapes_are_rejected() {
        for yaml in ["8080", "true", "[api.example.com]"] {
            let err = serde_yaml::from_str::<UpstreamAuthority>(yaml).unwrap_err();
            assert!(
                err.to_string().contains("host[:port] string or { from: endpoint }"),
                "{yaml:?} should be rejected with the expected-shape message: {err}"
            );
        }
    }

    #[test]
    fn literal_round_trips_as_a_string() {
        let authority = UpstreamAuthority::from("api.example.com");
        let value = serde_yaml::to_value(&authority).unwrap();
        assert_eq!(
            value,
            serde_yaml::Value::String("api.example.com".to_owned()),
            "a fixed authority should serialize as a bare string"
        );
        let back: UpstreamAuthority = serde_yaml::from_value(value).unwrap();
        assert_eq!(back, authority, "a fixed authority should round-trip");
    }

    #[test]
    fn derived_round_trips_as_a_mapping() {
        let authority = UpstreamAuthority::Derived {
            from: AuthoritySource::Endpoint,
        };
        let value = serde_yaml::to_value(&authority).unwrap();
        assert_eq!(
            value,
            serde_yaml::from_str::<serde_yaml::Value>("from: endpoint").unwrap(),
            "the endpoint-derived form should serialize as {{from: endpoint}}"
        );
        let back: UpstreamAuthority = serde_yaml::from_value(value).unwrap();
        assert_eq!(back, authority, "the endpoint-derived form should round-trip");
    }
}
