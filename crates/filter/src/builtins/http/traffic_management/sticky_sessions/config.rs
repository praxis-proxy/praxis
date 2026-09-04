// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Configuration types for the sticky sessions filter.

use serde::Deserialize;

/// Maximum allowed `max_entries` to prevent unbounded memory growth.
const MAX_ENTRIES_UPPER_BOUND: u64 = 200_000;

// -----------------------------------------------------------------------------
// PersistenceConfig (tagged enum)
// -----------------------------------------------------------------------------

/// How session identity is determined.
///
/// Uses `#[serde(tag = "type")]` so the YAML discriminator is `type: cookie`,
/// `type: header`, or `type: learn`. Each variant carries only the fields
/// relevant to that mode, eliminating conditionally-required `Option` fields.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(crate) enum PersistenceConfig {
    /// Proxy-managed session cookie.
    Cookie {
        /// Cookie name used to store the session ID.
        cookie_name: String,
        /// Cookie attributes for the `Set-Cookie` header.
        #[serde(default)]
        cookie_attributes: CookieAttributes,
    },
    /// Request header value as session key.
    Header {
        /// Header name to read the session key from.
        header_name: String,
    },
    /// Learn session ID from upstream `Set-Cookie` response.
    Learn {
        /// Cookie name to observe in upstream responses.
        cookie_name: String,
    },
}

impl PersistenceConfig {
    /// The cookie name, if applicable to this persistence type.
    pub(crate) fn cookie_name(&self) -> Option<&str> {
        match self {
            Self::Cookie { cookie_name, .. } | Self::Learn { cookie_name } => Some(cookie_name.as_str()),
            Self::Header { .. } => None,
        }
    }

    /// The cookie attributes, if applicable (cookie type only).
    pub(crate) fn cookie_attributes(&self) -> Option<&CookieAttributes> {
        match self {
            Self::Cookie { cookie_attributes, .. } => Some(cookie_attributes),
            Self::Header { .. } | Self::Learn { .. } => None,
        }
    }
}

// -----------------------------------------------------------------------------
// SameSite
// -----------------------------------------------------------------------------

/// `SameSite` cookie attribute.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
pub(crate) enum SameSite {
    /// `SameSite=Strict`
    Strict,
    /// `SameSite=Lax`
    Lax,
    /// `SameSite=None`
    None,
}

impl SameSite {
    /// String representation for Set-Cookie header.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Strict => "Strict",
            Self::Lax => "Lax",
            Self::None => "None",
        }
    }
}

// -----------------------------------------------------------------------------
// CookieAttributes
// -----------------------------------------------------------------------------

/// Configurable attributes for the session cookie.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct CookieAttributes {
    /// `Domain` attribute.
    #[serde(default)]
    pub domain: Option<String>,

    /// `Path` attribute.
    #[serde(default)]
    pub path: Option<String>,

    /// `HttpOnly` flag.
    #[serde(default)]
    pub http_only: bool,

    /// `Secure` flag.
    #[serde(default)]
    pub secure: bool,

    /// `SameSite` attribute.
    #[serde(default)]
    pub same_site: Option<SameSite>,
}

// -----------------------------------------------------------------------------
// EvictionPolicy
// -----------------------------------------------------------------------------

/// How entries are evicted when the store reaches capacity.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum EvictionPolicy {
    /// Evict least-recently-accessed entries first.
    #[default]
    Lru,
    /// Evict oldest entries (by creation time) first.
    Ttl,
}

// -----------------------------------------------------------------------------
// MaxEntries
// -----------------------------------------------------------------------------

/// Constrained entry cap (`1..=200_000`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MaxEntries(u64);

impl MaxEntries {
    /// Return the underlying value.
    #[must_use]
    pub(crate) const fn get(self) -> u64 {
        self.0
    }
}

impl TryFrom<u64> for MaxEntries {
    type Error = String;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        if value == 0 {
            return Err("max_entries must be > 0".into());
        }
        if value > MAX_ENTRIES_UPPER_BOUND {
            return Err(format!("max_entries must be <= {MAX_ENTRIES_UPPER_BOUND}, got {value}"));
        }
        Ok(Self(value))
    }
}

impl Default for MaxEntries {
    fn default() -> Self {
        Self(100_000)
    }
}

impl<'de> Deserialize<'de> for MaxEntries {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = u64::deserialize(deserializer)?;
        Self::try_from(value).map_err(serde::de::Error::custom)
    }
}

// -----------------------------------------------------------------------------
// ClusterSessionConfig
// -----------------------------------------------------------------------------

/// Per-cluster session persistence configuration.
#[derive(Clone, Debug, Deserialize)]
pub(crate) struct ClusterSessionConfig {
    /// Cluster name this config applies to.
    pub name: String,

    /// Persistence mechanism (tagged enum discriminated by `type`).
    #[serde(flatten)]
    pub persistence: PersistenceConfig,

    /// Idle timeout for session entries in seconds (sliding TTL).
    /// The binding expires after this many seconds of inactivity.
    #[serde(default = "default_ttl_secs")]
    pub ttl_secs: u64,

    /// Re-pin to a healthy endpoint when the pinned one is unhealthy.
    #[serde(default = "default_true")]
    pub failover: bool,

    /// Maximum number of session entries in the store.
    #[serde(default)]
    pub max_entries: MaxEntries,

    /// Eviction policy when at capacity.
    #[serde(default)]
    pub eviction: EvictionPolicy,
}

/// Default idle TTL for session entries (1 hour).
fn default_ttl_secs() -> u64 {
    3600
}

/// Returns `true`; used as serde default for opt-out booleans.
fn default_true() -> bool {
    true
}

impl ClusterSessionConfig {
    /// Validate the config after deserialization.
    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.ttl_secs == 0 {
            return Err(format!("sticky_sessions: cluster '{}' ttl_secs must be > 0", self.name));
        }
        match &self.persistence {
            PersistenceConfig::Cookie { cookie_name, .. } | PersistenceConfig::Learn { cookie_name } => {
                if cookie_name.is_empty() {
                    return Err(format!(
                        "sticky_sessions: cluster '{}' requires non-empty cookie_name",
                        self.name
                    ));
                }
            },
            PersistenceConfig::Header { header_name } => {
                if header_name.is_empty() {
                    return Err(format!(
                        "sticky_sessions: cluster '{}' requires non-empty header_name for header type",
                        self.name
                    ));
                }
            },
        }
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// StickySessionsConfig
// -----------------------------------------------------------------------------

/// Top-level config for the sticky sessions filter.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StickySessionsConfig {
    /// Per-cluster session persistence configurations.
    pub clusters: Vec<ClusterSessionConfig>,
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn parse_cookie_config() {
        let yaml = r#"
clusters:
  - name: app_backend
    type: cookie
    cookie_name: "_praxis_route"
    ttl_secs: 3600
    cookie_attributes:
      path: "/"
      http_only: true
      secure: true
      same_site: Lax
    failover: true
    max_entries: 100000
    eviction: lru
"#;
        let config: StickySessionsConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.clusters.len(), 1);
        let c = config.clusters.first().unwrap();
        assert_eq!(c.name, "app_backend");
        assert!(matches!(c.persistence, PersistenceConfig::Cookie { .. }));
        assert_eq!(c.persistence.cookie_name(), Some("_praxis_route"));
        assert_eq!(c.ttl_secs, 3600);
        let attrs = c.persistence.cookie_attributes().unwrap();
        assert!(attrs.http_only);
        assert!(attrs.secure);
        assert_eq!(attrs.same_site, Some(SameSite::Lax));
        assert!(c.failover);
        assert_eq!(c.max_entries.get(), 100_000);
        assert_eq!(c.eviction, EvictionPolicy::Lru);
        c.validate().unwrap();
    }

    #[test]
    fn parse_header_config() {
        let yaml = r#"
clusters:
  - name: api_backend
    type: header
    header_name: "X-Session-Id"
    ttl_secs: 3600
    max_entries: 50000
"#;
        let config: StickySessionsConfig = serde_yaml::from_str(yaml).unwrap();
        let c = config.clusters.first().unwrap();
        assert!(matches!(c.persistence, PersistenceConfig::Header { .. }));
        assert!(matches!(&c.persistence, PersistenceConfig::Header { header_name } if header_name == "X-Session-Id"));
        c.validate().unwrap();
    }

    #[test]
    fn parse_learn_config() {
        let yaml = r#"
clusters:
  - name: legacy
    type: learn
    cookie_name: "JSESSIONID"
    ttl_secs: 1800
"#;
        let config: StickySessionsConfig = serde_yaml::from_str(yaml).unwrap();
        let c = config.clusters.first().unwrap();
        assert!(matches!(c.persistence, PersistenceConfig::Learn { .. }));
        c.validate().unwrap();
    }

    #[test]
    fn reject_cookie_type_without_cookie_name() {
        let yaml = "
clusters:
  - name: bad
    type: cookie
    cookie_name: \"\"
    ttl_secs: 100
";
        let config: StickySessionsConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(config.clusters.first().unwrap().validate().is_err());
    }

    #[test]
    fn reject_header_type_without_header_name() {
        let yaml = "
clusters:
  - name: bad
    type: header
    header_name: \"\"
    ttl_secs: 100
";
        let config: StickySessionsConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(config.clusters.first().unwrap().validate().is_err());
    }

    #[test]
    fn reject_max_entries_above_bound() {
        let yaml = r#"
clusters:
  - name: x
    type: header
    header_name: "X-Id"
    max_entries: 999999
"#;
        let err = serde_yaml::from_str::<StickySessionsConfig>(yaml).unwrap_err();
        assert!(err.to_string().contains("200000"), "got: {err}");
    }

    #[test]
    fn reject_zero_ttl() {
        let yaml = r#"
clusters:
  - name: x
    type: header
    header_name: "X-Id"
    ttl_secs: 0
"#;
        let config: StickySessionsConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(config.clusters.first().unwrap().validate().is_err());
    }
}
