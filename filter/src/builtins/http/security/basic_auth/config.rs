// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Deserialized YAML configuration types for the basic auth filter.

use std::fmt;

use serde::Deserialize;

/// Deserialized YAML config for the basic auth filter.
///
/// ```yaml
/// filter: basic_auth
/// realm: "Restricted"
/// strip_authorization: true
/// credentials:
///   - username: admin
///     password: secret
///   - username: deploy
///     env_var: DEPLOY_PASSWORD
/// ```
#[derive(Debug, Deserialize)]
#[serde(try_from = "RawBasicAuthConfig")]
pub(super) struct BasicAuthConfig {
    /// Realm string for the `WWW-Authenticate` challenge.
    pub realm: String,

    /// Whether to strip the `Authorization` header before forwarding upstream.
    pub strip_authorization: bool,

    /// Credential source (inline list or KV store name).
    pub source: CredentialSourceConfig,
}

/// Where credentials are looked up, as specified in config.
#[derive(Debug)]
pub(super) enum CredentialSourceConfig {
    /// Inline credential list.
    Inline(Vec<InlineCredential>),

    /// KV store name where key=username, value=password.
    KvStore(String),
}

/// Raw deserialization target for [`BasicAuthConfig`].
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawBasicAuthConfig {
    /// Realm string for the `WWW-Authenticate` challenge.
    #[serde(default = "default_realm")]
    realm: String,
    /// Whether to strip the `Authorization` header before forwarding.
    #[serde(default = "default_strip")]
    strip_authorization: bool,
    /// Inline credential list.
    #[serde(default)]
    credentials: Vec<InlineCredential>,
    /// KV store name for credential lookup.
    kv_store: Option<String>,
}

impl TryFrom<RawBasicAuthConfig> for BasicAuthConfig {
    type Error = String;

    fn try_from(raw: RawBasicAuthConfig) -> Result<Self, Self::Error> {
        let source = match (raw.credentials.is_empty(), raw.kv_store) {
            (false, Some(_)) => return Err("both 'credentials' and 'kv_store' are set (use exactly one)".into()),
            (true, None) => return Err("one of 'credentials' or 'kv_store' must be set".into()),
            (false, None) => CredentialSourceConfig::Inline(raw.credentials),
            (true, Some(store)) => CredentialSourceConfig::KvStore(store),
        };
        if raw.realm.contains('"') || raw.realm.bytes().any(|b| b < 0x20 || b == 0x7F) {
            return Err("realm must not contain double-quotes or control characters".into());
        }

        Ok(Self {
            realm: raw.realm,
            strip_authorization: raw.strip_authorization,
            source,
        })
    }
}

/// Where a credential's password comes from.
pub(super) enum PasswordSource {
    /// Literal password value from config.
    Password(String),

    /// Environment variable name resolved at filter construction time.
    EnvVar(String),
}

impl PasswordSource {
    /// Resolves the password value from the configured source.
    pub(super) fn resolve(&self, username: &str) -> Result<String, String> {
        match self {
            Self::Password(val) => Ok(val.clone()),
            Self::EnvVar(var) => std::env::var(var)
                .map_err(|e| format!("basic_auth: environment variable '{var}' not set for user '{username}': {e}")),
        }
    }
}

impl fmt::Debug for PasswordSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Password(_) => write!(f, "Password([REDACTED])"),
            Self::EnvVar(var) => write!(f, "EnvVar({var:?})"),
        }
    }
}

/// A single inline username/password entry.
///
/// The password source is validated at parse time via
/// [`PasswordSource`], ensuring exactly one of `password`
/// or `env_var` is present.
#[derive(Debug, Deserialize)]
#[serde(try_from = "RawInlineCredential")]
pub(super) struct InlineCredential {
    /// Username for authentication.
    pub username: String,

    /// Password source (literal or environment variable).
    pub source: PasswordSource,
}

/// Raw deserialization target for [`InlineCredential`].
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawInlineCredential {
    /// Username for authentication.
    username: String,
    /// Literal password value.
    password: Option<String>,
    /// Environment variable containing the password.
    env_var: Option<String>,
}

impl TryFrom<RawInlineCredential> for InlineCredential {
    type Error = String;

    fn try_from(raw: RawInlineCredential) -> Result<Self, Self::Error> {
        let source = match (raw.password, raw.env_var) {
            (Some(password), None) => PasswordSource::Password(password),
            (None, Some(env_var)) => PasswordSource::EnvVar(env_var),
            (Some(_), Some(_)) => {
                return Err(format!(
                    "user '{}' has both 'password' and 'env_var' set (use exactly one)",
                    raw.username
                ));
            },
            (None, None) => {
                return Err(format!(
                    "user '{}' must have either 'password' or 'env_var'",
                    raw.username
                ));
            },
        };
        if raw.username.trim().is_empty() {
            return Err("username must not be empty".to_owned());
        }

        Ok(Self {
            username: raw.username,
            source,
        })
    }
}

/// Default realm for the `WWW-Authenticate` challenge.
fn default_realm() -> String {
    "Restricted".to_owned()
}

/// Default for `strip_authorization`.
fn default_strip() -> bool {
    true
}

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::expect_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn debug_redacts_inline_password() {
        let cfg: BasicAuthConfig = serde_yaml::from_str(
            "
credentials:
  - username: admin
    password: super-secret
",
        )
        .expect("basic auth config should parse");

        let debug = format!("{cfg:?}");
        assert!(
            debug.contains("REDACTED"),
            "Debug output should include redaction marker"
        );
        assert!(debug.contains("admin"), "Debug output should retain username");
        assert!(
            !debug.contains("super-secret"),
            "Debug output must not contain inline password"
        );
    }

    #[test]
    fn debug_preserves_env_var_name() {
        let cfg: BasicAuthConfig = serde_yaml::from_str(
            "
credentials:
  - username: deploy
    env_var: DEPLOY_PASSWORD
",
        )
        .expect("basic auth config should parse");

        let debug = format!("{cfg:?}");
        assert!(
            debug.contains("DEPLOY_PASSWORD"),
            "Debug output should retain env var name"
        );
        assert!(
            !debug.contains("REDACTED"),
            "Debug output should not redact absent password"
        );
    }

    #[test]
    fn default_realm_is_restricted() {
        let cfg: BasicAuthConfig = serde_yaml::from_str(
            "
credentials:
  - username: admin
    password: secret
",
        )
        .expect("basic auth config should parse");

        assert_eq!(cfg.realm, "Restricted", "default realm should be Restricted");
    }

    #[test]
    fn default_strip_authorization_is_true() {
        let cfg: BasicAuthConfig = serde_yaml::from_str(
            "
credentials:
  - username: admin
    password: secret
",
        )
        .expect("basic auth config should parse");

        assert!(cfg.strip_authorization, "default strip_authorization should be true");
    }

    #[test]
    fn parses_kv_store_config() {
        let cfg: BasicAuthConfig = serde_yaml::from_str(
            "
kv_store: auth_credentials
realm: \"Internal\"
",
        )
        .expect("basic auth kv_store config should parse");

        assert!(
            matches!(&cfg.source, CredentialSourceConfig::KvStore(name) if name == "auth_credentials"),
            "should parse as KvStore source"
        );
        assert_eq!(cfg.realm, "Internal");
    }
}
