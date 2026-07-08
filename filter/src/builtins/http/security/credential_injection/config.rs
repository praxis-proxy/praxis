// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Deserialized YAML configuration types for the credential injection filter.

use std::fmt;

use serde::Deserialize;

// -----------------------------------------------------------------------------
// CredentialInjectionConfig
// -----------------------------------------------------------------------------

/// Deserialized YAML config for the credential injection filter.
///
/// ```yaml
/// filter: credential_injection
/// clusters:
///   - name: provider-a
///     header: Authorization
///     env_var: PROVIDER_A_API_KEY
///     header_prefix: "Bearer "
///     strip_client_credential: true
/// ```
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CredentialInjectionConfig {
    /// Per-cluster credential injection rules.
    pub clusters: Vec<ClusterCredentialConfig>,
}

// -----------------------------------------------------------------------------
// ClusterCredentialConfig
// -----------------------------------------------------------------------------

/// Credential injection rule for a single cluster.
///
/// Exactly one of `value` or `env_var` must be set.
/// When `env_var` is used, the environment variable is
/// read once at filter construction time.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ClusterCredentialConfig {
    /// Cluster name this rule applies to.
    pub name: String,

    /// Environment variable name containing the credential.
    /// Resolved at filter construction time.
    /// Mutually exclusive with `value`.
    pub env_var: Option<String>,

    /// Header name to inject (e.g. `"Authorization"`, `"x-api-key"`).
    pub header: String,

    /// Optional prefix prepended to the credential value
    /// before injection (e.g. `"Bearer "`).
    #[serde(default)]
    pub header_prefix: Option<String>,

    /// Deprecated: injection always replaces any client-provided
    /// value for the header. Retained for config compatibility.
    #[serde(default = "default_strip")]
    pub strip_client_credential: bool,

    /// Literal credential value. Mutually exclusive with `env_var`.
    pub value: Option<String>,
}

impl fmt::Debug for ClusterCredentialConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = self.value.as_ref().map(|_| "[REDACTED]");

        f.debug_struct("ClusterCredentialConfig")
            .field("name", &self.name)
            .field("env_var", &self.env_var)
            .field("header", &self.header)
            .field("header_prefix", &self.header_prefix)
            .field("strip_client_credential", &self.strip_client_credential)
            .field("value", &value)
            .finish()
    }
}

/// Default for `strip_client_credential`.
fn default_strip() -> bool {
    true
}

#[cfg(test)]
#[expect(clippy::expect_used, reason = "tests use expect for parse setup")]
mod tests {
    use super::*;

    #[test]
    fn debug_redacts_inline_credential_value() {
        let cfg: CredentialInjectionConfig = serde_yaml::from_str(
            "
clusters:
  - name: provider-a
    header: Authorization
    value: super-secret-inline-value
    header_prefix: 'Bearer '
",
        )
        .expect("credential injection config should parse");

        let debug = format!("{cfg:?}");
        assert!(
            debug.contains("REDACTED"),
            "Debug output should include redaction marker"
        );
        assert!(debug.contains("provider-a"), "Debug output should retain cluster name");
        assert!(
            !debug.contains("super-secret-inline-value"),
            "Debug output must not contain inline credential value"
        );
    }

    #[test]
    fn debug_preserves_env_var_name_without_literal_secret() {
        let cfg: CredentialInjectionConfig = serde_yaml::from_str(
            "
clusters:
  - name: provider-a
    header: Authorization
    env_var: PROVIDER_A_API_KEY
",
        )
        .expect("credential injection config should parse");

        let debug = format!("{cfg:?}");
        assert!(
            debug.contains("PROVIDER_A_API_KEY"),
            "Debug output should retain env var name"
        );
        assert!(
            !debug.contains("REDACTED"),
            "Debug output should not redact absent literal values"
        );
    }
}
