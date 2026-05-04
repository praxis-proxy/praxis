// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Deserialized YAML configuration types for the credential injection filter.

use serde::Deserialize;

// -----------------------------------------------------------------------------
// CredentialInjectionConfig
// -----------------------------------------------------------------------------

/// Deserialized YAML config for the credential injection filter.
///
/// ```yaml
/// filter: credential_injection
/// clusters:
///   - name: openai
///     header: Authorization
///     env_var: OPENAI_API_KEY
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
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ClusterCredentialConfig {
    /// Cluster name this rule applies to.
    pub name: String,

    /// Header name to inject (e.g. `"Authorization"`, `"x-api-key"`).
    pub header: String,

    /// Literal credential value. Mutually exclusive with `env_var`.
    pub value: Option<String>,

    /// Environment variable name containing the credential.
    /// Resolved at filter construction time.
    /// Mutually exclusive with `value`.
    pub env_var: Option<String>,

    /// Optional prefix prepended to the credential value
    /// before injection (e.g. `"Bearer "`).
    #[serde(default)]
    pub header_prefix: Option<String>,

    /// Whether to strip client-provided values for this
    /// header before injecting the configured credential.
    /// Defaults to `true`.
    #[serde(default = "default_strip")]
    pub strip_client_credential: bool,
}

/// Default for `strip_client_credential`: always strip.
fn default_strip() -> bool {
    true
}
