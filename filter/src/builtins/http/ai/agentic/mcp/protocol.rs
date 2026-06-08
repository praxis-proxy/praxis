// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! MCP protocol version and profile types.
//!
//! Centralizes the protocol version string so it is not scattered through
//! handlers and tests. Future MCP spec versions can be added to
//! [`SUPPORTED_VERSIONS`] without modifying individual request handlers.

use serde::Deserialize;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Protocol version implemented by the current broker behavior.
pub(crate) const PROTOCOL_VERSION_CURRENT: &str = "2025-03-26";

/// All protocol versions this build of Praxis can handle.
pub(crate) const SUPPORTED_VERSIONS: &[&str] = &[PROTOCOL_VERSION_CURRENT];

/// Fallback protocol version used when no explicit version is configured.
pub(crate) const DEFAULT_VERSION: &str = PROTOCOL_VERSION_CURRENT;

// -----------------------------------------------------------------------------
// ProtocolProfile
// -----------------------------------------------------------------------------

/// MCP protocol profile governing session semantics and header requirements.
///
/// The `Current` profile preserves the existing `initialize`/session behavior.
/// Future profiles can be added when the MCP spec finalizes additional
/// transport modes.
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ProtocolProfile {
    /// Current MCP Streamable HTTP behavior: `initialize` handshake,
    /// optional `MCP-Session-Id`, and session-aware DELETE.
    #[default]
    Current,
}

impl ProtocolProfile {
    /// String label for logging and metadata.
    #[allow(dead_code, reason = "plumbing for follow-up profile-aware logging")]
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Current => "current",
        }
    }
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/// Returns `true` when `version` appears in [`SUPPORTED_VERSIONS`].
pub(crate) fn is_supported_version(version: &str) -> bool {
    SUPPORTED_VERSIONS.contains(&version)
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::needless_raw_strings,
    clippy::needless_raw_string_hashes,
    reason = "tests"
)]
mod tests {
    use super::*;

    #[test]
    fn default_version_is_supported() {
        assert!(
            is_supported_version(DEFAULT_VERSION),
            "DEFAULT_VERSION must appear in SUPPORTED_VERSIONS"
        );
    }

    #[test]
    fn current_version_is_supported() {
        assert!(
            is_supported_version(PROTOCOL_VERSION_CURRENT),
            "PROTOCOL_VERSION_CURRENT must be supported"
        );
    }

    #[test]
    fn unknown_version_is_not_supported() {
        assert!(
            !is_supported_version("9999-12-31"),
            "arbitrary version should not be supported"
        );
    }

    #[test]
    fn default_profile_is_current() {
        assert_eq!(
            ProtocolProfile::default(),
            ProtocolProfile::Current,
            "default profile should be Current"
        );
    }

    #[test]
    fn profile_as_str_round_trips() {
        assert_eq!(ProtocolProfile::Current.as_str(), "current");
    }

    #[test]
    fn profile_deserializes_from_yaml() {
        let profile: ProtocolProfile = serde_yaml::from_str("current").unwrap();
        assert_eq!(profile, ProtocolProfile::Current, "should parse 'current'");
    }

    #[test]
    fn profile_rejects_unknown_value() {
        let result = serde_yaml::from_str::<ProtocolProfile>("unknown");
        assert!(result.is_err(), "unknown profile value should fail to parse");
    }
}
