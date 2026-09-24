// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Validation for opaque cluster application metadata identifiers.
//!
//! Clusters may declare an `application_protocol` and an
//! `application_provider` under their HTTP options. Both are opaque
//! strings interpreted by consuming filters, never by Praxis core, so
//! this module only enforces that they are bounded, canonical
//! identifiers — it deliberately does not know any protocol or provider
//! name. The canonical form itself is enforced by the shared
//! [`validate_application_identifier`] so cluster declarations and
//! `bound_upstream` conditions accept exactly the same character set.
//!
//! [`validate_application_identifier`]: super::super::validate_application_identifier

use crate::{
    config::{Cluster, validate::validate_application_identifier},
    errors::ProxyError,
};

/// Validate the optional application metadata identifiers on a cluster.
///
/// Both fields are independently optional; an absent field is always
/// valid. A present field must be a canonical identifier per
/// [`validate_application_identifier`].
pub(super) fn validate_application_metadata(cluster: &Cluster) -> Result<(), ProxyError> {
    let context = format!("cluster '{}'", cluster.name);
    if let Some(protocol) = cluster.http.application_protocol.as_deref() {
        validate_application_identifier(protocol, "application_protocol", &context)?;
    }
    if let Some(provider) = cluster.http.application_provider.as_deref() {
        validate_application_identifier(provider, "application_provider", &context)?;
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
    clippy::panic,
    clippy::min_ident_chars,
    reason = "tests use unwrap/expect/panic for brevity"
)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::config::validate::MAX_APPLICATION_IDENTIFIER_LEN as MAX_IDENTIFIER_LEN;

    #[test]
    fn accept_canonical_identifiers() {
        ok("openai_chat_completions");
        ok("openai_responses");
        ok("openai");
        ok("vllm");
        ok("gpt-4.1");
        ok("a");
        ok("1");
    }

    #[test]
    fn accept_at_max_length() {
        let value = "a".repeat(MAX_IDENTIFIER_LEN);
        assert_eq!(value.len(), 64, "test value should exercise the boundary");
        ok(&value);
    }

    #[test]
    fn both_fields_absent_is_ok() {
        let cluster = Cluster::with_defaults("test", vec!["10.0.0.1:80".into()]);
        validate_application_metadata(&cluster).expect("absent metadata should be accepted");
    }

    #[test]
    fn reject_empty() {
        assert!(err("").contains("must not be empty"), "got: {}", err(""));
    }

    #[test]
    fn reject_over_max_length() {
        let value = "a".repeat(MAX_IDENTIFIER_LEN + 1);
        assert!(err(&value).contains("exceeds 64 bytes"), "got: {}", err(&value));
    }

    #[test]
    fn reject_disallowed_characters() {
        assert!(err("OpenAI").contains("lowercase ASCII"), "uppercase");
        assert!(err("open ai").contains("lowercase ASCII"), "space");
        assert!(err("openai!").contains("lowercase ASCII"), "punctuation");
        assert!(err("openai/v1").contains("lowercase ASCII"), "slash");
    }

    #[test]
    fn reject_non_ascii_identifiers() {
        assert!(
            err("café").contains("lowercase ASCII"),
            "byte-wise check must reject accented latin as non-lowercase-ASCII"
        );
        assert!(
            err("模型").contains("lowercase ASCII"),
            "byte-wise check must reject multi-byte CJK as non-lowercase-ASCII"
        );
        assert!(
            err("openai🚀").contains("lowercase ASCII"),
            "byte-wise check must reject an emoji as non-lowercase-ASCII"
        );
    }

    #[test]
    fn reject_non_alphanumeric_boundaries() {
        assert!(err("_openai").contains("must start and end"), "leading underscore");
        assert!(err("openai_").contains("must start and end"), "trailing underscore");
        assert!(err(".openai").contains("must start and end"), "leading dot");
        assert!(err("openai-").contains("must start and end"), "trailing dash");
        assert!(err("-").contains("must start and end"), "single symbol");
    }

    #[test]
    fn error_names_the_offending_field() {
        let protocol_err = validate_application_metadata(&with_protocol("Bad"))
            .unwrap_err()
            .to_string();
        assert!(protocol_err.contains("application_protocol"), "got: {protocol_err}");

        let provider_err = validate_application_metadata(&with_provider("Bad"))
            .unwrap_err()
            .to_string();
        assert!(provider_err.contains("application_provider"), "got: {provider_err}");
    }

    #[test]
    fn error_names_the_cluster() {
        let err = validate_application_metadata(&with_protocol("Bad"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("test"), "error should name the cluster: {err}");
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    fn with_protocol(value: &str) -> Cluster {
        let mut cluster = Cluster::with_defaults("test", vec!["10.0.0.1:80".into()]);
        cluster.http.application_protocol = Some(Arc::from(value));
        cluster
    }

    fn with_provider(value: &str) -> Cluster {
        let mut cluster = Cluster::with_defaults("test", vec!["10.0.0.1:80".into()]);
        cluster.http.application_provider = Some(Arc::from(value));
        cluster
    }

    fn ok(value: &str) {
        validate_application_metadata(&with_protocol(value))
            .unwrap_or_else(|e| panic!("expected Ok for protocol {value:?}, got: {e}"));
        validate_application_metadata(&with_provider(value))
            .unwrap_or_else(|e| panic!("expected Ok for provider {value:?}, got: {e}"));
    }

    fn err(value: &str) -> String {
        validate_application_metadata(&with_protocol(value))
            .unwrap_err()
            .to_string()
    }
}
