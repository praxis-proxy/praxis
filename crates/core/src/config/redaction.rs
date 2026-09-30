// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Redaction of credential-bearing condition headers in operator views.

use std::collections::HashMap;

use super::{Condition, ResponseCondition};

/// Substrings that mark a header name as credential-bearing (case-insensitive).
const SENSITIVE_HEADER_SUBSTRINGS: &[&str] = &["token", "secret", "key", "auth", "password", "credential"];

/// Well-known credential-bearing headers without relying on substring matches.
const CREDENTIAL_HEADER_NAMES: &[&str] = &[
    "authorization",
    "cookie",
    "proxy-authorization",
    "set-cookie",
    "x-amz-security-token",
    "x-api-key",
    "x-auth-token",
];

/// Whether a header name is treated as credential-bearing in operator views.
///
/// Matches well-known names and sensitive substrings case-insensitively.
#[must_use]
pub fn is_credential_header_name(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    CREDENTIAL_HEADER_NAMES.contains(&name.as_str())
        || SENSITIVE_HEADER_SUBSTRINGS.iter().any(|frag| name.contains(frag))
}

/// Replace credential-bearing header matcher values in request conditions.
pub fn redact_condition_headers(conditions: &mut [Condition]) {
    for condition in conditions {
        let (Condition::When(matcher) | Condition::Unless(matcher)) = condition;
        redact_header_matcher(matcher.headers.as_mut());
    }
}

/// Replace credential-bearing header matcher values in response conditions.
pub fn redact_response_condition_headers(conditions: &mut [ResponseCondition]) {
    for condition in conditions {
        let (ResponseCondition::When(matcher) | ResponseCondition::Unless(matcher)) = condition;
        redact_header_matcher(matcher.headers.as_mut());
    }
}

/// Replace credential-bearing values in one header matcher map.
fn redact_header_matcher(headers: Option<&mut HashMap<String, String>>) {
    let Some(headers) = headers else {
        return;
    };
    let credential_keys: Vec<String> = headers
        .keys()
        .filter(|name| is_credential_header_name(name))
        .cloned()
        .collect();
    for key in credential_keys {
        if let Some(value) = headers.get_mut(&key) {
            "[REDACTED]".clone_into(value);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_condition_redaction_preserves_non_credential_matchers() -> Result<(), serde_yaml::Error> {
        let mut request: Vec<Condition> = serde_yaml::from_str(concat!(
            "- when:\n",
            "    headers:\n",
            "      Authorization: Bearer secret\n",
            "      x-tenant: acme\n",
            "- unless:\n",
            "    headers:\n",
            "      X-Api-Key: another-secret\n",
        ))?;
        redact_condition_headers(&mut request);
        let yaml = serde_yaml::to_string(&request)?;
        assert!(
            !yaml.contains("Bearer secret"),
            "request credential should be redacted: {yaml}"
        );
        assert!(
            !yaml.contains("another-secret"),
            "unless credential should be redacted: {yaml}"
        );
        assert!(
            yaml.contains("acme"),
            "non-credential request matcher should remain: {yaml}"
        );
        Ok(())
    }

    #[test]
    fn response_condition_redaction_preserves_non_credential_matchers() -> Result<(), serde_yaml::Error> {
        let mut response: Vec<ResponseCondition> = serde_yaml::from_str(concat!(
            "- when:\n",
            "    headers:\n",
            "      Set-Cookie: session=secret\n",
            "      content-type: application/json\n",
        ))?;
        redact_response_condition_headers(&mut response);
        let yaml = serde_yaml::to_string(&response)?;
        assert!(
            !yaml.contains("session=secret"),
            "response credential should be redacted: {yaml}"
        );
        assert!(
            yaml.contains("application/json"),
            "non-credential response matcher should remain: {yaml}"
        );
        Ok(())
    }
}
