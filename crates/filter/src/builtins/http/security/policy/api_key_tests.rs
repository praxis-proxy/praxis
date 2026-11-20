// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

#![expect(
    clippy::tests_outside_test_module,
    reason = "test functions live in this cfg(test) module"
)]

//! API-key enforcement tests, available without the JWT builtin. A missing
//! crypto provider fails construction rather than answering 401; that case
//! needs its own process and lives in `fips_startup_tests.rs`.

use http::{HeaderValue, Method};

use super::{
    feature_tests::{filter_config, write_policy},
    filter::PolicyFilter,
};
use crate::{
    AuthenticatedIdentity, FilterAction,
    filter::HttpFilter as _,
    test_utils::{make_filter_context, make_request},
};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// The key the fixture's directory knows.
const TEST_API_KEY: &str = "sk-test-alice";

/// SHA-256 of [`TEST_API_KEY`].
///
/// [`TEST_API_KEY`]: TEST_API_KEY
const TEST_API_KEY_DIGEST: &str = "sha256:4d692786b022a5d5a48381dcaf1e5e346366feb5579a1d699de2991d153b05f9";

/// A policy whose only identity resolver is `identity/api-key`, requiring an
/// authenticated caller; `{keys}` is the key file path.
const API_KEY_POLICY: &str = r#"plugins:
  - name: api-keys
    kind: identity/api-key
    hooks: [identity.resolve]
    on_error: fail
    config:
      credential:
        kind: header
        name: Authorization
      prefix: "Bearer sk-test-"
      provider:
        kind: file
        path: "{keys}"
        index: sha256
      record_map:
        subject:
          id: user
global:
  authentication: [api-keys]
  authorization:
    pre_invocation:
      - "require(authenticated)"
"#;

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn a_known_api_key_resolves_identity() {
    let (status, subject) = dispatch_api_key(Some(&format!("Bearer {TEST_API_KEY}"))).await;
    assert_eq!(status, None, "a known key must Continue");
    assert_eq!(
        subject.as_deref(),
        Some("alice"),
        "a known key must publish its subject"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unknown_api_key_is_rejected() {
    let (status, subject) = dispatch_api_key(Some("Bearer sk-test-mallory")).await;
    assert_eq!(status, Some(401), "an unknown key must be rejected 401");
    assert_eq!(subject, None, "no identity is published on a rejection");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_missing_api_key_is_rejected() {
    let (status, subject) = dispatch_api_key(None).await;
    assert_eq!(status, Some(401), "a request with no key must be rejected 401");
    assert_eq!(subject, None, "no identity is published on a rejection");
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Dispatch one request and return its rejection status and resolved subject.
async fn dispatch_api_key(authorization: Option<&str>) -> (Option<u16>, Option<String>) {
    let keys_dir = tempfile::TempDir::new().expect("create tempdir");
    let keys = keys_dir.path().join("keys.yaml");
    std::fs::write(
        &keys,
        format!("keys:\n  - hash: \"{TEST_API_KEY_DIGEST}\"\n    user: alice\n"),
    )
    .expect("write keys.yaml");
    let yaml = API_KEY_POLICY.replace("{keys}", keys.to_str().expect("a UTF-8 tempdir path"));
    let (_dir, path) = write_policy(&yaml);
    let filter = PolicyFilter::new(filter_config(path), None).expect("the API-key policy builds");

    let mut req = make_request(Method::GET, "/");
    if let Some(value) = authorization {
        req.headers
            .insert("Authorization", HeaderValue::from_str(value).expect("header value"));
    }
    let mut ctx = make_filter_context(&req);
    let status = match filter.on_request(&mut ctx).await.expect("the filter runs") {
        FilterAction::Continue => None,
        FilterAction::Reject(rejection) => Some(rejection.status),
        other => panic!("API-key dispatch must Continue or Reject, got {other:?}"),
    };
    let subject = ctx
        .extensions
        .get::<AuthenticatedIdentity>()
        .map(|identity| identity.subject_id().to_owned());
    (status, subject)
}
