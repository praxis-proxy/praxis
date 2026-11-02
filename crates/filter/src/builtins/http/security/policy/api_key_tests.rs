// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! API-key enforcement tests, available without the JWT builtin.

use std::collections::HashMap;

use http::{HeaderValue, Method};
use tempfile::TempDir;

use super::{
    config::{BodyAccessMode, ContextMetaConfig, PolicyFilterConfig},
    filter::PolicyFilter,
};
use crate::{
    AuthenticatedIdentity, FilterAction,
    filter::HttpFilter as _,
    test_utils::{make_filter_context, make_request},
};

const TEST_API_KEY: &str = "sk-test-alice";
const TEST_API_KEY_DIGEST: &str = "sha256:4d692786b022a5d5a48381dcaf1e5e346366feb5579a1d699de2991d153b05f9";

/// Create a one-key policy config with `identity/api-key` as its only resolver.
#[expect(clippy::too_many_lines, reason = "the YAML fixture is the behavior under test")]
fn write_api_key_config() -> (TempDir, String) {
    let dir = TempDir::new().expect("create tempdir");
    let keys_path = dir.path().join("keys.yaml");
    std::fs::write(
        &keys_path,
        format!("keys:\n  - hash: \"{TEST_API_KEY_DIGEST}\"\n    user: alice\n"),
    )
    .expect("write keys.yaml");
    let cfg_path = dir.path().join("cpex.yaml");
    let yaml = format!(
        r#"plugins:
  - name: api-keys
    kind: identity/api-key
    hooks:
      - identity.resolve
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
  authentication:
    - api-keys
  authorization:
    pre_invocation:
      - "require(authenticated)"
"#,
        keys = keys_path.display()
    );
    std::fs::write(&cfg_path, yaml).expect("write cpex.yaml");
    (dir, cfg_path.to_str().expect("utf8 path").to_owned())
}

/// Dispatch one request and return its rejection status and resolved subject.
async fn dispatch_api_key(authorization: Option<&str>) -> (Option<u16>, Option<String>) {
    let (_dir, path) = write_api_key_config();
    let filter = build_filter(path);
    let mut req = make_request(Method::GET, "/");
    if let Some(value) = authorization {
        req.headers
            .insert("Authorization", HeaderValue::from_str(value).expect("header value"));
    }
    let mut ctx = make_filter_context(&req);
    let status = match filter.on_request(&mut ctx).await.expect("filter ran") {
        FilterAction::Continue => None,
        FilterAction::Reject(rejection) => Some(rejection.status),
        _ => panic!("api-key dispatch must Continue or Reject"),
    };
    let subject = ctx
        .extensions
        .get::<AuthenticatedIdentity>()
        .map(|identity| identity.subject_id().to_owned());
    (status, subject)
}

/// Build a policy filter with the normal request metadata requirement.
fn build_filter(config_path: String) -> PolicyFilter {
    let cfg = PolicyFilterConfig {
        config_path,
        allow_private_idp: false,
        trusted_private_endpoints: vec![],
        body_access: BodyAccessMode::ReadOnly,
        require_protocol_metadata: true,
        init_timeout_secs: 30,
        max_buffer_bytes: 10_485_760,
        llm: super::config::LlmOptions::default(),
        context_headers: HashMap::default(),
        context_meta: ContextMetaConfig::default(),
    };
    PolicyFilter::new(cfg, None).expect("filter should construct")
}

#[tokio::test(flavor = "multi_thread")]
async fn api_key_known_key_resolves_identity() {
    if let Err(error) = ppe::validate_api_key_crypto() {
        let (status, subject) = dispatch_api_key(Some(&format!("Bearer {TEST_API_KEY}"))).await;
        assert_eq!(
            status,
            Some(401),
            "an unavailable FIPS digest must reject the key: {error}"
        );
        assert_eq!(subject, None, "an unavailable digest must not publish identity");
        return;
    }

    let (status, subject) = dispatch_api_key(Some(&format!("Bearer {TEST_API_KEY}"))).await;
    assert_eq!(status, None, "a known key must Continue");
    assert_eq!(subject.as_deref(), Some("alice"));
}

#[tokio::test(flavor = "multi_thread")]
async fn api_key_unknown_key_is_rejected() {
    let (status, subject) = dispatch_api_key(Some("Bearer sk-test-mallory")).await;
    assert_eq!(status, Some(401), "an unknown key must be rejected 401");
    assert_eq!(subject, None, "no identity is published on a rejection");
}

#[tokio::test(flavor = "multi_thread")]
async fn api_key_missing_key_is_rejected() {
    let (status, subject) = dispatch_api_key(None).await;
    assert_eq!(status, Some(401), "a request with no key must be rejected 401");
    assert_eq!(subject, None, "no identity is published on a rejection");
}
