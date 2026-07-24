// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Tests for the iterative request router filter.

use super::config::{self, IterativeRequestRouterConfig};
use crate::factory::parse_filter_config;

// ---------------------------------------------------------------------------
// Config Validation
// ---------------------------------------------------------------------------

#[test]
fn valid_minimal_config() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        "
initial_step: step1
steps:
  - name: step1
    filters:
      - filter: static_response
        status: 200
    on_result:
      - default: true
        done: true
",
    )
    .unwrap();
    let cfg: IterativeRequestRouterConfig = parse_filter_config("iterative_request_router", &yaml).unwrap();
    assert!(
        config::validate(&cfg).is_ok(),
        "minimal valid config should pass validation"
    );
}

#[test]
fn rejects_zero_max_iterations() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        "
initial_step: step1
max_iterations: 0
steps:
  - name: step1
    filters:
      - filter: static_response
        status: 200
    on_result:
      - default: true
        done: true
",
    )
    .unwrap();
    let cfg: IterativeRequestRouterConfig = parse_filter_config("iterative_request_router", &yaml).unwrap();
    let err = config::validate(&cfg).unwrap_err();
    assert!(
        err.to_string().contains("max_iterations"),
        "error should mention max_iterations: {err}"
    );
}

#[test]
fn rejects_max_iterations_above_ceiling() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        "
initial_step: step1
max_iterations: 101
steps:
  - name: step1
    filters:
      - filter: static_response
        status: 200
    on_result:
      - default: true
        done: true
",
    )
    .unwrap();
    let cfg: IterativeRequestRouterConfig = parse_filter_config("iterative_request_router", &yaml).unwrap();
    let err = config::validate(&cfg).unwrap_err();
    assert!(
        err.to_string().contains("max_iterations"),
        "error should mention max_iterations: {err}"
    );
}

#[test]
fn rejects_empty_steps() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        "
initial_step: step1
steps: []
",
    )
    .unwrap();
    let cfg: IterativeRequestRouterConfig = parse_filter_config("iterative_request_router", &yaml).unwrap();
    let err = config::validate(&cfg).unwrap_err();
    assert!(
        err.to_string().contains("at least one step"),
        "error should mention empty steps: {err}"
    );
}

#[test]
fn rejects_missing_initial_step() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        "
initial_step: nonexistent
steps:
  - name: step1
    filters:
      - filter: static_response
        status: 200
    on_result:
      - default: true
        done: true
",
    )
    .unwrap();
    let cfg: IterativeRequestRouterConfig = parse_filter_config("iterative_request_router", &yaml).unwrap();
    let err = config::validate(&cfg).unwrap_err();
    assert!(
        err.to_string().contains("not found"),
        "error should mention missing step: {err}"
    );
}

#[test]
fn rejects_duplicate_step_names() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        "
initial_step: step1
steps:
  - name: step1
    filters:
      - filter: static_response
        status: 200
    on_result:
      - default: true
        done: true
  - name: step1
    filters:
      - filter: static_response
        status: 200
    on_result:
      - default: true
        done: true
",
    )
    .unwrap();
    let cfg: IterativeRequestRouterConfig = parse_filter_config("iterative_request_router", &yaml).unwrap();
    let err = config::validate(&cfg).unwrap_err();
    assert!(
        err.to_string().contains("duplicate"),
        "error should mention duplicate: {err}"
    );
}

#[test]
fn rejects_branch_chains_in_step_filters() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        "
initial_step: step1
steps:
  - name: step1
    filters:
      - filter: static_response
        status: 200
        branch_chains:
          - name: branch1
            chains:
              - name: inline1
                filters:
                  - filter: static_response
                    status: 200
    on_result:
      - default: true
        done: true
",
    )
    .unwrap();
    let cfg: IterativeRequestRouterConfig = parse_filter_config("iterative_request_router", &yaml).unwrap();
    let err = config::validate(&cfg).unwrap_err();
    assert!(
        err.to_string().contains("branch_chains not allowed"),
        "error should reject branch_chains in steps: {err}"
    );
}

#[test]
fn rejects_nested_iterative_request_router() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        "
initial_step: outer
steps:
  - name: outer
    filters:
      - filter: iterative_request_router
        initial_step: inner
        steps:
          - name: inner
            filters:
              - filter: static_response
                status: 200
            on_result:
              - default: true
                done: true
    on_result:
      - default: true
        done: true
",
    )
    .unwrap();
    let cfg: IterativeRequestRouterConfig = parse_filter_config("iterative_request_router", &yaml).unwrap();
    let err = config::validate(&cfg).unwrap_err();
    assert!(err.to_string().contains("nested"), "should reject nested IRR: {err}");
}

#[test]
fn rejects_done_and_next_together() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        "
initial_step: step1
steps:
  - name: step1
    filters:
      - filter: static_response
        status: 200
    on_result:
      - default: true
        done: true
        next: step1
",
    )
    .unwrap();
    let cfg: IterativeRequestRouterConfig = parse_filter_config("iterative_request_router", &yaml).unwrap();
    let err = config::validate(&cfg).unwrap_err();
    assert!(
        err.to_string().contains("mutually exclusive"),
        "error should reject done + next: {err}"
    );
}

#[test]
fn rejects_transition_to_unknown_step() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        "
initial_step: step1
steps:
  - name: step1
    filters:
      - filter: static_response
        status: 200
    on_result:
      - default: true
        next: nonexistent
",
    )
    .unwrap();
    let cfg: IterativeRequestRouterConfig = parse_filter_config("iterative_request_router", &yaml).unwrap();
    let err = config::validate(&cfg).unwrap_err();
    assert!(
        err.to_string().contains("unknown step"),
        "error should mention unknown step: {err}"
    );
}

#[test]
fn rejects_zero_timeout() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        "
initial_step: step1
timeout_ms: 0
steps:
  - name: step1
    filters:
      - filter: static_response
        status: 200
    on_result:
      - default: true
        done: true
",
    )
    .unwrap();
    let cfg: IterativeRequestRouterConfig = parse_filter_config("iterative_request_router", &yaml).unwrap();
    let err = config::validate(&cfg).unwrap_err();
    assert!(
        err.to_string().contains("timeout_ms"),
        "error should mention timeout: {err}"
    );
}

#[test]
fn accepts_multi_step_config() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
initial_step: primary
steps:
  - name: primary
    filters:
      - filter: static_response
        status: 200
    on_result:
      - filter: static_response
        key: status
        value: "503"
        next: fallback
      - default: true
        done: true
  - name: fallback
    filters:
      - filter: static_response
        status: 200
    on_result:
      - default: true
        done: true
"#,
    )
    .unwrap();
    let cfg: IterativeRequestRouterConfig = parse_filter_config("iterative_request_router", &yaml).unwrap();
    assert!(config::validate(&cfg).is_ok(), "multi-step config should be valid");
}

// ---------------------------------------------------------------------------
// Filter Construction
// ---------------------------------------------------------------------------

#[test]
fn from_config_builds_filter() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        "
initial_step: step1
steps:
  - name: step1
    filters:
      - filter: static_response
        status: 200
    on_result:
      - default: true
        done: true
",
    )
    .unwrap();
    let filter = super::IterativeRequestRouterFilter::from_config(&yaml);
    assert!(filter.is_ok(), "from_config should succeed: {:?}", filter.err());
    assert_eq!(filter.unwrap().name(), "iterative_request_router");
}

#[test]
fn accepts_status_transition_config() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        "
initial_step: primary
steps:
  - name: primary
    filters:
      - filter: static_response
        status: 200
    on_result:
      - status: [502, 503, 504]
        next: fallback
      - default: true
        done: true
  - name: fallback
    filters:
      - filter: static_response
        status: 200
    on_result:
      - default: true
        done: true
",
    )
    .unwrap();
    let cfg: IterativeRequestRouterConfig = parse_filter_config("iterative_request_router", &yaml).unwrap();
    assert!(
        config::validate(&cfg).is_ok(),
        "status transition config should be valid"
    );
}

// ---------------------------------------------------------------------------
// Transition Evaluation
// ---------------------------------------------------------------------------

#[test]
fn transition_default_returns_done() {
    let transitions = vec![make_default_done()];
    let response = make_response(200);
    let results = std::collections::HashMap::new();
    let result = super::evaluate_transitions(&transitions, &response, &results);
    assert!(
        matches!(result, super::TransitionResult::Done),
        "default done should return Done"
    );
}

#[test]
fn transition_status_match_triggers_next() {
    let transitions = vec![
        config::StepTransition {
            default: false,
            done: false,
            filter: None,
            key: None,
            next: Some("fallback".to_owned()),
            status: Some(vec![502, 503]),
            value: None,
        },
        make_default_done(),
    ];
    let response = make_response(503);
    let results = std::collections::HashMap::new();
    let result = super::evaluate_transitions(&transitions, &response, &results);
    assert!(
        matches!(result, super::TransitionResult::Next(s) if s.as_ref() == "fallback"),
        "status 503 should match [502, 503] and transition to fallback"
    );
}

#[test]
fn transition_status_no_match_falls_through() {
    let transitions = vec![
        config::StepTransition {
            default: false,
            done: false,
            filter: None,
            key: None,
            next: Some("fallback".to_owned()),
            status: Some(vec![502, 503]),
            value: None,
        },
        make_default_done(),
    ];
    let response = make_response(200);
    let results = std::collections::HashMap::new();
    let result = super::evaluate_transitions(&transitions, &response, &results);
    assert!(
        matches!(result, super::TransitionResult::Done),
        "status 200 should not match [502, 503], fall through to default done"
    );
}

#[test]
fn transition_filter_result_match() {
    let transitions = vec![
        config::StepTransition {
            default: false,
            done: false,
            filter: Some("classifier".to_owned()),
            key: Some("has_tools".to_owned()),
            next: Some("tools".to_owned()),
            status: None,
            value: Some("true".to_owned()),
        },
        make_default_done(),
    ];
    let response = make_response(200);
    let mut results = std::collections::HashMap::new();
    let mut rs = crate::results::FilterResultSet::new();
    rs.set("has_tools", "true").unwrap();
    results.insert("classifier", rs);
    let result = super::evaluate_transitions(&transitions, &response, &results);
    assert!(
        matches!(result, super::TransitionResult::Next(s) if s.as_ref() == "tools"),
        "matching filter result should transition to tools"
    );
}

#[test]
fn transition_no_transitions_returns_no_match() {
    let transitions: Vec<config::StepTransition> = vec![];
    let response = make_response(200);
    let results = std::collections::HashMap::new();
    let result = super::evaluate_transitions(&transitions, &response, &results);
    assert!(
        matches!(result, super::TransitionResult::NoMatch),
        "empty transitions should return NoMatch"
    );
}

#[test]
fn transition_first_match_wins() {
    let transitions = vec![
        config::StepTransition {
            default: false,
            done: false,
            filter: None,
            key: None,
            next: Some("first".to_owned()),
            status: Some(vec![200]),
            value: None,
        },
        config::StepTransition {
            default: false,
            done: false,
            filter: None,
            key: None,
            next: Some("second".to_owned()),
            status: Some(vec![200]),
            value: None,
        },
    ];
    let response = make_response(200);
    let results = std::collections::HashMap::new();
    let result = super::evaluate_transitions(&transitions, &response, &results);
    assert!(
        matches!(result, super::TransitionResult::Next(s) if s.as_ref() == "first"),
        "first matching transition should win"
    );
}

// ---------------------------------------------------------------------------
// Response Building
// ---------------------------------------------------------------------------

#[test]
fn build_rejection_preserves_status() {
    let response = make_response(201);
    let rejection = super::build_response_rejection(&response);
    assert_eq!(rejection.status, 201, "rejection status should match response");
}

#[test]
fn build_rejection_preserves_body() {
    use crate::pipeline::subrequest::SubResponse;

    let response = SubResponse {
        status: 200,
        headers: http::HeaderMap::new(),
        body: bytes::Bytes::from_static(b"test body"),
    };
    let rejection = super::build_response_rejection(&response);
    assert_eq!(
        rejection.body.as_deref(),
        Some(b"test body".as_slice()),
        "rejection body should match response body"
    );
}

#[test]
fn build_rejection_preserves_headers() {
    use crate::pipeline::subrequest::SubResponse;

    let mut headers = http::HeaderMap::new();
    headers.insert("content-type", "application/json".parse().unwrap());
    let response = SubResponse {
        status: 200,
        headers,
        body: bytes::Bytes::new(),
    };
    let rejection = super::build_response_rejection(&response);
    assert!(
        rejection
            .headers
            .iter()
            .any(|(k, v)| k == "content-type" && v == "application/json"),
        "rejection should preserve content-type header"
    );
}

// ---------------------------------------------------------------------------
// Test Utilities
// ---------------------------------------------------------------------------

/// Build a default-done transition.
fn make_default_done() -> config::StepTransition {
    config::StepTransition {
        default: true,
        done: true,
        filter: None,
        key: None,
        next: None,
        status: None,
        value: None,
    }
}

/// Build a minimal `SubResponse` with the given status.
fn make_response(status: u16) -> crate::pipeline::subrequest::SubResponse {
    crate::pipeline::subrequest::SubResponse {
        status,
        headers: http::HeaderMap::new(),
        body: bytes::Bytes::new(),
    }
}

// ---------------------------------------------------------------------------
// parse_depth
// ---------------------------------------------------------------------------

#[test]
fn parse_depth_missing_header() {
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    assert_eq!(super::parse_depth(&req), 0, "missing header should return 0");
}

#[test]
fn parse_depth_valid_one() {
    let mut req = crate::test_utils::make_request(http::Method::GET, "/");
    req.headers
        .insert(super::DEPTH_HEADER, http::HeaderValue::from_static("1"));
    assert_eq!(super::parse_depth(&req), 1);
}

#[test]
fn parse_depth_valid_three() {
    let mut req = crate::test_utils::make_request(http::Method::GET, "/");
    req.headers
        .insert(super::DEPTH_HEADER, http::HeaderValue::from_static("3"));
    assert_eq!(super::parse_depth(&req), 3);
}

#[test]
fn parse_depth_non_numeric() {
    let mut req = crate::test_utils::make_request(http::Method::GET, "/");
    req.headers
        .insert(super::DEPTH_HEADER, http::HeaderValue::from_static("abc"));
    assert_eq!(super::parse_depth(&req), 0, "non-numeric should return 0");
}

#[test]
fn parse_depth_overflow() {
    let mut req = crate::test_utils::make_request(http::Method::GET, "/");
    req.headers
        .insert(super::DEPTH_HEADER, http::HeaderValue::from_static("256"));
    assert_eq!(super::parse_depth(&req), 0, "overflow should return 0");
}

#[test]
fn parse_depth_negative() {
    let mut req = crate::test_utils::make_request(http::Method::GET, "/");
    req.headers
        .insert(super::DEPTH_HEADER, http::HeaderValue::from_static("-1"));
    assert_eq!(super::parse_depth(&req), 0, "negative should return 0");
}

#[test]
fn parse_depth_empty_string() {
    let mut req = crate::test_utils::make_request(http::Method::GET, "/");
    req.headers
        .insert(super::DEPTH_HEADER, http::HeaderValue::from_static(""));
    assert_eq!(super::parse_depth(&req), 0, "empty should return 0");
}

// ---------------------------------------------------------------------------
// strip_reserved_headers
// ---------------------------------------------------------------------------

#[test]
fn strip_reserved_empty_map() {
    let mut headers = http::HeaderMap::new();
    super::strip_reserved_headers(&mut headers);
    assert!(headers.is_empty(), "empty map should stay empty");
}

#[test]
fn strip_reserved_praxis_prefix() {
    let mut headers = http::HeaderMap::new();
    headers.insert("x-praxis-foo", "bar".parse().unwrap());
    super::strip_reserved_headers(&mut headers);
    assert!(headers.is_empty(), "x-praxis-* should be removed");
}

#[test]
fn strip_reserved_ext_protocol_prefix() {
    let mut headers = http::HeaderMap::new();
    headers.insert("x-ext-protocol-route", "value".parse().unwrap());
    super::strip_reserved_headers(&mut headers);
    assert!(headers.is_empty(), "x-ext-protocol-* should be removed");
}

#[test]
fn strip_reserved_ext_agent_prefix() {
    let mut headers = http::HeaderMap::new();
    headers.insert("x-ext-agent-task", "value".parse().unwrap());
    super::strip_reserved_headers(&mut headers);
    assert!(headers.is_empty(), "x-ext-agent-* should be removed");
}

#[test]
fn strip_reserved_preserves_non_reserved() {
    let mut headers = http::HeaderMap::new();
    headers.insert("authorization", "Bearer token".parse().unwrap());
    headers.insert("content-type", "application/json".parse().unwrap());
    super::strip_reserved_headers(&mut headers);
    assert_eq!(headers.len(), 2, "non-reserved headers should be preserved");
}

#[test]
fn strip_reserved_mixed() {
    let mut headers = http::HeaderMap::new();
    headers.insert("authorization", "Bearer token".parse().unwrap());
    headers.insert("x-praxis-internal", "secret".parse().unwrap());
    headers.insert("x-ext-agent-id", "agent1".parse().unwrap());
    headers.insert("x-custom", "value".parse().unwrap());
    super::strip_reserved_headers(&mut headers);
    assert_eq!(headers.len(), 2, "only reserved should be removed");
    assert!(headers.contains_key("authorization"));
    assert!(headers.contains_key("x-custom"));
}

#[test]
fn strip_reserved_no_dash_not_removed() {
    let mut headers = http::HeaderMap::new();
    headers.insert("x-praxisfoo", "value".parse().unwrap());
    super::strip_reserved_headers(&mut headers);
    assert_eq!(
        headers.len(),
        1,
        "x-praxisfoo (no dash after prefix) should NOT be removed"
    );
}

// ---------------------------------------------------------------------------
// max_depth
// ---------------------------------------------------------------------------

#[test]
fn max_depth_is_three() {
    assert_eq!(config::max_depth(), 3, "max_depth should be 3");
}

// ---------------------------------------------------------------------------
// Config Validation - Boundaries
// ---------------------------------------------------------------------------

#[test]
fn accepts_max_iterations_one() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        "
initial_step: s
max_iterations: 1
steps:
  - name: s
    filters:
      - filter: static_response
        status: 200
    on_result:
      - default: true
        done: true
",
    )
    .unwrap();
    let cfg: IterativeRequestRouterConfig = parse_filter_config("iterative_request_router", &yaml).unwrap();
    assert!(config::validate(&cfg).is_ok(), "max_iterations=1 should be valid");
}

#[test]
fn accepts_max_iterations_ceiling() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        "
initial_step: s
max_iterations: 100
steps:
  - name: s
    filters:
      - filter: static_response
        status: 200
    on_result:
      - default: true
        done: true
",
    )
    .unwrap();
    let cfg: IterativeRequestRouterConfig = parse_filter_config("iterative_request_router", &yaml).unwrap();
    assert!(config::validate(&cfg).is_ok(), "max_iterations=100 should be valid");
}

#[test]
fn rejects_too_many_steps() {
    let yaml = build_n_step_yaml(21);
    let cfg: IterativeRequestRouterConfig = parse_filter_config("iterative_request_router", &yaml).unwrap();
    let err = config::validate(&cfg).unwrap_err();
    assert!(err.to_string().contains("steps"), "should reject >20 steps: {err}");
}

#[test]
fn accepts_max_steps() {
    let yaml = build_n_step_yaml(20);
    let cfg: IterativeRequestRouterConfig = parse_filter_config("iterative_request_router", &yaml).unwrap();
    assert!(config::validate(&cfg).is_ok(), "20 steps should be valid");
}

#[test]
fn rejects_step_with_empty_filters() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        "
initial_step: s
steps:
  - name: s
    filters: []
    on_result:
      - default: true
        done: true
",
    )
    .unwrap();
    let cfg: IterativeRequestRouterConfig = parse_filter_config("iterative_request_router", &yaml).unwrap();
    let err = config::validate(&cfg).unwrap_err();
    assert!(err.to_string().contains("filter"), "should reject empty filters: {err}");
}

#[test]
fn rejects_multiple_default_transitions() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        "
initial_step: s
steps:
  - name: s
    filters:
      - filter: static_response
        status: 200
    on_result:
      - default: true
        done: true
      - default: true
        next: s
",
    )
    .unwrap();
    let cfg: IterativeRequestRouterConfig = parse_filter_config("iterative_request_router", &yaml).unwrap();
    let err = config::validate(&cfg).unwrap_err();
    assert!(
        err.to_string().contains("default"),
        "should reject multiple defaults: {err}"
    );
}

#[test]
fn rejects_non_default_transition_without_filter() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        "
initial_step: s
steps:
  - name: s
    filters:
      - filter: static_response
        status: 200
    on_result:
      - next: s
",
    )
    .unwrap();
    let cfg: IterativeRequestRouterConfig = parse_filter_config("iterative_request_router", &yaml).unwrap();
    let err = config::validate(&cfg).unwrap_err();
    assert!(
        err.to_string().contains("filter")
            || err.to_string().contains("status")
            || err.to_string().contains("done")
            || err.to_string().contains("next"),
        "should reject non-default without matching condition: {err}"
    );
}

#[test]
fn rejects_transition_without_done_next_or_default() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        "
initial_step: s
steps:
  - name: s
    filters:
      - filter: static_response
        status: 200
    on_result:
      - status: [200]
",
    )
    .unwrap();
    let cfg: IterativeRequestRouterConfig = parse_filter_config("iterative_request_router", &yaml).unwrap();
    let err = config::validate(&cfg).unwrap_err();
    assert!(
        err.to_string().contains("done") || err.to_string().contains("next") || err.to_string().contains("action"),
        "should reject transition without action: {err}"
    );
}

// ---------------------------------------------------------------------------
// Serde Defaults
// ---------------------------------------------------------------------------

#[test]
fn serde_default_max_iterations() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        "
initial_step: s
steps:
  - name: s
    filters:
      - filter: static_response
        status: 200
    on_result:
      - default: true
        done: true
",
    )
    .unwrap();
    let cfg: IterativeRequestRouterConfig = parse_filter_config("iterative_request_router", &yaml).unwrap();
    assert_eq!(cfg.max_iterations, 10, "default max_iterations should be 10");
}

#[test]
fn serde_default_timeout_ms() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        "
initial_step: s
steps:
  - name: s
    filters:
      - filter: static_response
        status: 200
    on_result:
      - default: true
        done: true
",
    )
    .unwrap();
    let cfg: IterativeRequestRouterConfig = parse_filter_config("iterative_request_router", &yaml).unwrap();
    assert_eq!(cfg.timeout_ms, 30_000, "default timeout_ms should be 30000");
}

#[test]
fn serde_default_max_response_bytes() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        "
initial_step: s
steps:
  - name: s
    filters:
      - filter: static_response
        status: 200
    on_result:
      - default: true
        done: true
",
    )
    .unwrap();
    let cfg: IterativeRequestRouterConfig = parse_filter_config("iterative_request_router", &yaml).unwrap();
    assert_eq!(
        cfg.max_response_bytes, 10_485_760,
        "default max_response_bytes should be 10 MiB"
    );
}

#[test]
fn serde_default_max_state_bytes() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        "
initial_step: s
steps:
  - name: s
    filters:
      - filter: static_response
        status: 200
    on_result:
      - default: true
        done: true
",
    )
    .unwrap();
    let cfg: IterativeRequestRouterConfig = parse_filter_config("iterative_request_router", &yaml).unwrap();
    assert_eq!(
        cfg.max_state_bytes, 52_428_800,
        "default max_state_bytes should be 50 MiB"
    );
}

// ---------------------------------------------------------------------------
// deny_unknown_fields
// ---------------------------------------------------------------------------

#[test]
fn rejects_unknown_top_level_key() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        "
initial_step: s
unknown_key: true
steps:
  - name: s
    filters:
      - filter: static_response
        status: 200
    on_result:
      - default: true
        done: true
",
    )
    .unwrap();
    let result: Result<IterativeRequestRouterConfig, _> = parse_filter_config("iterative_request_router", &yaml);
    assert!(result.is_err(), "unknown top-level key should be rejected");
}

#[test]
fn rejects_unknown_step_key() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        "
initial_step: s
steps:
  - name: s
    bogus: true
    filters:
      - filter: static_response
        status: 200
    on_result:
      - default: true
        done: true
",
    )
    .unwrap();
    let result: Result<IterativeRequestRouterConfig, _> = parse_filter_config("iterative_request_router", &yaml);
    assert!(result.is_err(), "unknown step key should be rejected");
}

#[test]
fn rejects_unknown_transition_key() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        "
initial_step: s
steps:
  - name: s
    filters:
      - filter: static_response
        status: 200
    on_result:
      - default: true
        done: true
        bogus: 42
",
    )
    .unwrap();
    let result: Result<IterativeRequestRouterConfig, _> = parse_filter_config("iterative_request_router", &yaml);
    assert!(result.is_err(), "unknown transition key should be rejected");
}

// ---------------------------------------------------------------------------
// Trait Methods
// ---------------------------------------------------------------------------

#[test]
fn request_body_access_returns_read_only() {
    let filter = build_filter();
    assert_eq!(
        filter.request_body_access(),
        crate::body::BodyAccess::ReadOnly,
        "should return ReadOnly"
    );
}

#[test]
fn request_body_mode_returns_stream_buffer() {
    let filter = build_filter();
    let mode = filter.request_body_mode();
    assert!(
        matches!(mode, crate::body::BodyMode::StreamBuffer { max_bytes: Some(_) }),
        "should return StreamBuffer with max_bytes"
    );
}

#[test]
fn from_config_parse_failure() {
    let yaml: serde_yaml::Value = serde_yaml::from_str("not_a_valid_key: true").unwrap();
    let result = super::IterativeRequestRouterFilter::from_config(&yaml);
    assert!(result.is_err(), "invalid YAML should fail");
}

#[test]
fn from_config_validation_failure() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        "
initial_step: nonexistent
steps:
  - name: step1
    filters:
      - filter: static_response
        status: 200
    on_result:
      - default: true
        done: true
",
    )
    .unwrap();
    let result = super::IterativeRequestRouterFilter::from_config(&yaml);
    assert!(result.is_err(), "validation failure should propagate");
}

// ---------------------------------------------------------------------------
// on_request
// ---------------------------------------------------------------------------

#[tokio::test]
async fn on_request_depth_exceeded() {
    let filter = build_filter();
    let mut req = crate::test_utils::make_request(http::Method::POST, "/v1/chat");
    req.headers
        .insert(super::DEPTH_HEADER, http::HeaderValue::from_static("3"));
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let result = filter.on_request(&mut ctx).await.unwrap();
    let is_508 = matches!(&result, crate::FilterAction::Reject(r) if r.status == 508);
    assert!(is_508, "depth >= max_depth should reject with 508");
}

#[tokio::test]
async fn on_request_depth_at_boundary() {
    let filter = build_filter();
    let mut req = crate::test_utils::make_request(http::Method::POST, "/v1/chat");
    req.headers
        .insert(super::DEPTH_HEADER, http::HeaderValue::from_static("2"));
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let result = filter.on_request(&mut ctx).await;
    let is_508 = matches!(&result, Ok(crate::FilterAction::Reject(r)) if r.status == 508);
    assert!(!is_508, "depth 2 < max_depth 3 should not reject with 508");
}

#[tokio::test]
async fn on_request_no_connector() {
    let filter = build_filter();
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/chat");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let result = filter.on_request(&mut ctx).await;
    assert!(result.is_err(), "no connector should return error");
}

// ---------------------------------------------------------------------------
// on_request_body - not end_of_stream
// ---------------------------------------------------------------------------

#[tokio::test]
async fn on_request_body_not_end_of_stream() {
    let filter = build_filter();
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/chat");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(bytes::Bytes::from_static(b"partial"));
    let result = filter.on_request_body(&mut ctx, &mut body, false).await.unwrap();
    assert!(
        matches!(result, crate::FilterAction::Continue),
        "not end_of_stream should return Continue"
    );
}

// ---------------------------------------------------------------------------
// Transition Evaluation - Additional
// ---------------------------------------------------------------------------

#[test]
fn transition_status_and_filter_both_match() {
    let transitions = vec![config::StepTransition {
        default: false,
        done: false,
        filter: Some("classifier".to_owned()),
        key: Some("action".to_owned()),
        next: Some("next-step".to_owned()),
        status: Some(vec![200]),
        value: Some("loop".to_owned()),
    }];
    let response = make_response(200);
    let mut results = std::collections::HashMap::new();
    let mut rs = crate::results::FilterResultSet::new();
    rs.set("action", "loop").unwrap();
    results.insert("classifier", rs);
    let result = super::evaluate_transitions(&transitions, &response, &results);
    assert!(
        matches!(result, super::TransitionResult::Next(s) if s.as_ref() == "next-step"),
        "both status and filter match should fire"
    );
}

#[test]
fn transition_status_match_filter_no_match() {
    let transitions = vec![config::StepTransition {
        default: false,
        done: false,
        filter: Some("classifier".to_owned()),
        key: Some("action".to_owned()),
        next: Some("next-step".to_owned()),
        status: Some(vec![200]),
        value: Some("loop".to_owned()),
    }];
    let response = make_response(200);
    let results = std::collections::HashMap::new();
    let result = super::evaluate_transitions(&transitions, &response, &results);
    assert!(
        matches!(result, super::TransitionResult::NoMatch),
        "status match but filter miss should not fire"
    );
}

#[test]
fn transition_status_no_match_filter_match() {
    let transitions = vec![config::StepTransition {
        default: false,
        done: false,
        filter: Some("classifier".to_owned()),
        key: Some("action".to_owned()),
        next: Some("next-step".to_owned()),
        status: Some(vec![503]),
        value: Some("loop".to_owned()),
    }];
    let response = make_response(200);
    let mut results = std::collections::HashMap::new();
    let mut rs = crate::results::FilterResultSet::new();
    rs.set("action", "loop").unwrap();
    results.insert("classifier", rs);
    let result = super::evaluate_transitions(&transitions, &response, &results);
    assert!(
        matches!(result, super::TransitionResult::NoMatch),
        "status miss but filter match should not fire"
    );
}

#[test]
fn transition_partial_fields_filter_key_no_value() {
    let transitions = vec![config::StepTransition {
        default: false,
        done: false,
        filter: Some("f".to_owned()),
        key: Some("k".to_owned()),
        next: Some("n".to_owned()),
        status: None,
        value: None,
    }];
    let response = make_response(200);
    let results = std::collections::HashMap::new();
    let result = super::evaluate_transitions(&transitions, &response, &results);
    assert!(
        matches!(result, super::TransitionResult::NoMatch),
        "filter+key without value should not match"
    );
}

#[test]
fn transition_partial_fields_filter_no_key_has_value() {
    let transitions = vec![config::StepTransition {
        default: false,
        done: false,
        filter: Some("f".to_owned()),
        key: None,
        next: Some("n".to_owned()),
        status: None,
        value: Some("v".to_owned()),
    }];
    let response = make_response(200);
    let results = std::collections::HashMap::new();
    let result = super::evaluate_transitions(&transitions, &response, &results);
    assert!(
        matches!(result, super::TransitionResult::NoMatch),
        "filter+value without key should not match"
    );
}

#[test]
fn transition_default_without_done_or_next_returns_done() {
    let transitions = vec![config::StepTransition {
        default: true,
        done: false,
        filter: None,
        key: None,
        next: None,
        status: None,
        value: None,
    }];
    let response = make_response(200);
    let results = std::collections::HashMap::new();
    let result = super::evaluate_transitions(&transitions, &response, &results);
    assert!(
        matches!(result, super::TransitionResult::Done),
        "default without done/next should return Done"
    );
}

#[test]
fn transition_non_default_done_on_status_match() {
    let transitions = vec![config::StepTransition {
        default: false,
        done: true,
        filter: None,
        key: None,
        next: None,
        status: Some(vec![200]),
        value: None,
    }];
    let response = make_response(200);
    let results = std::collections::HashMap::new();
    let result = super::evaluate_transitions(&transitions, &response, &results);
    assert!(
        matches!(result, super::TransitionResult::Done),
        "status match with done=true should return Done"
    );
}

#[test]
fn transition_filter_wrong_value_no_match() {
    let transitions = vec![config::StepTransition {
        default: false,
        done: false,
        filter: Some("classifier".to_owned()),
        key: Some("action".to_owned()),
        next: Some("n".to_owned()),
        status: None,
        value: Some("loop".to_owned()),
    }];
    let response = make_response(200);
    let mut results = std::collections::HashMap::new();
    let mut rs = crate::results::FilterResultSet::new();
    rs.set("action", "done").unwrap();
    results.insert("classifier", rs);
    let result = super::evaluate_transitions(&transitions, &response, &results);
    assert!(
        matches!(result, super::TransitionResult::NoMatch),
        "wrong filter value should not match"
    );
}

// ---------------------------------------------------------------------------
// build_response_rejection - Additional
// ---------------------------------------------------------------------------

#[test]
fn build_rejection_empty_body_has_no_body() {
    let response = make_response(200);
    let rejection = super::build_response_rejection(&response);
    assert!(
        rejection.body.is_none(),
        "empty response body should result in None rejection body"
    );
}

#[test]
fn build_rejection_multiple_headers() {
    use crate::pipeline::subrequest::SubResponse;

    let mut headers = http::HeaderMap::new();
    headers.insert("content-type", "application/json".parse().unwrap());
    headers.insert("x-request-id", "abc123".parse().unwrap());
    let response = SubResponse {
        status: 200,
        headers,
        body: bytes::Bytes::new(),
    };
    let rejection = super::build_response_rejection(&response);
    assert!(rejection.headers.len() >= 2, "rejection should preserve all headers");
}

// ---------------------------------------------------------------------------
// Additional Test Utility
// ---------------------------------------------------------------------------

/// Build YAML with `n` steps chained s0 -> s1 -> ... -> s(n-1).
fn build_n_step_yaml(n: usize) -> serde_yaml::Value {
    use std::fmt::Write as _;

    let mut yaml = String::from("initial_step: s0\nsteps:");
    for i in 0..n {
        write!(yaml, "\n  - name: s{i}").unwrap();
        yaml.push_str(
            "\n    filters:\n      - filter: static_response\n        status: 200\n    on_result:\n      - default: true",
        );
        if i + 1 < n {
            write!(yaml, "\n        next: s{}", i + 1).unwrap();
        } else {
            yaml.push_str("\n        done: true");
        }
    }
    serde_yaml::from_str(&yaml).unwrap()
}

/// Build a filter from a minimal valid config for trait method tests.
fn build_filter() -> Box<dyn crate::HttpFilter> {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        "
initial_step: s
steps:
  - name: s
    filters:
      - filter: static_response
        status: 200
    on_result:
      - default: true
        done: true
",
    )
    .unwrap();
    super::IterativeRequestRouterFilter::from_config(&yaml).unwrap()
}
