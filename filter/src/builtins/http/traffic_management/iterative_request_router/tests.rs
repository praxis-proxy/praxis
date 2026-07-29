// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Tests for the iterative request router filter.

use http::HeaderMap;

use super::{
    DEPTH_HEADER,
    config::{self, IterativeRequestRouterConfig},
};
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
fn rejects_protocol_only_compression_step() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        "
initial_step: step1
steps:
  - name: step1
    filters:
      - filter: compression
    on_result:
      - default: true
        done: true
",
    )
    .unwrap();
    let cfg: IterativeRequestRouterConfig = parse_filter_config("iterative_request_router", &yaml).unwrap();
    let err = config::validate(&cfg).unwrap_err();
    assert!(err.to_string().contains("protocol-only"));
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
fn rejects_partial_filter_transition_predicate() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        "
initial_step: step1
steps:
  - name: step1
    filters:
      - filter: static_response
        status: 200
    on_result:
      - filter: classifier
        next: step1
",
    )
    .unwrap();
    let cfg: IterativeRequestRouterConfig = parse_filter_config("iterative_request_router", &yaml).unwrap();
    let err = config::validate(&cfg).unwrap_err();
    assert!(err.to_string().contains("specified together"));
}

#[test]
fn rejects_empty_status_transition_predicate() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        "
initial_step: step1
steps:
  - name: step1
    filters:
      - filter: static_response
        status: 200
    on_result:
      - status: []
        next: step1
",
    )
    .unwrap();
    let cfg: IterativeRequestRouterConfig = parse_filter_config("iterative_request_router", &yaml).unwrap();
    let err = config::validate(&cfg).unwrap_err();
    assert!(err.to_string().contains("must not be empty"));
}

#[test]
fn rejects_out_of_range_status_transition_predicate() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        "
initial_step: step1
steps:
  - name: step1
    filters:
      - filter: static_response
        status: 200
    on_result:
      - status: [700]
        next: step1
",
    )
    .unwrap();
    let cfg: IterativeRequestRouterConfig = parse_filter_config("iterative_request_router", &yaml).unwrap();
    let err = config::validate(&cfg).unwrap_err();
    assert!(err.to_string().contains("100..=599"));
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
fn rejects_timeout_outside_platform_instant_range() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        "
initial_step: step1
timeout_ms: 18446744073709551615
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
    assert!(result.is_err(), "overflowing timeout should be rejected");
    let error = result.err().unwrap();
    assert!(error.to_string().contains("timeout_ms must be <="));
}

#[test]
fn rejects_zero_max_state_bytes() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        "
initial_step: step1
max_state_bytes: 0
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
    assert!(err.to_string().contains("max_state_bytes"));
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
    let outcome = make_upstream_outcome(200);
    let results = std::collections::HashMap::new();
    let result = super::evaluate_transitions(&transitions, &outcome, &results);
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
            origin: None,
            status: Some(vec![502, 503]),
            transport_error: None,
            value: None,
        },
        make_default_done(),
    ];
    let outcome = make_upstream_outcome(503);
    let results = std::collections::HashMap::new();
    let result = super::evaluate_transitions(&transitions, &outcome, &results);
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
            origin: None,
            status: Some(vec![502, 503]),
            transport_error: None,
            value: None,
        },
        make_default_done(),
    ];
    let outcome = make_upstream_outcome(200);
    let results = std::collections::HashMap::new();
    let result = super::evaluate_transitions(&transitions, &outcome, &results);
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
            origin: None,
            status: None,
            transport_error: None,
            value: Some("true".to_owned()),
        },
        make_default_done(),
    ];
    let outcome = make_upstream_outcome(200);
    let mut results = std::collections::HashMap::new();
    let mut rs = crate::results::FilterResultSet::new();
    rs.set("has_tools", "true").unwrap();
    results.insert("classifier", rs);
    let result = super::evaluate_transitions(&transitions, &outcome, &results);
    assert!(
        matches!(result, super::TransitionResult::Next(s) if s.as_ref() == "tools"),
        "matching filter result should transition to tools"
    );
}

#[test]
fn transition_no_transitions_returns_no_match() {
    let transitions: Vec<config::StepTransition> = vec![];
    let outcome = make_upstream_outcome(200);
    let results = std::collections::HashMap::new();
    let result = super::evaluate_transitions(&transitions, &outcome, &results);
    assert!(
        matches!(result, super::TransitionResult::NoMatch),
        "empty transitions should return NoMatch"
    );
}

#[test]
fn transition_first_match_wins() {
    let mut first = make_status_transition(200);
    first.next = Some("first".to_owned());
    let mut second = make_status_transition(200);
    second.next = Some("second".to_owned());
    let transitions = vec![first, second];
    let outcome = make_upstream_outcome(200);
    let results = std::collections::HashMap::new();
    let result = super::evaluate_transitions(&transitions, &outcome, &results);
    assert!(
        matches!(result, super::TransitionResult::Next(s) if s.as_ref() == "first"),
        "first matching transition should win"
    );
}

// ---------------------------------------------------------------------------
// Response Building
// ---------------------------------------------------------------------------

#[test]
fn build_terminal_preserves_status() {
    let response = make_response(201);
    let terminal = super::build_terminal_response(&response, false);
    assert_eq!(terminal.status, 201, "terminal status should match response");
}

#[test]
fn build_terminal_normalizes_unsupported_status() {
    let response = make_response(700);
    let terminal = super::build_terminal_response(&response, false);
    assert_eq!(terminal.status, 502, "unsupported upstream status should become 502");
}

#[test]
fn build_terminal_normalizes_informational_status() {
    let response = make_response(103);
    let terminal = super::build_terminal_response(&response, false);
    assert_eq!(
        terminal.status, 502,
        "an informational status cannot terminate a response"
    );
}

#[test]
fn local_rejection_becomes_transition_response() {
    let mut rejection = crate::Rejection::status(503)
        .with_header("Retry-After", "1")
        .with_header("Connection", "x-private")
        .with_header("x-private", "secret")
        .with_header("x-praxis-private", "secret")
        .with_body(bytes::Bytes::from_static(b"unavailable"));
    rejection
        .header_map
        .get_or_insert_with(Default::default)
        .append("x-opaque", http::HeaderValue::from_bytes(&[0x80]).unwrap());
    let response = super::subresponse_from_rejection(rejection);
    assert_eq!(response.status, 503);
    assert_eq!(response.headers.get("retry-after").unwrap(), "1");
    assert!(!response.headers.contains_key("connection"));
    assert!(!response.headers.contains_key("x-private"));
    assert!(!response.headers.contains_key("x-praxis-private"));
    assert_eq!(response.headers.get("x-opaque").unwrap().as_bytes(), &[0x80]);
    assert_eq!(response.body, bytes::Bytes::from_static(b"unavailable"));
}

#[test]
fn build_terminal_preserves_body() {
    use crate::SubResponse;

    let response = SubResponse {
        status: 200,
        headers: HeaderMap::new(),
        body: bytes::Bytes::from_static(b"test body"),
    };
    let terminal = super::build_terminal_response(&response, false);
    assert_eq!(
        terminal.body.as_deref(),
        Some(b"test body".as_slice()),
        "terminal body should match response body"
    );
    assert_eq!(
        terminal.headers.get(http::header::CONTENT_LENGTH).unwrap(),
        "9",
        "the finalized body should be explicitly framed"
    );
}

#[test]
fn build_terminal_preserves_headers() {
    use crate::SubResponse;

    let mut headers = HeaderMap::new();
    headers.insert("content-type", "application/json".parse().unwrap());
    let response = SubResponse {
        status: 200,
        headers,
        body: bytes::Bytes::new(),
    };
    let terminal = super::build_terminal_response(&response, false);
    assert_eq!(
        terminal.headers.get("content-type").unwrap(),
        "application/json",
        "terminal should preserve content-type header"
    );
}

// ---------------------------------------------------------------------------
// classify_transport_failure
// ---------------------------------------------------------------------------

#[test]
fn classify_admission_timeout_returns_503() {
    let error = praxis_core::subrequest::SubRequestError::AdmissionTimeout { max_connections: 64 };
    let (status, kind) = super::classify_transport_failure(&error);
    assert_eq!(status, 503, "AdmissionTimeout should return 503");
    assert_eq!(kind, config::TransportErrorKind::AdmissionTimeout);
}

#[test]
fn classify_connect_returns_502() {
    let error = praxis_core::subrequest::SubRequestError::Connect("refused".to_owned());
    let (status, kind) = super::classify_transport_failure(&error);
    assert_eq!(status, 502, "Connect should return 502");
    assert_eq!(kind, config::TransportErrorKind::Connect);
}

#[test]
fn classify_deadline_exceeded_returns_504() {
    let error = praxis_core::subrequest::SubRequestError::DeadlineExceeded;
    let (status, kind) = super::classify_transport_failure(&error);
    assert_eq!(status, 504, "DeadlineExceeded should return 504");
    assert_eq!(kind, config::TransportErrorKind::DeadlineExceeded);
}

#[test]
fn classify_response_too_large_returns_502() {
    let error = praxis_core::subrequest::SubRequestError::ResponseTooLarge {
        actual: 200,
        limit: 100,
    };
    let (status, kind) = super::classify_transport_failure(&error);
    assert_eq!(status, 502, "ResponseTooLarge should return 502");
    assert_eq!(kind, config::TransportErrorKind::ResponseTooLarge);
}

#[test]
fn classify_io_returns_502() {
    let error = praxis_core::subrequest::SubRequestError::Io("broken pipe".to_owned());
    let (status, kind) = super::classify_transport_failure(&error);
    assert_eq!(status, 502, "Io should return 502");
    assert_eq!(kind, config::TransportErrorKind::Io);
}

#[test]
fn classify_invalid_request_falls_through_to_io() {
    let error = praxis_core::subrequest::SubRequestError::InvalidRequest("bad uri".to_owned());
    let (status, kind) = super::classify_transport_failure(&error);
    assert_eq!(status, 502, "InvalidRequest wildcard should return 502");
    assert_eq!(kind, config::TransportErrorKind::Io);
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
        origin: None,
        status: None,
        transport_error: None,
        value: None,
    }
}

/// Build a minimal `SubResponse` with the given status.
fn make_response(status: u16) -> crate::SubResponse {
    crate::SubResponse {
        status,
        headers: HeaderMap::new(),
        body: bytes::Bytes::new(),
    }
}

fn make_status_transition(status: u16) -> config::StepTransition {
    config::StepTransition {
        default: false,
        done: false,
        filter: None,
        key: None,
        next: None,
        origin: None,
        status: Some(vec![status]),
        transport_error: None,
        value: None,
    }
}

/// Build a `StepOutcome` with upstream origin from a status code.
fn make_upstream_outcome(status: u16) -> super::StepOutcome {
    super::StepOutcome {
        response: make_response(status),
        origin: config::ResponseOrigin::Upstream,
        transport_error: None,
    }
}

/// Build a transport failure `StepOutcome`.
fn make_transport_outcome(status: u16, kind: config::TransportErrorKind) -> super::StepOutcome {
    super::StepOutcome {
        response: make_response(status),
        origin: config::ResponseOrigin::Transport,
        transport_error: Some(kind),
    }
}

/// Build a local rejection `StepOutcome`.
fn make_local_outcome(status: u16) -> super::StepOutcome {
    super::StepOutcome {
        response: make_response(status),
        origin: config::ResponseOrigin::Local,
        transport_error: None,
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
    req.headers.insert(DEPTH_HEADER, http::HeaderValue::from_static("1"));
    assert_eq!(super::parse_depth(&req), 1);
}

#[test]
fn parse_depth_valid_three() {
    let mut req = crate::test_utils::make_request(http::Method::GET, "/");
    req.headers.insert(DEPTH_HEADER, http::HeaderValue::from_static("3"));
    assert_eq!(super::parse_depth(&req), 3);
}

#[test]
fn parse_depth_non_numeric() {
    let mut req = crate::test_utils::make_request(http::Method::GET, "/");
    req.headers.insert(DEPTH_HEADER, http::HeaderValue::from_static("abc"));
    assert_eq!(super::parse_depth(&req), 0, "non-numeric should return 0");
}

#[test]
fn parse_depth_overflow() {
    let mut req = crate::test_utils::make_request(http::Method::GET, "/");
    req.headers.insert(DEPTH_HEADER, http::HeaderValue::from_static("256"));
    assert_eq!(super::parse_depth(&req), 0, "overflow should return 0");
}

#[test]
fn parse_depth_negative() {
    let mut req = crate::test_utils::make_request(http::Method::GET, "/");
    req.headers.insert(DEPTH_HEADER, http::HeaderValue::from_static("-1"));
    assert_eq!(super::parse_depth(&req), 0, "negative should return 0");
}

#[test]
fn parse_depth_empty_string() {
    let mut req = crate::test_utils::make_request(http::Method::GET, "/");
    req.headers.insert(DEPTH_HEADER, http::HeaderValue::from_static(""));
    assert_eq!(super::parse_depth(&req), 0, "empty should return 0");
}

// ---------------------------------------------------------------------------
// strip_reserved_headers
// ---------------------------------------------------------------------------

#[test]
fn strip_reserved_empty_map() {
    let mut headers = HeaderMap::new();
    super::strip_reserved_headers(&mut headers);
    assert!(headers.is_empty(), "empty map should stay empty");
}

#[test]
fn strip_reserved_praxis_prefix() {
    let mut headers = HeaderMap::new();
    headers.insert("x-praxis-foo", "bar".parse().unwrap());
    super::strip_reserved_headers(&mut headers);
    assert!(headers.is_empty(), "x-praxis-* should be removed");
}

#[test]
fn strip_reserved_ext_protocol_prefix() {
    let mut headers = HeaderMap::new();
    headers.insert("x-ext-protocol-route", "value".parse().unwrap());
    super::strip_reserved_headers(&mut headers);
    assert!(headers.is_empty(), "x-ext-protocol-* should be removed");
}

#[test]
fn strip_reserved_ext_agent_prefix() {
    let mut headers = HeaderMap::new();
    headers.insert("x-ext-agent-task", "value".parse().unwrap());
    super::strip_reserved_headers(&mut headers);
    assert!(headers.is_empty(), "x-ext-agent-* should be removed");
}

#[test]
fn strip_reserved_preserves_non_reserved() {
    let mut headers = HeaderMap::new();
    headers.insert("authorization", "Bearer token".parse().unwrap());
    headers.insert("content-type", "application/json".parse().unwrap());
    super::strip_reserved_headers(&mut headers);
    assert_eq!(headers.len(), 2, "non-reserved headers should be preserved");
}

#[test]
fn strip_reserved_mixed() {
    let mut headers = HeaderMap::new();
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
    let mut headers = HeaderMap::new();
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

#[test]
#[expect(clippy::too_many_lines, reason = "YAML config literal")]
fn transport_error_without_transport_origin_rejected() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        "
initial_step: s
steps:
  - name: s
    filters:
      - filter: static_response
        status: 200
    on_result:
      - transport_error: connect
        status: [502]
        next: retry
      - default: true
        done: true
  - name: retry
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
    let result = config::validate(&cfg);
    assert!(
        result.is_err(),
        "transport_error without origin: transport should be rejected"
    );
    assert!(
        result.unwrap_err().to_string().contains("requires"),
        "error should mention the requirement"
    );
}

#[test]
fn origin_only_transition_accepted() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        "
initial_step: s
steps:
  - name: s
    filters:
      - filter: static_response
        status: 200
    on_result:
      - origin: upstream
        status: [429]
        next: retry
      - default: true
        done: true
  - name: retry
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
    let result = config::validate(&cfg);
    assert!(
        result.is_ok(),
        "origin + status transition should be accepted: {result:?}"
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
        matches!(
            mode,
            crate::body::BodyMode::StreamBuffer {
                max_bytes: Some(52_428_800)
            }
        ),
        "request buffering should use the independent state budget"
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
    req.headers.insert(DEPTH_HEADER, http::HeaderValue::from_static("3"));
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let result = filter.on_request(&mut ctx).await.unwrap();
    let is_508 = matches!(&result, crate::FilterAction::Reject(r) if r.status == 508);
    assert!(is_508, "depth >= max_depth should reject with 508");
}

#[tokio::test]
async fn on_request_depth_at_boundary() {
    let filter = build_filter();
    let mut req = crate::test_utils::make_request(http::Method::POST, "/v1/chat");
    req.headers.insert(DEPTH_HEADER, http::HeaderValue::from_static("2"));
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
        origin: None,
        status: Some(vec![200]),
        transport_error: None,
        value: Some("loop".to_owned()),
    }];
    let outcome = make_upstream_outcome(200);
    let mut results = std::collections::HashMap::new();
    let mut rs = crate::results::FilterResultSet::new();
    rs.set("action", "loop").unwrap();
    results.insert("classifier", rs);
    let result = super::evaluate_transitions(&transitions, &outcome, &results);
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
        origin: None,
        status: Some(vec![200]),
        transport_error: None,
        value: Some("loop".to_owned()),
    }];
    let outcome = make_upstream_outcome(200);
    let results = std::collections::HashMap::new();
    let result = super::evaluate_transitions(&transitions, &outcome, &results);
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
        origin: None,
        status: Some(vec![503]),
        transport_error: None,
        value: Some("loop".to_owned()),
    }];
    let outcome = make_upstream_outcome(200);
    let mut results = std::collections::HashMap::new();
    let mut rs = crate::results::FilterResultSet::new();
    rs.set("action", "loop").unwrap();
    results.insert("classifier", rs);
    let result = super::evaluate_transitions(&transitions, &outcome, &results);
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
        origin: None,
        status: None,
        transport_error: None,
        value: None,
    }];
    let outcome = make_upstream_outcome(200);
    let results = std::collections::HashMap::new();
    let result = super::evaluate_transitions(&transitions, &outcome, &results);
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
        origin: None,
        status: None,
        transport_error: None,
        value: Some("v".to_owned()),
    }];
    let outcome = make_upstream_outcome(200);
    let results = std::collections::HashMap::new();
    let result = super::evaluate_transitions(&transitions, &outcome, &results);
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
        origin: None,
        status: None,
        transport_error: None,
        value: None,
    }];
    let outcome = make_upstream_outcome(200);
    let results = std::collections::HashMap::new();
    let result = super::evaluate_transitions(&transitions, &outcome, &results);
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
        origin: None,
        status: Some(vec![200]),
        transport_error: None,
        value: None,
    }];
    let outcome = make_upstream_outcome(200);
    let results = std::collections::HashMap::new();
    let result = super::evaluate_transitions(&transitions, &outcome, &results);
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
        origin: None,
        status: None,
        transport_error: None,
        value: Some("loop".to_owned()),
    }];
    let outcome = make_upstream_outcome(200);
    let mut results = std::collections::HashMap::new();
    let mut rs = crate::results::FilterResultSet::new();
    rs.set("action", "done").unwrap();
    results.insert("classifier", rs);
    let result = super::evaluate_transitions(&transitions, &outcome, &results);
    assert!(
        matches!(result, super::TransitionResult::NoMatch),
        "wrong filter value should not match"
    );
}

#[test]
fn transition_origin_upstream_matches_upstream_response() {
    let transitions = vec![config::StepTransition {
        default: false,
        done: true,
        filter: None,
        key: None,
        next: None,
        origin: Some(config::ResponseOrigin::Upstream),
        status: Some(vec![429]),
        transport_error: None,
        value: None,
    }];
    let outcome = make_upstream_outcome(429);
    let results = std::collections::HashMap::new();
    let result = super::evaluate_transitions(&transitions, &outcome, &results);
    assert!(
        matches!(result, super::TransitionResult::Done),
        "upstream 429 should match origin: upstream + status: [429]"
    );
}

#[test]
fn transition_origin_upstream_does_not_match_local_429() {
    let transitions = vec![config::StepTransition {
        default: false,
        done: true,
        filter: None,
        key: None,
        next: None,
        origin: Some(config::ResponseOrigin::Upstream),
        status: Some(vec![429]),
        transport_error: None,
        value: None,
    }];
    let outcome = make_local_outcome(429);
    let results = std::collections::HashMap::new();
    let result = super::evaluate_transitions(&transitions, &outcome, &results);
    assert!(
        matches!(result, super::TransitionResult::NoMatch),
        "local 429 should not match origin: upstream"
    );
}

#[test]
fn transition_connect_only_does_not_match_io_failure() {
    let transitions = vec![config::StepTransition {
        default: false,
        done: false,
        filter: None,
        key: None,
        next: Some("fallback".to_owned()),
        origin: Some(config::ResponseOrigin::Transport),
        status: None,
        transport_error: Some(config::TransportErrorKind::Connect),
        value: None,
    }];
    let outcome = make_transport_outcome(502, config::TransportErrorKind::Io);
    let results = std::collections::HashMap::new();
    let result = super::evaluate_transitions(&transitions, &outcome, &results);
    assert!(
        matches!(result, super::TransitionResult::NoMatch),
        "connect-only transition should not match I/O failure"
    );
}

#[test]
fn transition_connect_matches_connect_failure() {
    let transitions = vec![config::StepTransition {
        default: false,
        done: false,
        filter: None,
        key: None,
        next: Some("fallback".to_owned()),
        origin: Some(config::ResponseOrigin::Transport),
        status: None,
        transport_error: Some(config::TransportErrorKind::Connect),
        value: None,
    }];
    let outcome = make_transport_outcome(502, config::TransportErrorKind::Connect);
    let results = std::collections::HashMap::new();
    let result = super::evaluate_transitions(&transitions, &outcome, &results);
    assert!(
        matches!(result, super::TransitionResult::Next(s) if s.as_ref() == "fallback"),
        "connect failure should match connect-only transition"
    );
}

#[test]
fn transition_legacy_status_only_still_works() {
    let transitions = vec![config::StepTransition {
        default: false,
        done: false,
        filter: None,
        key: None,
        next: Some("fallback".to_owned()),
        origin: None,
        status: Some(vec![502, 503, 504]),
        transport_error: None,
        value: None,
    }];
    let outcome = make_transport_outcome(502, config::TransportErrorKind::Connect);
    let results = std::collections::HashMap::new();
    let result = super::evaluate_transitions(&transitions, &outcome, &results);
    assert!(
        matches!(result, super::TransitionResult::Next(s) if s.as_ref() == "fallback"),
        "legacy status-only transition should still match transport failures"
    );
}

#[test]
fn transition_transport_origin_matches_any_transport_error() {
    let transitions = vec![config::StepTransition {
        default: false,
        done: false,
        filter: None,
        key: None,
        next: Some("retry".to_owned()),
        origin: Some(config::ResponseOrigin::Transport),
        status: None,
        transport_error: None,
        value: None,
    }];
    let outcome = make_transport_outcome(504, config::TransportErrorKind::DeadlineExceeded);
    let results = std::collections::HashMap::new();
    let result = super::evaluate_transitions(&transitions, &outcome, &results);
    assert!(
        matches!(result, super::TransitionResult::Next(s) if s.as_ref() == "retry"),
        "origin: transport without transport_error should match any transport failure"
    );
}

// ---------------------------------------------------------------------------
// build_terminal_response - Additional
// ---------------------------------------------------------------------------

#[test]
fn build_terminal_empty_body_has_no_body() {
    let response = make_response(200);
    let terminal = super::build_terminal_response(&response, false);
    assert!(
        terminal.body.is_none(),
        "empty response body should result in None terminal body"
    );
}

#[test]
fn build_terminal_multiple_headers() {
    use crate::SubResponse;

    let mut headers = HeaderMap::new();
    headers.insert("content-type", "application/json".parse().unwrap());
    headers.insert("x-request-id", "abc123".parse().unwrap());
    let response = SubResponse {
        status: 200,
        headers,
        body: bytes::Bytes::new(),
    };
    let terminal = super::build_terminal_response(&response, false);
    assert!(terminal.headers.len() >= 2, "terminal should preserve all headers");
}

#[test]
fn build_terminal_reframes_empty_response_for_keepalive() {
    use crate::SubResponse;

    let mut headers = HeaderMap::new();
    headers.insert(http::header::CONTENT_LENGTH, "99".parse().unwrap());
    headers.insert(http::header::TRANSFER_ENCODING, "chunked".parse().unwrap());
    headers.insert(http::header::CONTENT_TYPE, "application/json".parse().unwrap());
    let response = SubResponse {
        status: 200,
        headers,
        body: bytes::Bytes::new(),
    };

    let terminal = super::build_terminal_response(&response, false);

    assert_eq!(terminal.headers.get("content-length").unwrap(), "0");
    assert!(!terminal.headers.contains_key("transfer-encoding"));
    assert!(terminal.headers.contains_key("content-type"));
    assert!(terminal.body.is_none());
}

#[test]
fn build_terminal_does_not_frame_bodyless_status() {
    let response = make_response(204);
    let terminal = super::build_terminal_response(&response, false);

    assert!(!terminal.headers.contains_key(http::header::CONTENT_LENGTH));
}

#[test]
fn build_terminal_preserves_head_content_length() {
    use crate::SubResponse;

    let mut headers = HeaderMap::new();
    headers.insert(http::header::CONTENT_LENGTH, "123".parse().unwrap());
    let response = SubResponse {
        status: 200,
        headers,
        body: bytes::Bytes::new(),
    };

    let terminal = super::build_terminal_response(&response, true);

    assert_eq!(terminal.headers.get(http::header::CONTENT_LENGTH).unwrap(), "123");
}

#[test]
fn build_terminal_preserves_opaque_header_bytes() {
    use crate::SubResponse;

    let mut headers = HeaderMap::new();
    headers.insert("x-opaque", http::HeaderValue::from_bytes(&[b'a', 0x80, b'z']).unwrap());
    let response = SubResponse {
        status: 200,
        headers,
        body: bytes::Bytes::new(),
    };

    let terminal = super::build_terminal_response(&response, false);

    assert_eq!(
        terminal.headers.get("x-opaque").unwrap().as_bytes(),
        &[b'a', 0x80, b'z']
    );
}

#[test]
fn nested_body_limit_detects_oversized_buffer() {
    assert!(super::body_exceeds_limit(
        crate::BodyMode::StreamBuffer { max_bytes: Some(4) },
        5
    ));
    assert!(!super::body_exceeds_limit(
        crate::BodyMode::SizeLimit { max_bytes: 5 },
        5
    ));
    assert!(!super::body_exceeds_limit(crate::BodyMode::Stream, usize::MAX));
}

#[test]
fn transformed_response_must_remain_within_all_limits() {
    assert!(super::response_body_exceeds_limits(crate::BodyMode::Stream, 4, 5));
    assert!(super::response_body_exceeds_limits(
        crate::BodyMode::StreamBuffer { max_bytes: Some(3) },
        4,
        4,
    ));
    assert!(!super::response_body_exceeds_limits(
        crate::BodyMode::StreamBuffer { max_bytes: Some(4) },
        4,
        4,
    ));
}

#[test]
fn listener_response_limit_clamps_router_limit() {
    assert_eq!(
        super::effective_response_limit(
            crate::pipeline::subrequest::default_max_response_bytes(),
            crate::BodyMode::SizeLimit { max_bytes: 4 }
        ),
        4
    );
    assert_eq!(super::effective_response_limit(4, crate::BodyMode::Stream), 4);
}

#[test]
fn strip_request_framing_headers_removes_stale_lengths() {
    let mut headers = HeaderMap::new();
    headers.insert(http::header::CONTENT_LENGTH, "100".parse().unwrap());
    headers.insert(http::header::TRANSFER_ENCODING, "chunked".parse().unwrap());
    headers.insert(http::header::CONTENT_TYPE, "application/json".parse().unwrap());

    super::strip_request_framing_headers(&mut headers);

    assert!(!headers.contains_key(http::header::CONTENT_LENGTH));
    assert!(!headers.contains_key(http::header::TRANSFER_ENCODING));
    assert!(headers.contains_key(http::header::CONTENT_TYPE));
}

#[test]
fn request_sanitization_strips_all_reserved_headers_including_depth() {
    let mut headers = HeaderMap::new();
    headers.insert(http::header::CONNECTION, "x-remove, keep-alive".parse().unwrap());
    headers.insert("x-remove", "secret".parse().unwrap());
    headers.insert("keep-alive", "timeout=5".parse().unwrap());
    headers.insert("x-praxis-route", "internal".parse().unwrap());
    headers.insert(DEPTH_HEADER, "1".parse().unwrap());
    headers.insert(http::header::AUTHORIZATION, "Bearer step-token".parse().unwrap());
    headers.insert(http::header::CONTENT_LENGTH, "99".parse().unwrap());

    super::sanitize_subrequest_headers(&mut headers);

    assert!(!headers.contains_key(http::header::CONNECTION));
    assert!(!headers.contains_key("x-remove"));
    assert!(!headers.contains_key("keep-alive"));
    assert!(!headers.contains_key("x-praxis-route"));
    assert!(!headers.contains_key(http::header::CONTENT_LENGTH));
    assert!(
        !headers.contains_key(DEPTH_HEADER),
        "sanitize must strip depth; core executor re-injects via framework_headers"
    );
    assert_eq!(headers.get(http::header::AUTHORIZATION).unwrap(), "Bearer step-token");
}

#[test]
fn sanitize_strips_depth_header_for_framework_reinsertion() {
    let mut headers = HeaderMap::new();
    headers.insert(DEPTH_HEADER, "spoofed".parse().unwrap());
    headers.insert("x-praxis-route", "internal".parse().unwrap());
    headers.insert(http::header::AUTHORIZATION, "Bearer token".parse().unwrap());

    super::sanitize_subrequest_headers(&mut headers);

    assert!(
        !headers.contains_key(DEPTH_HEADER),
        "sanitize must strip depth so core executor can re-inject via framework_headers"
    );
    assert!(!headers.contains_key("x-praxis-route"));
    assert_eq!(headers.get(http::header::AUTHORIZATION).unwrap(), "Bearer token");
}

#[test]
fn response_sanitization_strips_hop_by_hop_and_internal_headers() {
    let mut headers = HeaderMap::new();
    headers.insert(http::header::CONNECTION, "x-remove".parse().unwrap());
    headers.insert("x-remove", "secret".parse().unwrap());
    headers.insert("upgrade", "h2c".parse().unwrap());
    headers.insert("x-ext-agent-task", "internal".parse().unwrap());
    headers.append(http::header::SET_COOKIE, "first=1".parse().unwrap());
    headers.append(http::header::SET_COOKIE, "second=2".parse().unwrap());

    super::sanitize_subresponse_headers(&mut headers);

    assert!(!headers.contains_key(http::header::CONNECTION));
    assert!(!headers.contains_key("x-remove"));
    assert!(!headers.contains_key("upgrade"));
    assert!(!headers.contains_key("x-ext-agent-task"));
    assert_eq!(headers.get_all(http::header::SET_COOKIE).iter().count(), 2);
}

#[test]
fn destination_host_is_synthesized_without_overwriting_step_override() {
    let mut generated = HeaderMap::new();
    super::ensure_destination_host(&mut generated, "model.example:443").unwrap();
    assert_eq!(generated.get(http::header::HOST).unwrap(), "model.example:443");

    let mut explicit = HeaderMap::new();
    explicit.insert(http::header::HOST, "override.example".parse().unwrap());
    super::ensure_destination_host(&mut explicit, "model.example:443").unwrap();
    assert_eq!(explicit.get(http::header::HOST).unwrap(), "override.example");
}

#[test]
fn nested_security_pipeline_rejects_failure_mode_open() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
initial_step: protected
steps:
  - name: protected
    filters:
      - filter: ip_acl
        failure_mode: open
        allow: ["127.0.0.0/8"]
    on_result:
      - default: true
        done: true
"#,
    )
    .unwrap();
    let registry = crate::FilterRegistry::with_builtins();

    let error = super::IterativeRequestRouterFilter::from_config_with_registry(&yaml, &registry)
        .err()
        .expect("open security filter must fail nested validation");

    assert!(error.to_string().contains("failure_mode: open"));
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "resource identity assertions are intentionally explicit"
)]
fn sub_filter_context_inherits_parent_runtime_resources() {
    use std::{collections::HashMap, sync::Arc, time::Duration};

    use praxis_core::{
        health::HealthRegistry,
        id::IdGenerator,
        kv::KvStoreRegistry,
        subrequest::{SubRequestClient, SubRequestConnector},
        time::FixedTimeSource,
    };

    let registry = crate::FilterRegistry::with_builtins();
    let pipeline = crate::FilterPipeline::build(&mut [], &registry).unwrap();
    let request = crate::Request {
        headers: HeaderMap::new(),
        method: http::Method::POST,
        uri: http::Uri::from_static("/v1/responses"),
    };
    let health_registry: HealthRegistry = Arc::new(HashMap::new());
    let id_generator = IdGenerator::with_seed(42);
    let kv_stores = KvStoreRegistry::new();
    let client = SubRequestClient::new(SubRequestConnector::new(1, None));
    let time_source = FixedTimeSource::new(Duration::from_secs(123));

    let ctx = super::build_sub_filter_context(
        &pipeline,
        &request,
        super::SubPipelineRuntimeResources {
            client_addr: Some(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
            downstream_tls: true,
            health_registry: Some(&health_registry),
            id_generator: &id_generator,
            kv_stores: Some(&kv_stores),
            peer_identity: None,
            request_start: std::time::Instant::now(),
            subrequest_client: Some(&client),
            time_source: &time_source,
        },
    );

    assert!(std::ptr::eq(ctx.health_registry.unwrap(), &health_registry));
    assert!(std::ptr::eq(ctx.id_generator, &id_generator));
    assert!(std::ptr::eq(ctx.kv_stores.unwrap(), &kv_stores));
    assert!(std::ptr::eq(ctx.subrequest_client.unwrap(), &client));
    assert_eq!(
        ctx.client_addr,
        Some(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
    );
    assert!(ctx.downstream_tls);
    assert_eq!(ctx.time_source.now(), Duration::from_secs(123));
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
