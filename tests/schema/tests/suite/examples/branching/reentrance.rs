// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Re-entrant branch example config tests.

use std::collections::HashMap;

use praxis_core::config::{Config, MAX_ITERATIONS_CEILING};
use praxis_test_utils::{
    build_pipeline, free_port, http_send, parse_body, parse_status, registry_with, start_header_echo_backend,
    start_proxy_with_registry,
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn reentrance_pipeline_builds() {
    let config = crate::example_utils::load_example_config(
        "branching/reentrance.yaml",
        8080,
        HashMap::from([("127.0.0.1:3000", 3000)]),
    );
    let pipeline = build_pipeline(&config);
    assert_eq!(
        pipeline.len(),
        4,
        "reentrance pipeline: request_id + headers + router + load_balancer"
    );
}

#[test]
fn reentrance_requires_max_iterations() {
    let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: headers
        name: target
        branch_chains:
          - name: no_limit
            on_result:
              filter: headers
              result: retry
            rejoin: target
            chains:
              - name: inline
                filters:
                  - filter: headers
      - filter: static_response
        status: 200
"#;
    let config = Config::from_yaml(yaml).unwrap();
    let registry = praxis_filter::FilterRegistry::with_builtins();
    let chains: HashMap<&str, &[_]> = config
        .filter_chains
        .iter()
        .map(|c| (c.name.as_str(), c.filters.as_slice()))
        .collect();
    let mut entries = Vec::new();
    for chain_name in &config.listeners[0].filter_chains {
        if let Some(filters) = chains.get(chain_name.as_str()) {
            entries.extend_from_slice(filters);
        }
    }
    let result = praxis_filter::FilterPipeline::build_with_chains(&mut entries, &registry, &chains);
    assert!(result.is_err(), "backward rejoin without max_iterations should fail");
    let err = result.err().unwrap();
    assert!(
        err.to_string().contains("max_iterations"),
        "error should mention max_iterations: {err}"
    );
}

#[test]
fn reentrance_rejects_max_iterations_zero() {
    let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: headers
        name: loop_target
        branch_chains:
          - name: bad_limit
            rejoin: loop_target
            max_iterations: 0
            chains:
              - name: inline
                filters:
                  - filter: headers
      - filter: static_response
        status: 200
"#;
    let err = Config::from_yaml(yaml).unwrap_err();
    assert!(
        err.to_string().contains("max_iterations must be 1-"),
        "max_iterations=0 should be rejected: {err}"
    );
}

#[test]
fn reentrance_rejects_max_iterations_above_ceiling() {
    let yaml = format!(
        r#"
listeners:
  - name: web
    address: "0.0.0.0:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: headers
        name: loop_target
        branch_chains:
          - name: over_limit
            rejoin: loop_target
            max_iterations: {}
            chains:
              - name: inline
                filters:
                  - filter: headers
      - filter: static_response
        status: 200
"#,
        MAX_ITERATIONS_CEILING + 1
    );
    let err = Config::from_yaml(&yaml).unwrap_err();
    assert!(
        err.to_string().contains("max_iterations must be 1-"),
        "max_iterations above ceiling should be rejected: {err}"
    );
}

#[test]
fn reentrance_accepts_max_iterations_at_ceiling() {
    let yaml = format!(
        r#"
listeners:
  - name: web
    address: "0.0.0.0:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: headers
        name: loop_target
        branch_chains:
          - name: at_ceiling
            rejoin: loop_target
            max_iterations: {MAX_ITERATIONS_CEILING}
            chains:
              - name: inline
                filters:
                  - filter: headers
      - filter: static_response
        status: 200
"#
    );
    Config::from_yaml(&yaml).unwrap();
}

#[test]
fn reentrance_accepts_max_iterations_one() {
    let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: headers
        name: loop_target
        branch_chains:
          - name: single_retry
            rejoin: loop_target
            max_iterations: 1
            chains:
              - name: inline
                filters:
                  - filter: headers
      - filter: static_response
        status: 200
"#;
    Config::from_yaml(yaml).unwrap();
}

#[test]
fn reentrance_forward_rejoin_does_not_require_max_iterations() {
    let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: headers
        branch_chains:
          - name: skip_ahead
            rejoin: target
            chains:
              - name: inline
                filters:
                  - filter: headers
      - filter: headers
        name: target
      - filter: static_response
        status: 200
"#;
    let config = Config::from_yaml(yaml).unwrap();
    build_pipeline(&config);
}

#[test]
fn reentrance_e2e_branch_executes_and_reaches_backend() {
    let _backend = start_header_echo_backend();
    let backend_port = _backend.port();
    let proxy_port = free_port();
    let yaml = format!(
        r#"
listeners:
  - name: web
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: retry_test
        name: classify
        branch_chains:
          - name: retry_loop
            on_result:
              filter: retry_test
              key: action
              result: retry
            rejoin: classify
            max_iterations: 3
            chains:
              - name: retry_chain
                filters:
                  - filter: headers
                    request_add:
                      - name: X-Retry
                        value: "true"
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:{backend_port}"
"#
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let registry = registry_with("retry_test", make_retry_filter);
    let proxy = start_proxy_with_registry(&config, &registry);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    let status = parse_status(&raw);
    assert_eq!(status, 200, "request should reach backend through re-entrance");
    let body = parse_body(&raw);
    let lower = body.to_lowercase();
    assert!(
        lower.contains("x-retry: true"),
        "branch chain should inject X-Retry header; got body:\n{body}"
    );
}

#[test]
fn reentrance_e2e_no_match_passes_through() {
    let _backend = start_header_echo_backend();
    let backend_port = _backend.port();
    let proxy_port = free_port();
    let yaml = format!(
        r#"
listeners:
  - name: web
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: retry_test_done
        name: classify
        branch_chains:
          - name: retry_loop
            on_result:
              filter: retry_test_done
              key: action
              result: retry
            rejoin: classify
            max_iterations: 3
            chains:
              - name: retry_chain
                filters:
                  - filter: headers
                    request_add:
                      - name: X-Retry
                        value: "true"
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:{backend_port}"
"#
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let registry = registry_with("retry_test_done", make_done_filter);
    let proxy = start_proxy_with_registry(&config, &registry);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    let status = parse_status(&raw);
    assert_eq!(status, 200, "request should reach backend when branch does not fire");
    let body = parse_body(&raw);
    let lower = body.to_lowercase();
    assert!(
        !lower.contains("x-retry"),
        "branch chain should not inject X-Retry header when condition does not match; got body:\n{body}"
    );
}

#[test]
fn reentrance_self_rejoin_requires_max_iterations() {
    let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: headers
        name: self_ref
        branch_chains:
          - name: self_loop
            rejoin: self_ref
            chains:
              - name: inline
                filters:
                  - filter: headers
      - filter: static_response
        status: 200
"#;
    let config = Config::from_yaml(yaml).unwrap();
    let registry = praxis_filter::FilterRegistry::with_builtins();
    let chains: HashMap<&str, &[_]> = config
        .filter_chains
        .iter()
        .map(|c| (c.name.as_str(), c.filters.as_slice()))
        .collect();
    let mut entries = Vec::new();
    for chain_name in &config.listeners[0].filter_chains {
        if let Some(filters) = chains.get(chain_name.as_str()) {
            entries.extend_from_slice(filters);
        }
    }
    let result = praxis_filter::FilterPipeline::build_with_chains(&mut entries, &registry, &chains);
    assert!(
        result.is_err(),
        "self-referencing rejoin without max_iterations should fail"
    );
    let err = result.err().unwrap();
    assert!(
        err.to_string().contains("max_iterations"),
        "error should mention max_iterations: {err}"
    );
}

// ---------------------------------------------------------------------------
// Test Utilities
// ---------------------------------------------------------------------------

use praxis_filter::{FilterAction, FilterError, FilterResultSet, HttpFilter, HttpFilterContext};

/// Filter that always writes `action=retry` to
/// [`FilterResultSet`]. The re-entrant branch fires on
/// every evaluation; [`max_iterations`] caps the loop.
///
/// [`max_iterations`]: praxis_core::config::BranchChainConfig::max_iterations
struct RetryFilter;

#[async_trait::async_trait]
impl HttpFilter for RetryFilter {
    fn name(&self) -> &'static str {
        "retry_test"
    }

    async fn on_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        let mut results = FilterResultSet::new();
        results.set("action", "retry")?;
        ctx.filter_results.insert(self.name(), results);
        Ok(FilterAction::Continue)
    }
}

/// Factory for [`RetryFilter`].
fn make_retry_filter() -> Box<dyn HttpFilter> {
    Box::new(RetryFilter)
}

/// Filter that always writes `action=done` (never triggers
/// the retry branch).
struct DoneFilter;

#[async_trait::async_trait]
impl HttpFilter for DoneFilter {
    fn name(&self) -> &'static str {
        "retry_test_done"
    }

    async fn on_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        let mut results = FilterResultSet::new();
        results.set("action", "done")?;
        ctx.filter_results.insert(self.name(), results);
        Ok(FilterAction::Continue)
    }
}

/// Factory for [`DoneFilter`].
fn make_done_filter() -> Box<dyn HttpFilter> {
    Box::new(DoneFilter)
}
