// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

#![forbid(unsafe_code)]

//! Build-level guarantees about the policy engine.
//!
//! This is a dedicated per-crate test binary, not an inline `#[cfg(test)]`
//! module or a case in the shared `tests/integration` suite. It has to be:
//! both guarantees below only hold when these tests are compiled against this
//! crate, with its own feature resolution, and run in their own process.
//!
//! The registration case lives in its own test binary because the connector
//! slot is process-wide and last-wins: the lib unit tests resolve pipelines
//! concurrently, and any of their registrations would clobber the one asserted
//! on here. The manifest case is deliberately ungated so feature unification
//! cannot mask it.

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// This crate's own manifest, embedded so the assertion reads the shipped
/// feature declaration rather than a `cfg` derived from it.
const MANIFEST: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"));

/// Minimal valid config. It carries no `policy` filter on purpose: the
/// connector registration is unconditional, so it must happen for any config.
#[cfg(feature = "policy-engine")]
const CONFIG: &str = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints: ["10.0.0.1:80"]
"#;

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[expect(
    clippy::expect_used,
    clippy::tests_outside_test_module,
    reason = "integration tests are in tests/ directory, not in src"
)]
#[cfg(feature = "policy-engine")]
#[test]
fn resolving_pipelines_registers_the_proxy_pool_for_policy_calls() {
    use std::{collections::HashMap, sync::Arc};

    use praxis::{build_subrequest_client, resolve_pipelines};
    use praxis_core::config::Config;
    use praxis_filter::{FilterRegistry, SessionStoreRegistry, registered_policy_subrequest_connector};

    // Calls resolve_pipelines directly, so it misses main()'s provider install.
    praxis::install_crypto_provider();

    let config = Config::from_yaml(CONFIG).expect("the test config must parse");
    let client = build_subrequest_client(&config);

    resolve_pipelines(
        &config,
        &FilterRegistry::with_builtins(),
        &Arc::new(HashMap::new()),
        &praxis_core::kv::KvStoreRegistry::new(),
        &Arc::new(SessionStoreRegistry::new()),
        &client,
    )
    .expect("the test config must resolve into pipelines");

    let registered = registered_policy_subrequest_connector().expect(
        "resolve_pipelines must register the sub-request connector; gating that call on the \
         server's own `policy-engine` feature misses every build where feature unification turned \
         the filter on, and policy calls then silently open a second connection pool",
    );
    assert!(
        std::ptr::eq(registered.connector(), client.connector().connector()),
        "policy calls must share the proxy's keepalive pool, not a pool of their own"
    );
}

#[expect(
    clippy::expect_used,
    clippy::tests_outside_test_module,
    reason = "integration tests are in tests/ directory, not in src"
)]
#[test]
fn the_default_feature_set_includes_the_policy_engine() {
    let declaration = default_feature_declaration().expect("[features] must declare a `default` array");

    assert!(
        declaration.contains("\"policy-engine\""),
        "`policy-engine` must stay in this crate's default features: the binary's own feature set \
         is what decides whether the `policy` filter is nameable in config, and no cfg-based test \
         can catch its removal — tests/integration turns praxis-filter/policy-engine on through \
         its own default, so every suite would stay green while the shipped binary lost the \
         filter. Got: {declaration}"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// The right-hand side of `default = [...]` in this crate's `[features]` table.
///
/// A line scan rather than a TOML parse: the workspace carries no TOML parser,
/// and adding one for a single-line assertion is not worth the dependency.
fn default_feature_declaration() -> Option<&'static str> {
    MANIFEST
        .lines()
        .skip_while(|line| line.trim() != "[features]")
        .skip(1)
        .take_while(|line| !line.trim_start().starts_with('['))
        .find_map(|line| line.trim().strip_prefix("default"))
        .and_then(|rest| rest.trim_start().strip_prefix('='))
}
