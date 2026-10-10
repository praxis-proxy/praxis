// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

#![forbid(unsafe_code)]

//! Build-level guarantees about the policy engine.
//!
//! Per-crate tests rather than cases in the shared `tests/integration` suite:
//! they only hold when compiled against this crate, with its own feature
//! resolution. The manifest case is deliberately ungated so feature
//! unification cannot mask it.

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// This crate's own manifest, embedded so the assertion reads the shipped
/// feature declaration rather than a `cfg` derived from it.
const MANIFEST: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"));

/// Config whose sub-request client admits one exchange at a time, with a
/// `policy` filter that gives up on initializing after two seconds, well
/// inside the five the JWKS fetch itself waits. `{policy}` stands for the path
/// of the policy document.
#[cfg(feature = "policy-engine")]
const CONFIG: &str = r#"
runtime:
  subrequest_max_connections: 1
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: policy
        config_path: "{policy}"
        allow_private_idp: true
        init_timeout_secs: 2
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints: ["10.0.0.1:80"]
"#;

/// Policy document whose JWT issuer fetches its JWKS while the filter is
/// constructed, from a loopback port nothing listens on. The fetch fails at
/// once unless it has to wait for admission, and a failed fetch at boot is
/// recoverable, so the filter still builds.
#[cfg(feature = "policy-engine")]
const POLICY: &str = r#"
plugins:
  - name: jwt-user
    kind: identity/jwt
    hooks:
      - identity.resolve
    mode: sequential
    on_error: fail
    capabilities:
      - perform_http
    config:
      header: Authorization
      trusted_issuers:
        - issuer: "https://issuer.test"
          audiences: ["praxis"]
          algorithms: ["RS256"]
          decoding_key:
            kind: jwks_url
            url: "http://127.0.0.1:1/jwks.json"
            insecure_http: true
      claim_mapper: standard
global:
  authentication:
    - jwt-user
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
fn resolved_policy_filters_call_out_through_the_runtime_connector() {
    // Calls resolve_pipelines directly, so it misses main()'s provider install.
    praxis::install_crypto_provider();
    let dir = tempfile::TempDir::new().expect("create a tempdir");
    let config = runtime_config(&dir);
    let client = praxis::build_subrequest_client(&config).expect("sub-request client");

    let permit = hold_the_only_admission_permit(&client);
    let err = resolve(&config, &client).expect_err(
        "with the runtime's only admission permit held, the policy filter's JWKS fetch must wait \
         for it until initialization times out; a filter built over a pool of its own fetches \
         without waiting and the pipelines resolve",
    );
    assert!(
        err.contains("timed out"),
        "the policy filter must stall on the runtime's admission limit; got: {err}"
    );

    drop(permit);
    resolve(&config, &client).expect("with the permit released, the same config must resolve");
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

/// Parse [`CONFIG`] with its `policy` filter pointed at [`POLICY`], written
/// into `dir`.
#[cfg(feature = "policy-engine")]
#[expect(clippy::expect_used, reason = "test utility")]
fn runtime_config(dir: &tempfile::TempDir) -> praxis_core::config::Config {
    let policy = dir.path().join("policy.yaml");
    std::fs::write(&policy, POLICY).expect("write the policy document");
    let path = policy.to_str().expect("a UTF-8 tempdir path");
    praxis_core::config::Config::from_yaml(&CONFIG.replace("{policy}", path)).expect("the test config must parse")
}

/// Take the one admission permit `client`'s connector hands out.
#[cfg(feature = "policy-engine")]
#[expect(clippy::expect_used, reason = "test utility")]
fn hold_the_only_admission_permit(
    client: &praxis_core::subrequest::SubRequestClient,
) -> tokio::sync::OwnedSemaphorePermit {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("build a runtime to take the permit on")
        .block_on(client.connector().acquire_permit())
        .expect("the connector must enforce subrequest_max_connections")
}

/// Resolve `config`'s pipelines over `client` the way server startup does,
/// keeping only the error text.
#[cfg(feature = "policy-engine")]
fn resolve(
    config: &praxis_core::config::Config,
    client: &praxis_core::subrequest::SubRequestClient,
) -> Result<(), String> {
    praxis::resolve_pipelines(
        config,
        &praxis_filter::FilterRegistry::with_builtins(),
        &std::sync::Arc::new(std::collections::HashMap::new()),
        &praxis_core::kv::KvStoreRegistry::new(),
        &std::sync::Arc::new(praxis_filter::SessionStoreRegistry::new()),
        client,
    )
    .map(drop)
    .map_err(|err| err.to_string())
}
