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

/// The filter crate's manifest, which defines the Policy features.
const FILTER_MANIFEST: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../filter/Cargo.toml"));

/// The protocol crate's manifest, which forwards them.
const PROTOCOL_MANIFEST: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../protocol/Cargo.toml"));

/// Filter features that only combine other `policy-*` features, so each layer
/// re-declares them from its own forwards instead of forwarding them.
const FILTER_ALIASES: &[&str] = &["policy-api-key-fips", "policy-jwt-fips"];

/// Config whose sub-request client admits one exchange at a time, with a
/// `policy` filter that gives up on initializing after two seconds, well
/// inside the five the JWKS fetch itself waits. `{policy}` stands for the path
/// of the policy document.
#[cfg(feature = "policy-builtins")]
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
#[cfg(feature = "policy-builtins")]
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
#[cfg(feature = "policy-builtins")]
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
fn the_default_feature_set_includes_the_policy_builtins() {
    let declaration = default_feature_declaration().expect("[features] must declare a `default` array");

    assert!(
        declaration.contains("\"policy-builtins\""),
        "`policy-builtins` must stay in this crate's default features: the binary's own feature set \
         is what decides whether the `policy` filter is nameable in config, and no cfg-based test \
         can catch its removal — tests/integration turns the policy filter on through \
         its own default, so every suite would stay green while the shipped binary lost the \
         filter. Got: {declaration}"
    );
}

#[expect(
    clippy::tests_outside_test_module,
    reason = "integration tests are in tests/ directory, not in src"
)]
#[test]
fn every_filter_policy_feature_is_forwarded_by_protocol_and_server() {
    let filter_features = feature_names(FILTER_MANIFEST, "policy-");
    assert!(
        filter_features.len() > 10,
        "the filter manifest scan found too few Policy features: {filter_features:?}"
    );
    for feature in filter_features
        .iter()
        .filter(|name| !FILTER_ALIASES.contains(&name.as_str()))
    {
        let forward = format!("\"praxis-filter/{feature}\"");
        let protocol = declaration_in(PROTOCOL_MANIFEST, feature).unwrap_or_default();
        assert!(
            protocol.contains(&forward),
            "praxis-proxy-protocol's `{feature}` must forward {forward}: {protocol:?}"
        );
        let server = feature_declaration(feature).unwrap_or_default();
        assert!(
            server.contains(&forward) && server.contains(&format!("\"praxis-protocol/{feature}\"")),
            "praxis-proxy's `{feature}` must forward to the filter and protocol crates: {server:?}"
        );
    }
}

#[expect(
    clippy::tests_outside_test_module,
    reason = "integration tests are in tests/ directory, not in src"
)]
#[test]
fn protocol_and_server_expose_exactly_the_filter_policy_features() {
    let filter_features = feature_names(FILTER_MANIFEST, "policy-");
    assert_eq!(
        feature_names(PROTOCOL_MANIFEST, "policy-"),
        filter_features,
        "praxis-proxy-protocol must expose exactly the filter's Policy features"
    );
    assert_eq!(
        feature_names(MANIFEST, "policy-"),
        filter_features,
        "praxis-proxy must expose exactly the filter's Policy features"
    );
}

#[expect(
    clippy::expect_used,
    clippy::tests_outside_test_module,
    reason = "integration tests are in tests/ directory, not in src"
)]
#[test]
fn the_default_bundle_carries_the_experimental_limiter() {
    let builtins = feature_declaration("policy-builtins").expect("the bundle");
    assert!(
        builtins.contains("\"policy-experimental-ratelimit\""),
        "the default bundle must carry the limiter selector, so its experimental marker follows: {builtins}"
    );
    let limiter = feature_declaration("policy-experimental-ratelimit").expect("the limiter selector");
    assert!(
        limiter.contains("\"experimental\""),
        "the limiter is experimental and must set the marker: {limiter}"
    );
}

#[expect(
    clippy::expect_used,
    clippy::tests_outside_test_module,
    reason = "integration tests are in tests/ directory, not in src"
)]
#[test]
fn policy_plugin_features_select_no_crypto_backend() {
    for plugin in [
        "policy-api-key",
        "policy-jwt",
        "policy-jwt-openssl-fips",
        "policy-experimental-ratelimit",
        "policy-engine",
    ] {
        let declaration = declaration_in(FILTER_MANIFEST, plugin).expect("plugin feature");
        assert!(
            !declaration.contains("policy-crypto-")
                && !declaration.contains("ppe/crypto-")
                && !declaration.contains("ppe/fips")
                && !declaration.contains("ppe/builtins"),
            "`{plugin}` must select neither a crypto backend nor the bundle: {declaration}"
        );
    }
}

#[expect(
    clippy::expect_used,
    clippy::tests_outside_test_module,
    reason = "integration tests are in tests/ directory, not in src"
)]
#[test]
fn the_fips_aliases_combine_one_plugin_with_the_fips_backend() {
    let jwt_fips = declaration_in(FILTER_MANIFEST, "policy-jwt-fips").expect("FIPS JWT alias");
    assert!(
        jwt_fips.contains("\"policy-jwt-openssl-fips\"")
            && jwt_fips.contains("\"policy-crypto-fips\"")
            && !jwt_fips.contains("policy-api-key"),
        "`policy-jwt-fips` is the OpenSSL JWT plugin plus the FIPS backend, without API-key: {jwt_fips}"
    );
    let alias_features = declaration_in(FILTER_MANIFEST, "policy-api-key-fips").expect("FIPS API-key alias");
    assert!(
        alias_features.contains("\"policy-api-key\"") && alias_features.contains("\"policy-crypto-fips\""),
        "`policy-api-key-fips` must select the API-key plugin and the FIPS backend"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// The right-hand side of `default = [...]` in this crate's `[features]` table.
///
/// A line scan rather than a TOML parse: the workspace carries no TOML parser,
/// and adding one for a single-line assertion is not worth the dependency.
fn default_feature_declaration() -> Option<String> {
    feature_declaration("default")
}

/// Find a feature's right-hand side in this crate's `[features]` table.
fn feature_declaration(name: &str) -> Option<String> {
    declaration_in(MANIFEST, name)
}

/// The `[features]` table of `manifest` as `(name, right-hand side)` pairs,
/// joining a declaration that spans several lines.
fn feature_table(manifest: &str) -> Vec<(String, String)> {
    let mut table: Vec<(String, String)> = Vec::new();
    for line in manifest
        .lines()
        .skip_while(|line| line.trim() != "[features]")
        .skip(1)
        .take_while(|line| !line.starts_with('['))
        .filter(|line| !line.trim_start().starts_with('#'))
    {
        match line.split_once('=') {
            Some((name, rest)) if !line.starts_with(' ') => {
                table.push((name.trim().to_owned(), rest.trim().to_owned()));
            },
            _ => {
                if let Some((_, rest)) = table.last_mut() {
                    rest.push_str(line.trim());
                }
            },
        }
    }
    table
}

/// The right-hand side of feature `name` in `manifest`.
fn declaration_in(manifest: &str, name: &str) -> Option<String> {
    feature_table(manifest)
        .into_iter()
        .find_map(|(feature, rest)| (feature == name).then_some(rest))
}

/// The sorted names of `manifest`'s features starting with `prefix`.
fn feature_names(manifest: &str, prefix: &str) -> Vec<String> {
    let mut names: Vec<String> = feature_table(manifest)
        .into_iter()
        .map(|(name, _)| name)
        .filter(|name| name.starts_with(prefix))
        .collect();
    names.sort();
    names
}

/// Parse [`CONFIG`] with its `policy` filter pointed at [`POLICY`], written
/// into `dir`.
#[cfg(feature = "policy-builtins")]
#[expect(clippy::expect_used, reason = "test utility")]
fn runtime_config(dir: &tempfile::TempDir) -> praxis_core::config::Config {
    let policy = dir.path().join("policy.yaml");
    std::fs::write(&policy, POLICY).expect("write the policy document");
    let path = policy.to_str().expect("a UTF-8 tempdir path");
    praxis_core::config::Config::from_yaml(&CONFIG.replace("{policy}", path)).expect("the test config must parse")
}

/// Take the one admission permit `client`'s connector hands out.
#[cfg(feature = "policy-builtins")]
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
#[cfg(feature = "policy-builtins")]
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
