// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

#![forbid(unsafe_code)]

//! `--validate` and `--dump` must surface config validation warnings.
//!
//! Runs the real binary as a subprocess: these modes never install the
//! configured subscriber, so only the process's own stderr proves that the
//! warnings raised while loading the config are not silently dropped.

#![expect(
    clippy::tests_outside_test_module,
    clippy::expect_used,
    reason = "integration tests are in tests/ directory, not in src"
)]

use std::{io::Write as _, process::Command};

/// Minimal valid config with two insecure overrides enabled.
const INSECURE_CONFIG: &str = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
insecure_options:
  allow_tls_no_verify: true
  csrf_log_only: true
"#;

/// Config that shares one deprecated filter chain between two listeners.
#[cfg(feature = "basic-auth-filter")]
const DEPRECATED_FILTER_CONFIG: &str = r#"
listeners:
  - name: public
    address: "127.0.0.1:8080"
    filter_chains: [auth]
  - name: internal
    address: "127.0.0.1:8081"
    filter_chains: [auth]
filter_chains:
  - name: auth
    filters:
      - filter: basic_auth
        credentials:
          - username: operator
            password: secret
      - filter: static_response
        status: 200
"#;

/// Run the binary in `mode` against `yaml`, returning success and process output.
fn run_check_mode(mode: &str, yaml: &str, log_format: Option<&str>) -> (bool, String, String) {
    let mut config = tempfile::NamedTempFile::new().expect("temp config file");
    config
        .write_all(yaml.as_bytes())
        .expect("temp config should be writable");
    let mut command = Command::new(env!("CARGO_BIN_EXE_praxis"));
    command.arg(mode).arg("-c").arg(config.path());
    command
        .env_remove("PRAXIS_REQUIRE_FIPS")
        .env_remove("PRAXIS_LOG_FORMAT");
    if let Some(format) = log_format {
        command.env("PRAXIS_LOG_FORMAT", format);
    }
    let output = command.output().expect("the praxis binary must run");
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[cfg(feature = "basic-auth-filter")]
#[test]
fn validate_reports_deprecated_filter_for_each_listener() {
    let (ok, _, stderr) = run_check_mode("--validate", DEPRECATED_FILTER_CONFIG, Some("json"));
    assert!(ok, "deprecated config should still validate: {stderr}");

    let listeners: Vec<String> = stderr
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("each stderr log line should be valid JSON"))
        .filter_map(|event| {
            let fields = event.get("fields")?;
            if fields.get("item")?.as_str()? != "basic_auth" {
                return None;
            }
            fields.get("listener")?.as_str().map(str::to_owned)
        })
        .collect();

    assert_eq!(
        listeners,
        ["public", "internal"],
        "each listener using the deprecated shared chain should be reported: {stderr}"
    );
}

#[cfg(feature = "basic-auth-filter")]
#[test]
fn dump_surfaces_deprecation_warning_without_mixing_stdout() {
    let (ok, stdout, stderr) = run_check_mode("--dump", DEPRECATED_FILTER_CONFIG, Some("json"));
    assert!(ok, "deprecated config should still dump: {stderr}");
    assert_eq!(
        stderr
            .matches("candidate configuration contains deprecated settings")
            .count(),
        2,
        "each listener should be warned about: {stderr}"
    );
    assert!(
        !stdout.contains("candidate configuration contains deprecated settings"),
        "warnings must not leak into YAML output: {stdout}"
    );
    serde_yaml::from_str::<serde_yaml::Value>(&stdout).expect("dump stdout should remain valid YAML");
}

#[test]
fn validate_prints_each_insecure_flag_warning_once() {
    let (ok, stdout, stderr) = run_check_mode("--validate", INSECURE_CONFIG, None);
    assert!(ok, "config should validate: {stderr}");
    assert!(stdout.is_empty(), "--validate should keep stdout empty: {stdout}");
    for flag in ["allow_tls_no_verify", "csrf_log_only"] {
        assert_eq!(
            stderr.matches(flag).count(),
            1,
            "{flag} should warn exactly once on stderr: {stderr}"
        );
    }
}

/// Valid credential injection settings with two explicit deprecated fields and one omitted default.
const DEPRECATED_CREDENTIAL_FIELD_CONFIG: &str = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: credential_injection
        clusters:
          - name: explicit-true
            header: Authorization
            value: example-secret
            strip_client_credential: true
          - name: omitted
            header: Authorization
            value: example-secret
          - name: explicit-false
            header: Authorization
            value: example-secret
            strip_client_credential: false
      - filter: static_response
        status: 200
"#;

#[test]
fn validate_warns_for_explicit_deprecated_credential_fields() {
    let (ok, _, stderr) = run_check_mode("--validate", DEPRECATED_CREDENTIAL_FIELD_CONFIG, Some("json"));
    assert!(ok, "deprecated credential settings remain accepted: {stderr}");
    let paths: Vec<String> = stderr
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("each stderr log line should be valid JSON"))
        .filter_map(|event| {
            let fields = event.get("fields")?;
            if fields.get("item")?.as_str()? != "credential_injection.clusters[].strip_client_credential" {
                return None;
            }
            fields.get("path")?.as_str().map(str::to_owned)
        })
        .collect();
    assert_eq!(
        paths,
        [
            "filter_chains[main].filters[0].clusters[0].strip_client_credential",
            "filter_chains[main].filters[0].clusters[2].strip_client_credential",
        ],
        "omitting the deprecated field must not warn: {stderr}"
    );
    assert!(
        stderr.contains("remove strip_client_credential"),
        "warning should explain the remedy: {stderr}"
    );
    assert!(
        !stderr.contains("example-secret"),
        "warnings must not include credential values"
    );
}

#[test]
fn validate_honours_json_log_format() {
    let (ok, _, stderr) = run_check_mode("--validate", INSECURE_CONFIG, Some("json"));
    assert!(ok, "config should validate: {stderr}");
    let flags: Vec<String> = stderr
        .lines()
        .map(|line| serde_yaml::from_str::<serde_yaml::Value>(line).expect("each stderr line should be JSON"))
        .filter_map(|event| event.get("fields")?.get("flag")?.as_str().map(str::to_owned))
        .collect();
    assert_eq!(
        flags,
        ["allow_tls_no_verify", "csrf_log_only"],
        "each active flag should be one JSON warning: {stderr}"
    );
}

#[test]
fn dump_keeps_stdout_yaml_and_warns_on_stderr() {
    let (ok, stdout, stderr) = run_check_mode("--dump", INSECURE_CONFIG, Some("json"));
    assert!(ok, "config should dump: {stderr}");
    assert!(
        stderr.contains("allow_tls_no_verify"),
        "--dump should surface validation warnings on stderr: {stderr}"
    );
    assert!(
        !stdout.contains("insecure_options flag is active"),
        "warnings must not leak into the YAML dump: {stdout}"
    );
    serde_yaml::from_str::<serde_yaml::Value>(&stdout).expect("--dump stdout should stay valid YAML");
}

/// Two grouped TCP listeners whose `filter_chains` disagree.
const INCONSISTENT_TCP_GROUP_CONFIG: &str = r#"
listeners:
  - name: db1
    address: "127.0.0.1:5432"
    protocol: tcp
    upstream: "203.0.113.10:5432"
    filter_chains: [a]
  - name: db2
    address: "127.0.0.1:5433"
    protocol: tcp
    upstream: "203.0.113.10:5432"
    filter_chains: [b]
filter_chains:
  - name: a
    filters:
      - filter: tcp_access_log
  - name: b
    filters:
      - filter: tcp_access_log
"#;

#[test]
fn validate_rejects_inconsistent_tcp_group() {
    let mut config = tempfile::NamedTempFile::new().expect("temp config file");
    config
        .write_all(INCONSISTENT_TCP_GROUP_CONFIG.as_bytes())
        .expect("temp config should be writable");
    let output = Command::new(env!("CARGO_BIN_EXE_praxis"))
        .arg("--validate")
        .arg("-c")
        .arg(config.path())
        .env_remove("PRAXIS_REQUIRE_FIPS")
        .env_remove("PRAXIS_LOG_FORMAT")
        .output()
        .expect("the praxis binary must run");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "an inconsistent TCP group must fail --validate: {stderr}"
    );
    assert!(
        stderr.contains("filter_chains"),
        "the failure should name the inconsistent field: {stderr}"
    );
}
