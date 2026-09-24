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

/// Run the binary in `mode` on [`INSECURE_CONFIG`], returning (success, stdout, stderr).
fn run_check_mode(mode: &str, log_format: Option<&str>) -> (bool, String, String) {
    let mut config = tempfile::NamedTempFile::new().expect("temp config file");
    config
        .write_all(INSECURE_CONFIG.as_bytes())
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

#[test]
fn validate_prints_each_insecure_flag_warning_once() {
    let (ok, stdout, stderr) = run_check_mode("--validate", None);
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

#[test]
fn validate_honours_json_log_format() {
    let (ok, _, stderr) = run_check_mode("--validate", Some("json"));
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
    let (ok, stdout, stderr) = run_check_mode("--dump", Some("json"));
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
