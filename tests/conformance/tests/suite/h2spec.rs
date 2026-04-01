//! HTTP/2 conformance tests via [h2spec].
//!
//! Runs all h2spec tests in strict mode.
//!
//! JUnit XML report is written to `target/praxis-conformance-tests/h2spec.xml`.
//!
//! [h2spec]: https://github.com/summerwind/h2spec

use std::{fs, process::Command};

use praxis_core::config::Config;

use crate::common::{free_port, start_proxy, wait_for_http2};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

/// [RFC 7540] / [RFC 7541] conformance (strict mode, all MUST and SHOULD requirements).
///
/// [RFC 7540]: https://datatracker.ietf.org/doc/html/rfc7540
/// [RFC 7541]: https://datatracker.ietf.org/doc/html/rfc7541
#[test]
fn h2spec_strict_conformance() {
    let h2spec = find_h2spec();
    let proxy_port = free_port();
    let config = Config::from_yaml(&static_response_yaml(proxy_port)).unwrap();
    let addr = start_proxy(&config);
    wait_for_http2(&addr);

    let dir = report_dir();
    fs::create_dir_all(&dir).unwrap();
    let report_path = format!("{dir}/h2spec.xml");

    let output = Command::new(&h2spec)
        .args([
            "-h",
            "127.0.0.1",
            "-p",
            &proxy_port.to_string(),
            "--strict",
            "--verbose",
            // Per-test timeout in seconds. The default (1s)
            // causes intermittent failures on slow CI runners.
            "-t",
            "5",
            "-j",
            &report_path,
        ])
        .output()
        .unwrap_or_else(|e| panic!("failed to execute h2spec at {}: {e}", h2spec.display()));

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    let failures = parse_failures(&stdout);

    assert!(
        failures.is_empty(),
        "h2spec: {} failure(s):\n{}\n\n\
         --- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
        failures.len(),
        failures
            .iter()
            .map(|s| format!("  - {s}"))
            .collect::<Vec<_>>()
            .join("\n"),
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Build the workspace-relative report directory path.
fn report_dir() -> String {
    format!("{}/../../target/praxis-conformance-tests", env!("CARGO_MANIFEST_DIR"))
}

/// Extract failure names from h2spec verbose output.
fn parse_failures(stdout: &str) -> Vec<String> {
    stdout
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.starts_with('×') {
                trimmed.split_once(": ").map(|(_, name)| name.to_owned())
            } else {
                None
            }
        })
        .collect()
}

/// Locate the `h2spec` binary in `$PATH`.
fn find_h2spec() -> std::path::PathBuf {
    std::env::var_os("PATH")
        .iter()
        .flat_map(|paths| std::env::split_paths(paths))
        .map(|dir| dir.join("h2spec"))
        .find(|candidate| candidate.is_file())
        .unwrap_or_else(|| {
            panic!(
                "h2spec not found in $PATH. \
                 Run `make tools` or install from \
                 https://github.com/summerwind/h2spec/releases"
            )
        })
}

/// Build a YAML config with a `static_response` filter
/// returning 200 on every request (no upstream needed).
fn static_response_yaml(port: u16) -> String {
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{port}"
    filter_chains:
      - main
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
        headers:
          - name: Content-Type
            value: text/plain
        body: "h2spec conformance"
"#
    )
}
