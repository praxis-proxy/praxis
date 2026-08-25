// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! HTTP/2 conformance tests via [h2spec]. Runs all h2spec tests in strict mode.
//!
//! [h2spec]: https://github.com/summerwind/h2spec

use std::{fs, process::Command};

use praxis_core::config::Config;
use praxis_test_utils::{free_port, start_proxy, wait_for_http2};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

/// [RFC 7540] / [RFC 7541] conformance (strict mode, all MUST and SHOULD requirements).
///
/// [RFC 7540]: https://datatracker.ietf.org/doc/html/rfc7540
/// [RFC 7541]: https://datatracker.ietf.org/doc/html/rfc7541
///
/// Known failures in the HTTP/2 transport layer (the pingora fork's `h2`
/// stack, below Praxis code) are pinned in [`KNOWN_UPSTREAM_FAILURES`]; any
/// failure outside that list fails the test, and an allowlisted check that
/// passes is logged so the list can shrink as upstream improves.
#[test]
fn h2spec_strict_conformance() {
    let h2spec = find_h2spec();
    let proxy_port = free_port();
    let config = Config::from_yaml(&static_response_yaml(proxy_port)).unwrap();
    let proxy = start_proxy(&config);
    wait_for_http2(proxy.addr());

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
            "--timeout",
            "5",
            "-j",
            &report_path,
        ])
        .output()
        .unwrap_or_else(|e| panic!("failed to execute h2spec at {}: {e}", h2spec.display()));

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Guard against a vacuous pass: h2spec exits 0 when its arguments match
    // no test cases ("No matched tests found."), so require the summary line
    // proving a non-zero number of tests actually ran.
    let ran = parse_tests_run(&stdout);
    assert!(
        ran > 0,
        "h2spec ran no tests\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}"
    );

    let failures = parse_failures(&stdout);

    let unexpected: Vec<&String> = failures
        .iter()
        .filter(|name| !KNOWN_UPSTREAM_FAILURES.contains(&name.as_str()))
        .collect();
    assert!(
        unexpected.is_empty(),
        "h2spec: {} unexpected failure(s):\n{}\n\n\
         --- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
        unexpected.len(),
        unexpected
            .iter()
            .map(|s| format!("  - {s}"))
            .collect::<Vec<_>>()
            .join("\n"),
    );

    // The raced checks pass or fail nondeterministically, so a passing
    // allowlist entry is informational, not an error.
    for name in KNOWN_UPSTREAM_FAILURES {
        if !failures.iter().any(|f| f == name) {
            eprintln!("h2spec: known upstream failure passed this run: {name}");
        }
    }
}

/// h2spec strict-mode checks that fail inside the HTTP/2 transport layer of
/// the pingora fork (the `h2` stack), which Praxis sits above and cannot
/// influence. Five are one race: Praxis answers with END_STREAM before the
/// transport reads the offending client frame, so h2spec sees the successful
/// response instead of the prescribed error code. The preface case closes the
/// TCP connection (satisfying the MUST) without the GOAWAY h2spec expects.
const KNOWN_UPSTREAM_FAILURES: &[&str] = &[
    // RFC 9113 §3.4: MAY send GOAWAY before terminating; transport just closes.
    "Sends invalid connection preface",
    // RFC 9113 §5.1 (closed state): early-response race.
    "closed: Sends a DATA frame after sending RST_STREAM frame",
    // RFC 9113 §5.1 (closed state): early-response race.
    "closed: Sends a HEADERS frame after sending RST_STREAM frame",
    // RFC 9113 §6.9.1: RST_STREAM sent, but not with FLOW_CONTROL_ERROR.
    "Sends multiple WINDOW_UPDATE frames increasing the flow control window \
     to above 2^31-1 on a stream",
    // RFC 9113 §8.1: early-response race.
    "Sends a second HEADERS frame without the END_STREAM flag",
    // RFC 9113 §8.1.2.1: early-response race.
    "Sends a HEADERS frame that contains a pseudo-header field as trailers",
    // RFC 9113 §8.1.2.6: early-response race.
    "Sends a HEADERS frame with the \"content-length\" header field which \
     does not equal the DATA frame payload length",
    // RFC 9113 §8.1.2.6: early-response race.
    "Sends a HEADERS frame with the \"content-length\" header field which \
     does not equal the sum of the multiple DATA frames payload length",
];

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Build the workspace-relative report directory path.
fn report_dir() -> String {
    format!("{}/../../target/praxis-conformance-tests", env!("CARGO_MANIFEST_DIR"))
}

/// Extract the total test count from the h2spec summary line
/// (`146 tests, 146 passed, 0 skipped, 0 failed`).
fn parse_tests_run(stdout: &str) -> usize {
    stdout
        .lines()
        .filter_map(|line| {
            line.trim()
                .split_once(" tests, ")
                .and_then(|(count, _)| count.parse().ok())
        })
        .next_back()
        .unwrap_or(0)
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
