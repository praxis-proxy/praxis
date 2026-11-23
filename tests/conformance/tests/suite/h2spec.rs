// SPDX-License-Identifier: Apache-2.0
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

    let failures = evaluate_result(&stdout, output.status.code()).unwrap_or_else(|reason| {
        panic!(
            "h2spec result invalid: {reason}\nstatus: {}\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
            output.status
        )
    });

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

/// h2spec's final summary counts.
#[derive(Debug, PartialEq, Eq)]
struct Summary {
    total: usize,
    passed: usize,
    skipped: usize,
    failed: usize,
}

/// Parse one exact h2spec 2.6 summary line.
fn parse_summary(line: &str) -> Option<Summary> {
    let fields: Vec<_> = line.trim().split(", ").collect();
    let count = |field: Option<&&str>, suffix: &str| -> Option<usize> { field?.strip_suffix(suffix)?.parse().ok() };
    Some(Summary {
        total: count(fields.first(), " tests")?,
        passed: count(fields.get(1), " passed")?,
        skipped: count(fields.get(2), " skipped")?,
        failed: count(fields.get(3), " failed")?,
    })
    .filter(|_| fields.len() == 4)
}

/// Parse a failure title from h2spec's `× section: title` line.
fn failure_name(line: &str) -> Option<String> {
    line.trim()
        .strip_prefix('×')?
        .trim()
        .split_once(": ")
        .map(|(_, name)| name.to_owned())
}

/// Check the final report, verbose failures, and process termination together.
fn evaluate_result(stdout: &str, exit_code: Option<i32>) -> Result<Vec<String>, String> {
    let summary = stdout
        .lines()
        .filter_map(parse_summary)
        .next_back()
        .ok_or("missing or malformed h2spec summary")?;
    let counted = summary
        .passed
        .checked_add(summary.skipped)
        .and_then(|count| count.checked_add(summary.failed));
    if counted != Some(summary.total) {
        return Err(format!("inconsistent h2spec counts: {summary:?}"));
    }
    if summary.passed + summary.failed == 0 {
        return Err("h2spec executed no checks".to_owned());
    }
    let mut final_section = false;
    let mut verbose = Vec::new();
    let mut failures = Vec::new();
    for line in stdout.lines() {
        if line.trim() == "Failures:" {
            final_section = true;
        } else if let Some(name) = failure_name(line) {
            if final_section {
                failures.push(name);
            } else {
                verbose.push(name);
            }
        }
    }
    let mut sorted_verbose = verbose.clone();
    let mut sorted_failures = failures.clone();
    sorted_verbose.sort_unstable();
    sorted_failures.sort_unstable();
    if failures.len() != summary.failed || sorted_verbose != sorted_failures {
        return Err(format!(
            "h2spec failure report disagrees with summary: {summary:?}, verbose={verbose:?}, failures={failures:?}"
        ));
    }
    let unexpected: Vec<_> = failures
        .iter()
        .filter(|name| !KNOWN_UPSTREAM_FAILURES.contains(&name.as_str()))
        .collect();
    if !unexpected.is_empty() {
        return Err(format!("unexpected h2spec failures: {unexpected:?}"));
    }
    let expected_exit = if summary.failed == 0 { 0 } else { 1 };
    if exit_code != Some(expected_exit) {
        return Err(format!("h2spec exit {exit_code:?}, expected {expected_exit}"));
    }
    Ok(failures)
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

#[cfg(test)]
mod tests {
    use super::evaluate_result;

    const KNOWN: &str = "Sends invalid connection preface";

    fn report(summary: &str, failed: &[&str]) -> String {
        let mut output = String::new();
        for name in failed {
            output.push_str(&format!("× 3.4: {name}\n"));
        }
        if !failed.is_empty() {
            output.push_str("Failures:\n");
            for name in failed {
                output.push_str(&format!("× 3.4: {name}\n"));
            }
        }
        output.push_str(summary);
        output
    }

    #[test]
    fn summary_and_failure_lines_must_reconcile() {
        evaluate_result(&report("2 tests, 2 passed, 0 skipped, 0 failed", &[]), Some(0)).unwrap();
        evaluate_result(&report("2 tests, 1 passed, 0 skipped, 1 failed", &[KNOWN]), Some(1)).unwrap();
        evaluate_result(&report("2 tests, 1 passed, 0 skipped, 1 failed", &["unknown"]), Some(1)).unwrap_err();
        evaluate_result(&report("2 tests, 1 passed, 0 skipped, 1 failed", &[]), Some(1)).unwrap_err();
        evaluate_result(&report("3 tests, 1 passed, 0 skipped, 1 failed", &[KNOWN]), Some(1)).unwrap_err();
        evaluate_result("no summary", Some(0)).unwrap_err();
        evaluate_result("2 tests, bad passed, 0 skipped, 0 failed", Some(0)).unwrap_err();
    }

    #[test]
    fn all_skipped_run_is_not_conformance() {
        evaluate_result(&report("2 tests, 0 passed, 2 skipped, 0 failed", &[]), Some(0)).unwrap_err();
        evaluate_result(&report("2 tests, 1 passed, 1 skipped, 0 failed", &[]), Some(0)).unwrap();
    }

    #[test]
    fn execution_error_after_summary_is_failure() {
        let passed = report("2 tests, 2 passed, 0 skipped, 0 failed", &[]);
        evaluate_result(&passed, Some(1)).unwrap_err();
        evaluate_result(&passed, None).unwrap_err();
        let failed = report("2 tests, 1 passed, 0 skipped, 1 failed", &[KNOWN]);
        evaluate_result(&failed, Some(1)).unwrap();
        evaluate_result(&failed, Some(2)).unwrap_err();
    }
}
