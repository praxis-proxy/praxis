// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Functional integration tests for the `credential_injection` env_var gateway
//! example config.
//!
//! The filter reads its credentials from the environment when it is built, and
//! this process's environment cannot be changed safely while other tests run,
//! so these start the real binary with the variables set on the child only.

use std::{
    collections::HashMap,
    fs,
    process::{Command, ExitStatus, Stdio},
    time::{Duration, Instant},
};

use praxis_test_utils::{
    BackendGuard, PraxisProcess, allow_loopback_endpoints, example_config_path, free_port, http_get, http_send,
    parse_body, parse_status, patch_yaml, praxis_bin, start_header_echo_backend, start_uri_echo_backend,
};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// The example under test.
const EXAMPLE: &str = "security/credential-injection-env-vars.yaml";

/// A test credential for each environment variable the example reads.
const CREDENTIALS: [(&str, &str); 3] = [
    ("GITHUB_TOKEN", "test-github-token"),
    ("OPENAI_API_KEY", "test-openai-key"),
    ("INTERNAL_API_KEY", "test-internal-key"),
];

/// How long `praxis -t` may run before the test gives up on it.
const VALIDATE_TIMEOUT: Duration = Duration::from_secs(30);

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
#[cfg_attr(
    coverage,
    ignore = "spawns the praxis binary; deadlocks on exit under llvm-cov instrumentation"
)]
fn credential_injection_env_vars_injects_each_service_credential() {
    let backends = [
        start_header_echo_backend(),
        start_header_echo_backend(),
        start_header_echo_backend(),
    ];
    let (_proxy, addr) = spawn_gateway(&backends);

    for (path, credential, host) in [
        (
            "/github/user",
            "authorization: bearer test-github-token",
            "host: api.github.com",
        ),
        (
            "/openai/v1/models",
            "authorization: bearer test-openai-key",
            "host: api.openai.com",
        ),
        (
            "/internal/data",
            "x-api-key: test-internal-key",
            "host: internal.example.com",
        ),
    ] {
        let (status, body) = http_get(&addr, path, None);
        let headers = body.to_lowercase();

        assert_eq!(status, 200, "{path} should reach its service");
        assert!(
            headers.contains(credential),
            "{path} should carry its service's credential from the environment, got:\n{body}"
        );
        assert!(
            headers.contains(host),
            "{path} should carry its service's Host override, got:\n{body}"
        );
        for (_, other) in CREDENTIALS.iter().filter(|(_, value)| !credential.ends_with(value)) {
            assert!(
                !headers.contains(other),
                "{path} must not receive another service's credential ({other}), got:\n{body}"
            );
        }
    }
}

#[test]
#[cfg_attr(
    coverage,
    ignore = "spawns the praxis binary; deadlocks on exit under llvm-cov instrumentation"
)]
fn credential_injection_env_vars_replaces_client_credential() {
    let backends = [
        start_header_echo_backend(),
        start_header_echo_backend(),
        start_header_echo_backend(),
    ];
    let (_proxy, addr) = spawn_gateway(&backends);

    for (path, client_header, injected) in [
        (
            "/github/user",
            "Authorization: Bearer client-supplied",
            "authorization: bearer test-github-token",
        ),
        (
            "/internal/data",
            "x-api-key: client-supplied",
            "x-api-key: test-internal-key",
        ),
    ] {
        let raw = http_send(
            &addr,
            &format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n{client_header}\r\nConnection: close\r\n\r\n"),
        );
        let body = parse_body(&raw);
        let headers = body.to_lowercase();

        assert_eq!(parse_status(&raw), 200, "{path} should reach its service");
        assert!(
            headers.contains(injected),
            "{path} should carry the injected credential, got:\n{body}"
        );
        assert!(
            !headers.contains("client-supplied"),
            "{path} must not forward the client's credential, got:\n{body}"
        );
    }
}

#[test]
#[cfg_attr(
    coverage,
    ignore = "spawns the praxis binary; deadlocks on exit under llvm-cov instrumentation"
)]
fn credential_injection_env_vars_strips_service_prefix() {
    let backends = [
        start_uri_echo_backend(),
        start_uri_echo_backend(),
        start_uri_echo_backend(),
    ];
    let (_proxy, addr) = spawn_gateway(&backends);

    for (path, forwarded) in [
        (
            "/github/repos/praxis-proxy/praxis?per_page=1",
            "/repos/praxis-proxy/praxis?per_page=1",
        ),
        ("/openai/v1/chat/completions", "/v1/chat/completions"),
        ("/internal", "/"),
    ] {
        let (status, body) = http_get(&addr, path, None);

        assert_eq!(status, 200, "{path} should reach its service");
        assert_eq!(body, forwarded, "{path} should reach its service without the prefix");
    }
}

#[test]
#[cfg_attr(
    coverage,
    ignore = "spawns the praxis binary; deadlocks on exit under llvm-cov instrumentation"
)]
fn credential_injection_env_vars_missing_variable_fails_validation() {
    let (status, stderr) = validate(&CREDENTIALS, &[]);
    assert!(
        status.success(),
        "the example should validate with every variable set ({status}):\n{stderr}"
    );

    for (missing, _) in CREDENTIALS {
        let present: Vec<(&str, &str)> = CREDENTIALS.into_iter().filter(|(name, _)| *name != missing).collect();
        let (status, stderr) = validate(&present, &[missing]);

        assert!(
            !status.success(),
            "praxis -t should reject the example without {missing}:\n{stderr}"
        );
        assert!(
            stderr.contains(&format!("environment variable '{missing}' not set")),
            "the error should name {missing}, got:\n{stderr}"
        );
    }
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Start the example against `backends` (GitHub, OpenAI, internal, in that
/// order) with every credential set, returning the process and its address.
fn spawn_gateway(backends: &[BackendGuard; 3]) -> (PraxisProcess, String) {
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let yaml = fs::read_to_string(example_config_path(EXAMPLE)).expect("read example");
    let [github, openai, internal] = backends.each_ref().map(BackendGuard::port);
    let ports = HashMap::from([
        ("127.0.0.1:3001", github),
        ("127.0.0.1:3002", openai),
        ("127.0.0.1:3003", internal),
    ]);
    let patched = allow_loopback_endpoints(&patch_yaml(&yaml, port, &ports));
    let proxy = PraxisProcess::spawn_with_env(&patched, &addr, &CREDENTIALS);
    (proxy, addr)
}

/// Run `praxis -t` on the example as shipped, with `set` in its environment
/// and `unset` removed from it, returning the exit status and stderr.
///
/// The child is killed if it outlives [`VALIDATE_TIMEOUT`], so a hang fails
/// this test instead of stalling the suite.
fn validate(set: &[(&str, &str)], unset: &[&str]) -> (ExitStatus, String) {
    let dir = tempfile::tempdir().expect("tempdir");
    let stderr_path = dir.path().join("stderr.log");
    let mut command = Command::new(praxis_bin());
    command
        .arg("-t")
        .arg("-c")
        .arg(example_config_path(EXAMPLE))
        .env("NO_COLOR", "1")
        .envs(set.iter().copied())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(fs::File::create(&stderr_path).expect("create stderr log"));
    for name in unset {
        command.env_remove(name);
    }

    let mut child = command.spawn().expect("spawn praxis -t");
    let deadline = Instant::now() + VALIDATE_TIMEOUT;
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll praxis -t") {
            break status;
        }
        if Instant::now() >= deadline {
            let _killed = child.kill();
            let _reaped = child.wait();
            panic!("praxis -t did not exit within {VALIDATE_TIMEOUT:?}");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    (status, fs::read_to_string(&stderr_path).unwrap_or_default())
}
