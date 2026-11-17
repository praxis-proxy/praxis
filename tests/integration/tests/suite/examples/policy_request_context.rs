// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Functional coverage of security/policy-request-context.yaml and its PPE predicates.

use std::{
    collections::HashMap,
    time::{SystemTime, UNIX_EPOCH},
};

use praxis_core::config::Config;
use praxis_test_utils::{
    example_config_path, free_port, http_send, parse_status, patch_yaml, start_header_echo_backend, start_proxy,
};
use tempfile::TempDir;

/// Fixture signing key; never a production credential.
const SECRET: &str = "REPLACE-WITH-A-PROPERLY-RANDOM-SHARED-SECRET-DO-NOT-COMMIT";
/// Trace ID carried by the known-header request.
const TRACE: &str = "4bf92f3577b34da6a3ce929d0e0e4736";

/// Load the example with a real policy document and isolated sockets.
fn config(backend: u16, tracing: bool, environment: &str, known: bool) -> (TempDir, Config) {
    let dir = TempDir::new().unwrap();
    let mut policy = include_str!("../../../fixtures/request-context-policy.yaml").to_owned();
    if !tracing {
        policy = policy
            .lines()
            .filter(|line| !line.contains("exists(request."))
            .collect::<Vec<_>>()
            .join("\n");
    } else if known {
        policy = policy
            .replace("exists(request.request_id)", "request.request_id == 'known-request'")
            .replace("exists(request.trace_id)", &format!("request.trace_id == '{TRACE}'"));
    }
    let policy_path = dir.path().join("policy.yaml");
    std::fs::write(&policy_path, policy).unwrap();
    let mut yaml = std::fs::read_to_string(example_config_path("security/policy-request-context.yaml"))
        .unwrap()
        .replace("/etc/praxis/request-context-policy.yaml", policy_path.to_str().unwrap())
        .replace("environment: production", &format!("environment: {environment}"));
    if !tracing {
        yaml = yaml.replace("      - filter: trace_context\n", "");
    }
    let yaml = patch_yaml(&yaml, free_port(), &HashMap::from([("127.0.0.1:3000", backend)]));
    (dir, Config::from_yaml(&yaml).unwrap())
}

/// A fresh identity accepted by the example's fixture.
fn token() -> String {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let claims = serde_json::json!({
        "iss": "https://idp.example.com", "aud": "praxis-policy-example",
        "sub": "alice", "iat": now, "exp": now + 300,
    });
    super::jwt::hs256(&claims, None, SECRET.as_bytes())
}

#[test]
fn policy_request_context_known_and_generated_ids_reach_both_phases() {
    for known in [true, false] {
        let backend = start_header_echo_backend();
        let (_dir, config) = config(backend.port(), true, "production", known);
        let proxy = start_proxy(&config);
        let headers = if known {
            format!("X-Request-Id: known-request\r\nTraceparent: 00-{TRACE}-00f067aa0ba902b7-01\r\n")
        } else {
            String::new()
        };
        let raw = http_send(
            proxy.addr(),
            &format!(
                "GET / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\n{headers}Connection: close\r\n\r\n",
                token()
            ),
        );
        assert_eq!(
            parse_status(&raw),
            200,
            "both request and response predicates must pass: {raw}"
        );
        assert!(
            raw.to_ascii_lowercase().contains("x-request-id:"),
            "correlation reaches upstream: {raw}"
        );
        if known {
            assert!(raw.contains("known-request") && raw.contains(TRACE), "{raw}");
        }
    }
}

#[test]
fn policy_request_context_environment_only_still_enforces_policy() {
    for (environment, status) in [("production", 200), ("staging", 403)] {
        let backend = start_header_echo_backend();
        let (_dir, config) = config(backend.port(), false, environment, false);
        let proxy = start_proxy(&config);
        let raw = http_send(
            proxy.addr(),
            &format!(
                "GET / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\nConnection: close\r\n\r\n",
                token()
            ),
        );
        assert_eq!(parse_status(&raw), status, "environment policy without tracing: {raw}");
    }
}
