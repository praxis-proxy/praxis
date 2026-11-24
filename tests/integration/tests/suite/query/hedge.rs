// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! QUERY body replay through configured hedged requests.

use std::sync::{Arc, mpsc};

use praxis_test_utils::{http_send, parse_body, parse_status, start_recording_backend};

use super::{QUERY_BODY, assert_query, observed, request, response, start, yaml};

#[test]
fn query_hedging_replays_the_body_and_returns_the_successful_endpoint() {
    let (release, ready) = mpsc::channel();
    let ready = Arc::new(std::sync::Mutex::new(ready));
    let (primary, primary_log) = start_recording_backend(move |_| {
        ready
            .lock()
            .unwrap()
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        response(503, "unavailable")
    });
    let (copy, copy_log) = start_recording_backend(move |_| {
        release.send(()).unwrap();
        response(200, "results")
    });
    let proxy = start(&hedged_yaml(&[primary.port(), copy.port()], 2));

    let raw = http_send(proxy.addr(), &request("QUERY", QUERY_BODY));

    assert_eq!(
        parse_status(&raw),
        200,
        "the QUERY copy must answer while its primary waits: {raw}"
    );
    assert_eq!(parse_body(&raw), "results");
    assert_query(&observed(&primary_log), QUERY_BODY);
    assert_query(&observed(&copy_log), QUERY_BODY);
}

#[test]
fn query_hedging_respects_the_attempt_limit_and_post_stays_single_attempt() {
    for (method, limit) in [("QUERY", 1), ("POST", 2)] {
        let (primary, primary_log) = start_recording_backend(|_| response(503, "unavailable"));
        let (copy, copy_log) = start_recording_backend(|_| response(200, "results"));
        let proxy = start(&hedged_yaml(&[primary.port(), copy.port()], limit));

        let raw = http_send(proxy.addr(), &request(method, QUERY_BODY));

        assert_eq!(parse_status(&raw), 503, "{method} should stay on one attempt: {raw}");
        assert_eq!(observed(&primary_log).len(), 1);
        assert!(observed(&copy_log).is_empty(), "{method} must not start a copy");
    }
}

#[test]
fn query_hedging_rejects_a_body_above_the_buffer_limit_before_dispatch() {
    let (primary, primary_log) = start_recording_backend(|_| response(200, "results"));
    let (copy, copy_log) = start_recording_backend(|_| response(200, "results"));
    let config = format!(
        "{}\nbody_limits:\n  max_buffer_bytes: 4\n",
        hedged_yaml(&[primary.port(), copy.port()], 2)
    );
    let proxy = start(&config);

    let raw = http_send(proxy.addr(), &request("QUERY", QUERY_BODY));

    assert_eq!(
        parse_status(&raw),
        413,
        "the hedge body limit must apply to QUERY: {raw}"
    );
    assert!(
        observed(&primary_log).is_empty(),
        "an oversized QUERY must not start the primary"
    );
    assert!(
        observed(&copy_log).is_empty(),
        "an oversized QUERY must not start a copy"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Start a second attempt immediately, bounded by the route's attempt cap.
fn hedged_yaml(ports: &[u16], limit: u32) -> String {
    let initial = limit.min(2);
    yaml(ports, "max_retries: 0").replace("            cluster: backend", &format!(
        "            cluster: backend\n            hedge_policy:\n              initial_requests: {initial}\n              max_attempts: {limit}\n              budget_percent: 100"
    ))
}
