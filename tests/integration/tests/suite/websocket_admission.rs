// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Adapter-level WebSocket admission tests. The light harness installs listener
//! policies directly; the server's explicit-policy startup gate remains in place
//! until the final-response enforcement layer lands.

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use praxis_core::config::Config;
use praxis_filter::{
    BodyAccess, BodyRequirement, FilterAction, FilterError, FilterFactory, FilterRegistry, HttpFilter,
    HttpFilterContext,
};
use praxis_test_utils::{
    custom_filter_yaml, free_port, http_send, parse_status, start_proxy_with_registry, start_request_counting_backend,
};

/// Request-filter behavior used to probe the adapter admission boundary.
#[derive(Clone, Copy)]
enum Behavior {
    Observe,
    RequiredBody,
    ChangeKey,
    RemoveUpgrade,
}

/// Counts filter execution and optionally requires a body or mutates the offer.
struct AdmissionFilter {
    behavior: Behavior,
    calls: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl HttpFilter for AdmissionFilter {
    fn name(&self) -> &'static str {
        "test_admission"
    }

    fn request_body_access(&self) -> BodyAccess {
        match self.behavior {
            Behavior::RequiredBody => BodyAccess::ReadOnly(BodyRequirement::Required),
            Behavior::Observe | Behavior::ChangeKey | Behavior::RemoveUpgrade => BodyAccess::None,
        }
    }

    async fn on_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        match self.behavior {
            Behavior::ChangeKey => ctx.request_headers_to_set.push((
                http::HeaderName::from_static("sec-websocket-key"),
                http::HeaderValue::from_static("YWJjZGVmZ2hpamtsbW5vcA=="),
            )),
            Behavior::RemoveUpgrade => ctx
                .request_headers_to_remove
                .push(http::HeaderName::from_static("upgrade")),
            Behavior::Observe | Behavior::RequiredBody => {},
        }
        Ok(FilterAction::Continue)
    }
}

/// Check local refusals and count request-filter and upstream execution.
fn assert_refusal(behavior: Behavior, policy: Option<&str>, headers: &str, expected: u16, expected_calls: usize) {
    let (backend, requests) = start_request_counting_backend("must not reach upstream");
    let config_yaml = custom_filter_yaml(free_port(), backend.port(), "test_admission");
    let mut config = Config::from_yaml(&config_yaml).unwrap();
    config.listeners[0].upgrade_policy = policy.map(|yaml| serde_yaml::from_str(yaml).unwrap());
    let calls = Arc::new(AtomicUsize::new(0));
    let captured = Arc::clone(&calls);
    let mut registry = FilterRegistry::with_builtins();
    registry
        .register(
            "test_admission",
            FilterFactory::Http(Arc::new(move |_| {
                Ok(Box::new(AdmissionFilter {
                    behavior,
                    calls: Arc::clone(&captured),
                }))
            })),
        )
        .unwrap();
    let proxy = start_proxy_with_registry(&config, &registry);
    let baseline_calls = calls.load(Ordering::SeqCst);
    let baseline_requests = requests.load(Ordering::SeqCst);
    let raw = http_send(
        proxy.addr(),
        &format!("GET / HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n{headers}\r\n"),
    );
    assert_eq!(parse_status(&raw), expected, "unexpected admission response: {raw}");
    assert_eq!(
        requests.load(Ordering::SeqCst),
        baseline_requests,
        "refused offers must never reach upstream"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst) - baseline_calls,
        expected_calls,
        "admission must precede request filters"
    );
}

/// Complete RFC 6455 request fields shared by adapter tests.
const HANDSHAKE: &str = "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n";

#[test]
fn websocket_policy_denial_precedes_request_filters() {
    assert_refusal(Behavior::Observe, Some("default: deny"), HANDSHAKE, 403, 0);
}

#[test]
fn websocket_malformed_handshake_precedes_request_filters() {
    assert_refusal(
        Behavior::Observe,
        None,
        "Sec-WebSocket-Key: invalid\r\nSec-WebSocket-Version: 13\r\n",
        400,
        0,
    );
}

#[test]
fn websocket_required_body_processing_is_refused_before_upstream() {
    assert_refusal(Behavior::RequiredBody, None, HANDSHAKE, 403, 0);
}

#[test]
fn websocket_filter_changed_key_is_refused_before_upstream() {
    assert_refusal(Behavior::ChangeKey, None, HANDSHAKE, 502, 1);
}

#[test]
fn websocket_filter_removed_upgrade_is_refused_before_upstream() {
    assert_refusal(Behavior::RemoveUpgrade, None, HANDSHAKE, 502, 1);
}

#[test]
fn websocket_duplicate_subprotocols_are_refused_before_upstream() {
    for protocols in [
        "Sec-WebSocket-Protocol: chat, chat\r\n",
        "Sec-WebSocket-Protocol: chat\r\nSec-WebSocket-Protocol: chat\r\n",
    ] {
        assert_refusal(Behavior::Observe, None, &format!("{HANDSHAKE}{protocols}"), 400, 0);
    }
}
