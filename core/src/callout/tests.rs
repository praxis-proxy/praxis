// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Unit tests for the callout client.

#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    reason = "tests"
)]
mod unit {
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_bytes, header, method, path},
    };

    use super::super::{
        CalloutClient, CalloutConfig, CalloutRequest, CalloutResult, CircuitBreakerConfig, FailureMode,
        circuit::{CircuitBreaker, CircuitState},
    };

    // -------------------------------------------------------------------------
    // Circuit breaker tests (1–13)
    // -------------------------------------------------------------------------

    #[test]
    fn cb_starts_closed() {
        let cb = CircuitBreaker::new(3, 1_000);
        assert_eq!(cb.check(), CircuitState::Closed, "new breaker should be Closed");
    }

    #[test]
    fn cb_stays_closed_below_threshold() {
        let cb = CircuitBreaker::new(3, 1_000);
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.check(), CircuitState::Closed, "should stay Closed below threshold");
    }

    #[test]
    fn cb_trips_at_threshold() {
        let cb = CircuitBreaker::new(3, 1_000);
        cb.record_failure();
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.check(), CircuitState::Open, "should trip to Open at threshold");
    }

    #[test]
    fn cb_success_resets_count() {
        let cb = CircuitBreaker::new(3, 1_000);
        cb.record_failure();
        cb.record_failure();
        cb.record_success();
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.check(), CircuitState::Closed, "success should reset failure count");
    }

    #[test]
    fn cb_open_rejects() {
        let cb = CircuitBreaker::new(1, 60_000);
        cb.record_failure();
        assert_eq!(cb.check(), CircuitState::Open, "should be Open after tripping");
    }

    #[tokio::test]
    async fn cb_half_open_after_recovery() {
        let cb = CircuitBreaker::new(1, 1); // 1 ms recovery
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open, "should be Open after failure");
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        assert_eq!(
            cb.check(),
            CircuitState::HalfOpen,
            "should be HalfOpen after recovery window"
        );
    }

    #[tokio::test]
    async fn cb_half_open_success_closes() {
        let cb = CircuitBreaker::new(1, 1);
        cb.record_failure();
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        assert_eq!(cb.check(), CircuitState::HalfOpen, "should be HalfOpen");
        cb.record_success();
        assert_eq!(cb.state(), CircuitState::Closed, "success in HalfOpen should close");
    }

    #[tokio::test]
    async fn cb_half_open_failure_reopens() {
        let cb = CircuitBreaker::new(1, 1);
        cb.record_failure();
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        assert_eq!(cb.check(), CircuitState::HalfOpen, "should be HalfOpen");
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open, "failure in HalfOpen should reopen");
    }

    #[tokio::test]
    async fn cb_half_open_one_probe_only() {
        let cb = CircuitBreaker::new(1, 1);
        cb.record_failure();
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        assert_eq!(cb.check(), CircuitState::HalfOpen, "first check should be HalfOpen");
        assert_eq!(cb.check(), CircuitState::Open, "second check should be Open");
    }

    #[test]
    fn cb_open_record_failure_noop() {
        let cb = CircuitBreaker::new(1, 60_000);
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open, "should be Open");
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open, "failure in Open should be no-op");
    }

    #[test]
    fn cb_open_record_success_noop() {
        let cb = CircuitBreaker::new(1, 60_000);
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open, "should be Open");
        cb.record_success();
        assert_eq!(cb.state(), CircuitState::Open, "success in Open should be no-op");
    }

    #[test]
    fn cb_consecutive_successes_stay_closed() {
        let cb = CircuitBreaker::new(3, 1_000);
        cb.record_success();
        cb.record_success();
        cb.record_success();
        assert_eq!(
            cb.check(),
            CircuitState::Closed,
            "consecutive successes should stay Closed"
        );
    }

    #[test]
    fn cb_saturating_failure_count() {
        let cb = CircuitBreaker::new(u32::MAX, 60_000);
        for _ in 0..100 {
            cb.record_failure();
        }
        assert_eq!(
            cb.check(),
            CircuitState::Closed,
            "should stay Closed with u32::MAX threshold"
        );
    }

    // -------------------------------------------------------------------------
    // Config validation tests (14–20)
    // -------------------------------------------------------------------------

    #[test]
    fn new_valid_config() {
        let client = CalloutClient::new(CalloutConfig::default());
        assert!(client.is_ok(), "default config should build");
    }

    #[test]
    fn new_with_circuit_breaker() {
        let config = CalloutConfig {
            circuit_breaker: Some(CircuitBreakerConfig {
                consecutive_failures: 5,
                recovery_window_ms: 30_000,
            }),
            ..CalloutConfig::default()
        };
        assert!(CalloutClient::new(config).is_ok(), "CB config should build");
    }

    #[test]
    fn new_rejects_zero_timeout() {
        let config = CalloutConfig {
            timeout_ms: 0,
            ..CalloutConfig::default()
        };
        let err = CalloutClient::new(config).unwrap_err();
        assert!(
            err.to_string().contains("timeout_ms"),
            "error should mention timeout_ms"
        );
    }

    #[test]
    fn new_rejects_status_below_100() {
        let config = CalloutConfig {
            status_on_error: 99,
            ..CalloutConfig::default()
        };
        let err = CalloutClient::new(config).unwrap_err();
        assert!(
            err.to_string().contains("status_on_error"),
            "error should mention status_on_error"
        );
    }

    #[test]
    fn new_rejects_status_above_599() {
        let config = CalloutConfig {
            status_on_error: 600,
            ..CalloutConfig::default()
        };
        let err = CalloutClient::new(config).unwrap_err();
        assert!(
            err.to_string().contains("status_on_error"),
            "error should mention status_on_error"
        );
    }

    #[test]
    fn new_rejects_cb_zero_threshold() {
        let config = CalloutConfig {
            circuit_breaker: Some(CircuitBreakerConfig {
                consecutive_failures: 0,
                recovery_window_ms: 1_000,
            }),
            ..CalloutConfig::default()
        };
        let err = CalloutClient::new(config).unwrap_err();
        assert!(
            err.to_string().contains("consecutive_failures"),
            "error should mention consecutive_failures"
        );
    }

    #[test]
    fn new_rejects_cb_zero_recovery() {
        let config = CalloutConfig {
            circuit_breaker: Some(CircuitBreakerConfig {
                consecutive_failures: 5,
                recovery_window_ms: 0,
            }),
            ..CalloutConfig::default()
        };
        let err = CalloutClient::new(config).unwrap_err();
        assert!(
            err.to_string().contains("recovery_window_ms"),
            "error should mention recovery_window_ms"
        );
    }

    // -------------------------------------------------------------------------
    // Execute — happy path (21–25)
    // -------------------------------------------------------------------------

    fn default_request(url: &str) -> CalloutRequest {
        CalloutRequest {
            body: None,
            depth: 0,
            headers: vec![],
            method: http::Method::GET,
            url: url.to_owned(),
        }
    }

    fn make_client() -> CalloutClient {
        CalloutClient::new(CalloutConfig::default()).unwrap()
    }

    #[tokio::test]
    async fn execute_success() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/check"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_bytes(b"ok".to_vec())
                    .append_header("x-custom", "value"),
            )
            .mount(&server)
            .await;

        let client = make_client();
        let req = default_request(&format!("{}/check", server.uri()));
        let result = client.execute(req).await;

        match result {
            CalloutResult::Success(resp) => {
                assert_eq!(resp.status, 200, "status should be 200");
                assert_eq!(resp.body, b"ok", "body should be captured");
                assert!(
                    resp.headers.iter().any(|(k, v)| k == "x-custom" && v == "value"),
                    "response headers should contain x-custom"
                );
            },
            _ => panic!("expected Success"),
        }
    }

    #[tokio::test]
    async fn execute_sends_headers() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/check"))
            .and(header("authorization", "Bearer token123"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let client = make_client();
        let req = CalloutRequest {
            body: None,
            depth: 0,
            headers: vec![(
                http::HeaderName::from_static("authorization"),
                http::HeaderValue::from_static("Bearer token123"),
            )],
            method: http::Method::GET,
            url: format!("{}/check", server.uri()),
        };
        let result = client.execute(req).await;
        assert!(
            matches!(result, CalloutResult::Success(_)),
            "should succeed with matching headers"
        );
    }

    #[tokio::test]
    async fn execute_sends_body() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/check"))
            .and(body_bytes(b"hello".to_vec()))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let client = make_client();
        let req = CalloutRequest {
            body: Some(b"hello".to_vec()),
            depth: 0,
            headers: vec![],
            method: http::Method::POST,
            url: format!("{}/check", server.uri()),
        };
        let result = client.execute(req).await;
        assert!(
            matches!(result, CalloutResult::Success(_)),
            "should succeed with matching body"
        );
    }

    #[tokio::test]
    async fn execute_sends_method() {
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/check"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let client = make_client();
        let req = CalloutRequest {
            body: None,
            depth: 0,
            headers: vec![],
            method: http::Method::PUT,
            url: format!("{}/check", server.uri()),
        };
        let result = client.execute(req).await;
        assert!(
            matches!(result, CalloutResult::Success(_)),
            "should succeed with PUT method"
        );
    }

    #[tokio::test]
    async fn execute_injects_depth_header() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/check"))
            .and(header("x-praxis-callout-depth", "2"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let client = CalloutClient::new(CalloutConfig {
            max_depth: 3,
            ..CalloutConfig::default()
        })
        .unwrap();
        let req = CalloutRequest {
            body: None,
            depth: 1,
            headers: vec![],
            method: http::Method::GET,
            url: format!("{}/check", server.uri()),
        };
        let result = client.execute(req).await;
        assert!(
            matches!(result, CalloutResult::Success(_)),
            "should inject depth header N+1"
        );
    }

    // -------------------------------------------------------------------------
    // Execute — failure modes (26–33)
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn execute_timeout_closed_rejects() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/slow"))
            .respond_with(ResponseTemplate::new(200).set_delay(std::time::Duration::from_secs(5)))
            .mount(&server)
            .await;

        let client = CalloutClient::new(CalloutConfig {
            timeout_ms: 50,
            failure_mode: FailureMode::Closed,
            ..CalloutConfig::default()
        })
        .unwrap();

        let req = default_request(&format!("{}/slow", server.uri()));
        let result = client.execute(req).await;
        assert!(
            matches!(result, CalloutResult::Rejected(_)),
            "timeout with Closed should reject"
        );
    }

    #[tokio::test]
    async fn execute_timeout_open_returns_failed() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/slow"))
            .respond_with(ResponseTemplate::new(200).set_delay(std::time::Duration::from_secs(5)))
            .mount(&server)
            .await;

        let client = CalloutClient::new(CalloutConfig {
            timeout_ms: 50,
            failure_mode: FailureMode::Open,
            ..CalloutConfig::default()
        })
        .unwrap();

        let req = default_request(&format!("{}/slow", server.uri()));
        let result = client.execute(req).await;
        assert!(
            matches!(result, CalloutResult::Failed),
            "timeout with Open should return Failed"
        );
    }

    #[tokio::test]
    async fn execute_connection_error_closed_rejects() {
        let client = CalloutClient::new(CalloutConfig {
            timeout_ms: 500,
            failure_mode: FailureMode::Closed,
            ..CalloutConfig::default()
        })
        .unwrap();

        let req = default_request("http://127.0.0.1:1/check");
        let result = client.execute(req).await;
        assert!(
            matches!(result, CalloutResult::Rejected(_)),
            "connection error with Closed should reject"
        );
    }

    #[tokio::test]
    async fn execute_connection_error_open_returns_failed() {
        let client = CalloutClient::new(CalloutConfig {
            timeout_ms: 500,
            failure_mode: FailureMode::Open,
            ..CalloutConfig::default()
        })
        .unwrap();

        let req = default_request("http://127.0.0.1:1/check");
        let result = client.execute(req).await;
        assert!(
            matches!(result, CalloutResult::Failed),
            "connection error with Open should return Failed"
        );
    }

    #[tokio::test]
    async fn execute_non_2xx_closed_rejects() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/fail"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let client = CalloutClient::new(CalloutConfig {
            failure_mode: FailureMode::Closed,
            ..CalloutConfig::default()
        })
        .unwrap();

        let req = default_request(&format!("{}/fail", server.uri()));
        let result = client.execute(req).await;
        assert!(
            matches!(result, CalloutResult::Rejected(_)),
            "non-2xx with Closed should reject"
        );
    }

    #[tokio::test]
    async fn execute_non_2xx_open_returns_failed() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/fail"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let client = CalloutClient::new(CalloutConfig {
            failure_mode: FailureMode::Open,
            ..CalloutConfig::default()
        })
        .unwrap();

        let req = default_request(&format!("{}/fail", server.uri()));
        let result = client.execute(req).await;
        assert!(
            matches!(result, CalloutResult::Failed),
            "non-2xx with Open should return Failed"
        );
    }

    #[tokio::test]
    async fn execute_redirect_not_followed() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/redirect"))
            .respond_with(ResponseTemplate::new(302).append_header("location", "http://example.com"))
            .mount(&server)
            .await;

        let client = CalloutClient::new(CalloutConfig {
            failure_mode: FailureMode::Closed,
            ..CalloutConfig::default()
        })
        .unwrap();

        let req = default_request(&format!("{}/redirect", server.uri()));
        let result = client.execute(req).await;
        assert!(
            matches!(result, CalloutResult::Rejected(_)),
            "302 should reject (no redirect following)"
        );
    }

    #[tokio::test]
    async fn execute_custom_status_on_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/fail"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let client = CalloutClient::new(CalloutConfig {
            failure_mode: FailureMode::Closed,
            status_on_error: 503,
            ..CalloutConfig::default()
        })
        .unwrap();

        let req = default_request(&format!("{}/fail", server.uri()));
        let result = client.execute(req).await;
        match result {
            CalloutResult::Rejected(r) => assert_eq!(r.status, 503, "rejection should use configured status"),
            _ => panic!("expected Rejected"),
        }
    }

    // -------------------------------------------------------------------------
    // Execute — loop prevention (34–37)
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn execute_depth_at_max_closed_rejects() {
        let client = CalloutClient::new(CalloutConfig {
            max_depth: 3,
            failure_mode: FailureMode::Closed,
            ..CalloutConfig::default()
        })
        .unwrap();

        let req = CalloutRequest {
            body: None,
            depth: 3,
            headers: vec![],
            method: http::Method::GET,
            url: "http://127.0.0.1:1/check".into(),
        };
        let result = client.execute(req).await;
        assert!(
            matches!(result, CalloutResult::Rejected(_)),
            "depth at max should reject"
        );
    }

    #[tokio::test]
    async fn execute_depth_at_max_open_returns_failed() {
        let client = CalloutClient::new(CalloutConfig {
            max_depth: 3,
            failure_mode: FailureMode::Open,
            ..CalloutConfig::default()
        })
        .unwrap();

        let req = CalloutRequest {
            body: None,
            depth: 3,
            headers: vec![],
            method: http::Method::GET,
            url: "http://127.0.0.1:1/check".into(),
        };
        let result = client.execute(req).await;
        assert!(
            matches!(result, CalloutResult::Failed),
            "depth at max with Open should return Failed"
        );
    }

    #[tokio::test]
    async fn execute_depth_below_max_proceeds() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/check"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let client = CalloutClient::new(CalloutConfig {
            max_depth: 3,
            ..CalloutConfig::default()
        })
        .unwrap();

        let req = CalloutRequest {
            body: None,
            depth: 2,
            headers: vec![],
            method: http::Method::GET,
            url: format!("{}/check", server.uri()),
        };
        let result = client.execute(req).await;
        assert!(
            matches!(result, CalloutResult::Success(_)),
            "depth below max should proceed"
        );
    }

    #[tokio::test]
    async fn execute_max_depth_zero_always_rejects() {
        let client = CalloutClient::new(CalloutConfig {
            max_depth: 0,
            failure_mode: FailureMode::Closed,
            ..CalloutConfig::default()
        })
        .unwrap();

        let req = CalloutRequest {
            body: None,
            depth: 0,
            headers: vec![],
            method: http::Method::GET,
            url: "http://127.0.0.1:1/check".into(),
        };
        let result = client.execute(req).await;
        assert!(
            matches!(result, CalloutResult::Rejected(_)),
            "max_depth 0 should always reject"
        );
    }

    // -------------------------------------------------------------------------
    // Execute — circuit breaker integration (38–44)
    // -------------------------------------------------------------------------

    fn make_cb_config() -> CalloutConfig {
        CalloutConfig {
            circuit_breaker: Some(CircuitBreakerConfig {
                consecutive_failures: 2,
                recovery_window_ms: 60_000,
            }),
            failure_mode: FailureMode::Closed,
            ..CalloutConfig::default()
        }
    }

    fn make_cb_config_open() -> CalloutConfig {
        CalloutConfig {
            circuit_breaker: Some(CircuitBreakerConfig {
                consecutive_failures: 2,
                recovery_window_ms: 60_000,
            }),
            failure_mode: FailureMode::Open,
            ..CalloutConfig::default()
        }
    }

    async fn trip_breaker(client: &CalloutClient, server: &MockServer) {
        Mock::given(method("GET"))
            .and(path("/trip"))
            .respond_with(ResponseTemplate::new(500))
            .mount(server)
            .await;

        let url = format!("{}/trip", server.uri());
        for _ in 0..2 {
            let req = default_request(&url);
            drop(client.execute(req).await);
        }
    }

    #[tokio::test]
    async fn execute_circuit_open_skips_request() {
        let server = MockServer::start().await;
        let client = CalloutClient::new(make_cb_config()).unwrap();
        trip_breaker(&client, &server).await;

        // Set up a mock that should NOT be called.
        Mock::given(method("GET"))
            .and(path("/check"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&server)
            .await;

        let req = default_request(&format!("{}/check", server.uri()));
        let result = client.execute(req).await;
        assert!(
            matches!(result, CalloutResult::Rejected(_)),
            "open circuit should reject"
        );
    }

    #[tokio::test]
    async fn execute_circuit_open_open_mode() {
        let server = MockServer::start().await;
        let client = CalloutClient::new(make_cb_config_open()).unwrap();
        trip_breaker(&client, &server).await;

        let req = default_request(&format!("{}/check", server.uri()));
        let result = client.execute(req).await;
        assert!(
            matches!(result, CalloutResult::Failed),
            "open circuit with Open mode should return Failed"
        );
    }

    #[tokio::test]
    async fn execute_records_success() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/check"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let client = CalloutClient::new(make_cb_config()).unwrap();
        let req = default_request(&format!("{}/check", server.uri()));
        let result = client.execute(req).await;
        assert!(
            matches!(result, CalloutResult::Success(_)),
            "first request should succeed"
        );

        let req2 = default_request(&format!("{}/check", server.uri()));
        let result2 = client.execute(req2).await;
        assert!(
            matches!(result2, CalloutResult::Success(_)),
            "circuit should remain closed after success"
        );
    }

    #[tokio::test]
    async fn execute_records_failure_on_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/fail"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let client = CalloutClient::new(make_cb_config()).unwrap();
        let url = format!("{}/fail", server.uri());

        let req = default_request(&url);
        drop(client.execute(req).await);
        let req2 = default_request(&url);
        drop(client.execute(req2).await);

        // Circuit should now be open.
        Mock::given(method("GET"))
            .and(path("/fail"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&server)
            .await;

        let req3 = default_request(&url);
        let result = client.execute(req3).await;
        assert!(
            matches!(result, CalloutResult::Rejected(_)),
            "circuit should be open after two failures"
        );
    }

    #[tokio::test]
    async fn execute_records_failure_on_timeout() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/slow"))
            .respond_with(ResponseTemplate::new(200).set_delay(std::time::Duration::from_secs(5)))
            .mount(&server)
            .await;

        let config = CalloutConfig {
            timeout_ms: 50,
            circuit_breaker: Some(CircuitBreakerConfig {
                consecutive_failures: 2,
                recovery_window_ms: 60_000,
            }),
            ..CalloutConfig::default()
        };
        let client = CalloutClient::new(config).unwrap();
        let url = format!("{}/slow", server.uri());

        let req = default_request(&url);
        drop(client.execute(req).await);
        let req2 = default_request(&url);
        drop(client.execute(req2).await);

        let req3 = default_request(&url);
        let result = client.execute(req3).await;
        assert!(
            matches!(result, CalloutResult::Rejected(_)),
            "timeouts should trip the circuit breaker"
        );
    }

    #[tokio::test]
    async fn execute_half_open_success_closes() {
        let server = MockServer::start().await;
        let config = CalloutConfig {
            circuit_breaker: Some(CircuitBreakerConfig {
                consecutive_failures: 2,
                recovery_window_ms: 1,
            }),
            ..CalloutConfig::default()
        };
        let client = CalloutClient::new(config).unwrap();
        trip_breaker(&client, &server).await;

        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        Mock::given(method("GET"))
            .and(path("/probe"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let req = default_request(&format!("{}/probe", server.uri()));
        let result = client.execute(req).await;
        assert!(
            matches!(result, CalloutResult::Success(_)),
            "probe success should close circuit"
        );

        let req2 = default_request(&format!("{}/probe", server.uri()));
        let result2 = client.execute(req2).await;
        assert!(
            matches!(result2, CalloutResult::Success(_)),
            "circuit should be closed after probe"
        );
    }

    #[tokio::test]
    async fn execute_half_open_failure_reopens() {
        let server = MockServer::start().await;
        let config = CalloutConfig {
            circuit_breaker: Some(CircuitBreakerConfig {
                consecutive_failures: 2,
                recovery_window_ms: 1,
            }),
            ..CalloutConfig::default()
        };
        let client = CalloutClient::new(config).unwrap();
        trip_breaker(&client, &server).await;

        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        Mock::given(method("GET"))
            .and(path("/probe"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let req = default_request(&format!("{}/probe", server.uri()));
        let result = client.execute(req).await;
        assert!(
            matches!(result, CalloutResult::Rejected(_)),
            "probe failure should reject"
        );

        let req2 = default_request(&format!("{}/probe", server.uri()));
        let result2 = client.execute(req2).await;
        assert!(
            matches!(result2, CalloutResult::Rejected(_)),
            "circuit should remain open after probe failure"
        );
    }

    // -------------------------------------------------------------------------
    // Execute — no circuit breaker (45)
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn execute_no_circuit_breaker_works() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/check"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let config = CalloutConfig {
            circuit_breaker: None,
            ..CalloutConfig::default()
        };
        let client = CalloutClient::new(config).unwrap();

        let req = default_request(&format!("{}/check", server.uri()));
        let result = client.execute(req).await;
        assert!(matches!(result, CalloutResult::Success(_)), "should succeed without CB");

        let req2 = default_request("http://127.0.0.1:1/fail");
        let result2 = client.execute(req2).await;
        assert!(
            matches!(result2, CalloutResult::Rejected(_)),
            "should reject on failure without CB"
        );
    }
}
