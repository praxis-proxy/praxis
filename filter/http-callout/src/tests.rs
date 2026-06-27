// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Unit tests for the HTTP callout filter.
//!
//! Uses [`wiremock`] to simulate the callout backend.

#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::needless_pass_by_value,
    clippy::too_many_lines,
    reason = "tests"
)]
mod filter_tests {
    use std::time::Duration;

    use praxis_filter::{BodyAccess, BodyMode, FilterAction};
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    use crate::HttpCalloutFilter;

    // -------------------------------------------------------------------------
    // Config Parsing
    // -------------------------------------------------------------------------

    #[test]
    fn config_valid_minimal() {
        let yaml = serde_yaml::from_str::<serde_yaml::Value>(
            r#"
            target:
              url: "http://example.com/api"
            "#,
        )
        .unwrap();

        let filter = HttpCalloutFilter::from_config(&yaml).unwrap();
        assert_eq!(filter.name(), "http_callout");
    }

    #[test]
    fn config_missing_target() {
        let yaml = serde_yaml::from_str::<serde_yaml::Value>("{}").unwrap();
        let err = HttpCalloutFilter::from_config(&yaml).err().expect("expected error");
        assert!(
            err.to_string().contains("target"),
            "should mention missing target: {err}"
        );
    }

    #[test]
    fn config_invalid_url_no_scheme() {
        let yaml = serde_yaml::from_str::<serde_yaml::Value>(
            r#"
            target:
              url: "example.com/api"
            "#,
        )
        .unwrap();

        let err = HttpCalloutFilter::from_config(&yaml).err().expect("expected error");
        assert!(
            err.to_string().contains("invalid") || err.to_string().contains("http or https"),
            "should reject URL without scheme: {err}"
        );
    }

    #[test]
    fn config_invalid_url_template() {
        let yaml = serde_yaml::from_str::<serde_yaml::Value>(
            r#"
            target:
              url: "https://${HOST}/api"
            "#,
        )
        .unwrap();

        let err = HttpCalloutFilter::from_config(&yaml).err().expect("expected error");
        assert!(
            err.to_string().contains("template"),
            "should reject template URL: {err}"
        );
    }

    #[test]
    fn config_invalid_jsonpath() {
        let yaml = serde_yaml::from_str::<serde_yaml::Value>(
            r#"
            target:
              url: "http://example.com/api"
            response:
              extract:
                - json_path: "$[invalid"
                  result_key: "key"
            "#,
        )
        .unwrap();

        let err = HttpCalloutFilter::from_config(&yaml).err().expect("expected error");
        assert!(
            err.to_string().contains("invalid JSONPath"),
            "should reject invalid JSONPath: {err}"
        );
    }

    #[test]
    fn config_env_var_expansion_unset() {
        let yaml = serde_yaml::from_str::<serde_yaml::Value>(
            r#"
            target:
              url: "http://example.com/api"
              headers:
                - name: "Authorization"
                  value: "Bearer ${PRAXIS_TEST_MISSING_VAR_ABC123}"
            "#,
        )
        .unwrap();

        let err = HttpCalloutFilter::from_config(&yaml).err().expect("expected error");
        assert!(
            err.to_string().contains("not set"),
            "should fail on unset env var: {err}"
        );
    }

    #[test]
    fn config_non_http_scheme_rejected() {
        let yaml = serde_yaml::from_str::<serde_yaml::Value>(
            r#"
            target:
              url: "ftp://example.com/file"
            "#,
        )
        .unwrap();

        let err = HttpCalloutFilter::from_config(&yaml).err().expect("expected error");
        assert!(
            err.to_string().contains("http or https"),
            "should reject non-http scheme: {err}"
        );
    }

    // -------------------------------------------------------------------------
    // Phase Handling
    // -------------------------------------------------------------------------

    #[test]
    fn phase_request_headers_body_access_is_none() {
        let yaml = serde_yaml::from_str::<serde_yaml::Value>(
            r#"
            target:
              url: "http://example.com/api"
            request:
              phase: request_headers
            "#,
        )
        .unwrap();

        let filter = HttpCalloutFilter::from_config(&yaml).unwrap();
        assert_eq!(filter.request_body_access(), BodyAccess::None);
        assert_eq!(filter.request_body_mode(), BodyMode::Stream);
    }

    #[test]
    fn phase_request_body_access_is_readonly() {
        let yaml = serde_yaml::from_str::<serde_yaml::Value>(
            r#"
            target:
              url: "http://example.com/api"
            request:
              phase: request_body
            "#,
        )
        .unwrap();

        let filter = HttpCalloutFilter::from_config(&yaml).unwrap();
        assert_eq!(filter.request_body_access(), BodyAccess::ReadOnly);
        assert!(
            matches!(
                filter.request_body_mode(),
                BodyMode::StreamBuffer { max_bytes: Some(_) }
            ),
            "request_body phase should use StreamBuffer"
        );
    }

    #[test]
    fn needs_request_context_is_true() {
        let yaml = serde_yaml::from_str::<serde_yaml::Value>(
            r#"
            target:
              url: "http://example.com/api"
            "#,
        )
        .unwrap();

        let filter = HttpCalloutFilter::from_config(&yaml).unwrap();
        assert!(filter.needs_request_context());
    }

    // -------------------------------------------------------------------------
    // Successful Callout
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn successful_callout_extracts_results() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/guard"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "flagged": true,
                "score": 0.95
            })))
            .mount(&mock_server)
            .await;

        let yaml = serde_yaml::from_str::<serde_yaml::Value>(&format!(
            r#"
            target:
              url: "{}/guard"
            request:
              phase: request_headers
            response:
              extract:
                - json_path: "$.flagged"
                  result_key: "flagged"
                - json_path: "$.score"
                  result_key: "score"
            "#,
            mock_server.uri()
        ))
        .unwrap();

        let filter = HttpCalloutFilter::from_config(&yaml).unwrap();

        let req = praxis_filter::Request {
            method: http::Method::POST,
            uri: "/test".parse().unwrap(),
            headers: http::HeaderMap::new(),
        };
        let mut ctx = make_test_context(&req);

        let action = filter.on_request(&mut ctx).await.unwrap();
        assert!(
            matches!(action, FilterAction::Continue),
            "should continue after success"
        );

        let results = ctx.filter_results.get("http_callout").expect("should have results");
        assert_eq!(results.get("flagged"), Some("true"));
        assert_eq!(results.get("score"), Some("0.95"));
    }

    // -------------------------------------------------------------------------
    // Failure Modes
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn failure_mode_closed_rejects() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/guard"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&mock_server)
            .await;

        let yaml = serde_yaml::from_str::<serde_yaml::Value>(&format!(
            r#"
            target:
              url: "{}/guard"
            request:
              phase: request_headers
            on_failure: closed
            status_on_error: 403
            "#,
            mock_server.uri()
        ))
        .unwrap();

        let filter = HttpCalloutFilter::from_config(&yaml).unwrap();

        let req = praxis_filter::Request {
            method: http::Method::POST,
            uri: "/test".parse().unwrap(),
            headers: http::HeaderMap::new(),
        };
        let mut ctx = make_test_context(&req);

        let action = filter.on_request(&mut ctx).await.unwrap();
        assert!(
            matches!(action, FilterAction::Reject(r) if r.status == 403),
            "fail-closed should reject with 403"
        );
    }

    #[tokio::test]
    async fn failure_mode_open_continues() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/guard"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&mock_server)
            .await;

        let yaml = serde_yaml::from_str::<serde_yaml::Value>(&format!(
            r#"
            target:
              url: "{}/guard"
            request:
              phase: request_headers
            on_failure: open
            "#,
            mock_server.uri()
        ))
        .unwrap();

        let filter = HttpCalloutFilter::from_config(&yaml).unwrap();

        let req = praxis_filter::Request {
            method: http::Method::POST,
            uri: "/test".parse().unwrap(),
            headers: http::HeaderMap::new(),
        };
        let mut ctx = make_test_context(&req);

        let action = filter.on_request(&mut ctx).await.unwrap();
        assert!(matches!(action, FilterAction::Continue), "fail-open should continue");
    }

    // -------------------------------------------------------------------------
    // Timeout
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn timeout_triggers_failure_mode() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/slow"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(10)))
            .mount(&mock_server)
            .await;

        let yaml = serde_yaml::from_str::<serde_yaml::Value>(&format!(
            r#"
            target:
              url: "{}/slow"
              timeout: "100ms"
            request:
              phase: request_headers
            on_failure: closed
            status_on_error: 504
            "#,
            mock_server.uri()
        ))
        .unwrap();

        let filter = HttpCalloutFilter::from_config(&yaml).unwrap();

        let req = praxis_filter::Request {
            method: http::Method::POST,
            uri: "/test".parse().unwrap(),
            headers: http::HeaderMap::new(),
        };
        let mut ctx = make_test_context(&req);

        let action = filter.on_request(&mut ctx).await.unwrap();
        assert!(
            matches!(action, FilterAction::Reject(r) if r.status == 504),
            "timeout should reject with configured status"
        );
    }

    // -------------------------------------------------------------------------
    // Depth Limiting
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn depth_limit_rejects_at_max() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/guard"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0) // should not be called
            .mount(&mock_server)
            .await;

        let yaml = serde_yaml::from_str::<serde_yaml::Value>(&format!(
            r#"
            target:
              url: "{}/guard"
            request:
              phase: request_headers
            on_failure: closed
            max_depth: 1
            "#,
            mock_server.uri()
        ))
        .unwrap();

        let filter = HttpCalloutFilter::from_config(&yaml).unwrap();

        let mut headers = http::HeaderMap::new();
        headers.insert("x-praxis-callout-depth", "1".parse().unwrap());

        let req = praxis_filter::Request {
            method: http::Method::POST,
            uri: "/test".parse().unwrap(),
            headers,
        };
        let mut ctx = make_test_context(&req);

        let action = filter.on_request(&mut ctx).await.unwrap();
        assert!(
            matches!(action, FilterAction::Reject(_)),
            "depth >= max_depth should reject"
        );
    }

    // -------------------------------------------------------------------------
    // Forward Headers
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn forward_headers_copied_to_callout() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/guard"))
            .and(wiremock::matchers::header("x-custom", "my-value"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true})))
            .mount(&mock_server)
            .await;

        let yaml = serde_yaml::from_str::<serde_yaml::Value>(&format!(
            r#"
            target:
              url: "{}/guard"
              forward_headers:
                - "x-custom"
            request:
              phase: request_headers
            "#,
            mock_server.uri()
        ))
        .unwrap();

        let filter = HttpCalloutFilter::from_config(&yaml).unwrap();

        let mut headers = http::HeaderMap::new();
        headers.insert("x-custom", "my-value".parse().unwrap());

        let req = praxis_filter::Request {
            method: http::Method::POST,
            uri: "/test".parse().unwrap(),
            headers,
        };
        let mut ctx = make_test_context(&req);

        let action = filter.on_request(&mut ctx).await.unwrap();
        assert!(matches!(action, FilterAction::Continue), "forward_headers should work");
    }

    // -------------------------------------------------------------------------
    // Inject Headers
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn inject_headers_from_callout_response() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/guard"))
            .respond_with(
                ResponseTemplate::new(200)
                    .append_header("x-guard-id", "abc-123")
                    .set_body_json(serde_json::json!({"ok": true})),
            )
            .mount(&mock_server)
            .await;

        let yaml = serde_yaml::from_str::<serde_yaml::Value>(&format!(
            r#"
            target:
              url: "{}/guard"
            request:
              phase: request_headers
            response:
              inject_headers:
                - "x-guard-id"
            "#,
            mock_server.uri()
        ))
        .unwrap();

        let filter = HttpCalloutFilter::from_config(&yaml).unwrap();

        let req = praxis_filter::Request {
            method: http::Method::POST,
            uri: "/test".parse().unwrap(),
            headers: http::HeaderMap::new(),
        };
        let mut ctx = make_test_context(&req);

        let action = filter.on_request(&mut ctx).await.unwrap();
        assert!(matches!(action, FilterAction::Continue));

        let injected = ctx
            .extra_request_headers
            .iter()
            .find(|(name, _)| name.as_ref() == "x-guard-id");
        assert!(injected.is_some(), "x-guard-id should be injected");
        assert_eq!(injected.unwrap().1, "abc-123");
    }

    // -------------------------------------------------------------------------
    // Request Body Phase
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn request_body_phase_skips_on_request() {
        let yaml = serde_yaml::from_str::<serde_yaml::Value>(
            r#"
            target:
              url: "http://example.com/api"
            request:
              phase: request_body
            "#,
        )
        .unwrap();

        let filter = HttpCalloutFilter::from_config(&yaml).unwrap();

        let req = praxis_filter::Request {
            method: http::Method::POST,
            uri: "/test".parse().unwrap(),
            headers: http::HeaderMap::new(),
        };
        let mut ctx = make_test_context(&req);

        let action = filter.on_request(&mut ctx).await.unwrap();
        assert!(
            matches!(action, FilterAction::Continue),
            "request_body phase should skip on_request"
        );
    }

    #[tokio::test]
    async fn request_body_phase_fires_on_end_of_stream() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/guard"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"flagged": false})))
            .mount(&mock_server)
            .await;

        let yaml = serde_yaml::from_str::<serde_yaml::Value>(&format!(
            r#"
            target:
              url: "{}/guard"
            request:
              phase: request_body
            response:
              extract:
                - json_path: "$.flagged"
                  result_key: "flagged"
            "#,
            mock_server.uri()
        ))
        .unwrap();

        let filter = HttpCalloutFilter::from_config(&yaml).unwrap();

        let req = praxis_filter::Request {
            method: http::Method::POST,
            uri: "/test".parse().unwrap(),
            headers: http::HeaderMap::new(),
        };
        let mut ctx = make_test_context(&req);
        let mut body = Some(bytes::Bytes::from(r#"{"prompt":"hello"}"#));

        let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
        assert!(matches!(action, FilterAction::Continue));

        let results = ctx.filter_results.get("http_callout").expect("should have results");
        assert_eq!(results.get("flagged"), Some("false"));
    }

    #[tokio::test]
    async fn request_body_phase_skips_non_eos() {
        let yaml = serde_yaml::from_str::<serde_yaml::Value>(
            r#"
            target:
              url: "http://example.com/api"
            request:
              phase: request_body
            "#,
        )
        .unwrap();

        let filter = HttpCalloutFilter::from_config(&yaml).unwrap();

        let req = praxis_filter::Request {
            method: http::Method::POST,
            uri: "/test".parse().unwrap(),
            headers: http::HeaderMap::new(),
        };
        let mut ctx = make_test_context(&req);
        let mut body = Some(bytes::Bytes::from("chunk"));

        let action = filter.on_request_body(&mut ctx, &mut body, false).await.unwrap();
        assert!(
            matches!(action, FilterAction::Continue),
            "should skip non-end-of-stream chunks"
        );
    }

    // -------------------------------------------------------------------------
    // Circuit Breaker
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn circuit_breaker_trips_after_threshold() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/guard"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&mock_server)
            .await;

        let yaml = serde_yaml::from_str::<serde_yaml::Value>(&format!(
            r#"
            target:
              url: "{}/guard"
            request:
              phase: request_headers
            on_failure: closed
            status_on_error: 503
            circuit_breaker:
              failure_threshold: 2
              recovery_timeout: "60s"
            "#,
            mock_server.uri()
        ))
        .unwrap();

        let filter = HttpCalloutFilter::from_config(&yaml).unwrap();

        // Fire enough requests to trip the breaker.
        for _ in 0..3 {
            let req = praxis_filter::Request {
                method: http::Method::POST,
                uri: "/test".parse().unwrap(),
                headers: http::HeaderMap::new(),
            };
            let mut ctx = make_test_context(&req);
            let _action = filter.on_request(&mut ctx).await.unwrap();
        }

        // After the breaker trips, requests should still be rejected
        // without hitting the server.
        let req = praxis_filter::Request {
            method: http::Method::POST,
            uri: "/test".parse().unwrap(),
            headers: http::HeaderMap::new(),
        };
        let mut ctx = make_test_context(&req);
        let action = filter.on_request(&mut ctx).await.unwrap();
        assert!(
            matches!(action, FilterAction::Reject(r) if r.status == 503),
            "circuit breaker should reject after threshold"
        );
    }

    // -------------------------------------------------------------------------
    // JSONPath Coercion (via filter)
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn extraction_integer_coerced_to_string() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/guard"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"count": 42})))
            .mount(&mock_server)
            .await;

        let yaml = serde_yaml::from_str::<serde_yaml::Value>(&format!(
            r#"
            target:
              url: "{}/guard"
            request:
              phase: request_headers
            response:
              extract:
                - json_path: "$.count"
                  result_key: "count"
            "#,
            mock_server.uri()
        ))
        .unwrap();

        let filter = HttpCalloutFilter::from_config(&yaml).unwrap();

        let req = praxis_filter::Request {
            method: http::Method::POST,
            uri: "/test".parse().unwrap(),
            headers: http::HeaderMap::new(),
        };
        let mut ctx = make_test_context(&req);

        let _action = filter.on_request(&mut ctx).await.unwrap();
        let results = ctx.filter_results.get("http_callout").expect("should have results");
        assert_eq!(results.get("count"), Some("42"));
    }

    #[tokio::test]
    async fn extraction_null_skipped() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/guard"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"field": null})))
            .mount(&mock_server)
            .await;

        let yaml = serde_yaml::from_str::<serde_yaml::Value>(&format!(
            r#"
            target:
              url: "{}/guard"
            request:
              phase: request_headers
            response:
              extract:
                - json_path: "$.field"
                  result_key: "field"
            "#,
            mock_server.uri()
        ))
        .unwrap();

        let filter = HttpCalloutFilter::from_config(&yaml).unwrap();

        let req = praxis_filter::Request {
            method: http::Method::POST,
            uri: "/test".parse().unwrap(),
            headers: http::HeaderMap::new(),
        };
        let mut ctx = make_test_context(&req);

        let _action = filter.on_request(&mut ctx).await.unwrap();
        // No results written when null.
        let has_field = ctx
            .filter_results
            .get("http_callout")
            .is_some_and(|rs| rs.get("field").is_some());
        assert!(!has_field, "null field should not be written to results");
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// Build a minimal [`HttpFilterContext`] for unit tests.
    fn make_test_context(req: &praxis_filter::Request) -> praxis_filter::HttpFilterContext<'_> {
        use std::sync::LazyLock;

        use praxis_core::id::IdGenerator;

        static TEST_ID_GEN: LazyLock<IdGenerator> = LazyLock::new(|| IdGenerator::with_seed(0));

        praxis_filter::HttpFilterContext {
            body_done_indices: Vec::new(),
            branch_iterations: std::collections::HashMap::new(),
            client_addr: None,
            cluster: None,
            current_filter_id: None,
            downstream_tls: false,
            extensions: praxis_filter::RequestExtensions::default(),
            executed_filter_indices: Vec::new(),
            extra_request_headers: Vec::new(),
            request_headers_to_remove: Vec::new(),
            request_headers_to_set: Vec::new(),
            filter_metadata: std::collections::HashMap::new(),
            filter_results: std::collections::HashMap::new(),
            filter_state: std::collections::HashMap::new(),
            health_registry: None,
            id_generator: &TEST_ID_GEN,
            kv_stores: None,
            request: req,
            request_body_bytes: 0,
            request_body_mode: BodyMode::Stream,
            request_start: std::time::Instant::now(),
            response_body_bytes: 0,
            response_body_mode: BodyMode::Stream,
            response_header: None,
            response_headers_modified: false,
            selected_endpoint_index: None,
            time_source: &praxis_core::time::SystemTimeSource,
            upstream: None,
            rewritten_path: None,
        }
    }
}
