// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Unit tests for the sticky sessions filter.

#![expect(clippy::expect_used, clippy::unwrap_used, reason = "tests")]
#![expect(clippy::disallowed_methods, reason = "sync tests need thread::sleep")]

use super::*;

#[test]
fn from_config_parses_valid_cookie_config() {
    let yaml = serde_yaml::from_str(
        r#"
clusters:
  - name: backend
    type: cookie
    cookie_name: "_praxis_route"
    ttl_secs: 3600
    cookie_attributes:
      path: "/"
      http_only: true
      secure: true
    max_entries: 1000
    storage: local
"#,
    )
    .unwrap();
    let filter = StickySessionsFilter::from_config(&yaml);
    filter.unwrap();
}

#[test]
fn from_config_rejects_missing_cookie_name() {
    let yaml = serde_yaml::from_str(
        "
clusters:
  - name: backend
    type: cookie
    ttl_secs: 3600
    storage: local
",
    )
    .unwrap();
    let filter = StickySessionsFilter::from_config(&yaml);
    assert!(filter.is_err());
}

#[test]
fn from_config_rejects_missing_header_name() {
    let yaml = serde_yaml::from_str(
        "
clusters:
  - name: backend
    type: header
    ttl_secs: 3600
    storage: local
",
    )
    .unwrap();
    let filter = StickySessionsFilter::from_config(&yaml);
    assert!(filter.is_err());
}

#[test]
fn filter_owns_stores() {
    let yaml = serde_yaml::from_str(
        r#"
clusters:
  - name: cluster-a
    type: cookie
    cookie_name: "_sess"
    ttl_secs: 3600
    max_entries: 1000
    storage: local
"#,
    )
    .unwrap();
    let filter = StickySessionsFilter::from_config(&yaml);
    assert!(filter.is_ok(), "filter should be created successfully with stores");
}

#[test]
fn from_config_rejects_omitted_storage() {
    let yaml = serde_yaml::from_str(
        r#"
clusters:
  - name: backend
    type: cookie
    cookie_name: "_sess"
"#,
    )
    .unwrap();
    // `Box<dyn HttpFilter>` is not `Debug`, so unwrap the error side.
    let err = StickySessionsFilter::from_config(&yaml).err().unwrap();
    assert!(err.to_string().contains("storage"), "got: {err}");
}

#[test]
fn session_store_falls_back_to_filter_registry_without_pipeline_stores() {
    let cfg = Arc::new(ClusterSessionConfig {
        name: "cluster-a".into(),
        persistence: PersistenceConfig::Cookie {
            cookie_name: "_sess".into(),
            cookie_attributes: CookieAttributes::default(),
        },
        ttl_secs: 3600,
        failover: true,
        max_entries: config::MaxEntries::try_from(1000).unwrap(),
        eviction: config::EvictionPolicy::Lru,
        storage: StorageConfig::Local,
    });
    let mut configs = HashMap::new();
    configs.insert(Arc::<str>::from("cluster-a"), Arc::clone(&cfg));
    let filter = StickySessionsFilter {
        stores: Arc::new(StickySessionsFilter::build_stores(&configs)),
        configs,
    };

    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let ctx = crate::test_utils::make_filter_context(&req);
    assert!(ctx.session_stores.is_none(), "context should lack pipeline stores");

    let store = filter.session_store(&ctx, &cfg, "cluster-a");
    store.put("sess-1", Arc::from("10.0.0.1:80"));

    let again = filter.session_store(&ctx, &cfg, "cluster-a");
    assert_eq!(
        again.get("sess-1").as_deref(),
        Some("10.0.0.1:80"),
        "fallback registry should return the same store across calls"
    );
}

#[test]
fn generate_session_id_is_unique() {
    let id1 = generate_session_id();
    let id2 = generate_session_id();
    assert_ne!(id1, id2, "consecutive session IDs should differ");
    assert_eq!(id1.len(), 16, "session ID should be 16 hex characters");
    assert!(
        id1.bytes().all(|b| b.is_ascii_hexdigit()),
        "session ID should be hex: {id1}"
    );
}

#[test]
fn extract_session_key_header_mode() {
    let cfg = ClusterSessionConfig {
        name: "backend".into(),
        persistence: PersistenceConfig::Header {
            header_name: "X-Session-Id".into(),
        },
        ttl_secs: 3600,
        failover: true,
        max_entries: config::MaxEntries::try_from(1000).unwrap(),
        eviction: config::EvictionPolicy::Lru,
        storage: StorageConfig::Local,
    };

    let mut req = crate::test_utils::make_request(http::Method::GET, "/");
    req.headers
        .insert("x-session-id", http::HeaderValue::from_static("abc-123"));
    let ctx = crate::test_utils::make_filter_context(&req);

    let key = StickySessionsFilter::extract_session_key(&cfg, &ctx);
    assert_eq!(key.as_deref(), Some("abc-123"));
}

#[test]
fn extract_session_key_learn_mode_reads_cookie() {
    let cfg = ClusterSessionConfig {
        name: "backend".into(),
        persistence: PersistenceConfig::Learn {
            cookie_name: "JSESSIONID".into(),
        },
        ttl_secs: 3600,
        failover: true,
        max_entries: config::MaxEntries::try_from(1000).unwrap(),
        eviction: config::EvictionPolicy::Lru,
        storage: StorageConfig::Local,
    };

    let mut req = crate::test_utils::make_request(http::Method::GET, "/");
    req.headers.insert(
        http::header::COOKIE,
        http::HeaderValue::from_static("JSESSIONID=sess42; other=val"),
    );
    let ctx = crate::test_utils::make_filter_context(&req);

    let key = StickySessionsFilter::extract_session_key(&cfg, &ctx);
    assert_eq!(key.as_deref(), Some("sess42"));
}

#[test]
fn extract_session_key_rejects_overlong_key() {
    let cfg = ClusterSessionConfig {
        name: "backend".into(),
        persistence: PersistenceConfig::Header {
            header_name: "X-Session-Id".into(),
        },
        ttl_secs: 3600,
        failover: true,
        max_entries: config::MaxEntries::try_from(1000).unwrap(),
        eviction: config::EvictionPolicy::Lru,
        storage: StorageConfig::Local,
    };

    let long_key = "x".repeat(MAX_SESSION_KEY_LEN + 1);
    let mut req = crate::test_utils::make_request(http::Method::GET, "/");
    req.headers
        .insert("x-session-id", http::HeaderValue::from_str(&long_key).unwrap());
    let ctx = crate::test_utils::make_filter_context(&req);

    let key = StickySessionsFilter::extract_session_key(&cfg, &ctx);
    assert!(
        key.is_none(),
        "should reject keys longer than {MAX_SESSION_KEY_LEN} bytes"
    );
}

#[test]
fn handle_learn_response_records_session() {
    let store = SessionStore::new(100, Duration::from_secs(3600), config::EvictionPolicy::Lru);
    let endpoint: Arc<str> = Arc::from("10.0.0.1:80");

    let cfg = Arc::new(ClusterSessionConfig {
        name: "backend".into(),
        persistence: PersistenceConfig::Learn {
            cookie_name: "JSESSIONID".into(),
        },
        ttl_secs: 3600,
        failover: true,
        max_entries: config::MaxEntries::try_from(1000).unwrap(),
        eviction: config::EvictionPolicy::Lru,
        storage: StorageConfig::Local,
    });

    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut resp = crate::test_utils::make_response();
    resp.headers.insert(
        http::header::SET_COOKIE,
        http::HeaderValue::from_static("JSESSIONID=learned123; Path=/"),
    );
    ctx.response_header = Some(&mut resp);

    StickySessionsFilter::handle_learn_response(&cfg, &ctx, &store, &endpoint);

    assert_eq!(store.get("learned123").as_deref(), Some("10.0.0.1:80"));
}

#[test]
fn handle_header_response_records_session() {
    let store = SessionStore::new(100, Duration::from_secs(3600), config::EvictionPolicy::Lru);
    let endpoint: Arc<str> = Arc::from("10.0.0.2:80");

    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.filter_metadata
        .insert(META_SESSION_KEY, "header-key-abc")
        .expect("entry must fit in the filter's metadata");
    ctx.upstream_reached = true;
    ctx.extensions
        .insert(crate::UpstreamForwardedEndpoint(Arc::clone(&endpoint)));

    StickySessionsFilter::handle_header_response(&ctx, &store, &endpoint);

    assert_eq!(store.get("header-key-abc").as_deref(), Some("10.0.0.2:80"));
}

#[test]
fn header_connect_failure_does_not_create_binding() {
    let store = SessionStore::new(100, Duration::from_secs(3600), config::EvictionPolicy::Lru);
    let endpoint: Arc<str> = Arc::from("10.0.0.2:80");
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.filter_metadata
        .insert(META_SESSION_KEY, "failed-key")
        .expect("entry must fit in the filter's metadata");
    ctx.upstream_reached = true;

    StickySessionsFilter::handle_header_response(&ctx, &store, &endpoint);

    assert!(
        store.get("failed-key").is_none(),
        "selecting a peer is not a successful dial"
    );
}

#[test]
fn header_local_rejection_does_not_create_binding() {
    let store = SessionStore::new(100, Duration::from_secs(3600), config::EvictionPolicy::Lru);
    let endpoint: Arc<str> = Arc::from("10.0.0.2:80");
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.filter_metadata
        .insert(META_SESSION_KEY, "local-key")
        .expect("entry must fit in the filter's metadata");
    // An earlier attempt can leave this request-level bit true while the
    // response hook sees a later local terminal header.
    ctx.upstream_reached = true;

    let mut local_response = crate::test_utils::make_response();
    local_response.status = http::StatusCode::FORBIDDEN;
    ctx.response_header = Some(&mut local_response);
    StickySessionsFilter::handle_header_response(&ctx, &store, &endpoint);

    assert!(
        store.get("local-key").is_none(),
        "a local response header cannot establish a backend session"
    );
}

/// Emit an actual terminal response after endpoint selection in the unit fixture.
struct LocalTerminalFilter;

#[async_trait::async_trait]
impl HttpFilter for LocalTerminalFilter {
    fn name(&self) -> &'static str {
        "test_local_terminal"
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        let mut headers = http::HeaderMap::new();
        headers.insert("x-fixture-terminal", http::HeaderValue::from_static("local"));
        Ok(FilterAction::TerminalResponse(Box::new(
            crate::TerminalResponse::new(202)
                .with_headers(headers)
                .with_body("local-terminal"),
        )))
    }
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "the fixture and local response assertions prove the complete pipeline path"
)]
async fn header_local_terminal_response_with_header_does_not_bind() -> Result<(), FilterError> {
    let yaml = "
- filter: router
  routes:
    - path_prefix: /
      cluster: backend
- filter: sticky_sessions
  clusters:
    - name: backend
      type: header
      header_name: X-Session-Id
      ttl_secs: 3600
      max_entries: 1000
      storage: local
- filter: load_balancer
  clusters:
    - name: backend
      endpoints: ['127.0.0.1:9']
- filter: test_local_terminal
";
    let mut registry = crate::FilterRegistry::with_builtins();
    registry
        .register(
            "test_local_terminal",
            crate::FilterFactory::Http(Arc::new(|_| Ok(Box::new(LocalTerminalFilter)))),
        )
        .unwrap();
    let mut entries: Vec<crate::FilterEntry> = serde_yaml::from_str(yaml).unwrap();
    let mut pipeline = crate::FilterPipeline::build(&mut entries, &registry).unwrap();
    let stores = Arc::new(SessionStoreRegistry::new());
    pipeline.set_session_stores(Arc::clone(&stores));
    let store = stores.get_or_create("backend", 1000, Duration::from_secs(3600), config::EvictionPolicy::Lru);
    let mut req = crate::test_utils::make_request(http::Method::GET, "/");
    req.headers
        .insert("x-session-id", http::HeaderValue::from_static("local-terminal"));
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.session_stores = Some(&stores);

    let terminal = match pipeline.execute_http_request(&mut ctx).await.unwrap() {
        FilterAction::TerminalResponse(terminal) => terminal,
        other => return Err(format!("expected a real terminal response after selection, got {other:?}").into()),
    };
    assert_eq!(terminal.status, 202, "the local status is synthetic");
    assert_eq!(terminal.body.as_deref(), Some(b"local-terminal".as_slice()));
    assert_eq!(
        terminal.headers.get("x-fixture-terminal"),
        Some(&http::HeaderValue::from_static("local"))
    );
    assert!(
        ctx.upstream.is_some(),
        "load balancer must have selected an endpoint before local terminal"
    );
    assert_eq!(
        ctx.filter_metadata.get(META_SESSION_KEY),
        Some("local-terminal"),
        "the sticky filter must carry this exact key into response processing"
    );
    let mut response = crate::Response {
        status: http::StatusCode::from_u16(terminal.status).unwrap(),
        headers: terminal.headers.clone(),
    };
    ctx.response_header = Some(&mut response);
    drop(pipeline.execute_http_response(&mut ctx).await.unwrap());
    drop(ctx);
    assert_eq!(response.status, http::StatusCode::ACCEPTED);

    assert!(
        store.get("local-terminal").is_none(),
        "a synthetic local header must not authorize a binding"
    );
    Ok(())
}

#[test]
fn header_failed_failover_keeps_previous_binding() {
    let store = SessionStore::new(100, Duration::from_secs(3600), config::EvictionPolicy::Lru);
    let previous: Arc<str> = Arc::from("10.0.0.1:80");
    let failed: Arc<str> = Arc::from("10.0.0.2:80");
    store.put("existing-key", Arc::clone(&previous));
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.filter_metadata
        .insert(META_SESSION_KEY, "existing-key")
        .expect("entry must fit in the filter's metadata");

    StickySessionsFilter::handle_header_response(&ctx, &store, &failed);

    assert_eq!(
        store.get("existing-key"),
        Some(previous),
        "failed failover must retain the usable binding"
    );
}

#[test]
fn header_later_failed_dial_does_not_claim_endpoint() {
    let store = SessionStore::new(100, Duration::from_secs(3600), config::EvictionPolicy::Lru);
    let connected: Arc<str> = Arc::from("10.0.0.1:80");
    let failed: Arc<str> = Arc::from("10.0.0.2:80");
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.filter_metadata
        .insert(META_SESSION_KEY, "retry-key")
        .expect("entry must fit in the filter's metadata");
    ctx.upstream_reached = true;
    ctx.extensions.insert(crate::UpstreamForwardedEndpoint(connected));

    StickySessionsFilter::handle_header_response(&ctx, &store, &failed);

    assert!(
        store.get("retry-key").is_none(),
        "an earlier endpoint cannot authorize a later failed dial"
    );
}

#[test]
fn header_read_failure_obeys_binding_policy() {
    let store = SessionStore::new(100, Duration::from_secs(3600), config::EvictionPolicy::Lru);
    let endpoint: Arc<str> = Arc::from("10.0.0.2:80");
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.filter_metadata
        .insert(META_SESSION_KEY, "ambiguous-key")
        .expect("entry must fit in the filter's metadata");
    ctx.upstream_reached = true;
    ctx.extensions
        .insert(crate::UpstreamForwardedEndpoint(Arc::clone(&endpoint)));

    StickySessionsFilter::handle_header_response(&ctx, &store, &endpoint);

    assert_eq!(
        store.get("ambiguous-key"),
        Some(endpoint),
        "the backend may have created state before read failed"
    );
}

#[test]
fn header_successful_exchange_creates_binding() {
    let store = SessionStore::new(100, Duration::from_secs(3600), config::EvictionPolicy::Lru);
    let endpoint: Arc<str> = Arc::from("10.0.0.2:80");
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.filter_metadata
        .insert(META_SESSION_KEY, "served-key")
        .expect("entry must fit in the filter's metadata");
    ctx.upstream_reached = true;
    ctx.extensions
        .insert(crate::UpstreamForwardedEndpoint(Arc::clone(&endpoint)));
    let mut response = crate::test_utils::make_response();
    ctx.response_header = Some(&mut response);

    StickySessionsFilter::handle_header_response(&ctx, &store, &endpoint);

    assert_eq!(
        store.get("served-key"),
        Some(endpoint),
        "a served header-mode request must remain sticky"
    );
}

#[test]
fn put_update_replaces_endpoint_without_duplicate_entry() {
    let store = SessionStore::new(100, Duration::from_millis(500), config::EvictionPolicy::Ttl);
    store.put("key1", "ep1".into());
    std::thread::sleep(Duration::from_millis(10));
    store.put("key1", "ep2".into());

    assert_eq!(
        store.get("key1").as_deref(),
        Some("ep2"),
        "update should replace the endpoint in place"
    );
    assert_eq!(store.len(), 1, "update must not create a duplicate map entry");
}

#[test]
fn opportunistic_sweep_fires_after_half_ttl() {
    let store = SessionStore::new(100, Duration::from_millis(20), config::EvictionPolicy::Lru);
    store.put("a", "ep1".into());
    store.put("b", "ep2".into());

    std::thread::sleep(Duration::from_millis(25));

    assert!(
        store.get("a").is_none(),
        "expired 'a' should be gone, and the miss should trigger a sweep"
    );
    assert_eq!(store.len(), 0, "the opportunistic sweep should also remove expired 'b'");
}

// -----------------------------------------------------------------------------
// Regression tests for review fixes
// -----------------------------------------------------------------------------

/// A cookie-mode cluster config for response-handling tests.
fn cookie_cfg() -> Arc<ClusterSessionConfig> {
    Arc::new(ClusterSessionConfig {
        name: "backend".into(),
        persistence: PersistenceConfig::Cookie {
            cookie_name: "_praxis_route".into(),
            cookie_attributes: CookieAttributes::default(),
        },
        ttl_secs: 3600,
        failover: true,
        max_entries: config::MaxEntries::try_from(1000).unwrap(),
        eviction: config::EvictionPolicy::Lru,
        storage: StorageConfig::Local,
    })
}

#[test]
fn cookie_response_does_not_adopt_unknown_client_value() {
    let store = SessionStore::new(100, Duration::from_secs(3600), config::EvictionPolicy::Lru);
    let endpoint: Arc<str> = Arc::from("10.0.0.1:80");
    let cfg = cookie_cfg();

    let mut req = crate::test_utils::make_request(http::Method::GET, "/");
    req.headers.insert(
        http::header::COOKIE,
        http::HeaderValue::from_static("_praxis_route=attacker-chosen"),
    );
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.filter_metadata
        .insert(META_SESSION_KEY, "attacker-chosen")
        .expect("entry must fit in the filter's metadata");
    let mut resp = crate::test_utils::make_response();
    ctx.response_header = Some(&mut resp);

    StickySessionsFilter::handle_cookie_response(&cfg, &mut ctx, &store, &endpoint);

    assert!(
        store.get("attacker-chosen").is_none(),
        "client-chosen keys must never be adopted into the store"
    );
    assert_eq!(store.len(), 1, "a fresh server-minted binding should exist");
}

#[test]
fn cookie_response_repins_known_value_after_failover() {
    let store = SessionStore::new(100, Duration::from_secs(3600), config::EvictionPolicy::Lru);
    store.put("sessA", Arc::from("10.0.0.1:80"));
    let new_endpoint: Arc<str> = Arc::from("10.0.0.2:80");
    let cfg = cookie_cfg();

    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.filter_metadata
        .insert(META_SESSION_KEY, "sessA")
        .expect("entry must fit in the filter's metadata");
    let mut resp = crate::test_utils::make_response();
    ctx.response_header = Some(&mut resp);

    StickySessionsFilter::handle_cookie_response(&cfg, &mut ctx, &store, &new_endpoint);

    assert_eq!(
        store.get("sessA").as_deref(),
        Some("10.0.0.2:80"),
        "an established session should re-pin to the serving endpoint"
    );
    assert_eq!(store.len(), 1, "failover must not mint a second binding");
}

#[test]
fn cookie_response_skips_store_when_no_response_header() {
    let store = SessionStore::new(100, Duration::from_secs(3600), config::EvictionPolicy::Lru);
    let endpoint: Arc<str> = Arc::from("10.0.0.1:80");
    let cfg = cookie_cfg();

    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    StickySessionsFilter::handle_cookie_response(&cfg, &mut ctx, &store, &endpoint);

    assert!(
        store.is_empty(),
        "no binding should be written when the exchange produced no response headers"
    );
}

#[test]
fn learn_response_repins_existing_binding_after_failover() {
    let store = SessionStore::new(100, Duration::from_secs(3600), config::EvictionPolicy::Lru);
    store.put("sess1", Arc::from("10.0.0.1:80"));
    let new_endpoint: Arc<str> = Arc::from("10.0.0.2:80");

    let cfg = Arc::new(ClusterSessionConfig {
        name: "backend".into(),
        persistence: PersistenceConfig::Learn {
            cookie_name: "JSESSIONID".into(),
        },
        ttl_secs: 3600,
        failover: true,
        max_entries: config::MaxEntries::try_from(1000).unwrap(),
        eviction: config::EvictionPolicy::Lru,
        storage: StorageConfig::Local,
    });

    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.filter_metadata
        .insert(META_SESSION_KEY, "sess1")
        .expect("entry must fit in the filter's metadata");
    let mut resp = crate::test_utils::make_response();
    ctx.response_header = Some(&mut resp);

    StickySessionsFilter::handle_learn_response(&cfg, &ctx, &store, &new_endpoint);

    assert_eq!(
        store.get("sess1").as_deref(),
        Some("10.0.0.2:80"),
        "existing learn-mode binding should re-pin to the serving endpoint"
    );
}

#[test]
fn learn_response_does_not_adopt_unknown_metadata_key() {
    let store = SessionStore::new(100, Duration::from_secs(3600), config::EvictionPolicy::Lru);
    let endpoint: Arc<str> = Arc::from("10.0.0.1:80");

    let cfg = Arc::new(ClusterSessionConfig {
        name: "backend".into(),
        persistence: PersistenceConfig::Learn {
            cookie_name: "JSESSIONID".into(),
        },
        ttl_secs: 3600,
        failover: true,
        max_entries: config::MaxEntries::try_from(1000).unwrap(),
        eviction: config::EvictionPolicy::Lru,
        storage: StorageConfig::Local,
    });

    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.filter_metadata
        .insert(META_SESSION_KEY, "never-bound")
        .expect("entry must fit in the filter's metadata");
    let mut resp = crate::test_utils::make_response();
    ctx.response_header = Some(&mut resp);

    StickySessionsFilter::handle_learn_response(&cfg, &ctx, &store, &endpoint);

    assert!(
        store.is_empty(),
        "learn mode must not adopt client-presented keys that were never bound"
    );
}

#[test]
fn registry_preserves_store_across_reload_when_config_unchanged() {
    let registry = SessionStoreRegistry::new();
    let first = registry.get_or_create("backend", 100, Duration::from_secs(3600), config::EvictionPolicy::Lru);
    first.put("sess1", Arc::from("10.0.0.1:80"));

    let second = registry.get_or_create("backend", 100, Duration::from_secs(3600), config::EvictionPolicy::Lru);
    assert!(
        Arc::ptr_eq(&first, &second),
        "unchanged config must reuse the existing store"
    );
    assert_eq!(
        second.get("sess1").as_deref(),
        Some("10.0.0.1:80"),
        "session bindings must survive a reload"
    );

    let third = registry.get_or_create("backend", 100, Duration::from_secs(60), config::EvictionPolicy::Lru);
    assert!(!Arc::ptr_eq(&first, &third), "changed config must replace the store");
    assert!(third.get("sess1").is_none(), "replaced store starts empty");
}

#[test]
fn find_request_cookie_checks_all_cookie_headers() {
    let mut req = crate::test_utils::make_request(http::Method::GET, "/");
    req.headers
        .append(http::header::COOKIE, http::HeaderValue::from_static("other=1"));
    req.headers.append(
        http::header::COOKIE,
        http::HeaderValue::from_static("_praxis_route=split-value"),
    );
    let ctx = crate::test_utils::make_filter_context(&req);

    assert_eq!(
        StickySessionsFilter::find_request_cookie(&ctx, "_praxis_route").as_deref(),
        Some("split-value"),
        "cookie lookup must consider every Cookie header"
    );
}
/// Select streaming without changing affinity processing.
struct StickyStreamingSelector;

#[async_trait::async_trait]
impl HttpFilter for StickyStreamingSelector {
    fn name(&self) -> &'static str {
        "sticky_streaming_selector"
    }

    fn may_select_streaming_subrequest_response(&self) -> bool {
        true
    }

    async fn on_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        ctx.set_subrequest_response_mode(crate::SubRequestResponseMode::Streaming);
        Ok(FilterAction::Continue)
    }
}

/// A backend whose receipt counter also witnesses deliberately missing responses.
async fn sticky_counted_backend(
    reply: bool,
) -> (
    std::net::SocketAddr,
    Arc<std::sync::atomic::AtomicUsize>,
    tokio::task::JoinHandle<()>,
) {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let receipt = Arc::clone(&count);
    let task = tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                head.push(socket.read_u8().await.unwrap());
            }
            receipt.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if reply {
                socket
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .await
                    .unwrap();
            }
        }
    });
    (address, count, task)
}

#[tokio::test]
#[expect(
    clippy::large_futures,
    reason = "exercises real buffered and streaming nested exchanges"
)]
#[expect(
    clippy::too_many_lines,
    reason = "both response modes verify backend receipt and parent scope restoration"
)]
async fn nested_header_affinity_preserves_success_and_ambiguous_read_bindings() -> Result<(), FilterError> {
    for streaming in [false, true] {
        for reply in [false, true] {
            let (first, first_count, first_task) = sticky_counted_backend(reply).await;
            let (second, second_count, second_task) = sticky_counted_backend(true).await;
            let (pipeline, stores) = nested_sticky_pipeline(first, second, streaming);
            let client = praxis_core::subrequest::SubRequestClient::new(crate::test_support::connector(4, None));
            let executor = crate::FilteredSubrequestExecutor::for_callout(
                client,
                crate::SubrequestRuntime::new(None, false, None, std::time::Instant::now()),
                0,
                1024,
                Duration::from_secs(2),
            );
            let mut request = crate::SubRequest {
                method: http::Method::GET,
                uri: http::Uri::from_static("/"),
                headers: http::HeaderMap::new(),
                body: bytes::Bytes::new(),
            };
            request
                .headers
                .insert("x-session-id", http::HeaderValue::from_static("nested-session"));
            for _ in 0..2 {
                let parent_endpoint: Arc<str> = Arc::from("parent.example:80");
                let mut extensions = crate::RequestExtensions::default();
                extensions.insert(crate::UpstreamForwardedEndpoint(Arc::clone(&parent_endpoint)));
                let input = crate::filtered_subrequest::FilteredSubrequestInput::callout(
                    &pipeline,
                    &request,
                    std::time::Instant::now() + Duration::from_secs(2),
                    extensions,
                );
                let crate::filtered_subrequest::OpenedSubrequest { continuation, kind } =
                    match executor.execute(input).await {
                        Ok(opened) => opened,
                        Err(error) => return Err(error.into_parts().0),
                    };
                let status = match &kind {
                    crate::filtered_subrequest::OpenedResponse::Complete(outcome)
                    | crate::filtered_subrequest::OpenedResponse::Streaming { outcome, .. } => outcome.response.status,
                };
                assert_eq!(
                    status,
                    if reply { 200 } else { 502 },
                    "must observe the first backend's actual exchange outcome"
                );
                drop(kind);
                let restored = continuation.into_parent_extensions();
                assert_eq!(
                    restored
                        .get::<crate::UpstreamForwardedEndpoint>()
                        .map(|marker| &marker.0),
                    Some(&parent_endpoint),
                    "child forwarding must restore parent evidence"
                );
            }
            let store = stores.get_or_create("backend", 100, Duration::from_secs(3600), config::EvictionPolicy::Lru);
            assert_eq!(store.get("nested-session").as_deref(), Some(first.to_string().as_str()));
            assert_eq!(
                first_count.load(std::sync::atomic::Ordering::SeqCst),
                2,
                "both actual requests must reach the bound endpoint"
            );
            assert_eq!(
                second_count.load(std::sync::atomic::Ordering::SeqCst),
                0,
                "the second round-robin endpoint must be bypassed by affinity"
            );
            first_task.abort();
            second_task.abort();
        }
    }
    Ok(())
}

/// Build the actual nested sticky chain for two observable transport endpoints.
fn nested_sticky_pipeline(
    first: std::net::SocketAddr,
    second: std::net::SocketAddr,
    streaming: bool,
) -> (Arc<crate::FilterPipeline>, Arc<SessionStoreRegistry>) {
    let selector = if streaming {
        "- filter: sticky_streaming_selector\n"
    } else {
        ""
    };
    let yaml = format!(
        "{selector}- filter: router\n  routes:\n    - path_prefix: /\n      cluster: backend\n- filter: sticky_sessions\n  clusters:\n    - name: backend\n      type: header\n      header_name: X-Session-Id\n      ttl_secs: 3600\n      max_entries: 100\n      storage: local\n- filter: load_balancer\n  clusters:\n    - name: backend\n      load_balancer_strategy: round_robin\n      endpoints: ['{first}', '{second}']\n"
    );
    let mut registry = crate::FilterRegistry::with_builtins();
    registry
        .register(
            "sticky_streaming_selector",
            crate::FilterFactory::Http(Arc::new(|_| Ok(Box::new(StickyStreamingSelector)))),
        )
        .unwrap();
    let mut entries = serde_yaml::from_str::<Vec<crate::FilterEntry>>(&yaml).unwrap();
    let mut pipeline = crate::FilterPipeline::build(&mut entries, &registry).unwrap();
    let stores = Arc::new(SessionStoreRegistry::new());
    pipeline.set_session_stores(Arc::clone(&stores));
    pipeline.set_allow_private_upstreams(true);
    let pipeline = Arc::new(pipeline);
    (pipeline, stores)
}

#[tokio::test]
#[expect(
    clippy::large_futures,
    reason = "exercises nested failed dial followed by real forwarded requests"
)]
#[expect(
    clippy::too_many_lines,
    reason = "failed dial and subsequent exchanges prove absence then establishment of affinity"
)]
async fn nested_failed_dial_cannot_inherit_parent_forwarding_or_create_affinity() {
    for streaming in [false, true] {
        let refused = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let refused_address = refused.local_addr().unwrap();
        drop(refused);
        let (healthy, count, backend) = sticky_counted_backend(true).await;
        let (pipeline, stores) = nested_sticky_pipeline(refused_address, healthy, streaming);
        let client = praxis_core::subrequest::SubRequestClient::new(crate::test_support::connector(4, None));
        let executor = crate::FilteredSubrequestExecutor::for_callout(
            client,
            crate::SubrequestRuntime::new(None, false, None, std::time::Instant::now()),
            0,
            1024,
            Duration::from_secs(2),
        );
        let mut request = crate::SubRequest {
            method: http::Method::GET,
            uri: http::Uri::from_static("/"),
            headers: http::HeaderMap::new(),
            body: bytes::Bytes::new(),
        };
        request
            .headers
            .insert("x-session-id", http::HeaderValue::from_static("failed-then-healthy"));
        let store = stores.get_or_create("backend", 100, Duration::from_secs(3600), config::EvictionPolicy::Lru);
        for expected in [502, 200, 200] {
            let mut extensions = crate::RequestExtensions::default();
            extensions.insert(crate::UpstreamForwardedEndpoint(Arc::from(refused_address.to_string())));
            let result = executor
                .run(
                    &pipeline,
                    &request,
                    extensions,
                    std::time::Instant::now() + Duration::from_secs(2),
                )
                .await
                .unwrap();
            let status = match result {
                crate::CalloutResponse::Buffered(response) | crate::CalloutResponse::Streaming { response, .. } => {
                    response.status
                },
            };
            assert_eq!(
                status, expected,
                "failed dial must permit a fresh selection, then successful affinity"
            );
            if expected == 502 {
                assert!(
                    store.get("failed-then-healthy").is_none(),
                    "parent forwarding cannot authorize a failed child dial"
                );
                assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 0);
            } else {
                assert_eq!(
                    store.get("failed-then-healthy").as_deref(),
                    Some(healthy.to_string().as_str())
                );
            }
        }
        assert_eq!(
            count.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "both later requests must reach the healthy pinned endpoint"
        );
        backend.abort();
    }
}

#[tokio::test]
#[expect(
    clippy::large_futures,
    reason = "drives real staged-address fallback in both nested response modes"
)]
#[expect(
    clippy::too_many_lines,
    reason = "first fallback and subsequent pinned exchange require distinct transport assertions"
)]
async fn nested_fallback_binds_the_address_that_forwarded_the_request() {
    for streaming in [false, true] {
        let (_reserved, refused) = crate::test_support::refusing_addr();
        let (healthy, count, backend) = sticky_counted_backend(true).await;
        let (pipeline, stores) = nested_sticky_pipeline(refused, healthy, streaming);
        let client = praxis_core::subrequest::SubRequestClient::new(crate::test_support::connector(4, None));
        let executor = crate::FilteredSubrequestExecutor::for_callout(
            client,
            crate::SubrequestRuntime::new(None, false, None, std::time::Instant::now()),
            0,
            1024,
            Duration::from_secs(2),
        );
        let mut request = crate::SubRequest {
            method: http::Method::GET,
            uri: http::Uri::from_static("/"),
            headers: http::HeaderMap::new(),
            body: bytes::Bytes::new(),
        };
        request
            .headers
            .insert("x-session-id", http::HeaderValue::from_static("fallback-session"));
        let staged = crate::StagedUpstream(praxis_core::connectivity::Upstream {
            address: Arc::from(refused.to_string()),
            authority: None,
            base_path: None,
            connection: Arc::new(praxis_core::connectivity::ConnectionOptions::default()),
            tls: None,
        });
        let mut first_extensions = crate::RequestExtensions::default();
        first_extensions.insert(staged);
        first_extensions.insert(crate::StagedUpstreamFallback(vec![refused, healthy]));
        let first = executor
            .run(
                &pipeline,
                &request,
                first_extensions,
                std::time::Instant::now() + Duration::from_secs(2),
            )
            .await
            .unwrap();
        let first_status = match first {
            crate::CalloutResponse::Buffered(response) | crate::CalloutResponse::Streaming { response, .. } => {
                response.status
            },
        };
        assert_eq!(first_status, 200, "live fallback must answer");
        assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 1);
        let store = stores.get_or_create("backend", 100, Duration::from_secs(3600), config::EvictionPolicy::Lru);
        assert_eq!(
            store.get("fallback-session").as_deref(),
            Some(healthy.to_string().as_str()),
            "binding must name the backend that received the request"
        );

        for follow_up in 1..=2 {
            let next = executor
                .run(
                    &pipeline,
                    &request,
                    crate::RequestExtensions::default(),
                    std::time::Instant::now() + Duration::from_secs(2),
                )
                .await
                .unwrap();
            let status = match next {
                crate::CalloutResponse::Buffered(response) | crate::CalloutResponse::Streaming { response, .. } => {
                    response.status
                },
            };
            assert_eq!(status, 200, "follow-up {follow_up} must use the healthy binding");
            assert_eq!(
                count.load(std::sync::atomic::Ordering::SeqCst),
                follow_up + 1,
                "follow-up {follow_up} must reach the real fallback backend"
            );
            assert_eq!(
                store.get("fallback-session").as_deref(),
                Some(healthy.to_string().as_str()),
                "follow-up {follow_up} must retain the forwarded endpoint binding"
            );
        }
        backend.abort();
    }
}
