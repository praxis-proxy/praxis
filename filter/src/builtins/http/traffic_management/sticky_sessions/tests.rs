// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Unit tests for the sticky sessions filter.

#![expect(clippy::unwrap_used, reason = "tests")]
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
"#,
    )
    .unwrap();
    let filter = StickySessionsFilter::from_config(&yaml);
    assert!(filter.is_ok(), "filter should be created successfully with stores");
}

#[test]
fn generate_session_id_is_unique() {
    let id1 = generate_session_id("10.0.0.1:80");
    std::thread::sleep(Duration::from_millis(1));
    let id2 = generate_session_id("10.0.0.1:80");
    assert_ne!(id1, id2);
    assert_eq!(id1.len(), 16);
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
    ctx.set_metadata(META_SESSION_KEY, "header-key-abc");

    StickySessionsFilter::handle_header_response(&ctx, &store, &endpoint);

    assert_eq!(store.get("header-key-abc").as_deref(), Some("10.0.0.2:80"));
}

#[test]
fn put_update_replaces_endpoint_without_duplicate_entry() {
    // An update must replace the endpoint in place (single map entry, single
    // eviction-queue position) under the TTL policy.
    let store = SessionStore::new(100, Duration::from_millis(500), config::EvictionPolicy::Ttl);
    store.put("key1", "ep1".into());
    std::thread::sleep(Duration::from_millis(10));
    store.put("key1", "ep2".into());

    assert_eq!(store.get("key1").as_deref(), Some("ep2"));
    assert_eq!(store.len(), 1);
}

#[test]
fn opportunistic_sweep_fires_after_half_ttl() {
    let store = SessionStore::new(100, Duration::from_millis(20), config::EvictionPolicy::Lru);
    store.put("a", "ep1".into());
    store.put("b", "ep2".into());

    std::thread::sleep(Duration::from_millis(25));

    // "a" and "b" are expired; the next get (miss) should trigger a sweep
    assert!(store.get("a").is_none());
    // Sweep should have cleaned up "b" as well
    assert_eq!(store.len(), 0);
}

// ---------------------------------------------------------------------------
// Regression tests for review fixes
// ---------------------------------------------------------------------------

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
    // on_request records the extracted key when no binding exists.
    ctx.set_metadata(META_SESSION_KEY, "attacker-chosen");
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
    ctx.set_metadata(META_SESSION_KEY, "sessA");
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
    });

    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.set_metadata(META_SESSION_KEY, "sess1");
    // Upstream response carries no Set-Cookie: backends issue the session
    // cookie once, so a failed-over session must re-pin from metadata.
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
    });

    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.set_metadata(META_SESSION_KEY, "never-bound");
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

    // A rebuilt pipeline resolves the store again with identical bounds.
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

    // Changed bounds get a fresh store (bindings intentionally dropped).
    let third = registry.get_or_create("backend", 100, Duration::from_secs(60), config::EvictionPolicy::Lru);
    assert!(!Arc::ptr_eq(&first, &third), "changed config must replace the store");
    assert!(third.get("sess1").is_none(), "replaced store starts empty");
}

#[test]
fn find_request_cookie_checks_all_cookie_headers() {
    let mut req = crate::test_utils::make_request(http::Method::GET, "/");
    // HTTP/2 clients may split cookies across multiple `cookie` fields.
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
