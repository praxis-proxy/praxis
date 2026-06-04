// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Tests for the router filter.

use std::collections::HashMap;

use http::{HeaderMap, HeaderValue};
use praxis_core::config::{PathMatch, Route};

use super::{
    ResolvedRoute, RouterFilter,
    config::{JsonAlias, RouterConfig, RouterRouteConfig},
    matching::{route_matches_request, should_stop_early, update_best_match},
};
use crate::{FilterAction, filter::HttpFilter};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn match_root() {
    let router = make_router(vec![prefix_route("/", "default")]);
    let route = router.match_route("/anything", None, &HeaderMap::new()).unwrap();
    assert_eq!(&*route.cluster, "default", "root prefix should match any path");
}

#[test]
fn longest_prefix_wins() {
    let router = make_router(vec![prefix_route("/", "default"), prefix_route("/api/", "api")]);

    let route = router.match_route("/api/users", None, &HeaderMap::new()).unwrap();
    assert_eq!(&*route.cluster, "api", "longer /api/ prefix should win");

    let route = router.match_route("/static/main.js", None, &HeaderMap::new()).unwrap();
    assert_eq!(&*route.cluster, "default", "non-api path should fall back to root");
}

#[test]
fn host_filtering() {
    let router = make_router(vec![
        Route {
            path_match: PathMatch::Prefix {
                path_prefix: "/".to_owned(),
            },
            host: Some("api.example.com".to_owned()),
            headers: None,
            cluster: "api".into(),
        },
        prefix_route("/", "default"),
    ]);

    let route = router
        .match_route("/", Some("api.example.com"), &HeaderMap::new())
        .unwrap();
    assert_eq!(
        &*route.cluster, "api",
        "matching host should select host-specific route"
    );

    let route = router
        .match_route("/", Some("other.example.com"), &HeaderMap::new())
        .unwrap();
    assert_eq!(
        &*route.cluster, "default",
        "non-matching host should fall back to default"
    );
}

#[test]
fn host_with_port() {
    let router = make_router(vec![Route {
        path_match: PathMatch::Prefix {
            path_prefix: "/".to_owned(),
        },
        host: Some("api.example.com".to_owned()),
        headers: None,
        cluster: "api".into(),
    }]);

    let route = router
        .match_route("/", Some("api.example.com:8080"), &HeaderMap::new())
        .unwrap();
    assert_eq!(
        &*route.cluster, "api",
        "host with port should match after stripping port"
    );
}

#[test]
fn no_match() {
    let router = make_router(vec![prefix_route("/api/", "api")]);
    assert!(
        router.match_route("/other", None, &HeaderMap::new()).is_none(),
        "non-matching prefix should return None"
    );
}

#[test]
fn no_match_wrong_host() {
    let router = make_router(vec![Route {
        path_match: PathMatch::Prefix {
            path_prefix: "/".to_owned(),
        },
        host: Some("api.example.com".to_owned()),
        headers: None,
        cluster: "api".into(),
    }]);
    assert!(
        router.match_route("/", Some("other.com"), &HeaderMap::new()).is_none(),
        "wrong host should return no match"
    );
}

#[test]
fn from_config_parses_routes() {
    let yaml = serde_yaml::from_str::<serde_yaml::Value>(
        r#"
            routes:
              - path_prefix: "/api/"
                cluster: "api"
              - path_prefix: "/"
                cluster: "default"
            "#,
    )
    .unwrap();

    let filter = RouterFilter::from_config(&yaml).unwrap();

    assert_eq!(filter.name(), "router", "filter name should be router");
}

#[test]
fn from_config_empty_routes_key_missing() {
    let yaml = serde_yaml::Value::Mapping(serde_yaml::Mapping::new());

    let filter = RouterFilter::from_config(&yaml).unwrap();

    assert_eq!(filter.name(), "router", "missing routes key should still create router");
}

#[tokio::test]
async fn on_request_sets_cluster_on_match() {
    let router = make_router(vec![prefix_route("/", "default")]);
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let action = router.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "matched route should continue"
    );
    assert_eq!(
        ctx.cluster.as_deref(),
        Some("default"),
        "cluster should be set to matched route"
    );
}

#[tokio::test]
async fn on_request_rejects_on_no_match() {
    let router = make_router(vec![prefix_route("/api/", "api")]);
    let req = crate::test_utils::make_request(http::Method::GET, "/other");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let action = router.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Reject(r) if r.status == 404),
        "unmatched route should reject with 404"
    );
    assert!(ctx.cluster.is_none(), "cluster should remain unset on no match");
}

#[tokio::test]
async fn on_request_combined_host_and_path() {
    let router = make_router(vec![
        Route {
            path_match: PathMatch::Prefix {
                path_prefix: "/".to_owned(),
            },
            host: Some("api.example.com".to_owned()),
            headers: None,
            cluster: "api".into(),
        },
        prefix_route("/", "default"),
    ]);

    let mut req = crate::test_utils::make_request(http::Method::GET, "/v1/users");
    req.headers.insert("host", HeaderValue::from_static("api.example.com"));
    let mut ctx = crate::test_utils::make_filter_context(&req);
    drop(router.on_request(&mut ctx).await.unwrap());
    assert_eq!(
        ctx.cluster.as_deref(),
        Some("api"),
        "host header should select api cluster"
    );

    let req2 = crate::test_utils::make_request(http::Method::GET, "/v1/users");
    let mut ctx2 = crate::test_utils::make_filter_context(&req2);
    drop(router.on_request(&mut ctx2).await.unwrap());
    assert_eq!(
        ctx2.cluster.as_deref(),
        Some("default"),
        "missing host should select default"
    );
}

#[test]
fn route_matches_by_header() {
    let router = make_router(vec![Route {
        path_match: PathMatch::Prefix {
            path_prefix: "/".to_owned(),
        },
        host: None,
        headers: Some(HashMap::from([("x-model".to_owned(), "claude-sonnet-4-5".to_owned())])),
        cluster: "claude_sonnet".into(),
    }]);

    let mut hdrs = HeaderMap::new();
    hdrs.insert("x-model", HeaderValue::from_static("claude-sonnet-4-5"));
    let route = router.match_route("/chat", None, &hdrs).unwrap();
    assert_eq!(
        &*route.cluster, "claude_sonnet",
        "matching header should select header-constrained route"
    );
}

#[test]
fn route_skips_mismatched_header() {
    let router = make_router(vec![Route {
        path_match: PathMatch::Prefix {
            path_prefix: "/".to_owned(),
        },
        host: None,
        headers: Some(HashMap::from([("x-model".to_owned(), "claude-sonnet-4-5".to_owned())])),
        cluster: "claude_sonnet".into(),
    }]);

    let mut hdrs = HeaderMap::new();
    hdrs.insert("x-model", HeaderValue::from_static("mistral-small-latest"));
    assert!(
        router.match_route("/chat", None, &hdrs).is_none(),
        "mismatched header value should return no match"
    );
}

#[test]
fn route_with_headers_wins_over_plain() {
    let router = make_router(vec![
        Route {
            path_match: PathMatch::Prefix {
                path_prefix: "/".to_owned(),
            },
            host: None,
            headers: Some(HashMap::from([("x-model".to_owned(), "claude-sonnet-4-5".to_owned())])),
            cluster: "claude_sonnet".into(),
        },
        prefix_route("/", "default"),
    ]);

    let mut hdrs = HeaderMap::new();
    hdrs.insert("x-model", HeaderValue::from_static("claude-sonnet-4-5"));
    let route = router.match_route("/chat", None, &hdrs).unwrap();
    assert_eq!(
        &*route.cluster, "claude_sonnet",
        "header-constrained route should win over plain"
    );
}

#[test]
fn route_without_headers_used_as_fallback() {
    let router = make_router(vec![
        Route {
            path_match: PathMatch::Prefix {
                path_prefix: "/".to_owned(),
            },
            host: None,
            headers: Some(HashMap::from([("x-model".to_owned(), "claude-sonnet-4-5".to_owned())])),
            cluster: "claude_sonnet".into(),
        },
        prefix_route("/", "default"),
    ]);

    let mut hdrs = HeaderMap::new();
    hdrs.insert("x-model", HeaderValue::from_static("mistral-small-latest"));
    let route = router.match_route("/chat", None, &hdrs).unwrap();
    assert_eq!(
        &*route.cluster, "default",
        "non-matching header should fall back to default"
    );
}

#[tokio::test]
async fn host_falls_back_to_uri_authority() {
    let router = make_router(vec![
        Route {
            path_match: PathMatch::Prefix {
                path_prefix: "/".to_owned(),
            },
            host: Some("api.example.com".to_owned()),
            headers: None,
            cluster: "api".into(),
        },
        prefix_route("/", "default"),
    ]);

    let req = crate::context::Request {
        method: http::Method::GET,
        uri: "http://api.example.com/v1/data".parse().unwrap(),
        headers: HeaderMap::new(),
    };
    let mut ctx = crate::test_utils::make_filter_context(&req);
    drop(router.on_request(&mut ctx).await.unwrap());
    assert_eq!(
        ctx.cluster.as_deref(),
        Some("api"),
        "URI authority should be used when Host header is absent"
    );
}

#[test]
fn multi_value_header_matches_any() {
    let router = make_router(vec![Route {
        path_match: PathMatch::Prefix {
            path_prefix: "/".to_owned(),
        },
        host: None,
        headers: Some(HashMap::from([("x-model".to_owned(), "claude-sonnet-4-5".to_owned())])),
        cluster: "claude_sonnet".into(),
    }]);

    let mut hdrs = HeaderMap::new();
    hdrs.append("x-model", HeaderValue::from_static("claude-3"));
    hdrs.append("x-model", HeaderValue::from_static("claude-sonnet-4-5"));
    let route = router.match_route("/chat", None, &hdrs).unwrap();
    assert_eq!(
        &*route.cluster, "claude_sonnet",
        "any matching value in multi-value header should match"
    );
}

#[test]
fn ipv6_host_with_port() {
    let router = make_router(vec![Route {
        path_match: PathMatch::Prefix {
            path_prefix: "/".to_owned(),
        },
        host: Some("[::1]".to_owned()),
        headers: None,
        cluster: "ipv6".into(),
    }]);

    let route = router.match_route("/", Some("[::1]:8080"), &HeaderMap::new()).unwrap();
    assert_eq!(&*route.cluster, "ipv6", "bracketed IPv6 with port should match");
}

#[test]
fn ipv6_host_without_port() {
    let router = make_router(vec![Route {
        path_match: PathMatch::Prefix {
            path_prefix: "/".to_owned(),
        },
        host: Some("[::1]".to_owned()),
        headers: None,
        cluster: "ipv6".into(),
    }]);

    let route = router.match_route("/", Some("[::1]"), &HeaderMap::new()).unwrap();
    assert_eq!(&*route.cluster, "ipv6", "bracketed IPv6 without port should match");
}

#[test]
fn empty_route_table() {
    let router = make_router(vec![]);
    assert!(
        router.match_route("/anything", None, &HeaderMap::new()).is_none(),
        "empty route table should match nothing"
    );
}

#[test]
fn route_with_host_and_headers() {
    let router = make_router(vec![
        Route {
            path_match: PathMatch::Prefix {
                path_prefix: "/".to_owned(),
            },
            host: Some("api.example.com".to_owned()),
            headers: Some(HashMap::from([("x-version".to_owned(), "v2".to_owned())])),
            cluster: "api-v2".into(),
        },
        prefix_route("/", "default"),
    ]);

    let mut hdrs = HeaderMap::new();
    hdrs.insert("x-version", HeaderValue::from_static("v2"));
    let route = router.match_route("/", Some("api.example.com"), &hdrs).unwrap();
    assert_eq!(
        &*route.cluster, "api-v2",
        "route with both host and headers should match"
    );
}

#[test]
fn same_prefix_same_constraints_first_wins() {
    let router = make_router(vec![
        Route {
            path_match: PathMatch::Prefix {
                path_prefix: "/".to_owned(),
            },
            host: None,
            headers: Some(HashMap::from([("x-a".to_owned(), "1".to_owned())])),
            cluster: "first".into(),
        },
        Route {
            path_match: PathMatch::Prefix {
                path_prefix: "/".to_owned(),
            },
            host: None,
            headers: Some(HashMap::from([("x-b".to_owned(), "2".to_owned())])),
            cluster: "second".into(),
        },
    ]);

    let mut hdrs = HeaderMap::new();
    hdrs.insert("x-a", HeaderValue::from_static("1"));
    hdrs.insert("x-b", HeaderValue::from_static("2"));
    let route = router.match_route("/", None, &hdrs).unwrap();
    assert_eq!(
        &*route.cluster, "first",
        "equal-constraint routes should prefer first match"
    );
}

#[test]
fn empty_headers_map_matches_everything() {
    let router = make_router(vec![Route {
        path_match: PathMatch::Prefix {
            path_prefix: "/".to_owned(),
        },
        host: None,
        headers: Some(HashMap::new()),
        cluster: "vacuous".into(),
    }]);

    let route = router.match_route("/test", None, &HeaderMap::new()).unwrap();
    assert_eq!(&*route.cluster, "vacuous", "empty headers map should match everything");
}

#[tokio::test]
async fn on_request_strips_port_from_host_header() {
    let router = make_router(vec![Route {
        path_match: PathMatch::Prefix {
            path_prefix: "/".to_owned(),
        },
        host: Some("example.com".to_owned()),
        headers: None,
        cluster: "example".into(),
    }]);

    let mut req = crate::test_utils::make_request(http::Method::GET, "/");
    req.headers.insert("host", HeaderValue::from_static("example.com:9090"));
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let action = router.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "host with port should still match route"
    );
    assert_eq!(
        ctx.cluster.as_deref(),
        Some("example"),
        "port should be stripped from Host header for matching"
    );
}

#[test]
fn route_matches_request_path_only_hit() {
    let route = prefix_route("/api/", "api");
    let resolved = ResolvedRoute {
        route,
        json_aliases: None,
        wildcard_suffix: None,
    };
    assert!(
        route_matches_request(&resolved, "/api/users", None, &HeaderMap::new(), false),
        "path-only route should match when prefix matches"
    );
}

#[test]
fn route_matches_request_path_miss() {
    let route = prefix_route("/api/", "api");
    let resolved = ResolvedRoute {
        route,
        json_aliases: None,
        wildcard_suffix: None,
    };
    assert!(
        !route_matches_request(&resolved, "/other", None, &HeaderMap::new(), false),
        "path-only route should not match when prefix differs"
    );
}

#[test]
fn route_matches_request_host_hit() {
    let route = Route {
        path_match: PathMatch::Prefix {
            path_prefix: "/".to_owned(),
        },
        host: Some("example.com".to_owned()),
        headers: None,
        cluster: "ex".into(),
    };
    let resolved = ResolvedRoute {
        route,
        json_aliases: None,
        wildcard_suffix: None,
    };
    assert!(
        route_matches_request(&resolved, "/", Some("example.com"), &HeaderMap::new(), false),
        "host-constrained route should match when host is equal"
    );
}

#[test]
fn route_matches_request_host_miss() {
    let route = Route {
        path_match: PathMatch::Prefix {
            path_prefix: "/".to_owned(),
        },
        host: Some("example.com".to_owned()),
        headers: None,
        cluster: "ex".into(),
    };
    let resolved = ResolvedRoute {
        route,
        json_aliases: None,
        wildcard_suffix: None,
    };
    assert!(
        !route_matches_request(&resolved, "/", Some("other.com"), &HeaderMap::new(), false),
        "host-constrained route should not match when host differs"
    );
}

#[test]
fn route_matches_request_host_miss_when_no_host() {
    let route = Route {
        path_match: PathMatch::Prefix {
            path_prefix: "/".to_owned(),
        },
        host: Some("example.com".to_owned()),
        headers: None,
        cluster: "ex".into(),
    };
    let resolved = ResolvedRoute {
        route,
        json_aliases: None,
        wildcard_suffix: None,
    };
    assert!(
        !route_matches_request(&resolved, "/", None, &HeaderMap::new(), false),
        "host-constrained route should not match when no host is provided"
    );
}

#[test]
fn route_matches_request_header_hit() {
    let route = Route {
        path_match: PathMatch::Prefix {
            path_prefix: "/".to_owned(),
        },
        host: None,
        headers: Some(HashMap::from([("x-key".to_owned(), "val".to_owned())])),
        cluster: "h".into(),
    };
    let resolved = ResolvedRoute {
        route,
        json_aliases: None,
        wildcard_suffix: None,
    };
    let mut hdrs = HeaderMap::new();
    hdrs.insert("x-key", HeaderValue::from_static("val"));
    assert!(
        route_matches_request(&resolved, "/", None, &hdrs, false),
        "header-constrained route should match when header is present"
    );
}

#[test]
fn route_matches_request_header_miss() {
    let route = Route {
        path_match: PathMatch::Prefix {
            path_prefix: "/".to_owned(),
        },
        host: None,
        headers: Some(HashMap::from([("x-key".to_owned(), "val".to_owned())])),
        cluster: "h".into(),
    };
    let resolved = ResolvedRoute {
        route,
        json_aliases: None,
        wildcard_suffix: None,
    };
    let mut hdrs = HeaderMap::new();
    hdrs.insert("x-key", HeaderValue::from_static("wrong"));
    assert!(
        !route_matches_request(&resolved, "/", None, &hdrs, false),
        "header-constrained route should not match when header value differs"
    );
}

#[test]
fn route_matches_request_compound() {
    let route = Route {
        path_match: PathMatch::Prefix {
            path_prefix: "/api/".to_owned(),
        },
        host: Some("example.com".to_owned()),
        headers: Some(HashMap::from([("x-ver".to_owned(), "2".to_owned())])),
        cluster: "c".into(),
    };
    let resolved = ResolvedRoute {
        route,
        json_aliases: None,
        wildcard_suffix: None,
    };
    let mut hdrs = HeaderMap::new();
    hdrs.insert("x-ver", HeaderValue::from_static("2"));
    assert!(
        route_matches_request(&resolved, "/api/data", Some("example.com"), &hdrs, false),
        "compound route should match when path, host, and header all match"
    );
    assert!(
        !route_matches_request(&resolved, "/api/data", Some("other.com"), &hdrs, false),
        "compound route should fail when host mismatches"
    );
    assert!(
        !route_matches_request(&resolved, "/other", Some("example.com"), &hdrs, false),
        "compound route should fail when path mismatches"
    );
}

#[test]
fn update_best_match_prefers_more_constraints_at_same_prefix() {
    let route_a = prefix_route("/", "a");
    let route_b = Route {
        path_match: PathMatch::Prefix {
            path_prefix: "/".to_owned(),
        },
        host: Some("example.com".to_owned()),
        headers: None,
        cluster: "b".into(),
    };
    let best = update_best_match(None, &route_a);
    let best = update_best_match(best, &route_b);
    assert_eq!(
        &*best.unwrap().1.cluster,
        "b",
        "route with more constraints should win at same prefix length"
    );
}

#[test]
fn update_best_match_prefers_longer_prefix() {
    let short = prefix_route("/", "short");
    let long = prefix_route("/api/", "long");
    let best = update_best_match(None, &short);
    let best = update_best_match(best, &long);
    assert_eq!(&*best.unwrap().1.cluster, "long", "route with longer prefix should win");
}

#[test]
fn update_best_match_keeps_current_when_dominated() {
    let first = Route {
        path_match: PathMatch::Prefix {
            path_prefix: "/api/".to_owned(),
        },
        host: Some("example.com".to_owned()),
        headers: None,
        cluster: "first".into(),
    };
    let second = prefix_route("/", "second");
    let best = update_best_match(None, &first);
    let best = update_best_match(best, &second);
    assert_eq!(
        &*best.unwrap().1.cluster,
        "first",
        "dominated route should not replace current best"
    );
}

#[test]
fn should_stop_early_true_when_prefix_shorter_than_best() {
    let best_route = prefix_route("/api/v2/", "best");
    let shorter = prefix_route("/api/", "shorter");
    let best = Some(((false, best_route.path_match.len(), 0), &best_route));
    assert!(
        should_stop_early(best, &shorter),
        "should stop when current route prefix is shorter than best"
    );
}

#[test]
fn should_stop_early_false_when_prefix_equal_to_best() {
    let best_route = prefix_route("/api/", "best");
    let same = prefix_route("/api/", "same");
    let best = Some(((false, best_route.path_match.len(), 0), &best_route));
    assert!(
        !should_stop_early(best, &same),
        "should not stop when prefix lengths are equal"
    );
}

#[test]
fn should_stop_early_false_when_no_best() {
    let route = prefix_route("/", "any");
    assert!(
        !should_stop_early(None, &route),
        "should not stop when there is no current best"
    );
}

#[test]
fn prefix_without_trailing_slash_accepted() {
    let router = make_router(vec![prefix_route("/api", "api"), prefix_route("/", "default")]);
    let route = router.match_route("/api/v1", None, &HeaderMap::new()).unwrap();
    assert_eq!(&*route.cluster, "api", "/api/v1 should match /api prefix without trailing slash");
}

#[test]
fn segment_boundary_rejects_non_segment_continuation() {
    let router = make_router(vec![prefix_route("/api", "api"), prefix_route("/", "default")]);
    let route = router.match_route("/apikeys", None, &HeaderMap::new()).unwrap();
    assert_eq!(&*route.cluster, "default", "/apikeys must NOT match /api prefix");
}

#[test]
fn segment_boundary_exact_path_match() {
    let router = make_router(vec![prefix_route("/api", "api"), prefix_route("/", "default")]);
    let route = router.match_route("/api", None, &HeaderMap::new()).unwrap();
    assert_eq!(&*route.cluster, "api", "/api should match /api prefix exactly");
}

#[test]
fn segment_boundary_trailing_slash_on_path() {
    let router = make_router(vec![prefix_route("/api", "api"), prefix_route("/", "default")]);
    let route = router.match_route("/api/", None, &HeaderMap::new()).unwrap();
    assert_eq!(&*route.cluster, "api", "/api/ should match /api prefix");
}

#[test]
fn prefix_with_and_without_trailing_slash_equivalent() {
    let r1 = make_router(vec![prefix_route("/api", "api"), prefix_route("/", "default")]);
    let r2 = make_router(vec![prefix_route("/api/", "api"), prefix_route("/", "default")]);

    for path in &["/api", "/api/", "/api/v1", "/apikeys"] {
        let m1 = r1.match_route(path, None, &HeaderMap::new()).unwrap();
        let m2 = r2.match_route(path, None, &HeaderMap::new()).unwrap();
        assert_eq!(
            &*m1.cluster, &*m2.cluster,
            "prefix /api and /api/ should behave identically for path {path}"
        );
    }
}

#[test]
fn wildcard_host_matches_subdomain() {
    let router = make_router(vec![Route {
        path_match: PathMatch::Prefix {
            path_prefix: "/".to_owned(),
        },
        host: Some("*.example.com".to_owned()),
        headers: None,
        cluster: "wildcard".into(),
    }]);

    let route = router
        .match_route("/", Some("api.example.com"), &HeaderMap::new())
        .unwrap();
    assert_eq!(
        &*route.cluster, "wildcard",
        "*.example.com should match api.example.com"
    );
}

#[test]
fn wildcard_host_does_not_match_bare_domain() {
    let router = make_router(vec![Route {
        path_match: PathMatch::Prefix {
            path_prefix: "/".to_owned(),
        },
        host: Some("*.example.com".to_owned()),
        headers: None,
        cluster: "wildcard".into(),
    }]);

    assert!(
        router
            .match_route("/", Some("example.com"), &HeaderMap::new())
            .is_none(),
        "*.example.com should not match bare example.com"
    );
}

#[test]
fn wildcard_host_rejects_multi_level_subdomain_by_default() {
    let router = make_router(vec![Route {
        path_match: PathMatch::Prefix {
            path_prefix: "/".to_owned(),
        },
        host: Some("*.example.com".to_owned()),
        headers: None,
        cluster: "wildcard".into(),
    }]);

    assert!(
        router
            .match_route("/", Some("a.b.example.com"), &HeaderMap::new())
            .is_none(),
        "*.example.com should not match multi-level subdomain by default"
    );
}

#[test]
fn wildcard_host_matches_multi_level_with_flag() {
    let router = make_router(vec![Route {
        path_match: PathMatch::Prefix {
            path_prefix: "/".to_owned(),
        },
        host: Some("*.example.com".to_owned()),
        headers: None,
        cluster: "wildcard".into(),
    }])
    .with_multi_level_subdomain_matching(true);

    assert!(
        router
            .match_route("/", Some("a.b.example.com"), &HeaderMap::new())
            .is_some(),
        "*.example.com should match multi-level subdomain when flag is enabled"
    );
}

#[test]
fn wildcard_host_with_port() {
    let router = make_router(vec![Route {
        path_match: PathMatch::Prefix {
            path_prefix: "/".to_owned(),
        },
        host: Some("*.example.com".to_owned()),
        headers: None,
        cluster: "wildcard".into(),
    }]);

    let route = router
        .match_route("/", Some("www.example.com:8080"), &HeaderMap::new())
        .unwrap();
    assert_eq!(
        &*route.cluster, "wildcard",
        "wildcard host should match after stripping port"
    );
}

#[test]
fn wildcard_host_case_insensitive() {
    let router = make_router(vec![Route {
        path_match: PathMatch::Prefix {
            path_prefix: "/".to_owned(),
        },
        host: Some("*.Example.COM".to_owned()),
        headers: None,
        cluster: "wildcard".into(),
    }]);

    let route = router
        .match_route("/", Some("API.example.com"), &HeaderMap::new())
        .unwrap();
    assert_eq!(
        &*route.cluster, "wildcard",
        "wildcard host matching should be case-insensitive"
    );
}

#[test]
fn wildcard_host_with_fallback() {
    let router = make_router(vec![
        Route {
            path_match: PathMatch::Prefix {
                path_prefix: "/".to_owned(),
            },
            host: Some("*.example.com".to_owned()),
            headers: None,
            cluster: "wildcard".into(),
        },
        prefix_route("/", "default"),
    ]);

    let route = router
        .match_route("/", Some("api.example.com"), &HeaderMap::new())
        .unwrap();
    assert_eq!(
        &*route.cluster, "wildcard",
        "wildcard route should match api.example.com"
    );

    let route = router.match_route("/", Some("other.dev"), &HeaderMap::new()).unwrap();
    assert_eq!(
        &*route.cluster, "default",
        "non-matching host should fall back to default"
    );
}

#[test]
fn exact_host_wins_over_wildcard_same_constraints() {
    let router = make_router(vec![
        Route {
            path_match: PathMatch::Prefix {
                path_prefix: "/".to_owned(),
            },
            host: Some("api.example.com".to_owned()),
            headers: None,
            cluster: "exact".into(),
        },
        Route {
            path_match: PathMatch::Prefix {
                path_prefix: "/".to_owned(),
            },
            host: Some("*.example.com".to_owned()),
            headers: None,
            cluster: "wildcard".into(),
        },
    ]);

    let route = router
        .match_route("/", Some("api.example.com"), &HeaderMap::new())
        .unwrap();
    assert_eq!(
        &*route.cluster, "exact",
        "exact host match should win over wildcard (first-match semantics)"
    );
}

#[test]
fn wildcard_host_does_not_match_empty_subdomain() {
    let router = make_router(vec![Route {
        path_match: PathMatch::Prefix {
            path_prefix: "/".to_owned(),
        },
        host: Some("*.example.com".to_owned()),
        headers: None,
        cluster: "wildcard".into(),
    }]);

    assert!(
        router
            .match_route("/", Some(".example.com"), &HeaderMap::new())
            .is_none(),
        "*.example.com should not match .example.com (empty subdomain)"
    );
}

#[tokio::test]
async fn on_request_wildcard_host_via_host_header() {
    let router = make_router(vec![
        Route {
            path_match: PathMatch::Prefix {
                path_prefix: "/".to_owned(),
            },
            host: Some("*.example.com".to_owned()),
            headers: None,
            cluster: "wildcard".into(),
        },
        prefix_route("/", "default"),
    ]);

    let mut req = crate::test_utils::make_request(http::Method::GET, "/");
    req.headers.insert("host", HeaderValue::from_static("app.example.com"));
    let mut ctx = crate::test_utils::make_filter_context(&req);
    drop(router.on_request(&mut ctx).await.unwrap());
    assert_eq!(
        ctx.cluster.as_deref(),
        Some("wildcard"),
        "wildcard should match via Host header"
    );
}

#[tokio::test]
async fn on_request_uses_original_path_when_rewritten_path_is_none() {
    let router = make_router(vec![prefix_route("/api/", "api"), prefix_route("/", "default")]);
    let req = crate::test_utils::make_request(http::Method::GET, "/api/users");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let action = router.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "original path match should continue"
    );
    assert_eq!(
        ctx.cluster.as_deref(),
        Some("api"),
        "should route based on original path when rewritten_path is None"
    );
}

#[tokio::test]
async fn on_request_uses_rewritten_path_when_set() {
    let router = make_router(vec![
        prefix_route("/internal/", "internal"),
        prefix_route("/", "default"),
    ]);
    let req = crate::test_utils::make_request(http::Method::GET, "/api/v1/data");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.rewritten_path = Some("/internal/data".to_owned());
    let action = router.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "rewritten path match should continue"
    );
    assert_eq!(
        ctx.cluster.as_deref(),
        Some("internal"),
        "should route based on rewritten_path, not original"
    );
}

#[tokio::test]
async fn on_request_rewritten_path_no_match_still_rejects() {
    let router = make_router(vec![prefix_route("/api/", "api")]);
    let req = crate::test_utils::make_request(http::Method::GET, "/api/users");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.rewritten_path = Some("/unknown/path".to_owned());
    let action = router.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Reject(r) if r.status == 404),
        "rewritten path that matches no route should reject with 404"
    );
    assert!(
        ctx.cluster.is_none(),
        "cluster should remain unset when rewritten path matches nothing"
    );
}

#[test]
fn exact_path_matches_only_exact() {
    let router = make_router(vec![exact_route("/one", "exact"), prefix_route("/", "fallback")]);
    assert_eq!(
        &*router.match_route("/one", None, &HeaderMap::new()).unwrap().cluster,
        "exact",
        "/one should match exact route"
    );
    assert_eq!(
        &*router.match_route("/", None, &HeaderMap::new()).unwrap().cluster,
        "fallback",
        "/ should match fallback"
    );
    assert_eq!(
        &*router.match_route("/one/sub", None, &HeaderMap::new()).unwrap().cluster,
        "fallback",
        "/one/sub should NOT match exact /one"
    );
    assert_eq!(
        &*router.match_route("/one/", None, &HeaderMap::new()).unwrap().cluster,
        "fallback",
        "/one/ should NOT match exact /one"
    );
    assert_eq!(
        &*router.match_route("/ONE", None, &HeaderMap::new()).unwrap().cluster,
        "fallback",
        "/ONE should NOT match exact /one (case-sensitive)"
    );
}

#[test]
fn exact_path_dominates_prefix() {
    let router = make_router(vec![
        exact_route("/api", "exact"),
        prefix_route("/api/", "prefix"),
        prefix_route("/", "root"),
    ]);
    assert_eq!(
        &*router.match_route("/api", None, &HeaderMap::new()).unwrap().cluster,
        "exact",
        "exact /api should win over prefix /api/"
    );
    assert_eq!(
        &*router.match_route("/api/v1", None, &HeaderMap::new()).unwrap().cluster,
        "prefix",
        "/api/v1 should match prefix /api/"
    );
    assert_eq!(
        &*router.match_route("/other", None, &HeaderMap::new()).unwrap().cluster,
        "root",
        "/other should match root /"
    );
}

#[test]
fn exact_path_with_host_constraint() {
    let router = make_router(vec![
        Route {
            path_match: PathMatch::Exact {
                path: "/health".to_owned(),
            },
            host: Some("api.example.com".to_owned()),
            headers: None,
            cluster: "api-health".into(),
        },
        exact_route("/health", "any-health"),
    ]);
    assert_eq!(
        &*router
            .match_route("/health", Some("api.example.com"), &HeaderMap::new())
            .unwrap()
            .cluster,
        "api-health",
        "host-constrained exact should win"
    );
    assert_eq!(
        &*router
            .match_route("/health", Some("other.example.com"), &HeaderMap::new())
            .unwrap()
            .cluster,
        "any-health",
        "unconstrained exact should match other hosts"
    );
    assert_eq!(
        &*router.match_route("/health", None, &HeaderMap::new()).unwrap().cluster,
        "any-health",
        "unconstrained exact should match no host"
    );
}

#[test]
fn exact_path_with_headers() {
    let mut headers_constraint = HashMap::new();
    headers_constraint.insert("x-version".to_owned(), "v2".to_owned());
    let router = make_router(vec![
        Route {
            path_match: PathMatch::Exact {
                path: "/api".to_owned(),
            },
            host: None,
            headers: Some(headers_constraint),
            cluster: "v2".into(),
        },
        exact_route("/api", "default"),
    ]);
    let mut req_headers = HeaderMap::new();
    req_headers.insert("x-version", "v2".parse().unwrap());
    assert_eq!(
        &*router.match_route("/api", None, &req_headers).unwrap().cluster,
        "v2",
        "exact with matching headers should win"
    );
    assert_eq!(
        &*router.match_route("/api", None, &HeaderMap::new()).unwrap().cluster,
        "default",
        "exact without matching headers should fall back"
    );
}

#[test]
fn exact_path_no_trailing_slash_validation() {
    let router = RouterFilter::new(vec![exact_route("/one", "a"), exact_route("/two", "b")]);
    assert!(router.is_ok(), "exact paths should not require trailing slash");
}

#[test]
fn exact_path_empty_prefix_accepted() {
    let router = RouterFilter::new(vec![exact_route("/exact", "a")]);
    assert!(router.is_ok(), "exact path should be accepted");
}

#[test]
fn multiple_exact_paths() {
    let router = make_router(vec![
        exact_route("/one", "c1"),
        exact_route("/two", "c2"),
        exact_route("/three", "c3"),
    ]);
    assert_eq!(
        &*router.match_route("/one", None, &HeaderMap::new()).unwrap().cluster,
        "c1"
    );
    assert_eq!(
        &*router.match_route("/two", None, &HeaderMap::new()).unwrap().cluster,
        "c2"
    );
    assert_eq!(
        &*router.match_route("/three", None, &HeaderMap::new()).unwrap().cluster,
        "c3"
    );
    assert!(
        router.match_route("/four", None, &HeaderMap::new()).is_none(),
        "/four should match nothing"
    );
}

#[test]
fn exact_path_no_match_returns_none() {
    let router = make_router(vec![exact_route("/only-this", "a")]);
    assert!(router.match_route("/something-else", None, &HeaderMap::new()).is_none());
    assert!(router.match_route("/only-this/sub", None, &HeaderMap::new()).is_none());
    assert!(router.match_route("/", None, &HeaderMap::new()).is_none());
}

#[test]
fn mixed_exact_and_prefix_ordering() {
    let router = make_router(vec![
        exact_route("/api/v1/users", "exact-users"),
        prefix_route("/api/v1/", "prefix-v1"),
        prefix_route("/api/", "prefix-api"),
        prefix_route("/", "root"),
    ]);
    assert_eq!(
        &*router
            .match_route("/api/v1/users", None, &HeaderMap::new())
            .unwrap()
            .cluster,
        "exact-users"
    );
    assert_eq!(
        &*router
            .match_route("/api/v1/posts", None, &HeaderMap::new())
            .unwrap()
            .cluster,
        "prefix-v1"
    );
    assert_eq!(
        &*router
            .match_route("/api/v2/other", None, &HeaderMap::new())
            .unwrap()
            .cluster,
        "prefix-api"
    );
    assert_eq!(
        &*router.match_route("/other", None, &HeaderMap::new()).unwrap().cluster,
        "root"
    );
}

// -----------------------------------------------------------------------------
// JSON Alias Validation Tests
// -----------------------------------------------------------------------------

#[test]
fn json_alias_validation_empty_aliases_rejected() {
    let err = RouterFilter::with_alias_options(
        vec![router_route("/", "test", Some(vec![]))],
        super::config::DEFAULT_JSON_ALIAS_HEADER,
        super::config::DEFAULT_JSON_ALIAS_MAX_BODY_BYTES,
    )
    .unwrap_err();
    assert!(
        err.to_string().contains("must not be empty"),
        "empty json_aliases should be rejected: {err}"
    );
}

#[test]
fn json_alias_validation_empty_field_rejected() {
    let err = RouterFilter::with_alias_options(
        vec![router_route(
            "/",
            "test",
            Some(vec![JsonAlias {
                field: String::new(),
                pattern: "fast".to_owned(),
                target: None,
            }]),
        )],
        super::config::DEFAULT_JSON_ALIAS_HEADER,
        super::config::DEFAULT_JSON_ALIAS_MAX_BODY_BYTES,
    )
    .unwrap_err();
    assert!(
        err.to_string().contains("field"),
        "empty field should be rejected: {err}"
    );
}

#[test]
fn json_alias_validation_empty_pattern_rejected() {
    let err = RouterFilter::with_alias_options(
        vec![router_route(
            "/",
            "test",
            Some(vec![JsonAlias {
                field: "model".to_owned(),
                pattern: String::new(),
                target: None,
            }]),
        )],
        super::config::DEFAULT_JSON_ALIAS_HEADER,
        super::config::DEFAULT_JSON_ALIAS_MAX_BODY_BYTES,
    )
    .unwrap_err();
    assert!(
        err.to_string().contains("must not be empty"),
        "empty match pattern should be rejected: {err}"
    );
}

#[test]
fn json_alias_validation_multiple_wildcards_rejected() {
    let err = RouterFilter::with_alias_options(
        vec![router_route(
            "/",
            "test",
            Some(vec![JsonAlias {
                field: "model".to_owned(),
                pattern: "a-*-b-*".to_owned(),
                target: None,
            }]),
        )],
        super::config::DEFAULT_JSON_ALIAS_HEADER,
        super::config::DEFAULT_JSON_ALIAS_MAX_BODY_BYTES,
    )
    .unwrap_err();
    assert!(
        err.to_string().contains("at most one"),
        "multiple wildcards should be rejected: {err}"
    );
}

#[test]
fn json_alias_validation_empty_target_rejected() {
    let err = RouterFilter::with_alias_options(
        vec![router_route(
            "/",
            "test",
            Some(vec![JsonAlias {
                field: "model".to_owned(),
                pattern: "fast".to_owned(),
                target: Some(String::new()),
            }]),
        )],
        super::config::DEFAULT_JSON_ALIAS_HEADER,
        super::config::DEFAULT_JSON_ALIAS_MAX_BODY_BYTES,
    )
    .unwrap_err();
    assert!(
        err.to_string().contains("must not be empty"),
        "empty target should be rejected: {err}"
    );
}

#[test]
fn json_alias_config_stores_header_and_max_bytes() {
    let filter = RouterFilter::with_alias_options(
        vec![json_alias_route(
            "/",
            "test",
            vec![("tenant_id", "acme", Some("tenant-acme"))],
        )],
        "X-Tenant",
        4096,
    )
    .unwrap();

    assert_eq!(
        filter.json_alias_header.as_str(),
        "x-tenant",
        "custom json_alias_header"
    );
    assert_eq!(filter.json_alias_max_body_bytes, 4096, "custom max body bytes");
}

#[test]
fn json_alias_config_preserves_route_count() {
    let filter = make_alias_config_filter();
    assert_eq!(filter.routes.len(), 3, "should have 3 routes");
}

#[test]
fn json_alias_config_preserves_anthropic_alias() {
    let filter = make_alias_config_filter();
    let anthropic = find_resolved_route(&filter, "anthropic");
    let aliases = anthropic.json_aliases.as_ref().unwrap();

    assert_eq!(aliases.len(), 1, "anthropic should have 1 alias");
    assert_eq!(aliases[0].field, "model", "anthropic alias field");
    assert_eq!(aliases[0].pattern, "claude-*", "wildcard alias pattern");
    assert!(aliases[0].target.is_none(), "wildcard alias should have no target");
}

#[test]
fn json_alias_config_preserves_openai_aliases() {
    let filter = make_alias_config_filter();
    let openai = find_resolved_route(&filter, "openai");
    let aliases = openai.json_aliases.as_ref().unwrap();

    assert_eq!(aliases.len(), 2, "openai should have 2 aliases");
    assert_eq!(aliases[0].field, "model", "first alias field");
    assert_eq!(aliases[0].pattern, "fast", "first alias pattern");
    assert_eq!(aliases[0].target.as_deref(), Some("gpt-4o-mini"), "first alias target");
    assert_eq!(aliases[1].field, "tenant_id", "second alias field");
    assert_eq!(aliases[1].pattern, "cheap", "second alias pattern");
}

#[test]
fn json_alias_config_preserves_fallback_without_aliases() {
    let filter = make_alias_config_filter();
    let fallback = find_resolved_route(&filter, "fallback");

    assert!(fallback.json_aliases.is_none(), "fallback should have no aliases");
}

#[test]
fn json_alias_from_config_parses_global_options() {
    let cfg = parse_json_alias_config();

    assert_eq!(cfg.json_alias_header, "X-AI-Model", "custom json alias header");
    assert_eq!(cfg.json_alias_max_body_bytes, 4096, "custom max body bytes");
    assert_eq!(cfg.routes.len(), 3, "should parse 3 routes");
}

#[test]
fn json_alias_from_config_parses_first_route_alias() {
    let cfg = parse_json_alias_config();
    let first = &cfg.routes[0];

    assert_eq!(&*first.route.cluster, "openai", "first route cluster");
    let aliases = first.json_aliases.as_ref().unwrap();
    assert_eq!(aliases.len(), 1, "first route should have one alias");
    assert_eq!(aliases[0].field, "model", "first alias field");
    assert_eq!(aliases[0].pattern, "fast", "first alias pattern");
    assert_eq!(aliases[0].target.as_deref(), Some("gpt-4o-mini"), "first alias target");
}

#[test]
fn json_alias_from_config_parses_second_route_alias() {
    let cfg = parse_json_alias_config();
    let second = &cfg.routes[1];

    assert_eq!(&*second.route.cluster, "tenant", "second route cluster");
    let aliases = second.json_aliases.as_ref().unwrap();
    assert_eq!(aliases.len(), 1, "second route should have one alias");
    assert_eq!(aliases[0].field, "tenant_id", "second alias field");
    assert_eq!(aliases[0].pattern, "fast", "second alias pattern");
    assert_eq!(aliases[0].target.as_deref(), Some("tenant-fast"), "second alias target");
}

#[test]
fn json_alias_from_config_parses_fallback_without_aliases() {
    let cfg = parse_json_alias_config();
    let third = &cfg.routes[2];

    assert_eq!(&*third.route.cluster, "fallback", "third route cluster");
    assert!(third.json_aliases.is_none(), "fallback should have no aliases");
}

#[test]
fn json_alias_from_config_builds_filter() {
    let yaml = serde_yaml::from_str::<serde_yaml::Value>(json_alias_config_yaml()).unwrap();
    let filter = RouterFilter::from_config(&yaml).unwrap();

    assert_eq!(filter.name(), "router", "from_config should produce a valid router");
}

#[test]
fn json_alias_from_config_uses_defaults() {
    let cfg: RouterConfig = serde_yaml::from_str(
        r#"
routes:
  - path_prefix: "/"
    cluster: "default"
    json_aliases:
      - field: model
        match: fast
        target: gpt-4o-mini
"#,
    )
    .unwrap();

    assert_eq!(
        cfg.json_alias_header,
        super::config::DEFAULT_JSON_ALIAS_HEADER,
        "should use default json_alias_header"
    );
    assert_eq!(
        cfg.json_alias_max_body_bytes,
        super::config::DEFAULT_JSON_ALIAS_MAX_BODY_BYTES,
        "should use default max body bytes"
    );
}

#[test]
fn json_alias_validate_invalid_header_name_rejected() {
    let err = RouterFilter::with_alias_options(
        vec![json_alias_route(
            "/",
            "test",
            vec![("model", "fast", Some("gpt-4o-mini"))],
        )],
        "bad header",
        super::config::DEFAULT_JSON_ALIAS_MAX_BODY_BYTES,
    )
    .unwrap_err();
    assert!(
        err.to_string().contains("not a valid HTTP header name"),
        "invalid header name should be rejected: {err}"
    );
}

#[test]
fn json_alias_validate_zero_max_bytes_rejected() {
    let err = RouterFilter::with_alias_options(
        vec![json_alias_route(
            "/",
            "test",
            vec![("model", "fast", Some("gpt-4o-mini"))],
        )],
        super::config::DEFAULT_JSON_ALIAS_HEADER,
        0,
    )
    .unwrap_err();
    assert!(
        err.to_string().contains("must be greater than 0"),
        "zero max bytes should be rejected: {err}"
    );
}

#[test]
fn json_alias_validate_max_bytes_above_upper_bound_rejected() {
    let err = RouterFilter::with_alias_options(
        vec![json_alias_route(
            "/",
            "test",
            vec![("model", "fast", Some("gpt-4o-mini"))],
        )],
        super::config::DEFAULT_JSON_ALIAS_HEADER,
        super::config::MAX_JSON_ALIAS_BODY_BYTES + 1,
    )
    .unwrap_err();
    assert!(
        err.to_string().contains("must be <="),
        "above upper bound should be rejected: {err}"
    );
}

#[test]
fn json_alias_validate_max_bytes_at_upper_bound_accepted() {
    let result = RouterFilter::with_alias_options(
        vec![json_alias_route(
            "/",
            "test",
            vec![("model", "fast", Some("gpt-4o-mini"))],
        )],
        super::config::DEFAULT_JSON_ALIAS_HEADER,
        super::config::MAX_JSON_ALIAS_BODY_BYTES,
    );
    assert!(result.is_ok(), "exactly at upper bound should be accepted");
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

fn make_router(routes: Vec<Route>) -> RouterFilter {
    RouterFilter::new(routes).expect("test routes should be valid")
}

fn json_alias_config_yaml() -> &'static str {
    r#"
json_alias_header: X-AI-Model
json_alias_max_body_bytes: 4096
routes:
  - path_prefix: "/v1/chat/"
    cluster: "openai"
    json_aliases:
      - field: model
        match: fast
        target: gpt-4o-mini
  - path_prefix: "/tenant/"
    cluster: "tenant"
    json_aliases:
      - field: tenant_id
        match: fast
        target: tenant-fast
  - path_prefix: "/"
    cluster: "fallback"
"#
}

fn parse_json_alias_config() -> RouterConfig {
    serde_yaml::from_str(json_alias_config_yaml()).unwrap()
}

fn prefix_route(prefix: &str, cluster: &str) -> Route {
    Route {
        path_match: PathMatch::Prefix {
            path_prefix: prefix.to_owned(),
        },
        host: None,
        headers: None,
        cluster: cluster.into(),
    }
}

fn exact_route(path: &str, cluster: &str) -> Route {
    Route {
        path_match: PathMatch::Exact { path: path.to_owned() },
        host: None,
        headers: None,
        cluster: cluster.into(),
    }
}

fn router_route(prefix: &str, cluster: &str, json_aliases: Option<Vec<JsonAlias>>) -> RouterRouteConfig {
    RouterRouteConfig {
        route: prefix_route(prefix, cluster),
        json_aliases,
    }
}

fn json_alias_route(prefix: &str, cluster: &str, aliases: Vec<(&str, &str, Option<&str>)>) -> RouterRouteConfig {
    router_route(
        prefix,
        cluster,
        Some(
            aliases
                .into_iter()
                .map(|(field, pattern, target)| JsonAlias {
                    field: field.to_owned(),
                    pattern: pattern.to_owned(),
                    target: target.map(str::to_owned),
                })
                .collect(),
        ),
    )
}

/// Build the standard three-route alias config used by multiple tests.
fn make_alias_config_filter() -> RouterFilter {
    RouterFilter::with_alias_options(
        vec![
            json_alias_route(
                "/v1/chat/",
                "openai",
                vec![
                    ("model", "fast", Some("gpt-4o-mini")),
                    ("tenant_id", "cheap", Some("tenant-cheap")),
                ],
            ),
            json_alias_route("/v1/messages/", "anthropic", vec![("model", "claude-*", None)]),
            router_route("/", "fallback", None),
        ],
        "X-AI-Model",
        4096,
    )
    .unwrap()
}

/// Find a route by cluster name (panics if not found).
fn find_resolved_route<'a>(filter: &'a RouterFilter, cluster: &str) -> &'a ResolvedRoute {
    filter
        .routes
        .iter()
        .find(|r| &*r.route.cluster == cluster)
        .unwrap_or_else(|| panic!("no route with cluster '{cluster}'"))
}
