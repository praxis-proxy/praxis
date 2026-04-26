// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Tests for the load balancer filter.

use std::{
    collections::HashMap,
    sync::{Arc, atomic::Ordering},
    time::Duration,
};

use praxis_core::config::{
    Cluster, ConsistentHashOpts, Endpoint, LoadBalancerStrategy, ParameterisedStrategy, SimpleStrategy,
};

use super::{LoadBalancerFilter, entry::build_cluster_entry, strategy::build_strategy};
use crate::{
    FilterAction,
    filter::HttpFilter,
    load_balancing::{endpoint::WeightedEndpoint, strategy::Strategy as SharedStrategy},
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn new_creates_clusters() {
    let clusters = vec![test_cluster("web", &["127.0.0.1:8080"])];
    let lb = LoadBalancerFilter::new(&clusters);
    assert!(lb.clusters.contains_key("web"), "cluster 'web' should be registered");
}

#[test]
fn new_multiple_clusters() {
    let clusters = vec![
        test_cluster("web", &["127.0.0.1:8080"]),
        test_cluster("api", &["127.0.0.1:9090"]),
    ];
    let lb = LoadBalancerFilter::new(&clusters);
    assert_eq!(lb.clusters.len(), 2, "both clusters should be registered");
}

#[tokio::test]
async fn on_request_sets_upstream_round_robin() {
    let lb = LoadBalancerFilter::new(&[test_cluster("web", &["127.0.0.1:8080"])]);
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.cluster = Some(Arc::from("web"));
    let action = lb.on_request(&mut ctx).await.unwrap();
    assert!(matches!(action, FilterAction::Continue), "round robin should continue");
    let upstream = ctx.upstream.expect("upstream should be set");
    assert_eq!(
        &*upstream.address, "127.0.0.1:8080",
        "upstream address should match endpoint"
    );
}

#[tokio::test]
async fn on_request_sets_upstream_least_connections() {
    let cluster = cluster_with_strategy(
        "web",
        &["127.0.0.1:8080", "127.0.0.1:8081"],
        LoadBalancerStrategy::Simple(SimpleStrategy::LeastConnections),
    );
    let lb = LoadBalancerFilter::new(&[cluster]);
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.cluster = Some(Arc::from("web"));
    let action = lb.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "least connections should continue"
    );
    assert!(ctx.upstream.is_some(), "upstream should be set by least connections");
}

#[tokio::test]
async fn on_request_sets_upstream_consistent_hash() {
    let cluster = cluster_with_strategy(
        "web",
        &["127.0.0.1:8080", "127.0.0.1:8081"],
        LoadBalancerStrategy::Parameterised(ParameterisedStrategy::ConsistentHash(ConsistentHashOpts {
            header: None,
        })),
    );
    let lb = LoadBalancerFilter::new(&[cluster]);
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.cluster = Some(Arc::from("web"));
    let action = lb.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "consistent hash should continue"
    );
    assert!(ctx.upstream.is_some(), "upstream should be set by consistent hash");
}

#[tokio::test]
async fn on_response_releases_least_connections_counter() {
    let cluster = cluster_with_strategy(
        "web",
        &["127.0.0.1:8080"],
        LoadBalancerStrategy::Simple(SimpleStrategy::LeastConnections),
    );
    let lb = LoadBalancerFilter::new(&[cluster]);

    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.cluster = Some(Arc::from("web"));

    drop(lb.on_request(&mut ctx).await.unwrap());

    let entry = lb.clusters.get("web").unwrap();
    if let SharedStrategy::LeastConnections(lc) = entry.strategy.inner() {
        assert_eq!(
            lc.counters["127.0.0.1:8080"].load(Ordering::Relaxed),
            1,
            "counter should be 1 after request"
        );
    }

    drop(lb.on_response(&mut ctx).await.unwrap());

    if let SharedStrategy::LeastConnections(lc) = entry.strategy.inner() {
        assert_eq!(
            lc.counters["127.0.0.1:8080"].load(Ordering::Relaxed),
            0,
            "counter should be 0 after response"
        );
    }
}

#[tokio::test]
async fn on_request_errors_when_no_cluster() {
    let lb = LoadBalancerFilter::new(&[test_cluster("web", &["127.0.0.1:8080"])]);
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let result = lb.on_request(&mut ctx).await;
    assert!(result.is_err(), "missing cluster should produce error");
    assert!(
        result.unwrap_err().to_string().contains("no cluster set"),
        "error should mention no cluster set"
    );
}

#[tokio::test]
async fn on_request_errors_for_unknown_cluster() {
    let lb = LoadBalancerFilter::new(&[test_cluster("web", &["127.0.0.1:8080"])]);
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.cluster = Some(Arc::from("nonexistent"));
    let result = lb.on_request(&mut ctx).await;
    assert!(result.is_err(), "unknown cluster should produce error");
    assert!(
        result.unwrap_err().to_string().contains("unknown cluster"),
        "error should mention unknown cluster"
    );
}

#[test]
fn from_config_parses_yaml() {
    let yaml = serde_yaml::from_str::<serde_yaml::Value>(
        r#"
            clusters:
              - name: "backend"
                endpoints: ["10.0.0.1:80"]
            "#,
    )
    .unwrap();
    let filter = LoadBalancerFilter::from_config(&yaml).unwrap();
    assert_eq!(filter.name(), "load_balancer", "filter name should be load_balancer");
}

#[test]
fn from_config_empty_clusters() {
    let yaml = serde_yaml::Value::Mapping(serde_yaml::Mapping::new());
    let filter = LoadBalancerFilter::from_config(&yaml).unwrap();
    assert_eq!(
        filter.name(),
        "load_balancer",
        "empty clusters should still create filter"
    );
}

#[test]
fn timeout_options_from_cluster() {
    let cluster = Cluster {
        connection_timeout_ms: Some(5000),
        idle_timeout_ms: Some(30000),
        read_timeout_ms: Some(10000),
        ..Cluster::with_defaults("web", vec!["127.0.0.1:80".into()])
    };
    let opts = praxis_core::connectivity::ConnectionOptions::from(&cluster);
    assert_eq!(
        opts.connection_timeout,
        Some(Duration::from_millis(5000)),
        "connection timeout should be parsed from config"
    );
    assert_eq!(
        opts.idle_timeout,
        Some(Duration::from_millis(30000)),
        "idle timeout should be parsed from config"
    );
    assert_eq!(
        opts.read_timeout,
        Some(Duration::from_millis(10000)),
        "read timeout should be parsed from config"
    );
    assert!(opts.write_timeout.is_none(), "unset write timeout should be None");
}

#[test]
fn timeout_options_all_none() {
    let cluster = test_cluster("web", &["127.0.0.1:80"]);
    let opts = praxis_core::connectivity::ConnectionOptions::from(&cluster);
    assert!(
        opts.connection_timeout.is_none(),
        "default connection timeout should be None"
    );
    assert!(opts.idle_timeout.is_none(), "default idle timeout should be None");
    assert!(opts.read_timeout.is_none(), "default read timeout should be None");
    assert!(opts.write_timeout.is_none(), "default write timeout should be None");
}

#[tokio::test]
async fn weighted_endpoints_expand_proportionally() {
    let cluster = Cluster::with_defaults(
        "weighted",
        vec![
            Endpoint::Simple("10.0.0.1:80".into()),
            Endpoint::Weighted {
                address: "10.0.0.2:80".into(),
                weight: 3,
            },
        ],
    );

    let lb = LoadBalancerFilter::new(&[cluster]);

    let mut counts = HashMap::new();
    for _ in 0..4 {
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.cluster = Some(Arc::from("weighted"));
        let action = lb.on_request(&mut ctx).await.unwrap();
        assert!(
            matches!(action, FilterAction::Continue),
            "weighted selection should continue"
        );
        *counts.entry(ctx.upstream.unwrap().address).or_insert(0u32) += 1;
    }

    assert_eq!(
        *counts.get("10.0.0.1:80").unwrap_or(&0),
        1,
        "weight-1 endpoint should be selected once per cycle"
    );
    assert_eq!(
        *counts.get("10.0.0.2:80").unwrap_or(&0),
        3,
        "weight-3 endpoint should be selected three times per cycle"
    );
}

#[tokio::test]
async fn sni_fallback_to_host_header_when_sni_none() {
    let cluster = Cluster {
        tls: Some(praxis_core::config::ClusterTls::default()),
        ..Cluster::with_defaults("no-sni", vec!["10.0.0.1:443".into()])
    };
    let lb = LoadBalancerFilter::new(&[cluster]);

    let mut req = crate::test_utils::make_request(http::Method::GET, "/");
    req.headers
        .insert("host", http::HeaderValue::from_static("api.example.com"));
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.cluster = Some(Arc::from("no-sni"));

    drop(lb.on_request(&mut ctx).await.unwrap());
    let upstream = ctx.upstream.expect("upstream should be set");
    assert!(upstream.tls.is_some(), "TLS should be enabled");
    assert_eq!(
        upstream.tls.as_ref().unwrap().sni(),
        Some("api.example.com"),
        "SNI should fall back to Host header when sni is None"
    );
}

#[tokio::test]
async fn sni_fallback_is_none_when_no_host_header() {
    let cluster = Cluster {
        tls: Some(praxis_core::config::ClusterTls::default()),
        ..Cluster::with_defaults("no-sni", vec!["10.0.0.1:443".into()])
    };
    let lb = LoadBalancerFilter::new(&[cluster]);

    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.cluster = Some(Arc::from("no-sni"));

    drop(lb.on_request(&mut ctx).await.unwrap());
    let upstream = ctx.upstream.expect("upstream should be set");
    assert!(upstream.tls.is_some(), "TLS should be enabled");
    assert!(
        upstream.tls.as_ref().unwrap().sni().is_none(),
        "SNI should be None when no Host header and no explicit sni"
    );
}

#[tokio::test]
async fn explicit_sni_overrides_host_header() {
    let cluster = Cluster {
        tls: Some(praxis_core::config::ClusterTls {
            sni: Some("override.example.com".into()),
            ..praxis_core::config::ClusterTls::default()
        }),
        ..Cluster::with_defaults("explicit-sni", vec!["10.0.0.1:443".into()])
    };
    let lb = LoadBalancerFilter::new(&[cluster]);

    let mut req = crate::test_utils::make_request(http::Method::GET, "/");
    req.headers
        .insert("host", http::HeaderValue::from_static("original.example.com"));
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.cluster = Some(Arc::from("explicit-sni"));

    drop(lb.on_request(&mut ctx).await.unwrap());
    let upstream = ctx.upstream.expect("upstream should be set");
    assert_eq!(
        upstream.tls.as_ref().unwrap().sni(),
        Some("override.example.com"),
        "explicit sni should override Host header"
    );
}

#[test]
fn build_cluster_entry_preserves_endpoints_via_selection() {
    let cluster = test_cluster("web", &["10.0.0.1:80", "10.0.0.2:80", "10.0.0.3:80"]);
    let entry = build_cluster_entry(&cluster);
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let ctx = crate::test_utils::make_filter_context(&req);
    let mut seen = std::collections::HashSet::new();
    for _ in 0..3 {
        seen.insert(entry.strategy.select(&ctx, None).to_string());
    }
    assert_eq!(seen.len(), 3, "all three endpoints should be reachable");
}

#[test]
fn build_cluster_entry_preserves_weights_via_distribution() {
    let cluster = Cluster::with_defaults(
        "weighted",
        vec![
            Endpoint::Weighted {
                address: "10.0.0.1:80".into(),
                weight: 5,
            },
            Endpoint::Weighted {
                address: "10.0.0.2:80".into(),
                weight: 3,
            },
        ],
    );
    let entry = build_cluster_entry(&cluster);
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let ctx = crate::test_utils::make_filter_context(&req);
    let mut counts = HashMap::new();
    for _ in 0..8 {
        *counts
            .entry(entry.strategy.select(&ctx, None).to_string())
            .or_insert(0u32) += 1;
    }
    assert_eq!(
        counts["10.0.0.1:80"], 5,
        "weight-5 endpoint should be selected 5 times per 8-slot cycle"
    );
    assert_eq!(
        counts["10.0.0.2:80"], 3,
        "weight-3 endpoint should be selected 3 times per 8-slot cycle"
    );
}

#[test]
fn build_cluster_entry_tls_and_sni() {
    let cluster = Cluster {
        tls: Some(praxis_core::config::ClusterTls {
            sni: Some("api.example.com".to_owned()),
            ..praxis_core::config::ClusterTls::default()
        }),
        ..Cluster::with_defaults("secure", vec!["10.0.0.1:443".into()])
    };
    let entry = build_cluster_entry(&cluster);
    assert!(entry.tls.is_some(), "TLS should be present");
    assert_eq!(
        entry.tls.as_ref().unwrap().sni(),
        Some("api.example.com"),
        "SNI should be preserved"
    );
}

#[test]
fn build_strategy_round_robin() {
    let endpoints = vec![WeightedEndpoint {
        address: Arc::from("10.0.0.1:80"),
        weight: 1,
        index: 0,
    }];
    let strategy = build_strategy(&LoadBalancerStrategy::Simple(SimpleStrategy::RoundRobin), endpoints);
    assert!(
        matches!(strategy.inner(), SharedStrategy::RoundRobin(_)),
        "RoundRobin config should produce RoundRobin strategy"
    );
}

#[test]
fn build_strategy_least_connections() {
    let endpoints = vec![WeightedEndpoint {
        address: Arc::from("10.0.0.1:80"),
        weight: 1,
        index: 0,
    }];
    let strategy = build_strategy(
        &LoadBalancerStrategy::Simple(SimpleStrategy::LeastConnections),
        endpoints,
    );
    assert!(
        matches!(strategy.inner(), SharedStrategy::LeastConnections(_)),
        "LeastConnections config should produce LeastConnections strategy"
    );
}

#[test]
fn build_strategy_consistent_hash() {
    let endpoints = vec![WeightedEndpoint {
        address: Arc::from("10.0.0.1:80"),
        weight: 1,
        index: 0,
    }];
    let strategy = build_strategy(
        &LoadBalancerStrategy::Parameterised(ParameterisedStrategy::ConsistentHash(ConsistentHashOpts {
            header: None,
        })),
        endpoints,
    );
    assert!(
        matches!(strategy.inner(), SharedStrategy::ConsistentHash(_)),
        "ConsistentHash config should produce ConsistentHash strategy"
    );
}

#[tokio::test]
async fn tls_and_sni_wired_from_cluster() {
    let cluster = Cluster {
        tls: Some(praxis_core::config::ClusterTls {
            sni: Some("api.example.com".into()),
            ..praxis_core::config::ClusterTls::default()
        }),
        ..Cluster::with_defaults("secure", vec!["10.0.0.1:443".into()])
    };
    let lb = LoadBalancerFilter::new(&[cluster]);
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.cluster = Some(Arc::from("secure"));
    drop(lb.on_request(&mut ctx).await.unwrap());
    let upstream = ctx.upstream.unwrap();
    assert!(upstream.tls.is_some(), "TLS should be enabled from cluster config");
    assert_eq!(
        upstream.tls.as_ref().unwrap().sni(),
        Some("api.example.com"),
        "SNI should match cluster config"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Build a [`Cluster`] with default strategy for testing.
fn test_cluster(name: &str, endpoints: &[&str]) -> Cluster {
    Cluster::with_defaults(name, endpoints.iter().map(|s| (*s).into()).collect())
}

/// Build a [`Cluster`] with a specific load balancer strategy.
fn cluster_with_strategy(name: &str, endpoints: &[&str], strategy: LoadBalancerStrategy) -> Cluster {
    Cluster {
        load_balancer_strategy: strategy,
        ..Cluster::with_defaults(name, endpoints.iter().map(|s| (*s).into()).collect())
    }
}
