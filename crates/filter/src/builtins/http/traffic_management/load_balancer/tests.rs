// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Tests for the load balancer filter.

use std::{collections::HashMap, sync::Arc, time::Duration};

use praxis_core::{
    config::{Cluster, ConsistentHashOpts, Endpoint, LoadBalancerStrategy, ParameterisedStrategy, SimpleStrategy},
    health::{ClusterHealthEntry, ClusterHealthState, EndpointHealth, HealthRegistry},
};

use super::{LoadBalancerFilter, entry::build_cluster_entry, strategy::build_strategy};
use crate::{
    FilterAction,
    filter::HttpFilter as _,
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
fn try_new_rejects_semantically_invalid_authority() {
    let cluster = Cluster {
        http: praxis_core::config::ClusterHttpOptions {
            version: praxis_core::config::UpstreamHttpVersion::default(),
            authority: Some(Arc::from("https://api.example.com")),
            ..praxis_core::config::ClusterHttpOptions::default()
        },
        ..test_cluster("api", &["127.0.0.1:8080"])
    };

    let error = LoadBalancerFilter::try_new(&[cluster])
        .err()
        .expect("scheme-bearing authority should be rejected");
    assert!(
        error.to_string().contains("not a valid HTTP authority"),
        "error should identify the invalid authority component: {error}"
    );
}

#[test]
fn from_config_rejects_semantically_invalid_authority() {
    let config: serde_yaml::Value = serde_yaml::from_str(
        r#"
clusters:
  - name: api
    endpoints: ["127.0.0.1:8080"]
    http:
      authority: "api.example.com/v1"
"#,
    )
    .unwrap();

    let error = LoadBalancerFilter::from_config(&config)
        .err()
        .expect("path-bearing authority should be rejected");
    assert!(
        error.to_string().contains("not a valid HTTP authority"),
        "error should identify the invalid authority component: {error}"
    );
}

#[test]
#[should_panic(expected = "invalid load balancer cluster configuration")]
fn new_panics_on_invalid_authority() {
    let cluster = Cluster {
        http: praxis_core::config::ClusterHttpOptions {
            version: praxis_core::config::UpstreamHttpVersion::default(),
            authority: Some(Arc::from("user@api.example.com")),
            ..praxis_core::config::ClusterHttpOptions::default()
        },
        ..test_cluster("api", &["127.0.0.1:8080"])
    };

    drop(LoadBalancerFilter::new(&[cluster]));
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

#[test]
fn load_balancer_clusters_reports_configured_clusters() {
    let clusters = vec![
        test_cluster("web", &["127.0.0.1:8080"]),
        test_cluster("api", &["127.0.0.1:9090"]),
    ];
    let lb = LoadBalancerFilter::new(&clusters);
    let mut cluster_names = lb.load_balancer_clusters();
    cluster_names.sort();
    assert_eq!(
        cluster_names,
        vec!["api".to_owned(), "web".to_owned()],
        "load balancer should report configured clusters"
    );
}

#[test]
fn empty_load_balancer_reports_no_clusters() {
    let lb = LoadBalancerFilter::new(&[]);
    assert!(
        lb.load_balancer_clusters().is_empty(),
        "empty load balancer should report no clusters"
    );
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
        assert_eq!(lc.load_for("127.0.0.1:8080"), 1, "counter should be 1 after request");
    }

    drop(lb.on_response(&mut ctx).await.unwrap());

    if let SharedStrategy::LeastConnections(lc) = entry.strategy.inner() {
        assert_eq!(lc.load_for("127.0.0.1:8080"), 0, "counter should be 0 after response");
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
fn from_config_empty_clusters_rejected() {
    let yaml = serde_yaml::Value::Mapping(serde_yaml::Mapping::new());
    let Err(err) = LoadBalancerFilter::from_config(&yaml) else {
        panic!("empty clusters must be rejected");
    };
    assert!(
        err.to_string().contains("empty"),
        "an empty cluster table can serve nothing and must be rejected, got: {err}"
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
                metadata: HashMap::default(),
                zone: None,
                priority: 0,
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
        *counts.entry(ctx.upstream.unwrap().address).or_insert(0_u32) += 1;
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
    let entry = build_cluster_entry(&cluster).unwrap();
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let ctx = crate::test_utils::make_filter_context(&req);
    let mut seen = std::collections::HashSet::new();
    for _ in 0..3 {
        seen.insert(entry.strategy.select(&ctx, None, &[]).unwrap().to_string());
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
                metadata: HashMap::default(),
                zone: None,
                priority: 0,
            },
            Endpoint::Weighted {
                address: "10.0.0.2:80".into(),
                weight: 3,
                metadata: HashMap::default(),
                zone: None,
                priority: 0,
            },
        ],
    );
    let entry = build_cluster_entry(&cluster).unwrap();
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let ctx = crate::test_utils::make_filter_context(&req);
    let mut counts = HashMap::new();
    for _ in 0..8 {
        *counts
            .entry(entry.strategy.select(&ctx, None, &[]).unwrap().to_string())
            .or_insert(0_u32) += 1;
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
    let entry = build_cluster_entry(&cluster).unwrap();
    assert!(entry.tls.is_some(), "TLS should be present");
    assert_eq!(
        entry.tls.as_ref().unwrap().sni(),
        Some("api.example.com"),
        "SNI should be preserved"
    );
}

#[test]
fn build_cluster_entry_unreadable_tls_material_fails_closed() {
    let cluster = Cluster {
        tls: Some(praxis_core::config::ClusterTls {
            ca: Some(praxis_tls::CaConfig {
                ca_path: "/nonexistent/ca.pem".to_owned(),
                crl_paths: vec![],
            }),
            ..praxis_core::config::ClusterTls::default()
        }),
        ..Cluster::with_defaults("secure", vec!["10.0.0.1:443".into()])
    };
    let Err(err) = build_cluster_entry(&cluster) else {
        panic!("unreadable TLS material must fail the build, not silently disable TLS");
    };
    assert!(
        err.to_string().contains("refusing to fall back to plaintext"),
        "the error should say TLS will not silently downgrade: {err}"
    );
}

#[test]
fn build_strategy_round_robin() {
    let endpoints = vec![WeightedEndpoint::simple(Arc::from("10.0.0.1:80"), 1)];
    let strategy = build_strategy(&LoadBalancerStrategy::Simple(SimpleStrategy::RoundRobin), endpoints);
    assert!(
        matches!(strategy.inner(), SharedStrategy::RoundRobin(_)),
        "RoundRobin config should produce RoundRobin strategy"
    );
}

#[test]
fn build_strategy_least_connections() {
    let endpoints = vec![WeightedEndpoint::simple(Arc::from("10.0.0.1:80"), 1)];
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
    let endpoints = vec![WeightedEndpoint::simple(Arc::from("10.0.0.1:80"), 1)];
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
        http: praxis_core::config::ClusterHttpOptions {
            version: praxis_core::config::UpstreamHttpVersion::default(),
            authority: Some(Arc::from("public.example.com")),
            ..praxis_core::config::ClusterHttpOptions::default()
        },
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
    assert_eq!(
        upstream.authority.as_ref().and_then(|value| value.to_str().ok()),
        Some("public.example.com"),
        "HTTP authority should remain independent from TLS SNI"
    );
    assert!(upstream.tls.is_some(), "TLS should be enabled from cluster config");
    assert_eq!(
        upstream.tls.as_ref().unwrap().sni(),
        Some("api.example.com"),
        "SNI should match cluster config"
    );
}

#[tokio::test]
async fn on_request_errors_when_cluster_has_no_endpoints() {
    let lb = LoadBalancerFilter::new(&[test_cluster("empty", &[])]);
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.cluster = Some(Arc::from("empty"));
    let result = lb.on_request(&mut ctx).await;
    assert!(result.is_err(), "empty cluster should produce error");
    assert!(
        result.unwrap_err().to_string().contains("no available endpoints"),
        "error should mention no available endpoints"
    );
}

// -----------------------------------------------------------------------------
// Selected Cluster Application Tests
// -----------------------------------------------------------------------------

#[tokio::test]
async fn on_request_publishes_selected_application_ordinary_path() {
    let lb = LoadBalancerFilter::new(&[cluster_with_application(
        "llm",
        &["127.0.0.1:8080"],
        Some("openai_chat_completions"),
        Some("vllm"),
    )]);
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.cluster = Some(Arc::from("llm"));

    drop(lb.on_request(&mut ctx).await.unwrap());

    assert_eq!(
        ctx.selected_application_protocol(),
        Some("openai_chat_completions"),
        "ordinary selection should publish the selected cluster's application protocol"
    );
    assert_eq!(
        ctx.selected_application_provider(),
        Some("vllm"),
        "ordinary selection should publish the selected cluster's application provider"
    );
}

#[tokio::test]
async fn on_request_publishes_selected_application_for_preset_upstream() {
    let lb = LoadBalancerFilter::new(&[cluster_with_application(
        "llm",
        &["127.0.0.1:8080"],
        Some("openai_chat_completions"),
        Some("vllm"),
    )]);
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.cluster = Some(Arc::from("llm"));
    ctx.upstream = Some(praxis_core::connectivity::Upstream {
        address: Arc::from("10.0.0.7:8000"),
        authority: None,
        connection: Arc::new(praxis_core::connectivity::ConnectionOptions::default()),
        tls: None,
    });

    drop(lb.on_request(&mut ctx).await.unwrap());

    assert_eq!(
        ctx.upstream.as_ref().map(|upstream| upstream.address.as_ref()),
        Some("10.0.0.7:8000"),
        "a preset upstream (e.g. from endpoint_selector) must be kept"
    );
    assert_eq!(
        ctx.selected_application_provider(),
        Some("vllm"),
        "the routed cluster's metadata must be published even when the upstream was preset"
    );
}

#[tokio::test]
async fn on_request_publishes_selected_application_pinned_endpoint() {
    let lb = LoadBalancerFilter::new(&[cluster_with_application(
        "llm",
        &["127.0.0.1:8080"],
        Some("openai_responses"),
        Some("openai"),
    )]);
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.cluster = Some(Arc::from("llm"));
    ctx.pinned_endpoint_address = Some(Arc::from("127.0.0.1:8080"));

    drop(lb.on_request(&mut ctx).await.unwrap());

    assert!(ctx.upstream.is_some(), "the pinned endpoint should have been used");
    assert_eq!(
        ctx.selected_application_protocol(),
        Some("openai_responses"),
        "the pinned-endpoint path should publish the selected cluster's application protocol"
    );
    assert_eq!(
        ctx.selected_application_provider(),
        Some("openai"),
        "the pinned-endpoint path should publish the selected cluster's application provider"
    );
}

#[tokio::test]
async fn on_request_publishes_selected_application_panic_mode() {
    let lb = LoadBalancerFilter::new(&[cluster_with_application(
        "llm",
        &["127.0.0.1:8080", "127.0.0.1:8081"],
        Some("openai_chat_completions"),
        Some("vllm"),
    )]);
    let registry = health_registry("llm", &["127.0.0.1:8080", "127.0.0.1:8081"], &[0, 1]);
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.cluster = Some(Arc::from("llm"));
    ctx.health_registry = Some(&registry);

    drop(lb.on_request(&mut ctx).await.unwrap());

    assert!(ctx.upstream.is_some(), "panic mode should still select an upstream");
    assert_eq!(
        ctx.selected_application_protocol(),
        Some("openai_chat_completions"),
        "panic-mode selection should publish the selected cluster's application protocol"
    );
    assert_eq!(
        ctx.selected_application_provider(),
        Some("vllm"),
        "panic-mode selection should publish the selected cluster's application provider"
    );
}

#[tokio::test]
async fn on_request_leaves_application_absent_for_untagged_cluster() {
    let lb = LoadBalancerFilter::new(&[test_cluster("web", &["127.0.0.1:8080"])]);
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.cluster = Some(Arc::from("web"));

    drop(lb.on_request(&mut ctx).await.unwrap());

    assert!(
        ctx.upstream.is_some(),
        "an untagged cluster should still select an upstream"
    );
    assert_eq!(
        ctx.selected_application_protocol(),
        None,
        "an untagged cluster must not publish an application protocol"
    );
    assert_eq!(
        ctx.selected_application_provider(),
        None,
        "an untagged cluster must not publish an application provider"
    );
}

#[tokio::test]
async fn on_request_leaves_application_absent_on_failed_selection() {
    let lb = LoadBalancerFilter::new(&[cluster_with_application(
        "empty",
        &[],
        Some("openai_chat_completions"),
        Some("vllm"),
    )]);
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.cluster = Some(Arc::from("empty"));

    let result = lb.on_request(&mut ctx).await;

    assert!(result.is_err(), "a cluster with no endpoints must fail selection");
    assert_eq!(
        ctx.selected_application_protocol(),
        None,
        "a failed selection must not publish an application protocol"
    );
    assert_eq!(
        ctx.selected_application_provider(),
        None,
        "a failed selection must not publish an application provider"
    );
}

#[tokio::test]
async fn selected_application_survives_on_response() {
    let lb = LoadBalancerFilter::new(&[cluster_with_application(
        "llm",
        &["127.0.0.1:8080"],
        Some("openai_responses"),
        Some("openai"),
    )]);
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.cluster = Some(Arc::from("llm"));

    drop(lb.on_request(&mut ctx).await.unwrap());
    drop(lb.on_response(&mut ctx).await.unwrap());

    assert_eq!(
        ctx.selected_application_protocol(),
        Some("openai_responses"),
        "the response phase must observe the same application protocol published at selection"
    );
    assert_eq!(
        ctx.selected_application_provider(),
        Some("openai"),
        "the response phase must observe the same application provider published at selection"
    );
}

#[tokio::test]
async fn transport_retry_does_not_change_selected_application() {
    let lb = LoadBalancerFilter::new(&[cluster_with_application(
        "llm",
        &["127.0.0.1:8080", "127.0.0.1:8081"],
        Some("openai_chat_completions"),
        Some("vllm"),
    )]);
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.cluster = Some(Arc::from("llm"));

    drop(lb.on_request(&mut ctx).await.unwrap());

    let reselector = ctx.endpoint_reselector.clone().expect("reselector should be set");
    let attempted = ctx.attempted_endpoints.clone();
    let next = reselector
        .select_address(None, &attempted)
        .expect("an alternate endpoint should be available for retry");
    ctx.upstream = Some(reselector.build_upstream(next));

    assert_eq!(
        ctx.selected_application_protocol(),
        Some("openai_chat_completions"),
        "a transport retry must not change the published application protocol"
    );
    assert_eq!(
        ctx.selected_application_provider(),
        Some("vllm"),
        "a transport retry must not change the published application provider"
    );
}

#[tokio::test]
async fn selected_application_survives_pipeline_drop() {
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.cluster = Some(Arc::from("llm"));

    {
        let lb = LoadBalancerFilter::new(&[cluster_with_application(
            "llm",
            &["127.0.0.1:8080"],
            Some("openai_chat_completions"),
            Some("vllm"),
        )]);
        drop(lb.on_request(&mut ctx).await.unwrap());
    }

    assert_eq!(
        ctx.selected_application_protocol(),
        Some("openai_chat_completions"),
        "dropping the selecting pipeline (as a hot reload does) must not disturb this exchange's protocol"
    );
    assert_eq!(
        ctx.selected_application_provider(),
        Some("vllm"),
        "dropping the selecting pipeline (as a hot reload does) must not disturb this exchange's provider"
    );
}

#[tokio::test]
async fn irr_style_reuse_untagged_step_clears_prior_application() {
    let tagged_step = LoadBalancerFilter::new(&[cluster_with_application(
        "llm",
        &["127.0.0.1:8080"],
        Some("openai_chat_completions"),
        Some("vllm"),
    )]);
    let untagged_step = LoadBalancerFilter::new(&[test_cluster("web", &["127.0.0.1:9090"])]);
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    ctx.cluster = Some(Arc::from("llm"));
    drop(tagged_step.on_request(&mut ctx).await.unwrap());
    assert_eq!(
        ctx.selected_application_protocol(),
        Some("openai_chat_completions"),
        "the first step must publish its tagged cluster's application protocol"
    );

    ctx.upstream = None;
    ctx.cluster = Some(Arc::from("web"));
    drop(untagged_step.on_request(&mut ctx).await.unwrap());

    assert_eq!(
        ctx.selected_application_protocol(),
        None,
        "a later untagged step reusing the same extensions must not observe the prior step's protocol"
    );
    assert_eq!(
        ctx.selected_application_provider(),
        None,
        "a later untagged step reusing the same extensions must not observe the prior step's provider"
    );
}

// -----------------------------------------------------------------------------
// Bound Upstream Source Tests
// -----------------------------------------------------------------------------

#[cfg(feature = "upstream-binding")]
#[test]
fn consumes_bound_upstream_reflects_cluster_source() {
    let router_lb = LoadBalancerFilter::new(&[test_cluster("backend", &["127.0.0.1:8080"])]);
    assert!(
        !router_lb.consumes_bound_upstream(),
        "the default router source must not consume a binding"
    );

    let bound_lb = LoadBalancerFilter::try_new_with_source(
        &[test_cluster("backend", &["127.0.0.1:8080"])],
        super::ClusterSource::BoundUpstream,
    )
    .unwrap();
    assert!(
        bound_lb.consumes_bound_upstream(),
        "the bound_upstream source must report that it consumes a binding"
    );
}

#[test]
fn from_config_rejects_unknown_cluster_source() {
    let config: serde_yaml::Value = serde_yaml::from_str(
        r#"
cluster_source: sideways
clusters:
  - name: backend
    endpoints: ["127.0.0.1:8080"]
"#,
    )
    .unwrap();

    let error = LoadBalancerFilter::from_config(&config)
        .err()
        .expect("an unknown cluster_source value must be rejected");
    assert!(
        error.to_string().contains("sideways") || error.to_string().contains("variant"),
        "the error should identify the invalid cluster_source: {error}"
    );
}

#[cfg(feature = "upstream-binding")]
#[tokio::test]
async fn bound_upstream_source_selects_bound_cluster_from_config() {
    let config: serde_yaml::Value = serde_yaml::from_str(
        r#"
cluster_source: bound_upstream
clusters:
  - name: backend
    endpoints: ["127.0.0.1:8080"]
    http:
      application_protocol: openai_responses
      application_provider: openai
"#,
    )
    .unwrap();
    let lb = LoadBalancerFilter::from_config(&config).unwrap();
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.publish_bound_upstream(
        Arc::from("backend"),
        Some(Arc::from("openai_responses")),
        Some(Arc::from("openai")),
    )
    .unwrap();

    let action = lb.on_request(&mut ctx).await.unwrap();

    assert!(
        matches!(action, FilterAction::Continue),
        "a resolved bound selection should continue"
    );
    let upstream = ctx
        .upstream
        .as_ref()
        .expect("upstream should be selected from the bound cluster");
    assert_eq!(
        &*upstream.address, "127.0.0.1:8080",
        "the endpoint must come from the bound cluster"
    );
    assert_eq!(
        ctx.cluster.as_deref(),
        Some("backend"),
        "the bound path must seed ctx.cluster so retry, health, and release paths key off the same cluster"
    );
    assert_eq!(
        ctx.selected_application_protocol(),
        Some("openai_responses"),
        "the bound path must publish the selected cluster's application protocol"
    );
    assert_eq!(
        ctx.selected_application_provider(),
        Some("openai"),
        "the bound path must publish the selected cluster's application provider"
    );
}

#[cfg(feature = "upstream-binding")]
#[tokio::test]
async fn bound_upstream_source_does_not_mutate_binding() {
    let lb = LoadBalancerFilter::try_new_with_source(
        &[cluster_with_application(
            "backend",
            &["127.0.0.1:8080"],
            Some("openai_responses"),
            Some("openai"),
        )],
        super::ClusterSource::BoundUpstream,
    )
    .unwrap();
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.publish_bound_upstream(
        Arc::from("backend"),
        Some(Arc::from("bound_proto")),
        Some(Arc::from("bound_prov")),
    )
    .unwrap();

    drop(lb.on_request(&mut ctx).await.unwrap());

    assert_eq!(
        ctx.bound_cluster(),
        Some("backend"),
        "the frozen binding cluster must be untouched by endpoint selection"
    );
    assert_eq!(
        ctx.bound_application_protocol(),
        Some("bound_proto"),
        "the frozen binding protocol must be untouched by endpoint selection"
    );
    assert_eq!(
        ctx.bound_application_provider(),
        Some("bound_prov"),
        "the frozen binding provider must be untouched by endpoint selection"
    );
}

#[cfg(feature = "upstream-binding")]
#[tokio::test]
async fn bound_upstream_source_rejects_conflicting_context_cluster() {
    let lb = LoadBalancerFilter::try_new_with_source(
        &[test_cluster("backend", &["127.0.0.1:8080"])],
        super::ClusterSource::BoundUpstream,
    )
    .unwrap();
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.cluster = Some(Arc::from("stale"));
    ctx.publish_bound_upstream(Arc::from("backend"), None, None).unwrap();

    let error = lb.on_request(&mut ctx).await.unwrap_err();

    assert_eq!(
        ctx.cluster.as_deref(),
        Some("stale"),
        "a conflicting exchange selection must remain visible for diagnostics"
    );
    assert!(
        ctx.upstream.is_none(),
        "a conflicting selection must not choose an endpoint"
    );
    assert!(
        error.to_string().contains("conflicts with bound cluster 'backend'"),
        "the error must name both selection domains: {error}"
    );
}

#[cfg(feature = "upstream-binding")]
#[tokio::test]
async fn bound_upstream_source_preserves_retry_policy_when_conflict_is_rejected() {
    let lb = LoadBalancerFilter::try_new_with_source(
        &[test_cluster("backend", &["127.0.0.1:8080"])],
        super::ClusterSource::BoundUpstream,
    )
    .unwrap();
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.cluster = Some(Arc::from("stale"));
    ctx.route_retry_policy = Some(Arc::new(praxis_core::config::RetryPolicy::default()));
    ctx.publish_bound_upstream(Arc::from("backend"), None, None).unwrap();

    let error = lb.on_request(&mut ctx).await.unwrap_err();

    assert!(
        ctx.route_retry_policy.is_some(),
        "rejected resolution must not mutate retry state"
    );
    assert_eq!(
        ctx.cluster.as_deref(),
        Some("stale"),
        "rejected resolution must not overwrite the selected cluster"
    );
    assert!(
        error.to_string().contains("conflicts with bound cluster"),
        "error should report the conflict with the bound cluster: {error}"
    );
}

#[cfg(feature = "upstream-binding")]
#[tokio::test]
async fn bound_upstream_source_with_existing_upstream_preserves_context() {
    let lb = LoadBalancerFilter::try_new_with_source(
        &[test_cluster("backend", &["127.0.0.1:8080"])],
        super::ClusterSource::BoundUpstream,
    )
    .unwrap();
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.cluster = Some(Arc::from("already-selected"));
    ctx.upstream = Some(praxis_core::connectivity::Upstream {
        address: Arc::from("127.0.0.1:9090"),
        authority: None,
        connection: Arc::new(praxis_core::connectivity::ConnectionOptions::default()),
        tls: None,
    });
    ctx.publish_bound_upstream(Arc::from("backend"), None, None).unwrap();

    let action = lb.on_request(&mut ctx).await.unwrap();

    assert!(
        matches!(action, FilterAction::Continue),
        "an existing upstream should let the pipeline continue: {action:?}"
    );
    assert_eq!(
        ctx.cluster.as_deref(),
        Some("already-selected"),
        "an existing upstream should keep its selected cluster"
    );
    assert_eq!(
        ctx.upstream.as_ref().map(|upstream| upstream.address.as_ref()),
        Some("127.0.0.1:9090"),
        "an existing upstream should not be replaced by the bound cluster's endpoint"
    );
}

#[cfg(feature = "upstream-binding")]
#[tokio::test]
async fn bound_upstream_source_honors_session_affinity() {
    let lb = LoadBalancerFilter::try_new_with_source(
        &[test_cluster("backend", &["127.0.0.1:8080", "127.0.0.1:8081"])],
        super::ClusterSource::BoundUpstream,
    )
    .unwrap();
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.publish_bound_upstream(Arc::from("backend"), None, None).unwrap();
    ctx.pinned_endpoint_address = Some(Arc::from("127.0.0.1:8081"));

    drop(lb.on_request(&mut ctx).await.unwrap());

    assert_eq!(
        ctx.upstream.as_ref().map(|upstream| upstream.address.as_ref()),
        Some("127.0.0.1:8081"),
        "the bound cluster should honor the pinned session-affinity endpoint"
    );
    assert_eq!(
        ctx.cluster.as_deref(),
        Some("backend"),
        "the bound cluster should become the selected cluster"
    );
}

#[cfg(feature = "upstream-binding")]
#[tokio::test]
async fn bound_upstream_source_skips_unhealthy_endpoints() {
    let endpoints = ["127.0.0.1:8080", "127.0.0.1:8081"];
    let lb = LoadBalancerFilter::try_new_with_source(
        &[test_cluster("backend", &endpoints)],
        super::ClusterSource::BoundUpstream,
    )
    .unwrap();
    let registry = health_registry("backend", &endpoints, &[0]);
    let req = crate::test_utils::make_request(http::Method::GET, "/");

    for _ in 0..4 {
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.publish_bound_upstream(Arc::from("backend"), None, None).unwrap();
        ctx.health_registry = Some(&registry);

        drop(lb.on_request(&mut ctx).await.unwrap());

        assert_eq!(
            ctx.upstream.as_ref().map(|upstream| upstream.address.as_ref()),
            Some("127.0.0.1:8081"),
            "the bound load balancer must skip the unhealthy endpoint"
        );
        assert_eq!(
            ctx.selected_endpoint_index,
            Some(1),
            "the healthy endpoint's index must be recorded for release"
        );
    }
}

#[cfg(feature = "upstream-binding")]
#[tokio::test]
async fn bound_upstream_source_panics_to_all_endpoints_when_none_are_healthy() {
    let endpoints = ["127.0.0.1:8080", "127.0.0.1:8081"];
    let lb = LoadBalancerFilter::try_new_with_source(
        &[test_cluster("backend", &endpoints)],
        super::ClusterSource::BoundUpstream,
    )
    .unwrap();
    let registry = health_registry("backend", &endpoints, &[0, 1]);
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut reached = std::collections::HashSet::new();

    for _ in 0..4 {
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.publish_bound_upstream(Arc::from("backend"), None, None).unwrap();
        ctx.health_registry = Some(&registry);

        drop(lb.on_request(&mut ctx).await.unwrap());

        assert!(
            ctx.selected_endpoint_index.is_some(),
            "panic mode must still record the selected endpoint for release"
        );
        reached.extend(ctx.upstream.map(|upstream| upstream.address.to_string()));
    }

    assert_eq!(
        reached,
        endpoints.iter().map(ToString::to_string).collect(),
        "with every endpoint down, panic mode spreads over all of them"
    );
}

#[cfg(feature = "upstream-binding")]
#[tokio::test]
async fn bound_upstream_source_preserves_consistent_hash_selection() {
    let cluster = cluster_with_strategy(
        "backend",
        &["127.0.0.1:8080", "127.0.0.1:8081", "127.0.0.1:8082"],
        LoadBalancerStrategy::Parameterised(ParameterisedStrategy::ConsistentHash(ConsistentHashOpts {
            header: Some("x-session".to_owned()),
        })),
    );
    let lb = LoadBalancerFilter::try_new_with_source(&[cluster], super::ClusterSource::BoundUpstream).unwrap();
    let mut req = crate::test_utils::make_request(http::Method::GET, "/different-paths-do-not-matter");
    req.headers
        .insert("x-session", http::HeaderValue::from_static("stable-key"));

    let mut first = crate::test_utils::make_filter_context(&req);
    first.publish_bound_upstream(Arc::from("backend"), None, None).unwrap();
    drop(lb.on_request(&mut first).await.unwrap());

    let mut second = crate::test_utils::make_filter_context(&req);
    second.publish_bound_upstream(Arc::from("backend"), None, None).unwrap();
    drop(lb.on_request(&mut second).await.unwrap());

    assert_eq!(
        first.upstream.as_ref().map(|upstream| upstream.address.as_ref()),
        second.upstream.as_ref().map(|upstream| upstream.address.as_ref()),
        "bound selection must use the same strategy and hash key as router-source selection"
    );
}

#[tokio::test]
async fn bound_upstream_source_errors_when_unbound() {
    let lb = LoadBalancerFilter::try_new_with_source(
        &[test_cluster("backend", &["127.0.0.1:8080"])],
        super::ClusterSource::BoundUpstream,
    )
    .unwrap();
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let error = lb.on_request(&mut ctx).await.unwrap_err();

    assert!(
        error.to_string().contains("no upstream is bound"),
        "a bound-source LB with no binding must fail closed: {error}"
    );
    assert!(ctx.upstream.is_none(), "no upstream may be selected without a binding");
    assert!(
        ctx.cluster.is_none(),
        "a failed bound resolution must not seed the exchange cluster"
    );
}

#[cfg(feature = "upstream-binding")]
#[tokio::test]
async fn bound_upstream_source_errors_when_bound_cluster_not_declared() {
    let lb = LoadBalancerFilter::try_new_with_source(
        &[test_cluster("backend", &["127.0.0.1:8080"])],
        super::ClusterSource::BoundUpstream,
    )
    .unwrap();
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.publish_bound_upstream(Arc::from("other"), None, None).unwrap();

    let error = lb.on_request(&mut ctx).await.unwrap_err();

    assert!(
        error.to_string().contains("not declared in this load_balancer"),
        "a binding to a cluster this load balancer does not declare must fail closed: {error}"
    );
    assert!(
        ctx.upstream.is_none(),
        "no upstream may be selected for an undeclared cluster"
    );
    assert!(
        ctx.cluster.is_none(),
        "an undeclared bound cluster must not be seeded as the exchange cluster"
    );
}

#[cfg(feature = "upstream-binding")]
#[tokio::test]
async fn bound_upstream_source_accepts_matching_context_cluster() {
    let lb = LoadBalancerFilter::try_new_with_source(
        &[test_cluster("backend", &["127.0.0.1:8080"])],
        super::ClusterSource::BoundUpstream,
    )
    .expect("a valid bound-source load balancer builds");
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.cluster = Some(Arc::from("backend"));
    ctx.publish_bound_upstream(Arc::from("backend"), None, None)
        .expect("publish before freeze succeeds");

    let action = lb
        .on_request(&mut ctx)
        .await
        .expect("an exchange cluster that agrees with the binding is accepted");

    assert!(
        matches!(action, FilterAction::Continue),
        "an agreeing exchange cluster should continue: {action:?}"
    );
    assert_eq!(
        ctx.upstream.as_ref().map(|upstream| upstream.address.as_ref()),
        Some("127.0.0.1:8080"),
        "the endpoint must come from the bound cluster"
    );
    assert_eq!(
        ctx.cluster.as_deref(),
        Some("backend"),
        "an agreeing exchange cluster is left in place"
    );
}

#[cfg(feature = "upstream-binding")]
#[test]
fn bound_upstream_clusters_lists_declared_clusters_only_for_the_bound_source() {
    let clusters = r#"
clusters:
  - name: alpha
    endpoints: ["127.0.0.1:8080"]
  - name: beta
    endpoints: ["127.0.0.1:8081"]
"#;
    let bound: serde_yaml::Value =
        serde_yaml::from_str(&format!("cluster_source: bound_upstream{clusters}")).expect("valid YAML");
    let router: serde_yaml::Value = serde_yaml::from_str(clusters).expect("valid YAML");
    let bound_lb = LoadBalancerFilter::from_config(&bound).expect("the bound source parses");
    let router_lb = LoadBalancerFilter::from_config(&router).expect("the default source parses");

    let mut declared = bound_lb.bound_upstream_clusters();
    declared.sort();

    assert_eq!(
        declared,
        vec!["alpha".to_owned(), "beta".to_owned()],
        "a bound-source load balancer reports every cluster it can resolve from the binding"
    );
    assert!(
        router_lb.bound_upstream_clusters().is_empty(),
        "a router-source load balancer resolves nothing from the binding"
    );
}

#[cfg(feature = "upstream-binding")]
#[test]
fn declared_cluster_metadata_is_sorted_and_keeps_untagged_clusters() {
    let lb = LoadBalancerFilter::new(&[
        cluster_with_application("zeta", &["127.0.0.1:8080"], Some("openai_responses"), Some("openai")),
        test_cluster("alpha", &["127.0.0.1:8081"]),
        cluster_with_application("mid", &["127.0.0.1:8082"], Some("openai_chat_completions"), None),
    ]);

    let declared = lb.declared_cluster_metadata();

    let names: Vec<&str> = declared.iter().map(|decl| decl.name.as_ref()).collect();
    assert_eq!(
        names,
        vec!["alpha", "mid", "zeta"],
        "declarations are sorted by cluster name so the catalog is deterministic"
    );
    let tags: Vec<(Option<&str>, Option<&str>)> = declared
        .iter()
        .map(|decl| (decl.metadata.protocol(), decl.metadata.provider()))
        .collect();
    assert_eq!(
        tags,
        vec![
            (None, None),
            (Some("openai_chat_completions"), None),
            (Some("openai_responses"), Some("openai")),
        ],
        "every cluster is declared, with untagged ones carrying no metadata"
    );
}

#[cfg(feature = "upstream-binding")]
#[test]
fn explicit_router_cluster_source_parses_as_the_default() {
    let config: serde_yaml::Value = serde_yaml::from_str(
        r#"
cluster_source: router
clusters:
  - name: backend
    endpoints: ["127.0.0.1:8080"]
"#,
    )
    .expect("valid YAML");

    let lb = LoadBalancerFilter::from_config(&config).expect("an explicit router source is accepted");

    assert!(
        !lb.consumes_bound_upstream(),
        "an explicit router source behaves like the omitted default"
    );
    assert!(
        lb.bound_upstream_clusters().is_empty(),
        "an explicit router source resolves nothing from the binding"
    );
    assert_eq!(
        lb.load_balancer_clusters(),
        vec!["backend".to_owned()],
        "the declared cluster is still served through the router path"
    );
}

#[cfg(feature = "upstream-binding")]
#[tokio::test]
async fn bound_source_releases_least_connections_on_response() {
    let cluster = cluster_with_strategy(
        "backend",
        &["127.0.0.1:8080"],
        LoadBalancerStrategy::Simple(SimpleStrategy::LeastConnections),
    );
    let lb = LoadBalancerFilter::try_new_with_source(&[cluster], super::ClusterSource::BoundUpstream)
        .expect("a valid bound-source load balancer builds");
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.publish_bound_upstream(Arc::from("backend"), None, None)
        .expect("publish before freeze succeeds");

    drop(lb.on_request(&mut ctx).await.expect("bound selection succeeds"));

    assert_eq!(
        least_connections_load(&lb, "backend", "127.0.0.1:8080"),
        Some(1),
        "the bound selection is counted in flight"
    );

    drop(lb.on_response(&mut ctx).await.expect("release succeeds"));

    assert_eq!(
        least_connections_load(&lb, "backend", "127.0.0.1:8080"),
        Some(0),
        "on_response releases the in-flight count through the cluster the bound path seeded"
    );
}

#[cfg(feature = "upstream-binding")]
#[tokio::test]
async fn bound_source_panic_mode_metric_uses_the_bound_cluster() {
    crate::test_utils::install_metrics_recorder();
    let endpoints = ["127.0.0.1:8080", "127.0.0.1:8081"];
    let lb = LoadBalancerFilter::try_new_with_source(
        &[test_cluster("bound-panic", &endpoints)],
        super::ClusterSource::BoundUpstream,
    )
    .expect("a valid bound-source load balancer builds");
    let registry = health_registry("bound-panic", &endpoints, &[0, 1]);
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.publish_bound_upstream(Arc::from("bound-panic"), None, None)
        .expect("publish before freeze succeeds");
    ctx.health_registry = Some(&registry);

    drop(
        lb.on_request(&mut ctx)
            .await
            .expect("panic mode still selects an endpoint"),
    );

    let rendered = crate::test_utils::render_metrics();
    assert!(
        rendered.contains("praxis_lb_panic_mode_total{cluster=\"bound-panic\"}"),
        "panic mode under the bound source must label the counter with the bound cluster:\n{rendered}"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Build a [`Cluster`] with default strategy for testing.
fn test_cluster(name: &str, endpoints: &[&str]) -> Cluster {
    Cluster::with_defaults(name, endpoints.iter().map(|s| (*s).into()).collect())
}

/// Build a [`Cluster`] tagged with application protocol and/or provider.
fn cluster_with_application(name: &str, endpoints: &[&str], protocol: Option<&str>, provider: Option<&str>) -> Cluster {
    Cluster {
        http: praxis_core::config::ClusterHttpOptions {
            application_protocol: protocol.map(Arc::from),
            application_provider: provider.map(Arc::from),
            ..praxis_core::config::ClusterHttpOptions::default()
        },
        ..Cluster::with_defaults(name, endpoints.iter().map(|s| (*s).into()).collect())
    }
}

/// Build a [`HealthRegistry`] for `cluster` with the endpoints at `unhealthy`
/// marked down.
fn health_registry(cluster: &str, endpoints: &[&str], unhealthy: &[usize]) -> HealthRegistry {
    let entry: ClusterHealthState = Arc::new(ClusterHealthEntry::new(
        endpoints.iter().map(|_| EndpointHealth::new()).collect(),
        endpoints.iter().map(|s| Arc::from(*s)).collect(),
        None,
        None,
    ));
    for (idx, ep) in entry.endpoints().iter().enumerate() {
        if unhealthy.contains(&idx) {
            ep.mark_unhealthy();
        }
    }
    Arc::new(HashMap::from([(Arc::from(cluster), entry)]))
}

/// Build a [`Cluster`] with a specific load balancer strategy.
fn cluster_with_strategy(name: &str, endpoints: &[&str], strategy: LoadBalancerStrategy) -> Cluster {
    Cluster {
        load_balancer_strategy: strategy,
        ..Cluster::with_defaults(name, endpoints.iter().map(|s| (*s).into()).collect())
    }
}

#[cfg(feature = "upstream-binding")]
/// In-flight count the least-connections strategy tracks for `endpoint` in
/// `cluster`, or `None` when the cluster is unknown or uses another strategy.
fn least_connections_load(lb: &LoadBalancerFilter, cluster: &str, endpoint: &str) -> Option<usize> {
    match lb.clusters.get(cluster)?.strategy.inner() {
        SharedStrategy::LeastConnections(lc) => Some(lc.load_for(endpoint)),
        _ => None,
    }
}

#[cfg(not(feature = "upstream-binding"))]
#[test]
fn bound_upstream_source_needs_the_upstream_binding_feature() {
    let config: serde_yaml::Value = serde_yaml::from_str(
        r#"
cluster_source: bound_upstream
clusters:
  - name: backend
    endpoints: ["127.0.0.1:9"]
"#,
    )
    .unwrap();

    let error = LoadBalancerFilter::from_config(&config)
        .map(drop)
        .expect_err("a bound source is rejected without the feature");

    assert!(
        error.to_string().contains("needs the upstream-binding build feature"),
        "the error names the missing feature instead of failing at request time: {error}"
    );
}
