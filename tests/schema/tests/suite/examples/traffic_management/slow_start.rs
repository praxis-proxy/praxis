// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Slow start example schema test.

#[cfg(feature = "slow-start")]
use praxis_core::config::{Cluster, Config};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(feature = "slow-start")]
#[test]
fn slow_start_example_sets_window_and_aggression() {
    let path = format!(
        "{}/../../examples/configs/traffic-management/slow-start.yaml",
        env!("CARGO_MANIFEST_DIR")
    );
    let yaml = std::fs::read_to_string(&path).expect("read example");
    let config = Config::from_yaml(&yaml).expect("parse example");
    let load_balancer = config
        .filter_chains
        .iter()
        .flat_map(|chain| &chain.filters)
        .find(|entry| entry.filter_type == "load_balancer")
        .expect("load_balancer filter");
    let clusters = load_balancer.config.get("clusters").expect("clusters");
    let clusters: Vec<Cluster> = serde_yaml::from_value(clusters.clone()).expect("clusters deserialize");
    let cluster = clusters
        .iter()
        .find(|cluster| &*cluster.name == "backend")
        .expect("backend cluster");
    let slow_start = cluster.slow_start.expect("slow_start is set");
    assert_eq!(slow_start.window_ms, 30_000);
    assert_eq!(slow_start.aggression.to_bits(), 1.0_f64.to_bits());
}
