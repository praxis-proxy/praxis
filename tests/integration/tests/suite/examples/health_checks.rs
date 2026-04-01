//! Example config test: health-checks.yaml parses and validates correctly.

use std::collections::HashMap;

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn health_checks_config_parses() {
    let config = super::load_example_config(
        "traffic-management/health-checks.yaml",
        19800,
        HashMap::from([
            ("127.0.0.1:3001", 19801_u16),
            ("127.0.0.1:3002", 19802_u16),
            ("127.0.0.1:3003", 19803_u16),
            ("127.0.0.1:5432", 19804_u16),
            ("127.0.0.1:5433", 19805_u16),
            ("127.0.0.1:9090", 19806_u16),
        ]),
    );

    assert_eq!(config.clusters.len(), 2, "should have 2 clusters");

    let backend = config.clusters.iter().find(|c| &*c.name == "backend").expect("backend cluster");
    let hc = backend.health_check.as_ref().expect("backend should have health_check");
    assert_eq!(
        hc.check_type,
        praxis_core::config::HealthCheckType::Http,
        "backend check type should be http"
    );
    assert_eq!(hc.path, "/healthz", "backend path should be /healthz");
    assert_eq!(hc.expected_status, 200, "expected status should be 200");
    assert_eq!(hc.interval_ms, 5000, "interval should be 5000");
    assert_eq!(hc.timeout_ms, 2000, "timeout should be 2000");
    assert_eq!(hc.healthy_threshold, 2, "healthy threshold should be 2");
    assert_eq!(hc.unhealthy_threshold, 3, "unhealthy threshold should be 3");

    let database = config.clusters.iter().find(|c| &*c.name == "database").expect("database cluster");
    let hc = database.health_check.as_ref().expect("database should have health_check");
    assert_eq!(
        hc.check_type,
        praxis_core::config::HealthCheckType::Tcp,
        "database check type should be tcp"
    );
    assert_eq!(hc.interval_ms, 10000, "database interval should be 10000");
    assert_eq!(hc.timeout_ms, 3000, "database timeout should be 3000");
}
