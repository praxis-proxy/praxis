// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Tests for the trusted private endpoints example configuration.

use std::net::{IpAddr, UdpSocket};

use praxis_core::{config::Config, connectivity::peer::seed_dns};
use praxis_test_utils::{Backend, example_config_path, free_port, http_get};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// The endpoint hostname the example lists.
const HOST: &str = "backend.models.svc.cluster.local";

/// The example's endpoint host, root dot included.
const FQDN: &str = "backend.models.svc.cluster.local.";

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn trusted_private_endpoints_reach_a_listed_private_host() {
    let ip = host_private_ip().expect("test setup: this host needs an RFC 1918 or unique-local address");
    let backend = Backend::fixed("private-backend").start_on_with_shutdown(ip);
    let backend_port = backend.port();
    seed_dns(FQDN, &[ip]);

    let proxy = praxis_test_utils::start_proxy(&example_config(backend_port, true));
    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "a listed host resolving to {ip} should be reached");
    assert_eq!(body, "private-backend", "proxy should forward to the listed host");
}

#[test]
fn trusted_private_endpoints_refuse_the_host_once_unlisted() {
    let ip = host_private_ip().expect("test setup: this host needs an RFC 1918 or unique-local address");
    let backend = Backend::fixed("private-backend").start_on_with_shutdown(ip);
    let backend_port = backend.port();
    seed_dns(FQDN, &[ip]);

    let proxy = praxis_test_utils::start_proxy(&example_config(backend_port, false));
    let (status, _) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 502, "an unlisted host resolving to {ip} should be refused");
}

#[test]
fn trusted_private_endpoints_refuse_a_listed_host_resolving_to_loopback() {
    let backend = Backend::fixed("loopback-backend").start_with_shutdown();
    let host = "loopback.models.svc.cluster.local";
    seed_dns(&format!("{host}."), &[IpAddr::from([127, 0, 0, 1])]);
    let yaml = std::fs::read_to_string(example_config_path("traffic-management/trusted-private-endpoints.yaml"))
        .expect("read example")
        .replace("0.0.0.0:8080", &format!("127.0.0.1:{}", free_port()))
        .replace(&format!("{FQDN}:3000"), &format!("{host}.:{}", backend.port()))
        .replace(HOST, host);
    let config = Config::from_yaml(&yaml).expect("listed host should load");
    let proxy = praxis_test_utils::start_proxy(&config);
    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(
        status, 502,
        "a listed host resolving to loopback should be refused, got {body:?}"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// The example with test ports, keeping the hostname endpoint intact.
fn example_config(backend_port: u16, listed: bool) -> Config {
    let path = example_config_path("traffic-management/trusted-private-endpoints.yaml");
    let mut yaml = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {path}: {e}"))
        .replace("0.0.0.0:8080", &format!("127.0.0.1:{}", free_port()))
        .replace(&format!("{FQDN}:3000"), &format!("{FQDN}:{backend_port}"));
    if !listed {
        yaml = yaml.replace(
            &format!("            trusted_private_endpoints:\n              - \"{HOST}\"\n"),
            "",
        );
        assert!(
            !yaml.contains("trusted_private_endpoints"),
            "the unlisted variant must drop the list"
        );
        // Past the load-time health check name rule, so the connect-time check is what refuses.
        yaml.push_str("\ninsecure_options:\n  allow_private_health_checks: true\n");
    }
    Config::from_yaml(&yaml).expect("trusted private endpoints example should parse")
}

/// This host's outbound RFC 1918 or unique-local address, if it has one.
fn host_private_ip() -> Option<IpAddr> {
    let probe = |bind: &str, target: &str| -> Option<IpAddr> {
        let socket = UdpSocket::bind(bind).ok()?;
        socket.connect(target).ok()?;
        Some(socket.local_addr().ok()?.ip())
    };
    [probe("0.0.0.0:0", "10.255.255.255:9"), probe("[::]:0", "[fd00::1]:9")]
        .into_iter()
        .flatten()
        .find(|ip| match ip {
            IpAddr::V4(v4) => v4.is_private(),
            IpAddr::V6(v6) => v6.is_unique_local(),
        })
}
