// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Tests for the endpoint-derived upstream authority example configuration.

use std::{collections::BTreeMap, net::IpAddr};

use praxis_core::{config::Config, connectivity::peer::seed_dns};
use praxis_test_utils::{
    BackendGuard, ProxyGuard, TestCertificates, example_config_path, free_port, h2c_get, http_get,
    start_tagged_header_echo_backend, start_tls_backend,
};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// The `Host` every test client sends, which must never reach a backend.
const CLIENT_HOST: &str = "client.example.com";

/// The first TLS endpoint's hostname, the only name on its certificate.
const ALPHA_HOST: &str = "alpha.authority-from-endpoint.test";

/// The second TLS endpoint's hostname, the only name on its certificate.
const BETA_HOST: &str = "beta.authority-from-endpoint.test";

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn authority_from_endpoint_sends_each_endpoint_its_own_address() {
    let example = ExampleProxy::start();

    let hosts = example.hosts_by_backend(|addr, path| http_get(addr, path, Some(CLIENT_HOST)));

    assert_eq!(
        hosts,
        example.expected_hosts(),
        "each backend should receive its own endpoint address as Host"
    );
}

#[test]
fn authority_from_endpoint_works_over_h2c_downstream() {
    let example = ExampleProxy::start();

    let hosts = example.hosts_by_backend(|addr, path| h2c_get(addr, path, Some(CLIENT_HOST)));

    assert_eq!(
        hosts,
        example.expected_hosts(),
        "an HTTP/2 client should not change the per-endpoint Host"
    );
}

#[test]
fn authority_from_endpoint_retry_sends_the_reselected_endpoint_address() {
    let live = start_tagged_header_echo_backend("live");
    let dead_port = free_port();
    let path = example_config_path("traffic-management/authority-from-endpoint.yaml");
    let yaml = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {path}: {e}"))
        .replace("localhost:9000", &format!("localhost:{dead_port}"))
        .replace("127.0.0.1:9001", &format!("127.0.0.1:{}", live.port()))
        .replace(
            "              authority: { from: endpoint }\n",
            "              authority: { from: endpoint }\n            retry_policy:\n              max_retries: 2\n              \
             retriable_conditions: [connect_failure]\n",
        )
        .replace("0.0.0.0:8080", &format!("127.0.0.1:{}", free_port()));
    assert!(
        yaml.contains("retry_policy:"),
        "test setup: the retry policy should have been added"
    );
    let config = Config::from_yaml(&yaml).expect("example with a retry policy should parse");
    let proxy = praxis_test_utils::start_proxy(&config);

    for i in 0..4 {
        let (status, body) = http_get(proxy.addr(), &format!("/req-{i}"), Some(CLIENT_HOST));
        assert_eq!(
            status, 200,
            "request {i} should fail over to the live endpoint; got {body}"
        );
        assert_eq!(
            tag_and_host(&body),
            ("live".to_owned(), format!("127.0.0.1:{}", live.port())),
            "request {i}: a retry must send the reselected endpoint's address, not the dead one's"
        );
    }
}

#[test]
fn authority_from_endpoint_tls_presents_each_endpoint_name_as_sni() {
    let tls = TlsEndpoints::start();
    let config = Config::from_yaml(&tls.yaml("")).expect("verify without tls.sni is accepted for hostname endpoints");
    let proxy = praxis_test_utils::start_proxy(&config);

    let mut bodies = Vec::new();
    for i in 0..4 {
        let (status, body) = http_get(proxy.addr(), &format!("/req-{i}"), Some(CLIENT_HOST));
        assert_eq!(
            status, 200,
            "request {i}: each endpoint's certificate names only that endpoint, so SNI must follow it; got {body}"
        );
        bodies.push(body);
    }
    bodies.sort();
    bodies.dedup();
    assert_eq!(
        bodies,
        ["alpha", "beta"],
        "round robin should have verified and reached both endpoints"
    );
}

#[test]
fn tls_without_endpoint_authority_presents_the_client_host_and_fails_verification() {
    let tls = TlsEndpoints::start();
    let with_authority = tls.yaml("allow_tls_without_sni: true");
    let yaml = with_authority.replace("            http:\n              authority: { from: endpoint }\n", "");
    assert_ne!(
        yaml, with_authority,
        "test setup: the endpoint authority should have been removed"
    );
    let config = Config::from_yaml(&yaml).expect("config without the endpoint authority should parse");
    let proxy = praxis_test_utils::start_proxy(&config);

    let (status, _) = http_get(proxy.addr(), "/", Some(CLIENT_HOST));
    assert_eq!(
        status, 502,
        "without the endpoint authority the client Host becomes the SNI and fails verification"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// The example config running against two tagged header-echo backends.
struct ExampleProxy {
    /// Answers for the example's `localhost:9000` endpoint.
    first: BackendGuard,

    /// Answers for the example's `127.0.0.1:9001` endpoint.
    second: BackendGuard,

    /// The running proxy.
    proxy: ProxyGuard,
}

impl ExampleProxy {
    /// Load the example with test ports, keeping `localhost` as a hostname
    /// so the derived authority is visibly the endpoint as written.
    fn start() -> Self {
        let first = start_tagged_header_echo_backend("first");
        let second = start_tagged_header_echo_backend("second");
        let path = example_config_path("traffic-management/authority-from-endpoint.yaml");
        let yaml = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {path}: {e}"))
            .replace("localhost:9000", &format!("localhost:{}", first.port()))
            .replace("127.0.0.1:9001", &format!("127.0.0.1:{}", second.port()))
            .replace("0.0.0.0:8080", &format!("127.0.0.1:{}", free_port()));
        let config = Config::from_yaml(&yaml).expect("authority-from-endpoint example should parse");
        let proxy = praxis_test_utils::start_proxy(&config);
        Self { first, second, proxy }
    }

    /// The `Host` each backend tag should receive.
    fn expected_hosts(&self) -> BTreeMap<String, String> {
        BTreeMap::from([
            ("first".to_owned(), format!("localhost:{}", self.first.port())),
            ("second".to_owned(), format!("127.0.0.1:{}", self.second.port())),
        ])
    }

    /// Send four requests through `get` and map each answering backend's tag
    /// to the `Host` it received, failing on any request whose backend saw a
    /// different `Host` than an earlier request to the same backend.
    fn hosts_by_backend<F>(&self, get: F) -> BTreeMap<String, String>
    where
        F: Fn(&str, &str) -> (u16, String),
    {
        let mut hosts = BTreeMap::new();
        for i in 0..4 {
            let (status, body) = get(self.proxy.addr(), &format!("/req-{i}"));
            assert_eq!(status, 200, "request {i} should succeed; got {body}");
            let (tag, host) = tag_and_host(&body);
            let previous = hosts.insert(tag.clone(), host.clone());
            assert!(
                previous.is_none_or(|seen| seen == host),
                "request {i}: backend {tag} saw a different Host than before: {host}"
            );
        }
        hosts
    }
}

/// Two TLS backends whose certificates each name only their own endpoint.
struct TlsEndpoints {
    /// Certificates for the first endpoint; also holds the combined CA file.
    alpha_certs: TestCertificates,

    /// Port of the first endpoint's backend.
    alpha_port: u16,

    /// Port of the second endpoint's backend.
    beta_port: u16,
}

impl TlsEndpoints {
    /// Start both backends and resolve both hostnames to loopback.
    fn start() -> Self {
        let alpha_certs = TestCertificates::generate_dns_only(ALPHA_HOST);
        let beta_certs = TestCertificates::generate_dns_only(BETA_HOST);
        let alpha_port = start_tls_backend(&alpha_certs, "alpha");
        let beta_port = start_tls_backend(&beta_certs, "beta");
        for host in [ALPHA_HOST, BETA_HOST] {
            seed_dns(host, &[IpAddr::from([127, 0, 0, 1])]);
        }
        let both_cas = [&alpha_certs.ca_cert_path, &beta_certs.ca_cert_path]
            .iter()
            .map(|path| std::fs::read_to_string(path).expect("read test CA"))
            .collect::<String>();
        std::fs::write(combined_ca_path(&alpha_certs), both_cas).expect("write combined CA");
        Self {
            alpha_certs,
            alpha_port,
            beta_port,
        }
    }

    /// A proxy config for both endpoints with the endpoint authority, verify
    /// on, no `tls.sni`, and `extra_insecure` added to `insecure_options`.
    fn yaml(&self, extra_insecure: &str) -> String {
        format!(
            r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "{ALPHA_HOST}:{alpha_port}"
              - "{BETA_HOST}:{beta_port}"
            http:
              authority: {{ from: endpoint }}
            tls:
              ca:
                ca_path: "{ca}"
insecure_options:
  allow_private_endpoints: true
  allow_private_upstreams: true
  {extra_insecure}
"#,
            proxy_port = free_port(),
            alpha_port = self.alpha_port,
            beta_port = self.beta_port,
            ca = combined_ca_path(&self.alpha_certs).display(),
        )
    }
}

/// Where the combined CA bundle for both endpoints lives.
fn combined_ca_path(alpha_certs: &TestCertificates) -> std::path::PathBuf {
    alpha_certs.ca_cert_path.with_file_name("both-ca.pem")
}

/// Split a tagged header-echo body into the backend tag and the `Host` it saw.
fn tag_and_host(body: &str) -> (String, String) {
    let mut lines = body.lines();
    let tag = lines.next().unwrap_or_default().to_owned();
    let host = lines
        .find_map(|line| {
            line.split_once(':')
                .filter(|(name, _)| name.eq_ignore_ascii_case("host"))
                .map(|(_, value)| value.trim().to_owned())
        })
        .unwrap_or_else(|| panic!("backend {tag} saw no Host header; got:\n{body}"));
    assert_ne!(host, CLIENT_HOST, "the client Host must not reach backend {tag}");
    (tag, host)
}
