// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Simple fixed-response and routed backends.

use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    time::Duration,
};

use praxis_core::config::{
    AdminConfig, BodyLimitsConfig, Cluster, Config, Endpoint, FailureMode, FilterChainConfig, FilterEntry,
    InsecureOptions, Listener, ProtocolKind, RuntimeConfig,
};

use super::specialized::{BackendGuard, read_until_headers_complete, spawn_tcp_server, spawn_tcp_server_with_shutdown};

// -----------------------------------------------------------------------------
// Backend
// -----------------------------------------------------------------------------

/// A HTTP backend for testing.
pub struct Backend {
    /// HTTP status code to return.
    status: u16,

    /// Response body content.
    body: String,

    /// Extra response headers as `(name, value)` pairs.
    headers: Vec<(String, String)>,
}

impl Backend {
    /// Create a backend returning a fixed 200 response.
    pub fn fixed(body: &str) -> Self {
        Self {
            status: 200,
            body: body.to_owned(),
            headers: Vec::new(),
        }
    }

    /// Create a backend returning a custom status and body.
    pub fn status(code: u16, body: &str) -> Self {
        Self {
            status: code,
            body: body.to_owned(),
            headers: Vec::new(),
        }
    }

    /// Add a response header.
    #[must_use]
    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }

    /// Start the backend and return the port.
    ///
    /// # Panics
    ///
    /// Panics if the server fails to bind or accept connections.
    pub fn start(self) -> u16 {
        let status = self.status;
        let reason = reason_phrase(status);
        let body = self.body;
        let headers = self.headers;

        spawn_tcp_server(move |mut stream| {
            stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let _headers = read_until_headers_complete(&mut stream);

            let mut resp = format!(
                "HTTP/1.1 {status} {reason}\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\
                 Server: praxis-test-backend\r\n",
                body.len()
            );
            for (name, value) in &headers {
                use std::fmt::Write;
                let _written = write!(resp, "{name}: {value}\r\n");
            }
            resp.push_str("\r\n");
            resp.push_str(&body);
            let _sent = stream.write_all(resp.as_bytes());
        })
    }

    /// Start the backend and return a [`BackendGuard`] that
    /// shuts down the listener thread when dropped.
    ///
    /// # Panics
    ///
    /// Panics if the server fails to bind.
    pub fn start_with_shutdown(self) -> BackendGuard {
        let status = self.status;
        let reason = reason_phrase(status);
        let body = self.body;
        let headers = self.headers;

        spawn_tcp_server_with_shutdown(move |mut stream| {
            stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let _headers = read_until_headers_complete(&mut stream);

            let mut resp = format!(
                "HTTP/1.1 {status} {reason}\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\
                 Server: praxis-test-backend\r\n",
                body.len()
            );
            for (name, value) in &headers {
                use std::fmt::Write;
                let _written = write!(resp, "{name}: {value}\r\n");
            }
            resp.push_str("\r\n");
            resp.push_str(&body);
            let _sent = stream.write_all(resp.as_bytes());
        })
    }
}

// -----------------------------------------------------------------------------
// RoutedBackend
// -----------------------------------------------------------------------------

/// Builder for a route-based mock backend.
#[derive(Default)]
pub struct RoutedBackend {
    /// Route entries in match order.
    routes: Vec<RoutedEntry>,
}

/// A single route entry for a [`RoutedBackend`], mapping a
/// path prefix to a fixed response.
///
/// [`RoutedBackend`]: crate::net::backend::RoutedBackend
struct RoutedEntry {
    /// URL path prefix to match (e.g. `"/api"`).
    path_prefix: String,

    /// HTTP status code to return.
    status: u16,

    /// Response body content.
    body: String,

    /// Extra response headers as `(name, value)` pairs.
    headers: Vec<(String, String)>,
}

impl RoutedBackend {
    /// Create a new routed backend builder.
    pub fn new() -> Self {
        Self { routes: vec![] }
    }

    /// Add a route returning a fixed response.
    #[must_use]
    pub fn route(mut self, path_prefix: &str, status: u16, body: &str) -> Self {
        self.routes.push(RoutedEntry {
            path_prefix: path_prefix.to_owned(),
            status,
            body: body.to_owned(),
            headers: Vec::new(),
        });
        self
    }

    /// Add a route with custom response headers.
    #[must_use]
    pub fn route_with_headers(
        mut self,
        path_prefix: &str,
        status: u16,
        body: &str,
        headers: Vec<(&str, &str)>,
    ) -> Self {
        self.routes.push(RoutedEntry {
            path_prefix: path_prefix.to_owned(),
            status,
            body: body.to_owned(),
            headers: headers.into_iter().map(|(k, v)| (k.to_owned(), v.to_owned())).collect(),
        });
        self
    }

    /// Start the backend and return the port.
    pub fn start(self) -> u16 {
        let config = build_routed_config("127.0.0.1:0", &self.routes);
        start_server(config)
    }
}

// -----------------------------------------------------------------------------
// IPv6 Backend
// -----------------------------------------------------------------------------

/// Spawn a raw TCP backend on `[::1]` that returns a fixed
/// HTTP response body. Returns the port.
///
/// # Panics
///
/// Panics if binding to `[::1]:0` fails.
pub fn start_backend_v6(body: &str) -> u16 {
    let listener = TcpListener::bind("[::1]:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let body = body.to_owned();

    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let body = body.clone();
            std::thread::spawn(move || {
                handle_v6_connection(stream, &body);
            });
        }
    });

    port
}

/// Handle a single IPv6 TCP connection: read request headers,
/// write a minimal HTTP 200 response.
fn handle_v6_connection(mut stream: TcpStream, body: &str) {
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    let mut buf = [0u8; 4096];
    let _bytes = stream.read(&mut buf);
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _sent = stream.write_all(response.as_bytes());
}

/// Start a mock HTTP backend returning a fixed body.
pub fn start_backend(body: &str) -> u16 {
    Backend::fixed(body).start()
}

/// Start a mock HTTP backend returning a fixed body,
/// with a [`BackendGuard`] that shuts down the listener
/// thread when dropped.
pub fn start_backend_with_shutdown(body: &str) -> BackendGuard {
    Backend::fixed(body).start_with_shutdown()
}

// -----------------------------------------------------------------------------
// Config Builders
// -----------------------------------------------------------------------------

/// Map an HTTP status code to its reason phrase.
fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        413 => "Content Too Large",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "Unknown",
    }
}

/// Build a [`Config`] with conditional `static_response`
/// filters for each route, plus dummy clusters.
///
/// [`Config`]: praxis_core::config::Config
fn build_routed_config(address: &str, routes: &[RoutedEntry]) -> Config {
    let mut cluster_configs = Vec::new();
    let mut chain_filters = Vec::new();

    for (i, entry) in routes.iter().enumerate() {
        let cluster_name = format!("route-{i}");
        let (cluster, filter) = build_route_entry(entry, &cluster_name);
        cluster_configs.push(cluster);
        chain_filters.push(filter);
    }

    build_config(address, cluster_configs, chain_filters)
}

/// Build a cluster/filter pair from a [`RoutedEntry`].
fn build_route_entry(entry: &RoutedEntry, cluster_name: &str) -> (Cluster, FilterEntry) {
    let cluster = build_dummy_cluster(cluster_name);
    let filter = build_static_response_filter(entry);
    (cluster, filter)
}

/// Build a dummy cluster pointing at a placeholder address.
fn build_dummy_cluster(cluster_name: &str) -> Cluster {
    Cluster::with_defaults(cluster_name, vec![Endpoint::Simple("127.0.0.1:1".to_owned())])
}

/// Build a `static_response` filter entry from a [`RoutedEntry`].
fn build_static_response_filter(entry: &RoutedEntry) -> FilterEntry {
    let mut headers = vec![header_value("Server", "praxis-test-backend")];
    for (k, v) in &entry.headers {
        headers.push(header_value(k, v));
    }

    let conditions = if entry.path_prefix == "/" {
        vec![]
    } else {
        let mut cond = serde_yaml::Mapping::new();
        let mut when = serde_yaml::Mapping::new();
        when.insert("path_prefix".into(), entry.path_prefix.clone().into());
        cond.insert("when".into(), serde_yaml::Value::Mapping(when));
        vec![serde_yaml::from_value(serde_yaml::Value::Mapping(cond)).expect("valid condition")]
    };

    let mut filter_config = serde_yaml::Mapping::new();
    filter_config.insert("filter".into(), "static_response".into());
    filter_config.insert("status".into(), entry.status.into());
    filter_config.insert("headers".into(), serde_yaml::Value::Sequence(headers));
    filter_config.insert("body".into(), entry.body.clone().into());

    FilterEntry {
        branch_chains: None,
        filter_type: "static_response".to_owned(),
        conditions,
        config: serde_yaml::Value::Mapping(filter_config),
        failure_mode: FailureMode::default(),
        name: None,
        response_conditions: vec![],
    }
}

/// Assemble a [`Config`] from parts.
fn build_config(address: &str, clusters: Vec<Cluster>, filters: Vec<FilterEntry>) -> Config {
    Config {
        admin: AdminConfig::default(),
        body_limits: BodyLimitsConfig::default(),
        clusters,
        filter_chains: vec![FilterChainConfig {
            name: "backend".to_owned(),
            filters,
        }],
        insecure_options: InsecureOptions::default(),
        listeners: vec![Listener {
            address: address.to_owned(),
            cluster: None,
            downstream_read_timeout_ms: None,
            filter_chains: vec!["backend".to_owned()],
            max_connections: None,
            name: "backend".to_owned(),
            protocol: ProtocolKind::default(),
            tcp_idle_timeout_ms: None,
            tcp_max_duration_secs: None,
            tls: None,
            upstream: None,
        }],
        runtime: RuntimeConfig::default(),
        shutdown_timeout_secs: 5,
    }
}

/// Build a YAML header mapping with `name` and `value` keys.
fn header_value(name: &str, value: &str) -> serde_yaml::Value {
    let mut m = serde_yaml::Mapping::new();
    m.insert("name".into(), name.into());
    m.insert("value".into(), value.into());
    serde_yaml::Value::Mapping(m)
}

/// Start a Praxis server in a background thread and return the port it bound to.
fn start_server(mut config: Config) -> u16 {
    let port = crate::net::port::free_port();
    let addr = format!("127.0.0.1:{port}");

    for l in &mut config.listeners {
        if l.address == "127.0.0.1:0" {
            l.address.clone_from(&addr);
        }
    }

    std::thread::spawn(move || {
        praxis::run_server(config);
    });

    crate::net::wait::wait_for_http(&addr);
    port
}
