//! HTTP backends for integration testing.
//!
//! Two flavors:
//!
//! - **Praxis-powered** ([`Backend`], [`RoutedBackend`]) start a Praxis server with `static_response` filters.
//! - **Raw TCP** ([`start_echo_backend`], [`start_header_echo_backend`], [`start_slow_backend`])

use std::{
    io::{Read, Write},
    net::TcpStream,
    sync::Arc,
    time::Duration,
};

use praxis_core::config::{Cluster, Config, Endpoint, FilterChainConfig, FilterEntry, Listener, Route, RuntimeConfig};

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
    pub fn start(self) -> u16 {
        let status = self.status;
        let reason = reason_phrase(status);
        let body = self.body;
        let headers = self.headers;

        spawn_tcp_server(move |mut stream| {
            stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let _ = read_until_headers_complete(&mut stream);

            let mut resp = format!(
                "HTTP/1.1 {status} {reason}\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\
                 Server: praxis-test-backend\r\n",
                body.len()
            );
            for (name, value) in &headers {
                use std::fmt::Write;
                let _ = write!(resp, "{name}: {value}\r\n");
            }
            resp.push_str("\r\n");
            resp.push_str(&body);
            let _ = stream.write_all(resp.as_bytes());
        })
    }
}

// -----------------------------------------------------------------------------
// RoutedBackend
// -----------------------------------------------------------------------------

/// Builder for a route-based mock backend.
pub struct RoutedBackend {
    /// Route entries in match order.
    routes: Vec<RoutedEntry>,
}

/// A single route entry for a [`RoutedBackend`], mapping a
/// path prefix to a fixed response.
///
/// [`RoutedBackend`]: crate::backend::RoutedBackend
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

impl Default for RoutedBackend {
    fn default() -> Self {
        Self::new()
    }
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
// Test Utilities
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

/// Spawn a raw TCP server that calls `handler` in a new
/// thread for each accepted connection. Returns the port.
fn spawn_tcp_server(handler: impl Fn(TcpStream) + Send + Clone + 'static) -> u16 {
    let (listener, port) = crate::network::bind_unique_port();

    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let handler = handler.clone();
            std::thread::spawn(move || handler(stream));
        }
    });

    port
}

/// Start a mock backend that echoes the request body back
/// as the response body.
pub fn start_echo_backend() -> u16 {
    spawn_tcp_server(|mut stream| {
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let body = read_request_body(&mut stream);
        let _ = write_http_response(&mut stream, &body);
    })
}

/// Start a backend that echoes request headers as the
/// response body (one per line).
pub fn start_header_echo_backend() -> u16 {
    spawn_tcp_server(|mut stream| {
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let raw = read_until_headers_complete(&mut stream);

        let headers: String = raw
            .lines()
            .skip(1)
            .take_while(|l| !l.is_empty())
            .fold(String::new(), |mut acc, line| {
                if !acc.is_empty() {
                    acc.push('\n');
                }
                acc.push_str(line);
                acc
            });

        let _ = write_http_response(&mut stream, &headers);
    })
}

/// Start a backend that includes hop-by-hop headers in its
/// responses. Used to verify the proxy strips them before
/// forwarding to the client.
pub fn start_hop_by_hop_response_backend() -> u16 {
    spawn_tcp_server(|mut stream| {
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let _ = read_until_headers_complete(&mut stream);

        let body = "hop-by-hop-test";
        let response = format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Length: {}\r\n\
             Connection: X-Internal-Token\r\n\
             Keep-Alive: timeout=300\r\n\
             Upgrade: websocket\r\n\
             Proxy-Authenticate: Basic realm=\"test\"\r\n\
             Trailer: X-Checksum\r\n\
             X-Internal-Token: secret-value\r\n\
             X-Safe-Header: visible\r\n\
             Server: test-backend\r\n\
             \r\n\
             {body}",
            body.len()
        );
        let _ = stream.write_all(response.as_bytes());
    })
}

/// Start a backend that waits `delay` before responding.
pub fn start_slow_backend(body: &str, delay: Duration) -> u16 {
    let body = body.to_owned();
    spawn_tcp_server(move |mut stream| {
        let mut buf = [0u8; 4096];
        let _ = stream.read(&mut buf);
        std::thread::sleep(delay);
        let _ = write_http_response(&mut stream, &body);
    })
}

/// Read from a TCP stream until the HTTP header terminator
/// (`\r\n\r\n`) is received. Returns the raw request as a
/// string. Prevents partial-read flakiness under load.
fn read_until_headers_complete(stream: &mut TcpStream) -> String {
    let mut data = Vec::new();
    let mut buf = [0u8; 4096];

    loop {
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => data.extend_from_slice(&buf[..n]),
        }
        if data.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }

    String::from_utf8_lossy(&data).into_owned()
}

/// Read a complete HTTP request body from a raw TCP stream,
/// using Content-Length to determine when all bytes have arrived.
fn read_request_body(stream: &mut TcpStream) -> String {
    let mut data = Vec::new();
    let mut buf = [0u8; 4096];

    loop {
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => data.extend_from_slice(&buf[..n]),
        }

        let raw = String::from_utf8_lossy(&data);
        if let Some(header_section) = raw.split("\r\n\r\n").next() {
            let content_length = parse_content_length(header_section);
            let header_len = header_section.len() + 4;
            if data.len() >= header_len + content_length {
                break;
            }
        }
    }

    let raw = String::from_utf8_lossy(&data);
    raw.split("\r\n\r\n").nth(1).unwrap_or("").to_owned()
}

/// Extract Content-Length from raw HTTP headers.
fn parse_content_length(headers: &str) -> usize {
    headers
        .lines()
        .find(|l| l.to_lowercase().starts_with("content-length:"))
        .and_then(|l| l.split_once(':').map(|(_, v)| v))
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0)
}

/// Write a minimal HTTP 200 response with the given body.
fn write_http_response(stream: &mut TcpStream, body: &str) -> std::io::Result<()> {
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes())
}

/// Build a [`Config`] with conditional `static_response`
/// filters for each route, plus a router and dummy clusters.
///
/// [`Config`]: praxis_core::config::Config
fn build_routed_config(address: &str, routes: &[RoutedEntry]) -> Config {
    let mut route_configs = Vec::new();
    let mut cluster_configs = Vec::new();
    let mut chain_filters = Vec::new();

    for (i, entry) in routes.iter().enumerate() {
        let cluster_name = format!("route-{i}");
        let (route, cluster, filter) = build_route_entry(entry, &cluster_name);
        route_configs.push(route);
        cluster_configs.push(cluster);
        chain_filters.push(filter);
    }

    build_config(address, cluster_configs, chain_filters, route_configs)
}

/// Build a single route/cluster/filter tuple from a [`RoutedEntry`].
fn build_route_entry(entry: &RoutedEntry, cluster_name: &str) -> (Route, Cluster, FilterEntry) {
    let mut headers = vec![header_value("Server", "praxis-test-backend")];
    for (k, v) in &entry.headers {
        headers.push(header_value(k, v));
    }

    let route = Route {
        path_prefix: entry.path_prefix.clone(),
        host: None,
        headers: None,
        cluster: Arc::from(cluster_name),
    };

    let cluster = Cluster {
        name: Arc::from(cluster_name),
        endpoints: vec![Endpoint::Simple("127.0.0.1:1".to_owned())],
        connection_timeout_ms: None,
        idle_timeout_ms: None,
        load_balancer_strategy: Default::default(),
        read_timeout_ms: None,
        total_connection_timeout_ms: None,
        upstream_sni: None,
        upstream_tls: false,
        write_timeout_ms: None,
        health_check: None,
    };

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

    let filter = FilterEntry {
        filter_type: "static_response".to_owned(),
        conditions,
        response_conditions: vec![],
        config: serde_yaml::Value::Mapping(filter_config),
    };

    (route, cluster, filter)
}

/// Assemble a [`Config`] from parts.
fn build_config(address: &str, clusters: Vec<Cluster>, filters: Vec<FilterEntry>, routes: Vec<Route>) -> Config {
    Config {
        admin_address: None,
        clusters,
        filter_chains: vec![FilterChainConfig {
            name: "backend".to_owned(),
            filters,
        }],
        listeners: vec![Listener {
            name: "backend".to_owned(),
            address: address.to_owned(),
            protocol: Default::default(),
            tls: None,
            upstream: None,
            filter_chains: vec!["backend".to_owned()],
            tcp_idle_timeout_ms: None,
            downstream_read_timeout_ms: None,
        }],
        pipeline: vec![],
        routes,
        runtime: RuntimeConfig::default(),
        max_request_body_bytes: None,
        max_response_body_bytes: None,
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
    let port = crate::network::free_port();
    let addr = format!("127.0.0.1:{port}");

    for l in &mut config.listeners {
        if l.address == "127.0.0.1:0" {
            l.address.clone_from(&addr);
        }
    }

    std::thread::spawn(move || {
        praxis::run_server(config);
    });

    crate::network::wait_for_http(&addr);
    port
}

/// Start a mock HTTP backend returning a fixed body.
pub fn start_backend(body: &str) -> u16 {
    Backend::fixed(body).start()
}
