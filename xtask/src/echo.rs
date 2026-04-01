//! `cargo xtask echo` — quick HTTP test server.

use clap::Parser;
use praxis_core::config::{Config, FilterChainConfig, FilterEntry, Listener, RuntimeConfig};

// -----------------------------------------------------------------------------
// CLI Arguments
// -----------------------------------------------------------------------------

/// CLI arguments for `cargo xtask echo`.
#[derive(Parser)]
pub(crate) struct Args {
    /// Listen address.
    #[arg(long, default_value = "127.0.0.1:8080")]
    address: String,

    /// HTTP response status code.
    #[arg(long, default_value_t = 200)]
    status: u16,

    /// Content-Type header value.
    #[arg(long, default_value = "application/json")]
    content_type: String,

    /// Response body string.
    #[arg(long, default_value = r#"{"status": "ok"}"#)]
    body: String,

    /// Additional response header (repeatable).
    /// Format: "Name: value"
    #[arg(long = "header", value_name = "NAME: VALUE")]
    headers: Vec<String>,
}

// -----------------------------------------------------------------------------
// Entry Point
// -----------------------------------------------------------------------------

/// Start a static-response HTTP server with the given args.
pub(crate) fn run(mut args: Args) {
    crate::init_tracing("info");
    args.address = crate::port::resolve_available(&args.address);

    let config = build_config(&args);
    praxis::run_server(config)
}

// -----------------------------------------------------------------------------
// Config Builder
// -----------------------------------------------------------------------------

/// Build a [`Config`] with a single `static_response` filter chain.
fn build_config(args: &Args) -> Config {
    let mut headers = vec![
        header_value("Content-Type", &args.content_type),
        header_value("Server", "praxis-echo"),
    ];
    for h in &args.headers {
        let (name, value) = parse_header(h);
        headers.push(header_value(name, value));
    }

    let mut filter_config = serde_yaml::Mapping::new();
    filter_config.insert("filter".into(), "static_response".into());
    filter_config.insert("status".into(), args.status.into());
    filter_config.insert("headers".into(), serde_yaml::Value::Sequence(headers));
    filter_config.insert("body".into(), args.body.clone().into());

    let entry = FilterEntry {
        filter_type: "static_response".to_owned(),
        conditions: vec![],
        response_conditions: vec![],
        config: serde_yaml::Value::Mapping(filter_config),
    };

    Config {
        admin_address: None,
        clusters: vec![],
        filter_chains: vec![FilterChainConfig {
            name: "echo".to_owned(),
            filters: vec![entry],
        }],
        listeners: vec![Listener {
            name: "echo".to_owned(),
            address: args.address.clone(),
            protocol: Default::default(),
            tls: None,
            upstream: None,
            filter_chains: vec!["echo".to_owned()],
            tcp_idle_timeout_ms: None,
            downstream_read_timeout_ms: None,
        }],
        pipeline: vec![],
        routes: vec![],
        runtime: RuntimeConfig::default(),
        max_request_body_bytes: None,
        max_response_body_bytes: None,
        shutdown_timeout_secs: 30,
    }
}

/// Build a YAML mapping with `name` and `value` keys.
fn header_value(name: &str, value: &str) -> serde_yaml::Value {
    let mut m = serde_yaml::Mapping::new();
    m.insert("name".into(), name.into());
    m.insert("value".into(), value.into());
    serde_yaml::Value::Mapping(m)
}

/// Split a `"Name: value"` string into its trimmed parts.
fn parse_header(s: &str) -> (&str, &str) {
    let (name, value) = s.split_once(':').unwrap_or_else(|| {
        eprintln!(
            "invalid header format: {s} \
             (expected \"Name: value\")"
        );
        std::process::exit(1);
    });
    (name.trim(), value.trim())
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_value_builds_mapping() {
        let val = header_value("Content-Type", "text/html");
        let map = val.as_mapping().expect("should be a YAML mapping");
        assert_eq!(
            map.get("name").and_then(|v| v.as_str()),
            Some("Content-Type"),
            "name key should match"
        );
        assert_eq!(
            map.get("value").and_then(|v| v.as_str()),
            Some("text/html"),
            "value key should match"
        );
    }

    #[test]
    fn parse_header_splits_name_and_value() {
        let (name, value) = parse_header("X-Custom: hello world");
        assert_eq!(name, "X-Custom", "header name should be trimmed");
        assert_eq!(value, "hello world", "header value should be trimmed");
    }

    #[test]
    fn parse_header_trims_whitespace() {
        let (name, value) = parse_header("  Key  :  Value  ");
        assert_eq!(name, "Key", "name should be trimmed");
        assert_eq!(value, "Value", "value should be trimmed");
    }

    #[test]
    fn build_config_has_one_listener() {
        let args = Args {
            address: "127.0.0.1:8080".into(),
            status: 200,
            content_type: "application/json".into(),
            body: r#"{"ok":true}"#.into(),
            headers: vec![],
        };
        let config = build_config(&args);
        assert_eq!(config.listeners.len(), 1, "should have exactly one listener");
        assert_eq!(
            config.listeners[0].address, "127.0.0.1:8080",
            "listener address should match"
        );
    }

    #[test]
    fn build_config_includes_custom_headers() {
        let args = Args {
            address: "127.0.0.1:8080".into(),
            status: 201,
            content_type: "text/plain".into(),
            body: "hello".into(),
            headers: vec!["X-Foo: bar".into()],
        };
        let config = build_config(&args);
        assert_eq!(config.filter_chains.len(), 1, "should have one filter chain");
        assert_eq!(
            config.filter_chains[0].name, "echo",
            "filter chain should be named 'echo'"
        );
    }
}
