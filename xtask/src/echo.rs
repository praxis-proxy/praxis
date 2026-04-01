//! `cargo xtask echo` — quick HTTP test server.
//!
//! Returns a configurable static response to every request.

use clap::Parser;
use praxis_core::config::{Config, FilterChainConfig, Listener, PipelineEntry, RuntimeConfig};

// -----------------------------------------------------------------------------
// CLI Arguments
// -----------------------------------------------------------------------------

/// CLI arguments for `cargo xtask echo`.
#[derive(Parser)]
pub struct Args {
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
pub fn run(mut args: Args) {
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

    let entry = PipelineEntry {
        filter: "static_response".to_owned(),
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
#[allow(clippy::print_stderr)]
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
