// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! `cargo xtask echo` — quick HTTP test server.

use clap::Parser;
use praxis_core::config::{
    AdminConfig, BodyLimitsConfig, Config, FailureMode, FilterChainConfig, FilterEntry, InsecureOptions, Listener,
    ProtocolKind, RuntimeConfig,
};

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
    praxis::run_server(config, None)
}

// -----------------------------------------------------------------------------
// Config Builder
// -----------------------------------------------------------------------------

/// Build a [`Config`] with a single `static_response` filter chain.
///
/// [`Config`]: praxis_core::config::Config
fn build_config(args: &Args) -> Config {
    let entry = build_static_response_entry(args);
    Config {
        admin: AdminConfig::default(),
        body_limits: BodyLimitsConfig::default(),
        clusters: vec![],
        filter_chains: vec![FilterChainConfig {
            name: "echo".into(),
            filters: vec![entry],
        }],
        insecure_options: InsecureOptions::default(),
        listeners: vec![echo_listener(&args.address)],
        runtime: RuntimeConfig::default(),
        shutdown_timeout_secs: 30,
    }
}

/// Build the echo listener bound to `address`.
fn echo_listener(address: &str) -> Listener {
    Listener {
        address: address.into(),
        cluster: None,
        downstream_read_timeout_ms: None,
        filter_chains: vec!["echo".into()],
        max_connections: None,
        name: "echo".into(),
        protocol: ProtocolKind::default(),
        tcp_idle_timeout_ms: None,
        tcp_max_duration_secs: None,
        tls: None,
        upstream: None,
    }
}

/// Build a `static_response` filter entry from CLI args.
fn build_static_response_entry(args: &Args) -> FilterEntry {
    let mut headers = vec![
        header_value("Content-Type", &args.content_type),
        header_value("Server", "praxis-echo"),
    ];
    for h in &args.headers {
        let (name, value) = parse_header(h).unwrap_or_else(|err| {
            tracing::error!("{err}");
            std::process::exit(1);
        });
        headers.push(header_value(name, value));
    }

    let mut filter_config = serde_yaml::Mapping::new();
    filter_config.insert("filter".into(), "static_response".into());
    filter_config.insert("status".into(), args.status.into());
    filter_config.insert("headers".into(), serde_yaml::Value::Sequence(headers));
    filter_config.insert("body".into(), args.body.clone().into());

    FilterEntry {
        branch_chains: None,
        filter_type: "static_response".into(),
        conditions: vec![],
        config: serde_yaml::Value::Mapping(filter_config),
        failure_mode: FailureMode::default(),
        name: None,
        response_conditions: vec![],
    }
}

/// Build a YAML mapping with `name` and `value` keys.
///
/// # Examples
///
/// ```rust,ignore
/// let val = header_value("Content-Type", "text/html");
/// let map = val.as_mapping().unwrap();
/// assert_eq!(map.get("name").unwrap().as_str(), Some("Content-Type"));
/// assert_eq!(map.get("value").unwrap().as_str(), Some("text/html"));
/// ```
fn header_value(name: &str, value: &str) -> serde_yaml::Value {
    let mut m = serde_yaml::Mapping::new();
    m.insert("name".into(), name.into());
    m.insert("value".into(), value.into());
    serde_yaml::Value::Mapping(m)
}

/// Split a `"Name: value"` string into its trimmed parts.
///
/// Returns an error if the input does not contain a colon separator.
///
/// # Examples
///
/// ```rust,ignore
/// let (name, value) = parse_header("X-Custom: hello").unwrap();
/// assert_eq!(name, "X-Custom");
/// assert_eq!(value, "hello");
///
/// assert!(parse_header("no-colon").is_err());
/// ```
fn parse_header(s: &str) -> Result<(&str, &str), String> {
    let (name, value) = s
        .split_once(':')
        .ok_or_else(|| format!("invalid header format: {s} (expected \"Name: value\")"))?;
    Ok((name.trim(), value.trim()))
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::redundant_closure_for_method_calls,
    reason = "tests"
)]
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
        let (name, value) = parse_header("X-Custom: hello world").expect("valid header");
        assert_eq!(name, "X-Custom", "header name should be trimmed");
        assert_eq!(value, "hello world", "header value should be trimmed");
    }

    #[test]
    fn parse_header_trims_whitespace() {
        let (name, value) = parse_header("  Key  :  Value  ").expect("valid header");
        assert_eq!(name, "Key", "name should be trimmed");
        assert_eq!(value, "Value", "value should be trimmed");
    }

    #[test]
    fn parse_header_rejects_missing_colon() {
        let result = parse_header("no-colon-here");
        assert!(result.is_err(), "should fail without a colon separator");
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

        let filter = &config.filter_chains[0].filters[0];
        let fc = filter.config.as_mapping().expect("filter config should be a mapping");

        assert_eq!(
            fc.get("status").and_then(|v| v.as_u64()),
            Some(201),
            "status code should match args"
        );
        assert_eq!(
            fc.get("body").and_then(|v| v.as_str()),
            Some("hello"),
            "body should match args"
        );

        let headers = fc
            .get("headers")
            .and_then(|v| v.as_sequence())
            .expect("headers should be a sequence");
        let ct = headers[0].as_mapping().expect("first header should be a mapping");
        assert_eq!(
            ct.get("name").and_then(|v| v.as_str()),
            Some("Content-Type"),
            "first header name should be Content-Type"
        );
        assert_eq!(
            ct.get("value").and_then(|v| v.as_str()),
            Some("text/plain"),
            "content-type value should match args"
        );

        let custom = headers[2].as_mapping().expect("custom header should be a mapping");
        assert_eq!(
            custom.get("name").and_then(|v| v.as_str()),
            Some("X-Foo"),
            "custom header name should match"
        );
        assert_eq!(
            custom.get("value").and_then(|v| v.as_str()),
            Some("bar"),
            "custom header value should match"
        );
    }
}
