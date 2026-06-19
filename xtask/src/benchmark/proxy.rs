// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Proxy configuration builders and Docker image management for benchmark runs.

use benchmarks::proxy::{EnvoyConfig, HaproxyConfig, NginxConfig, PraxisConfig, ProxyConfig};

use super::cli::Args;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Docker image tag used when building Praxis for benchmarks.
const PRAXIS_BENCH_IMAGE: &str = "praxis-bench:latest";

// -----------------------------------------------------------------------------
// Docker Build
// -----------------------------------------------------------------------------

/// Build the Praxis Docker image from the repo root
/// Containerfile. Returns the image tag.
pub(crate) fn build_praxis_image() -> String {
    let status = std::process::Command::new("docker")
        .args(["build", "-t", PRAXIS_BENCH_IMAGE, "-f", "Containerfile", "."])
        .status();

    match status {
        Ok(s) if s.success() => PRAXIS_BENCH_IMAGE.into(),
        Ok(s) => {
            eprintln!("error: docker build failed (exit {})", s.code().unwrap_or(-1));
            std::process::exit(1);
        },
        Err(e) => {
            eprintln!("error: failed to run docker build: {e}");
            std::process::exit(1);
        },
    }
}

// -----------------------------------------------------------------------------
// Proxy Config Factory
// -----------------------------------------------------------------------------

/// Build a boxed [`ProxyConfig`] for the named proxy.
///
/// All proxies run containerized with identical resource constraints.
///
/// [`ProxyConfig`]: benchmarks::proxy::ProxyConfig
pub(crate) fn build_proxy_config(name: &str, args: &Args, praxis_image: &str) -> Box<dyn ProxyConfig> {
    match name {
        "praxis" => Box::new(PraxisConfig::new(praxis_image.to_owned())),
        "envoy" => Box::new(EnvoyConfig {
            image: Some(args.envoy_image.clone()),
            ..Default::default()
        }),
        "nginx" => Box::new(NginxConfig {
            image: Some(args.nginx_image.clone()),
            ..Default::default()
        }),
        "haproxy" => Box::new(HaproxyConfig {
            image: Some(args.haproxy_image.clone()),
            ..Default::default()
        }),
        other => {
            tracing::error!(proxy = other, "unknown proxy");
            std::process::exit(1);
        },
    }
}
