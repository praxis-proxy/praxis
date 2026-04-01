// SPDX-License-Identifier: LGPL-3.0-only
// Copyright (c) 2024 Shane Utt

//! Proxy configuration builders and Docker image management for benchmark runs.

use benchmarks::proxy::{EnvoyConfig, HaproxyConfig, NginxConfig, PraxisConfig, ProxyConfig};
use tempfile::TempDir;

use super::cli::Args;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Docker image tag used when building Praxis for comparison benchmarks.
const PRAXIS_BENCH_IMAGE: &str = "praxis-bench:latest";

/// Embedded local Praxis benchmark config content.
const LOCAL_PRAXIS_CONFIG: &str = include_str!("../../../benchmarks/comparison/configs/praxis-local.yaml");

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
// Config Path
// -----------------------------------------------------------------------------

/// Write the embedded local config to a temp file and return both the
/// [`TempDir`] (must be kept alive) and the config path within it.
fn local_praxis_config_path() -> (TempDir, std::path::PathBuf) {
    let dir = tempfile::Builder::new()
        .prefix("praxis-bench-")
        .tempdir()
        .expect("failed to create temp directory for config");
    let path = dir.path().join("praxis-local.yaml");
    std::fs::write(&path, LOCAL_PRAXIS_CONFIG).expect("failed to write temp config");
    (dir, path)
}

// -----------------------------------------------------------------------------
// Proxy Config Factory
// -----------------------------------------------------------------------------

/// Build a boxed [`ProxyConfig`] for the named proxy.
///
/// Returns the config and an optional [`TempDir`] that must be kept
/// alive for the duration of the benchmark (the config file lives
/// inside it for local Praxis runs).
///
/// [`ProxyConfig`]: benchmarks::proxy::ProxyConfig
pub(crate) fn build_proxy_config(
    name: &str,
    args: &Args,
    praxis_image: &Option<String>,
) -> (Box<dyn ProxyConfig>, Option<TempDir>) {
    match name {
        "praxis" => build_praxis_config(praxis_image),
        "envoy" => (
            Box::new(EnvoyConfig {
                image: Some(args.envoy_image.clone()),
                ..Default::default()
            }),
            None,
        ),
        "nginx" => (
            Box::new(NginxConfig {
                image: Some(args.nginx_image.clone()),
                ..Default::default()
            }),
            None,
        ),
        "haproxy" => (
            Box::new(HaproxyConfig {
                image: Some(args.haproxy_image.clone()),
                ..Default::default()
            }),
            None,
        ),
        other => {
            tracing::error!(proxy = other, "unknown proxy");
            std::process::exit(1);
        },
    }
}

/// Build a [`PraxisConfig`] with the appropriate config path.
///
/// For Docker runs, uses the checked-in config. For local runs,
/// writes the embedded config to a temp directory.
fn build_praxis_config(praxis_image: &Option<String>) -> (Box<dyn ProxyConfig>, Option<TempDir>) {
    let (tmpdir, config) = if praxis_image.is_some() {
        (
            None,
            std::path::PathBuf::from("benchmarks/comparison/configs/praxis.yaml"),
        )
    } else {
        let (td, path) = local_praxis_config_path();
        (Some(td), path)
    };
    (
        Box::new(PraxisConfig {
            config,
            address: "127.0.0.1:18090".into(),
            image: praxis_image.clone(),
        }),
        tmpdir,
    )
}
