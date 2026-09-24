// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Every example config must pass the pipeline validation server startup runs.
//!
//! Examples that need a build feature this binary lacks, or deployment files
//! that only exist on a real host, are skipped rather than failed.

use std::{path::PathBuf, sync::Arc};

use praxis_core::config::Config;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn every_example_resolves_its_pipelines() {
    praxis_test_utils::ensure_crypto_provider();
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/configs");
    let mut validated = 0;
    let mut failures = Vec::new();
    for path in yaml_files(&root) {
        #[cfg(not(feature = "spiffe"))]
        if path.file_name().is_some_and(|name| name == "tls-mtls-spiffe.yaml") {
            continue;
        }
        match resolve(&path) {
            Ok(()) => validated += 1,
            Err(error) if environmental(&error) => {},
            Err(error) => failures.push(format!("{}: {error}", path.display())),
        }
    }

    assert!(validated > 0, "no example configs found under {}", root.display());
    assert!(
        failures.is_empty(),
        "examples must pass the same pipeline validation as startup:\n{}",
        failures.join("\n")
    );
}

// ---------------------------------------------------------------------------
// Test Utilities
// ---------------------------------------------------------------------------

/// Built-in filters that exist only behind a build feature, so an example
/// using one is skipped when this test binary lacks the feature.
const GATED_FILTERS: &[(&str, bool)] = &[
    ("basic_auth", cfg!(feature = "basic-auth-filter")),
    ("cloud_events", cfg!(feature = "cloud-events-filter")),
    ("iterative_request_router", cfg!(feature = "iterative-request-router")),
    ("peer_identity_trust", cfg!(feature = "spiffe")),
    ("policy", cfg!(feature = "policy-engine")),
];

/// Whether a resolution error is about this environment rather than the
/// example: a filter or config form behind a disabled build feature, or
/// deployment files (certificates, policies) the example expects on the host.
fn environmental(error: &str) -> bool {
    let gated = GATED_FILTERS
        .iter()
        .any(|(filter, enabled)| !enabled && error.contains(&format!("unknown filter type: '{filter}'")));
    let binding = !cfg!(feature = "upstream-binding") && error.contains("needs the upstream-binding build feature");
    gated || binding || error.contains("No such file or directory")
}

/// Load `path` and resolve its pipelines the way server startup does.
fn resolve(path: &std::path::Path) -> Result<(), String> {
    let config = Config::from_file(path).map_err(|error| error.to_string())?;
    praxis::resolve_pipelines(
        &config,
        &praxis::build_full_registry(),
        &praxis_core::health::build_health_registry(&config.clusters),
        &praxis_core::kv::KvStoreRegistry::new(),
        &Arc::new(praxis_filter::SessionStoreRegistry::new()),
        &praxis::build_subrequest_client(&config),
    )
    .map(drop)
    .map_err(|error| error.to_string())
}

/// Every `.yaml` file under `root`, sorted for a stable failure report.
fn yaml_files(root: &std::path::Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let mut dirs = vec![root.to_path_buf()];
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(&dir).expect("example directory is readable") {
            let path = entry.expect("directory entry is readable").path();
            if path.is_dir() {
                dirs.push(path);
            } else if path.extension().is_some_and(|extension| extension == "yaml") {
                files.push(path);
            }
        }
    }
    files.sort();
    files
}
