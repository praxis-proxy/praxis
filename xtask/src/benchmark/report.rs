// SPDX-License-Identifier: LGPL-3.0-only
// Copyright (c) 2024 Shane Utt

//! Benchmark report serialization and deserialization.

use benchmarks::report::BenchmarkReport;

// -----------------------------------------------------------------------------
// Load
// -----------------------------------------------------------------------------

/// Load a [`BenchmarkReport`] from a file, detecting format from the extension.
///
/// [`BenchmarkReport`]: benchmarks::report::BenchmarkReport
pub(crate) fn load_report(path: &str) -> BenchmarkReport {
    let content = std::fs::read_to_string(path).unwrap_or_else(|e| {
        eprintln!("failed to read {path}: {e}");
        std::process::exit(1);
    });

    if path.ends_with(".json") {
        serde_json::from_str(&content).unwrap_or_else(|e| {
            eprintln!("failed to parse JSON: {e}");
            std::process::exit(1);
        })
    } else {
        serde_yaml::from_str(&content).unwrap_or_else(|e| {
            eprintln!("failed to parse YAML: {e}");
            std::process::exit(1);
        })
    }
}

// -----------------------------------------------------------------------------
// Write
// -----------------------------------------------------------------------------

/// Serialize and write the report to `path` in the given format (`yaml` or `json`).
pub(crate) fn write_report(report: &BenchmarkReport, path: &str, format: &str) {
    let content = match format {
        "json" => serde_json::to_string_pretty(report).expect("failed to serialize report to JSON"),
        _ => serde_yaml::to_string(report).expect("failed to serialize report to YAML"),
    };
    std::fs::write(path, content).unwrap_or_else(|e| {
        eprintln!("failed to write report: {e}");
        std::process::exit(1);
    });
}
