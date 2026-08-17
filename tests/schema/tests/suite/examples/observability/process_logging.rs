// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Process logging example schema tests.

use praxis_core::config::{LogOutput, LogRotation};

#[test]
fn process_logging_example_parses() {
    let path = format!(
        "{}/../../examples/configs/observability/process-logging.yaml",
        env!("CARGO_MANIFEST_DIR")
    );
    let yaml = std::fs::read_to_string(&path).expect("read example");
    let config = praxis_core::config::Config::from_yaml(&yaml).expect("parse example");
    assert_eq!(config.runtime.logging.output, LogOutput::File);
    assert_eq!(
        config.runtime.logging.rotation,
        Some(LogRotation::Size { max_bytes: 1_048_576 })
    );
    assert!(config.runtime.logging.non_blocking);
}
