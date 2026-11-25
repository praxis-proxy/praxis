// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Exercises validation through the public embedding API.

#![expect(clippy::tests_outside_test_module, reason = "Cargo integration test crate")]

use praxis::{CompositionError, ServerComposition, validate_config_with_composition};
use praxis_core::config::{Config, DEFAULT_CONFIG};

/// Embedders may edit a parsed config before asking the server to validate it.
#[test]
fn validation_rejects_a_config_with_no_listeners() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut config = Config::from_yaml(DEFAULT_CONFIG)?;
    config.listeners.clear();
    let err = praxis::validate_config(&config).expect_err("a server requires a listener");
    assert!(
        err.to_string().contains("at least one listener"),
        "unexpected error: {err}"
    );
    Ok(())
}

/// Validation and startup apply the same downstream rejection.
#[test]
fn validation_uses_downstream_pipeline_validators() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config = Config::from_yaml(DEFAULT_CONFIG)?;
    let composition = ServerComposition::standard()
        .add_pipeline_validator(|_| Err(CompositionError::new("downstream validator rejected candidate")));

    let result = validate_config_with_composition(&config, composition);
    let rejects = |error: praxis::StartupError| error.to_string().contains("downstream validator rejected candidate");
    assert!(
        result.is_err_and(rejects),
        "validation should return the downstream error"
    );
    let mut startup_config = config;
    startup_config.insecure_options.allow_root = true;
    let startup = ServerComposition::standard()
        .add_pipeline_validator(|_| Err(CompositionError::new("downstream validator rejected candidate")));
    assert!(
        praxis::try_run_server_with_composition(startup_config, startup, None, None).is_err_and(rejects),
        "startup should return the same downstream error"
    );
    Ok(())
}

/// Validation and dump check access logs without creating their sink files.
#[expect(
    clippy::too_many_lines,
    reason = "inline config and assertions cover the library and CLI paths"
)]
#[test]
fn validation_does_not_create_access_log_files() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let temp = tempfile::tempdir()?;
    let path = temp.path().join("access.log");
    let yaml = format!(
        r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: access_log
        sink:
          type: file
          path: {}
      - filter: static_response
        status: 200
        body: ok
"#,
        path.display()
    );
    praxis::validate_config(&Config::from_yaml(&yaml)?)?;
    assert!(
        !path.exists(),
        "library validation created the configured access-log sink"
    );

    let config_path = temp.path().join("praxis.yaml");
    std::fs::write(&config_path, yaml)?;
    for flag in ["--validate", "--dump"] {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_praxis"))
            .args([flag, "-c"])
            .arg(&config_path)
            .output()?;
        assert!(
            output.status.success(),
            "{flag} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!path.exists(), "{flag} created the configured access-log sink");
    }
    Ok(())
}
