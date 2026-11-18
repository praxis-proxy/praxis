// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Every example config must pass the pipeline validation server startup runs.
//!
//! Examples that need a build feature this binary lacks, or deployment files
//! and environment variables that only exist on a real host, are skipped
//! rather than failed.

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
        #[cfg(not(feature = "policy-builtins"))]
        if let Some(name) = path.file_name().and_then(|name| name.to_str())
            && name.starts_with("policy-")
        {
            let api_key_example = name == "policy-api-key.yaml"
                && cfg!(any(
                    feature = "policy-api-key-fips",
                    all(feature = "policy-api-key", feature = "policy-crypto-default"),
                    all(feature = "policy-api-key", feature = "policy-crypto-fips")
                ));
            if !api_key_example {
                continue;
            }
        }
        #[cfg(not(feature = "tls-health-check"))]
        if path.file_name().is_some_and(|name| name == "tls-health-check.yaml") {
            continue;
        }
        #[cfg(not(feature = "spiffe"))]
        if path.file_name().is_some_and(|name| name == "tls-mtls-spiffe.yaml") {
            continue;
        }
        #[cfg(not(feature = "access-log-syslog"))]
        if path.file_name().is_some_and(|name| name == "access-log-syslog.yaml") {
            continue;
        }
        #[cfg(not(feature = "slow-start"))]
        if path.file_name().is_some_and(|name| name == "slow-start.yaml") {
            continue;
        }
        let relative = path.strip_prefix(&root).expect("example under root");
        match resolve(&path) {
            Ok(()) => validated += 1,
            Err(error) => {
                if let Some(reason) = skip_reason(relative, &error) {
                    eprintln!("skipping {}: {reason}", relative.display());
                } else {
                    failures.push(format!("{}: {error}", path.display()));
                }
            },
        }
    }

    assert!(validated > 0, "no example configs found under {}", root.display());
    assert!(
        failures.is_empty(),
        "examples must pass the same pipeline validation as startup:\n{}",
        failures.join("\n")
    );
}

#[test]
fn missing_file_exceptions_are_scoped() {
    praxis_test_utils::ensure_crypto_provider();
    let source = PathBuf::from(praxis_test_utils::example_config_path(
        "protocols/tls-mtls-upstream.yaml",
    ));
    let yaml = std::fs::read_to_string(&source).expect("read upstream mTLS example");
    let directory = tempfile::tempdir().expect("temporary example directory");
    let copied = directory.path().join("tls-mtls-upstream.yaml");
    let permitted = directory.path().join("expected-proxy-client.pem");
    let unexpected = directory.path().join("misspelled-proxy-client.pem");
    let original = "/etc/ssl/certs/proxy-client.pem";
    let permitted_name = permitted.to_str().expect("UTF-8 test path");
    let unexpected_name = unexpected.to_str().expect("UTF-8 test path");
    assert!(
        external_files(std::path::Path::new("protocols/tls-mtls-upstream.yaml")).contains(&ExternalFile {
            path: original,
            loader: FileLoader::ClientCert("backend")
        }),
        "only the named example may exempt its documented deployment cert"
    );
    assert!(
        external_files(std::path::Path::new("protocols/tls-termination.yaml")).is_empty(),
        "a different TLS example must not inherit that exception"
    );

    write_example_with_client_cert(&copied, &yaml, permitted_name);
    let error = resolve(&copied).expect_err("missing external cert must fail resolution");
    let ResolveFailure::Pipeline(detail, config) = error else {
        panic!("missing deployment cert must fail in pipeline resolution: {error}");
    };
    assert_eq!(
        environmental(
            &detail,
            &[ExternalFile {
                path: permitted_name,
                loader: FileLoader::ClientCert("backend")
            }],
            &config
        ),
        Some(permitted_name),
        "documented example/path pair may be skipped"
    );

    for missing in [
        unexpected_name.to_owned(),
        format!("{}{permitted_name}", directory.path().display()),
        format!("{permitted_name}.misspelled"),
        format!("{permitted_name}: misspelled"),
    ] {
        write_example_with_client_cert(&copied, &yaml, &missing);
        let error = resolve(&copied).expect_err("mistyped external cert must fail resolution");
        let ResolveFailure::Pipeline(detail, config) = error else {
            panic!("mistyped cert must fail in pipeline resolution: {error}");
        };
        assert_eq!(
            environmental(
                &detail,
                &[ExternalFile {
                    path: permitted_name,
                    loader: FileLoader::ClientCert("backend")
                }],
                &config
            ),
            None,
            "different missing path in same example must fail: {missing}"
        );
    }

    std::fs::remove_file(&copied).expect("remove temporary example");
    assert!(
        matches!(resolve(&copied), Err(ResolveFailure::Config(_))),
        "missing example YAML must fail before external-file classification"
    );
}

#[test]
#[cfg(feature = "policy-engine")]
fn policy_file_exception_respects_loader_context() {
    praxis_test_utils::ensure_crypto_provider();
    let yaml = std::fs::read_to_string(praxis_test_utils::example_config_path("security/policy.yaml"))
        .expect("read actual policy example");
    let mut config: serde_yaml::Value = serde_yaml::from_str(&yaml).expect("parse actual policy example");
    let directory = tempfile::tempdir().expect("temporary example directory");
    let copied = directory.path().join("policy.yaml");
    let permitted = directory.path().join("expected-policy.yaml");
    let permitted_name = permitted.to_str().expect("UTF-8 policy path");
    let files = [ExternalFile {
        path: permitted_name,
        loader: FileLoader::Policy,
    }];
    assert_eq!(
        config["filter_chains"][0]["filters"][0]["config_path"].as_str(),
        Some("/etc/praxis/policy.yaml"),
        "substitution must target the actual policy document field"
    );
    for (suffix, expected) in [
        ("", Some(permitted_name)),
        (": failed to read cert", None),
        (": failed to read key", None),
    ] {
        let missing = format!("{permitted_name}{suffix}");
        config["filter_chains"][0]["filters"][0]["config_path"] = missing.clone().into();
        assert_file_classification(
            &copied,
            &config,
            &files,
            ExternalFile {
                path: &missing,
                loader: FileLoader::Policy,
            },
            expected,
        );
    }
}

#[test]
fn ca_file_exception_respects_loader_context() {
    praxis_test_utils::ensure_crypto_provider();
    let yaml = std::fs::read_to_string(praxis_test_utils::example_config_path(
        "protocols/tls-mtls-upstream.yaml",
    ))
    .expect("read actual upstream mTLS example");
    let mut config: serde_yaml::Value = serde_yaml::from_str(&yaml).expect("parse actual mTLS example");
    let directory = tempfile::tempdir().expect("temporary example directory");
    let copied = directory.path().join("tls-mtls-upstream.yaml");
    let permitted = directory.path().join("expected-upstream-ca.pem");
    let permitted_name = permitted.to_str().expect("UTF-8 CA path");
    let files = [ExternalFile {
        path: permitted_name,
        loader: FileLoader::Ca("backend"),
    }];
    for (suffix, expected) in [
        ("", Some(permitted_name)),
        (": failed to read cert", None),
        (": failed to read key", None),
    ] {
        let missing = format!("{permitted_name}{suffix}");
        config["filter_chains"][0]["filters"][1]["clusters"][0]["tls"]["ca"] =
            serde_yaml::to_value(serde_json::json!({"ca_path": &missing})).expect("serialize CA path");
        assert_file_classification(
            &copied,
            &config,
            &files,
            ExternalFile {
                path: &missing,
                loader: FileLoader::Ca("backend"),
            },
            expected,
        );
    }

    let files = external_files(std::path::Path::new("protocols/tls-mtls-upstream.yaml"));
    for (field, suffix) in [
        ("cert_path", ": failed to read cert"),
        ("key_path", ": failed to read key"),
    ] {
        let tls = &mut config["filter_chains"][0]["filters"][1]["clusters"][0]["tls"];
        let identity_path = tls["client_cert"][field]
            .as_str()
            .expect("actual example identity path");
        let missing = format!("{identity_path}{suffix}");
        tls["ca"]["ca_path"] = missing.clone().into();
        assert_file_classification(
            &copied,
            &config,
            files,
            ExternalFile {
                path: &missing,
                loader: FileLoader::Ca("backend"),
            },
            None,
        );
    }
}

#[test]
#[cfg(feature = "tls-health-check")]
fn tls_health_file_exception_preserves_global_ca() {
    praxis_test_utils::ensure_crypto_provider();
    let yaml = std::fs::read_to_string(praxis_test_utils::example_config_path(
        "observability/tls-health-check.yaml",
    ))
    .expect("read actual TLS health-check example");
    let mut config: serde_yaml::Value = serde_yaml::from_str(&yaml).expect("parse actual TLS health-check example");
    let directory = tempfile::tempdir().expect("temporary example directory");
    let copied = directory.path().join("tls-health-check.yaml");
    let permitted = directory.path().join("expected-upstream-ca.pem");
    let permitted_name = permitted.to_str().expect("UTF-8 CA path");
    let files = [
        ExternalFile {
            path: permitted_name,
            loader: FileLoader::Ca("handshake"),
        },
        ExternalFile {
            path: permitted_name,
            loader: FileLoader::Ca("https"),
        },
    ];
    for loader in [FileLoader::Ca("handshake"), FileLoader::Ca("https")] {
        assert!(
            external_files(std::path::Path::new("observability/tls-health-check.yaml")).contains(&ExternalFile {
                path: "/etc/praxis/upstream-ca.pem",
                loader
            }),
            "both actual health-check clusters retain their documented CA exception"
        );
    }
    for index in [0, 1] {
        assert_eq!(
            config["clusters"][index]["tls"]["ca"]["ca_path"].as_str(),
            Some("/etc/praxis/upstream-ca.pem"),
            "replace the actual global CA reference"
        );
        assert_eq!(
            config["filter_chains"][0]["filters"][1]["clusters"][index]["tls"]["ca"]["ca_path"].as_str(),
            Some("/etc/praxis/upstream-ca.pem"),
            "replace the actual inline CA reference"
        );
        config["clusters"][index]["tls"]["ca"]["ca_path"] = permitted_name.into();
        config["filter_chains"][0]["filters"][1]["clusters"][index]["tls"]["ca"]["ca_path"] = permitted_name.into();
    }
    assert_file_classification(
        &copied,
        &config,
        &files,
        ExternalFile {
            path: permitted_name,
            loader: FileLoader::Ca("handshake"),
        },
        Some(permitted_name),
    );
}

#[test]
fn client_key_file_exception_preserves_exact_path() {
    praxis_test_utils::ensure_crypto_provider();
    let yaml = std::fs::read_to_string(praxis_test_utils::example_config_path(
        "protocols/tls-mtls-upstream.yaml",
    ))
    .expect("read actual upstream mTLS example");
    let mut config: serde_yaml::Value = serde_yaml::from_str(&yaml).expect("parse actual mTLS example");
    let directory = tempfile::tempdir().expect("temporary example directory");
    let copied = directory.path().join("tls-mtls-upstream.yaml");
    let cert = directory.path().join("readable-cert.pem");
    std::fs::write(&cert, "").expect("certificate is read before the missing key, then parsed after it");
    config["filter_chains"][0]["filters"][1]["clusters"][0]["tls"]["client_cert"]["cert_path"] =
        cert.to_str().expect("UTF-8 certificate path").into();
    let permitted = directory.path().join("expected-client-key.pem");
    let permitted_name = permitted.to_str().expect("UTF-8 key path");
    let files = [ExternalFile {
        path: permitted_name,
        loader: FileLoader::ClientKey("backend"),
    }];
    for (suffix, expected) in [
        ("", Some(permitted_name)),
        (": failed to read cert", None),
        (": failed to read key", None),
    ] {
        let missing = format!("{permitted_name}{suffix}");
        config["filter_chains"][0]["filters"][1]["clusters"][0]["tls"]["client_cert"]["key_path"] =
            missing.clone().into();
        assert_file_classification(
            &copied,
            &config,
            &files,
            ExternalFile {
                path: &missing,
                loader: FileLoader::ClientKey("backend"),
            },
            expected,
        );
    }
}

#[test]
fn feature_exception_respects_config_phase() {
    praxis_test_utils::ensure_crypto_provider();
    let relative = std::path::Path::new("traffic-management/bound-upstream-condition.yaml");
    let yaml = std::fs::read_to_string(praxis_test_utils::example_config_path(
        "traffic-management/bound-upstream-condition.yaml",
    ))
    .expect("read bound-upstream example");
    let directory = tempfile::tempdir().expect("temporary example directory");
    let copied = directory.path().join("bound-upstream-condition.yaml");
    std::fs::write(&copied, yaml).expect("write bound-upstream example");
    if cfg!(feature = "upstream-binding") {
        assert!(
            resolve(&copied).is_ok(),
            "enabled binding feature must resolve the example"
        );
    } else {
        let failure = resolve(&copied).expect_err("disabled binding feature must fail validation");
        assert!(
            matches!(&failure, ResolveFailure::Config(_)),
            "missing feature is diagnosed during config validation: {failure}"
        );
        assert_eq!(
            skip_reason(relative, &failure),
            Some("disabled upstream-binding feature"),
            "the actual disabled-feature validation error may skip its example"
        );
        assert_eq!(
            skip_reason(
                std::path::Path::new("traffic-management/basic-reverse-proxy.yaml"),
                &failure
            ),
            None,
            "a different example must not inherit the config exception"
        );
    }

    let misleading = "config: filter 'headers' in chain 'main': condition 0 uses bound_upstream, which needs the upstream-binding build feature";
    std::fs::write(
        &copied,
        serde_yaml::to_string(misleading).expect("serialize root scalar"),
    )
    .expect("write invalid config shape containing feature diagnostic");
    let failure = resolve(&copied).expect_err("a diagnostic string is not a valid config mapping");
    assert!(
        matches!(&failure, ResolveFailure::Config(_)),
        "invalid config shape must fail parsing"
    );
    assert_eq!(
        skip_reason(relative, &failure),
        None,
        "feature wording inside a parse failure must not excuse the malformed config"
    );

    std::fs::remove_file(&copied).expect("remove temporary example");
    let failure = resolve(&copied).expect_err("missing top-level config must fail loading");
    assert!(
        matches!(&failure, ResolveFailure::Config(_)),
        "missing config must fail before pipelines"
    );
    assert_eq!(
        skip_reason(relative, &failure),
        None,
        "missing top-level example must never be skipped"
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

/// Exercise actual config loading and pipeline construction before classifying a file error.
fn assert_file_classification(
    path: &std::path::Path,
    yaml: &serde_yaml::Value,
    permitted: &[ExternalFile<'_>],
    missing: ExternalFile<'_>,
    expected: Option<&str>,
) {
    std::fs::write(path, serde_yaml::to_string(yaml).expect("serialize modified example"))
        .expect("write modified example");
    let failure = resolve(path).expect_err("missing deployment file must fail pipeline resolution");
    let ResolveFailure::Pipeline(error, config) = failure else {
        panic!("a quoted deployment filename must reach pipeline resolution: {failure}");
    };
    assert!(
        missing.matches_error(&error),
        "failure must name the intended missing path and loader: {error}"
    );
    assert_eq!(
        environmental(&error, permitted, &config),
        expected,
        "only the exact configured path and loader may be exempt: {error}"
    );
}

/// Preserve YAML scalar quoting when a test path contains a colon or space.
fn write_example_with_client_cert(path: &std::path::Path, yaml: &str, cert_path: &str) {
    let mut config: serde_yaml::Value = serde_yaml::from_str(yaml).expect("parse actual mTLS example");
    let cert = &mut config["filter_chains"][0]["filters"][1]["clusters"][0]["tls"]["client_cert"]["cert_path"];
    assert_eq!(
        cert.as_str(),
        Some("/etc/ssl/certs/proxy-client.pem"),
        "fixture replacement must target the actual example client certificate"
    );
    *cert = serde_yaml::Value::from(cert_path);
    std::fs::write(path, serde_yaml::to_string(&config).expect("serialize example copy"))
        .expect("write example with substituted client certificate");
}

/// Match environment exceptions only at the stage that can produce them.
fn skip_reason(example: &std::path::Path, failure: &ResolveFailure) -> Option<&'static str> {
    match failure {
        ResolveFailure::Pipeline(error, config) => environmental(error, external_files(example), config),
        ResolveFailure::Config(error) => (!cfg!(feature = "upstream-binding")
            && matches!(
                example.to_str(),
                Some(
                    "traffic-management/bound-upstream-condition.yaml"
                        | "traffic-management/bound-upstream-dispatch.yaml"
                )
            )
            && error.starts_with("config: filter '")
            && error.ends_with("uses bound_upstream, which needs the upstream-binding build feature"))
        .then_some("disabled upstream-binding feature"),
    }
}

/// Whether a resolution error is about this environment rather than the
/// example: a filter or config form behind a disabled build feature, or
/// deployment files (certificates, policies) or environment variables
/// (credentials) the example expects on the host.
fn environmental<'a>(error: &str, permitted_files: &[ExternalFile<'a>], config: &serde_yaml::Value) -> Option<&'a str> {
    let gated = GATED_FILTERS
        .iter()
        .any(|(filter, enabled)| !enabled && error == format!("unknown filter type: '{filter}'"));
    let binding = !cfg!(feature = "upstream-binding")
        && error == "load_balancer: cluster_source 'bound_upstream' needs the upstream-binding build feature";
    let unset_credential =
        error.starts_with("credential_injection: environment variable '") && error.contains("' not set");
    if gated {
        return Some("disabled filter feature");
    }
    if binding {
        return Some("disabled upstream-binding feature");
    }
    if unset_credential {
        return Some("unset deployment credential");
    }
    let configured = configured_files(config);
    let matching: Vec<_> = configured.iter().filter(|file| file.matches_error(error)).collect();
    let first = matching.first()?;
    matching
        .iter()
        .all(|file| permitted_files.contains(file))
        .then(|| permitted_files.iter().find(|file| file == first).map(|file| file.path))
        .flatten()
}

/// The loader and cluster determine the complete diagnostic around a file path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FileLoader<'a> {
    /// Certificate read performed before parsing an upstream identity pair.
    ClientCert(&'a str),
    /// Private-key read performed before parsing an upstream identity pair.
    ClientKey(&'a str),
    /// Raw PEM read for an upstream trust bundle.
    Ca(&'a str),
    /// Raw policy document read by the policy filter.
    Policy,
}

/// A deployment path together with the exact operation that may read it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ExternalFile<'a> {
    /// Literal configured filesystem path.
    path: &'a str,
    /// Source of the read failure, including its upstream cluster when relevant.
    loader: FileLoader<'a>,
}

impl ExternalFile<'_> {
    /// Compare the complete loader diagnostic; filenames are never stripped or split.
    fn matches_error(&self, error: &str) -> bool {
        let missing = std::io::Error::from_raw_os_error(2);
        let (cluster, detail) = match self.loader {
            FileLoader::ClientCert(cluster) => (cluster, "failed to read cert: "),
            FileLoader::ClientKey(cluster) => (cluster, "failed to read key: "),
            FileLoader::Ca(cluster) => (cluster, ""),
            FileLoader::Policy => {
                return error == format!("policy: failed to read config_path {}: {missing}", self.path);
            },
        };
        error
            == format!(
                "cluster '{cluster}': TLS material is unreadable, refusing to fall back to plaintext: failed to load TLS file {}: {detail}{missing}",
                self.path
            )
    }
}

/// Read the actual fields used by the documented examples' loader factories.
///
/// Ambiguous diagnostics must match only permitted configured fields. A raw CA
/// filename ending in `: failed to read cert` can otherwise impersonate the
/// client-certificate loader's diagnostic in the same cluster.
fn configured_files(config: &serde_yaml::Value) -> Vec<ExternalFile<'_>> {
    let mut files = cluster_files(config);
    match config {
        serde_yaml::Value::Mapping(fields) => {
            if config.get("filter").and_then(serde_yaml::Value::as_str) == Some("policy")
                && let Some(path) = config.get("config_path").and_then(serde_yaml::Value::as_str)
            {
                files.push(ExternalFile {
                    path,
                    loader: FileLoader::Policy,
                });
            }
            files.extend(fields.values().flat_map(configured_files));
        },
        serde_yaml::Value::Sequence(items) => files.extend(items.iter().flat_map(configured_files)),
        serde_yaml::Value::Tagged(tag) => files.extend(configured_files(&tag.value)),
        serde_yaml::Value::Null
        | serde_yaml::Value::Bool(_)
        | serde_yaml::Value::Number(_)
        | serde_yaml::Value::String(_) => {},
    }
    files
}

/// Enumerate literal CA, certificate, and key fields without reading any file.
fn cluster_files(cluster: &serde_yaml::Value) -> Vec<ExternalFile<'_>> {
    let Some(name) = cluster.get("name").and_then(serde_yaml::Value::as_str) else {
        return Vec::new();
    };
    let Some(tls) = cluster.get("tls") else {
        return Vec::new();
    };
    [
        ("ca", "ca_path", FileLoader::Ca(name)),
        ("client_cert", "cert_path", FileLoader::ClientCert(name)),
        ("client_cert", "key_path", FileLoader::ClientKey(name)),
    ]
    .into_iter()
    .filter_map(|(section, field, loader)| {
        tls.get(section)?
            .get(field)?
            .as_str()
            .map(|path| ExternalFile { path, loader })
    })
    .collect()
}

/// Deployment-owned files that a specific example may omit locally.
fn external_files(example: &std::path::Path) -> &'static [ExternalFile<'static>] {
    match example.to_str().unwrap_or_default() {
        "protocols/tls-mtls-upstream.yaml" | "protocols/tls-mtls-both.yaml" => &[
            ExternalFile {
                path: "/etc/ssl/certs/proxy-client.pem",
                loader: FileLoader::ClientCert("backend"),
            },
            ExternalFile {
                path: "/etc/ssl/private/proxy-client-key.pem",
                loader: FileLoader::ClientKey("backend"),
            },
        ],
        "observability/tls-health-check.yaml" => &[
            ExternalFile {
                path: "/etc/praxis/upstream-ca.pem",
                loader: FileLoader::Ca("handshake"),
            },
            ExternalFile {
                path: "/etc/praxis/upstream-ca.pem",
                loader: FileLoader::Ca("https"),
            },
        ],
        "security/policy-jwt-fips.yaml" => &[ExternalFile {
            path: "/etc/praxis/jwt-fips-policy.yaml",
            loader: FileLoader::Policy,
        }],
        "security/policy-llm.yaml" => &[ExternalFile {
            path: "/etc/praxis/llm-policy.yaml",
            loader: FileLoader::Policy,
        }],
        "security/policy-rate-limit.yaml" => &[ExternalFile {
            path: "/etc/praxis/rate-limit-policy.yaml",
            loader: FileLoader::Policy,
        }],
        "security/policy-query-credential.yaml" => &[ExternalFile {
            path: "/etc/praxis/query-credential-policy.yaml",
            loader: FileLoader::Policy,
        }],
        "security/policy-assertions.yaml" => &[ExternalFile {
            path: "/etc/praxis/assertions-policy.yaml",
            loader: FileLoader::Policy,
        }],
        "security/policy.yaml" | "security/policy-context.yaml" => &[ExternalFile {
            path: "/etc/praxis/policy.yaml",
            loader: FileLoader::Policy,
        }],
        "security/policy-api-key.yaml" => &[ExternalFile {
            path: "/etc/praxis/api-key-policy.yaml",
            loader: FileLoader::Policy,
        }],
        "security/policy-admission.yaml" => &[ExternalFile {
            path: "/etc/praxis/admission-policy.yaml",
            loader: FileLoader::Policy,
        }],
        "security/policy-http.yaml" => &[ExternalFile {
            path: "/etc/praxis/http-policy.yaml",
            loader: FileLoader::Policy,
        }],
        "security/policy-llm-input.yaml" => &[ExternalFile {
            path: "/etc/praxis/llm-input-policy.yaml",
            loader: FileLoader::Policy,
        }],
        _ => &[],
    }
}

/// Distinguish failure to read the example itself from pipeline errors.
#[derive(Debug)]
enum ResolveFailure {
    Config(String),
    Pipeline(String, Box<serde_yaml::Value>),
}

impl std::fmt::Display for ResolveFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Config(error) | Self::Pipeline(error, _) => f.write_str(error),
        }
    }
}

/// Load `path` and resolve its pipelines the way server startup does.
fn resolve(path: &std::path::Path) -> Result<(), ResolveFailure> {
    let config = Config::from_file(path).map_err(|error| ResolveFailure::Config(error.to_string()))?;
    let subrequest = praxis::build_subrequest_client(&config).map_err(|error| pipeline_failure(error, &config))?;
    praxis::resolve_pipelines(
        &config,
        &praxis::build_full_registry(),
        &praxis_core::health::build_health_registry(&config.clusters),
        &praxis_core::kv::KvStoreRegistry::new(),
        &Arc::new(praxis_filter::SessionStoreRegistry::new()),
        &subrequest,
    )
    .map(drop)
    .map_err(|error| pipeline_failure(error, &config))
}

/// Retain literal configured paths so diagnostic text cannot impersonate another loader.
fn pipeline_failure(error: impl std::fmt::Display, config: &Config) -> ResolveFailure {
    ResolveFailure::Pipeline(
        error.to_string(),
        Box::new(serde_yaml::to_value(config).expect("serialize successfully parsed config")),
    )
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
