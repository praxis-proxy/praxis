// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

#![expect(
    clippy::tests_outside_test_module,
    reason = "test functions live in this cfg(test) module"
)]

//! Policy FIPS construction under real OpenSSL provider configurations.
//!
//! The provider, the default properties and the process-global
//! `jsonwebtoken` provider are fixed once per process, so each scenario runs
//! in a child copy of this test binary with its own `OPENSSL_CONF`. The
//! parent spawns it and asserts on its outcome.
//!
//! Every scenario runs in both environments. `PRAXIS_POLICY_FIPS_TEST_MODE`
//! explicitly selects `configurable-provider` or `kernel-fips`, and must
//! match the kernel flag. The former proves rejection of unavailable crypto;
//! the latter proves RHEL's automatic FIPS activation survives those configs.
//! JWT cases require `PRAXIS_FIPS_PROVIDER_CONF`; missing prerequisites fail.

use std::{
    path::{Path, PathBuf},
    process::Command,
};

use super::feature_tests::{filter_config, write_policy};
use crate::builtins::http::security::policy::filter::PolicyFilter;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Names the scenario a child process runs.
const CHILD_ENV: &str = "PRAXIS_POLICY_FIPS_CHILD";

/// An OpenSSL config activating the FIPS provider with FIPS defaults.
#[cfg(feature = "policy-jwt-openssl-fips")]
const PROVIDER_CONF_ENV: &str = "PRAXIS_FIPS_PROVIDER_CONF";

/// An OpenSSL config that loads only the `base` provider: no digests.
const NO_PROVIDER_CONF: &str = "openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
base = base_sect

[base_sect]
activate = 1
";

/// A JWT policy on an asymmetric key, as FIPS JWT requires; `{pem}` is the
/// public key path.
#[cfg(feature = "policy-jwt-openssl-fips")]
const JWT_POLICY: &str = r#"plugins:
  - name: jwt-user
    kind: identity/jwt
    hooks: [identity.resolve]
    config:
      credential: { kind: header, name: Authorization }
      trusted_issuers:
        - issuer: "https://idp.test.local"
          audiences: ["test-api"]
          algorithms: ["RS256"]
          decoding_key: { kind: pem_file, path: "{pem}" }
global:
  authentication: [jwt-user]
"#;

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn base_only_config_preserves_crypto_validation() {
    run_isolated(
        "base_only_config_preserves_crypto_validation",
        no_provider_conf,
        child_base_only,
    );
}

#[cfg(feature = "policy-jwt-openssl-fips")]
#[test]
fn jwt_config_without_fips_defaults_preserves_crypto_validation() {
    run_isolated(
        "jwt_config_without_fips_defaults_preserves_crypto_validation",
        relaxed_provider_conf,
        child_without_fips_defaults,
    );
}

#[cfg(feature = "policy-jwt-openssl-fips")]
#[test]
fn a_rival_jsonwebtoken_provider_is_refused() {
    run_isolated(
        "a_rival_jsonwebtoken_provider_is_refused",
        |_| provider_conf(),
        child_rival_provider,
    );
}

#[cfg(feature = "policy-jwt-openssl-fips")]
#[test]
fn reloading_a_fips_jwt_policy_twice_does_not_conflict() {
    run_isolated(
        "reloading_a_fips_jwt_policy_twice_does_not_conflict",
        |_| provider_conf(),
        child_double_reload,
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// The explicitly requested environment; never inferred from crypto availability.
#[derive(Clone, Copy)]
enum HostMode {
    /// Configuration controls which providers and default properties are active.
    ConfigurableProvider,
    /// RHEL activates FIPS from the kernel flag, even under a relaxed config.
    KernelFips,
}

impl HostMode {
    /// Require the selected environment to agree with the actual kernel flag.
    fn required() -> Self {
        let mode = std::env::var("PRAXIS_POLICY_FIPS_TEST_MODE")
            .ok()
            .filter(|mode| !mode.is_empty())
            .expect(
                "PRAXIS_POLICY_FIPS_TEST_MODE must be configurable-provider or kernel-fips; use the Makefile FIPS targets",
            );
        let kernel_fips = match std::fs::read_to_string("/proc/sys/crypto/fips_enabled") {
            Ok(flag) => match flag.trim() {
                "0" => false,
                "1" => true,
                other => panic!("unexpected kernel FIPS flag: {other}"),
            },
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => panic!("cannot read the kernel FIPS flag: {error}"),
        };
        match mode.as_str() {
            "configurable-provider" => {
                assert!(
                    !kernel_fips,
                    "configurable-provider tests require a kernel without FIPS enforcement"
                );
                Self::ConfigurableProvider
            },
            "kernel-fips" => {
                assert!(kernel_fips, "kernel-fips tests require the kernel FIPS flag to be 1");
                Self::KernelFips
            },
            other => panic!("unknown policy FIPS test mode: {other}"),
        }
    }
}

/// A base-only config either lacks SHA-256 or retains the host's FIPS enforcement.
fn child_base_only(mode: HostMode) {
    let (_dir, path) = write_policy("plugins: []\n");
    match mode {
        HostMode::ConfigurableProvider => {
            assert!(
                openssl::md::Md::fetch(None, "SHA256", Some("fips=yes")).is_err(),
                "the negative case must lack a FIPS SHA-256 implementation"
            );
            let error = construction_error(path);
            assert!(
                error.contains(ppe::CRYPTO_FAILED_CODE),
                "a missing SHA-256 provider must fail construction with the crypto code: {error}"
            );
        },
        HostMode::KernelFips => {
            assert_fips_crypto();
            assert!(
                PolicyFilter::new(filter_config(path), None).is_ok(),
                "kernel-enforced FIPS construction must succeed"
            );
        },
    }
}

/// Relaxed defaults must be rejected unless the host still enforces FIPS.
#[cfg(feature = "policy-jwt-openssl-fips")]
fn child_without_fips_defaults(mode: HostMode) {
    match mode {
        HostMode::ConfigurableProvider => {
            assert!(
                openssl::md::Md::fetch(None, "SHA256", Some("fips=yes")).is_ok(),
                "FIPS SHA-256 must remain available before checking the relaxed defaults"
            );
            assert!(
                openssl::md::Md::fetch(None, "MD5", None).is_ok(),
                "the negative case must have non-FIPS defaults"
            );
            child_expect_jwt_crypto_failure("do not restrict operations to the FIPS provider");
        },
        HostMode::KernelFips => child_double_reload(mode),
    }
}

/// The effective default context admits FIPS SHA-256 and refuses non-FIPS MD5.
fn assert_fips_crypto() {
    assert!(
        openssl::md::Md::fetch(None, "SHA256", Some("fips=yes")).is_ok(),
        "FIPS SHA-256 must be available"
    );
    assert!(
        openssl::md::Md::fetch(None, "MD5", None).is_err(),
        "FIPS defaults must refuse MD5"
    );
}

/// JWT config load refuses with a crypto error mentioning `detail`.
#[cfg(feature = "policy-jwt-openssl-fips")]
fn child_expect_jwt_crypto_failure(detail: &str) {
    let (_keys, path) = write_jwt_policy();
    let error = construction_error(path);
    assert!(
        error.contains(ppe::CRYPTO_FAILED_CODE) && error.contains(detail),
        "a FIPS JWT load must fail with a crypto error mentioning {detail}: {error}"
    );
}

/// A provider installed before Policy loads JWT config is refused.
#[cfg(feature = "policy-jwt-openssl-fips")]
fn child_rival_provider(_mode: HostMode) {
    assert_fips_crypto();
    rival::install();
    child_expect_jwt_crypto_failure("another jsonwebtoken crypto provider");
}

/// Policy's own provider, installed on the first load, is accepted again.
#[cfg(feature = "policy-jwt-openssl-fips")]
fn child_double_reload(_mode: HostMode) {
    assert_fips_crypto();
    let (_keys, path) = write_jwt_policy();
    for attempt in 1..=3 {
        if let Err(error) = PolicyFilter::new(filter_config(path.clone()), None) {
            panic!("FIPS JWT construction {attempt} must succeed with Policy's own provider: {error}");
        }
    }
}

/// Require a readable FIPS configuration; absence is a test failure.
#[cfg(feature = "policy-jwt-openssl-fips")]
fn provider_conf() -> PathBuf {
    let path = std::env::var_os(PROVIDER_CONF_ENV).map(PathBuf::from).expect(
        "PRAXIS_FIPS_PROVIDER_CONF must name a FIPS provider config; use FIPS_POLICY_PROVIDER_CONF with the Makefile targets",
    );
    assert!(path.is_file(), "FIPS provider config must exist: {}", path.display());
    path
}

/// Write the deliberately base-only config used by the first scenario.
fn no_provider_conf(dir: &Path) -> PathBuf {
    let conf = dir.join("no-provider.cnf");
    std::fs::write(&conf, NO_PROVIDER_CONF).expect("write the OpenSSL config");
    conf
}

/// Load both providers without requesting FIPS defaults in the configuration.
#[cfg(feature = "policy-jwt-openssl-fips")]
fn relaxed_provider_conf(dir: &Path) -> PathBuf {
    let text = std::fs::read_to_string(provider_conf()).expect("read the FIPS provider config");
    let relaxed: String = text
        .lines()
        .filter(|line| !line.trim_start().starts_with("default_properties"))
        .flat_map(|line| match line.trim() {
            "[provider_sect]" => vec![line, "default = default_sect"],
            _ => vec![line],
        })
        .map(|line| format!("{line}\n"))
        .chain(["\n[default_sect]\nactivate = 1\n".to_owned()])
        .collect();
    let conf = dir.join("fips-without-defaults.cnf");
    std::fs::write(&conf, relaxed).expect("write the relaxed config");
    conf
}

/// Re-execute this exact test in an isolated process, or perform its assertions.
#[expect(
    clippy::print_stdout,
    reason = "the completion marker proves the child executed its assertions"
)]
fn run_isolated(test: &str, prepare: impl FnOnce(&Path) -> PathBuf, check: fn(HostMode)) {
    let mode = HostMode::required();
    match std::env::var(CHILD_ENV) {
        Ok(child) => {
            assert_eq!(child, test, "a child must execute the requested test");
            check(mode);
            println!("fips-startup: checked {test}");
        },
        Err(std::env::VarError::NotPresent) => {
            let dir = tempfile::TempDir::new().expect("create tempdir");
            run_child(test, &prepare(dir.path()));
        },
        Err(error) => panic!("invalid FIPS child marker: {error}"),
    }
}

/// Require the exact child test to pass and report that its assertions completed.
#[expect(clippy::print_stdout, reason = "the ran line records every completed scenario")]
fn run_child(test: &str, openssl_conf: &Path) {
    let output = Command::new(std::env::current_exe().expect("test executable path"))
        .args([
            "--exact",
            &format!("builtins::http::security::policy::fips_startup_tests::{test}"),
        ])
        .args(["--nocapture", "--test-threads=1"])
        .env(CHILD_ENV, test)
        .env("OPENSSL_CONF", openssl_conf)
        .output()
        .expect("spawn the FIPS child");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success()
            && stdout.contains("1 passed")
            && stdout.contains(&format!("fips-startup: checked {test}")),
        "FIPS child {test} failed:\n{stdout}\n{stderr}"
    );
    println!("fips-startup: ran {test}");
}

/// The construction error for `config_path`, which must fail to build.
fn construction_error(config_path: String) -> String {
    match PolicyFilter::new(filter_config(config_path), None) {
        Ok(_) => panic!("construction must fail in this scenario"),
        Err(error) => error.to_string(),
    }
}

/// Write [`JWT_POLICY`] beside a fresh RSA-2048 public key; the returned
/// directories must outlive construction.
///
/// [`JWT_POLICY`]: JWT_POLICY
#[cfg(feature = "policy-jwt-openssl-fips")]
fn write_jwt_policy() -> ([tempfile::TempDir; 2], String) {
    let keys = tempfile::TempDir::new().expect("create tempdir");
    let rsa = openssl::rsa::Rsa::generate(2048).expect("generate an RSA key");
    let pem_path = keys.path().join("issuer.pem");
    std::fs::write(&pem_path, rsa.public_key_to_pem().expect("encode the public key")).expect("write the key");
    let yaml = JWT_POLICY.replace("{pem}", pem_path.to_str().expect("a UTF-8 tempdir path"));
    let (policy, path) = write_policy(&yaml);
    ([keys, policy], path)
}

/// Test utilities for installing a rival `jsonwebtoken` provider.
#[cfg(feature = "policy-jwt-openssl-fips")]
mod rival {
    use jsonwebtoken::{
        Algorithm, DecodingKey, EncodingKey,
        crypto::{CryptoProvider, JwtSigner, JwtVerifier, KeyUtils},
        errors::{ErrorKind, Result},
    };

    /// Supports nothing; only its installation matters.
    static RIVAL: CryptoProvider = CryptoProvider {
        signer_factory: refuse_signer,
        verifier_factory: refuse_verifier,
        key_utils: KeyUtils::new_unimplemented(),
    };

    /// Install [`RIVAL`] as the process default.
    ///
    /// [`RIVAL`]: RIVAL
    pub(super) fn install() {
        assert!(RIVAL.install_default().is_ok(), "the rival provider must install first");
    }

    /// Refuse every signer.
    #[expect(clippy::trivially_copy_pass_by_ref, reason = "jsonwebtoken's factory signature")]
    fn refuse_signer(_algorithm: &Algorithm, _key: &EncodingKey) -> Result<Box<dyn JwtSigner>> {
        Err(ErrorKind::InvalidAlgorithm.into())
    }

    /// Refuse every verifier.
    #[expect(clippy::trivially_copy_pass_by_ref, reason = "jsonwebtoken's factory signature")]
    fn refuse_verifier(_algorithm: &Algorithm, _key: &DecodingKey) -> Result<Box<dyn JwtVerifier>> {
        Err(ErrorKind::InvalidAlgorithm.into())
    }
}
