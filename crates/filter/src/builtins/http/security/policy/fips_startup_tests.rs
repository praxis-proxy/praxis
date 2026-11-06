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
//! The missing-provider scenario needs only OpenSSL's `base` provider and
//! runs everywhere. The others need the FIPS module: they run when
//! `PRAXIS_FIPS_PROVIDER_CONF` names an OpenSSL config that activates it
//! with `default_properties = fips=yes` (`make test-fips-policy-startup`
//! inside the toolchain image), and otherwise print
//! `fips-startup: skipped <scenario>` and pass. `PRAXIS_FIPS_HOST` makes a
//! missing config a failure instead.

use std::{path::Path, process::Command};

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
fn without_a_sha256_provider_construction_fails_with_a_crypto_error() {
    let dir = tempfile::TempDir::new().expect("create tempdir");
    let conf = dir.path().join("no-provider.cnf");
    std::fs::write(&conf, NO_PROVIDER_CONF).expect("write the OpenSSL config");
    run_child("no_provider", &conf);
}

#[cfg(feature = "policy-jwt-openssl-fips")]
#[test]
fn jwt_without_fips_default_properties_fails_to_load() {
    let Some(fips_conf) = provider_conf("jwt_without_fips_defaults") else {
        return;
    };
    let dir = tempfile::TempDir::new().expect("create tempdir");
    let conf = dir.path().join("fips-without-defaults.cnf");
    let text = std::fs::read_to_string(&fips_conf).expect("read the FIPS provider config");
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
    std::fs::write(&conf, relaxed).expect("write the relaxed config");
    run_child("jwt_without_fips_defaults", &conf);
}

#[cfg(feature = "policy-jwt-openssl-fips")]
#[test]
fn a_rival_jsonwebtoken_provider_is_refused() {
    if let Some(conf) = provider_conf("rival_provider") {
        run_child("rival_provider", &conf);
    }
}

#[cfg(feature = "policy-jwt-openssl-fips")]
#[test]
fn reloading_a_fips_jwt_policy_twice_does_not_conflict() {
    if let Some(conf) = provider_conf("double_reload") {
        run_child("double_reload", &conf);
    }
}

#[test]
fn policy_fips_child() {
    let Ok(scenario) = std::env::var(CHILD_ENV) else {
        return;
    };
    match scenario.as_str() {
        "no_provider" => child_no_provider(),
        #[cfg(feature = "policy-jwt-openssl-fips")]
        "jwt_without_fips_defaults" => {
            child_expect_jwt_crypto_failure("do not restrict operations to the FIPS provider");
        },
        #[cfg(feature = "policy-jwt-openssl-fips")]
        "rival_provider" => child_rival_provider(),
        #[cfg(feature = "policy-jwt-openssl-fips")]
        "double_reload" => child_double_reload(),
        other => panic!("unknown FIPS child scenario {other}"),
    }
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Engine initialization refuses a backend with no SHA-256.
fn child_no_provider() {
    let (_dir, path) = write_policy("plugins: []\n");
    let error = construction_error(path);
    assert!(
        error.contains(ppe::CRYPTO_FAILED_CODE),
        "a missing SHA-256 provider must fail construction with the crypto code: {error}"
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
fn child_rival_provider() {
    rival::install();
    child_expect_jwt_crypto_failure("another jsonwebtoken crypto provider");
}

/// Policy's own provider, installed on the first load, is accepted again.
#[cfg(feature = "policy-jwt-openssl-fips")]
fn child_double_reload() {
    let (_keys, path) = write_jwt_policy();
    for attempt in 1..=3 {
        if let Err(error) = PolicyFilter::new(filter_config(path.clone()), None) {
            panic!("FIPS JWT construction {attempt} must succeed with Policy's own provider: {error}");
        }
    }
}

/// The FIPS provider config, or `None` after printing a counted skip.
#[cfg(feature = "policy-jwt-openssl-fips")]
#[expect(clippy::print_stdout, reason = "the skip line is how a run counts what it skipped")]
fn provider_conf(scenario: &str) -> Option<std::path::PathBuf> {
    let conf = std::env::var_os(PROVIDER_CONF_ENV).map(std::path::PathBuf::from);
    if conf.is_none() {
        assert!(
            !fips_host_declared(),
            "PRAXIS_FIPS_HOST is set, so {PROVIDER_CONF_ENV} must name the FIPS provider config"
        );
        println!("fips-startup: skipped {scenario} ({PROVIDER_CONF_ENV} is not set)");
    }
    conf
}

/// Whether `PRAXIS_FIPS_HOST` declares a FIPS host. An empty value, `0`,
/// `false`, `no` or `off` leave it undeclared, as in the test harness.
#[cfg(feature = "policy-jwt-openssl-fips")]
fn fips_host_declared() -> bool {
    std::env::var("PRAXIS_FIPS_HOST").is_ok_and(|value| {
        !matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "" | "0" | "false" | "no" | "off"
        )
    })
}

/// Run [`policy_fips_child`] for `scenario` under `openssl_conf`.
///
/// [`policy_fips_child`]: policy_fips_child
#[expect(clippy::print_stdout, reason = "the ran line is how a run counts what it ran")]
fn run_child(scenario: &str, openssl_conf: &Path) {
    let output = Command::new(std::env::current_exe().expect("test executable path"))
        .args([
            "--exact",
            "builtins::http::security::policy::fips_startup_tests::policy_fips_child",
        ])
        .args(["--nocapture", "--test-threads=1"])
        .env(CHILD_ENV, scenario)
        .env("OPENSSL_CONF", openssl_conf)
        .output()
        .expect("spawn the FIPS child");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success() && stdout.contains("1 passed"),
        "FIPS child {scenario} failed:\n{stdout}\n{stderr}"
    );
    println!("fips-startup: ran {scenario}");
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
