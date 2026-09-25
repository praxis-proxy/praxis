// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! `cargo xtask fips runtime-probe`: run the shipped FIPS image on this host
//! and prove, from outside, what it negotiates and refuses.
//!
//! The image is started with a TLS listener under `PRAXIS_REQUIRE_FIPS=1`, so
//! it only comes up on a FIPS host. The listener probes of the integration
//! suite (`tests/integration/tests/suite/fips.rs`, the `listener_` tests)
//! are then pointed at it through `PRAXIS_FIPS_PROBE_ADDR`, and run inside
//! the toolchain image (`make fips-toolchain`) so the host needs podman and
//! nothing else; `--host-cargo` runs them with this host's cargo instead.
//! Finally the container's log must carry the startup line that reports the
//! provider and the kernel flag as FIPS.
//!
//! This is the check against the bits that ship: the same image the static
//! checks built and scanned, not a rebuild.

use std::{
    net::TcpStream,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

use clap::Parser;
use openssl::{
    asn1::Asn1Time,
    bn::BigNum,
    ec::{EcGroup, EcKey},
    error::ErrorStack,
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    x509::{
        X509, X509Builder, X509NameBuilder,
        extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName},
    },
};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// The listener port inside the container.
const CONTAINER_PORT: u16 = 8_443;

/// Where the probe's files are mounted inside both containers.
const PROBE_MOUNT: &str = "/probe";

/// How long the image gets to come up.
const STARTUP_DEADLINE: Duration = Duration::from_secs(30);

/// The named volumes `make test-fips-host` uses, shared so a probe after it
/// is incremental: the cargo home (the image's is root-owned, and the
/// container runs as the invoking user) and the target directory.
const CARGO_VOLUME: &str = "praxis-fips-host-cargo";
/// The target directory volume.
const TARGET_VOLUME: &str = "praxis-fips-host-target";

/// The tests to run: the listener probes of the FIPS module.
const TEST_FILTER: &str = "fips::listener_";

// -----------------------------------------------------------------------------
// CLI Arguments
// -----------------------------------------------------------------------------

/// CLI arguments for `cargo xtask fips runtime-probe`.
#[derive(Parser)]
pub(crate) struct Args {
    /// The FIPS runtime image to probe, as podman names it.
    image: String,

    /// The toolchain image the probe tests run in (`make fips-toolchain`).
    #[arg(long, default_value = "praxis-fips-toolchain", value_name = "IMAGE")]
    toolchain_image: String,

    /// Run the probe tests with this host's cargo instead of the toolchain
    /// image.
    #[arg(long)]
    host_cargo: bool,

    /// Also write the container's log here.
    #[arg(long, value_name = "FILE")]
    log: Option<PathBuf>,
}

// -----------------------------------------------------------------------------
// Entry Point
// -----------------------------------------------------------------------------

/// Probe the image; exit 1 when any step fails.
pub(crate) fn run(args: &Args) {
    if let Err(reason) = probe(args) {
        eprintln!("fips-runtime-probe: FAIL: {reason}");
        std::process::exit(1);
    }
}

/// The steps in order.
fn probe(args: &Args) -> Result<(), String> {
    let work = tempfile::tempdir().map_err(|err| format!("cannot create a temporary directory: {err}"))?;
    // The image runs as an unprivileged user that owns nothing on the mount,
    // so the directory and its files must be world-readable.
    set_mode(work.path(), 0o755)?;
    generate_certificates(work.path())?;
    write_config(work.path())?;
    let port = free_port()?;
    let container = Container::start(&args.image, work.path(), port)?;
    container.wait_until_serving(port)?;
    println!(
        "fips-runtime-probe: ok: {} serves TLS on 127.0.0.1:{port} under PRAXIS_REQUIRE_FIPS=1",
        args.image
    );
    let probes = run_probe_tests(args, work.path(), port);
    // The log is kept whether or not the probes passed; it is what explains a
    // failure.
    let log = container.logs()?;
    if let Some(path) = &args.log {
        std::fs::write(path, &log).map_err(|err| format!("cannot write {}: {err}", path.display()))?;
    }
    probes?;
    println!("fips-runtime-probe: ok: the listener probes passed against the image");
    let line = status_line(&log)?;
    println!("fips-runtime-probe: ok: {line}");
    Ok(())
}

/// Set a path's permission bits.
fn set_mode(path: &Path, mode: u32) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|err| format!("cannot set the mode of {}: {err}", path.display()))
}

// -----------------------------------------------------------------------------
// Container
// -----------------------------------------------------------------------------

/// The running image, removed when dropped.
struct Container {
    /// Its podman name.
    name: String,
}

impl Container {
    /// Start the image with the probe listener, publishing it on loopback.
    fn start(image: &str, work: &Path, port: u16) -> Result<Self, String> {
        let name = format!("praxis-fips-probe-{}", std::process::id());
        let output = Command::new("podman")
            .args(["run", "--detach", "--name", &name, "--security-opt", "label=disable"])
            .args(["--publish", &format!("127.0.0.1:{port}:{CONTAINER_PORT}")])
            .args(["--volume", &format!("{}:{PROBE_MOUNT}:ro", work.display())])
            .args(["--env", "PRAXIS_REQUIRE_FIPS=1", "--entrypoint", "praxis", image])
            .args(["-c", &format!("{PROBE_MOUNT}/config.yaml")])
            .output()
            .map_err(|err| format!("podman is required to run the image ({err})"))?;
        if !output.status.success() {
            return Err(format!(
                "podman could not start {image}: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        Ok(Self { name })
    }

    /// Wait until the listener completes a TLS handshake, or the container
    /// exits. A TCP connect is not enough: rootless podman's port forwarder
    /// accepts connections whether or not anything listens behind it.
    fn wait_until_serving(&self, port: u16) -> Result<(), String> {
        let deadline = Instant::now() + STARTUP_DEADLINE;
        loop {
            if !self.running()? {
                return Err(format!(
                    "the image exited instead of serving; under PRAXIS_REQUIRE_FIPS=1 that means the host is not in \
                     FIPS mode. Its log:\n{}",
                    self.logs()?
                ));
            }
            if handshake_completes(port) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "the image did not serve on 127.0.0.1:{port} within {STARTUP_DEADLINE:?}. Its log:\n{}",
                    self.logs()?
                ));
            }
            #[expect(
                clippy::disallowed_methods,
                reason = "a synchronous command-line tool with no async runtime"
            )]
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    /// Whether podman still reports the container running.
    fn running(&self) -> Result<bool, String> {
        let output = Command::new("podman")
            .args(["inspect", "--format", "{{.State.Running}}", &self.name])
            .output()
            .map_err(|err| format!("podman inspect: {err}"))?;
        Ok(String::from_utf8_lossy(&output.stdout).trim() == "true")
    }

    /// The container's log so far, both streams.
    fn logs(&self) -> Result<String, String> {
        let output = Command::new("podman")
            .args(["logs", &self.name])
            .output()
            .map_err(|err| format!("podman logs: {err}"))?;
        let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
        text.push_str(&String::from_utf8_lossy(&output.stderr));
        Ok(text)
    }
}

impl Drop for Container {
    fn drop(&mut self) {
        let _removed = Command::new("podman")
            .args(["rm", "--force", "--time", "5", &self.name])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

/// Whether a TLS handshake with the published port completes, through the
/// host's OpenSSL without verifying the probe certificate: only readiness
/// is being asked, the probes check the rest.
fn handshake_completes(port: u16) -> bool {
    use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
    let Ok(stream) = TcpStream::connect(("127.0.0.1", port)) else {
        return false;
    };
    let Ok(mut builder) = SslConnector::builder(SslMethod::tls_client()) else {
        return false;
    };
    builder.set_verify(SslVerifyMode::NONE);
    builder.build().connect("localhost", stream).is_ok()
}

// -----------------------------------------------------------------------------
// Probe Tests
// -----------------------------------------------------------------------------

/// Run the listener probes against the published port.
fn run_probe_tests(args: &Args, work: &Path, port: u16) -> Result<(), String> {
    let addr = format!("127.0.0.1:{port}");
    let status = if args.host_cargo {
        host_cargo_test(&addr, work)
    } else {
        toolchain_cargo_test(&args.toolchain_image, &addr, work)
    }
    .map_err(|err| format!("cannot run the probe tests: {err}"))?;
    if status.success() {
        Ok(())
    } else {
        Err("the listener probes failed against the image (see the test output above)".to_owned())
    }
}

/// The probe tests with this host's cargo.
fn host_cargo_test(addr: &str, work: &Path) -> std::io::Result<std::process::ExitStatus> {
    Command::new(env!("CARGO"))
        .current_dir(workspace_root())
        .args(["test", "--target-dir", "target/fips", "--no-default-features"])
        .args(["-p", "praxis-tests-integration", "--test", "suite", "--", TEST_FILTER])
        .env("PRAXIS_FIPS_HOST", "1")
        .env("PRAXIS_FIPS_PROBE_ADDR", addr)
        .env("PRAXIS_FIPS_PROBE_CA", work.join("ca.pem"))
        .status()
}

/// The probe tests inside the toolchain image, on the host network so the
/// published port is reachable, with the checkout bind-mounted and the same
/// cache volumes as `make test-fips-host`.
fn toolchain_cargo_test(toolchain_image: &str, addr: &str, work: &Path) -> std::io::Result<std::process::ExitStatus> {
    Command::new("podman")
        .args(["run", "--rm", "--network", "host", "--userns=keep-id"])
        .args(["--security-opt", "label=disable"])
        .args([
            "--volume",
            &format!("{}:/src", workspace_root().display()),
            "--workdir",
            "/src",
        ])
        .args(["--volume", &format!("{CARGO_VOLUME}:/cargo:U")])
        .args(["--volume", &format!("{TARGET_VOLUME}:/target")])
        .args(["--volume", &format!("{}:{PROBE_MOUNT}:ro", work.display())])
        .args(["--env", "PRAXIS_FIPS_HOST=1", "--env", "PRAXIS_REQUIRE_FIPS=1"])
        .args(["--env", &format!("PRAXIS_FIPS_PROBE_ADDR={addr}")])
        .args(["--env", &format!("PRAXIS_FIPS_PROBE_CA={PROBE_MOUNT}/ca.pem")])
        .args(["--env", "CARGO_TERM_COLOR=always", toolchain_image])
        .args(["cargo", "test", "--target-dir", "/target", "--no-default-features"])
        .args([
            "-p",
            "praxis-tests-integration",
            "--test",
            "suite",
            "--ignore-rust-version",
        ])
        .args(["--", TEST_FILTER])
        .status()
}

/// The workspace root, two levels up from xtask's manifest.
fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
}

// -----------------------------------------------------------------------------
// Startup Line
// -----------------------------------------------------------------------------

/// The startup status line, which must report FIPS on both signals.
fn status_line(log: &str) -> Result<String, String> {
    let clean = strip_ansi(log);
    let line = clean
        .lines()
        .find(|line| line.contains("installed rustls crypto provider"))
        .ok_or_else(|| format!("the startup status line is missing from the image's log:\n{clean}"))?;
    for field in [
        "provider=\"openssl\"",
        "provider_fips=true",
        "kernel_fips=Some(true)",
        "fips_required=true",
    ] {
        if !line.contains(field) {
            return Err(format!("the startup status line lacks {field}: {line}"));
        }
    }
    Ok(line.trim().to_owned())
}

/// Remove ANSI escape sequences from the log.
fn strip_ansi(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(ch) = chars.next() {
        if ch == '\u{1b}' {
            for next in chars.by_ref() {
                if next == 'm' {
                    break;
                }
            }
        } else {
            out.push(ch);
        }
    }
    out
}

// -----------------------------------------------------------------------------
// Probe Files
// -----------------------------------------------------------------------------

/// The listener config, at the paths the container sees.
fn write_config(work: &Path) -> Result<(), String> {
    let config = format!(
        "listeners:\n  - name: probe\n    address: \"0.0.0.0:{CONTAINER_PORT}\"\n    filter_chains: [main]\n    tls:\n      \
         certificates:\n        - cert_path: {PROBE_MOUNT}/cert.pem\n          key_path: {PROBE_MOUNT}/key.pem\n\
         filter_chains:\n  - name: main\n    filters:\n      - filter: static_response\n        status: 200\n        \
         body: fips\n"
    );
    std::fs::write(work.join("config.yaml"), config).map_err(|err| format!("cannot write the probe config: {err}"))
}

/// A CA and a `localhost` leaf it signed, valid for a day, as `ca.pem`,
/// `cert.pem` and `key.pem`. The key is world-readable on purpose: the image
/// runs as an unprivileged user that owns nothing on the mount.
fn generate_certificates(work: &Path) -> Result<(), String> {
    let ca_key = p256_key()?;
    let ca = certificate(&ca_key, &ca_key, "Praxis FIPS Probe CA", None)?;
    let leaf_key = p256_key()?;
    let leaf = certificate(&leaf_key, &ca_key, "localhost", Some(&ca))?;
    let ca_pem = ca.to_pem().map_err(ossl)?;
    let leaf_pem = leaf.to_pem().map_err(ossl)?;
    let key_pem = leaf_key.private_key_to_pem_pkcs8().map_err(ossl)?;
    for (name, contents) in [("ca.pem", ca_pem), ("cert.pem", leaf_pem), ("key.pem", key_pem)] {
        let path = work.join(name);
        std::fs::write(&path, contents).map_err(|err| format!("cannot write {name}: {err}"))?;
        set_mode(&path, 0o644)?;
    }
    Ok(())
}

/// A fresh P-256 key.
fn p256_key() -> Result<PKey<Private>, String> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).map_err(ossl)?;
    PKey::from_ec_key(EcKey::generate(&group).map_err(ossl)?).map_err(ossl)
}

/// A certificate for `subject_key` named `common_name`, signed by
/// `signing_key`: a CA when `issuer` is `None` (self-signed), otherwise a
/// server leaf for `localhost` issued by it.
fn certificate(
    subject_key: &PKey<Private>,
    signing_key: &PKey<Private>,
    common_name: &str,
    issuer: Option<&X509>,
) -> Result<X509, String> {
    let mut name = X509NameBuilder::new().map_err(ossl)?;
    name.append_entry_by_text("CN", common_name).map_err(ossl)?;
    let name = name.build();
    let mut builder = X509Builder::new().map_err(ossl)?;
    builder.set_version(2).map_err(ossl)?;
    let serial = BigNum::from_u32(std::process::id().max(1))
        .map_err(ossl)?
        .to_asn1_integer()
        .map_err(ossl)?;
    builder.set_serial_number(&serial).map_err(ossl)?;
    builder.set_subject_name(&name).map_err(ossl)?;
    let issuer_name = issuer.map_or(&*name, |ca| ca.subject_name());
    builder.set_issuer_name(issuer_name).map_err(ossl)?;
    builder.set_pubkey(subject_key).map_err(ossl)?;
    let not_before = Asn1Time::days_from_now(0).map_err(ossl)?;
    builder.set_not_before(&not_before).map_err(ossl)?;
    let not_after = Asn1Time::days_from_now(1).map_err(ossl)?;
    builder.set_not_after(&not_after).map_err(ossl)?;
    add_extensions(&mut builder, issuer)?;
    builder.sign(signing_key, MessageDigest::sha256()).map_err(ossl)?;
    Ok(builder.build())
}

/// CA extensions for a self-signed certificate, server extensions for a
/// leaf.
fn add_extensions(builder: &mut X509Builder, issuer: Option<&X509>) -> Result<(), String> {
    match issuer {
        None => {
            let constraints = BasicConstraints::new().critical().ca().build().map_err(ossl)?;
            builder.append_extension(constraints).map_err(ossl)?;
            let usage = KeyUsage::new()
                .critical()
                .key_cert_sign()
                .crl_sign()
                .build()
                .map_err(ossl)?;
            builder.append_extension(usage).map_err(ossl)?;
        },
        Some(ca) => {
            let san = {
                let context = builder.x509v3_context(Some(ca), None);
                SubjectAlternativeName::new()
                    .dns("localhost")
                    .ip("127.0.0.1")
                    .build(&context)
                    .map_err(ossl)?
            };
            builder.append_extension(san).map_err(ossl)?;
            let usage = ExtendedKeyUsage::new().server_auth().build().map_err(ossl)?;
            builder.append_extension(usage).map_err(ossl)?;
        },
    }
    Ok(())
}

/// An OpenSSL error as text, shaped for `map_err`.
#[expect(
    clippy::needless_pass_by_value,
    reason = "a `map_err` adapter takes the error by value"
)]
fn ossl(err: ErrorStack) -> String {
    format!("openssl: {err}")
}

/// A free loopback port.
fn free_port() -> Result<u16, String> {
    std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|listener| listener.local_addr())
        .map(|addr| addr.port())
        .map_err(|err| format!("cannot find a free port: {err}"))
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_status_line_must_report_fips_on_both_signals() {
        let good = "\u{1b}[2m2026-09-24T00:00:00Z\u{1b}[0m INFO praxis::server: installed rustls crypto provider \
                    provider=\"openssl\" provider_fips=true kernel_fips=Some(true) fips_required=true\n";
        assert!(status_line(good).is_ok_and(|line| line.contains("kernel_fips=Some(true)")));
        let bad = "installed rustls crypto provider provider=\"openssl\" provider_fips=false kernel_fips=Some(false) \
                   fips_required=true\n";
        let err = status_line(bad).expect_err("not FIPS");
        assert!(err.contains("provider_fips=true"), "{err}");
        assert!(status_line("starting server\n").is_err(), "no line at all");
    }

    #[test]
    fn the_probe_certificates_chain_and_name_localhost() {
        let work = tempfile::tempdir().expect("temp dir");
        generate_certificates(work.path()).expect("certificates");
        let ca = X509::from_pem(&std::fs::read(work.path().join("ca.pem")).expect("ca")).expect("parse ca");
        let leaf = X509::from_pem(&std::fs::read(work.path().join("cert.pem")).expect("leaf")).expect("parse leaf");
        assert!(
            leaf.verify(&ca.public_key().expect("ca key")).expect("verify"),
            "the leaf is signed by the CA"
        );
        let names: Vec<String> = leaf
            .subject_alt_names()
            .expect("SAN")
            .iter()
            .filter_map(|name| name.dnsname().map(str::to_owned))
            .collect();
        assert_eq!(names, vec!["localhost".to_owned()]);
        let key = PKey::private_key_from_pem(&std::fs::read(work.path().join("key.pem")).expect("key")).expect("parse");
        assert!(
            key.public_eq(&leaf.public_key().expect("leaf key")),
            "the key matches the leaf"
        );
    }

    #[test]
    fn the_config_names_the_mounted_files() {
        let work = tempfile::tempdir().expect("temp dir");
        write_config(work.path()).expect("config");
        let config = std::fs::read_to_string(work.path().join("config.yaml")).expect("read");
        assert!(config.contains("cert_path: /probe/cert.pem"), "{config}");
        assert!(config.contains(&format!("0.0.0.0:{CONTAINER_PORT}")), "{config}");
    }
}
