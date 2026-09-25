// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! `cargo xtask fips host-check`: is this host in FIPS mode the way the
//! module's Security Policy requires, and does the FIPS image carry a
//! validated build of the module?
//!
//! The runtime proof the hosted checks cannot give starts with the host: the
//! kernel flag that activates the module, the boot parameter that set it,
//! the FIPS crypto policy, and the module the host's OpenSSL actually loads.
//! With `--image`, the same questions are asked of the runtime image, which
//! carries its own copy of the module: the crypto policy podman propagates
//! into the container and the build of `fips.so` inside it, looked up in
//! `certified-modules.json`.
//!
//! The result is an attestation: text on standard output (and `--out`), JSON
//! with `--json`, one `FAIL` per unmet requirement and exit status 1 when
//! there is any. A module build that is in validation is a `WARN` unless
//! `--require-certified` makes it a failure.

use std::{path::PathBuf, process::Command};

use clap::Parser;
use serde_json::{Map, Value, json};

use super::certified;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Where the module reports its version, in every build Red Hat ships.
const MODULE_PATH: &str = "/usr/lib64/ossl-modules/fips.so";

/// A module version string as Red Hat's builds report it.
const VERSION_PATTERN: &str = r"[0-9]+\.[0-9]+\.[0-9]+-[0-9a-f]{16}";

// -----------------------------------------------------------------------------
// CLI Arguments
// -----------------------------------------------------------------------------

/// CLI arguments for `cargo xtask fips host-check`.
#[derive(Parser)]
pub(crate) struct Args {
    /// A FIPS runtime image to check as well, as podman names it.
    #[arg(long, value_name = "IMAGE")]
    image: Option<String>,

    /// Fail unless every module found is on an active certificate; without
    /// it a module in validation is a warning.
    #[arg(long)]
    require_certified: bool,

    /// Also write the text attestation here.
    #[arg(long, value_name = "FILE")]
    out: Option<PathBuf>,

    /// Write a JSON attestation here.
    #[arg(long, value_name = "FILE")]
    json: Option<PathBuf>,
}

// -----------------------------------------------------------------------------
// Entry Point
// -----------------------------------------------------------------------------

/// Run every check, print the attestation, exit 1 on any failure.
pub(crate) fn run(args: &Args) {
    let mut attestation = Attestation::default();
    host_checks(&mut attestation, args.require_certified);
    if let Some(image) = &args.image {
        image_checks(&mut attestation, image, args.require_certified);
    }
    attestation.summary();
    print!("{}", attestation.text());
    if let Some(path) = &args.out
        && let Err(err) = std::fs::write(path, attestation.text())
    {
        eprintln!("fips-host-check: cannot write {}: {err}", path.display());
        std::process::exit(1);
    }
    if let Some(path) = &args.json
        && let Err(err) = std::fs::write(path, attestation.json())
    {
        eprintln!("fips-host-check: cannot write {}: {err}", path.display());
        std::process::exit(1);
    }
    if attestation.failures > 0 {
        std::process::exit(1);
    }
}

// -----------------------------------------------------------------------------
// Attestation
// -----------------------------------------------------------------------------

/// The attestation under construction.
#[derive(Default)]
struct Attestation {
    /// Lines, in order.
    lines: Vec<String>,
    /// How many checks failed.
    failures: usize,
    /// How many warnings were emitted.
    warnings: usize,
    /// The facts, for the JSON form.
    facts: Map<String, Value>,
}

impl Attestation {
    /// Start a section.
    fn section(&mut self, title: &str) {
        self.lines.push(String::new());
        self.lines.push(format!("== {title}"));
    }

    /// A check that passed.
    fn ok(&mut self, message: &str) {
        self.lines.push(format!("  ok    {message}"));
    }

    /// Context.
    fn info(&mut self, message: &str) {
        self.lines.push(format!("  info  {message}"));
    }

    /// Something to know that does not fail the check.
    fn warn(&mut self, message: &str) {
        self.lines.push(format!("  WARN  {message}"));
        self.warnings += 1;
    }

    /// A requirement that is not met.
    fn fail(&mut self, message: &str) {
        self.lines.push(format!("  FAIL  {message}"));
        self.failures += 1;
    }

    /// Record a fact for the JSON form, under a dotted key.
    fn fact(&mut self, key: &str, value: impl Into<Value>) {
        self.facts.insert(key.to_owned(), value.into());
    }

    /// The closing verdict.
    fn summary(&mut self) {
        self.section("Summary");
        let line = if self.failures == 0 {
            format!(
                "RESULT: FIPS host attested, {} warning(s). Keep this attestation with the run it belongs to.",
                self.warnings
            )
        } else {
            format!(
                "RESULT: {} requirement(s) not met, {} warning(s). This is not a FIPS host as the module's Security \
                 Policy requires it (docs/operating/fips.md).",
                self.failures, self.warnings
            )
        };
        self.lines.push(format!("  {line}"));
    }

    /// The text form.
    fn text(&self) -> String {
        let mut text = self.lines.join("\n");
        text.push('\n');
        text
    }

    /// The JSON form.
    fn json(&self) -> String {
        let generated = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs());
        let document = json!({
            "generated_unix": generated,
            "failures": self.failures,
            "warnings": self.warnings,
            "facts": self.facts,
        });
        serde_json::to_string_pretty(&document).unwrap_or_default()
    }
}

// -----------------------------------------------------------------------------
// Host
// -----------------------------------------------------------------------------

/// The host: kernel flag, boot parameter, crypto policy, loaded module.
fn host_checks(attestation: &mut Attestation, require_certified: bool) {
    attestation.section("Host");
    if let Some(name) = os_release() {
        attestation.info(&format!("os: {name}"));
        attestation.fact("host.os", name);
    }
    if let Some(kernel) = first_line("uname", &["-r"]) {
        attestation.info(&format!("kernel: {kernel}"));
        attestation.fact("host.kernel", kernel);
    }
    kernel_flag(attestation);
    boot_parameter(attestation);
    crypto_policy(attestation);
    fips_mode_setup(attestation);
    host_module(attestation, require_certified);
}

/// `/proc/sys/crypto/fips_enabled` must read `1`.
fn kernel_flag(attestation: &mut Attestation) {
    let flag = std::fs::read_to_string("/proc/sys/crypto/fips_enabled")
        .map_or_else(|_| "unreadable".to_owned(), |flag| flag.trim().to_owned());
    attestation.fact("host.kernel_fips", flag.clone());
    if flag == "1" {
        attestation.ok("kernel is in FIPS mode (/proc/sys/crypto/fips_enabled is 1)");
    } else {
        attestation.fail(&format!(
            "kernel is not in FIPS mode (/proc/sys/crypto/fips_enabled is {flag}); enable FIPS mode at installation \
             or with fips-mode-setup --enable and reboot"
        ));
    }
}

/// The kernel command line must carry `fips=1`, which both ways of enabling
/// FIPS mode set and the Security Policy names.
fn boot_parameter(attestation: &mut Attestation) {
    let cmdline = std::fs::read_to_string("/proc/cmdline").unwrap_or_default();
    let set = cmdline.split_whitespace().any(|token| token == "fips=1");
    attestation.fact("host.cmdline_fips", set);
    if set {
        attestation.ok("kernel command line carries fips=1");
    } else {
        attestation.fail("kernel command line does not carry fips=1");
    }
}

/// The system-wide crypto policy must be FIPS.
fn crypto_policy(attestation: &mut Attestation) {
    let policy = crypto_policy_from(&std::fs::read_to_string("/etc/crypto-policies/config").unwrap_or_default());
    attestation.fact("host.crypto_policy", policy.clone());
    if policy.starts_with("FIPS") {
        attestation.ok(&format!("crypto policy is {policy}"));
    } else {
        attestation.fail(&format!(
            "crypto policy is {policy:?}, not FIPS (/etc/crypto-policies/config)"
        ));
    }
}

/// The policy named in a crypto-policies config file: its first line that is
/// not blank or a comment.
fn crypto_policy_from(contents: &str) -> String {
    contents
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && !line.starts_with('#'))
        .unwrap_or("(none)")
        .to_owned()
}

/// `fips-mode-setup --check`, the check the Security Policy names, where the
/// tool exists.
fn fips_mode_setup(attestation: &mut Attestation) {
    match Command::new("fips-mode-setup").arg("--check").output() {
        Err(_) => attestation.info("fips-mode-setup is not installed; the kernel flag above stands in for its check"),
        Ok(output) => {
            let text = String::from_utf8_lossy(&output.stdout).trim().to_owned();
            attestation.fact("host.fips_mode_setup", text.clone());
            if text.contains("FIPS mode is enabled") {
                attestation.ok(&format!("fips-mode-setup --check: {text}"));
            } else {
                attestation.fail(&format!("fips-mode-setup --check: {text}"));
            }
        },
    }
}

/// The module the host's OpenSSL loads: `openssl list -providers` must show
/// the fips provider active, and its version is looked up.
fn host_module(attestation: &mut Attestation, require_certified: bool) {
    let Ok(output) = Command::new("openssl").args(["list", "-providers"]).output() else {
        attestation.fail("openssl is not installed on the host, so the loaded module cannot be read");
        return;
    };
    let listing = String::from_utf8_lossy(&output.stdout);
    match provider_entry(&listing, "fips") {
        Some((version, status)) if status == "active" => {
            attestation.ok(&format!(
                "host OpenSSL loads the fips provider, version {version}, active"
            ));
            attestation.fact("host.module.version", version.clone());
            module_verdict(attestation, "host", &version, require_certified);
        },
        Some((version, status)) => attestation.fail(&format!(
            "host OpenSSL lists the fips provider (version {version}) but its status is {status:?}, not active"
        )),
        None => attestation.fail("host OpenSSL does not list the fips provider; is openssl-fips-provider installed?"),
    }
}

/// The `version` and `status` of the named provider in an `openssl list
/// -providers` listing.
fn provider_entry(listing: &str, provider: &str) -> Option<(String, String)> {
    let mut lines = listing.lines().peekable();
    while let Some(line) = lines.next() {
        if line.trim() != provider {
            continue;
        }
        let mut version = None;
        let mut status = None;
        while let Some(detail) = lines.peek() {
            let detail = detail.trim();
            if !detail.contains(':') || detail == provider {
                break;
            }
            if let Some(value) = detail.strip_prefix("version:") {
                version = Some(value.trim().to_owned());
            } else if let Some(value) = detail.strip_prefix("status:") {
                status = Some(value.trim().to_owned());
            }
            lines.next();
        }
        return Some((version?, status?));
    }
    None
}

/// Record what the list says about a module version, as a pass, a warning
/// or a failure.
fn module_verdict(attestation: &mut Attestation, subject: &str, version: &str, require_certified: bool) {
    let verdict = certified::verdict(version);
    let line = verdict.describe(version);
    attestation.fact(&format!("{subject}.module.certified"), verdict.validated());
    if verdict.validated() {
        attestation.ok(&line);
    } else if require_certified {
        attestation.fail(&line);
    } else {
        attestation.warn(&line);
    }
}

// -----------------------------------------------------------------------------
// Image
// -----------------------------------------------------------------------------

/// The runtime image: the crypto policy podman gives it and the module
/// build it carries.
fn image_checks(attestation: &mut Attestation, image: &str, require_certified: bool) {
    attestation.section(&format!("Image {image}"));
    match image_id(image) {
        Ok(id) => {
            attestation.info(&format!("image id: {id}"));
            attestation.fact("image.reference", image);
            attestation.fact("image.id", id);
        },
        Err(reason) => {
            attestation.fail(&reason);
            return;
        },
    }
    match run_in_image(image, &["cat", "/etc/redhat-release"]) {
        Ok(release) => attestation.info(&format!("release: {}", String::from_utf8_lossy(&release).trim())),
        Err(reason) => attestation.warn(&reason),
    }
    image_crypto_policy(attestation, image);
    image_packages(attestation, image);
    image_module(attestation, image, require_certified);
}

/// The container's crypto policy, which podman sets to FIPS on a FIPS host.
fn image_crypto_policy(attestation: &mut Attestation, image: &str) {
    match run_in_image(image, &["cat", "/etc/crypto-policies/config"]) {
        Ok(contents) => {
            let policy = crypto_policy_from(&String::from_utf8_lossy(&contents));
            attestation.fact("image.crypto_policy", policy.clone());
            if policy.starts_with("FIPS") {
                attestation.ok(&format!(
                    "crypto policy inside the container is {policy} (podman propagated it)"
                ));
            } else {
                attestation.fail(&format!(
                    "crypto policy inside the container is {policy:?}, not FIPS: podman only sets it when the host \
                     is in FIPS mode"
                ));
            }
        },
        Err(reason) => attestation.fail(&reason),
    }
}

/// The OpenSSL packages inside the image, for the record.
fn image_packages(attestation: &mut Attestation, image: &str) {
    match run_in_image(image, &["rpm", "-q", "openssl-libs", "openssl-fips-provider-so"]) {
        Ok(listing) => {
            let packages: Vec<String> = String::from_utf8_lossy(&listing).lines().map(str::to_owned).collect();
            for package in &packages {
                attestation.info(&format!("rpm: {package}"));
            }
            attestation.fact("image.packages", packages);
        },
        Err(reason) => attestation.warn(&reason),
    }
}

/// The build of `fips.so` inside the image, by the version string it carries.
fn image_module(attestation: &mut Attestation, image: &str, require_certified: bool) {
    let module = match run_in_image(image, &["cat", MODULE_PATH]) {
        Ok(bytes) => bytes,
        Err(reason) => {
            attestation.fail(&format!("cannot read {MODULE_PATH} inside the image: {reason}"));
            return;
        },
    };
    match module_version(&module) {
        Some(version) => {
            attestation.ok(&format!("{MODULE_PATH} inside the image reports version {version}"));
            attestation.fact("image.module.version", version.clone());
            module_verdict(attestation, "image", &version, require_certified);
        },
        None => attestation.fail(&format!(
            "{MODULE_PATH} inside the image carries no version string matching {VERSION_PATTERN}"
        )),
    }
}

/// The version string embedded in a module file.
fn module_version(module: &[u8]) -> Option<String> {
    regex::bytes::Regex::new(VERSION_PATTERN)
        .ok()?
        .find(module)
        .map(|found| String::from_utf8_lossy(found.as_bytes()).into_owned())
}

/// The image's id, which also proves it is in podman's store.
fn image_id(image: &str) -> Result<String, String> {
    let output = Command::new("podman")
        .args(["image", "inspect", "--format", "{{.Id}}", image])
        .output()
        .map_err(|err| format!("podman is required to inspect the image ({err})"))?;
    if !output.status.success() {
        return Err(format!(
            "podman does not have '{image}': {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

/// Run a command inside a throwaway container of the image and return its
/// standard output.
fn run_in_image(image: &str, command: &[&str]) -> Result<Vec<u8>, String> {
    let (program, rest) = command.split_first().ok_or("empty command")?;
    let output = Command::new("podman")
        .args(["run", "--rm", "--entrypoint", program, image])
        .args(rest)
        .output()
        .map_err(|err| format!("podman run: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "`{}` failed inside {image}: {}",
            command.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(output.stdout)
}

// -----------------------------------------------------------------------------
// Utilities
// -----------------------------------------------------------------------------

/// `PRETTY_NAME` from `/etc/os-release`.
fn os_release() -> Option<String> {
    std::fs::read_to_string("/etc/os-release")
        .ok()?
        .lines()
        .find_map(|line| line.strip_prefix("PRETTY_NAME="))
        .map(|value| value.trim_matches('"').to_owned())
}

/// The first line of a command's standard output, when it succeeds.
fn first_line(program: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(program).args(args).output().ok()?;
    output.status.success().then(|| {
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .next()
            .unwrap_or("")
            .trim()
            .to_owned()
    })
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const LISTING: &str = "Providers:\n  default\n    name: OpenSSL Default Provider\n    version: 3.5.8\n    status: \
                           active\n  fips\n    name: Red Hat Enterprise Linux 9 - OpenSSL FIPS Provider\n    version: \
                           3.0.7-395c1a240fbfffd8\n    status: active\n";

    #[test]
    fn the_provider_listing_is_parsed_per_provider() {
        assert_eq!(
            provider_entry(LISTING, "fips"),
            Some(("3.0.7-395c1a240fbfffd8".to_owned(), "active".to_owned()))
        );
        assert_eq!(
            provider_entry(LISTING, "default"),
            Some(("3.5.8".to_owned(), "active".to_owned()))
        );
        assert_eq!(provider_entry(LISTING, "legacy"), None);
        assert_eq!(provider_entry("Providers:\n", "fips"), None);
    }

    #[test]
    fn the_module_version_is_found_in_a_binary() {
        let mut blob = vec![0_u8, 1, 2];
        blob.extend_from_slice(b"Red Hat Enterprise Linux 9 - OpenSSL FIPS Provider\0");
        blob.extend_from_slice(b"3.0.7-cda111b5812c30d4\0");
        assert_eq!(module_version(&blob).as_deref(), Some("3.0.7-cda111b5812c30d4"));
        assert_eq!(module_version(b"3.0.7 without a hash"), None);
    }

    #[test]
    fn the_crypto_policy_is_the_first_real_line() {
        assert_eq!(crypto_policy_from("# comment\n\nFIPS\n"), "FIPS");
        assert_eq!(crypto_policy_from("FIPS:OSPP\n"), "FIPS:OSPP");
        assert_eq!(crypto_policy_from("DEFAULT\n"), "DEFAULT");
        assert_eq!(crypto_policy_from(""), "(none)");
    }

    #[test]
    fn the_attestation_counts_and_renders() {
        let mut attestation = Attestation::default();
        attestation.section("Host");
        attestation.ok("fine");
        attestation.warn("hmm");
        attestation.fail("no");
        attestation.fact("host.kernel_fips", "1");
        attestation.summary();
        let text = attestation.text();
        assert!(
            text.contains("== Host\n  ok    fine\n  WARN  hmm\n  FAIL  no\n"),
            "{text}"
        );
        assert!(text.contains("1 requirement(s) not met, 1 warning(s)"), "{text}");
        let json: Value = serde_json::from_str(&attestation.json()).expect("valid json");
        assert_eq!(json["failures"], 1);
        assert_eq!(json["facts"]["host.kernel_fips"], "1");
    }
}
