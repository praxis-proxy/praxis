// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Environment section of the report: what the host offers (OpenSSL and its
//! FIPS provider module, kernel FIPS mode, the toolchain).

use std::{
    io::Write as _,
    path::Path,
    process::{Command, Stdio},
};

use super::{
    assets,
    report::{Context, Report},
};

/// Where the FIPS provider module lives on the distributions we care about.
const FIPS_MODULE_PATHS: &[&str] = &[
    "/usr/lib64/ossl-modules/fips.so",
    "/usr/lib/x86_64-linux-gnu/ossl-modules/fips.so",
];

/// Append the environment section.
pub(crate) fn section(report: &mut Report, context: &Context) {
    report.section("Environment");
    report.info(&format!(
        "host: {}",
        first_line("uname", &["-srm"]).unwrap_or_else(|| "unknown".to_owned())
    ));
    if let Some(name) = os_pretty_name() {
        report.info(&format!("os: {name}"));
    }
    let openssl = first_line("openssl", &["version"]);
    if let Some(version) = &openssl {
        report.info(&format!("openssl: {version}"));
    }
    for line in rpm_versions() {
        report.info(&format!("rpm: {line}"));
    }
    let module = fips_module();
    report.info(&module.map_or_else(
        || "fips provider module: not installed".to_owned(),
        |path| format!("fips provider module: {path}"),
    ));
    report.info(&format!("kernel fips_enabled: {}", kernel_flag()));
    if module.is_some() && openssl.is_some() {
        report.info(&provider_activation());
    }
    if let Some(toolchain) = toolchain() {
        report.info(&format!("toolchain: {toolchain}"));
    }
    report.info(&format!("build assessed: praxis-proxy, {}", context.feature_label()));
}

/// The first line of a command's standard output, when it runs successfully.
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

/// `PRETTY_NAME` from `/etc/os-release`.
fn os_pretty_name() -> Option<String> {
    let contents = std::fs::read_to_string("/etc/os-release").ok()?;
    contents
        .lines()
        .find_map(|line| line.strip_prefix("PRETTY_NAME="))
        .map(|value| value.trim_matches('"').to_owned())
}

/// What rpm says about the OpenSSL packages, on hosts that have rpm.
fn rpm_versions() -> Vec<String> {
    let Ok(output) = Command::new("rpm")
        .args(["-q", "openssl-libs", "openssl-fips-provider-so"])
        .output()
    else {
        return Vec::new();
    };
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Where the FIPS provider module is installed, if anywhere.
fn fips_module() -> Option<&'static str> {
    FIPS_MODULE_PATHS.iter().copied().find(|path| Path::new(path).is_file())
}

/// The kernel's FIPS flag, or `n/a` where it cannot be read.
fn kernel_flag() -> String {
    std::fs::read_to_string("/proc/sys/crypto/fips_enabled")
        .map_or_else(|_| "n/a".to_owned(), |flag| flag.trim().to_owned())
}

/// Whether the FIPS provider can be activated for a single process here: it
/// must load under the bundled configuration and refuse MD5 once loaded.
fn provider_activation() -> String {
    let activated = provider_config().is_some_and(|cnf| provider_listed(cnf.path()) && !md5_works(cnf.path()));
    if activated {
        "fips provider can be activated per process here (MD5 refused under it): yes".to_owned()
    } else {
        "fips provider can be activated per process here: no".to_owned()
    }
}

/// The bundled provider configuration, written to a temporary file.
fn provider_config() -> Option<tempfile::NamedTempFile> {
    let mut file = tempfile::NamedTempFile::new().ok()?;
    file.write_all(assets::FIPS_PROVIDER_CNF.as_bytes()).ok()?;
    Some(file)
}

/// Whether `openssl list -providers` under the configuration lists `fips`.
fn provider_listed(cnf: &Path) -> bool {
    Command::new("openssl")
        .args(["list", "-providers"])
        .env("OPENSSL_CONF", cnf)
        .output()
        .is_ok_and(|output| {
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .any(|line| line == "  fips")
        })
}

/// Whether MD5 still works under the configuration (it must not under the
/// FIPS provider).
fn md5_works(cnf: &Path) -> bool {
    let Ok(mut child) = Command::new("openssl")
        .args(["dgst", "-md5"])
        .env("OPENSSL_CONF", cnf)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    else {
        return false;
    };
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(b"abc").ok();
    }
    child.wait().is_ok_and(|status| status.success())
}

/// The cargo and rustc versions.
fn toolchain() -> Option<String> {
    let cargo = first_line("cargo", &["--version"])?;
    let rustc = first_line("rustc", &["--version"]).unwrap_or_default();
    Some(format!("{cargo}, {rustc}"))
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_line_reports_only_successful_commands() {
        assert!(
            first_line("true", &[]).is_some(),
            "a successful command yields its (empty) first line"
        );
        assert!(first_line("false", &[]).is_none(), "a failing command yields nothing");
        assert!(
            first_line("praxis-no-such-program", &[]).is_none(),
            "a missing program yields nothing"
        );
    }

    #[test]
    fn the_kernel_flag_is_a_digit_or_not_available() {
        let flag = kernel_flag();
        assert!(
            flag == "0" || flag == "1" || flag == "n/a",
            "unexpected kernel flag {flag:?}"
        );
    }
}
