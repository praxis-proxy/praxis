// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Binary section of the report: the shipped binary must link the system
//! libcrypto dynamically, define no symbol of a bundled crypto backend, import
//! OpenSSL, and carry the cargo-auditable manifest and the rustc producer
//! string.

use std::{collections::BTreeMap, io::Read as _, path::Path, process::Command};

use object::{Object as _, ObjectSection as _, ObjectSymbol as _};

use super::{
    graph::DENIED,
    report::{Finding, Report},
};

/// Defined-symbol prefixes that identify a bundled crypto backend
/// (check-payload's list).
const BACKEND_PREFIXES: &[&str] = &["ring_core_", "GFp_", "aws_lc_", "AWSLC_", "BORINGSSL_", "OPENSSL_"];

/// Imported-symbol prefixes that show calls into libcrypto and libssl.
const OPENSSL_PREFIXES: &[&str] = &["EVP_", "SSL_", "OSSL_", "RAND_"];

/// Append the binary section.
pub(crate) fn section(report: &mut Report, binary: Option<&Path>) {
    report.section("Binary");
    let Some(binary) = binary else {
        report.warn("no binary given; build one (make release-fips) and pass its path");
        return;
    };
    if !binary.is_file() {
        report.fail(Finding {
            title: "binary not found".to_owned(),
            why: "the binary checks cannot pass without a binary to check".to_owned(),
            location: binary.display().to_string(),
            fix: "build it first (make release-fips) or pass the right path".to_owned(),
        });
        return;
    }
    report.info(&format!("path: {}", binary.display()));
    linkage(report, binary);
    let Ok(data) = std::fs::read(binary) else {
        report.warn("could not read the binary; ELF checks skipped");
        return;
    };
    let Ok(file) = object::File::parse(&*data) else {
        report.warn("not an ELF file; ELF checks skipped");
        return;
    };
    defined_symbols(report, &file);
    imports(report, &file);
    manifest(report, &file, binary);
    producer(report, &file);
}

// -----------------------------------------------------------------------------
// Dynamic Linkage
// -----------------------------------------------------------------------------

/// Which libcrypto the dynamic loader resolves, according to ldd.
fn linkage(report: &mut Report, binary: &Path) {
    let Ok(output) = Command::new("ldd").arg(binary).output() else {
        report.warn("ldd not found; dynamic linkage not checked");
        return;
    };
    let ldd = String::from_utf8_lossy(&output.stdout);
    if ldd.lines().any(is_system_libcrypto) {
        report.ok("dynamically links the system libcrypto.so.3");
        report.info(&openssl_lines(&ldd));
    } else if ldd.contains("libcrypto") {
        report.fail(Finding {
            title: "links a libcrypto that is not the system one".to_owned(),
            why: "only the OS-provided libcrypto.so.3 (the openssl-libs RPM) contains the validated module".to_owned(),
            location: openssl_lines(&ldd),
            fix: "build against the system OpenSSL (OPENSSL_NO_VENDOR=1) and ship on UBI".to_owned(),
        });
    } else {
        report.fail(missing_libcrypto());
    }
}

/// Whether an ldd line resolves libcrypto to the system library.
fn is_system_libcrypto(line: &str) -> bool {
    line.contains("libcrypto.so.3 => /lib64/") || line.contains("libcrypto.so.3 => /usr/lib64/")
}

/// The ldd lines about libssl and libcrypto, joined on one line.
fn openssl_lines(ldd: &str) -> String {
    ldd.lines()
        .filter(|line| line.contains("libssl") || line.contains("libcrypto"))
        .map(str::trim)
        .collect::<Vec<_>>()
        .join("; ")
}

/// The finding for a binary that does not link libcrypto at all.
fn missing_libcrypto() -> Finding {
    Finding {
        title: "does not link libcrypto.so.3 at all".to_owned(),
        why: "no cryptography can be reaching the RHEL OpenSSL FIPS module; the binary carries its own crypto instead \
              of calling libcrypto"
            .to_owned(),
        location: "crates/tls/src/provider.rs is the only place a provider is chosen; a binary without libcrypto was \
                   built without it (or against a vendored OpenSSL)"
            .to_owned(),
        fix: "build with the workspace's rustls-openssl provider and OPENSSL_NO_VENDOR=1, on a host with the OpenSSL \
              headers"
            .to_owned(),
    }
}

// -----------------------------------------------------------------------------
// Symbols
// -----------------------------------------------------------------------------

/// Symbols defined by a bundled crypto backend must be absent.
fn defined_symbols(report: &mut Report, file: &object::File<'_>) {
    let hits = backend_symbols(file);
    if !hits.is_empty() {
        let summary: Vec<String> = hits.iter().map(|(prefix, count)| format!("{count} {prefix}")).collect();
        report.fail(Finding {
            title: format!("defines symbols of a bundled crypto backend: {}", summary.join(" ")),
            why: "ring_core_/GFp_ mean ring, aws_lc_/AWSLC_ mean aws-lc-sys, BORINGSSL_ means boring-sys, OPENSSL_ \
                  means a statically linked or vendored OpenSSL; the scanner fails on any of them"
                .to_owned(),
            location: "the crate that owns the prefix; see the dependency graph section for who pulls it".to_owned(),
            fix: "remove the crate from the release graph (see above)".to_owned(),
        });
    } else if file.section_by_name(".symtab").is_none() {
        report.info("no bundled-crypto symbols in .dynsym; .symtab is stripped, so this is weaker evidence (the scanner sees the same)");
        report.ok("no bundled-crypto symbols exported");
    } else {
        report.ok("no bundled-crypto symbols defined");
    }
}

/// How many defined symbols (static and dynamic tables) carry each backend
/// prefix.
fn backend_symbols(file: &object::File<'_>) -> BTreeMap<&'static str, usize> {
    let mut hits = BTreeMap::new();
    // nm's rule: anything that is not undefined counts, whatever its type.
    for symbol in file.symbols().chain(file.dynamic_symbols()) {
        if symbol.is_undefined() {
            continue;
        }
        let Ok(name) = symbol.name() else {
            continue;
        };
        if let Some(prefix) = BACKEND_PREFIXES.iter().find(|prefix| name.starts_with(*prefix)) {
            *hits.entry(*prefix).or_insert(0) += 1;
        }
    }
    hits
}

/// Calls into libcrypto and libssl must be present: undefined dynamic symbols
/// that the system library resolves.
fn imports(report: &mut Report, file: &object::File<'_>) {
    let count = file.imports().map_or(0, |imports| {
        imports
            .iter()
            .filter(|import| {
                OPENSSL_PREFIXES
                    .iter()
                    .any(|prefix| import.name().starts_with(prefix.as_bytes()))
            })
            .count()
    });
    if count > 0 {
        report.ok(&format!(
            "imports {count} OpenSSL functions from libcrypto/libssl (undefined symbols resolved by the system library)"
        ));
    } else {
        report.fail(Finding {
            title: "imports no OpenSSL functions".to_owned(),
            why: "a binary that never calls into libcrypto performs all of its cryptography elsewhere".to_owned(),
            location: "same as the libcrypto linkage finding".to_owned(),
            fix: "same as the libcrypto linkage finding".to_owned(),
        });
    }
}

// -----------------------------------------------------------------------------
// Manifest and Producer
// -----------------------------------------------------------------------------

/// The cargo-auditable manifest must be present, readable and free of denied
/// crates.
fn manifest(report: &mut Report, file: &object::File<'_>, binary: &Path) {
    let Some(section) = file.section_by_name(".dep-v0") else {
        report.fail(missing_manifest());
        return;
    };
    report.ok("cargo-auditable manifest (.dep-v0) present");
    let manifest = match section.data().map_err(|err| err.to_string()).and_then(parse_manifest) {
        Ok(manifest) => manifest,
        Err(reason) => {
            report.fail(unreadable_manifest(&reason, binary));
            return;
        },
    };
    if manifest.format != PRECURSOR_FORMAT {
        report.fail(metadata_derived(manifest.format, binary));
    }
    if manifest.denied.is_empty() {
        report.ok("manifest lists no denied crate");
    } else {
        report.fail(denied_manifest(&manifest.denied));
    }
}

/// The finding for a binary without a manifest.
fn missing_manifest() -> Finding {
    Finding {
        title: "no cargo-auditable manifest (.dep-v0 section)".to_owned(),
        why: "without it Red Hat's scanner cannot list the crates compiled in and reports the binary as inconclusive, \
              which fails a gated scan"
            .to_owned(),
        location: "the build command".to_owned(),
        fix: "build with 'make release-fips' (cargo auditable with the SBOM precursor) and keep .dep-v0 through \
              stripping"
            .to_owned(),
    }
}

/// The finding for a manifest that cannot be decoded.
fn unreadable_manifest(reason: &str, binary: &Path) -> Finding {
    Finding {
        title: format!("cargo-auditable manifest is unreadable ({reason})"),
        why: "the scanner treats a present but unparseable manifest as corrupt evidence and fails the binary"
            .to_owned(),
        location: format!("the build that produced {}", binary.display()),
        fix: "rebuild with cargo auditable; do not post-process the .dep-v0 section".to_owned(),
    }
}

/// The finding for a manifest that cargo-auditable built from `cargo
/// metadata` rather than cargo's SBOM precursor.
fn metadata_derived(format: u64, binary: &Path) -> Finding {
    Finding {
        title: format!(
            "manifest was derived from 'cargo metadata', not cargo's SBOM precursor (format {format}, expected \
             {PRECURSOR_FORMAT})"
        ),
        why: "a metadata-derived manifest can list crates the build never compiled (weak features, workspace-wide \
              feature unification), so it is not evidence of what is in the binary"
            .to_owned(),
        location: format!("the build command that produced {}", binary.display()),
        fix: "build with 'make release-fips' or Containerfile.fips (RUSTC_BOOTSTRAP=1 CARGO_BUILD_SBOM=true cargo \
              auditable -Zsbom ...)"
            .to_owned(),
    }
}

/// The finding for a manifest that names denied crates.
fn denied_manifest(listed: &[String]) -> Finding {
    Finding {
        title: format!("manifest lists denied crates: {}", listed.join(" ")),
        why: "this is exactly what the scanner's manifest check reads; it fails on the name alone, whether or not the \
              crate's code was linked"
            .to_owned(),
        location: "the dependency graph section when it has findings; otherwise the manifest was derived from 'cargo \
                   metadata', which lists crates the build never compiled (weak features, workspace-wide feature \
                   unification)"
            .to_owned(),
        fix: "fix the graph findings first; then build with cargo's SBOM precursor the way 'make release-fips' and \
              Containerfile.fips do (RUSTC_BOOTSTRAP=1 CARGO_BUILD_SBOM=true cargo auditable -Zsbom ...)"
            .to_owned(),
    }
}

/// The manifest's `format` when cargo-auditable built it from cargo's SBOM
/// precursor; `cargo metadata` yields 0 (or no field at all).
const PRECURSOR_FORMAT: u64 = 8;

/// What the report needs from a cargo-auditable manifest.
struct Manifest {
    /// The manifest's `format` field, 0 when absent.
    format: u64,
    /// Denied crates among the runtime packages, sorted. Build and dev
    /// packages are ignored, as the scanner ignores them.
    denied: Vec<String>,
}

/// Decompress and parse a `.dep-v0` section.
fn parse_manifest(compressed: &[u8]) -> Result<Manifest, String> {
    let mut json = Vec::new();
    flate2::read::ZlibDecoder::new(compressed)
        .read_to_end(&mut json)
        .map_err(|err| format!("zlib: {err}"))?;
    let manifest: serde_json::Value = serde_json::from_slice(&json).map_err(|err| format!("json: {err}"))?;
    let packages = manifest
        .get("packages")
        .and_then(serde_json::Value::as_array)
        .ok_or("no packages array")?;
    let mut denied: Vec<String> = packages
        .iter()
        .filter(|package| {
            package
                .get("kind")
                .and_then(serde_json::Value::as_str)
                .is_none_or(|kind| kind == "runtime")
        })
        .filter_map(|package| package.get("name").and_then(serde_json::Value::as_str))
        .filter(|name| DENIED.contains(name))
        .map(str::to_owned)
        .collect();
    denied.sort();
    denied.dedup();
    let format = manifest.get("format").and_then(serde_json::Value::as_u64).unwrap_or(0);
    Ok(Manifest { format, denied })
}

/// The rustc producer string must survive stripping, so the scanner
/// classifies the file as a Rust binary.
fn producer(report: &mut Report, file: &object::File<'_>) {
    let has_rustc = file
        .section_by_name(".comment")
        .and_then(|section| section.data().ok())
        .is_some_and(|data| data.windows(5).any(|window| window == b"rustc"));
    if has_rustc {
        report.ok("rustc producer string present (scanner classifies it as a Rust binary)");
    } else {
        report.fail(Finding {
            title: "no rustc producer string in .comment".to_owned(),
            why: "a stripped binary with neither .comment nor .dep-v0 is scanned as a plain executable and bundled \
                  crypto passes silently"
                .to_owned(),
            location: "the strip step".to_owned(),
            fix: "keep the .comment section (do not strip it) and build with cargo auditable".to_owned(),
        });
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use super::*;

    /// zlib-compress a manifest the way cargo-auditable stores it.
    fn compressed(manifest: &str) -> Vec<u8> {
        let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(manifest.as_bytes()).expect("in-memory write");
        encoder.finish().expect("in-memory finish")
    }

    #[test]
    fn denied_runtime_packages_are_listed_and_build_packages_ignored() {
        let manifest = r#"{"format":8,"packages":[
            {"name":"ring","version":"0.17.14","kind":"runtime"},
            {"name":"sha2","version":"0.10.9","kind":"build"},
            {"name":"hmac","version":"0.12.1"},
            {"name":"serde","version":"1.0.229"},
            {"name":"ring","version":"0.16.20"}
        ]}"#;
        let parsed = parse_manifest(&compressed(manifest)).expect("a valid manifest");
        assert_eq!(
            parsed.denied,
            ["hmac", "ring"],
            "runtime (default kind) denied crates, sorted and de-duplicated"
        );
        assert_eq!(parsed.format, PRECURSOR_FORMAT, "the format field is read");
    }

    #[test]
    fn a_clean_manifest_lists_nothing_and_a_metadata_one_is_flagged() {
        let manifest = r#"{"packages":[{"name":"openssl","version":"0.10.81"}]}"#;
        let parsed = parse_manifest(&compressed(manifest)).expect("a valid manifest");
        assert!(parsed.denied.is_empty(), "nothing denied");
        assert_eq!(parsed.format, 0, "no format field means cargo metadata");
        let finding = metadata_derived(parsed.format, Path::new("praxis"));
        assert!(
            finding.title.contains("format 0, expected 8"),
            "the finding names both formats: {}",
            finding.title
        );
    }

    #[test]
    fn a_missing_binary_is_a_finding() {
        let mut report = Report::default();
        section(&mut report, Some(Path::new("/nonexistent/praxis")));
        assert!(
            report.failed() && report.has_finding("binary not found"),
            "a named binary that does not exist must fail the report, not pass it unchecked"
        );
    }

    #[test]
    fn a_corrupt_manifest_is_an_error() {
        assert!(parse_manifest(b"not zlib").is_err(), "garbage is not zlib");
        assert!(
            parse_manifest(&compressed("[]")).is_err(),
            "JSON without a packages array"
        );
    }

    #[test]
    fn the_test_binary_itself_is_a_rust_elf_and_the_symbol_scan_sees_what_it_links() {
        let me = std::env::current_exe().expect("the test binary has a path");
        let data = std::fs::read(&me).expect("the test binary is readable");
        let file = object::File::parse(&*data).expect("the test binary is an ELF file");
        let hits = backend_symbols(&file);
        if cfg!(feature = "dev") {
            // The development build of xtask links the standard proxy, whose
            // policy engine bundles aws-lc; the scan must see it.
            assert!(
                hits.contains_key("aws_lc_"),
                "the scan finds the bundled aws-lc: {hits:?}"
            );
        } else {
            assert!(
                hits.is_empty(),
                "the FIPS-only build of xtask links no bundled backend: {hits:?}"
            );
        }
        let mut report = Report::default();
        producer(&mut report, &file);
        assert!(!report.failed(), "a rustc-built binary carries the producer string");
    }
}
