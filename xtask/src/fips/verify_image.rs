// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! `cargo xtask fips verify-image`: prove that a container image really is
//! the Red Hat image we think it is before it becomes the base of a FIPS
//! build.
//!
//! The checks, all of which must pass:
//!
//! 1. the reference is digest-pinned and on registry.access.redhat.com (and, with `--pinned-in`, the supported
//!    Containerfile base stage consumes its matching digest argument)
//! 2. the bundled Red Hat release key has the fingerprint Red Hat publishes
//! 3. the host can verify signatures at all: gnupg is installed (podman checks `signedBy` policies through gpgme) and
//!    podman's `registries.d` names a signature store for Red Hat's registry, as containers-common ships
//! 4. podman accepts the image under a policy that rejects everything except images signed by that key
//! 5. the pulled image carries Red Hat's vendor label
//!
//! Requires podman on Linux; docker cannot verify Red Hat's signatures.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    process::Command,
};

use clap::Parser;

use super::{assets, openpgp, signature_store};

/// The registry whose images this task is willing to verify.
const REGISTRY: &str = assets::REDHAT_REGISTRY;

/// The vendor label Red Hat's images carry.
const VENDOR: &str = "Red Hat, Inc.";

// -----------------------------------------------------------------------------
// CLI Arguments
// -----------------------------------------------------------------------------

/// CLI arguments for `cargo xtask fips verify-image`.
#[derive(Parser)]
pub(crate) struct Args {
    /// Digest-pinned reference: registry.access.redhat.com/REPO@sha256:DIGEST
    image: String,

    /// Also check the supported UBI base stages and digest argument defaults
    /// in the Containerfile against this image reference.
    #[arg(long, value_name = "CONTAINERFILE")]
    pinned_in: Option<PathBuf>,
}

// -----------------------------------------------------------------------------
// Entry Point
// -----------------------------------------------------------------------------

/// Verify the image; exit 1 with the reason when any check fails.
pub(crate) fn run(args: &Args) {
    if let Err(reason) = verify(&args.image, args.pinned_in.as_deref()) {
        eprintln!("fips-verify-image: FAIL: {reason}");
        std::process::exit(1);
    }
}

/// Run the checks in order, printing a line for each that passes.
fn verify(image: &str, pinned_in: Option<&Path>) -> Result<(), String> {
    check_reference(image)?;
    if let Some(containerfile) = pinned_in {
        check_pinned(containerfile, image)?;
    }
    check_key()?;
    check_gnupg()?;
    check_signature_store(&signature_store::registries_d())?;
    let work = tempfile::tempdir().map_err(|err| format!("cannot create a temporary directory: {err}"))?;
    pull_under_policy(work.path(), image)?;
    let labels = labels(image)?;
    let label = |name: &str| labels.get(name).map_or("?", String::as_str);
    if label("vendor") != VENDOR {
        return Err(format!("vendor label is '{}', expected '{VENDOR}'", label("vendor")));
    }
    println!(
        "fips-verify-image: ok: {} {}-{}, built {}, vendor {}",
        label("name"),
        label("version"),
        label("release"),
        label("build-date"),
        label("vendor")
    );
    Ok(())
}

// -----------------------------------------------------------------------------
// Checks
// -----------------------------------------------------------------------------

/// The reference must be pinned by digest and live on Red Hat's registry.
fn check_reference(image: &str) -> Result<(), String> {
    let pinned = image
        .strip_prefix(REGISTRY)
        .and_then(|rest| rest.strip_prefix('/'))
        .is_some_and(|rest| rest.contains("@sha256:"));
    if pinned {
        Ok(())
    } else {
        Err(format!(
            "refusing '{image}': must be a digest-pinned {REGISTRY} reference"
        ))
    }
}

/// The supported UBI base stage must consume the matching digest argument.
fn check_pinned(containerfile: &Path, image: &str) -> Result<(), String> {
    let (repository, digest) = image
        .rsplit_once('@')
        .ok_or_else(|| format!("image reference has no digest: {image}"))?;
    let argument = base_argument(repository)?;
    let text = std::fs::read_to_string(containerfile)
        .map_err(|err| format!("cannot read {}: {err}", containerfile.display()))?;
    check_base_stages(&text)?;
    let default = global_argument(&text, argument);
    if default != Some(digest) {
        return Err(format!(
            "{} must default {argument} to {digest} for {repository}",
            containerfile.display(),
        ));
    }
    println!(
        "fips-verify-image: ok: {} binds {repository} to {argument}={digest}",
        containerfile.display()
    );
    Ok(())
}

/// The two external base repositories supported by this recipe.
fn base_argument(repository: &str) -> Result<&'static str, String> {
    match repository {
        "registry.access.redhat.com/ubi9/ubi" => Ok("UBI9_DIGEST"),
        "registry.access.redhat.com/ubi9/ubi-minimal" => Ok("UBI9_MINIMAL_DIGEST"),
        _ => Err(format!("unsupported FIPS base repository: {repository}")),
    }
}

/// Read a global ARG default, before the first FROM, with current recipe syntax.
fn global_argument<'a>(text: &'a str, name: &str) -> Option<&'a str> {
    let mut defaults = text
        .lines()
        .map(str::trim)
        .take_while(|line| {
            !line
                .split_whitespace()
                .next()
                .is_some_and(|instruction| instruction.eq_ignore_ascii_case("FROM"))
        })
        .filter_map(|line| {
            let (instruction, argument) = line.split_once(char::is_whitespace)?;
            instruction.eq_ignore_ascii_case("ARG").then_some(argument.trim())
        })
        .filter_map(|argument| {
            let (argument, value) = argument.split_once('=').unwrap_or((argument, ""));
            (argument.trim() == name).then_some(value.trim().trim_matches('"'))
        });
    let default = defaults.next()?;
    defaults.next().is_none().then_some(default)
}

/// Require the supported source and alias of every stage, in build order.
fn check_base_stages(text: &str) -> Result<(), String> {
    let expected = [
        ("registry.access.redhat.com/ubi9/ubi@${UBI9_DIGEST}", "toolchain"),
        ("toolchain", "builder"),
        ("builder", "report"),
        (
            "registry.access.redhat.com/ubi9/ubi-minimal@${UBI9_MINIMAL_DIGEST}",
            "runtime",
        ),
    ];
    let mut stages = Vec::new();
    for line in text.lines().map(str::trim) {
        if let Some(stage) = from_stage(line)? {
            stages.push(stage);
        }
    }
    if stages.as_slice() == expected.as_slice() {
        Ok(())
    } else {
        Err(format!("unsupported FIPS stage graph: {stages:?}"))
    }
}

/// Parse the source and `AS` alias of one supported FROM instruction.
fn from_stage(line: &str) -> Result<Option<(&str, &str)>, String> {
    let mut fields = line.split_whitespace();
    let Some(instruction) = fields.next() else {
        return Ok(None);
    };
    if !instruction.eq_ignore_ascii_case("FROM") {
        return Ok(None);
    }
    match (fields.next(), fields.next(), fields.next(), fields.next()) {
        (Some(source), Some("AS"), Some(alias), None) => Ok(Some((source, alias))),
        _ => Err(format!("unsupported FIPS FROM instruction: {line}")),
    }
}

/// The bundled key must have the fingerprint Red Hat publishes.
fn check_key() -> Result<(), String> {
    let fingerprint = openpgp::v4_fingerprint(assets::REDHAT_RELEASE_KEY_2)?;
    if fingerprint != assets::REDHAT_RELEASE_KEY_2_FINGERPRINT {
        return Err(format!(
            "signing key fingerprint is {fingerprint}, expected {}",
            assets::REDHAT_RELEASE_KEY_2_FINGERPRINT
        ));
    }
    println!("fips-verify-image: ok: signing key is Red Hat, Inc. (release key 2), fingerprint {fingerprint}");
    Ok(())
}

/// podman verifies `signedBy` policies through gpgme, which needs gnupg; a
/// missing gpg would otherwise surface as "podman rejected the image".
fn check_gnupg() -> Result<(), String> {
    Command::new("gpg")
        .arg("--version")
        .output()
        .map_err(|err| format!("gpg (gnupg) is required: podman verifies signatures through it ({err})"))?;
    Ok(())
}

/// podman must know where Red Hat's detached signatures live, or a signed
/// image looks unsigned. `signature_store` knows where podman looks and what
/// to install, so the host gets fixed rather than the image blamed.
fn check_signature_store(dir: &Path) -> Result<(), String> {
    if !signature_store::configured(dir)? {
        return Err(signature_store::missing(dir));
    }
    println!(
        "fips-verify-image: ok: {} names a signature store for {REGISTRY}",
        dir.display()
    );
    Ok(())
}

/// Pull the image under a policy that accepts nothing but images signed by
/// the bundled key.
fn pull_under_policy(work: &Path, image: &str) -> Result<(), String> {
    let key = work.join("redhat-release-key-2.asc");
    let policy = work.join("policy.json");
    write(&key, assets::REDHAT_RELEASE_KEY_2)?;
    write(&policy, &policy_json(&key))?;
    let output = Command::new("podman")
        .args(["pull", "--quiet", "--signature-policy"])
        .arg(&policy)
        .arg(image)
        .output()
        .map_err(|err| format!("podman is required for signature verification ({err})"))?;
    if !output.status.success() {
        return Err(format!(
            "podman rejected '{image}' under a policy requiring Red Hat's signature: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    println!("fips-verify-image: ok: Red Hat signature verified for {image}");
    Ok(())
}

/// A containers-policy that rejects everything except images from Red Hat's
/// registry signed by the key at `key`.
fn policy_json(key: &Path) -> String {
    serde_json::json!({
        "default": [{ "type": "reject" }],
        "transports": {
            "docker": {
                REGISTRY: [{ "type": "signedBy", "keyType": "GPGKeys", "keyPath": key }]
            },
            "containers-storage": { "": [{ "type": "insecureAcceptAnything" }] }
        }
    })
    .to_string()
}

/// The pulled image's labels.
fn labels(image: &str) -> Result<BTreeMap<String, String>, String> {
    let output = Command::new("podman")
        .args(["image", "inspect", "--format", "{{json .Labels}}", image])
        .output()
        .map_err(|err| format!("podman image inspect: {err}"))?;
    if !output.status.success() {
        return Err(format!("podman image inspect failed for '{image}'"));
    }
    serde_json::from_slice(&output.stdout).map_err(|err| format!("image labels are not a JSON object: {err}"))
}

/// Write a file, naming it in the error.
fn write(path: &Path, contents: &str) -> Result<(), String> {
    std::fs::write(path, contents).map_err(|err| format!("cannot write {}: {err}", path.display()))
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_digest_pinned_red_hat_references_are_accepted() {
        assert!(
            check_reference("registry.access.redhat.com/ubi9/ubi@sha256:0123").is_ok(),
            "digest-pinned Red Hat reference"
        );
        for bad in [
            "registry.access.redhat.com/ubi9/ubi:9.8",
            "docker.io/library/ubi9@sha256:0123",
            "registry.access.redhat.com.evil.example/ubi9/ubi@sha256:0123",
            "registry.access.redhat.com@sha256:0123",
        ] {
            assert!(check_reference(bad).is_err(), "{bad} must be refused");
        }
    }

    #[test]
    fn the_containerfile_must_pin_the_verified_digest() {
        let dir = tempfile::tempdir().expect("temp dir");
        let containerfile = dir.path().join("Containerfile.fips");
        std::fs::write(&containerfile, base_fixture()).expect("write");
        assert!(
            check_pinned(&containerfile, "registry.access.redhat.com/ubi9/ubi@sha256:0123").is_ok(),
            "the base stage consumes the matching default"
        );
        let err = check_pinned(&containerfile, "registry.access.redhat.com/ubi9/ubi@sha256:4567")
            .expect_err("a digest the file does not pin");
        assert!(err.contains("sha256:4567"), "the error names the digest: {err}");
        let missing = check_pinned(
            Path::new("/nonexistent"),
            "registry.access.redhat.com/ubi9/ubi@sha256:0123",
        )
        .expect_err("missing file fails");
        assert!(missing.contains("cannot read"), "read failure is reported: {missing}");
    }

    /// A minimal fixture with both external bases and two internal stages.
    fn base_fixture() -> &'static str {
        "ARG UBI9_DIGEST=sha256:0123\n\
ARG UBI9_MINIMAL_DIGEST=sha256:4567\n\
FROM registry.access.redhat.com/ubi9/ubi@${UBI9_DIGEST} AS toolchain\n\
FROM toolchain AS builder\n\
FROM builder AS report\n\
FROM registry.access.redhat.com/ubi9/ubi-minimal@${UBI9_MINIMAL_DIGEST} AS runtime\n"
    }

    #[test]
    fn unused_digest_argument_does_not_pin_base() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("Containerfile.fips");
        for invalid_from in [
            "FROM registry.access.redhat.com/ubi9/ubi@sha256:9999 AS toolchain",
            "FROM registry.access.redhat.com/ubi9/ubi@${OTHER_DIGEST} AS toolchain",
        ] {
            let fixture = base_fixture().replace(
                "FROM registry.access.redhat.com/ubi9/ubi@${UBI9_DIGEST} AS toolchain",
                invalid_from,
            );
            std::fs::write(&path, fixture).expect("write fixture");
            assert!(
                check_pinned(&path, "registry.access.redhat.com/ubi9/ubi@sha256:0123").is_err(),
                "unused matching ARG must not validate {invalid_from}"
            );
        }
    }

    #[test]
    fn matching_digest_in_wrong_repository_is_rejected() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("Containerfile.fips");
        let fixture = base_fixture().replace(
            "registry.access.redhat.com/ubi9/ubi@${UBI9_DIGEST}",
            "registry.access.redhat.com/ubi9/ubi-init@${UBI9_DIGEST}",
        );
        std::fs::write(&path, fixture).expect("write fixture");
        assert!(
            check_pinned(&path, "registry.access.redhat.com/ubi9/ubi@sha256:0123").is_err(),
            "the digest alone does not establish repository identity"
        );
    }

    #[test]
    fn current_base_stages_resolve_to_verified_references() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("Containerfile.fips");
        std::fs::write(&path, base_fixture()).expect("write fixture");
        for image in [
            "registry.access.redhat.com/ubi9/ubi@sha256:0123",
            "registry.access.redhat.com/ubi9/ubi-minimal@sha256:4567",
        ] {
            assert!(check_pinned(&path, image).is_ok(), "the base resolves to {image}");
        }
        let changed = base_fixture().replace("UBI9_MINIMAL_DIGEST=sha256:4567", "UBI9_MINIMAL_DIGEST=sha256:9999");
        std::fs::write(&path, changed).expect("write mutation");
        assert!(
            check_pinned(&path, "registry.access.redhat.com/ubi9/ubi-minimal@sha256:4567").is_err(),
            "a changed default is rejected"
        );
    }

    #[test]
    fn swapped_or_misderived_fips_stages_cannot_claim_verified_bases() {
        let source = "FROM registry.access.redhat.com/ubi9/ubi@${UBI9_DIGEST} AS toolchain";
        let minimal = "FROM registry.access.redhat.com/ubi9/ubi-minimal@${UBI9_MINIMAL_DIGEST} AS runtime";
        let variants = [
            base_fixture().replace(
                source,
                "FROM registry.access.redhat.com/ubi9/ubi@${UBI9_DIGEST} AS runtime",
            ),
            base_fixture().replace(
                minimal,
                "FROM registry.access.redhat.com/ubi9/ubi-minimal@${UBI9_MINIMAL_DIGEST} AS toolchain",
            ),
            base_fixture().replace("FROM toolchain AS builder", "FROM runtime AS builder"),
            base_fixture().replace("FROM builder AS report", "FROM toolchain AS report"),
            base_fixture().replace(minimal, "FROM builder AS runtime"),
        ];
        for recipe in variants {
            assert_unsupported_stage_graph(&recipe);
        }
    }

    #[test]
    fn missing_duplicate_or_extra_fips_stages_are_rejected() {
        for recipe in [
            base_fixture().replace("FROM builder AS report\n", ""),
            format!("{}FROM builder AS report\n", base_fixture()),
            format!(
                "{}FROM registry.access.redhat.com/ubi9/ubi-init@sha256:0123 AS extra\n",
                base_fixture()
            ),
            format!("{}from docker.io/library/alpine:latest AS runtime\n", base_fixture()),
            format!("{}FROM\tdocker.io/library/alpine:latest\tAS runtime\n", base_fixture()),
            base_fixture().replace("FROM toolchain AS builder", "FROM toolchain"),
        ] {
            assert_unsupported_stage_graph(&recipe);
        }
    }

    /// Both verified references must reject a wrong stage graph.
    fn assert_unsupported_stage_graph(recipe: &str) {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("Containerfile.fips");
        std::fs::write(&path, recipe).expect("write fixture");
        for image in [
            "registry.access.redhat.com/ubi9/ubi@sha256:0123",
            "registry.access.redhat.com/ubi9/ubi-minimal@sha256:4567",
        ] {
            let error = check_pinned(&path, image).expect_err("unsupported stage graph must fail");
            assert!(
                error.contains("FIPS stage") || error.contains("FROM instruction"),
                "{error}"
            );
        }
    }

    #[test]
    fn digest_arguments_must_have_one_global_default() {
        let original = "ARG UBI9_DIGEST=sha256:0123\n";
        let duplicated = base_fixture().replace(original, &original.repeat(2));
        let mixed_case = base_fixture().replace(original, "ARG UBI9_DIGEST=sha256:0123\narg UBI9_DIGEST=sha256:9999\n");
        let tabbed = base_fixture().replace(original, "ARG UBI9_DIGEST=sha256:0123\nARG\tUBI9_DIGEST=sha256:9999\n");
        let missing_default = base_fixture().replace(original, "ARG UBI9_DIGEST\n");
        let local_only = base_fixture().replacen(original, "", 1).replace(
            "FROM registry.access.redhat.com/ubi9/ubi@${UBI9_DIGEST} AS toolchain\n",
            "FROM registry.access.redhat.com/ubi9/ubi@${UBI9_DIGEST} AS toolchain\nARG UBI9_DIGEST=sha256:0123\n",
        );
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("Containerfile.fips");
        for recipe in [duplicated, mixed_case, tabbed, missing_default, local_only] {
            std::fs::write(&path, recipe).expect("write fixture");
            let error = check_pinned(&path, "registry.access.redhat.com/ubi9/ubi@sha256:0123")
                .expect_err("missing or duplicate global default must fail");
            assert!(error.contains("must default UBI9_DIGEST"), "{error}");
        }
        std::fs::write(&path, base_fixture()).expect("restore fixture");
        check_pinned(&path, "registry.access.redhat.com/ubi9/ubi@sha256:0123").expect("valid fixture remains accepted");
    }

    #[test]
    fn a_host_without_the_signature_store_entry_is_told_how_to_install_it() {
        let dir = tempfile::tempdir().expect("temp dir");
        let missing = dir.path().join("registries.d");
        let err = check_signature_store(&missing).expect_err("nothing is configured");
        assert!(err.contains("fips-signature-store"), "the fix is named: {err}");
        assert!(!err.contains("cannot read"), "not reported as an I/O failure: {err}");
        std::fs::create_dir(&missing).expect("create");
        std::fs::write(missing.join("redhat.yaml"), assets::REDHAT_REGISTRIES_D).expect("write");
        assert!(
            check_signature_store(&missing).is_ok(),
            "the bundled entry satisfies the check"
        );
    }

    #[test]
    fn the_policy_names_the_key_and_rejects_by_default() {
        let policy: serde_json::Value =
            serde_json::from_str(&policy_json(Path::new("/tmp/key.asc"))).expect("valid JSON");
        assert_eq!(policy["default"][0]["type"], "reject", "everything else is rejected");
        let rule = &policy["transports"]["docker"][REGISTRY][0];
        assert_eq!(rule["type"], "signedBy", "Red Hat's registry requires a signature");
        assert_eq!(rule["keyPath"], "/tmp/key.asc", "signed by the bundled key");
    }
}
