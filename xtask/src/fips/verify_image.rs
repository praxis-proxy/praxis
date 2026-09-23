// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! `cargo xtask fips verify-image`: prove that a container image really is
//! the Red Hat image we think it is before it becomes the base of a FIPS
//! build.
//!
//! The checks, all of which must pass:
//!
//! 1. the reference is digest-pinned and on registry.access.redhat.com (and, with `--pinned-in`, a Containerfile
//!    defaults a build argument to it)
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

    /// Also require a Containerfile whose `ARG <name>=<digest>` default pins
    /// this same digest, so what is verified is what gets built.
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

/// The Containerfile must default one of its build arguments to the digest
/// being verified; otherwise the verified image and the built image drift.
fn check_pinned(containerfile: &Path, image: &str) -> Result<(), String> {
    let digest = image.rsplit_once('@').map_or("", |(_, digest)| digest);
    let text = std::fs::read_to_string(containerfile)
        .map_err(|err| format!("cannot read {}: {err}", containerfile.display()))?;
    let pinned = text
        .lines()
        .filter_map(|line| line.trim().strip_prefix("ARG "))
        .filter_map(|arg| arg.split_once('='))
        .any(|(_, value)| value.trim().trim_matches('"') == digest);
    if !pinned {
        return Err(format!(
            "{} pins no build argument to {digest}",
            containerfile.display()
        ));
    }
    println!(
        "fips-verify-image: ok: {} defaults a build argument to {digest}",
        containerfile.display()
    );
    Ok(())
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
        std::fs::write(&containerfile, "ARG UBI9_DIGEST=sha256:0123\nFROM x@${UBI9_DIGEST}\n").expect("write");
        assert!(
            check_pinned(&containerfile, "registry.access.redhat.com/ubi9/ubi@sha256:0123").is_ok(),
            "the digest is pinned as a build argument default"
        );
        let err = check_pinned(&containerfile, "registry.access.redhat.com/ubi9/ubi@sha256:4567")
            .expect_err("a digest the file does not pin");
        assert!(err.contains("sha256:4567"), "the error names the digest: {err}");
        assert!(
            check_pinned(Path::new("/nonexistent"), "x@sha256:0123").is_err(),
            "a missing file fails"
        );
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
