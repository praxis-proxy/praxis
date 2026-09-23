// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Dependency graph section of the report: crates on Red Hat's denylist must
//! not be in the shipped binary's normal dependency graph.

use std::process::Command;

use super::report::{Context, Finding, Report};

/// Mirrors check-payload's `rust_denied_crypto` (PR #360) plus openssl-src.
pub(crate) const DENIED: &[&str] = &[
    "ring",
    "aws-lc-rs",
    "aws-lc-sys",
    "aws-lc-fips-sys",
    "boring",
    "boring-sys",
    "openssl-src",
    "sha1",
    "sha2",
    "sha3",
    "md-5",
    "hmac",
    "aes",
    "aes-gcm",
    "chacha20poly1305",
    "ctr",
    "cbc",
    "rsa",
    "ecdsa",
    "ed25519-dalek",
    "curve25519-dalek",
    "x25519-dalek",
    "p256",
    "p384",
];

/// Where a denied crate usually comes from in this tree.
fn hint_location(crate_name: &str) -> &'static str {
    match crate_name {
        "ring" => {
            "a dependency enabling rustls' 'ring' feature (the Pingora fork before 0.10.0 did); rcgen outside \
             dev-dependencies; a manifest built from 'cargo metadata' (which activates rustls-webpki's weak \
             'ring?/alloc' feature) when the graph itself is clean"
        },
        "aws-lc-rs" | "aws-lc-sys" => {
            "a dependency enabling rustls' 'aws_lc_rs' feature (rustls' default, kept off in the workspace \
             Cargo.toml); jsonwebtoken via the policy engine 'jwt' builtin"
        },
        "sha2" => {
            "praxis-policy-apl-runtime session_resolver.rs; policy 'oauth' and 'valkey' builtins; basic-auth filter \
             (feature basic-auth-filter)"
        },
        "hmac" => "policy 'oauth' builtin (delegator-oauth cache/key.rs)",
        "sha1" => "tokio-tungstenite WebSocket accept key (test utilities)",
        "openssl-src" => "the 'vendored' feature of the openssl crate, or OPENSSL_STATIC",
        "boring" | "boring-sys" => "pingora 'boringssl' feature",
        _ => "see the dependency path above",
    }
}

/// What to do about a denied crate.
fn hint_fix(crate_name: &str) -> &'static str {
    match crate_name {
        "ring" => {
            "find the edge with 'cargo tree -e features -i ring'; keep rustls/tokio-rustls/reqwest on no-provider \
             features; the only provider is praxis-tls' OpenSSL one"
        },
        "aws-lc-rs" | "aws-lc-sys" => {
            "find the edge with 'cargo tree -e features -i aws-lc-rs'; keep rustls default-features off; leave the \
             policy 'jwt' builtin out of the FIPS build"
        },
        "sha1" => "keep it a dev-dependency; it must not appear in the release graph",
        "openssl-src" => "remove 'vendored', build with OPENSSL_NO_VENDOR=1, never set OPENSSL_STATIC",
        "boring" | "boring-sys" => "build pingora with the 'rustls' feature only",
        "aws-lc-fips-sys" => "remove the dependency or route it through the system OpenSSL",
        _ => {
            "route the operation through openssl (EVP APIs: openssl::hash, openssl::sign, openssl::pkey) or disable \
             the feature that pulls it"
        },
    }
}

/// Append the dependency graph section.
pub(crate) fn section(report: &mut Report, context: &Context) {
    report.section(&format!(
        "Dependency graph (praxis-proxy, {}, normal edges)",
        context.feature_label()
    ));
    if Command::new("cargo").arg("--version").output().is_err() {
        report.fail(unchecked_finding(&["cargo not found".to_owned()]));
        return;
    }
    let mut clean = true;
    let mut unchecked = Vec::new();
    for crate_name in DENIED {
        match inverted_tree(context, crate_name, &context.feature_flags()) {
            Tree::Absent => {},
            Tree::Error(first) => unchecked.push(format!("{crate_name}: {first}")),
            Tree::Present(tree) => {
                clean = false;
                report.fail(finding(crate_name));
                report.raw(&excerpt(&tree));
            },
        }
    }
    if !unchecked.is_empty() {
        clean = false;
        report.fail(unchecked_finding(&unchecked));
    }
    if clean {
        report.ok(&format!("no denied crate in the graph ({})", context.feature_label()));
    }
    all_features_note(report, context);
}

/// The finding for crates cargo could not check: an unchecked graph is not
/// a clean graph, so the gate fails closed.
fn unchecked_finding(unchecked: &[String]) -> Finding {
    Finding {
        title: format!(
            "cargo tree could not check {} of {} denied crates",
            unchecked.len(),
            DENIED.len()
        ),
        why: "a crate that could not be looked up may be in the graph; the check must fail closed".to_owned(),
        location: unchecked.first().cloned().unwrap_or_default(),
        fix: "fix the cargo error (run the same cargo tree by hand in the workspace root) and rerun".to_owned(),
    }
}

/// The finding for a denied crate in the graph.
fn finding(crate_name: &str) -> Finding {
    Finding {
        title: format!("denied crate '{crate_name}' is in the shipped dependency graph"),
        why: "this crate implements cryptography outside the RHEL OpenSSL FIPS module; Red Hat's scanner fails any \
              binary whose manifest lists it"
            .to_owned(),
        location: hint_location(crate_name).to_owned(),
        fix: hint_fix(crate_name).to_owned(),
    }
}

/// What `cargo tree -i <crate>` said.
enum Tree {
    /// The crate is not in the graph.
    Absent,
    /// cargo failed; the first error line.
    Error(String),
    /// The crate is in the graph; the inverted tree.
    Present(String),
}

/// Run `cargo tree` inverted on `crate_name` over normal edges with the given
/// feature flags, and classify the answer.
fn inverted_tree(context: &Context, crate_name: &str, feature_flags: &[String]) -> Tree {
    let output = Command::new("cargo")
        .current_dir(&context.root)
        .arg("tree")
        .args(context.cargo_flags())
        .args(["-e", "normal", "-p", "praxis-proxy"])
        .args(feature_flags)
        .args(["-i", crate_name, "--prefix", "indent"])
        .output();
    let Ok(output) = output else {
        return Tree::Error("cargo could not be run".to_owned());
    };
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    classify(&text)
}

/// Classify cargo tree's combined output.
fn classify(text: &str) -> Tree {
    if text.contains("did not match any packages") || text.contains("nothing to print") {
        return Tree::Absent;
    }
    if let Some(error) = text.lines().find(|line| line.starts_with("error")) {
        return Tree::Error(error.to_owned());
    }
    Tree::Present(text.to_owned())
}

/// The first 20 lines of a tree without the de-duplicated `(*)` repeats.
fn excerpt(tree: &str) -> String {
    tree.lines()
        .filter(|line| !line.ends_with("(*)"))
        .take(20)
        .collect::<Vec<_>>()
        .join("\n")
}

/// Informational: the same check with every feature enabled, for the crates
/// not already reported.
fn all_features_note(report: &mut Report, context: &Context) {
    let all_features = ["--all-features".to_owned()];
    let extra: Vec<&str> = DENIED
        .iter()
        .copied()
        .filter(|crate_name| !report.has_finding(&format!("'{crate_name}' is in the shipped")))
        .filter(|crate_name| matches!(inverted_tree(context, crate_name, &all_features), Tree::Present(_)))
        .collect();
    if !extra.is_empty() {
        report.warn(&format!(
            "with --all-features these denied crates also appear: {} (not in this build; check before enabling those \
             features)",
            extra.join(" ")
        ));
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cargo_tree_output_is_classified() {
        assert!(
            matches!(
                classify("error: package ID specification `ring` did not match any packages"),
                Tree::Absent
            ),
            "a crate outside the lockfile is absent"
        );
        assert!(
            matches!(classify("warning: nothing to print.\n"), Tree::Absent),
            "no inverted path is absent"
        );
        assert!(
            matches!(classify("error: could not find `Cargo.toml`"), Tree::Error(line) if line.starts_with("error")),
            "another error is reported"
        );
        assert!(
            matches!(classify("ring v0.17.14\n    rustls v0.23.45"), Tree::Present(_)),
            "a tree is present"
        );
    }

    #[test]
    fn excerpts_drop_repeats_and_cap_the_length() {
        let tree = "ring v0.17.14\n    dup v1 (*)\n    keep v1";
        assert_eq!(excerpt(tree), "ring v0.17.14\n    keep v1", "repeats are dropped");
        let long: String = (0..30).map(|n| format!("line {n}\n")).collect();
        assert_eq!(excerpt(&long).lines().count(), 20, "at most 20 lines");
    }

    #[test]
    fn an_unchecked_crate_is_a_finding_that_names_the_first_error() {
        let finding = unchecked_finding(&["ring: error: no cargo".to_owned(), "sha2: error: no cargo".to_owned()]);
        assert!(
            finding.title.starts_with("cargo tree could not check 2 of"),
            "counts the unchecked crates: {}",
            finding.title
        );
        assert_eq!(finding.location, "ring: error: no cargo", "names the first error");
    }

    #[test]
    fn every_denied_crate_has_a_fix() {
        for crate_name in DENIED {
            assert!(!hint_fix(crate_name).is_empty(), "{crate_name} has a fix");
            assert!(!hint_location(crate_name).is_empty(), "{crate_name} has a location");
        }
    }
}
