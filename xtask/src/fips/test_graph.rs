// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Test-graph section of the report: what the FIPS unit tests compile beyond
//! the shipped binary.
//!
//! `make test-fips` resolves the product crates with their dev-dependencies,
//! so a dev edge can unify a feature into a crate the binary also links, or
//! add a denied crate that runs next to the code under test. Neither ships,
//! but either can make the tests exercise something other than the FIPS
//! build. Three rules:
//!
//! 1. no test edge may add a feature to a crate whose features choose a crypto backend ([`UNIFICATION_WATCHED`]);
//!    Policy's `jsonwebtoken` is the case in point, where a dev edge naming `aws_lc_rs` would install AWS-LC as the
//!    process-wide JWT provider ahead of Policy's OpenSSL one;
//! 2. `aws-lc-rs` and `aws-lc-sys` are never in the test graph, whatever the reason;
//! 3. any other denied crate there must be classified in [`TEST_ONLY`] with the reason it cannot reach the code under
//!    test.
//!
//! [`TEST_ONLY`]: TEST_ONLY
//! [`UNIFICATION_WATCHED`]: UNIFICATION_WATCHED

use std::{
    collections::{BTreeMap, BTreeSet},
    process::Command,
};

use super::{
    graph::DENIED,
    report::{Context, Finding, Report},
};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// The crates `make test-fips` tests, all resolved together.
const UNIT_TEST_PACKAGES: &[&str] = &[
    "praxis-proxy",
    "praxis-proxy-protocol",
    "praxis-proxy-filter",
    "praxis-proxy-core",
    "praxis-proxy-tls",
];

/// Crates whose feature set selects a crypto backend. A test edge that turns
/// on any feature of theirs the binary does not is a finding.
const UNIFICATION_WATCHED: &[&str] = &[
    "jsonwebtoken",
    "praxis-policy",
    "praxis-policy-core",
    "praxis-policy-builtins",
    "praxis-policy-apl-cmf",
    "praxis-policy-apl-runtime",
    "rustls",
    "openssl",
    "openssl-sys",
];

/// Denied crates no test may compile: a provider that could be installed
/// process-wide ahead of the one under test.
const NEVER_IN_TESTS: &[&str] = &["aws-lc-rs", "aws-lc-sys"];

/// Denied crates the unit-test graph may carry, each with why it cannot reach
/// the code under test. Every entry requires a non-empty isolation reason.
const TEST_ONLY: &[(&str, &str)] = &[(
    "ring",
    "rcgen, a dev-dependency that generates test certificates; it signs with its own ring and is never installed \
     as a rustls provider",
)];

// -----------------------------------------------------------------------------
// Section
// -----------------------------------------------------------------------------

/// Append the test-graph section.
pub(crate) fn section(report: &mut Report, context: &Context) {
    report.section(&format!(
        "Unit-test graph (make test-fips, {}, dev edges)",
        context.feature_label()
    ));
    let shipped = match listing(
        context,
        &["-p", "praxis-proxy"],
        "normal,build",
        &context.feature_flags(),
    ) {
        Ok(listing) => listing,
        Err(error) => return report.fail(unchecked(&error)),
    };
    let tested = match listing(
        context,
        &unit_test_packages(),
        "normal,build,dev",
        &qualified_flags(context),
    ) {
        Ok(listing) => listing,
        Err(error) => return report.fail(unchecked(&error)),
    };
    let findings = check(&shipped, &tested);
    if findings.is_empty() {
        report.ok("test edges add no denied crate beyond the classified ones and unify no crypto feature");
    }
    for finding in findings {
        report.fail(finding);
    }
}

/// The `-p` arguments for [`UNIT_TEST_PACKAGES`].
///
/// [`UNIT_TEST_PACKAGES`]: UNIT_TEST_PACKAGES
fn unit_test_packages() -> Vec<&'static str> {
    UNIT_TEST_PACKAGES.iter().flat_map(|package| ["-p", package]).collect()
}

/// The assessed features, qualified for a multi-package invocation.
fn qualified_flags(context: &Context) -> Vec<String> {
    context.features.as_ref().map_or_else(Vec::new, |features| {
        let qualified = features
            .split(',')
            .filter(|feature| !feature.is_empty())
            .map(|feature| format!("praxis-proxy/{feature}"))
            .collect::<Vec<_>>()
            .join(",");
        vec!["--no-default-features".to_owned(), "--features".to_owned(), qualified]
    })
}

/// The finding for a listing cargo could not produce.
fn unchecked(error: &str) -> Finding {
    Finding {
        title: "cargo tree could not list the unit-test graph".to_owned(),
        why: "an unchecked graph is not a clean graph; the check must fail closed".to_owned(),
        location: error.to_owned(),
        fix: "fix the cargo error (run the same cargo tree by hand in the workspace root) and rerun".to_owned(),
    }
}

// -----------------------------------------------------------------------------
// Listing
// -----------------------------------------------------------------------------

/// Every package in a graph with the features it is built with.
type Listing = BTreeMap<String, BTreeSet<String>>;

/// Run `cargo tree` over `edges` and collect each package's features.
fn listing(context: &Context, packages: &[&str], edges: &str, feature_flags: &[String]) -> Result<Listing, String> {
    let output = Command::new("cargo")
        .current_dir(&context.root)
        .arg("tree")
        .args(context.cargo_flags())
        .args(packages)
        // Plain output: CARGO_TERM_COLOR=always would wrap the `(*)` marker in escapes `parse` cannot strip.
        .args(["-e", edges, "--prefix", "none", "--format", "{p}|{f}", "--color", "never"])
        .args(feature_flags)
        .output()
        .map_err(|err| format!("cargo could not be run: {err}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(stderr
            .lines()
            .find(|line| line.starts_with("error"))
            .unwrap_or("cargo tree failed")
            .to_owned());
    }
    Ok(parse(&String::from_utf8_lossy(&output.stdout)))
}

/// Parse `{p}|{f}` lines: `name vX.Y.Z (source)|feature,feature`.
fn parse(text: &str) -> Listing {
    let mut listing = Listing::new();
    for line in text.lines() {
        let Some((package, features)) = line.trim_end_matches(" (*)").split_once('|') else {
            continue;
        };
        let Some(name) = package.split_whitespace().next() else {
            continue;
        };
        listing.entry(name.to_owned()).or_default().extend(
            features
                .split(',')
                .filter(|feature| !feature.is_empty())
                .map(str::to_owned),
        );
    }
    listing
}

// -----------------------------------------------------------------------------
// Rules
// -----------------------------------------------------------------------------

/// Every rule over the two listings.
fn check(shipped: &Listing, tested: &Listing) -> Vec<Finding> {
    let mut findings: Vec<Finding> = UNIFICATION_WATCHED
        .iter()
        .filter_map(|name| unified(name, shipped, tested))
        .collect();
    findings.extend(
        DENIED
            .iter()
            .filter(|name| tested.contains_key(**name) && !shipped.contains_key(**name))
            .filter_map(|name| denied_in_tests(name)),
    );
    findings
}

/// A finding when test edges turn on features of `name` the binary lacks.
fn unified(name: &str, shipped: &Listing, tested: &Listing) -> Option<Finding> {
    let in_tests = tested.get(name)?;
    let empty = BTreeSet::new();
    let in_binary = shipped.get(name).unwrap_or(&empty);
    let extra: Vec<&str> = in_tests.difference(in_binary).map(String::as_str).collect();
    (!extra.is_empty()).then(|| Finding {
        title: format!("test edges unify features [{}] into '{name}'", extra.join(", ")),
        why: "a dev-dependency that changes a crypto-selecting crate's features makes the FIPS unit tests run a \
              different backend than the binary ships"
            .to_owned(),
        location: format!("cargo tree -e features,normal,build,dev -i {name} with the same features"),
        fix: format!("declare '{name}' backend-neutral (default-features = false) in every dev-dependency"),
    })
}

/// A finding for a denied crate only the tests compile, unless classified.
fn denied_in_tests(name: &str) -> Option<Finding> {
    let never = NEVER_IN_TESTS.contains(&name);
    if !never && TEST_ONLY.iter().any(|(classified, _)| *classified == name) {
        return None;
    }
    Some(Finding {
        title: format!("denied crate '{name}' is in the FIPS unit-test graph"),
        why: if never {
            "AWS-LC can be installed as the process-wide jsonwebtoken or rustls provider ahead of OpenSSL, so the \
             tests would not exercise the FIPS backend"
                .to_owned()
        } else {
            "a denied crate the tests compile can stand in for the code under test; it needs a reviewed reason"
                .to_owned()
        },
        location: format!("cargo tree -e normal,build,dev -i {name} with the same features"),
        fix: if never {
            "remove the dev edge or make it backend-neutral".to_owned()
        } else {
            "remove the dev edge, or classify it in xtask/src/fips/test_graph.rs TEST_ONLY with a reason".to_owned()
        },
    })
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listings_parse_names_and_merge_features() {
        let text = "jsonwebtoken v11.1.0|default,use_pem\npraxis-policy v0.6.0 (/p)|fips\njsonwebtoken v11.1.0|use_pem \
                    (*)\nring v0.17.14|\n";
        let listing = parse(text);
        assert_eq!(
            listing,
            of(&[
                ("jsonwebtoken", &["default", "use_pem"]),
                ("praxis-policy", &["fips"]),
                ("ring", &[])
            ])
        );
    }

    #[test]
    fn a_dev_edge_selecting_aws_lc_in_jsonwebtoken_is_a_finding() {
        let shipped = of(&[("jsonwebtoken", &["default", "use_pem"])]);
        let tested = of(&[
            ("jsonwebtoken", &["aws_lc_rs", "default", "use_pem"]),
            ("aws-lc-rs", &[]),
        ]);
        let titles: Vec<String> = check(&shipped, &tested)
            .into_iter()
            .map(|finding| finding.title)
            .collect();
        assert!(
            titles
                .iter()
                .any(|title| title.contains("[aws_lc_rs]") && title.contains("'jsonwebtoken'")),
            "the unified backend feature is named: {titles:?}"
        );
        assert!(
            titles
                .iter()
                .any(|title| title.contains("'aws-lc-rs' is in the FIPS unit-test graph")),
            "aws-lc-rs in the test graph is always a finding: {titles:?}"
        );
    }

    #[test]
    fn a_classified_test_only_crate_passes_and_an_unclassified_one_fails() {
        let shipped = of(&[("rustls", &["std"])]);
        let tested = of(&[("rustls", &["std"]), ("ring", &[]), ("sha1", &[])]);
        let titles: Vec<String> = check(&shipped, &tested)
            .into_iter()
            .map(|finding| finding.title)
            .collect();
        assert_eq!(
            titles,
            ["denied crate 'sha1' is in the FIPS unit-test graph"],
            "ring is classified, sha1 is not"
        );
    }

    #[test]
    fn a_crate_the_binary_already_ships_is_left_to_the_graph_section() {
        let both = of(&[("sha2", &[])]);
        assert!(
            check(&both, &both).is_empty(),
            "graph.rs reports a shipped denied crate"
        );
    }

    #[test]
    fn every_classification_has_a_reason_and_none_overrides_a_never_rule() {
        for (name, reason) in TEST_ONLY {
            assert!(
                DENIED.contains(name),
                "{name} is on the denylist, or it needs no classification"
            );
            assert!(reason.len() > 20, "{name} carries a real reason: {reason:?}");
            assert!(!NEVER_IN_TESTS.contains(name), "{name} can never be classified");
        }
    }

    #[test]
    fn features_are_qualified_for_the_unit_test_packages() {
        let context = Context {
            root: ".".into(),
            features: Some("pingora,policy-jwt-fips".to_owned()),
            offline: false,
        };
        assert_eq!(
            qualified_flags(&context),
            [
                "--no-default-features",
                "--features",
                "praxis-proxy/pingora,praxis-proxy/policy-jwt-fips"
            ],
            "each feature names the binary"
        );
    }

    // -----------------------------------------------------------------------------
    // Test Utilities
    // -----------------------------------------------------------------------------

    /// A listing from `(name, features)` pairs.
    fn of(entries: &[(&str, &[&str])]) -> Listing {
        entries
            .iter()
            .map(|(name, features)| {
                (
                    (*name).to_owned(),
                    features.iter().map(|feature| (*feature).to_owned()).collect(),
                )
            })
            .collect()
    }
}
