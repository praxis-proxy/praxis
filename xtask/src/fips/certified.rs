// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! The builds of Red Hat's OpenSSL FIPS provider module NIST has validated,
//! and the ones in validation, compiled in from
//! `xtask/assets/fips/certified-modules.json`.
//!
//! A FIPS 140-3 certificate names one exact module build, by the version
//! string the module reports (`openssl list -providers`). Red Hat rebuilds
//! the module for security fixes, and a rebuilt module is a new build that
//! goes through validation again; until it is listed on a certificate it is
//! not the validated module, whatever the package name says. `host-check`
//! looks the loaded build up here so that fact is stated rather than
//! assumed.

use serde::Deserialize;

use super::assets;

// -----------------------------------------------------------------------------
// Types
// -----------------------------------------------------------------------------

/// Where a build stands with NIST.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Status {
    /// On an active certificate.
    Active,
    /// Submitted; on the Modules In Process list, not on a certificate.
    InProcess,
    /// On a certificate that has been moved to the historical list.
    Historical,
}

/// One build of the module.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub(crate) struct Module {
    /// The version string the module reports.
    pub(crate) version: String,
    /// The module name it reports.
    pub(crate) name: String,
    /// Where it stands with NIST.
    pub(crate) status: Status,
    /// The CMVP validation number (the certificate's number), once it has
    /// one. A public identifier, not key material, whatever a name with
    /// "certificate" in it may suggest to a scanner.
    #[serde(default)]
    pub(crate) cmvp_number: Option<String>,
    /// The certificate's sunset date.
    #[serde(default)]
    pub(crate) sunset: Option<String>,
    /// The RPM packages that carry this build.
    #[serde(default)]
    pub(crate) packages: Vec<String>,
    /// Context worth repeating in a report.
    #[serde(default)]
    pub(crate) note: Option<String>,
    /// Where the fact was checked.
    pub(crate) source: String,
}

/// The list file.
#[derive(Deserialize)]
struct List {
    /// Every listed build.
    modules: Vec<Module>,
}

/// What the list says about a version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// On an active certificate.
    Validated(Module),
    /// In validation.
    InProcess(Module),
    /// On a historical certificate.
    Historical(Module),
    /// Not listed.
    Unknown,
}

// -----------------------------------------------------------------------------
// Lookup
// -----------------------------------------------------------------------------

/// Every listed build.
pub(crate) fn modules() -> Vec<Module> {
    serde_json::from_str::<List>(assets::CERTIFIED_MODULES)
        .expect("certified-modules.json is valid")
        .modules
}

/// What the list says about `version`.
pub(crate) fn verdict(version: &str) -> Verdict {
    modules()
        .into_iter()
        .find(|module| module.version == version)
        .map_or(Verdict::Unknown, |module| match module.status {
            Status::Active => Verdict::Validated(module),
            Status::InProcess => Verdict::InProcess(module),
            Status::Historical => Verdict::Historical(module),
        })
}

impl Verdict {
    /// Whether this satisfies `--require-certified`.
    pub(crate) fn validated(&self) -> bool {
        matches!(self, Self::Validated(_))
    }

    /// One line stating the verdict for `version`.
    pub(crate) fn describe(&self, version: &str) -> String {
        match self {
            Self::Validated(module) => format!(
                "module {version} is {} on CMVP certificate #{} (sunset {}), packages {}; {}",
                module.name,
                module.cmvp_number.as_deref().unwrap_or("?"),
                module.sunset.as_deref().unwrap_or("?"),
                module.packages.join(", "),
                module.source
            ),
            Self::InProcess(module) => format!(
                "module {version} ({}) is in validation, not on a certificate yet; packages {}. {} See {}",
                module.name,
                module.packages.join(", "),
                module.note.as_deref().unwrap_or(""),
                module.source
            ),
            Self::Historical(module) => format!(
                "module {version} ({}) is on historical certificate #{}; {}",
                module.name,
                module.cmvp_number.as_deref().unwrap_or("?"),
                module.source
            ),
            Self::Unknown => format!(
                "module {version} is not in xtask/assets/fips/certified-modules.json: look it up on the CMVP validated \
                 modules and Modules In Process lists and add it"
            ),
        }
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_list_parses_and_names_the_certified_build() {
        let modules = modules();
        assert!(modules.len() >= 2, "the two known builds at least");
        let validated = modules
            .iter()
            .find(|module| module.status == Status::Active)
            .expect("one active build");
        assert_eq!(validated.version, "3.0.7-395c1a240fbfffd8");
        assert_eq!(validated.cmvp_number.as_deref(), Some("4857"));
        assert!(validated.sunset.is_some(), "an active certificate has a sunset date");
        assert!(!validated.packages.is_empty(), "and names its packages");
    }

    #[test]
    fn verdicts_follow_the_list() {
        assert!(verdict("3.0.7-395c1a240fbfffd8").validated());
        let pending = verdict("3.0.7-cda111b5812c30d4");
        assert!(matches!(pending, Verdict::InProcess(_)), "{pending:?}");
        assert!(!pending.validated());
        assert_eq!(verdict("9.9.9-0000000000000000"), Verdict::Unknown);
    }

    #[test]
    fn every_description_names_the_version_and_a_source() {
        for version in [
            "3.0.7-395c1a240fbfffd8",
            "3.0.7-cda111b5812c30d4",
            "0.0.0-ffffffffffffffff",
        ] {
            let text = verdict(version).describe(version);
            assert!(text.contains(version), "{text}");
            assert!(
                text.contains("https://") || text.contains("certified-modules.json"),
                "{text}"
            );
        }
    }
}
