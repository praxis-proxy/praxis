// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Build-time version metadata for admin `/api/stats`.

use praxis_protocol::http::pingora::health::ProcessVersionInfo;

/// Version identity embedded at build time (`server/build.rs`).
#[must_use]
pub fn process_version_info() -> ProcessVersionInfo {
    let semver = env!("PRAXIS_VERSION_SEMVER").to_owned();
    let git_sha = option_env!("PRAXIS_GIT_SHA").map(str::to_owned);
    let display = match &git_sha {
        Some(sha) => format!("{semver} ({sha})"),
        None => semver.clone(),
    };
    ProcessVersionInfo {
        semver,
        display,
        git_sha,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_version_info_has_semver_and_display() {
        let info = process_version_info();
        assert!(!info.semver.is_empty(), "semver should be set at build time");
        assert!(!info.display.is_empty(), "display should be set at build time");
        assert!(
            info.display.starts_with(&info.semver),
            "display should include semver prefix: {}",
            info.display
        );
    }
}
