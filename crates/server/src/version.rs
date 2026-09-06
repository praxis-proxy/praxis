// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Build-time version metadata for admin `/api/stats`.

use praxis_protocol::http::pingora::health::ProcessVersionInfo;

/// Version identity embedded at build time (`server/build.rs`).
#[must_use]
pub fn process_version_info() -> ProcessVersionInfo {
    ProcessVersionInfo {
        semver: env!("PRAXIS_VERSION_SEMVER").to_owned(),
        display: env!("PRAXIS_VERSION").to_owned(),
        git_sha: option_env!("PRAXIS_GIT_SHA").map(str::to_owned),
        dirty: option_env!("PRAXIS_GIT_DIRTY").map(|value| value == "true"),
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
