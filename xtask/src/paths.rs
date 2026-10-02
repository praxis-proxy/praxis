// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Workspace paths shared by the xtask subcommands.

use std::path::{Path, PathBuf};

// -----------------------------------------------------------------------------
// Workspace Root
// -----------------------------------------------------------------------------

/// The workspace root: the parent of the xtask crate, fixed at compile time
/// so the binary works when run directly as well as through `cargo run`.
pub(crate) fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask lives in the workspace")
        .to_path_buf()
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workspace_root_holds_the_workspace_manifest() {
        assert!(
            workspace_root().join("Cargo.toml").is_file(),
            "the workspace root must contain Cargo.toml"
        );
        assert!(
            workspace_root().join("xtask").is_dir(),
            "the workspace root must contain the xtask crate"
        );
    }
}
