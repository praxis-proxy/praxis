// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Configuration loading with fallback resolution.
//!
//! [`load_config`] tries three sources in order: an explicit CLI
//! path, `praxis.yaml` in the working directory, then the built-in
//! [`DEFAULT_CONFIG`] (a static-response-only fallback). YAML safety
//! checks from [`parse`] run before deserialization to guard against
//! oversized files and alias expansion bombs. [`ConfigFile`] is a
//! config file as read, kept apart from parsing so the reload watcher
//! can baseline on the exact text the running config came from.
//!
//! [`parse`]: super::parse

use std::path::{Path, PathBuf};

use super::{Config, read_config_file};
use crate::errors::ProxyError;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Built-in fallback configuration (static JSON response on `/`).
///
/// ```
/// let config =
///     praxis_core::config::Config::from_yaml(praxis_core::config::DEFAULT_CONFIG).unwrap();
/// assert!(!config.listeners.is_empty());
/// ```
pub const DEFAULT_CONFIG: &str = include_str!("default.yaml");

// -----------------------------------------------------------------------------
// ConfigFile
// -----------------------------------------------------------------------------

/// A config file as it was read: its path and the exact text to parse.
///
/// Read once with [`ConfigFile::read`], parsed with
/// [`Config::from_config_file`], and then handed to the server so the
/// hot-reload watcher baselines its change detection on the text the
/// running config came from. Re-reading `path` later instead would adopt
/// any edit made in between as the baseline, and that edit would never
/// be applied.
///
/// ```
/// use praxis_core::config::{Config, ConfigFile};
///
/// let dir = tempfile::tempdir().unwrap();
/// let path = dir.path().join("praxis.yaml");
/// std::fs::write(&path, praxis_core::config::DEFAULT_CONFIG).unwrap();
///
/// let file = ConfigFile::read(&path).unwrap();
/// let config = Config::from_config_file(&file).unwrap();
/// assert_eq!(file.path, path);
/// assert_eq!(file.content, praxis_core::config::DEFAULT_CONFIG);
/// assert!(!config.listeners.is_empty());
/// ```
#[derive(Debug, Clone)]
pub struct ConfigFile {
    /// Path the config was read from, and the one to watch for reloads.
    pub path: PathBuf,

    /// File content exactly as read (size-capped).
    pub content: String,
}

impl ConfigFile {
    /// Read the config file at `path`.
    ///
    /// Uses the same size-capped reader as the reload path, so a special
    /// file or an oversized one is rejected before anything is parsed.
    ///
    /// # Errors
    ///
    /// Returns [`ProxyError::Config`] when the path is not a regular file,
    /// is too large, or cannot be read.
    ///
    /// [`ProxyError::Config`]: crate::errors::ProxyError::Config
    pub fn read(path: &Path) -> Result<Self, ProxyError> {
        let content = read_config_file(path)?;
        Ok(Self {
            path: path.to_path_buf(),
            content,
        })
    }
}

// -----------------------------------------------------------------------------
// Configuration Loading
// -----------------------------------------------------------------------------

/// Load configuration from an explicit path, falling back to
/// `praxis.yaml` in the working directory, then the built-in
/// default.
///
/// # Errors
///
/// Returns [`ProxyError::Config`] if the resolved config source
/// cannot be loaded or is invalid.
///
/// ```no_run
/// let config = praxis_core::config::load_config(None).unwrap();
/// assert!(!config.listeners.is_empty());
/// ```
///
/// [`ProxyError::Config`]: crate::errors::ProxyError::Config
pub fn load_config(explicit_path: Option<&str>) -> Result<Config, ProxyError> {
    Config::load(explicit_path, DEFAULT_CONFIG)
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::needless_raw_strings,
    clippy::needless_raw_string_hashes,
    reason = "tests use unwrap/expect/indexing/raw strings for brevity"
)]
mod tests {
    use super::*;

    #[test]
    fn default_config_parses_successfully() {
        let config = Config::from_yaml(DEFAULT_CONFIG).expect("DEFAULT_CONFIG should parse");
        assert!(
            !config.listeners.is_empty(),
            "default config should define at least one listener"
        );
    }

    #[test]
    fn load_from_explicit_path_reads_that_file() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let path = dir.path().join("praxis.yaml");
        std::fs::write(&path, config_with_listener_named("from-file")).expect("write config");

        let config = Config::load_from(Some(&path), DEFAULT_CONFIG).expect("file should load");
        assert_eq!(
            config.listeners[0].name, "from-file",
            "the resolved file must win over the fallback"
        );
    }

    #[test]
    fn load_from_none_uses_fallback_yaml() {
        let config = Config::load_from(None, &config_with_listener_named("fallback")).expect("fallback should load");
        assert_eq!(config.listeners[0].name, "fallback", "no path means the fallback YAML");
    }

    #[test]
    fn config_file_read_returns_the_exact_text() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let path = dir.path().join("praxis.yaml");
        let yaml = config_with_listener_named("from-file");
        std::fs::write(&path, &yaml).expect("write config");

        let file = ConfigFile::read(&path).expect("file should read");
        assert_eq!(file.path, path, "the returned path must be the one read");
        assert_eq!(file.content, yaml, "the returned content must be the text on disk");
    }

    #[test]
    fn config_file_content_is_unaffected_by_a_later_edit() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let path = dir.path().join("praxis.yaml");
        std::fs::write(&path, config_with_listener_named("before")).expect("write config");

        let file = ConfigFile::read(&path).expect("file should read");
        std::fs::write(&path, config_with_listener_named("after")).expect("edit config");
        let config = Config::from_config_file(&file).expect("file should parse");

        assert_eq!(config.listeners[0].name, "before", "the config is the pre-edit text");
        assert_eq!(
            file.content,
            config_with_listener_named("before"),
            "the content must match the parsed config, not the edited file"
        );
    }

    #[test]
    fn config_file_read_rejects_a_directory() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let err = ConfigFile::read(dir.path()).expect_err("a directory is not a config file");
        assert!(
            err.to_string().contains("not a regular file"),
            "the size-capped reader's error must surface: {err}"
        );
    }

    #[test]
    fn from_config_file_invalid_returns_error() {
        let file = ConfigFile {
            path: PathBuf::from("praxis.yaml"),
            content: "this: is: not: valid\n".to_owned(),
        };
        let result = Config::from_config_file(&file);
        assert!(
            matches!(result, Err(ProxyError::Config(_))),
            "invalid content must fail rather than fall back"
        );
    }

    #[test]
    fn from_config_file_or_parses_the_file_when_present() {
        let file = ConfigFile {
            path: PathBuf::from("praxis.yaml"),
            content: config_with_listener_named("from-file"),
        };
        let config = Config::from_config_file_or(Some(&file), DEFAULT_CONFIG).expect("file should parse");
        assert_eq!(
            config.listeners[0].name, "from-file",
            "the file must win over the fallback"
        );
    }

    #[test]
    fn from_config_file_or_uses_the_fallback_without_a_file() {
        let config =
            Config::from_config_file_or(None, &config_with_listener_named("fallback")).expect("fallback should load");
        assert_eq!(config.listeners[0].name, "fallback", "no file means the fallback YAML");
    }

    #[test]
    fn load_config_nonexistent_explicit_path_returns_error() {
        let result = Config::load(Some("/nonexistent/path/praxis.yaml"), DEFAULT_CONFIG);
        assert!(
            result.is_err(),
            "loading a nonexistent explicit path should return an error"
        );
    }

    #[test]
    fn load_config_none_with_valid_fallback_succeeds() {
        let config = Config::load(None, DEFAULT_CONFIG).expect("fallback YAML should parse successfully");
        assert!(
            !config.listeners.is_empty(),
            "fallback config should define at least one listener"
        );
        assert_eq!(
            config.listeners[0].name, "default",
            "fallback config listener name should be 'default'"
        );
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// The built-in default config with its single listener renamed.
    fn config_with_listener_named(name: &str) -> String {
        DEFAULT_CONFIG.replacen("name: default\n", &format!("name: {name}\n"), 1)
    }
}
