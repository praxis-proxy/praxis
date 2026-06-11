// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Configuration types for the response store filter.

use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;

use crate::{
    FilterError,
    builtins::http::{ai::store::validate_table_identifier, transformation::has_dot_dot_traversal},
};

// -----------------------------------------------------------------------------
// StorageBackend
// -----------------------------------------------------------------------------

/// Supported storage backends.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum StorageBackend {
    /// SQLite backend (file-backed or in-memory).
    Sqlite,
}

// -----------------------------------------------------------------------------
// ResponseStoreConfig
// -----------------------------------------------------------------------------

/// YAML configuration for the [`ResponseStoreFilter`].
///
/// [`ResponseStoreFilter`]: super::ResponseStoreFilter
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResponseStoreConfig {
    /// Storage backend to use.
    pub backend: StorageBackend,

    /// Database connection URL. Wrapped in [`SecretString`] to
    /// prevent accidental logging of credentials.
    pub database_url: SecretString,

    /// Table name for response records.
    pub responses_table: String,

    /// Table name for conversation message records.
    pub conversations_table: String,
}

// -----------------------------------------------------------------------------
// Config Validation
// -----------------------------------------------------------------------------

/// Validate the parsed configuration.
pub(crate) fn validate_config(cfg: &ResponseStoreConfig) -> Result<(), FilterError> {
    let database_url = cfg.database_url.expose_secret();
    if database_url.is_empty() {
        return Err("openai_response_store: 'database_url' must not be empty".into());
    }
    validate_database_url(database_url)?;
    validate_table_identifier(&cfg.responses_table)
        .map_err(|e| format!("openai_response_store: invalid responses_table: {e}"))?;
    validate_table_identifier(&cfg.conversations_table)
        .map_err(|e| format!("openai_response_store: invalid conversations_table: {e}"))?;
    if cfg.responses_table.eq_ignore_ascii_case(&cfg.conversations_table) {
        return Err("openai_response_store: response and conversation table names must be distinct".into());
    }
    Ok(())
}

/// Reject `..` segments in the SQLite file path to prevent a
/// crafted `database_url` from escaping the intended directory
/// and creating or overwriting files elsewhere on the filesystem.
fn validate_database_url(database_url: &str) -> Result<(), FilterError> {
    if is_memory_database_url(database_url) {
        return Ok(());
    }

    let path = sqlite_file_path(database_url).unwrap_or(database_url);
    if has_dot_dot_traversal(path) {
        return Err("openai_response_store: database_url must not contain '..' path traversal".into());
    }
    Ok(())
}

/// Return whether a SQLite URL targets an in-memory database.
fn is_memory_database_url(database_url: &str) -> bool {
    let url = database_url.trim();
    if url == "sqlite::memory:" || url == "sqlite://:memory:" {
        return true;
    }
    url.split_once('?')
        .map_or("", |(_, query)| query)
        .split('&')
        .any(|param| param == "mode=memory")
}

/// Extract the file path component from a SQLite URL.
fn sqlite_file_path(database_url: &str) -> Option<&str> {
    database_url
        .strip_prefix("sqlite://")
        .or_else(|| database_url.strip_prefix("sqlite:"))
        .map(|rest| rest.split_once('?').map_or(rest, |(path, _query)| path))
}
