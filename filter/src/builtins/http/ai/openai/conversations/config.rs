// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Configuration types for the conversations filter.

use std::{
    borrow::Cow,
    net::{IpAddr, Ipv4Addr},
};

use percent_encoding::percent_decode_str;
use praxis_core::connectivity::normalize_mapped_ipv4;
use secrecy::{ExposeSecret as _, SecretString};
use serde::Deserialize;

use crate::{
    FilterError,
    builtins::http::{
        ai::store::{SslMode, validate_postgres_table_set_identifiers, validate_table_identifier},
        transformation::has_dot_dot_traversal,
    },
};

// -----------------------------------------------------------------------------
// StorageBackend
// -----------------------------------------------------------------------------

/// Supported storage backends.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum StorageBackend {
    /// SQLite backend (file-backed or in-memory).
    Sqlite,

    /// `PostgreSQL` backend.
    Postgres,
}

// -----------------------------------------------------------------------------
// ConversationsConfig
// -----------------------------------------------------------------------------

/// YAML configuration for the [`OpenaiConversationsFilter`].
///
/// [`OpenaiConversationsFilter`]: super::OpenaiConversationsFilter
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ConversationsConfig {
    /// Storage backend to use.
    pub backend: StorageBackend,

    /// Database connection URL. Wrapped in [`SecretString`] to
    /// prevent accidental logging of credentials.
    pub database_url: SecretString,

    /// Table name for conversation records.
    #[serde(default = "default_conversations_table")]
    pub conversations_table: String,

    /// Table name for conversation item records.
    #[serde(default = "default_items_table")]
    pub items_table: String,

    /// TLS mode for `PostgreSQL` connections.
    ///
    /// Only valid when `backend` is `postgres`. Overrides any
    /// `sslmode` parameter in the connection URL.
    #[serde(default)]
    pub ssl_mode: Option<SslMode>,

    /// Path to a PEM-encoded root CA certificate for `PostgreSQL`
    /// TLS verification.
    ///
    /// Only valid when `backend` is `postgres` and the effective
    /// SSL mode is `verify-ca` or `verify-full`.
    #[serde(default)]
    pub ssl_root_cert: Option<SecretString>,

    /// Allow `PostgreSQL` URLs that target local-sensitive addresses.
    ///
    /// By default, DNS names, localhost, loopback, private,
    /// link-local, cloud metadata, unspecified, and Unix socket
    /// targets are rejected. This opt-in is intended for local
    /// development and tests.
    #[serde(default)]
    pub allow_private_database_url: bool,
}

/// Serde default for [`ConversationsConfig::conversations_table`].
fn default_conversations_table() -> String {
    "openai_conversations".to_owned()
}

/// Serde default for [`ConversationsConfig::items_table`].
fn default_items_table() -> String {
    "openai_conversation_items".to_owned()
}

impl ConversationsConfig {
    /// Return the generated internal responses table name.
    ///
    /// The store constructors require a responses table, but the
    /// conversations filter doesn't use it. This generates a
    /// deterministic name so the DDL runs cleanly; the table
    /// exists but remains empty.
    pub fn responses_table(&self) -> String {
        format!("{}_unused_responses", self.conversations_table)
    }
}

// -----------------------------------------------------------------------------
// Config Validation
// -----------------------------------------------------------------------------

/// Validate the parsed configuration.
pub(crate) fn validate_config(cfg: &ConversationsConfig) -> Result<(), FilterError> {
    let database_url = cfg.database_url.expose_secret();
    if database_url.is_empty() {
        return Err("openai_conversations: 'database_url' must not be empty".into());
    }
    validate_table_identifier(&cfg.conversations_table)
        .map_err(|e| format!("openai_conversations: invalid conversations_table: {e}"))?;
    validate_table_identifier(&cfg.items_table)
        .map_err(|e| format!("openai_conversations: invalid items_table: {e}"))?;
    if cfg.conversations_table.eq_ignore_ascii_case(&cfg.items_table) {
        return Err("openai_conversations: conversations and items table names must be distinct".into());
    }
    let responses_table = cfg.responses_table();
    validate_table_identifier(&responses_table)
        .map_err(|e| format!("openai_conversations: invalid generated responses_table: {e}"))?;
    if responses_table.eq_ignore_ascii_case(&cfg.items_table) {
        return Err("openai_conversations: generated responses and items table names must be distinct".into());
    }
    match cfg.backend {
        StorageBackend::Sqlite => {
            validate_sqlite_database_url(database_url)?;
            reject_postgres_fields(cfg)?;
        },
        StorageBackend::Postgres => {
            validate_postgres_database_url(database_url, cfg.allow_private_database_url)?;
            validate_postgres_table_set_identifiers(&responses_table, &cfg.conversations_table, Some(&cfg.items_table))
                .map_err(|e| format!("openai_conversations: invalid postgres table identifier: {e}"))?;
            validate_postgres_ssl_config(cfg, database_url)?;
        },
    }
    Ok(())
}

/// Reject `..` segments in the SQLite file path.
fn validate_sqlite_database_url(database_url: &str) -> Result<(), FilterError> {
    if is_memory_database_url(database_url) {
        return Ok(());
    }

    let path = sqlite_file_path(database_url).unwrap_or(database_url);
    let path = percent_decode_str(path)
        .decode_utf8()
        .map_err(|e| format!("openai_conversations: database_url path must be valid UTF-8: {e}"))?;
    if has_dot_dot_traversal(&path) {
        return Err("openai_conversations: database_url must not contain '..' path traversal".into());
    }
    Ok(())
}

/// Re-validate only the `PostgreSQL` host/IP portions of the
/// connection URL immediately before `SQLx` resolves and connects.
pub(crate) fn revalidate_postgres_host(cfg: &ConversationsConfig) -> Result<(), FilterError> {
    let database_url = cfg.database_url.expose_secret();
    let Some(after_scheme) = postgres_url_after_scheme(database_url) else {
        return Ok(());
    };
    if let Some(host) = postgres_authority_host(after_scheme) {
        validate_postgres_host_value("host", &host, cfg.allow_private_database_url)?;
    }
    for (key, value) in postgres_query_params(database_url) {
        if is_postgres_hostaddr_param(&key) {
            validate_postgres_hostaddr(&value, cfg.allow_private_database_url)?;
        } else if is_postgres_host_param(&key) {
            validate_postgres_host_value(&key, &value, cfg.allow_private_database_url)?;
        }
    }
    Ok(())
}

/// Validate a `PostgreSQL` connection URL.
fn validate_postgres_database_url(database_url: &str, allow_private: bool) -> Result<(), FilterError> {
    let Some(after_scheme) = postgres_url_after_scheme(database_url) else {
        return Err(
            "openai_conversations: postgres database_url must start with 'postgres://' or 'postgresql://'".into(),
        );
    };

    let mut has_explicit_target = false;
    if let Some(host) = postgres_authority_host(after_scheme) {
        has_explicit_target = true;
        validate_postgres_host_value("host", &host, allow_private)?;
    }

    for (key, value) in postgres_query_params(database_url) {
        if is_postgres_hostaddr_param(&key) {
            has_explicit_target = true;
            validate_postgres_hostaddr(&value, allow_private)?;
        } else if is_postgres_host_param(&key) {
            has_explicit_target = true;
            validate_postgres_host_value(&key, &value, allow_private)?;
        }
    }

    if !has_explicit_target {
        return Err("openai_conversations: postgres database_url must include an explicit host".into());
    }

    Ok(())
}

/// Return the URL portion after an accepted `PostgreSQL` scheme.
fn postgres_url_after_scheme(database_url: &str) -> Option<&str> {
    database_url
        .strip_prefix("postgres://")
        .or_else(|| database_url.strip_prefix("postgresql://"))
}

/// Extract the authority host from a `PostgreSQL` URL.
fn postgres_authority_host(after_scheme: &str) -> Option<Cow<'_, str>> {
    let authority = after_scheme.split(['/', '?', '#']).next().unwrap_or_default();
    let host_port = authority.rsplit_once('@').map_or(authority, |(_, host)| host);
    if host_port.is_empty() {
        return None;
    }

    let host = if let Some(bracketed) = host_port.strip_prefix('[') {
        bracketed.split_once(']').map_or(host_port, |(host, _)| host)
    } else {
        host_port.rsplit_once(':').map_or(host_port, |(host, port)| {
            if port.bytes().all(|b| b.is_ascii_digit()) {
                host
            } else {
                host_port
            }
        })
    };
    if host.is_empty() {
        return None;
    }

    Some(percent_decode_str(host).decode_utf8_lossy())
}

/// Validate a `PostgreSQL` host value from authority or query params.
fn validate_postgres_host_value(kind: &str, host: &str, allow_private: bool) -> Result<(), FilterError> {
    if host.is_empty() {
        return Err(format!("openai_conversations: database_url {kind} must not be empty").into());
    }
    if host.starts_with('/') {
        return validate_postgres_socket_path(kind, host, allow_private);
    }
    if !allow_private && is_postgres_localhost_name(host) {
        return Err(format!(
            "openai_conversations: database_url {kind} targets localhost; \
             set allow_private_database_url: true to allow"
        )
        .into());
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        validate_postgres_ip_target(kind, ip, allow_private)?;
    } else if let Some(ip) = parse_legacy_ipv4_host(host) {
        validate_postgres_ip_target(kind, IpAddr::V4(ip), allow_private)?;
    } else {
        validate_postgres_dns_target(kind, host, allow_private)?;
    }
    Ok(())
}

/// Validate a `PostgreSQL` `hostaddr` query parameter.
fn validate_postgres_hostaddr(value: &str, allow_private: bool) -> Result<(), FilterError> {
    let ip = value.parse::<IpAddr>().map_err(|e| {
        format!("openai_conversations: database_url parameter 'hostaddr' must be a valid IP address: {e}")
    })?;
    validate_postgres_ip_target("hostaddr", ip, allow_private)
}

/// Validate a `PostgreSQL` IP target against SSRF-sensitive ranges.
fn validate_postgres_ip_target(kind: &str, ip: IpAddr, allow_private: bool) -> Result<(), FilterError> {
    let ip = normalize_mapped_ipv4(ip);
    if !allow_private && is_postgres_ssrf_sensitive_ip(&ip) {
        return Err(format!(
            "openai_conversations: database_url {kind} targets a local-sensitive address; \
             set allow_private_database_url: true to allow"
        )
        .into());
    }
    Ok(())
}

/// Reject a `PostgreSQL` DNS hostname unless private targets are opted in.
fn validate_postgres_dns_target(kind: &str, host: &str, allow_private: bool) -> Result<(), FilterError> {
    if allow_private {
        return Ok(());
    }

    Err(format!(
        "openai_conversations: database_url {kind} host '{host}' is a DNS name; \
         use a literal IP address or set allow_private_database_url: true to allow DNS targets"
    )
    .into())
}

/// Validate a `PostgreSQL` Unix socket path.
fn validate_postgres_socket_path(kind: &str, path: &str, allow_private: bool) -> Result<(), FilterError> {
    if has_dot_dot_traversal(path) {
        return Err(format!("openai_conversations: database_url {kind} must not contain '..' path traversal").into());
    }
    if !allow_private {
        return Err(format!(
            "openai_conversations: database_url {kind} targets a Unix socket; \
             set allow_private_database_url: true to allow"
        )
        .into());
    }
    Ok(())
}

/// Return whether a `PostgreSQL` IP target is SSRF-sensitive.
fn is_postgres_ssrf_sensitive_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local() || v4.is_unspecified(),
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unique_local() || v6.is_unicast_link_local() || v6.is_unspecified(),
    }
}

/// Parse legacy IPv4 literals accepted by common libc resolvers.
fn parse_legacy_ipv4_host(host: &str) -> Option<Ipv4Addr> {
    let host = host.trim_end_matches('.');
    let parts: Vec<_> = host.split('.').collect();
    if parts.is_empty() || parts.len() > 4 || parts.iter().any(|part| part.is_empty()) {
        return None;
    }

    let mut numbers = Vec::with_capacity(parts.len());
    for part in parts {
        numbers.push(parse_legacy_ipv4_number(part)?);
    }

    let addr = match numbers.as_slice() {
        [a] => *a,
        [a, b] if *a <= 0xFF && *b <= 0x00FF_FFFF => (*a << 24) | *b,
        [a, b, c] if *a <= 0xFF && *b <= 0xFF && *c <= 0xFFFF => (*a << 24) | (*b << 16) | *c,
        [a, b, c, d] if numbers.iter().all(|part| *part <= 0xFF) => (*a << 24) | (*b << 16) | (*c << 8) | *d,
        _ => return None,
    };

    Some(Ipv4Addr::from(addr))
}

/// Parse a decimal, octal, or hexadecimal legacy IPv4 component.
fn parse_legacy_ipv4_number(part: &str) -> Option<u32> {
    let (digits, radix) = part.strip_prefix("0x").or_else(|| part.strip_prefix("0X")).map_or_else(
        || {
            if part.len() > 1 && part.starts_with('0') {
                (part.get(1..).unwrap_or_default(), 8)
            } else {
                (part, 10)
            }
        },
        |digits| (digits, 16),
    );

    if digits.is_empty() || !digits.chars().all(|c| c.is_digit(radix)) {
        return None;
    }

    u32::from_str_radix(digits, radix).ok()
}

/// Return whether a host name resolves through the local loopback alias.
fn is_postgres_localhost_name(host: &str) -> bool {
    host.trim_end_matches('.').eq_ignore_ascii_case("localhost")
}

/// Validate `PostgreSQL` TLS options.
fn validate_postgres_ssl_config(cfg: &ConversationsConfig, database_url: &str) -> Result<(), FilterError> {
    validate_postgres_url_tls_file_params(database_url)?;

    if let Some(root_cert) = &cfg.ssl_root_cert {
        let root_cert = root_cert.expose_secret();
        if has_dot_dot_traversal(root_cert) {
            return Err("openai_conversations: ssl_root_cert must not contain '..' path traversal".into());
        }
    }

    if has_postgres_ssl_root_cert(cfg, database_url) && !has_verified_postgres_ssl_mode(cfg, database_url) {
        return Err("openai_conversations: 'ssl_root_cert' requires ssl_mode 'verify-ca' or 'verify-full'".into());
    }
    Ok(())
}

/// Return whether any configured `PostgreSQL` root CA path is present.
fn has_postgres_ssl_root_cert(cfg: &ConversationsConfig, database_url: &str) -> bool {
    cfg.ssl_root_cert.is_some()
        || postgres_query_params(database_url).any(|(key, _)| is_postgres_ssl_root_cert_param(&key))
}

/// Return whether the effective `PostgreSQL` SSL mode verifies certificates.
fn has_verified_postgres_ssl_mode(cfg: &ConversationsConfig, database_url: &str) -> bool {
    match cfg.ssl_mode {
        Some(SslMode::VerifyCa | SslMode::VerifyFull) => true,
        Some(SslMode::Disable | SslMode::Prefer | SslMode::Require) => false,
        None => postgres_url_sslmode(database_url)
            .as_deref()
            .is_some_and(is_verified_postgres_sslmode),
    }
}

/// Extract a raw `sslmode` value from a `PostgreSQL` URL query string.
fn postgres_url_sslmode(database_url: &str) -> Option<String> {
    postgres_query_params(database_url)
        .filter(|(key, _)| is_postgres_sslmode_param(key))
        .map(|(_, value)| value.into_owned())
        .last()
}

/// Return whether an `sslmode` value enables certificate verification.
fn is_verified_postgres_sslmode(value: &str) -> bool {
    value.eq_ignore_ascii_case("verify-ca") || value.eq_ignore_ascii_case("verify-full")
}

/// Validate `PostgreSQL` TLS file paths embedded in the connection URL.
fn validate_postgres_url_tls_file_params(database_url: &str) -> Result<(), FilterError> {
    for (key, value) in postgres_query_params(database_url) {
        if is_postgres_tls_file_param(&key) && has_dot_dot_traversal(&value) {
            return Err(format!(
                "openai_conversations: database_url parameter '{key}' must not contain '..' path traversal"
            )
            .into());
        }
    }
    Ok(())
}

/// Iterate decoded query parameters from a `PostgreSQL` URL.
fn postgres_query_params(database_url: &str) -> impl Iterator<Item = (Cow<'_, str>, Cow<'_, str>)> + '_ {
    database_url
        .split_once('?')
        .map(|(_, query)| query.split_once('#').map_or(query, |(q, _)| q))
        .into_iter()
        .flat_map(|query| query.split('&'))
        .filter(|param| !param.is_empty())
        .map(|param| {
            let (key, value) = param.split_once('=').map_or((param, ""), |(k, v)| (k, v));
            (
                percent_decode_str(key).decode_utf8_lossy(),
                percent_decode_str(value).decode_utf8_lossy(),
            )
        })
}

/// Return whether a query key configures `PostgreSQL` host by address.
fn is_postgres_hostaddr_param(key: &str) -> bool {
    key == "hostaddr"
}

/// Return whether a query key configures `PostgreSQL` host.
fn is_postgres_host_param(key: &str) -> bool {
    key == "host"
}

/// Return whether a query key configures `PostgreSQL` TLS mode.
fn is_postgres_sslmode_param(key: &str) -> bool {
    key == "sslmode" || key == "ssl-mode"
}

/// Return whether a query key configures the `PostgreSQL` TLS root CA file.
fn is_postgres_ssl_root_cert_param(key: &str) -> bool {
    key == "sslrootcert" || key == "ssl-root-cert" || key == "ssl-ca"
}

/// Return whether a query key configures any `PostgreSQL` TLS file path.
fn is_postgres_tls_file_param(key: &str) -> bool {
    is_postgres_ssl_root_cert_param(key) || key == "sslcert" || key == "ssl-cert" || key == "sslkey" || key == "ssl-key"
}

/// Reject `PostgreSQL`-specific fields when backend is SQLite.
fn reject_postgres_fields(cfg: &ConversationsConfig) -> Result<(), FilterError> {
    if cfg.ssl_mode.is_some() {
        return Err("openai_conversations: 'ssl_mode' is only valid with the 'postgres' backend".into());
    }
    if cfg.ssl_root_cert.is_some() {
        return Err("openai_conversations: 'ssl_root_cert' is only valid with the 'postgres' backend".into());
    }
    if cfg.allow_private_database_url {
        return Err(
            "openai_conversations: 'allow_private_database_url' is only valid with the 'postgres' backend".into(),
        );
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
