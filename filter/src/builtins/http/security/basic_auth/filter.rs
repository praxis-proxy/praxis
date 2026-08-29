// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! [`BasicAuthFilter`] implementation and `HttpFilter` trait impl.

use std::{
    collections::{HashMap, hash_map::Entry},
    sync::Arc,
};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;

use super::config::{BasicAuthConfig, CredentialSourceConfig, InlineCredential};
use crate::{
    FilterAction, FilterError, Rejection,
    factory::parse_filter_config,
    filter::{HttpFilter, HttpFilterContext},
};

/// Where credentials are looked up.
enum CredentialSource {
    /// Pre-resolved map of username -> SHA-256 password hash.
    Inline(HashMap<Arc<str>, [u8; 32]>),

    /// Named KV store, looked up at request time.
    KvStore(String),
}

impl CredentialSource {
    /// Converts the parsed config source into a runtime [`CredentialSource`].
    fn from_config(config: CredentialSourceConfig) -> Result<Self, FilterError> {
        match config {
            CredentialSourceConfig::Inline(credentials) => Self::build_inline(&credentials),
            CredentialSourceConfig::KvStore(store) => Ok(Self::KvStore(store)),
        }
    }

    /// Resolves and hashes inline credentials into a lookup map.
    fn build_inline(credentials: &[InlineCredential]) -> Result<Self, FilterError> {
        let mut map = HashMap::with_capacity(credentials.len());
        for cred in credentials {
            let raw = cred.source.resolve(&cred.username)?;
            let key = Arc::<str>::from(cred.username.as_str());
            match map.entry(key) {
                Entry::Occupied(_) => return Err(format!("basic_auth: duplicate username '{}'", cred.username).into()),
                Entry::Vacant(e) => e.insert(hash_password(raw.as_bytes())),
            };
        }
        Ok(Self::Inline(map))
    }

    /// Dispatches credential verification to the configured source.
    fn verify(&self, ctx: &HttpFilterContext<'_>, username: &str, password: &str) -> bool {
        match self {
            Self::Inline(credentials) => Self::verify_inline(credentials, username, password),
            Self::KvStore(store_name) => Self::verify_kv(ctx, store_name, username, password),
        }
    }

    /// Verify against inline credential map.
    fn verify_inline(credentials: &HashMap<Arc<str>, [u8; 32]>, username: &str, password: &str) -> bool {
        let provided = hash_password(password.as_bytes());
        verify_password_hash(&provided, credentials.get(username))
    }

    /// Verify against a KV store.
    fn verify_kv(ctx: &HttpFilterContext<'_>, store_name: &str, username: &str, password: &str) -> bool {
        let Some(registry) = ctx.kv_stores else {
            tracing::warn!("KV store registry unavailable, denying request");
            return false;
        };
        let Some(store) = registry.get(store_name) else {
            tracing::warn!(store = %store_name, "KV store not found, denying request");
            return false;
        };
        let provided = hash_password(password.as_bytes());
        let (stored_hash, user_found) = match store.get(username) {
            Some(v) => (hash_password(v.as_ref().as_bytes()), true),
            None => (hash_password(b""), false),
        };
        let stored = user_found.then_some(stored_hash);
        verify_password_hash(&provided, stored.as_ref())
    }
}

/// HTTP Basic Authentication filter (RFC 7617).
///
/// Experimental: requires the `basic-auth-filter` cargo feature,
/// which is off by default. Credentials are stored in plaintext;
/// this filter is intended for development and testing only.
///
/// Extracts credentials from the `Authorization: Basic` header,
/// validates against a configurable credential source (inline
/// list or runtime KV store), and returns 401 with
/// `WWW-Authenticate: Basic realm="..."` on failure.
///
/// # YAML configuration
///
/// ```yaml
/// filter: basic_auth
/// realm: "Restricted"
/// strip_authorization: true
/// credentials:
///   - username: admin
///     password: secret
///   - username: deploy
///     env_var: DEPLOY_PASSWORD
/// ```
pub struct BasicAuthFilter {
    /// Pre-computed `WWW-Authenticate` challenge header value.
    challenge: String,

    /// Whether to strip the `Authorization` header before forwarding.
    strip_authorization: bool,

    /// Credential source (inline or KV store).
    source: CredentialSource,
}

impl BasicAuthFilter {
    /// Resolves inline credentials at construction time so that
    /// per-request processing is a simple map lookup.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if the config is invalid, a credential
    /// username is duplicated, or a referenced environment variable
    /// is not set.
    pub fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        let cfg: BasicAuthConfig = parse_filter_config("basic_auth", config)?;
        let source = CredentialSource::from_config(cfg.source)?;
        let challenge = format!("Basic realm=\"{}\"", cfg.realm);

        tracing::warn!(
            "basic_auth is an experimental filter with plaintext credential storage. \
             It is not suitable for production use."
        );
        Ok(Box::new(Self {
            challenge,
            strip_authorization: cfg.strip_authorization,
            source,
        }))
    }
}

#[async_trait]
impl HttpFilter for BasicAuthFilter {
    fn name(&self) -> &'static str {
        "basic_auth"
    }

    async fn on_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        let Some(auth_value) = ctx.request.headers.get(http::header::AUTHORIZATION) else {
            tracing::debug!("no Authorization header present");
            return Ok(challenge_rejection(&self.challenge));
        };

        let Some((decoded, colon)) = decode_basic_credentials(auth_value) else {
            return Ok(challenge_rejection(&self.challenge));
        };
        let (Some(username), Some(password)) = (decoded.get(..colon), decoded.get(colon + 1..)) else {
            return Ok(challenge_rejection(&self.challenge));
        };

        if !self.source.verify(ctx, username, password) {
            tracing::debug!(username = %username, "authentication failed");
            return Ok(challenge_rejection(&self.challenge));
        }

        tracing::debug!(username = %username, "authentication successful");

        if self.strip_authorization {
            ctx.request_headers_to_remove.push(http::header::AUTHORIZATION);
        }

        Ok(FilterAction::Continue)
    }
}

/// Decode a `Basic` Authorization header into the decoded credential
/// string and the index of its first colon.
///
/// Returning positions instead of copying both halves spares two
/// String allocations per attempt; the caller borrows the username
/// and password from the returned buffer. Runs entirely before any
/// comparison, so the constant-time verification is untouched.
fn decode_basic_credentials(header: &http::HeaderValue) -> Option<(String, usize)> {
    let auth_str = header.to_str().ok()?;

    // RFC 7617: scheme comparison is case-insensitive.
    let encoded = auth_str
        .get(..6)
        .filter(|p| p.eq_ignore_ascii_case("basic "))
        .and_then(|_| auth_str.get(6..))?
        .trim();

    let decoded = STANDARD
        .decode(encoded)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())?;

    // RFC 7617: split on first colon; password may contain colons.
    let colon = decoded.find(':')?;
    Some((decoded, colon))
}

/// Constant-time password hash check with dummy comparison for unknown
/// users to prevent timing-based user enumeration.
///
/// Both inputs are `[u8; 32]` SHA-256 digests, so `ct_eq` always
/// performs a full 32-byte comparison without short-circuiting on
/// length mismatch.
fn verify_password_hash(provided: &[u8; 32], stored: Option<&[u8; 32]>) -> bool {
    const DUMMY_HASH: [u8; 32] = [0_u8; 32];
    let expected = stored.unwrap_or(&DUMMY_HASH);
    let matches: bool = provided.ct_eq(expected).into();
    matches && stored.is_some()
}

/// Builds a 401 rejection with the `WWW-Authenticate` challenge header.
fn challenge_rejection(challenge: &str) -> FilterAction {
    FilterAction::Reject(Rejection::status(401).with_header("WWW-Authenticate", challenge))
}

/// Returns the SHA-256 digest of the given bytes.
fn hash_password(password: &[u8]) -> [u8; 32] {
    Sha256::digest(password).into()
}
