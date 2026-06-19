// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Header manipulation filter: add, set, or remove request and response headers.

mod ops;

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::needless_raw_strings,
    clippy::needless_raw_string_hashes,
    reason = "tests"
)]
mod tests;

use std::borrow::Cow;

use async_trait::async_trait;
use serde::Deserialize;
use tracing::trace;

use self::ops::{
    append_headers, parse_header_names, parse_header_pairs, remove_headers, set_headers, validate_raw_header_pairs,
};
use crate::{
    FilterAction, FilterError,
    factory::parse_filter_config,
    filter::{HttpFilter, HttpFilterContext},
};

// -----------------------------------------------------------------------------
// HeaderFilterConfig
// -----------------------------------------------------------------------------

/// Configuration for the header manipulation filter.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HeaderFilterConfig {
    /// Headers to append to the upstream request.
    #[serde(default)]
    pub(crate) request_add: Vec<HeaderPair>,

    /// Header names to remove from the upstream request.
    #[serde(default)]
    pub(crate) request_remove: Vec<String>,

    /// Headers to set on the upstream request (overwrites existing values).
    #[serde(default)]
    pub(crate) request_set: Vec<HeaderPair>,

    /// Headers to append to the downstream response.
    #[serde(default)]
    pub(crate) response_add: Vec<HeaderPair>,

    /// Header names to remove from the downstream response.
    #[serde(default)]
    pub(crate) response_remove: Vec<String>,

    /// Headers to set on the downstream response (overwrites existing values).
    #[serde(default)]
    pub(crate) response_set: Vec<HeaderPair>,
}

/// A name/value pair used in header add/set/remove config.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HeaderPair {
    /// Header field name.
    pub(crate) name: String,

    /// Header field value.
    pub(crate) value: String,
}

// -----------------------------------------------------------------------------
// HeaderFilter
// -----------------------------------------------------------------------------

/// Adds, sets, or removes headers on upstream requests and downstream
/// responses.
///
/// # YAML configuration
///
/// ```yaml
/// filter: headers
/// request_add:
///   - name: X-Forwarded-By
///     value: praxis
/// request_set:
///   - name: X-Custom-Auth
///     value: bearer-token
/// request_remove:
///   - X-Internal-Only
/// response_add:
///   - name: X-Frame-Options
///     value: DENY
/// response_remove:
///   - X-Backend-Server
/// response_set:
///   - name: Server
///     value: praxis
/// ```
///
/// # Example
///
/// ```ignore
/// use praxis_filter::HeaderFilter;
///
/// let yaml: serde_yaml::Value = serde_yaml::from_str(
///     r#"
/// response_set:
///   - name: Server
///     value: praxis
/// "#,
/// )
/// .unwrap();
/// let filter = HeaderFilter::from_config(&yaml).unwrap();
/// assert_eq!(filter.name(), "headers");
/// ```
pub struct HeaderFilter {
    /// Headers to append to the upstream request (raw strings for `Cow` output).
    pub(crate) request_add: Vec<(String, String)>,

    /// Pre-parsed header names to strip from the upstream request.
    pub(crate) request_remove: Vec<http::header::HeaderName>,

    /// Pre-parsed headers to overwrite on the upstream request.
    pub(crate) request_set: Vec<(http::header::HeaderName, http::header::HeaderValue)>,

    /// Pre-parsed headers to append to the downstream response.
    pub(crate) response_add: Vec<(http::header::HeaderName, http::header::HeaderValue)>,

    /// Pre-parsed header names to strip from the downstream response.
    pub(crate) response_remove: Vec<http::header::HeaderName>,

    /// Pre-parsed headers to overwrite on the downstream response.
    pub(crate) response_set: Vec<(http::header::HeaderName, http::header::HeaderValue)>,
}

impl HeaderFilter {
    /// Create a header filter from parsed YAML config.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if the YAML config is invalid.
    ///
    /// [`FilterError`]: crate::FilterError
    pub fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        let cfg: HeaderFilterConfig = parse_filter_config("headers", config)?;

        let request_add = validate_raw_header_pairs(cfg.request_add, "request_add")?;
        let request_remove = parse_header_names(cfg.request_remove, "request_remove")?;
        let request_set = parse_header_pairs(cfg.request_set, "request_set")?;
        let response_add = parse_header_pairs(cfg.response_add, "response_add")?;
        let response_remove = parse_header_names(cfg.response_remove, "response_remove")?;
        let response_set = parse_header_pairs(cfg.response_set, "response_set")?;

        Ok(Box::new(Self {
            request_add,
            request_remove,
            request_set,
            response_add,
            response_remove,
            response_set,
        }))
    }
}

#[async_trait]
impl HttpFilter for HeaderFilter {
    fn name(&self) -> &'static str {
        "headers"
    }

    async fn on_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        for name in &self.request_remove {
            trace!(header = %name, "removing request header");
            ctx.request_headers_to_remove.push(name.clone());
        }

        for (name, value) in &self.request_set {
            trace!(header = %name, "setting request header");
            ctx.request_headers_to_set.push((name.clone(), value.clone()));
        }

        for (name, value) in &self.request_add {
            trace!(header = %name, "adding request header");
            if let Some(existing) = ctx.request.headers.get(name.as_str())
                && let Ok(existing_str) = existing.to_str()
                && let Ok(hdr_name) = http::header::HeaderName::from_bytes(name.as_bytes())
            {
                let combined = format!("{existing_str},{value}");
                if let Ok(combined_val) = http::header::HeaderValue::from_str(&combined) {
                    ctx.request_headers_to_set.push((hdr_name, combined_val));
                    continue;
                }
            }

            ctx.extra_request_headers
                .push((Cow::Owned(name.clone()), value.clone()));
        }
        Ok(FilterAction::Continue)
    }

    async fn on_response(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        let Some(resp) = ctx.response_header.as_mut() else {
            return Ok(FilterAction::Continue);
        };

        if !self.response_remove.is_empty() || !self.response_add.is_empty() || !self.response_set.is_empty() {
            ctx.response_headers_modified = true;
        }

        remove_headers(&mut resp.headers, &self.response_remove);
        append_headers(&mut resp.headers, &self.response_add);
        set_headers(&mut resp.headers, &self.response_set);

        Ok(FilterAction::Continue)
    }
}
