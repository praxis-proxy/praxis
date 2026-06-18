// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Header manipulation operations and config-time validation.

use tracing::trace;

use crate::FilterError;

// -----------------------------------------------------------------------------
// Header Manipulation
// -----------------------------------------------------------------------------

/// Remove pre-parsed header names from the header map.
pub(super) fn remove_headers(headers: &mut http::HeaderMap, names: &[http::header::HeaderName]) {
    for name in names {
        trace!(header = %name, "removing response header");
        headers.remove(name);
    }
}

/// Append pre-parsed header pairs to the header map.
pub(super) fn append_headers(
    headers: &mut http::HeaderMap,
    pairs: &[(http::header::HeaderName, http::header::HeaderValue)],
) {
    for (name, value) in pairs {
        trace!(header = %name, "adding response header");
        headers.append(name.clone(), value.clone());
    }
}

/// Set (overwrite) pre-parsed header pairs on the header map.
pub(super) fn set_headers(
    headers: &mut http::HeaderMap,
    pairs: &[(http::header::HeaderName, http::header::HeaderValue)],
) {
    for (name, value) in pairs {
        trace!(header = %name, "setting response header");
        headers.insert(name.clone(), value.clone());
    }
}

// -----------------------------------------------------------------------------
// Config-Time Validation
// -----------------------------------------------------------------------------

/// Validate header pairs and return raw strings (for request headers
/// that are pushed as `Cow` values).
///
/// # Errors
///
/// Returns [`FilterError`] if any header name or value is invalid.
pub(super) fn validate_raw_header_pairs(
    pairs: Vec<super::HeaderPair>,
    section: &str,
) -> Result<Vec<(String, String)>, FilterError> {
    let mut out = Vec::with_capacity(pairs.len());
    for p in pairs {
        let name = &p.name;
        http::header::HeaderName::from_bytes(p.name.as_bytes()).map_err(|_e| {
            let msg: FilterError = format!("headers filter: invalid header name '{name}' in {section}").into();
            msg
        })?;
        http::header::HeaderValue::from_str(&p.value).map_err(|_e| {
            let msg: FilterError = format!("headers filter: invalid header value for '{name}' in {section}").into();
            msg
        })?;
        out.push((p.name, p.value));
    }
    Ok(out)
}

/// Parse header pairs into pre-validated `HeaderName`/`HeaderValue` types.
///
/// # Errors
///
/// Returns [`FilterError`] if any header name or value is invalid.
pub(super) fn parse_header_pairs(
    pairs: Vec<super::HeaderPair>,
    section: &str,
) -> Result<Vec<(http::header::HeaderName, http::header::HeaderValue)>, FilterError> {
    let mut out = Vec::with_capacity(pairs.len());
    for p in pairs {
        let pname = &p.name;
        let name = http::header::HeaderName::from_bytes(p.name.as_bytes()).map_err(|_e| {
            let msg: FilterError = format!("headers filter: invalid header name '{pname}' in {section}").into();
            msg
        })?;
        let value = http::header::HeaderValue::from_str(&p.value).map_err(|_e| {
            let msg: FilterError = format!("headers filter: invalid header value for '{pname}' in {section}").into();
            msg
        })?;
        out.push((name, value));
    }
    Ok(out)
}

/// Parse a list of header name strings into validated [`HeaderName`] values.
///
/// # Errors
///
/// Returns [`FilterError`] if any name is invalid.
///
/// [`HeaderName`]: http::header::HeaderName
pub(super) fn parse_header_names(
    names: Vec<String>,
    section: &str,
) -> Result<Vec<http::header::HeaderName>, FilterError> {
    names
        .into_iter()
        .map(|name| {
            http::header::HeaderName::from_bytes(name.as_bytes()).map_err(|_e| {
                let msg: FilterError = format!("headers filter: invalid header name '{name}' in {section}").into();
                msg
            })
        })
        .collect()
}
