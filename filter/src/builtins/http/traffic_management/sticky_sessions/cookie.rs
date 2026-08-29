// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Cookie parsing and injection utilities for sticky sessions.

use super::config::CookieAttributes;

/// Extract the value of a named cookie from a `Cookie` header string.
///
/// Handles the standard `Cookie: name1=val1; name2=val2` format.
/// Returns `None` if the cookie is not found.
#[must_use]
pub(crate) fn extract_cookie_value<'a>(cookie_header: &'a str, name: &str) -> Option<&'a str> {
    cookie_header.split(';').map(str::trim).find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (k.trim() == name).then_some(v.trim())
    })
}

/// Extract a session identifier from a `Set-Cookie` response header.
///
/// Looks for `name=value` as the first pair before any `;` attribute.
/// Returns the value portion if the cookie name matches.
#[must_use]
pub(crate) fn extract_set_cookie_value<'a>(set_cookie_header: &'a str, name: &str) -> Option<&'a str> {
    let first_pair = set_cookie_header.split(';').next()?.trim();
    let (k, v) = first_pair.split_once('=')?;
    (k.trim() == name).then_some(v.trim())
}

/// Build a `Set-Cookie` header value with the given attributes.
#[must_use]
pub(crate) fn build_set_cookie(name: &str, value: &str, attrs: &CookieAttributes, ttl_secs: u64) -> String {
    use std::fmt::Write as _;

    // Pre-size for the pair plus typical attributes so the builder does
    // not grow through reallocation; Max-Age digits are written straight
    // into the buffer instead of via an intermediate String.
    let mut cookie = String::with_capacity(name.len() + value.len() + 64);
    let _infallible = write!(cookie, "{name}={value}");
    if let Some(path) = &attrs.path {
        cookie.push_str("; Path=");
        cookie.push_str(path);
    }
    if let Some(domain) = &attrs.domain {
        cookie.push_str("; Domain=");
        cookie.push_str(domain);
    }
    let _infallible = write!(cookie, "; Max-Age={ttl_secs}");
    if attrs.http_only {
        cookie.push_str("; HttpOnly");
    }
    if attrs.secure {
        cookie.push_str("; Secure");
    }
    if let Some(ss) = &attrs.same_site {
        cookie.push_str("; SameSite=");
        cookie.push_str(ss.as_str());
    }
    cookie
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builtins::http::traffic_management::sticky_sessions::config::SameSite;

    #[test]
    fn extract_cookie_first() {
        let header = "_praxis_route=abc123; other=xyz";
        assert_eq!(extract_cookie_value(header, "_praxis_route"), Some("abc123"));
    }

    #[test]
    fn extract_cookie_last() {
        let header = "foo=bar; _praxis_route=endpoint42";
        assert_eq!(extract_cookie_value(header, "_praxis_route"), Some("endpoint42"));
    }

    #[test]
    fn extract_cookie_missing() {
        let header = "foo=bar; baz=qux";
        assert_eq!(extract_cookie_value(header, "_praxis_route"), None);
    }

    #[test]
    fn extract_cookie_spaces() {
        let header = " _praxis_route = abc123 ; other = xyz ";
        assert_eq!(extract_cookie_value(header, "_praxis_route"), Some("abc123"));
    }

    #[test]
    fn extract_set_cookie_match() {
        let header = "JSESSIONID=abc.node1; Path=/; HttpOnly";
        assert_eq!(extract_set_cookie_value(header, "JSESSIONID"), Some("abc.node1"));
    }

    #[test]
    fn extract_set_cookie_no_match() {
        let header = "OTHER=val; Path=/";
        assert_eq!(extract_set_cookie_value(header, "JSESSIONID"), None);
    }

    #[test]
    fn build_cookie_full_attributes() {
        let attrs = CookieAttributes {
            domain: Some("example.com".into()),
            path: Some("/api".into()),
            http_only: true,
            secure: true,
            same_site: Some(SameSite::Strict),
        };
        let result = build_set_cookie("_sess", "ep1", &attrs, 3600);
        assert_eq!(
            result,
            "_sess=ep1; Path=/api; Domain=example.com; Max-Age=3600; HttpOnly; Secure; SameSite=Strict"
        );
    }

    #[test]
    fn build_cookie_minimal_attributes() {
        let attrs = CookieAttributes::default();
        let result = build_set_cookie("_sess", "ep1", &attrs, 1800);
        assert_eq!(result, "_sess=ep1; Max-Age=1800");
    }
}
