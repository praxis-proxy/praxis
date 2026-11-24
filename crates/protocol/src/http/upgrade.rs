// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! HTTP/1.1 Upgrade admission and WebSocket handshake validation.

use std::collections::HashSet;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use http::{HeaderMap, Method, Version};

/// A valid single WebSocket offer accepted by the listener policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct WebSocketOffer {
    /// Client key retained for validating the forwarded handshake.
    pub(crate) key: String,
    /// Client-offered subprotocol tokens.
    pub(crate) subprotocols: Vec<String>,
}

/// Parsed client offer borrowing handshake fields from the request head.
struct BorrowedOffer<'head> {
    /// Validated client nonce.
    key: &'head str,
    /// Validated subprotocols in client preference order.
    subprotocols: Vec<&'head str>,
}

/// Local refusal for an invalid, unsupported, or disallowed upgrade request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct UpgradeRefusal {
    /// HTTP status sent to the client.
    pub(crate) status: u16,
    /// Bounded metric and log classification.
    pub(crate) code: &'static str,
    /// Stable, provider-neutral client-facing message.
    pub(crate) message: &'static str,
}

/// Classify an HTTP/1.1 WebSocket attempt; other offers follow ordinary HTTP.
///
/// HTTP/1.0 Upgrade fields are ignored per [RFC 9110 Section 7.8].
///
/// [RFC 9110 Section 7.8]: https://datatracker.ietf.org/doc/html/rfc9110#section-7.8
pub(crate) fn classify_request(
    headers: &HeaderMap,
    method: &Method,
    version: Version,
    websocket_permitted: bool,
) -> Result<Option<WebSocketOffer>, UpgradeRefusal> {
    Ok(
        parse_request(headers, method, version, websocket_permitted)?.map(|offer| WebSocketOffer {
            key: offer.key.to_owned(),
            subprotocols: offer.subprotocols.into_iter().map(str::to_owned).collect(),
        }),
    )
}

/// Parse and validate a client offer without copying header strings.
fn parse_request<'head>(
    headers: &'head HeaderMap,
    method: &Method,
    version: Version,
    websocket_permitted: bool,
) -> Result<Option<BorrowedOffer<'head>>, UpgradeRefusal> {
    if version != Version::HTTP_11 || !contains_list_token(headers, "upgrade", "websocket") {
        return Ok(None);
    }
    if !contains_list_token(headers, "connection", "upgrade") {
        return Err(malformed_handshake());
    }
    validate_connection_tokens(headers)?;
    let single_websocket = is_single_websocket_offer(headers)?;
    if method != Method::GET {
        return Err(malformed_handshake());
    }
    if !single_websocket {
        return Err(unsupported_upgrade());
    }
    let key = websocket_key(headers)?;
    validate_websocket_version(headers)?;
    let subprotocols = parse_subprotocols(headers)?;
    if !websocket_permitted {
        return Err(denied_upgrade());
    }
    Ok(Some(BorrowedOffer { key, subprotocols }))
}

/// Ensure filters preserved the client offer that authorized this upgrade.
#[cfg(feature = "pingora")]
pub(crate) fn validate_forwarded_request(
    offer: &WebSocketOffer,
    method: &Method,
    headers: &HeaderMap,
    version: Version,
) -> Result<(), &'static str> {
    let Ok(Some(forwarded)) = parse_request(headers, method, version, true) else {
        return Err("forwarded request no longer contains a valid WebSocket offer");
    };
    if forwarded.key != offer.key
        || !forwarded
            .subprotocols
            .iter()
            .copied()
            .eq(offer.subprotocols.iter().map(String::as_str))
    {
        return Err("filters changed the admitted WebSocket offer");
    }
    Ok(())
}

/// Detect a relevant token before imposing WebSocket syntax on an ordinary request.
fn contains_list_token(headers: &HeaderMap, name: &str, token: &str) -> bool {
    headers.get_all(name).iter().any(|value| {
        value
            .as_bytes()
            .split(|byte| *byte == b',')
            .any(|item| item.trim_ascii().eq_ignore_ascii_case(token.as_bytes()))
    })
}

/// Parse every `Connection` field as a comma-separated token list.
fn validate_connection_tokens(headers: &HeaderMap) -> Result<(), UpgradeRefusal> {
    for value in headers.get_all("connection") {
        let value = value.to_str().map_err(|_header_error| malformed_handshake())?;
        for token in value.split(',') {
            let token = trim_ows(token);
            if token.is_empty() {
                continue;
            }
            if !is_token(token) {
                return Err(malformed_handshake());
            }
        }
    }
    Ok(())
}

/// Validate Upgrade syntax and check for one unversioned WebSocket offer.
fn is_single_websocket_offer(headers: &HeaderMap) -> Result<bool, UpgradeRefusal> {
    let mut first = None;
    let mut multiple = false;
    for value in headers.get_all("upgrade") {
        let value = value.to_str().map_err(|_header_error| malformed_handshake())?;
        for item in value.split(',') {
            let item = trim_ows(item);
            if item.is_empty() {
                continue;
            }
            let mut parts = item.split('/');
            let name = parts.next().unwrap_or_default();
            let version = parts.next();
            if parts.next().is_some() || !is_token(name) || version.is_some_and(|v| !is_token(v)) {
                return Err(malformed_handshake());
            }
            multiple |= first.replace(item).is_some();
        }
    }
    Ok(!multiple && first.is_some_and(|item| item.eq_ignore_ascii_case("websocket")))
}

/// Validate and retain the one client nonce required by RFC 6455.
fn websocket_key(headers: &HeaderMap) -> Result<&str, UpgradeRefusal> {
    let Some(key) = single_header(headers, "sec-websocket-key") else {
        return Err(malformed_handshake());
    };
    let decoded = STANDARD.decode(key).map_err(|_decode_error| malformed_handshake())?;
    if decoded.len() != 16 {
        return Err(malformed_handshake());
    }
    Ok(key)
}

/// Validate the only WebSocket version supported by this listener adapter.
fn validate_websocket_version(headers: &HeaderMap) -> Result<(), UpgradeRefusal> {
    if single_header(headers, "sec-websocket-version") == Some("13") {
        Ok(())
    } else {
        Err(malformed_handshake())
    }
}

/// Parse the optional client subprotocol list, requiring case-sensitive uniqueness.
///
/// [RFC 6455 Section 4.1] requires unique offered subprotocol strings.
///
/// [RFC 6455 Section 4.1]: https://datatracker.ietf.org/doc/html/rfc6455#section-4.1
fn parse_subprotocols(headers: &HeaderMap) -> Result<Vec<&str>, UpgradeRefusal> {
    let mut protocols = Vec::new();
    let mut seen = HashSet::new();
    for value in headers.get_all("sec-websocket-protocol") {
        let value = value.to_str().map_err(|_header_error| malformed_handshake())?;
        for protocol in value.split(',') {
            let protocol = trim_ows(protocol);
            if protocol.is_empty() {
                continue;
            }
            if !is_token(protocol) || !seen.insert(protocol) {
                return Err(malformed_handshake());
            }
            protocols.push(protocol);
        }
    }
    if protocols.is_empty() && headers.contains_key("sec-websocket-protocol") {
        return Err(malformed_handshake());
    }
    Ok(protocols)
}

/// Read a single ASCII header value with surrounding optional whitespace removed.
fn single_header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?.to_str().ok()?;
    values.next().is_none().then(|| trim_ows(value))
}

/// Trim only HTTP optional whitespace.
fn trim_ows(value: &str) -> &str {
    value.trim_matches(|character| matches!(character, ' ' | '\t'))
}

/// Whether a string contains only HTTP token characters.
fn is_token(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
}

/// Malformed handshake response shared by request-header validation paths.
const fn malformed_handshake() -> UpgradeRefusal {
    UpgradeRefusal {
        status: 400,
        code: "upgrade_handshake_malformed",
        message: "malformed HTTP upgrade request",
    }
}

/// Refusal for a protocol the selected adapter cannot tunnel.
pub(crate) const fn unsupported_upgrade() -> UpgradeRefusal {
    UpgradeRefusal {
        status: 403,
        code: "upgrade_protocol_unsupported",
        message: "requested upgrade protocol is unsupported",
    }
}

/// Listener-policy denial response.
const fn denied_upgrade() -> UpgradeRefusal {
    UpgradeRefusal {
        status: 403,
        code: "upgrade_policy_denied",
        message: "requested upgrade is denied by listener policy",
    }
}

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "test helper assertions use concise unwraps")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test fixtures use valid static HTTP headers"
)]
mod tests {
    use super::*;

    const KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";

    fn valid_request() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("connection", "Upgrade".parse().unwrap());
        headers.insert("upgrade", "websocket".parse().unwrap());
        headers.insert("sec-websocket-key", KEY.parse().unwrap());
        headers.insert("sec-websocket-version", "13".parse().unwrap());
        headers
    }

    #[test]
    fn ordinary_request_is_not_classified_as_upgrade() {
        let mut headers = HeaderMap::new();
        headers.insert("connection", "keep-alive".parse().unwrap());
        assert_eq!(
            classify_request(&headers, &Method::GET, Version::HTTP_11, false).unwrap(),
            None
        );
    }

    #[test]
    fn websocket_accepts_case_variation_and_repeated_connection_tokens() {
        let mut headers = valid_request();
        headers.append("connection", "keep-alive".parse().unwrap());
        headers.append("connection", "uPgRaDe".parse().unwrap());
        headers.insert("upgrade", "WebSocket".parse().unwrap());
        let classified = classify_request(&headers, &Method::GET, Version::HTTP_11, true).unwrap();
        assert!(classified.is_some());
    }

    #[test]
    fn websocket_offer_is_denied_when_listener_does_not_permit_it() {
        let refusal = classify_request(&valid_request(), &Method::GET, Version::HTTP_11, false).unwrap_err();
        assert_eq!(refusal.status, 403);
        assert_eq!(refusal.code, "upgrade_policy_denied");
    }

    #[test]
    fn unknown_upgrade_is_ignored_and_repeated_websocket_is_refused() {
        let mut headers = valid_request();
        headers.insert("upgrade", "h2c".parse().unwrap());
        assert_eq!(
            classify_request(&headers, &Method::GET, Version::HTTP_11, true).unwrap(),
            None
        );

        headers = valid_request();
        headers.append("upgrade", "websocket".parse().unwrap());
        let refusal = classify_request(&headers, &Method::GET, Version::HTTP_11, true).unwrap_err();
        assert_eq!(refusal.status, 403);
        assert_eq!(refusal.code, "upgrade_protocol_unsupported");
    }

    #[test]
    fn malformed_upgrade_values_and_incomplete_handshakes_are_rejected() {
        let mut headers = valid_request();
        headers.insert("upgrade", "websocket, not protocol".parse().unwrap());
        let refusal = classify_request(&headers, &Method::GET, Version::HTTP_11, true).unwrap_err();
        assert_eq!(refusal.status, 400);

        headers = valid_request();
        headers.remove("connection");
        let refusal = classify_request(&headers, &Method::GET, Version::HTTP_11, true).unwrap_err();
        assert_eq!(refusal.status, 400);

        headers.insert("connection", "keep-alive".parse().unwrap());
        let refusal = classify_request(&headers, &Method::GET, Version::HTTP_11, true).unwrap_err();
        assert_eq!(refusal.status, 400);
        assert_eq!(
            classify_request(&valid_request(), &Method::GET, Version::HTTP_2, true).unwrap(),
            None
        );
    }

    #[test]
    #[cfg(feature = "pingora")]
    fn forwarded_request_must_preserve_the_admitted_offer() {
        let request = valid_request();
        let offer = classify_request(&request, &Method::GET, Version::HTTP_11, true)
            .unwrap()
            .unwrap();
        validate_forwarded_request(&offer, &Method::GET, &request, Version::HTTP_11).unwrap();

        let mut changed = request.clone();
        changed.insert("sec-websocket-key", "YWJjZGVmZ2hpamtsbW5vcA==".parse().unwrap());
        assert!(validate_forwarded_request(&offer, &Method::GET, &changed, Version::HTTP_11).is_err());

        changed = request.clone();
        changed.remove("upgrade");
        assert!(validate_forwarded_request(&offer, &Method::GET, &changed, Version::HTTP_11).is_err());
    }

    #[test]
    fn ordinary_requests_do_not_acquire_websocket_syntax_requirements() {
        for connection in [b"not a token".as_slice(), b"\xff".as_slice()] {
            let mut headers = HeaderMap::new();
            headers.insert("connection", http::HeaderValue::from_bytes(connection).unwrap());
            assert_eq!(
                classify_request(&headers, &Method::GET, Version::HTTP_11, true).unwrap(),
                None
            );
        }
        assert_eq!(
            classify_request(&valid_request(), &Method::GET, Version::HTTP_10, true).unwrap(),
            None
        );
        let mut headers = valid_request();
        headers.insert("upgrade", "h2c".parse().unwrap());
        assert_eq!(
            classify_request(&headers, &Method::POST, Version::HTTP_11, true).unwrap(),
            None
        );
    }

    #[test]
    fn websocket_subprotocols_skip_empty_members_and_reject_duplicates() {
        let mut headers = valid_request();
        headers.insert("sec-websocket-protocol", "chat,, superchat,".parse().unwrap());
        let offer = classify_request(&headers, &Method::GET, Version::HTTP_11, true)
            .unwrap()
            .unwrap();
        assert_eq!(offer.subprotocols, ["chat", "superchat"]);
        for value in ["chat, chat", "chat"] {
            headers.insert("sec-websocket-protocol", value.parse().unwrap());
            if value == "chat" {
                headers.append("sec-websocket-protocol", "chat".parse().unwrap());
            }
            assert_eq!(
                classify_request(&headers, &Method::GET, Version::HTTP_11, true)
                    .unwrap_err()
                    .status,
                400
            );
        }
        headers.insert("sec-websocket-protocol", "chat, Chat".parse().unwrap());
        assert_eq!(
            classify_request(&headers, &Method::GET, Version::HTTP_11, true)
                .unwrap()
                .unwrap()
                .subprotocols,
            ["chat", "Chat"]
        );
    }

    #[test]
    fn present_subprotocol_header_requires_at_least_one_token() {
        for value in ["", ", ,"] {
            let mut headers = valid_request();
            headers.insert("sec-websocket-protocol", value.parse().unwrap());
            let refusal = classify_request(&headers, &Method::GET, Version::HTTP_11, true).unwrap_err();
            assert_eq!(refusal.status, 400);
        }
    }

    #[test]
    fn websocket_handshake_requires_get() {
        let refusal = classify_request(&valid_request(), &Method::POST, Version::HTTP_11, true).unwrap_err();
        assert_eq!(refusal.status, 400, "non-GET WebSocket handshakes are malformed");
    }

    #[test]
    fn connection_and_upgrade_lists_ignore_empty_members() {
        let mut headers = valid_request();
        headers.insert("connection", "keep-alive,, Upgrade,".parse().unwrap());
        headers.insert("upgrade", ", websocket, ".parse().unwrap());
        assert!(
            classify_request(&headers, &Method::GET, Version::HTTP_11, true)
                .unwrap()
                .is_some()
        );

        let mut ordinary = HeaderMap::new();
        ordinary.insert("connection", "keep-alive,".parse().unwrap());
        assert_eq!(
            classify_request(&ordinary, &Method::GET, Version::HTTP_11, false).unwrap(),
            None
        );
    }
}
