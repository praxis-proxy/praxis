// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! HTTP/1.1 Upgrade admission and WebSocket handshake validation.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use http::{HeaderMap, Method, Version};

/// A valid single WebSocket offer accepted by the listener policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct WebSocketOffer {
    /// Client key retained for validating the handshake response.
    pub(crate) key: String,
    /// Client-offered subprotocol tokens.
    pub(crate) subprotocols: Vec<String>,
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

/// Classify and validate a downstream HTTP/1.1 upgrade request.
pub(crate) fn classify_request(
    headers: &HeaderMap,
    method: &Method,
    version: Version,
    websocket_permitted: bool,
) -> Result<Option<WebSocketOffer>, UpgradeRefusal> {
    let connection_upgrade = has_connection_upgrade(headers)?;
    let offered_protocols = parse_upgrade_offers(headers)?;
    if offered_protocols.is_empty() && !connection_upgrade {
        return Ok(None);
    }
    if offered_protocols.is_empty() || !connection_upgrade || method != Method::GET || version != Version::HTTP_11 {
        return Err(malformed_handshake());
    }
    if offered_protocols.len() != 1 || offered_protocols.first().map(String::as_str) != Some("websocket") {
        return Err(unsupported_upgrade());
    }
    let key = websocket_key(headers)?;
    validate_websocket_version(headers)?;
    let subprotocols = parse_subprotocols(headers)?;
    if !websocket_permitted {
        return Err(denied_upgrade());
    }
    Ok(Some(WebSocketOffer { key, subprotocols }))
}

/// Check the final, post-filter response before a 101 can reach the client.
#[cfg(feature = "pingora")]
pub(crate) fn validate_response(offer: &WebSocketOffer, headers: &HeaderMap) -> Result<(), &'static str> {
    if !has_connection_upgrade(headers).unwrap_or(false) {
        return Err("invalid WebSocket upgrade response headers");
    }
    let offered_protocols =
        parse_upgrade_offers(headers).map_err(|_parse_error| "WebSocket response has malformed Upgrade syntax")?;
    if offered_protocols.len() != 1 || offered_protocols.first().map(String::as_str) != Some("websocket") {
        return Err("WebSocket response selected multiple or unsupported Upgrade protocols");
    }
    let Some(accept) = single_header(headers, "sec-websocket-accept") else {
        return Err("WebSocket response omitted Sec-WebSocket-Accept");
    };
    if accept.is_empty() {
        return Err("WebSocket response supplied an empty Sec-WebSocket-Accept");
    }
    let challenge = format!("{}258EAFA5-E914-47DA-95CA-C5AB0DC85B11", offer.key);
    let digest = openssl::hash::hash(openssl::hash::MessageDigest::sha1(), challenge.as_bytes())
        .map_err(|_digest_error| "failed to calculate the WebSocket handshake digest")?;
    let expected = STANDARD.encode(digest);
    if accept != expected {
        return Err("WebSocket response supplied an invalid Sec-WebSocket-Accept");
    }
    validate_selected_subprotocol(offer, headers)
}

/// Ensure filters preserved the client offer that authorized this upgrade.
#[cfg(feature = "pingora")]
pub(crate) fn validate_forwarded_request(
    offer: &WebSocketOffer,
    method: &Method,
    headers: &HeaderMap,
    version: Version,
) -> Result<(), &'static str> {
    let Ok(Some(forwarded)) = classify_request(headers, method, version, true) else {
        return Err("forwarded request no longer contains a valid WebSocket offer");
    };
    if forwarded != *offer {
        return Err("filters changed the admitted WebSocket offer");
    }
    Ok(())
}

/// Parse every `Connection` field as a comma-separated token list.
fn has_connection_upgrade(headers: &HeaderMap) -> Result<bool, UpgradeRefusal> {
    let mut found = false;
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
            found |= token.eq_ignore_ascii_case("upgrade");
        }
    }
    Ok(found)
}

/// Parse all offered Upgrade protocol tokens, normalizing protocol names.
fn parse_upgrade_offers(headers: &HeaderMap) -> Result<Vec<String>, UpgradeRefusal> {
    let mut offers = Vec::new();
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
            let protocol = version.map_or_else(
                || name.to_ascii_lowercase(),
                |v| format!("{}/{}", name.to_ascii_lowercase(), v),
            );
            offers.push(protocol);
        }
    }
    Ok(offers)
}

/// Validate and retain the one client nonce required by RFC 6455.
fn websocket_key(headers: &HeaderMap) -> Result<String, UpgradeRefusal> {
    let Some(key) = single_header(headers, "sec-websocket-key") else {
        return Err(malformed_handshake());
    };
    let decoded = STANDARD.decode(key).map_err(|_decode_error| malformed_handshake())?;
    if decoded.len() != 16 {
        return Err(malformed_handshake());
    }
    Ok(key.to_owned())
}

/// Validate the only WebSocket version supported by this listener adapter.
fn validate_websocket_version(headers: &HeaderMap) -> Result<(), UpgradeRefusal> {
    if single_header(headers, "sec-websocket-version") == Some("13") {
        Ok(())
    } else {
        Err(malformed_handshake())
    }
}

/// Parse the optional client subprotocol list.
fn parse_subprotocols(headers: &HeaderMap) -> Result<Vec<String>, UpgradeRefusal> {
    let mut protocols = Vec::new();
    for value in headers.get_all("sec-websocket-protocol") {
        let value = value.to_str().map_err(|_header_error| malformed_handshake())?;
        for protocol in value.split(',') {
            let protocol = trim_ows(protocol);
            if !is_token(protocol) {
                return Err(malformed_handshake());
            }
            protocols.push(protocol.to_owned());
        }
    }
    Ok(protocols)
}

/// Verify an upstream-selected subprotocol was offered exactly once.
#[cfg(feature = "pingora")]
fn validate_selected_subprotocol(offer: &WebSocketOffer, headers: &HeaderMap) -> Result<(), &'static str> {
    let mut selected = headers.get_all("sec-websocket-protocol").iter();
    let Some(value) = selected.next() else {
        return Ok(());
    };
    if selected.next().is_some() {
        return Err("WebSocket response selected multiple subprotocols");
    }
    let Ok(value) = value.to_str() else {
        return Err("WebSocket response selected a malformed subprotocol");
    };
    let value = trim_ows(value);
    if value.contains(',') || !offer.subprotocols.iter().any(|offered| offered == value) {
        return Err("WebSocket response selected an unoffered subprotocol");
    }
    Ok(())
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
    #[cfg(feature = "pingora")]
    const ACCEPT: &str = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

    fn valid_request() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("connection", "Upgrade".parse().unwrap());
        headers.insert("upgrade", "websocket".parse().unwrap());
        headers.insert("sec-websocket-key", KEY.parse().unwrap());
        headers.insert("sec-websocket-version", "13".parse().unwrap());
        headers
    }

    #[cfg(feature = "pingora")]
    fn valid_response() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("connection", "Upgrade".parse().unwrap());
        headers.insert("upgrade", "WebSocket".parse().unwrap());
        headers.insert("sec-websocket-accept", ACCEPT.parse().unwrap());
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
        headers.insert("upgrade", "WebSocket".parse().unwrap());
        headers.remove("upgrade");
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
    fn unsupported_and_repeated_upgrade_protocols_are_refused() {
        let mut headers = valid_request();
        headers.insert("upgrade", "h2c".parse().unwrap());
        let refusal = classify_request(&headers, &Method::GET, Version::HTTP_11, true).unwrap_err();
        assert_eq!(refusal.status, 403);
        assert_eq!(refusal.code, "upgrade_protocol_unsupported");

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

        let refusal = classify_request(&valid_request(), &Method::GET, Version::HTTP_2, true).unwrap_err();
        assert_eq!(refusal.status, 400);
    }

    #[test]
    #[cfg(feature = "pingora")]
    fn response_requires_the_matching_accept_and_offered_subprotocol() {
        let mut request = valid_request();
        request.insert("sec-websocket-protocol", "chat, superchat".parse().unwrap());
        let offer = classify_request(&request, &Method::GET, Version::HTTP_11, true)
            .unwrap()
            .unwrap();
        validate_response(&offer, &valid_response()).unwrap();

        let mut response = valid_response();
        response.insert("sec-websocket-accept", "incorrect".parse().unwrap());
        assert!(validate_response(&offer, &response).is_err());

        response = valid_response();
        response.insert("sec-websocket-protocol", "other".parse().unwrap());
        assert!(validate_response(&offer, &response).is_err());
    }

    #[test]
    #[cfg(feature = "pingora")]
    fn response_distinguishes_multiple_protocols_from_malformed_upgrade_syntax() {
        let offer = classify_request(&valid_request(), &Method::GET, Version::HTTP_11, true)
            .unwrap()
            .unwrap();
        let mut response = valid_response();
        response.insert("upgrade", "websocket, permessage-deflate".parse().unwrap());
        assert_eq!(
            validate_response(&offer, &response),
            Err("WebSocket response selected multiple or unsupported Upgrade protocols"),
            "a syntactically valid list of unsupported protocols is not malformed"
        );

        response.insert("upgrade", "websocket, bad protocol".parse().unwrap());
        assert_eq!(
            validate_response(&offer, &response),
            Err("WebSocket response has malformed Upgrade syntax"),
            "invalid token syntax should be classified separately"
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
