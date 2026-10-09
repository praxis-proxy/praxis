// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Max-Forwards handling per [RFC 9110 Section 7.6.2].
//!
//! [RFC 9110]: https://datatracker.ietf.org/doc/html/rfc9110
//! [RFC 9110 Section 7.6.2]: https://datatracker.ietf.org/doc/html/rfc9110#section-7.6.2

use pingora_proxy::Session;
use praxis_filter::Rejection;
use tracing::debug;

use super::stream_buffer::build_trace_response;

/// Handle `Max-Forwards` on TRACE and OPTIONS requests per [RFC 9110 Section 7.6.2].
///
/// When `Max-Forwards` is present and zero, the proxy responds directly
/// instead of forwarding. When positive, it decrements and forwards.
/// For non-TRACE/OPTIONS methods, or when the header is absent, returns `None`.
pub(super) async fn handle_max_forwards(session: &mut Session) -> Option<bool> {
    let method = &session.req_header().method;
    if !matches!(*method, http::Method::TRACE | http::Method::OPTIONS) {
        return None;
    }

    let mf = parse_max_forwards(session)?;

    if mf == 0 {
        debug!(method = %method, "Max-Forwards is 0; responding without forwarding");
        let rejection = if *method == http::Method::TRACE {
            build_trace_response(session)
        } else {
            Rejection::status(200)
        };
        crate::http::pingora::convert::send_rejection(session, rejection).await;
        return Some(true);
    }

    debug!(method = %method, max_forwards = mf - 1, "decrementing Max-Forwards");
    let _insert = session
        .req_header_mut()
        .insert_header("max-forwards", (mf - 1).to_string());
    None
}

/// Parse `Max-Forwards` from a Pingora session.
fn parse_max_forwards(session: &Session) -> Option<u32> {
    session
        .req_header()
        .headers
        .get("max-forwards")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<u32>().ok())
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn max_forwards_applies_to_trace() {
        assert!(
            is_max_forwards_method(&http::Method::TRACE),
            "Max-Forwards should apply to TRACE"
        );
    }

    #[test]
    fn max_forwards_applies_to_options() {
        assert!(
            is_max_forwards_method(&http::Method::OPTIONS),
            "Max-Forwards should apply to OPTIONS"
        );
    }

    #[test]
    fn max_forwards_does_not_apply_to_get() {
        assert!(
            !is_max_forwards_method(&http::Method::GET),
            "Max-Forwards should not apply to GET"
        );
    }

    fn is_max_forwards_method(method: &http::Method) -> bool {
        matches!(*method, http::Method::TRACE | http::Method::OPTIONS)
    }

    async fn session_for(raw: &str) -> (Session, tokio::io::DuplexStream) {
        use tokio::io::AsyncWriteExt as _;

        let (mut client, server) = tokio::io::duplex(1_048_576);
        client.write_all(raw.as_bytes()).await.unwrap();
        let mut session = Session::new_h1(Box::new(server));
        let read = session.read_request().await.unwrap();
        assert!(read, "the session must parse the request header");
        (session, client)
    }

    #[tokio::test]
    async fn trace_with_zero_max_forwards_is_answered_directly() {
        let (mut session, _client) = session_for("TRACE / HTTP/1.1\r\nHost: x\r\nMax-Forwards: 0\r\n\r\n").await;
        let handled = handle_max_forwards(&mut session).await;
        assert_eq!(handled, Some(true), "TRACE with Max-Forwards 0 must be answered");
    }

    #[tokio::test]
    async fn options_with_zero_max_forwards_is_answered_directly() {
        let (mut session, _client) = session_for("OPTIONS / HTTP/1.1\r\nHost: x\r\nMax-Forwards: 0\r\n\r\n").await;
        let handled = handle_max_forwards(&mut session).await;
        assert_eq!(handled, Some(true), "OPTIONS with Max-Forwards 0 must be answered");
    }

    #[tokio::test]
    async fn positive_max_forwards_is_decremented() {
        let (mut session, _client) = session_for("TRACE / HTTP/1.1\r\nHost: x\r\nMax-Forwards: 3\r\n\r\n").await;
        let handled = handle_max_forwards(&mut session).await;
        assert_eq!(handled, None, "positive Max-Forwards must forward");
        let value = session
            .req_header()
            .headers
            .get("max-forwards")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        assert_eq!(value.as_deref(), Some("2"), "Max-Forwards must be decremented");
    }

    #[tokio::test]
    async fn get_requests_ignore_max_forwards() {
        let (mut session, _client) = session_for("GET / HTTP/1.1\r\nHost: x\r\nMax-Forwards: 0\r\n\r\n").await;
        let handled = handle_max_forwards(&mut session).await;
        assert_eq!(handled, None, "GET must ignore Max-Forwards");
    }
}
