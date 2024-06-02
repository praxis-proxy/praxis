//! Hop-by-hop header stripping on upstream requests (RFC 9110).

use pingora_http::RequestHeader;

// -----------------------------------------------------------------------------
// Hop-by-hop Header Stripping
// -----------------------------------------------------------------------------

/// RFC 9110 hop-by-hop headers that must not be forwarded.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Strip hop-by-hop headers from an upstream request.
///
/// Removes all RFC-defined hop-by-hop headers plus any custom
/// headers declared in the `Connection` header value.
pub(crate) fn strip_hop_by_hop(req: &mut RequestHeader) {
    // Collect custom headers named in "Connection: X-Foo, ..."
    let extra: Vec<String> = req
        .headers
        .get_all("connection")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect();

    for name in HOP_BY_HOP {
        let _ = req.remove_header(*name);
    }

    for name in &extra {
        if !HOP_BY_HOP.contains(&name.as_str()) {
            let _ = req.remove_header(name.as_str());
        }
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_request(headers: &[(&str, &str)]) -> RequestHeader {
        let mut req = RequestHeader::build("GET", b"/", None).unwrap();
        for (name, value) in headers {
            let _ = req.insert_header(name.to_string(), value.to_string());
        }
        req
    }

    #[test]
    fn strips_standard_hop_by_hop() {
        let mut req = make_request(&[
            ("connection", "close"),
            ("keep-alive", "300"),
            ("transfer-encoding", "chunked"),
            ("upgrade", "websocket"),
            ("te", "trailers"),
            ("trailer", "X-Checksum"),
            ("proxy-authorization", "Basic abc"),
            ("proxy-authenticate", "Basic"),
            ("x-real-header", "keep-me"),
        ]);

        strip_hop_by_hop(&mut req);

        assert!(req.headers.get("connection").is_none());
        assert!(req.headers.get("keep-alive").is_none());
        assert!(req.headers.get("transfer-encoding").is_none());
        assert!(req.headers.get("upgrade").is_none());
        assert!(req.headers.get("te").is_none());
        assert!(req.headers.get("trailer").is_none());
        assert!(req.headers.get("proxy-authorization").is_none());
        assert!(req.headers.get("proxy-authenticate").is_none());
        assert_eq!(req.headers.get("x-real-header").unwrap(), "keep-me");
    }

    #[test]
    fn strips_custom_connection_headers() {
        let mut req = make_request(&[
            ("connection", "X-Custom, X-Debug"),
            ("x-custom", "secret"),
            ("x-debug", "true"),
            ("x-safe", "keep"),
        ]);

        strip_hop_by_hop(&mut req);

        assert!(req.headers.get("connection").is_none());
        assert!(req.headers.get("x-custom").is_none());
        assert!(req.headers.get("x-debug").is_none());
        assert_eq!(req.headers.get("x-safe").unwrap(), "keep");
    }

    #[test]
    fn no_hop_by_hop_headers_is_noop() {
        let mut req = make_request(&[
            ("host", "example.com"),
            ("accept", "text/html"),
            ("authorization", "Bearer tok"),
            ("content-type", "application/json"),
        ]);

        strip_hop_by_hop(&mut req);

        assert_eq!(req.headers.get("host").unwrap(), "example.com");
        assert_eq!(req.headers.get("accept").unwrap(), "text/html");
        assert_eq!(req.headers.get("authorization").unwrap(), "Bearer tok");
        assert_eq!(req.headers.get("content-type").unwrap(), "application/json");
    }

    #[test]
    fn connection_header_with_single_value() {
        let mut req = make_request(&[("connection", "X-Only"), ("x-only", "gone"), ("x-keep", "stay")]);

        strip_hop_by_hop(&mut req);

        assert!(req.headers.get("connection").is_none());
        assert!(req.headers.get("x-only").is_none());
        assert_eq!(req.headers.get("x-keep").unwrap(), "stay");
    }

    #[test]
    fn connection_value_with_whitespace_variations() {
        let mut req = make_request(&[
            ("connection", " X-A ,  X-B  , X-C "),
            ("x-a", "1"),
            ("x-b", "2"),
            ("x-c", "3"),
            ("x-d", "4"),
        ]);

        strip_hop_by_hop(&mut req);

        assert!(req.headers.get("x-a").is_none());
        assert!(req.headers.get("x-b").is_none());
        assert!(req.headers.get("x-c").is_none());
        assert_eq!(req.headers.get("x-d").unwrap(), "4");
    }

    #[test]
    fn connection_value_case_insensitive() {
        let mut req = make_request(&[("connection", "X-MiXeD-CaSe"), ("x-mixed-case", "stripped")]);

        strip_hop_by_hop(&mut req);

        assert!(req.headers.get("x-mixed-case").is_none());
    }

    #[test]
    fn connection_value_referencing_standard_hop_by_hop() {
        // Connection: keep-alive is redundant with the static
        // list, but should not cause issues.
        let mut req = make_request(&[("connection", "keep-alive"), ("keep-alive", "timeout=5")]);

        strip_hop_by_hop(&mut req);

        assert!(req.headers.get("connection").is_none());
        assert!(req.headers.get("keep-alive").is_none());
    }

    #[test]
    fn empty_connection_header_value() {
        let mut req = make_request(&[("connection", ""), ("x-safe", "keep")]);

        strip_hop_by_hop(&mut req);

        assert!(req.headers.get("connection").is_none());
        assert_eq!(req.headers.get("x-safe").unwrap(), "keep");
    }

    #[test]
    fn only_hop_by_hop_headers_all_removed() {
        let mut req = make_request(&[("connection", "close"), ("keep-alive", "300"), ("upgrade", "h2c")]);

        strip_hop_by_hop(&mut req);

        assert!(req.headers.get("connection").is_none());
        assert!(req.headers.get("keep-alive").is_none());
        assert!(req.headers.get("upgrade").is_none());
        // Only the pseudo-headers remain
        assert_eq!(req.headers.len(), 0);
    }

    #[test]
    fn preserves_standard_end_to_end_headers() {
        let mut req = make_request(&[
            ("connection", "close"),
            ("host", "example.com"),
            ("accept", "*/*"),
            ("user-agent", "test/1.0"),
            ("content-length", "42"),
            ("cache-control", "no-cache"),
            ("authorization", "Bearer xyz"),
            ("cookie", "session=abc"),
        ]);

        strip_hop_by_hop(&mut req);

        assert!(req.headers.get("connection").is_none());
        assert_eq!(req.headers.get("host").unwrap(), "example.com");
        assert_eq!(req.headers.get("accept").unwrap(), "*/*");
        assert_eq!(req.headers.get("user-agent").unwrap(), "test/1.0");
        assert_eq!(req.headers.get("content-length").unwrap(), "42");
        assert_eq!(req.headers.get("cache-control").unwrap(), "no-cache");
        assert_eq!(req.headers.get("authorization").unwrap(), "Bearer xyz");
        assert_eq!(req.headers.get("cookie").unwrap(), "session=abc");
    }

    #[test]
    fn empty_request_no_panic() {
        let mut req = RequestHeader::build("GET", b"/", None).unwrap();
        strip_hop_by_hop(&mut req);
        // Just verifying no panic on empty headers
    }
}
