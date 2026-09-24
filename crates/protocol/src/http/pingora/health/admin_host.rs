// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! DNS rebinding defence for a loopback-bound admin listener.
//!
//! A page the operator visits can rebind its own DNS name to `127.0.0.1`,
//! after which the browser treats the unauthenticated admin API as
//! same-origin. Such requests still carry the attacker's name in `Host`, so a
//! loopback-bound admin listener only answers requests that name loopback.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use http::{Response, header::HOST};
use pingora_http::RequestHeader;
use praxis_core::connectivity::normalize_mapped_ipv4;
use tracing::debug;

use crate::http::pingora::json::json_response;

// -----------------------------------------------------------------------------
// Host Guard
// -----------------------------------------------------------------------------

/// Return a `421` response when the request names a non-loopback host.
///
/// Every `Host` header and any URI authority (the HTTP/2 `:authority`) must
/// satisfy [`is_loopback_host`]. An HTTP/1.1 absolute-form target keeps its
/// authority out of the URI, but the Pingora fork rejects one that disagrees
/// with `Host` at ingress, so the `Host` check covers it. A request that names
/// no host at all (HTTP/1.0) is
/// allowed: browsers always send `Host`, so its absence cannot come from a
/// rebound page, only from a client that already reaches the socket directly.
///
/// `421 Misdirected Request` per [RFC 9110 Section 15.5.20]: this listener is
/// unwilling to answer for the named authority.
///
/// [RFC 9110 Section 15.5.20]: https://datatracker.ietf.org/doc/html/rfc9110#section-15.5.20
pub(crate) fn reject_non_loopback_host(req: &RequestHeader) -> Option<Response<Vec<u8>>> {
    let header_hosts = req.headers.get_all(HOST).iter().map(|value| value.to_str().ok());
    let uri_host = req.uri.authority().map(|authority| Some(authority.as_str()));
    if header_hosts
        .chain(uri_host)
        .all(|host| host.is_some_and(is_loopback_host))
    {
        return None;
    }

    debug!(host = ?req.headers.get(HOST), path = %req.uri.path(), "admin request rejected: non-loopback Host");
    Some(json_response(421, br#"{"error":"misdirected request"}"#))
}

/// Whether a `Host` value (or bind address) names loopback.
///
/// Accepts a loopback IP literal (IPv4, bracketed IPv6, IPv4-mapped IPv6, or
/// an unbracketed IPv6 without port) and `localhost` in any case with an
/// optional trailing dot, each with an optional numeric port. DNS names are
/// rejected, since an attacker controls what they resolve to.
pub(crate) fn is_loopback_host(host: &str) -> bool {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return is_loopback_ip(ip);
    }

    if let Some(bracketed) = host.strip_prefix('[') {
        return bracketed.split_once(']').is_some_and(|(literal, rest)| {
            (rest.is_empty() || rest.strip_prefix(':').is_some_and(is_port))
                && literal
                    .parse::<Ipv6Addr>()
                    .is_ok_and(|addr| is_loopback_ip(IpAddr::V6(addr)))
        });
    }

    host.rsplit_once(':')
        .map_or(Some(host), |(name, port)| is_port(port).then_some(name))
        .is_some_and(|name| name.parse::<Ipv4Addr>().is_ok_and(|addr| addr.is_loopback()) || is_localhost(name))
}

// -----------------------------------------------------------------------------
// Utilities
// -----------------------------------------------------------------------------

/// Whether `ip` is loopback, treating IPv4-mapped IPv6 as IPv4.
fn is_loopback_ip(ip: IpAddr) -> bool {
    normalize_mapped_ipv4(ip).is_loopback()
}

/// Whether `name` is `localhost`, ignoring case and one trailing dot.
fn is_localhost(name: &str) -> bool {
    name.strip_suffix('.').unwrap_or(name).eq_ignore_ascii_case("localhost")
}

/// Whether `port` matches the `port = *DIGIT` grammar of [RFC 3986 Section 3.2.3].
///
/// [RFC 3986 Section 3.2.3]: https://datatracker.ietf.org/doc/html/rfc3986#section-3.2.3
fn is_port(port: &str) -> bool {
    port.bytes().all(|byte| byte.is_ascii_digit())
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
    use http::HeaderValue;

    use super::*;

    #[test]
    fn accepts_ipv4_loopback_with_and_without_port() {
        for host in ["127.0.0.1", "127.0.0.1:9901", "127.1.2.3:80", "127.0.0.1:"] {
            assert!(is_loopback_host(host), "{host} names IPv4 loopback");
        }
    }

    #[test]
    fn accepts_ipv6_loopback_bracketed_and_bare() {
        for host in [
            "[::1]",
            "[::1]:9901",
            "::1",
            "[0:0:0:0:0:0:0:1]:80",
            "[::ffff:127.0.0.1]:9901",
        ] {
            assert!(is_loopback_host(host), "{host} names IPv6 loopback");
        }
    }

    #[test]
    fn accepts_localhost_in_any_case_with_trailing_dot() {
        for host in [
            "localhost",
            "LOCALHOST",
            "LocalHost:9901",
            "localhost.",
            "localhost.:9901",
        ] {
            assert!(is_loopback_host(host), "{host} names localhost");
        }
    }

    #[test]
    fn rejects_dns_names() {
        for host in [
            "attacker.example",
            "attacker.example:9901",
            "localhost.attacker.example",
            "127.0.0.1.attacker.example",
            "foo.localhost",
            "localhost..",
        ] {
            assert!(!is_loopback_host(host), "{host} is a DNS name and must be rejected");
        }
    }

    #[test]
    fn rejects_non_loopback_ip_literals() {
        for host in [
            "0.0.0.0:9901",
            "10.0.0.1",
            "[::]:9901",
            "[2001:db8::1]",
            "::1:80",
            "[::ffff:10.0.0.1]",
        ] {
            assert!(!is_loopback_host(host), "{host} is not loopback");
        }
    }

    #[test]
    fn rejects_empty_and_malformed_hosts() {
        for host in [
            "",
            ":9901",
            "[::1",
            "[::1]x",
            "[::1]:80x",
            "[127.0.0.1]",
            "127.0.0.1:80:80",
            "127.0.0.1:+80",
            "127.1",
            "user@127.0.0.1",
            "127.0.0.1 ",
            "localhost:port",
        ] {
            assert!(!is_loopback_host(host), "{host:?} is malformed and must be rejected");
        }
    }

    #[test]
    fn guard_allows_loopback_host_header() {
        let req = request_with_hosts(b"/api/stats", &[b"127.0.0.1:9901"]);
        assert!(reject_non_loopback_host(&req).is_none(), "loopback Host must pass");
    }

    #[test]
    fn guard_allows_missing_host() {
        let req = request_with_hosts(b"/api/stats", &[]);
        assert!(
            reject_non_loopback_host(&req).is_none(),
            "a request without Host must pass"
        );
    }

    #[test]
    fn guard_rejects_rebound_host_with_421_json() {
        let req = request_with_hosts(b"/api/kv/store/key", &[b"attacker.example:9901"]);
        let resp = reject_non_loopback_host(&req).unwrap();
        assert_eq!(resp.status().as_u16(), 421, "rebound Host must be misdirected");
        assert_eq!(
            resp.body(),
            br#"{"error":"misdirected request"}"#,
            "rejection must use the JSON error style"
        );
        assert_eq!(
            resp.headers()["Content-Type"],
            "application/json",
            "rejection must be JSON"
        );
    }

    #[test]
    fn guard_rejects_empty_host() {
        let req = request_with_hosts(b"/healthy", &[b""]);
        assert!(
            reject_non_loopback_host(&req).is_some(),
            "an empty Host must be rejected"
        );
    }

    #[test]
    fn guard_rejects_non_utf8_host() {
        let req = request_with_hosts(b"/healthy", &[b"local\xffhost"]);
        assert!(
            reject_non_loopback_host(&req).is_some(),
            "a non-UTF-8 Host must be rejected"
        );
    }

    #[test]
    fn guard_rejects_any_non_loopback_host_among_duplicates() {
        let req = request_with_hosts(b"/healthy", &[b"localhost", b"attacker.example"]);
        assert!(
            reject_non_loopback_host(&req).is_some(),
            "every Host header must name loopback"
        );
    }

    #[test]
    fn guard_rejects_non_loopback_request_authority() {
        let mut req = request_with_hosts(b"/api/stats", &[b"localhost"]);
        req.set_uri(http::Uri::from_static("http://attacker.example/api/stats"));
        assert!(
            reject_non_loopback_host(&req).is_some(),
            "a request authority (HTTP/2 :authority) must also name loopback"
        );
    }

    #[test]
    fn guard_allows_loopback_absolute_form_authority_without_host() {
        let req = request_with_hosts(b"http://127.0.0.1:9901/api/stats", &[]);
        assert!(
            reject_non_loopback_host(&req).is_none(),
            "a loopback absolute-form authority must pass"
        );
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// Build a `GET` request header carrying each of `hosts` as a `Host` header.
    fn request_with_hosts(path: &[u8], hosts: &[&[u8]]) -> RequestHeader {
        let mut req = RequestHeader::build("GET", path, None).unwrap();
        for host in hosts {
            req.append_header(HOST, HeaderValue::from_bytes(host).unwrap()).unwrap();
        }
        req
    }
}
