// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! The effective client address: the TCP peer, or the client a trusted proxy
//! chain reported in `X-Forwarded-For`.
//!
//! RFC 7239 `Forwarded` is not read.

use std::net::{IpAddr, Ipv4Addr};

use http::HeaderMap;
use praxis_core::connectivity::{CidrRange, normalize_mapped_ipv4};

// -----------------------------------------------------------------------------
// ClientAddress
// -----------------------------------------------------------------------------

/// Where an effective client address came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AddressSource {
    /// The TCP peer.
    Peer,
    /// An `X-Forwarded-For` hop reported by a trusted peer.
    Forwarded,
}

/// An effective client address, without a port, and its source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ClientAddress {
    /// The address; IPv4-mapped IPv6 is normalized to IPv4.
    pub(crate) ip: IpAddr,
    /// Where it came from.
    pub(crate) source: AddressSource,
}

// -----------------------------------------------------------------------------
// Resolution
// -----------------------------------------------------------------------------

/// Resolve the effective client address of a request from `peer`.
///
/// `X-Forwarded-For` is read only when `peer` is in `trusted`. Its field lines
/// are joined and walked right to left; the first hop outside `trusted` is
/// the client, and the leftmost hop when every hop is trusted. Hops left of
/// the client are never parsed, since a client can write anything there. A
/// malformed or non-text hop reached before the client yields no address,
/// not the trusted peer, so clients cannot collapse onto a proxy's address.
/// A trusted peer with no `X-Forwarded-For` is the client. No peer, no
/// address.
pub(crate) fn resolve_client_address(
    headers: &HeaderMap,
    peer: Option<IpAddr>,
    trusted: &[CidrRange],
) -> Option<ClientAddress> {
    let peer = normalize_mapped_ipv4(peer?);
    if !is_trusted(peer, trusted) || !headers.contains_key("x-forwarded-for") {
        return Some(ClientAddress {
            ip: peer,
            source: AddressSource::Peer,
        });
    }
    forwarded_client(headers, trusted).map(|ip| ClientAddress {
        ip,
        source: AddressSource::Forwarded,
    })
}

/// Whether `ip` is in any of `trusted`, within each range's family.
fn is_trusted(ip: IpAddr, trusted: &[CidrRange]) -> bool {
    trusted.iter().any(|range| range.contains_same_family(&ip))
}

/// The client `X-Forwarded-For` names, walking hops right to left and
/// stopping at the first untrusted one; `None` when a hop reached first is
/// malformed.
fn forwarded_client(headers: &HeaderMap, trusted: &[CidrRange]) -> Option<IpAddr> {
    let mut leftmost = None;
    for hop in hops_right_to_left(headers) {
        let ip = hop?;
        if !is_trusted(ip, trusted) {
            return Some(ip);
        }
        leftmost = Some(ip);
    }
    leftmost
}

/// Every `X-Forwarded-For` hop, rightmost first, parsed lazily; `None` for a
/// malformed hop.
fn hops_right_to_left(headers: &HeaderMap) -> impl Iterator<Item = Option<IpAddr>> + '_ {
    headers
        .get_all("x-forwarded-for")
        .iter()
        .rev()
        // A non-text line reads as one empty, hence malformed, hop.
        .flat_map(|line| line.to_str().unwrap_or_default().rsplit(','))
        .map(parse_hop)
}

/// One `X-Forwarded-For` hop: an IP, optionally with a port (`[v6]:port` for
/// IPv6).
fn parse_hop(raw: &str) -> Option<IpAddr> {
    let hop = raw.trim();
    let ip = match hop.strip_prefix('[') {
        Some(bracketed) => {
            let (inner, tail) = bracketed.split_once(']')?;
            (tail.is_empty() || tail.strip_prefix(':').is_some_and(is_port))
                .then(|| inner.parse().ok())
                .flatten()?
        },
        None => hop.parse().ok().or_else(|| {
            hop.rsplit_once(':')
                .filter(|(_, port)| is_port(port))
                .and_then(|(host, _)| host.parse::<Ipv4Addr>().ok())
                .map(IpAddr::V4)
        })?,
    };
    Some(normalize_mapped_ipv4(ip))
}

/// Whether `text` is a decimal port.
fn is_port(text: &str) -> bool {
    text.parse::<u16>().is_ok()
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::expect_used, reason = "tests")]
mod tests {
    use std::net::IpAddr;

    use http::HeaderMap;
    use praxis_core::connectivity::CidrRange;

    use super::{AddressSource, ClientAddress, resolve_client_address};

    #[test]
    fn a_direct_peer_is_the_client() {
        assert_eq!(resolve(&[], Some("203.0.113.7")), peer("203.0.113.7"));
        assert_eq!(
            resolve(&[], Some("10.0.0.2")),
            peer("10.0.0.2"),
            "a trusted peer with no XFF"
        );
    }

    #[test]
    fn a_trusted_chain_yields_the_rightmost_untrusted_hop() {
        assert_eq!(
            resolve(&["198.51.100.1, 203.0.113.7, 10.0.0.1"], Some("10.0.0.2")),
            forwarded("203.0.113.7"),
            "the client the first trusted proxy saw, not a hop it could not vouch for"
        );
    }

    #[test]
    fn an_untrusted_peer_cannot_spoof_the_client() {
        assert_eq!(resolve(&["198.51.100.1"], Some("203.0.113.7")), peer("203.0.113.7"));
    }

    #[test]
    fn a_wildcard_trusts_only_its_own_family() {
        let all_v4 = [CidrRange::parse("0.0.0.0/0").expect("cidr")];
        assert_eq!(
            resolve_client_address(&xff(&["198.51.100.1"]), Some(ip("2001:db8::7")), &all_v4),
            peer("2001:db8::7"),
            "an IPv6 client cannot choose its address under an IPv4 wildcard"
        );
        assert_eq!(
            resolve_client_address(&xff(&["198.51.100.1"]), Some(ip("203.0.113.9")), &all_v4),
            forwarded("198.51.100.1")
        );
        let all_v6 = [CidrRange::parse("::/0").expect("cidr")];
        assert_eq!(
            resolve_client_address(&xff(&["2001:db8::1"]), Some(ip("203.0.113.9")), &all_v6),
            peer("203.0.113.9")
        );
    }

    #[test]
    fn a_malformed_hop_before_the_client_yields_no_address() {
        for value in [
            "203.0.113.7, unknown",
            "203.0.113.7,,10.0.0.1",
            "",
            "_hidden",
            "[::1",
            "1.2.3.4:x",
        ] {
            assert_eq!(resolve(&[value], Some("10.0.0.2")), None, "{value:?}");
        }
    }

    #[test]
    fn junk_left_of_the_client_is_ignored() {
        for value in [
            "unknown, 203.0.113.7",
            "_hidden, [::1, 203.0.113.7, 10.0.0.1",
            ",203.0.113.7",
        ] {
            assert_eq!(
                resolve(&[value], Some("10.0.0.2")),
                forwarded("203.0.113.7"),
                "{value:?}"
            );
        }
        assert_eq!(
            resolve(&["junk", "203.0.113.7"], Some("10.0.0.2")),
            forwarded("203.0.113.7"),
            "an earlier field line"
        );
    }

    #[test]
    fn a_non_text_line_is_a_malformed_hop() {
        let mut headers = HeaderMap::new();
        let opaque = http::HeaderValue::from_bytes(b"\xff").expect("header value");
        headers.append("x-forwarded-for", opaque.clone());
        headers.append("x-forwarded-for", "203.0.113.7".parse().expect("header value"));
        let peer = Some(ip("10.0.0.2"));
        assert_eq!(
            resolve_client_address(&headers, peer, &trusted()),
            forwarded("203.0.113.7"),
            "left of the client"
        );
        headers.append("x-forwarded-for", opaque);
        assert_eq!(
            resolve_client_address(&headers, peer, &trusted()),
            None,
            "before the client"
        );
    }

    #[test]
    fn an_untrusted_peer_ignores_malformed_forwarded_hops() {
        assert_eq!(resolve(&["junk"], Some("203.0.113.7")), peer("203.0.113.7"));
    }

    #[test]
    fn field_lines_are_joined_in_order() {
        assert_eq!(
            resolve(&["203.0.113.7", "10.0.0.1"], Some("10.0.0.2")),
            forwarded("203.0.113.7")
        );
        assert_eq!(
            resolve(&["10.0.0.1", "203.0.113.7"], Some("10.0.0.2")),
            forwarded("203.0.113.7"),
            "a later line is a later hop"
        );
    }

    #[test]
    fn an_all_trusted_chain_yields_the_leftmost_hop() {
        assert_eq!(
            resolve(&["10.1.1.1, 10.0.0.1"], Some("10.0.0.2")),
            forwarded("10.1.1.1")
        );
    }

    #[test]
    fn ports_are_stripped_and_mapped_ipv4_is_normalized() {
        assert_eq!(
            resolve(&["203.0.113.7:4711"], Some("::ffff:10.0.0.2")),
            forwarded("203.0.113.7"),
            "a mapped trusted peer still matches its IPv4 range"
        );
        assert_eq!(
            resolve(&["[2001:db8::7]:443, [::ffff:10.0.0.1]"], Some("fd00::1")),
            forwarded("2001:db8::7")
        );
        assert_eq!(
            resolve(&["::ffff:203.0.113.7"], Some("10.0.0.2")),
            forwarded("203.0.113.7")
        );
        assert_eq!(resolve(&[], Some("::ffff:203.0.113.7")), peer("203.0.113.7"));
    }

    #[test]
    fn no_peer_means_no_address() {
        assert_eq!(resolve(&["203.0.113.7"], None), None);
    }

    // -----------------------------------------------------------------------------
    // Test Utilities
    // -----------------------------------------------------------------------------

    /// `text` as an address.
    fn ip(text: &str) -> IpAddr {
        text.parse().expect("address")
    }

    /// Headers with one `X-Forwarded-For` field line per entry of `lines`.
    fn xff(lines: &[&str]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for line in lines {
            headers.append("x-forwarded-for", line.parse().expect("header value"));
        }
        headers
    }

    /// The proxies the tests trust.
    fn trusted() -> Vec<CidrRange> {
        ["10.0.0.0/8", "fd00::/8"]
            .into_iter()
            .map(|cidr| CidrRange::parse(cidr).expect("cidr"))
            .collect()
    }

    /// Resolve with [`trusted`] proxies.
    ///
    /// [`trusted`]: trusted
    fn resolve(lines: &[&str], peer: Option<&str>) -> Option<ClientAddress> {
        resolve_client_address(&xff(lines), peer.map(ip), &trusted())
    }

    /// A peer-sourced address.
    fn peer(text: &str) -> Option<ClientAddress> {
        address(text, AddressSource::Peer)
    }

    /// A forwarded address.
    fn forwarded(text: &str) -> Option<ClientAddress> {
        address(text, AddressSource::Forwarded)
    }

    /// A resolved address, as the resolver returns it.
    #[expect(clippy::unnecessary_wraps, reason = "compared with resolver output")]
    fn address(text: &str, source: AddressSource) -> Option<ClientAddress> {
        Some(ClientAddress { ip: ip(text), source })
    }
}
