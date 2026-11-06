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
/// the client, and the leftmost hop when every hop is trusted. A missing,
/// non-text or malformed value falls back to the peer. No peer, no address.
pub(crate) fn resolve_client_address(
    headers: &HeaderMap,
    peer: Option<IpAddr>,
    trusted: &[CidrRange],
) -> Option<ClientAddress> {
    let peer = normalize_mapped_ipv4(peer?);
    let forwarded = is_trusted(peer, trusted)
        .then(|| forwarded_client(headers, trusted))
        .flatten();
    Some(forwarded.map_or(
        ClientAddress {
            ip: peer,
            source: AddressSource::Peer,
        },
        |ip| ClientAddress {
            ip,
            source: AddressSource::Forwarded,
        },
    ))
}

/// Whether `ip` is in any of `trusted`.
fn is_trusted(ip: IpAddr, trusted: &[CidrRange]) -> bool {
    trusted.iter().any(|range| range.contains(&ip))
}

/// The client `X-Forwarded-For` names, or `None` when it is absent or any
/// hop is malformed.
fn forwarded_client(headers: &HeaderMap, trusted: &[CidrRange]) -> Option<IpAddr> {
    let mut hops = Vec::new();
    for line in headers.get_all("x-forwarded-for") {
        for hop in line.to_str().ok()?.split(',') {
            hops.push(parse_hop(hop)?);
        }
    }
    hops.iter()
        .rev()
        .find(|hop| !is_trusted(**hop, trusted))
        .or_else(|| hops.first())
        .copied()
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
    fn a_malformed_hop_falls_back_to_the_peer() {
        for value in [
            "unknown, 203.0.113.7",
            "203.0.113.7,,10.0.0.1",
            "",
            "_hidden",
            "[::1",
            "1.2.3.4:x",
        ] {
            assert_eq!(resolve(&[value], Some("10.0.0.2")), peer("10.0.0.2"), "{value:?}");
        }
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
}
