// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Network utilities: CIDR range matching and IP address normalization.

use std::net::IpAddr;

// -----------------------------------------------------------------------------
// IP Normalization
// -----------------------------------------------------------------------------

/// Convert IPv4-mapped IPv6 addresses (`::ffff:A.B.C.D`) to plain IPv4.
///
/// Native IPv4 and non-mapped IPv6 addresses pass through unchanged.
///
/// ```
/// use std::net::IpAddr;
///
/// use praxis_core::connectivity::normalize_mapped_ipv4;
///
/// let mapped: IpAddr = "::ffff:10.0.0.1".parse().unwrap();
/// assert_eq!(
///     normalize_mapped_ipv4(mapped),
///     IpAddr::V4("10.0.0.1".parse().unwrap()),
/// );
///
/// let native_v4: IpAddr = "10.0.0.1".parse().unwrap();
/// assert_eq!(normalize_mapped_ipv4(native_v4), native_v4);
///
/// let native_v6: IpAddr = "2001:db8::1".parse().unwrap();
/// assert_eq!(normalize_mapped_ipv4(native_v6), native_v6);
/// ```
pub fn normalize_mapped_ipv4(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        v4 @ IpAddr::V4(_) => v4,
    }
}

// -----------------------------------------------------------------------------
// CIDR Range
// -----------------------------------------------------------------------------

/// A parsed CIDR range (e.g. "10.0.0.0/8").
///
/// ```
/// use praxis_core::connectivity::CidrRange;
///
/// let range = CidrRange::parse("10.0.0.0/8").unwrap();
/// assert!(range.contains(&"10.1.2.3".parse().unwrap()));
/// assert!(!range.contains(&"192.168.1.1".parse().unwrap()));
/// ```
#[derive(Clone, Debug)]
pub struct CidrRange {
    /// Network base address.
    addr: IpAddr,

    /// Prefix length (e.g. 24 for a /24).
    prefix_len: u8,
}

impl CidrRange {
    /// Parse a CIDR string like `"10.0.0.0/8"` or `"fd00::/16"`.
    ///
    /// # Errors
    ///
    /// Returns an error string if the input is not a valid CIDR notation.
    ///
    /// ```
    /// use praxis_core::connectivity::CidrRange;
    ///
    /// let range = CidrRange::parse("192.168.0.0/16").unwrap();
    /// assert!(CidrRange::parse("10.0.0.0/33").is_err());
    /// ```
    pub fn parse(s: &str) -> Result<Self, String> {
        let (addr_str, len_str) = s
            .split_once('/')
            .ok_or_else(|| format!("invalid CIDR: {s} (missing /)"))?;

        let addr: IpAddr = addr_str.parse().map_err(|e| format!("invalid IP in CIDR {s}: {e}"))?;

        let prefix_len: u8 = len_str
            .parse()
            .map_err(|e| format!("invalid prefix length in {s}: {e}"))?;

        let max = match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix_len > max {
            return Err(format!("prefix length {prefix_len} exceeds maximum {max} for {s}"));
        }

        Ok(Self { addr, prefix_len })
    }

    /// Returns `true` if `ip` falls within this CIDR range.
    ///
    /// IPv4-mapped IPv6 addresses (e.g. `::ffff:10.0.0.1`) are
    /// transparently matched against IPv4 CIDR ranges, and vice versa.
    ///
    /// ```
    /// use praxis_core::connectivity::CidrRange;
    ///
    /// let range = CidrRange::parse("10.0.0.0/8").unwrap();
    /// assert!(range.contains(&"10.255.0.1".parse().unwrap()));
    /// assert!(!range.contains(&"11.0.0.1".parse().unwrap()));
    ///
    /// // IPv4-mapped IPv6 matches IPv4 CIDR
    /// assert!(range.contains(&"::ffff:10.1.2.3".parse().unwrap()));
    /// assert!(!range.contains(&"::ffff:192.168.1.1".parse().unwrap()));
    /// ```
    pub fn contains(&self, ip: &IpAddr) -> bool {
        match (&self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(candidate)) => v4_contains(*net, *candidate, self.prefix_len),
            (IpAddr::V6(net), IpAddr::V6(candidate)) => v6_contains(*net, *candidate, self.prefix_len),
            (IpAddr::V4(net), IpAddr::V6(candidate)) => v4_contains_mapped_v6(*net, *candidate, self.prefix_len),
            (IpAddr::V6(net), IpAddr::V4(candidate)) => v6_contains_v4(*net, *candidate, self.prefix_len),
        }
    }
}

// -----------------------------------------------------------------------------
// Utilities
// -----------------------------------------------------------------------------

/// Check whether two IPv4 addresses share the same prefix.
fn v4_contains(net: std::net::Ipv4Addr, candidate: std::net::Ipv4Addr, prefix_len: u8) -> bool {
    let mask = v4_mask(prefix_len);
    u32::from(net) & mask == u32::from(candidate) & mask
}

/// Check whether two IPv6 addresses share the same prefix.
fn v6_contains(net: std::net::Ipv6Addr, candidate: std::net::Ipv6Addr, prefix_len: u8) -> bool {
    let mask = v6_mask(prefix_len);
    u128::from(net) & mask == u128::from(candidate) & mask
}

/// Check if an IPv4-mapped IPv6 address falls within an IPv4 CIDR.
fn v4_contains_mapped_v6(net: std::net::Ipv4Addr, candidate: std::net::Ipv6Addr, prefix_len: u8) -> bool {
    candidate
        .to_ipv4_mapped()
        .is_some_and(|mapped| v4_contains(net, mapped, prefix_len))
}

/// Check if a plain IPv4 address falls within an IPv4-mapped IPv6 CIDR.
fn v6_contains_v4(net: std::net::Ipv6Addr, candidate: std::net::Ipv4Addr, prefix_len: u8) -> bool {
    net.to_ipv4_mapped()
        .filter(|_| prefix_len >= 96)
        .is_some_and(|mapped| v4_contains(mapped, candidate, prefix_len - 96))
}

/// Compute a 32-bit mask for the given IPv4 prefix length.
fn v4_mask(prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len)
    }
}

/// Compute a 128-bit mask for the given IPv6 prefix length.
fn v6_mask(prefix_len: u8) -> u128 {
    if prefix_len == 0 {
        0
    } else {
        u128::MAX << (128 - prefix_len)
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::needless_raw_strings,
    clippy::needless_raw_string_hashes,
    reason = "tests use unwrap/expect/indexing/raw strings for brevity"
)]
mod tests {
    use super::*;

    #[test]
    fn parse_v4() {
        let r = CidrRange::parse("10.0.0.0/8").unwrap();
        assert_eq!(r.prefix_len, 8, "IPv4 /8 prefix should parse as 8");
    }

    #[test]
    fn parse_v6() {
        let r = CidrRange::parse("fd00::/8").unwrap();
        assert_eq!(r.prefix_len, 8, "IPv6 /8 prefix should parse as 8");
    }

    #[test]
    fn parse_invalid_missing_slash() {
        assert!(CidrRange::parse("10.0.0.0").is_err(), "CIDR without slash should fail");
    }

    #[test]
    fn parse_invalid_prefix_too_large() {
        assert!(CidrRange::parse("10.0.0.0/33").is_err(), "/33 exceeds IPv4 max of 32");
    }

    #[test]
    fn contains_v4_match() {
        let r = CidrRange::parse("10.0.0.0/8").unwrap();
        assert!(
            r.contains(&"10.1.2.3".parse().unwrap()),
            "10.1.2.3 is within 10.0.0.0/8"
        );
    }

    #[test]
    fn contains_v4_no_match() {
        let r = CidrRange::parse("10.0.0.0/8").unwrap();
        assert!(
            !r.contains(&"192.168.1.1".parse().unwrap()),
            "192.168.1.1 is outside 10.0.0.0/8"
        );
    }

    #[test]
    fn contains_v4_exact() {
        let r = CidrRange::parse("192.168.1.100/32").unwrap();
        assert!(
            r.contains(&"192.168.1.100".parse().unwrap()),
            "/32 should match exact IP"
        );
    }

    #[test]
    fn v4_zero_prefix_matches_all() {
        let r = CidrRange::parse("0.0.0.0/0").unwrap();
        assert!(r.contains(&"8.8.8.8".parse().unwrap()), "/0 should match any IPv4");
    }

    #[test]
    fn v4_v6_mismatch() {
        let r = CidrRange::parse("10.0.0.0/8").unwrap();
        assert!(
            !r.contains(&"fd00::1".parse().unwrap()),
            "IPv4 range should not match non-mapped IPv6"
        );
    }

    #[test]
    fn ipv4_mapped_ipv6_matches_v4_range() {
        let r = CidrRange::parse("10.0.0.0/8").unwrap();
        assert!(
            r.contains(&"::ffff:10.1.2.3".parse().unwrap()),
            "::ffff:10.1.2.3 should match 10.0.0.0/8"
        );
    }

    #[test]
    fn ipv4_mapped_ipv6_outside_v4_range() {
        let r = CidrRange::parse("10.0.0.0/8").unwrap();
        assert!(
            !r.contains(&"::ffff:192.168.1.1".parse().unwrap()),
            "::ffff:192.168.1.1 should not match 10.0.0.0/8"
        );
    }

    #[test]
    fn ipv4_mapped_ipv6_exact_match() {
        let r = CidrRange::parse("192.168.1.100/32").unwrap();
        assert!(
            r.contains(&"::ffff:192.168.1.100".parse().unwrap()),
            "::ffff:192.168.1.100 should match 192.168.1.100/32"
        );
    }

    #[test]
    fn ipv4_mapped_ipv6_zero_prefix() {
        let r = CidrRange::parse("0.0.0.0/0").unwrap();
        assert!(
            r.contains(&"::ffff:8.8.8.8".parse().unwrap()),
            "::ffff:8.8.8.8 should match 0.0.0.0/0"
        );
    }

    #[test]
    fn plain_v4_matches_mapped_v6_range() {
        let r = CidrRange::parse("::ffff:10.0.0.0/104").unwrap();
        assert!(
            r.contains(&"10.1.2.3".parse().unwrap()),
            "10.1.2.3 should match ::ffff:10.0.0.0/104 (equivalent to 10.0.0.0/8)"
        );
    }

    #[test]
    fn plain_v4_outside_mapped_v6_range() {
        let r = CidrRange::parse("::ffff:10.0.0.0/104").unwrap();
        assert!(
            !r.contains(&"192.168.1.1".parse().unwrap()),
            "192.168.1.1 should not match ::ffff:10.0.0.0/104"
        );
    }

    #[test]
    fn v6_range_below_96_does_not_match_v4() {
        let r = CidrRange::parse("::ffff:0.0.0.0/64").unwrap();
        assert!(
            !r.contains(&"10.0.0.1".parse().unwrap()),
            "IPv6 /64 range should not match plain IPv4 (prefix < 96)"
        );
    }

    #[test]
    fn v6_range_at_96_matches_all_v4() {
        let r = CidrRange::parse("::ffff:0.0.0.0/96").unwrap();
        assert!(
            r.contains(&"10.0.0.1".parse().unwrap()),
            "/96 mapped range covers all IPv4 addresses"
        );
        assert!(
            r.contains(&"192.168.1.1".parse().unwrap()),
            "/96 mapped range covers all IPv4 addresses"
        );
    }

    #[test]
    fn contains_v6_match() {
        let r = CidrRange::parse("fd00::/16").unwrap();
        assert!(r.contains(&"fd00::1".parse().unwrap()), "fd00::1 is within fd00::/16");
    }

    #[test]
    fn contains_v6_no_match() {
        let r = CidrRange::parse("fd00::/16").unwrap();
        assert!(!r.contains(&"fe80::1".parse().unwrap()), "fe80::1 is outside fd00::/16");
    }
}
