//! CIDR range parsing and IP containment checks.

use std::net::IpAddr;

// -----------------------------------------------------------------------------
// CIDR Range
// -----------------------------------------------------------------------------

/// A parsed CIDR range (e.g. "10.0.0.0/8").
pub struct CidrRange {
    /// Network base address.
    addr: IpAddr,

    /// Prefix length (e.g. 24 for a /24).
    prefix_len: u8,
}

impl CidrRange {
    /// Parse a CIDR string like `"10.0.0.0/8"` or `"fd00::/16"`.
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
    pub fn contains(&self, ip: &IpAddr) -> bool {
        match (&self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(candidate)) => {
                let mask = v4_mask(self.prefix_len);
                u32::from(*net) & mask == u32::from(*candidate) & mask
            },
            (IpAddr::V6(net), IpAddr::V6(candidate)) => {
                let mask = v6_mask(self.prefix_len);
                let net_bits = u128::from(*net);
                let cand_bits = u128::from(*candidate);
                net_bits & mask == cand_bits & mask
            },
            _ => false,
        }
    }
}

// -----------------------------------------------------------------------------
// Mask Helpers
// -----------------------------------------------------------------------------

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
mod tests {
    use super::*;

    #[test]
    fn parse_v4() {
        let r = CidrRange::parse("10.0.0.0/8").unwrap();
        assert_eq!(r.prefix_len, 8);
    }

    #[test]
    fn parse_v6() {
        let r = CidrRange::parse("fd00::/8").unwrap();
        assert_eq!(r.prefix_len, 8);
    }

    #[test]
    fn parse_invalid_missing_slash() {
        assert!(CidrRange::parse("10.0.0.0").is_err());
    }

    #[test]
    fn parse_invalid_prefix_too_large() {
        assert!(CidrRange::parse("10.0.0.0/33").is_err());
    }

    #[test]
    fn contains_v4_match() {
        let r = CidrRange::parse("10.0.0.0/8").unwrap();
        assert!(r.contains(&"10.1.2.3".parse().unwrap()));
    }

    #[test]
    fn contains_v4_no_match() {
        let r = CidrRange::parse("10.0.0.0/8").unwrap();
        assert!(!r.contains(&"192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn contains_v4_exact() {
        let r = CidrRange::parse("192.168.1.100/32").unwrap();
        assert!(r.contains(&"192.168.1.100".parse().unwrap()));
    }

    #[test]
    fn v4_zero_prefix_matches_all() {
        let r = CidrRange::parse("0.0.0.0/0").unwrap();
        assert!(r.contains(&"8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn v4_v6_mismatch() {
        let r = CidrRange::parse("10.0.0.0/8").unwrap();
        assert!(!r.contains(&"fd00::1".parse().unwrap()));
    }

    #[test]
    fn contains_v6_match() {
        let r = CidrRange::parse("fd00::/16").unwrap();
        assert!(r.contains(&"fd00::1".parse().unwrap()));
    }

    #[test]
    fn contains_v6_no_match() {
        let r = CidrRange::parse("fd00::/16").unwrap();
        assert!(!r.contains(&"fe80::1".parse().unwrap()));
    }
}
