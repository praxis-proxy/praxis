// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Canonical IP address classification.
//!
//! [`classify_ip`] returns a neutral [`IpClassification`] describing which
//! IANA special-purpose categories an address belongs to. Consumers compose
//! the boolean properties they need instead of maintaining their own range
//! tables, which keeps SSRF and outbound-policy decisions consistent across
//! the codebase.
//!
//! The classification is deliberately *neutral*: it reports facts about an
//! address (loopback, private, link-local, cloud-metadata, …) and never an
//! allow/deny verdict. Policy — whether a private target is acceptable in a
//! given context — belongs to the caller.
//!
//! # Address tables
//!
//! The special-use ranges below are transcribed from the IANA
//! special-purpose address registries. An address block is treated as
//! non-public when its "Globally Reachable" value is `False`, `N/A`, blank,
//! or deprecated; only blocks explicitly marked `True` are treated as
//! globally reachable (and are therefore *absent* from the tables, except
//! where a globally-reachable island sits inside an otherwise-special block —
//! e.g. `192.0.0.9/32` — in which case it is listed as an exception).
//!
//! - IANA IPv4 Special-Purpose Address Registry: <https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml>
//! - IANA IPv6 Special-Purpose Address Registry: <https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml>
//!
//! Snapshot: both registries "Last Updated 2025-10-09"; transcribed
//! 2026-09-28. Two non-public ranges live outside the special-purpose
//! registries and are detected directly rather than from a table: multicast
//! (`224.0.0.0/4`, `ff00::/8`), via the standard library, and deprecated IPv6
//! site-local (`fec0::/10`, RFC 3879), via a prefix match — it was removed
//! from the registry but may still be routed on legacy networks.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::network::normalize_mapped_ipv4;

// -----------------------------------------------------------------------------
// Category flags
// -----------------------------------------------------------------------------
//
// Private bit layout. The public API exposes named predicates, never the raw
// `u16`, so categories and address tables can evolve without a breaking change.

/// `127.0.0.0/8` or `::1`.
const LOOPBACK: u16 = 0x0001;
/// RFC 1918 private-use or IPv6 unique-local (`fc00::/7`).
const PRIVATE_NETWORK: u16 = 0x0002;
/// `169.254.0.0/16` or `fe80::/10`.
const LINK_LOCAL: u16 = 0x0004;
/// CGNAT / shared address space (`100.64.0.0/10`).
const SHARED_ADDRESS_SPACE: u16 = 0x0008;
/// The IPv4 `0.0.0.0/8` "this host on this network" block.
const THIS_HOST: u16 = 0x0010;
/// The unspecified address (`0.0.0.0` or `::`).
const UNSPECIFIED: u16 = 0x0020;
/// `224.0.0.0/4` or `ff00::/8`.
const MULTICAST: u16 = 0x0040;
/// A non-global IANA special-purpose block not covered by another category.
const SPECIAL_USE: u16 = 0x0080;
/// A known cloud instance-metadata / credential endpoint.
const CLOUD_METADATA: u16 = 0x0100;
/// The union of every category above: not a globally reachable destination.
const NON_PUBLIC: u16 = 0x0200;

// -----------------------------------------------------------------------------
// IANA special-use tables
// -----------------------------------------------------------------------------

/// IPv4 special-purpose blocks that are not globally reachable and not covered
/// by loopback / private / link-local / shared / this-host / multicast.
const V4_SPECIAL_USE: &[V4Block] = &[
    V4Block::new(Ipv4Addr::new(192, 0, 0, 0), 24), // IETF Protocol Assignments (RFC 6890)
    V4Block::new(Ipv4Addr::new(192, 0, 2, 0), 24), // Documentation TEST-NET-1 (RFC 5737)
    V4Block::new(Ipv4Addr::new(198, 51, 100, 0), 24), // Documentation TEST-NET-2 (RFC 5737)
    V4Block::new(Ipv4Addr::new(203, 0, 113, 0), 24), // Documentation TEST-NET-3 (RFC 5737)
    V4Block::new(Ipv4Addr::new(192, 88, 99, 0), 24), // 6to4 Relay Anycast, deprecated (RFC 7526)
    V4Block::new(Ipv4Addr::new(198, 18, 0, 0), 15), // Benchmarking (RFC 2544)
    V4Block::new(Ipv4Addr::new(240, 0, 0, 0), 4),  // Reserved, incl. 255.255.255.255 (RFC 1112 / 8190)
];

/// Globally reachable `/32` islands inside `192.0.0.0/24` that must *not* be
/// treated as special-use (RFC 7723, RFC 8155).
const V4_GLOBALLY_REACHABLE_EXCEPTIONS: &[Ipv4Addr] = &[
    Ipv4Addr::new(192, 0, 0, 9),  // Port Control Protocol Anycast
    Ipv4Addr::new(192, 0, 0, 10), // Traversal Using Relays around NAT Anycast
];

/// IPv6 special-purpose blocks that are not globally reachable and not covered
/// by loopback / unspecified / unique-local / link-local / multicast. The
/// NAT64 well-known prefix `64:ff9b::/96` is handled by recursion, not here.
const V6_SPECIAL_USE: &[V6Block] = &[
    V6Block::new(Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 0), 23), /* IETF Protocol Assignments: TEREDO,
                                                                   * benchmarking, deprecated ORCHID, unallocated
                                                                   * (RFC 2928) */
    V6Block::new(Ipv6Addr::new(0x2001, 0x0DB8, 0, 0, 0, 0, 0, 0), 32), // Documentation (RFC 3849)
    V6Block::new(Ipv6Addr::new(0x2002, 0, 0, 0, 0, 0, 0, 0), 16),      // 6to4 (RFC 3056)
    V6Block::new(Ipv6Addr::new(0x3FFF, 0, 0, 0, 0, 0, 0, 0), 20),      // Documentation (RFC 9637)
    V6Block::new(Ipv6Addr::new(0x5F00, 0, 0, 0, 0, 0, 0, 0), 16),      // SRv6 SIDs (RFC 9602)
    V6Block::new(Ipv6Addr::new(0x0064, 0xFF9B, 0x0001, 0, 0, 0, 0, 0), 48), // Local-use NAT64 (RFC 8215)
    V6Block::new(Ipv6Addr::new(0x0100, 0, 0, 0, 0, 0, 0, 0), 64),      // Discard-Only (RFC 6666)
    V6Block::new(Ipv6Addr::new(0x0100, 0, 0, 1, 0, 0, 0, 0), 64),      // Dummy prefix (RFC 9780)
];

/// Globally reachable sub-blocks inside `2001::/23` that must *not* be treated
/// as special-use (RFC 7723 / 8155 / 9665 / 7450 / 7535 / 7343 / 9374).
const V6_GLOBALLY_REACHABLE_EXCEPTIONS: &[V6Block] = &[
    V6Block::new(Ipv6Addr::new(0x2001, 1, 0, 0, 0, 0, 0, 1), 128), // Port Control Protocol Anycast
    V6Block::new(Ipv6Addr::new(0x2001, 1, 0, 0, 0, 0, 0, 2), 128), // TURN Anycast
    V6Block::new(Ipv6Addr::new(0x2001, 1, 0, 0, 0, 0, 0, 3), 128), // DNS-SD SRP Anycast
    V6Block::new(Ipv6Addr::new(0x2001, 3, 0, 0, 0, 0, 0, 0), 32),  // AMT
    V6Block::new(Ipv6Addr::new(0x2001, 4, 0x0112, 0, 0, 0, 0, 0), 48), // AS112-v6
    V6Block::new(Ipv6Addr::new(0x2001, 0x0020, 0, 0, 0, 0, 0, 0), 28), // ORCHIDv2
    V6Block::new(Ipv6Addr::new(0x2001, 0x0030, 0, 0, 0, 0, 0, 0), 28), // Drone Remote ID
];

// -----------------------------------------------------------------------------
// Cloud metadata endpoints
// -----------------------------------------------------------------------------

/// Known IPv4 cloud instance-metadata / credential endpoints. Each already
/// falls inside a broader non-public range (link-local or shared address
/// space); the flag is an additional tag for policy that targets metadata
/// specifically.
const V4_CLOUD_METADATA: &[Ipv4Addr] = &[
    Ipv4Addr::new(169, 254, 169, 254), /* Multi-cloud IMDS: AWS, GCP, Azure, Oracle, IBM, Huawei, DigitalOcean,
                                        * OpenStack */
    Ipv4Addr::new(169, 254, 170, 2), // AWS ECS task IAM role credentials (container credential provider)
    Ipv4Addr::new(169, 254, 170, 23), // AWS EKS Pod Identity Agent credentials (IPv4)
    Ipv4Addr::new(100, 100, 100, 200), // Alibaba Cloud (Aliyun ECS) metadata service
    Ipv4Addr::new(169, 254, 0, 23),  // Tencent Cloud CVM metadata (metadata.tencentyun.com; VPC / intl regions)
    Ipv4Addr::new(169, 254, 10, 10), // Tencent Cloud CVM metadata (basic-network / mainland regions)
];

/// Known IPv6 cloud instance-metadata / credential endpoints. Each already
/// falls inside a broader non-public range (ULA `fc00::/7` or link-local
/// `fe80::/10`); the flag is an additional tag for policy that targets metadata
/// specifically.
const V6_CLOUD_METADATA: &[Ipv6Addr] = &[
    Ipv6Addr::new(0xFD00, 0x0EC2, 0, 0, 0, 0, 0, 0x0254), // AWS EC2 IMDS IPv6 (fd00:ec2::254)
    Ipv6Addr::new(0xFD00, 0x0EC2, 0, 0, 0, 0, 0, 0x0023), // AWS EKS Pod Identity Agent IPv6 (fd00:ec2::23)
    Ipv6Addr::new(0xFD20, 0x00CE, 0, 0, 0, 0, 0, 0x0254), // GCP metadata IPv6 (fd20:ce::254)
    Ipv6Addr::new(0xFE80, 0, 0, 0, 0, 0, 0xA9FE, 0xA9FE), // OpenStack Nova metadata IPv6 link-local (fe80::a9fe:a9fe)
];

// -----------------------------------------------------------------------------
// IpClassification
// -----------------------------------------------------------------------------

/// A canonical, family-normalized classification of an IP address.
///
/// Construct with [`classify_ip`]. The stored address is normalized:
/// IPv4-mapped IPv6 (`::ffff:A.B.C.D`) becomes plain IPv4, and an address in
/// the NAT64 well-known prefix (`64:ff9b::/96`) is reduced to the IPv4 address
/// it embeds, so callers reason about a single canonical form.
///
/// ```
/// use praxis_core::connectivity::classify_ip;
///
/// let c = classify_ip(&"169.254.169.254".parse().unwrap());
/// assert!(c.is_link_local());
/// assert!(c.is_cloud_metadata());
/// assert!(c.is_non_public());
/// assert!(!c.is_loopback());
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IpClassification {
    /// Packed category bits; never exposed directly.
    flags: u16,
    /// The family-normalized address (see [`classify_ip`]).
    normalized: IpAddr,
}

impl IpClassification {
    /// The normalized address the classification was computed from.
    ///
    /// ```
    /// use std::net::IpAddr;
    ///
    /// use praxis_core::connectivity::classify_ip;
    ///
    /// // IPv4-mapped IPv6 collapses to plain IPv4.
    /// let c = classify_ip(&"::ffff:127.0.0.1".parse().unwrap());
    /// assert_eq!(c.normalized(), IpAddr::V4("127.0.0.1".parse().unwrap()));
    ///
    /// // A NAT64-wrapped address reduces to the IPv4 it embeds.
    /// let c = classify_ip(&"64:ff9b::10.0.0.1".parse().unwrap());
    /// assert_eq!(c.normalized(), IpAddr::V4("10.0.0.1".parse().unwrap()));
    /// ```
    #[must_use]
    pub const fn normalized(self) -> IpAddr {
        self.normalized
    }

    /// A known cloud instance-metadata or credential endpoint (AWS, GCP,
    /// Azure, Alibaba, Oracle, …). Always also non-public.
    #[must_use]
    pub const fn is_cloud_metadata(self) -> bool {
        (self.flags & CLOUD_METADATA) != 0
    }

    /// Link-local: `169.254.0.0/16` or `fe80::/10`.
    #[must_use]
    pub const fn is_link_local(self) -> bool {
        (self.flags & LINK_LOCAL) != 0
    }

    /// Loopback: `127.0.0.0/8` or `::1`.
    #[must_use]
    pub const fn is_loopback(self) -> bool {
        (self.flags & LOOPBACK) != 0
    }

    /// Multicast: `224.0.0.0/4` or `ff00::/8`.
    #[must_use]
    pub const fn is_multicast(self) -> bool {
        (self.flags & MULTICAST) != 0
    }

    /// The address is not a globally reachable public unicast destination —
    /// the union of every category above. This is the broadest guard; it is
    /// intentionally wider than [`is_private_ip`] and callers must not treat
    /// the two as interchangeable.
    ///
    /// [`is_private_ip`]: super::is_private_ip
    #[must_use]
    pub const fn is_non_public(self) -> bool {
        (self.flags & NON_PUBLIC) != 0
    }

    /// RFC 1918 private-use (`10/8`, `172.16/12`, `192.168/16`) or IPv6
    /// unique-local (`fc00::/7`).
    #[must_use]
    pub const fn is_private_network(self) -> bool {
        (self.flags & PRIVATE_NETWORK) != 0
    }

    /// CGNAT / shared address space (`100.64.0.0/10`, RFC 6598).
    #[must_use]
    pub const fn is_shared_address_space(self) -> bool {
        (self.flags & SHARED_ADDRESS_SPACE) != 0
    }

    /// An IANA special-purpose block that is not globally reachable and is not
    /// already described by a more specific category (documentation /
    /// benchmarking / protocol-assignment / reserved / transition ranges).
    #[must_use]
    pub const fn is_special_use(self) -> bool {
        (self.flags & SPECIAL_USE) != 0
    }

    /// "This host on this network": the IPv4 `0.0.0.0/8` block. A `connect()`
    /// to any `0.x.x.x` address is routed to loopback.
    #[must_use]
    pub const fn is_this_host(self) -> bool {
        (self.flags & THIS_HOST) != 0
    }

    /// The unspecified address (`0.0.0.0` or `::`).
    #[must_use]
    pub const fn is_unspecified(self) -> bool {
        (self.flags & UNSPECIFIED) != 0
    }
}

// -----------------------------------------------------------------------------
// classify_ip
// -----------------------------------------------------------------------------

/// Classify an IP address into its IANA special-purpose categories.
///
/// The address is normalized first (IPv4-mapped IPv6 to plain IPv4), and an
/// address in the NAT64 well-known prefix `64:ff9b::/96` is classified by
/// recursing on the IPv4 address it embeds — so a NAT64-wrapped private or
/// metadata target is recognized as such.
///
/// ```
/// use praxis_core::connectivity::classify_ip;
///
/// assert!(classify_ip(&"10.0.0.1".parse().unwrap()).is_private_network());
/// assert!(classify_ip(&"192.0.2.1".parse().unwrap()).is_special_use());
/// assert!(!classify_ip(&"8.8.8.8".parse().unwrap()).is_non_public());
///
/// // Globally reachable islands inside a special block stay public.
/// assert!(!classify_ip(&"192.0.0.9".parse().unwrap()).is_non_public());
/// ```
#[must_use]
pub fn classify_ip(ip: &IpAddr) -> IpClassification {
    let normalized = normalize_mapped_ipv4(*ip);

    // A NAT64 well-known-prefix address embeds an IPv4 target; classify that
    // instead so the wrapper cannot hide a private or metadata destination.
    if let IpAddr::V6(v6) = normalized
        && let Some(embedded) = nat64_embedded_ipv4(v6)
    {
        return classify_ip(&IpAddr::V4(embedded));
    }

    classify_normalized(normalized)
}

/// Classify an address without unwrapping NAT64 (`64:ff9b::/96`) embeddings.
///
/// [`classify_ip`] recurses into a NAT64-wrapped IPv4 target so the canonical
/// classification reflects the address a translator actually reaches. The
/// legacy [`is_private_ip`] and health-check SSRF helpers predate that behavior
/// and must preserve their historical result set (issue #1279): they only ever
/// normalized IPv4-mapped IPv6, treating a `64:ff9b::` wrapper as an ordinary,
/// globally reachable IPv6 address. This entry point gives them that view while
/// still sharing the range tables.
///
/// [`is_private_ip`]: super::is_private_ip
#[must_use]
pub(crate) fn classify_without_nat64(ip: &IpAddr) -> IpClassification {
    classify_normalized(normalize_mapped_ipv4(*ip))
}

/// Classify an already family-normalized address (no further unwrapping).
fn classify_normalized(normalized: IpAddr) -> IpClassification {
    let flags = match normalized {
        IpAddr::V4(v4) => classify_v4(v4),
        IpAddr::V6(v6) => classify_v6(v6),
    };

    IpClassification { flags, normalized }
}

/// Compute the category flags for a plain IPv4 address.
fn classify_v4(v4: Ipv4Addr) -> u16 {
    let mut flags = 0;
    if v4.is_loopback() {
        flags |= LOOPBACK;
    }
    if v4.is_private() {
        flags |= PRIVATE_NETWORK;
    }
    if v4.is_link_local() {
        flags |= LINK_LOCAL;
    }
    if is_shared_v4(v4) {
        flags |= SHARED_ADDRESS_SPACE;
    }
    if v4.octets()[0] == 0 {
        flags |= THIS_HOST;
    }
    if v4.is_unspecified() {
        flags |= UNSPECIFIED;
    }
    if v4.is_multicast() {
        flags |= MULTICAST;
    }
    if is_special_use_v4(v4) {
        flags |= SPECIAL_USE;
    }
    if V4_CLOUD_METADATA.contains(&v4) {
        flags |= CLOUD_METADATA;
    }
    with_non_public(flags)
}

/// Compute the category flags for a non-mapped IPv6 address.
fn classify_v6(v6: Ipv6Addr) -> u16 {
    let mut flags = 0;
    if v6.is_loopback() {
        flags |= LOOPBACK;
    }
    if v6.is_unspecified() {
        flags |= UNSPECIFIED;
    }
    if is_unique_local_v6(v6) {
        flags |= PRIVATE_NETWORK;
    }
    if is_link_local_v6(v6) {
        flags |= LINK_LOCAL;
    }
    if v6.is_multicast() {
        flags |= MULTICAST;
    }
    if is_special_use_v6(v6) {
        flags |= SPECIAL_USE;
    }
    if V6_CLOUD_METADATA.contains(&v6) {
        flags |= CLOUD_METADATA;
    }
    with_non_public(flags)
}

/// Set [`NON_PUBLIC`] whenever any category flag is present. Every category in
/// this module describes a non-globally-reachable address, so their union is
/// exactly the non-public set.
const fn with_non_public(flags: u16) -> u16 {
    if flags == 0 { flags } else { flags | NON_PUBLIC }
}

// -----------------------------------------------------------------------------
// Range helpers
// -----------------------------------------------------------------------------

/// `true` for the CGNAT / shared address space `100.64.0.0/10` (RFC 6598).
const fn is_shared_v4(v4: Ipv4Addr) -> bool {
    (v4.to_bits() & 0xFFC0_0000) == 0x6440_0000
}

/// `true` for IPv6 unique-local addresses `fc00::/7` (RFC 4193).
const fn is_unique_local_v6(v6: Ipv6Addr) -> bool {
    (v6.segments()[0] & 0xFE00) == 0xFC00
}

/// `true` for IPv6 link-local addresses `fe80::/10` (RFC 4291).
const fn is_link_local_v6(v6: Ipv6Addr) -> bool {
    (v6.segments()[0] & 0xFFC0) == 0xFE80
}

/// `true` for deprecated IPv6 site-local addresses `fec0::/10` (RFC 3879).
const fn is_site_local_v6(v6: Ipv6Addr) -> bool {
    (v6.segments()[0] & 0xFFC0) == 0xFEC0
}

/// Extract the IPv4 address embedded in a NAT64 well-known-prefix address.
///
/// Returns `Some` only for `64:ff9b::/96` (RFC 6052 / RFC 8880); the embedded
/// IPv4 occupies the low 32 bits. The local-use NAT64 prefix
/// (`64:ff9b:1::/48`, RFC 8215) is intentionally excluded — it is classified
/// as special-use instead.
fn nat64_embedded_ipv4(v6: Ipv6Addr) -> Option<Ipv4Addr> {
    let seg = v6.segments();
    let in_well_known_prefix =
        seg[0] == 0x0064 && seg[1] == 0xFF9B && seg[2] == 0 && seg[3] == 0 && seg[4] == 0 && seg[5] == 0;
    in_well_known_prefix.then(|| Ipv4Addr::from((u32::from(seg[6]) << 16) | u32::from(seg[7])))
}

/// `true` for IANA IPv4 special-purpose blocks that are not globally reachable
/// and are not covered by a more specific category flag.
fn is_special_use_v4(v4: Ipv4Addr) -> bool {
    if V4_GLOBALLY_REACHABLE_EXCEPTIONS.contains(&v4) {
        return false;
    }
    V4_SPECIAL_USE.iter().any(|block| block.contains(v4))
}

/// `true` for IANA IPv6 special-purpose blocks that are not globally reachable
/// and are not covered by a more specific category flag.
fn is_special_use_v6(v6: Ipv6Addr) -> bool {
    if V6_GLOBALLY_REACHABLE_EXCEPTIONS.iter().any(|block| block.contains(v6)) {
        return false;
    }
    // Deprecated site-local (fec0::/10) was dropped from the IANA registry but
    // may still be routed locally, so it is treated as non-public special-use.
    is_site_local_v6(v6) || V6_SPECIAL_USE.iter().any(|block| block.contains(v6))
}

// -----------------------------------------------------------------------------
// CIDR block matchers
// -----------------------------------------------------------------------------

/// An IPv4 CIDR block used by the special-use tables.
struct V4Block {
    /// Network base address.
    net: Ipv4Addr,
    /// Prefix length in bits.
    prefix: u8,
}

impl V4Block {
    /// Construct a block from a network base address and prefix length.
    const fn new(net: Ipv4Addr, prefix: u8) -> Self {
        Self { net, prefix }
    }

    /// `true` if `addr` falls within this block.
    const fn contains(&self, addr: Ipv4Addr) -> bool {
        let mask = if self.prefix == 0 {
            0
        } else {
            u32::MAX << 32_u8.saturating_sub(self.prefix)
        };
        (addr.to_bits() & mask) == (self.net.to_bits() & mask)
    }
}

/// An IPv6 CIDR block used by the special-use tables.
struct V6Block {
    /// Network base address.
    net: Ipv6Addr,
    /// Prefix length in bits.
    prefix: u8,
}

impl V6Block {
    /// Construct a block from a network base address and prefix length.
    const fn new(net: Ipv6Addr, prefix: u8) -> Self {
        Self { net, prefix }
    }

    /// `true` if `addr` falls within this block.
    const fn contains(&self, addr: Ipv6Addr) -> bool {
        let mask = if self.prefix == 0 {
            0
        } else {
            u128::MAX << 128_u8.saturating_sub(self.prefix)
        };
        (addr.to_bits() & mask) == (self.net.to_bits() & mask)
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::min_ident_chars,
    reason = "tests use unwrap/indexing for brevity"
)]
mod tests {
    use super::*;

    #[test]
    fn loopback() {
        for addr in ["127.0.0.1", "127.0.0.0", "127.255.255.255", "::1"] {
            assert!(classify(addr).is_loopback(), "{addr} is loopback");
            assert!(classify(addr).is_non_public(), "{addr} is non-public");
        }
        assert!(!classify("128.0.0.0").is_loopback(), "128.0.0.0 is not loopback");
        assert!(!classify("126.255.255.255").is_loopback(), "126.* is not loopback");
    }

    #[test]
    fn private_network_v4_boundaries() {
        for addr in [
            "10.0.0.0",
            "10.255.255.255",
            "172.16.0.0",
            "172.31.255.255",
            "192.168.0.0",
            "192.168.255.255",
        ] {
            assert!(classify(addr).is_private_network(), "{addr} is RFC 1918");
        }
        for addr in [
            "9.255.255.255",
            "11.0.0.0",
            "172.15.255.255",
            "172.32.0.0",
            "192.167.255.255",
            "192.169.0.0",
        ] {
            assert!(!classify(addr).is_private_network(), "{addr} is not RFC 1918");
        }
    }

    #[test]
    fn private_network_v6_ula() {
        for addr in [
            "fc00::",
            "fc00::1",
            "fd00::1",
            "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
        ] {
            assert!(classify(addr).is_private_network(), "{addr} is ULA");
        }
        assert!(!classify("fbff::1").is_private_network(), "fbff:: is below fc00::/7");
        assert!(!classify("fe00::1").is_private_network(), "fe00:: is above fc00::/7");
    }

    #[test]
    fn link_local_boundaries() {
        assert!(classify("169.254.0.0").is_link_local(), "169.254.0.0 is link-local");
        assert!(
            classify("169.254.255.255").is_link_local(),
            "169.254.255.255 is link-local"
        );
        assert!(
            !classify("169.253.255.255").is_link_local(),
            "169.253.* is not link-local"
        );
        assert!(!classify("169.255.0.0").is_link_local(), "169.255.* is not link-local");
        assert!(classify("fe80::1").is_link_local(), "fe80::1 is link-local");
        assert!(
            classify("febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff").is_link_local(),
            "febf:* is link-local"
        );
        assert!(!classify("fec0::1").is_link_local(), "fec0:: is above fe80::/10");
    }

    #[test]
    fn shared_address_space_boundaries() {
        assert!(classify("100.64.0.0").is_shared_address_space(), "100.64.0.0 is CGNAT");
        assert!(
            classify("100.127.255.255").is_shared_address_space(),
            "100.127.* is CGNAT"
        );
        assert!(
            !classify("100.63.255.255").is_shared_address_space(),
            "100.63.* is below CGNAT"
        );
        assert!(
            !classify("100.128.0.0").is_shared_address_space(),
            "100.128.* is above CGNAT"
        );
    }

    #[test]
    fn this_host_and_unspecified() {
        assert_exact("0.0.0.0", THIS_HOST | UNSPECIFIED);
        assert!(classify("0.0.0.1").is_this_host(), "0.0.0.1 is this-host");
        assert!(!classify("0.0.0.1").is_unspecified(), "0.0.0.1 is not unspecified");
        assert!(classify("0.255.255.255").is_this_host(), "0.255.* is this-host");
        assert!(!classify("1.0.0.0").is_this_host(), "1.0.0.0 is not this-host");
        assert_exact("::", UNSPECIFIED);
        assert!(!classify("::").is_this_host(), ":: is unspecified, not this-host");
    }

    #[test]
    fn multicast() {
        assert!(classify("224.0.0.1").is_multicast(), "224.0.0.1 is multicast");
        assert!(classify("239.255.255.255").is_multicast(), "239.* is multicast");
        assert!(!classify("223.255.255.255").is_multicast(), "223.* is not multicast");
        assert!(classify("ff02::1").is_multicast(), "ff02::1 is multicast");
        assert!(classify("224.0.0.1").is_non_public(), "multicast is non-public");
        assert!(!classify("224.0.0.1").is_special_use(), "multicast is not special-use");
    }

    #[test]
    fn special_use_v4_documentation() {
        for block in ["192.0.2", "198.51.100", "203.0.113"] {
            assert!(
                classify(&format!("{block}.0")).is_special_use(),
                "{block}.0 is documentation"
            );
            assert!(
                classify(&format!("{block}.255")).is_special_use(),
                "{block}.255 is documentation"
            );
            assert!(
                classify(&format!("{block}.1")).is_non_public(),
                "{block}.1 is non-public"
            );
        }
        assert!(!classify("192.0.3.0").is_special_use(), "192.0.3.0 is public");
        assert!(!classify("198.51.101.0").is_special_use(), "198.51.101.0 is public");
    }

    #[test]
    fn special_use_v4_other_blocks() {
        assert!(classify("198.18.0.0").is_special_use(), "198.18.0.0 is benchmarking");
        assert!(
            classify("198.19.255.255").is_special_use(),
            "198.19.255.255 is benchmarking"
        );
        assert!(!classify("198.17.255.255").is_special_use(), "198.17.* is public");
        assert!(!classify("198.20.0.0").is_special_use(), "198.20.* is public");
        assert!(classify("240.0.0.0").is_special_use(), "240.0.0.0 is reserved");
        assert!(classify("255.255.255.255").is_special_use(), "broadcast is reserved");
        assert!(
            !classify("239.255.255.255").is_special_use(),
            "239.* is multicast, not reserved"
        );
        assert!(
            classify("192.88.99.1").is_special_use(),
            "192.88.99.1 is deprecated 6to4 anycast"
        );
        assert!(
            classify("192.0.0.0").is_special_use(),
            "192.0.0.0 is protocol assignments"
        );
        assert!(
            classify("192.0.0.255").is_special_use(),
            "192.0.0.255 is protocol assignments"
        );
        assert!(
            classify("192.0.0.170").is_special_use(),
            "192.0.0.170 is NAT64/DNS64 discovery"
        );
    }

    #[test]
    fn globally_reachable_islands_v4() {
        for addr in ["192.0.0.9", "192.0.0.10"] {
            let c = classify(addr);
            assert!(
                !c.is_special_use(),
                "{addr} is a globally reachable exception in 192.0.0.0/24"
            );
            assert!(!c.is_non_public(), "{addr} is globally reachable");
        }
        for addr in ["192.31.196.1", "192.52.193.1", "192.175.48.1"] {
            assert!(
                !classify(addr).is_non_public(),
                "{addr} is a standalone globally reachable delegation"
            );
        }
    }

    #[test]
    fn special_use_v4_table_boundaries() {
        // The first and last address of every V4_SPECIAL_USE block, generated
        // straight from the table, must be special-use (hence non-public). This
        // covers both edges of each entry — e.g. 192.88.99.0 and .255 — and any
        // future block automatically.
        for block in V4_SPECIAL_USE {
            let (first, last) = v4_block_bounds(block);
            for bits in [first, last] {
                let addr = Ipv4Addr::from(bits);
                let c = classify_v4(bits);
                assert!(c.is_special_use(), "{addr} is special-use (/{})", block.prefix);
                assert!(c.is_non_public(), "{addr} is non-public (/{})", block.prefix);
            }
        }
    }

    #[test]
    fn special_use_v6_table_boundaries() {
        // The same first/last edge coverage, generated from V6_SPECIAL_USE.
        for block in V6_SPECIAL_USE {
            let (first, last) = v6_block_bounds(block);
            for bits in [first, last] {
                let addr = Ipv6Addr::from(bits);
                let c = classify_v6(bits);
                assert!(c.is_special_use(), "{addr} is special-use (/{})", block.prefix);
                assert!(c.is_non_public(), "{addr} is non-public (/{})", block.prefix);
            }
        }
    }

    #[test]
    fn special_use_v4_table_adjacency() {
        // The address just below the first and just above the last of each
        // block must not be special-use, unless an adjacent block in the same
        // table owns it. Overflow at the ends of the address space is skipped.
        for (i, block) in V4_SPECIAL_USE.iter().enumerate() {
            let (first, last) = v4_block_bounds(block);
            for bits in [first.checked_sub(1), last.checked_add(1)].into_iter().flatten() {
                let addr = Ipv4Addr::from(bits);
                if V4_SPECIAL_USE
                    .iter()
                    .enumerate()
                    .any(|(j, b)| j != i && b.contains(addr))
                {
                    continue;
                }
                assert!(
                    !classify_v4(bits).is_special_use(),
                    "{addr} borders /{} but is public",
                    block.prefix
                );
            }
        }
    }

    #[test]
    fn special_use_v6_table_adjacency() {
        // As above, generated from V6_SPECIAL_USE. Neighbors owned by an
        // adjacent block (e.g. 100::/64 meets 100:0:0:1::/64) or by the
        // deprecated site-local range are skipped.
        for (i, block) in V6_SPECIAL_USE.iter().enumerate() {
            let (first, last) = v6_block_bounds(block);
            for bits in [first.checked_sub(1), last.checked_add(1)].into_iter().flatten() {
                let addr = Ipv6Addr::from(bits);
                let owned = V6_SPECIAL_USE
                    .iter()
                    .enumerate()
                    .any(|(j, b)| j != i && b.contains(addr));
                if owned || is_site_local_v6(addr) {
                    continue;
                }
                assert!(
                    !classify_v6(bits).is_special_use(),
                    "{addr} borders /{} but is public",
                    block.prefix
                );
            }
        }
    }

    #[test]
    fn globally_reachable_exceptions_are_public() {
        // Every carved-out exception, taken directly from the exception tables,
        // must be neither special-use nor non-public.
        for &addr in V4_GLOBALLY_REACHABLE_EXCEPTIONS {
            let c = classify_ip(&IpAddr::V4(addr));
            assert!(!c.is_special_use(), "{addr} is a globally reachable exception");
            assert!(!c.is_non_public(), "{addr} is globally reachable");
        }
        for block in V6_GLOBALLY_REACHABLE_EXCEPTIONS {
            let c = classify_ip(&IpAddr::V6(block.net));
            assert!(!c.is_special_use(), "{} is a globally reachable exception", block.net);
            assert!(!c.is_non_public(), "{} is globally reachable", block.net);
        }
    }

    #[test]
    fn site_local_v6_deprecated() {
        for addr in ["fec0::", "fec0::1", "feff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"] {
            assert!(classify(addr).is_special_use(), "{addr} is deprecated site-local");
            assert!(classify(addr).is_non_public(), "{addr} is non-public");
        }
        assert!(
            !classify("febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff").is_special_use(),
            "febf:* is link-local, just below fec0::/10"
        );
        assert!(
            !classify("ff00::").is_special_use(),
            "ff00:: is multicast, just above fec0::/10"
        );
    }

    #[test]
    fn globally_reachable_islands_v6() {
        for (addr, name) in [
            ("2001:1::1", "Port Control Protocol Anycast"),
            ("2001:1::2", "TURN Anycast"),
            ("2001:1::3", "DNS-SD SRP Anycast"),
            ("2001:3::1", "AMT"),
            ("2001:4:112::1", "AS112-v6"),
            ("2001:20::1", "ORCHIDv2"),
            ("2001:30::1", "Drone Remote ID"),
            ("2620:4f:8000::1", "Direct Delegation AS112"),
        ] {
            let c = classify(addr);
            assert!(!c.is_special_use(), "{addr} is a globally reachable exception ({name})");
            assert!(!c.is_non_public(), "{addr} is globally reachable ({name})");
        }
    }

    #[test]
    fn public_addresses() {
        for addr in [
            "8.8.8.8",
            "1.1.1.1",
            "203.0.114.1",
            "2001:4860:4860::8888",
            "2606:4700::1",
        ] {
            let c = classify(addr);
            assert!(!c.is_non_public(), "{addr} is public");
            assert_eq!(c.flags, 0, "{addr} has no category flags");
        }
    }

    #[test]
    fn ipv4_mapped_normalization() {
        let c = classify("::ffff:10.0.0.1");
        assert!(c.is_private_network(), "mapped 10.0.0.1 is private");
        assert_eq!(
            c.normalized(),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            "normalized to plain v4"
        );
        assert!(!classify("::ffff:8.8.8.8").is_non_public(), "mapped 8.8.8.8 is public");
    }

    #[test]
    fn nat64_wrapped_public_private_and_metadata() {
        let public = classify("64:ff9b::8.8.8.8");
        assert!(!public.is_non_public(), "NAT64-wrapped 8.8.8.8 is public");
        assert_eq!(
            public.normalized(),
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            "reduces to embedded v4"
        );

        let private = classify("64:ff9b::10.0.0.1");
        assert!(private.is_private_network(), "NAT64-wrapped 10.0.0.1 is private");

        let loopback = classify("64:ff9b::127.0.0.1");
        assert!(loopback.is_loopback(), "NAT64-wrapped 127.0.0.1 is loopback");

        for wrapped in [
            "64:ff9b::169.254.169.254",
            "64:ff9b::169.254.170.2",
            "64:ff9b::169.254.170.23",
            "64:ff9b::169.254.0.23",
            "64:ff9b::169.254.10.10",
        ] {
            let meta = classify(wrapped);
            assert!(meta.is_cloud_metadata(), "{wrapped}: NAT64-wrapped metadata endpoint");
            assert!(meta.is_link_local(), "{wrapped}: NAT64-wrapped metadata is link-local");
        }
    }

    #[test]
    fn cloud_metadata_endpoints() {
        // (endpoint, the broader non-public range flag it must also carry)
        for (addr, range) in [
            ("169.254.169.254", LINK_LOCAL),           // multi-cloud IMDS
            ("169.254.170.2", LINK_LOCAL),             // AWS ECS task credentials
            ("169.254.170.23", LINK_LOCAL),            // AWS EKS Pod Identity (v4)
            ("100.100.100.200", SHARED_ADDRESS_SPACE), // Alibaba
            ("169.254.0.23", LINK_LOCAL),              // Tencent CVM (VPC / intl)
            ("169.254.10.10", LINK_LOCAL),             // Tencent CVM (basic network / mainland)
            ("fd00:ec2::254", PRIVATE_NETWORK),        // AWS EC2 IMDS (v6, ULA)
            ("fd00:ec2::23", PRIVATE_NETWORK),         // AWS EKS Pod Identity (v6, ULA)
            ("fd20:ce::254", PRIVATE_NETWORK),         // GCP metadata (v6, ULA)
            ("fe80::a9fe:a9fe", LINK_LOCAL),           // OpenStack Nova metadata (v6, link-local)
        ] {
            let c = classify(addr);
            assert!(c.is_cloud_metadata(), "{addr} is a cloud metadata endpoint");
            assert_eq!(c.flags & range, range, "{addr} also carries its non-public range flag");
        }

        // Near-miss link-local neighbors that are NOT metadata: .169.253 borders
        // AWS IMDS, .0.22 borders Tencent .0.23, .20.10 is Tencent TKE NodeLocal DNS.
        for neighbor in ["169.254.169.253", "169.254.0.22", "169.254.20.10"] {
            assert!(
                !classify(neighbor).is_cloud_metadata(),
                "{neighbor} is a link-local neighbor, not a documented metadata endpoint"
            );
        }
    }

    #[test]
    fn is_non_public_is_the_union() {
        for addr in [
            "127.0.0.1",
            "10.0.0.1",
            "169.254.0.1",
            "100.64.0.1",
            "0.0.0.0",
            "::",
            "224.0.0.1",
            "192.0.2.1",
            "169.254.169.254",
            "::1",
            "fc00::1",
            "fe80::1",
            "fec0::1",
            "ff02::1",
        ] {
            assert!(classify(addr).is_non_public(), "{addr} must be non-public");
        }
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// Parse an IP literal and classify it via [`classify_ip`].
    fn classify(s: &str) -> IpClassification {
        classify_ip(&s.parse().unwrap())
    }

    /// Classify a raw IPv4 bit pattern via [`classify_ip`].
    fn classify_v4(bits: u32) -> IpClassification {
        classify_ip(&IpAddr::V4(Ipv4Addr::from(bits)))
    }

    /// Classify a raw IPv6 bit pattern via [`classify_ip`].
    fn classify_v6(bits: u128) -> IpClassification {
        classify_ip(&IpAddr::V6(Ipv6Addr::from(bits)))
    }

    /// First and last address (as raw bits) of an IPv4 special-use block.
    fn v4_block_bounds(block: &V4Block) -> (u32, u32) {
        let mask = if block.prefix == 0 {
            0
        } else {
            u32::MAX << 32_u8.saturating_sub(block.prefix)
        };
        let first = block.net.to_bits() & mask;
        (first, first | !mask)
    }

    /// First and last address (as raw bits) of an IPv6 special-use block.
    fn v6_block_bounds(block: &V6Block) -> (u128, u128) {
        let mask = if block.prefix == 0 {
            0
        } else {
            u128::MAX << 128_u8.saturating_sub(block.prefix)
        };
        let first = block.net.to_bits() & mask;
        (first, first | !mask)
    }

    /// Assert that `addr` classifies to exactly `flags` (with [`NON_PUBLIC`]
    /// implied for any non-zero `flags`).
    fn assert_exact(addr: &str, flags: u16) {
        let c = classify(addr);
        let expected = if flags == 0 { 0 } else { flags | NON_PUBLIC };
        assert_eq!(
            c.flags, expected,
            "{addr}: flags {:#06x} != expected {expected:#06x}",
            c.flags
        );
    }
}
