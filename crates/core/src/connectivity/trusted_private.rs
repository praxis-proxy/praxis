// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Hosts allowed to resolve into RFC 1918 or unique-local space, metadata excluded.

use std::net::IpAddr;

use super::classify_without_nat64;

/// Reject a `trusted_private_endpoints` entry that is not a bare host.
///
/// # Errors
///
/// Returns a message naming `context` and the first malformed entry.
pub fn validate_host_entries(context: &str, entries: &[String]) -> Result<(), String> {
    for entry in entries {
        let fault = if entry.is_empty() {
            "is empty"
        } else if entry.contains(char::is_whitespace) {
            "contains whitespace"
        } else if entry.contains('/') {
            "contains '/'"
        } else if entry.contains('@') {
            "contains '@'"
        } else if entry.contains('*') {
            "contains '*'"
        } else if entry.contains(':') && !(entry.starts_with('[') && entry.ends_with(']')) {
            "contains an unbracketed ':' (use [ipv6] for a literal, and no port)"
        } else {
            continue;
        };
        return Err(format!("{context}: trusted_private_endpoints entry {entry:?} {fault}"));
    }
    Ok(())
}

/// `host` without one trailing root dot.
pub(crate) fn strip_root_dot(host: &str) -> &str {
    host.strip_suffix('.').unwrap_or(host)
}

/// Whether `host` matches a listed entry, entries pre-normalized.
pub(crate) fn is_trusted_host(trusted: &[Box<str>], host: &str) -> bool {
    let host = strip_root_dot(host);
    trusted.iter().any(|entry| entry.eq_ignore_ascii_case(host))
}

/// RFC 1918 or unique local, excluding cloud metadata.
pub(crate) fn trusted_host_may_reach(ip: &IpAddr) -> bool {
    let class = classify_without_nat64(ip);
    class.is_private_network() && !class.is_cloud_metadata()
}

#[cfg(test)]
#[expect(clippy::expect_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn a_bare_host_or_bracketed_ipv6_is_accepted() {
        let ok = ["maas-api.svc".to_owned(), "10.0.0.1".to_owned(), "[fc00::1]".to_owned()];
        validate_host_entries("policy", &ok).expect("bare hosts and a bracketed IPv6 are valid");
    }

    #[test]
    fn a_malformed_entry_is_rejected_naming_the_context_and_entry() {
        for bad in [
            "host:8080",
            "::1",
            "[fc00::1]:80",
            "https://host",
            "host/path",
            "user@host",
            "*.svc",
            "host name",
            "",
        ] {
            let err = validate_host_entries("cluster 'models'", &[bad.to_owned()])
                .expect_err("a malformed entry must be rejected");
            assert!(
                err.starts_with("cluster 'models': trusted_private_endpoints entry"),
                "{err}"
            );
            assert!(err.contains(&format!("{bad:?}")), "{err}");
        }
    }

    #[test]
    fn host_match_is_case_insensitive_and_strips_one_root_dot() {
        let trusted: Vec<Box<str>> = vec!["model.ns.svc".into()];
        for (host, want) in [
            ("model.ns.svc", true),
            ("MODEL.ns.SVC", true),
            ("model.ns.svc.", true),
            ("model.ns.svc..", false),
            ("other.ns.svc", false),
            ("model.ns.svc.cluster.local", false),
            ("ns.svc", false),
        ] {
            assert_eq!(is_trusted_host(&trusted, host), want, "{host}");
        }
        assert!(!is_trusted_host(&[], "model.ns.svc"));
    }

    #[test]
    fn a_trusted_host_reaches_only_rfc1918_and_unique_local() {
        for (ip, want) in [
            ("10.96.0.10", true),
            ("172.30.202.42", true),
            ("192.168.1.5", true),
            ("::ffff:10.0.0.1", true),
            ("fd12:3456::1", true),
            ("::ffff:169.254.169.254", false),
            ("::ffff:127.0.0.1", false),
            ("127.0.0.1", false),
            ("::1", false),
            ("169.254.169.254", false),
            ("169.254.170.2", false),
            ("fe80::1", false),
            ("fd00:ec2::254", false),
            ("fd00:ec2::23", false),
            ("fd20:ce::254", false),
            ("100.64.0.1", false),
            ("100.100.100.200", false),
            ("0.0.0.0", false),
            ("::", false),
            ("8.8.8.8", false),
        ] {
            let parsed: IpAddr = ip.parse().expect("test address");
            assert_eq!(trusted_host_may_reach(&parsed), want, "{ip}");
        }
    }
}
