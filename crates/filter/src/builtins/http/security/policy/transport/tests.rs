// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Tests for the proxy-backed policy HTTP transport.
//!
//! Socket-level cases run against raw HTTP/1.1 backends served from OS
//! threads rather than tokio tasks, so a backend outlives any test runtime
//! the transport is driven from.

use std::{
    io::{Read as _, Write as _},
    net::{TcpListener, TcpStream},
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use bytes::Bytes;
use http::Method;
use pingora_core::upstreams::peer::Peer as _;
use ppe::praxis_policy_core::http_retry::RetryPolicy;

use super::*;

const OK_RESPONSE: &str = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi";

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// An empty private-endpoint allowlist, for transports under test.
fn no_allowlist() -> Arc<HashSet<String>> {
    Arc::new(HashSet::new())
}

/// A private-endpoint allowlist pinning a single host.
fn pinned_on(host: &str) -> HashSet<String> {
    let mut set = HashSet::new();
    set.insert(host.to_owned());
    set
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn a_pinned_host_permits_a_private_address_that_is_otherwise_refused() {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    let private = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)), 8443);

    // Not pinned: a private address is refused.
    assert!(
        usable_addresses(&[private], false, &HashSet::new(), "maas-api.svc").is_err(),
        "a private address must be refused when the host is not pinned"
    );

    // Pinned, matched case-insensitively: permitted. A non-listed host is not.
    let pinned = pinned_on("maas-api.svc");
    let usable =
        usable_addresses(&[private], false, &pinned, "MAAS-API.svc").expect("a pinned host permits a private address");
    assert_eq!(usable, vec![private]);
    assert!(
        usable_addresses(&[private], false, &pinned, "other.svc").is_err(),
        "a host not on the list is still refused a private address"
    );

    // The other relaxable range: a unique-local (fc00::/7) IPv6 address.
    let ula = SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0xFC00, 0, 0, 0, 0, 0, 0, 1)), 8443);
    assert!(
        usable_addresses(&[ula], false, &pinned, "maas-api.svc").is_ok(),
        "a pinned host permits a unique-local IPv6 address"
    );
}

#[test]
fn a_pinned_host_is_still_refused_localhost_and_metadata_ranges() {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    let pinned = pinned_on("maas-api.svc");

    // Everything a pin must NOT reach, in both families and in every embedded
    // form the metadata address can wear: link-local (cloud metadata) as IPv4,
    // as IPv4-mapped IPv6, as NAT64, and as the deprecated IPv4-compatible form;
    // IPv6 link-local; loopback and unspecified in both families; and the ranges
    // the old deny-list let a pin through by omission: shared address space
    // (CGNAT) and multicast.
    let denied: [SocketAddr; 11] = [
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)), 80),
        "[::ffff:169.254.169.254]:80"
            .parse()
            .expect("valid IPv4-mapped address"),
        "[64:ff9b::169.254.169.254]:80".parse().expect("valid NAT64 address"),
        "[::169.254.169.254]:80".parse().expect("valid IPv4-compatible address"),
        SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0xFE80, 0, 0, 0, 0, 0, 0, 1)), 80),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 80),
        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 80),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 80),
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 80),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)), 80),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)), 80),
    ];
    for address in denied {
        assert!(
            usable_addresses(&[address], false, &pinned, "maas-api.svc").is_err(),
            "a pinned host must not reach {address}"
        );
    }
}

#[test]
fn the_reason_prefixes_the_pin_allowlist_relies_on_hold() {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    // pin_may_relax keys on these two ppe-core reason prefixes, the only ranges
    // a pin relaxes. A reword there makes the allow-list stop matching, which
    // fails closed (the pin refuses a legitimate address) rather than open, but
    // it still silently breaks pinning, so lock the prefixes here.
    for (ip, prefix) in [
        (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)), "private address"),
        (
            IpAddr::V6(Ipv6Addr::new(0xFC00, 0, 0, 0, 0, 0, 0, 1)),
            "unique local address",
        ),
    ] {
        let reason = private_address_reason(&ip).expect("must be non-public");
        assert!(
            reason.starts_with(prefix),
            "reason {reason:?} must start with {prefix:?}"
        );
        assert!(pin_may_relax(reason), "pin_may_relax must accept {reason:?}");
    }

    // And the metadata address, in every embedded form, must never be relaxable.
    for ip in [
        "169.254.169.254".parse().expect("v4"),
        "::ffff:169.254.169.254".parse().expect("mapped"),
        "64:ff9b::169.254.169.254".parse().expect("nat64"),
        "::169.254.169.254".parse().expect("ipv4-compatible"),
    ] {
        let reason = private_address_reason(&ip).expect("must be non-public");
        assert!(!pin_may_relax(reason), "pin_may_relax must refuse {reason:?}");
    }
}

#[test]
fn only_rfc1918_and_unique_local_are_relaxable_across_every_range() {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    // A representative address for every range private_address_reason names,
    // asserting the pin relaxes RFC 1918 and unique-local only. This holds the
    // allow-list tight: a range whose reason does not begin with one of the two
    // relaxable prefixes stays denied, and a public address is never a pin case.
    let cases: [(IpAddr, bool); 16] = [
        (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), true),
        (IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)), true),
        (IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)), true),
        (IpAddr::V6(Ipv6Addr::new(0xFC00, 0, 0, 0, 0, 0, 0, 1)), true),
        (IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)), false),
        (IpAddr::V4(Ipv4Addr::LOCALHOST), false),
        (IpAddr::V4(Ipv4Addr::UNSPECIFIED), false),
        (IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)), false),
        (IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)), false),
        (IpAddr::V4(Ipv4Addr::BROADCAST), false),
        (IpAddr::V4(Ipv4Addr::new(240, 0, 0, 1)), false),
        (IpAddr::V4(Ipv4Addr::new(192, 0, 0, 1)), false),
        (IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1)), false),
        (IpAddr::V6(Ipv6Addr::LOCALHOST), false),
        (IpAddr::V6(Ipv6Addr::UNSPECIFIED), false),
        (IpAddr::V6(Ipv6Addr::new(0xFE80, 0, 0, 0, 0, 0, 0, 1)), false),
    ];
    for (ip, relaxable) in cases {
        match private_address_reason(&ip) {
            Some(reason) => assert_eq!(pin_may_relax(reason), relaxable, "{ip} reason {reason:?}"),
            None => assert!(
                !relaxable,
                "{ip} classifies as public and cannot be a relaxable private range"
            ),
        }
    }
}

#[test]
fn a_pin_matches_the_port_excluded_normalized_host() {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    // The allowlist matches Target::host, which excludes the port, so an IP
    // literal dialled with an explicit port still matches a bare entry.
    let t = Target::parse("http://10.0.0.1:8080/x").expect("parses");
    assert_eq!(t.host, "10.0.0.1");
    assert_eq!(t.host_header, "10.0.0.1:8080");
    let v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8080);
    assert!(
        usable_addresses(&[v4], false, &pinned_on("10.0.0.1"), &t.host).is_ok(),
        "a pinned IP literal with a port matches the port-excluded host"
    );

    // An IPv6 host keeps its brackets, so the entry is the bracketed literal.
    let t6 = Target::parse("http://[fc00::1]:8080/x").expect("parses");
    assert_eq!(t6.host, "[fc00::1]");
    let ula = SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0xFC00, 0, 0, 0, 0, 0, 0, 1)), 8080);
    assert!(
        usable_addresses(&[ula], false, &pinned_on("[fc00::1]"), &t6.host).is_ok(),
        "a pinned bracketed IPv6 literal matches"
    );

    // Case and a trailing dot on the dialled host normalize before the match.
    let svc = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)), 443);
    assert!(
        usable_addresses(&[svc], false, &pinned_on("maas-api.svc"), "MAAS-API.svc.").is_ok(),
        "an uppercase host with a trailing dot matches the normalized entry"
    );
}

#[test]
#[expect(clippy::too_many_lines, reason = "the mapping table is the test")]
fn every_transport_failure_maps_to_a_verdict_on_delivery() {
    let cases: Vec<(SubRequestError, HttpTransportError, bool)> = vec![
        (
            SubRequestError::InvalidRequest("bad header".to_owned()),
            HttpTransportError::InvalidRequest("bad header".to_owned()),
            false,
        ),
        (
            SubRequestError::AdmissionTimeout { max_connections: 7 },
            HttpTransportError::Connect("sub-request admission timeout (all 7 slots busy)".to_owned()),
            false,
        ),
        (
            SubRequestError::CircuitOpen {
                peer: "10.0.0.1:443".to_owned(),
            },
            HttpTransportError::Rejected("circuit open for peer 10.0.0.1:443".to_owned()),
            false,
        ),
        (
            SubRequestError::Connect("refused".to_owned()),
            HttpTransportError::Connect("refused".to_owned()),
            false,
        ),
        (
            SubRequestError::Io("reset".to_owned()),
            HttpTransportError::Io("reset".to_owned()),
            true,
        ),
        (SubRequestError::DeadlineExceeded, HttpTransportError::Timeout, true),
        (
            SubRequestError::StreamIdleTimeout {
                idle_timeout: Duration::from_secs(3),
            },
            HttpTransportError::Io("upstream stream idle for 3s".to_owned()),
            true,
        ),
        (
            SubRequestError::ResponseTooLarge {
                actual: 4096,
                limit: 1024,
            },
            HttpTransportError::ResponseTooLarge {
                actual: 4096,
                limit: 1024,
            },
            true,
        ),
    ];

    for (input, expected, may_have_reached_peer) in cases {
        let mapped = map_error(&input);
        assert_eq!(mapped, expected, "mapping {input:?}");
        assert_eq!(
            mapped.may_have_reached_peer(),
            may_have_reached_peer,
            "delivery verdict for {input:?}"
        );
    }
}

#[test]
fn a_starved_call_is_retryable_and_names_the_limit_it_hit() {
    let mapped = map_error(&SubRequestError::AdmissionTimeout { max_connections: 1 });

    assert!(
        !mapped.may_have_reached_peer(),
        "nothing was sent, so a token exchange must not have to reconcile a mint"
    );
    assert!(
        RetryPolicy::idempotent().should_retry(&mapped),
        "a JWKS fetch asks for idempotent retries and must actually get them"
    );
    assert!(
        RetryPolicy::undelivered_only().should_retry(&mapped),
        "an unsent request is safe to repeat even for a token mint"
    );
    assert!(
        mapped.to_string().contains("all 1 slots busy"),
        "the message must send an operator to the limit, not to the network; got {mapped}"
    );
}

#[test]
fn an_open_circuit_stays_a_refusal_and_is_not_retried() {
    let mapped = map_error(&SubRequestError::CircuitOpen {
        peer: "10.0.0.1:443".to_owned(),
    });

    assert!(matches!(mapped, HttpTransportError::Rejected(_)));
    assert!(!mapped.may_have_reached_peer());
    assert!(
        !RetryPolicy::idempotent().should_retry(&mapped),
        "retrying an open circuit only feeds it"
    );
}

#[test]
fn an_https_url_dials_port_443_with_the_host_as_sni() {
    let target = Target::parse("https://idp.example.com/jwks").unwrap();
    assert!(target.tls);
    assert_eq!(target.dial_authority, "idp.example.com:443");
    assert_eq!(target.sni, "idp.example.com");
    assert_eq!(target.host_header, "idp.example.com");
    assert_eq!(target.uri.to_string(), "/jwks");
}

#[test]
fn an_http_url_dials_port_80_with_no_sni() {
    let target = Target::parse("http://idp.example.com/jwks?v=2").unwrap();
    assert!(!target.tls);
    assert_eq!(target.dial_authority, "idp.example.com:80");
    assert_eq!(target.sni, "");
    assert_eq!(target.uri.to_string(), "/jwks?v=2");
}

#[test]
fn an_explicit_port_wins_over_the_scheme_default() {
    let target = Target::parse("https://idp.example.com:8443/jwks").unwrap();
    assert_eq!(target.dial_authority, "idp.example.com:8443");
    assert_eq!(target.host_header, "idp.example.com:8443");
    assert_eq!(target.sni, "idp.example.com");
}

#[test]
fn a_url_without_a_path_requests_the_root() {
    let target = Target::parse("https://idp.example.com").unwrap();
    assert_eq!(target.uri.to_string(), "/");
}

#[test]
fn an_ipv6_host_is_bracketed_for_dialling_and_carries_no_sni() {
    let target = Target::parse("http://[::1]:8080/jwks").unwrap();
    assert_eq!(target.dial_authority, "[::1]:8080");
    assert_eq!(target.sni, "");
    assert_eq!(target.host_header, "[::1]:8080");
}

#[test]
fn an_ip_literal_over_plaintext_is_accepted() {
    let target = Target::parse("http://127.0.0.1:9000/jwks").unwrap();
    assert_eq!(target.dial_authority, "127.0.0.1:9000");
    assert_eq!(target.sni, "");
}

#[test]
fn an_ip_literal_over_tls_is_refused_for_having_no_sni() {
    let err = Target::parse("https://10.0.0.1/jwks").unwrap_err();
    match err {
        HttpTransportError::InvalidRequest(message) => {
            assert!(
                message.contains("SNI"),
                "the refusal must name the reason; got {message}"
            );
        },
        other => panic!("expected InvalidRequest, got {other:?}"),
    }
}

#[test]
fn a_url_this_transport_will_not_dial_is_a_request_error() {
    for url in [
        "ftp://idp.example.com/jwks",
        "idp.example.com/jwks",
        "/jwks",
        "not a url at all",
        "https://user:pw@idp.example.com/jwks",
    ] {
        let err = Target::parse(url).unwrap_err();
        assert!(
            matches!(err, HttpTransportError::InvalidRequest(_)),
            "url '{url}' must be InvalidRequest, got {err:?}"
        );
    }
}

#[test]
fn userinfo_is_refused_rather_than_silently_dropped() {
    let err = Target::parse("https://user:pw@idp.example.com/jwks").unwrap_err();
    match err {
        HttpTransportError::InvalidRequest(message) => {
            assert!(
                message.contains("userinfo"),
                "the refusal must name userinfo; got {message}"
            );
        },
        other => panic!("expected InvalidRequest, got {other:?}"),
    }
}

#[test]
fn the_userinfo_refusal_does_not_repeat_the_credential() {
    let err = Target::parse("https://svc:S3cretPassw0rd@idp.example.com/jwks").unwrap_err();
    let message = err.to_string();
    assert!(
        !message.contains("S3cretPassw0rd"),
        "the password must not reach a log line; got {message}"
    );
    assert!(!message.contains("svc:"), "nor the userinfo it sat in; got {message}");
    assert!(message.contains("userinfo"), "but it must still say what was wrong");
}

#[test]
fn a_port_outside_the_u16_range_is_refused_not_defaulted() {
    for url in [
        "http://idp.example.com:99999/jwks",
        "https://idp.example.com:70000/jwks",
    ] {
        let err = Target::parse(url).unwrap_err();
        match err {
            HttpTransportError::InvalidRequest(message) => {
                assert!(
                    message.contains("port"),
                    "the refusal must name the port for '{url}'; got {message}"
                );
            },
            other => panic!("url '{url}' must be refused, got {other:?}"),
        }
    }
}

#[test]
fn port_zero_is_refused() {
    let err = Target::parse("http://idp.example.com:0/jwks").unwrap_err();
    assert!(matches!(err, HttpTransportError::InvalidRequest(_)), "got {err:?}");
}

#[test]
fn a_bracketed_ipv6_host_without_a_port_still_gets_the_scheme_default() {
    let target = Target::parse("http://[::1]/jwks").unwrap();
    assert_eq!(target.dial_authority, "[::1]:80");
}

#[test]
fn a_tls_peer_verifies_the_certificate_and_the_hostname() {
    let target = Target::parse("https://idp.example.com/jwks").unwrap();
    let peer = target.peer("203.0.113.10:443".parse().unwrap(), None);
    assert!(peer.options.verify_cert);
    assert!(peer.options.verify_hostname);
    assert_eq!(peer.sni, "idp.example.com");
}

#[test]
fn a_request_without_a_connect_bound_gets_the_engine_default() {
    let target = Target::parse("https://idp.example.com/jwks").unwrap();
    let peer = target.peer("203.0.113.10:443".parse().unwrap(), None);
    assert_eq!(peer.options.connection_timeout, Some(DEFAULT_CONNECT_TIMEOUT));
    assert_eq!(peer.options.total_connection_timeout, Some(DEFAULT_CONNECT_TIMEOUT));
}

#[test]
fn an_explicit_connect_bound_is_kept() {
    let target = Target::parse("https://idp.example.com/jwks").unwrap();
    let peer = target.peer("203.0.113.10:443".parse().unwrap(), Some(Duration::from_millis(250)));
    assert_eq!(peer.options.connection_timeout, Some(Duration::from_millis(250)));
}

#[test]
fn a_policy_peer_never_shares_a_pool_entry_with_a_data_plane_peer() {
    let address: SocketAddr = "203.0.113.10:443".parse().unwrap();
    let sni = "idp.internal".to_owned();

    let mut with_ca = HttpPeer::new(address, true, sni.clone());
    with_ca.options.ca = Some(Arc::from(Vec::new()));
    let without_ca = HttpPeer::new(address, true, sni.clone());
    assert_eq!(
        with_ca.reuse_hash(),
        without_ca.reuse_hash(),
        "if these ever differ, the group key below is no longer the thing keeping them apart"
    );

    let policy = Target::parse("https://idp.internal/jwks")
        .unwrap()
        .peer(address, Some(Duration::from_secs(1)));
    assert_ne!(
        policy.reuse_hash(),
        without_ca.reuse_hash(),
        "a policy call must not be handed a data-plane connection, or the reverse"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_non_public_destination_is_refused_before_a_socket_is_opened() {
    let (_reserved, closed) = crate::test_support::refusing_addr();
    let transport = transport(false);
    for url in [
        format!("http://{closed}/jwks"),
        "http://169.254.169.254/latest/meta-data/".to_owned(),
        "http://[::ffff:169.254.169.254]/latest/meta-data/".to_owned(),
        "http://100.64.0.1/jwks".to_owned(),
        "http://10.0.0.1/jwks".to_owned(),
    ] {
        let err = transport
            .execute(HttpRequest::get(url.clone()).timeout(Duration::from_secs(2)))
            .await
            .unwrap_err();
        match err {
            HttpTransportError::Rejected(reason) => {
                assert!(!reason.is_empty(), "the refusal must name the rule for '{url}'");
            },
            other => panic!("url '{url}' must be refused, got {other:?}"),
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_refusal_reason_names_the_rule_that_was_broken() {
    let transport = transport(false);
    let err = transport
        .execute(HttpRequest::get("http://169.254.169.254/latest/meta-data/"))
        .await
        .unwrap_err();
    match err {
        HttpTransportError::Rejected(reason) => {
            assert!(
                reason.contains("link-local") && reason.contains("metadata"),
                "the reason must send an operator to the right rule; got {reason}"
            );
        },
        other => panic!("expected Rejected, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn allowing_private_destinations_lets_a_loopback_idp_be_dialled() {
    let (_reserved, closed) = crate::test_support::refusing_addr();
    let err = transport(true)
        .execute(HttpRequest::get(format!("http://{closed}/jwks")).timeout(Duration::from_secs(2)))
        .await
        .unwrap_err();
    assert!(
        matches!(err, HttpTransportError::Connect(_)),
        "the dial must be attempted, not refused; got {err:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_host_that_does_not_resolve_reports_a_connect_failure() {
    let err = transport(true)
        .execute(HttpRequest::get("https://policy-transport-test.invalid/jwks").timeout(Duration::from_secs(5)))
        .await
        .unwrap_err();
    assert!(
        matches!(err, HttpTransportError::Connect(_)),
        "a name that does not resolve must not look like a delivered request; got {err:?}"
    );
    assert!(!err.may_have_reached_peer());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_hostname_resolving_only_to_loopback_is_refused_not_dialled() {
    let err = transport(false)
        .execute(HttpRequest::get("http://localhost:9/jwks").timeout(Duration::from_secs(2)))
        .await
        .unwrap_err();
    assert!(
        matches!(err, HttpTransportError::Rejected(_)),
        "resolution feeds the check, so a loopback name is refused; got {err:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn resolution_is_charged_against_the_callers_deadline() {
    let target = Target::parse("https://policy-transport-slow.invalid/jwks").unwrap();
    let err = transport(true)
        .resolve_within(&target, Duration::from_nanos(1))
        .await
        .expect_err("a budget this small cannot cover a lookup");

    assert!(
        matches!(err, HttpTransportError::Connect(_)),
        "an unsent request must stay retry-safe; got {err:?}"
    );
    assert!(!err.may_have_reached_peer());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_budget_spent_on_resolution_is_reported_as_unsent_not_as_a_timeout() {
    let target = Target::parse("http://127.0.0.1:9/jwks").unwrap();
    let err = transport(true)
        .resolve_within(&target, Duration::ZERO)
        .await
        .expect_err("no budget is left to send anything");

    assert!(
        matches!(err, HttpTransportError::Connect(_)),
        "nothing was sent, so this must not look delivered; got {err:?}"
    );
    assert!(!err.may_have_reached_peer(), "a token exchange must stay free to retry");
}

#[tokio::test(flavor = "multi_thread")]
async fn resolution_leaves_the_rest_of_the_budget_for_the_exchange() {
    let backend = Backend::spawn(Reply::Keepalive(OK_RESPONSE));
    let target = Target::parse(&backend.url("/jwks")).unwrap();
    let budget = Duration::from_secs(5);

    let (addresses, remaining) = transport(true).resolve_within(&target, budget).await.unwrap();

    assert_eq!(
        &*addresses,
        &[backend.address],
        "the literal address is what gets dialled"
    );
    assert!(remaining > Duration::ZERO, "a resolved literal leaves budget to spend");
    assert!(remaining <= budget, "and never more than was granted");
}

// -----------------------------------------------------------------------------
// Address selection and failover
// -----------------------------------------------------------------------------

#[test]
fn a_public_answer_survives_a_private_one() {
    let private: SocketAddr = "10.0.0.1:443".parse().unwrap();
    // Not a documentation range: the shared table denies those too.
    let public: SocketAddr = "8.8.8.8:443".parse().unwrap();

    let usable = usable_addresses(&[private, public], false, &HashSet::new(), "idp.example.com").unwrap();
    assert_eq!(usable, vec![public], "only the private answer is dropped");
}

#[test]
fn a_name_with_no_public_answer_is_refused_and_names_the_rule() {
    let err = usable_addresses(
        &["169.254.169.254:80".parse().unwrap(), "10.0.0.1:80".parse().unwrap()],
        false,
        &HashSet::new(),
        "idp.example.com",
    )
    .unwrap_err();

    match err {
        HttpTransportError::Rejected(reason) => {
            assert!(!reason.is_empty(), "the refusal must name a rule; got {reason}");
        },
        other => panic!("expected Rejected, got {other:?}"),
    }
}

#[test]
fn allowing_private_destinations_keeps_every_answer() {
    let addresses: Vec<SocketAddr> = vec!["10.0.0.1:443".parse().unwrap(), "127.0.0.1:443".parse().unwrap()];
    let usable = usable_addresses(&addresses, true, &HashSet::new(), "idp.internal").unwrap();
    assert_eq!(usable, addresses);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unreachable_address_fails_over_to_a_healthy_one() {
    let backend = Backend::spawn(Reply::Keepalive(OK_RESPONSE));
    let target = Target::parse(&backend.url("/jwks")).unwrap();
    let request = HttpRequest::get(backend.url("/jwks")).timeout(Duration::from_secs(5));
    let (_reserved, closed) = crate::test_support::refusing_addr();

    let response = transport(true)
        .dispatch(&target, &request, &[closed, backend.address], Duration::from_secs(5))
        .await
        .unwrap();

    assert_eq!(response.status, 200);
    assert_eq!(backend.heads().len(), 1, "the healthy address served it once");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_delivered_request_is_never_retried_on_another_address() {
    let read_then_closed = Backend::spawn(Reply::Silence);
    let untouched = Backend::spawn(Reply::Keepalive(OK_RESPONSE));
    let target = Target::parse(&read_then_closed.url("/token")).unwrap();
    let request = HttpRequest::post(read_then_closed.url("/token"), Bytes::from_static(b"grant_type=x"))
        .timeout(Duration::from_secs(5));

    let err = transport(true)
        .dispatch(
            &target,
            &request,
            &[read_then_closed.address, untouched.address],
            Duration::from_secs(5),
        )
        .await
        .unwrap_err();

    assert!(
        err.may_have_reached_peer(),
        "a peer that read the request leaves an unknown outcome; got {err:?}"
    );
    assert_eq!(read_then_closed.heads().len(), 1, "sent once");
    assert_eq!(
        untouched.connections(),
        0,
        "the next address must not be tried after a possible delivery"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_exhausted_budget_stops_the_walk_as_unsent() {
    let (_first_reserved, first) = crate::test_support::refusing_addr();
    let (_second_reserved, second) = crate::test_support::refusing_addr();
    let target = Target::parse("http://idp.example.com/jwks").unwrap();
    let request = HttpRequest::get("http://idp.example.com/jwks").timeout(Duration::from_millis(50));

    let err = transport(true)
        .dispatch(&target, &request, &[first, second], Duration::ZERO)
        .await
        .unwrap_err();

    assert!(matches!(err, HttpTransportError::Connect(_)), "got {err:?}");
    assert!(!err.may_have_reached_peer(), "nothing was sent");
}

#[test]
fn only_an_address_specific_failure_justifies_another_address() {
    assert!(worth_another_address(&SubRequestError::Connect("refused".to_owned())));
    assert!(worth_another_address(&SubRequestError::CircuitOpen {
        peer: "10.0.0.1:443".to_owned()
    }));
    assert!(!worth_another_address(&SubRequestError::AdmissionTimeout {
        max_connections: 1
    }));
    assert!(!worth_another_address(&SubRequestError::DeadlineExceeded));
    assert!(!worth_another_address(&SubRequestError::Io("reset".to_owned())));
}

// -----------------------------------------------------------------------------
// Limits and deadlines
// -----------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn a_successful_exchange_returns_the_status_body_and_headers() {
    let backend = Backend::spawn(Reply::Keepalive(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\n\r\n{\"keys\":[]}",
    ));
    let response = transport(true)
        .execute(HttpRequest::get(backend.url("/jwks")).timeout(Duration::from_secs(5)))
        .await
        .unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(&*response.body, br#"{"keys":[]}"#);
    assert_eq!(response.headers.get("content-type").unwrap(), "application/json");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_per_request_ceiling_is_enforced_below_the_transport_ceiling() {
    let backend = Backend::spawn(Reply::Keepalive(
        "HTTP/1.1 200 OK\r\nContent-Length: 64\r\n\r\n0123456789012345678901234567890123456789012345678901234567890123",
    ));
    let err = transport(true)
        .execute(
            HttpRequest::get(backend.url("/jwks"))
                .timeout(Duration::from_secs(5))
                .max_response_bytes(16),
        )
        .await
        .unwrap_err();
    match err {
        HttpTransportError::ResponseTooLarge { limit, .. } => {
            assert_eq!(
                limit, 16,
                "the per-request limit is authoritative, not the 1 MiB ceiling"
            );
        },
        other => panic!("expected ResponseTooLarge, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_jwks_sized_body_fits_under_the_transport_ceiling() {
    const BODY_BYTES: usize = 256 * 1024;
    let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {BODY_BYTES}\r\n\r\n");
    let response: &'static str = Box::leak(format!("{head}{}", "k".repeat(BODY_BYTES)).into_boxed_str());
    let backend = Backend::spawn(Reply::Keepalive(response));

    let got = transport(true)
        .execute(
            HttpRequest::get(backend.url("/jwks"))
                .timeout(Duration::from_secs(10))
                .max_response_bytes(BODY_BYTES),
        )
        .await
        .unwrap();
    assert_eq!(got.body.len(), BODY_BYTES);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_body_that_stalls_past_the_deadline_times_out() {
    let backend = Backend::spawn(Reply::Stall("HTTP/1.1 200 OK\r\nContent-Length: 32\r\n\r\n"));
    let err = transport(true)
        .execute(HttpRequest::get(backend.url("/jwks")).timeout(Duration::from_millis(300)))
        .await
        .unwrap_err();
    assert_eq!(err, HttpTransportError::Timeout);
    assert!(err.may_have_reached_peer(), "a timeout is an unknown outcome");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unreachable_peer_reports_a_connect_failure_not_a_timeout() {
    let err = transport(true)
        .execute(
            HttpRequest::get("http://192.0.2.1:443/token")
                .timeout(Duration::from_secs(30))
                .max_response_bytes(1024),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(err, HttpTransportError::Connect(_)),
        "an unsent request must be safe to retry; got {err:?}"
    );
    assert!(!err.may_have_reached_peer());
}

#[tokio::test(flavor = "multi_thread")]
async fn authorization_reaches_the_backend_verbatim() {
    let backend = Backend::spawn(Reply::Keepalive(OK_RESPONSE));
    let request = HttpRequest::post(
        backend.url("/token"),
        Bytes::from_static(b"grant_type=client_credentials"),
    )
    .timeout(Duration::from_secs(5))
    .header("authorization", "Basic Y2xpZW50OnNlY3JldA==")
    .unwrap();
    transport(true).execute(request).await.unwrap();

    let heads = backend.heads();
    assert_eq!(heads.len(), 1);
    assert!(
        heads[0].to_ascii_lowercase().contains("authorization:"),
        "client-secret basic auth must survive sanitisation; got {}",
        heads[0]
    );
    assert!(
        heads[0].contains("Basic Y2xpZW50OnNlY3JldA=="),
        "the credential must arrive byte for byte; got {}",
        heads[0]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_host_header_is_the_url_authority_not_the_socket_address() {
    let backend = Backend::spawn(Reply::Keepalive(OK_RESPONSE));
    let url = format!("http://localhost:{}/jwks", backend.address.port());
    transport(true)
        .execute(HttpRequest::get(url).timeout(Duration::from_secs(5)))
        .await
        .unwrap();

    let heads = backend.heads();
    assert!(
        heads[0]
            .to_ascii_lowercase()
            .contains(&format!("host: localhost:{}", backend.address.port())),
        "a virtual-hosted IdP needs the name it was configured with; got {}",
        heads[0]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn conditional_refresh_headers_survive_the_response() {
    let backend = Backend::spawn(Reply::Keepalive(
        "HTTP/1.1 200 OK\r\nETag: \"abc123\"\r\nCache-Control: max-age=600\r\nContent-Length: 2\r\n\r\nhi",
    ));
    let response = transport(true)
        .execute(HttpRequest::get(backend.url("/jwks")).timeout(Duration::from_secs(5)))
        .await
        .unwrap();
    assert_eq!(response.etag(), Some("\"abc123\""));
    assert_eq!(response.cache_max_age(), Some(Duration::from_secs(600)));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failed_exchange_is_never_resent() {
    for (method, body) in [
        (Method::GET, Bytes::new()),
        (Method::POST, Bytes::from_static(b"grant_type=client_credentials")),
    ] {
        let backend = Backend::spawn(Reply::Silence);
        let request = HttpRequest::new(method.clone(), backend.url("/token"))
            .body(body)
            .timeout(Duration::from_secs(5));
        let err = transport(true).execute(request).await.unwrap_err();
        assert!(
            err.may_have_reached_peer(),
            "{method}: a peer that read the request leaves an unknown outcome; got {err:?}"
        );
        assert_eq!(backend.heads().len(), 1, "{method}: the request was sent once");
        assert_eq!(backend.connections(), 1, "{method}: one connection was opened");
    }
}

#[test]
fn a_new_transport_builds_its_client_lazily() {
    let transport = PolicyHttpTransport::new(false, no_allowlist());
    assert!(transport.client.get().is_none(), "the client is built on first use");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_transport_that_was_never_handed_a_client_builds_its_own_and_dispatches() {
    praxis_tls::provider::install();
    let backend = Backend::spawn(Reply::Keepalive(OK_RESPONSE));
    let transport = PolicyHttpTransport::new(true, no_allowlist());
    assert!(transport.client.get().is_none(), "nothing built yet");

    let response = transport
        .execute(HttpRequest::get(backend.url("/jwks")).timeout(Duration::from_secs(5)))
        .await
        .unwrap();

    assert_eq!(response.status, 200);
    assert!(
        transport.client.get().is_some(),
        "the first call must have built the client through client()"
    );
    assert_eq!(backend.heads().len(), 1);
}

#[test]
fn a_transport_keeps_the_connector_it_was_built_with() {
    let _guard = crate::policy_connector::REGISTRATION_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let own = crate::test_support::connector(8, None);
    let transport = PolicyHttpTransport::with_connector(Some(own.clone()), true, no_allowlist());

    crate::set_policy_subrequest_connector(&crate::test_support::connector(1, None));

    assert!(
        std::ptr::eq(transport.client().connector().connector(), own.connector()),
        "the pool must be the one captured at construction, not the newest registration"
    );
}

#[test]
fn a_transport_built_after_registration_uses_the_registered_pool() {
    let _guard = crate::policy_connector::REGISTRATION_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let shared = crate::test_support::connector(16, None);
    crate::set_policy_subrequest_connector(&shared);

    let transport = PolicyHttpTransport::new(true, no_allowlist());

    assert!(
        std::ptr::eq(transport.client().connector().connector(), shared.connector()),
        "a transport built the way the filter builds it must pick up the host's registration \
         instead of opening a private pool"
    );
}

#[test]
fn a_transport_built_without_a_registration_falls_back() {
    praxis_tls::provider::install();
    let transport = PolicyHttpTransport::with_connector(None, true, no_allowlist());
    assert!(transport.client.get().is_none(), "nothing built before first use");
    let _client = transport.client();
    assert!(transport.client.get().is_some());
}

#[test]
fn the_registered_connector_is_the_one_policy_calls_use() {
    let shared = crate::test_support::connector(16, None);
    let client = build_client(Some(shared.clone()));
    assert!(
        std::ptr::eq(client.connector().connector(), shared.connector()),
        "policy calls must share the proxy's pool, not open a second one"
    );
}

#[test]
fn two_transports_from_one_registration_share_a_pool() {
    let shared = crate::test_support::connector(16, None);
    let first = build_client(Some(shared.clone()));
    let second = build_client(Some(shared.clone()));
    assert!(std::ptr::eq(
        first.connector().connector(),
        second.connector().connector()
    ));
}

#[test]
fn an_unregistered_host_falls_back_to_its_own_pool() {
    praxis_tls::provider::install();
    let first = build_client(None);
    let second = build_client(None);
    assert!(
        !std::ptr::eq(first.connector().connector(), second.connector().connector()),
        "the fallback is a private pool, so it cannot be mistaken for the shared one"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_pool_outlives_the_runtime_that_built_the_transport() {
    let backend = Backend::spawn(Reply::Keepalive(OK_RESPONSE));
    let url = backend.url("/jwks");

    let transport = Arc::new(transport(true));
    let init = Arc::clone(&transport);
    let init_url = url.clone();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime
            .block_on(init.execute(HttpRequest::get(init_url).timeout(Duration::from_secs(5))))
            .unwrap();
    })
    .join()
    .unwrap();

    let response = transport
        .execute(HttpRequest::get(url).timeout(Duration::from_secs(5)))
        .await
        .unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(backend.heads().len(), 2, "both requests reached the backend");
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Raw HTTP/1.1 test backend that records received request heads.
struct Backend {
    /// Listening address.
    address: SocketAddr,

    /// Request heads in arrival order.
    heads: Arc<Mutex<Vec<String>>>,

    /// Accepted connection count.
    connections: Arc<AtomicUsize>,
}

/// Test-backend response behavior.
#[derive(Clone, Copy)]
enum Reply {
    /// Reply and keep the connection open.
    Keepalive(&'static str),

    /// Reply with headers, then stall.
    Stall(&'static str),

    /// Close without replying.
    Silence,
}

impl Backend {
    /// Start a test backend.
    fn spawn(reply: Reply) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let heads = Arc::new(Mutex::new(Vec::new()));
        let connections = Arc::new(AtomicUsize::new(0));

        let thread_heads = Arc::clone(&heads);
        let thread_connections = Arc::clone(&connections);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { return };
                thread_connections.fetch_add(1, Ordering::SeqCst);
                let heads = Arc::clone(&thread_heads);
                std::thread::spawn(move || serve(stream, reply, &heads));
            }
        });

        Self {
            address,
            heads,
            connections,
        }
    }

    /// Return recorded request heads.
    fn heads(&self) -> Vec<String> {
        self.heads.lock().unwrap().clone()
    }

    /// Return the accepted connection count.
    fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }

    /// Build a plaintext URL for this backend.
    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.address)
    }
}

/// Serve requests on one test connection.
fn serve(mut stream: TcpStream, reply: Reply, heads: &Arc<Mutex<Vec<String>>>) {
    loop {
        let Some(head) = read_head(&mut stream) else { return };
        drain_body(&mut stream, &head);
        heads.lock().unwrap().push(head);
        match reply {
            Reply::Silence => return,
            Reply::Keepalive(response) => {
                if stream.write_all(response.as_bytes()).is_err() {
                    return;
                }
                let _ignored = stream.flush();
            },
            Reply::Stall(response) => {
                let _ignored = stream.write_all(response.as_bytes());
                let _ignored = stream.flush();
                while stream.read(&mut [0_u8; 1]).is_ok_and(|read| read > 0) {}
                return;
            },
        }
    }
}

/// Read one request head.
fn read_head(stream: &mut TcpStream) -> Option<String> {
    let mut head = Vec::new();
    let mut byte = [0_u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match stream.read(&mut byte) {
            Ok(0) | Err(_) => return None,
            Ok(_) => head.push(byte[0]),
        }
    }
    String::from_utf8(head).ok()
}

/// Consume the body announced by `Content-Length`.
fn drain_body(stream: &mut TcpStream, head: &str) {
    let length = head
        .lines()
        .find_map(|line| {
            line.strip_prefix("content-length: ")
                .or_else(|| line.strip_prefix("Content-Length: "))
        })
        .and_then(|value| value.trim().parse::<usize>().ok())
        .unwrap_or(0);
    if length > 0 {
        let mut body = vec![0_u8; length];
        let _ignored = stream.read_exact(&mut body);
    }
}

/// Build a transport with a private test pool.
fn transport(allow_private: bool) -> PolicyHttpTransport {
    praxis_tls::provider::install();
    let transport = PolicyHttpTransport::new(allow_private, no_allowlist());
    transport
        .client
        .set(build_client(None))
        .map_err(|_ignored| "client already set")
        .unwrap();
    transport
}
