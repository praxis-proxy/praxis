// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! SPIFFE identity read and validated from a certificate.
//!
//! One home for the SPIFFE domain logic both verifiers share. A SPIFFE
//! certificate names its bearer with exactly one URI SAN. Both validate the whole
//! X.509-SVID leaf against the standard (standards/X509-SVID.md): the connecting
//! side pins one exact identity (`svid_id_matches`), the listener side authorizes
//! a peer whose identity is in an allowlist (`authorize_peer`).

use std::sync::Arc;

use x509_parser::{certificate::X509Certificate, extensions::GeneralName, prelude::FromDer as _};

/// The URI subject alternative names of an already-parsed certificate (the
/// `SubjectAltName` extension, RFC 5280 section 4.2.1.6).
pub(crate) fn uri_sans<'cert>(cert: &'cert X509Certificate<'cert>) -> impl Iterator<Item = &'cert str> {
    cert.subject_alternative_name()
        .ok()
        .flatten()
        .into_iter()
        .flat_map(|san| san.value.general_names.iter())
        .filter_map(|name| match name {
            GeneralName::URI(uri) => Some(*uri),
            GeneralName::OtherName(..)
            | GeneralName::RFC822Name(_)
            | GeneralName::DNSName(_)
            | GeneralName::X400Address(_)
            | GeneralName::DirectoryName(_)
            | GeneralName::EDIPartyName(_)
            | GeneralName::IPAddress(_)
            | GeneralName::RegisteredID(_)
            | GeneralName::Invalid(..) => None,
        })
}

/// The outcome of authorizing a peer certificate at the handshake.
///
/// Distinguishes an invalid leaf from an allowlist miss so the caller can log the
/// reason without exposing it on the wire.
#[derive(Debug)]
pub(crate) enum PeerAuth {
    /// A valid X.509-SVID leaf whose SPIFFE ID the allowlist admits.
    Allowed,

    /// The certificate is not a valid X.509-SVID leaf.
    InvalidLeaf,

    /// A valid X.509-SVID leaf whose SPIFFE ID is not in a non-empty allowlist.
    NotAllowed(String),
}

/// Authorize a peer certificate: validate the X.509-SVID leaf, then check the
/// allowlist. An empty `allowed` admits any valid leaf.
///
/// The handshake authorization floor, applied after the chain check. Fails
/// closed: a parse failure or unmet leaf rule is [`PeerAuth::InvalidLeaf`].
pub(crate) fn authorize_peer(leaf_der: &[u8], allowed: &[Arc<str>]) -> PeerAuth {
    let Some(id) = validated_svid_id_from_der(leaf_der) else {
        return PeerAuth::InvalidLeaf;
    };
    if allowed.is_empty() || allowed.iter().any(|allowed_id| allowed_id.as_ref() == id) {
        PeerAuth::Allowed
    } else {
        PeerAuth::NotAllowed(id)
    }
}

/// Whether `leaf_der` is a valid X.509-SVID leaf whose SPIFFE ID equals
/// `expected`. The connecting side's pin, allocation-free (the id is borrowed and
/// compared in place). A parse failure or unmet rule returns `false` (fail closed).
pub(crate) fn svid_id_matches(leaf_der: &[u8], expected: &str) -> bool {
    let Ok((_, cert)) = X509Certificate::from_der(leaf_der) else {
        return false;
    };
    validated_svid_id(&cert) == Some(expected)
}

/// The SPIFFE ID of `leaf_der` if it is a valid X.509-SVID leaf, owned so the
/// parsed certificate need not outlive the call. `None` on any parse failure or
/// unmet rule (fail closed).
fn validated_svid_id_from_der(leaf_der: &[u8]) -> Option<String> {
    let (_, cert) = X509Certificate::from_der(leaf_der).ok()?;
    validated_svid_id(&cert).map(ToOwned::to_owned)
}

/// The SPIFFE ID borrowed from a parsed certificate, if it is a valid X.509-SVID
/// leaf, else `None`.
///
/// Enforces the SPIFFE X509-SVID standard (standards/X509-SVID.md) rules a chain
/// check does not. The section 5 validation floor: exactly one URI SAN that is a
/// valid leaf SPIFFE ID, `cA` not true, and neither keyCertSign nor cRLSign. Plus
/// the section 4 leaf profile a conforming SVID carries: a present, critical
/// `keyUsage` with digitalSignature, and, when the `extendedKeyUsage` is present,
/// both serverAuth and clientAuth. A malformed extension or unmet rule yields
/// `None` (fail closed). Chain and validity are the caller's trust-anchor check.
fn validated_svid_id<'cert>(cert: &'cert X509Certificate<'cert>) -> Option<&'cert str> {
    if has_unusable_extension(cert) {
        return None;
    }
    // 4.1 / 5: a leaf MUST NOT set cA true. A malformed extension rejects; an
    // absent one is cA false per the RFC 5280 default.
    match cert.basic_constraints() {
        Ok(Some(bc)) if bc.value.ca => return None,
        Err(_) => return None,
        _ => {},
    }
    // 4.3: keyUsage MUST be present, critical, set digitalSignature, and set
    // neither keyCertSign nor cRLSign.
    let Ok(Some(ku)) = cert.key_usage() else {
        return None;
    };
    if !ku.critical || !ku.value.digital_signature() || ku.value.key_cert_sign() || ku.value.crl_sign() {
        return None;
    }
    // 4.4: when the extendedKeyUsage is present it MUST set both serverAuth and
    // clientAuth. An absent EKU is permitted (the standard marks it SHOULD).
    match cert.extended_key_usage() {
        Ok(Some(eku)) if !(eku.value.server_auth && eku.value.client_auth) => return None,
        Err(_) => return None,
        _ => {},
    }
    // 5: exactly one URI SAN, and it must be a valid leaf SPIFFE ID.
    let mut uris = uri_sans(cert);
    let id = uris.next()?;
    if uris.next().is_some() || !is_leaf_spiffe_id(id) {
        return None;
    }
    Some(id)
}

/// Whether the certificate carries an extension the verifier cannot honor.
///
/// Rejects a known extension that failed to parse, such as a malformed
/// basicConstraints that x509-parser would otherwise report as absent, and any
/// unrecognized critical extension (RFC 5280 section 4.2). An unrecognized
/// non-critical extension is ignored, as RFC 5280 allows.
fn has_unusable_extension(cert: &X509Certificate<'_>) -> bool {
    use x509_parser::extensions::ParsedExtension;

    cert.extensions().iter().any(|ext| {
        let parsed = ext.parsed_extension();
        matches!(parsed, ParsedExtension::ParseError { .. })
            || (ext.critical && matches!(parsed, ParsedExtension::UnsupportedExtension { .. }))
    })
}

/// Whether `id` is a valid leaf SPIFFE ID: a valid SPIFFE ID by the SPIFFE-ID
/// spec (scheme, trust-domain and path grammar parsed by the `spiffe` crate) with
/// a non-empty path, so it names a workload rather than the trust domain root
/// (X509-SVID section 3.1).
///
/// The shared validity floor: the server pins one exact id, the client accepts
/// any valid name.
///
/// Only the canonical form is accepted. SPIFFE treats the scheme and trust domain
/// case-insensitively and the path case-sensitively (SPIFFE-ID section 2.4), and
/// the `spiffe` parser normalizes an uppercase scheme or trust domain rather than
/// rejecting it. The pin and the SAN both flow through here and are then compared
/// byte for byte, so requiring `id` to equal its own canonical string keeps a
/// noncanonical form from silently failing to match its canonical twin.
pub(crate) fn is_leaf_spiffe_id(id: &str) -> bool {
    id.starts_with("spiffe://")
        && id
            .parse::<spiffe::SpiffeId>()
            .is_ok_and(|sid| !sid.path().is_empty() && sid.to_string() == id)
}

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::expect_used, reason = "tests")]
mod tests {
    use rcgen::{
        BasicConstraints, CertificateParams, CustomExtension, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
        KeyUsagePurpose, SanType,
    };

    use super::*;

    const EXPECTED: &str = "spiffe://grid.internal/signals";

    #[test]
    fn a_conforming_svid_is_accepted() {
        assert!(svid_id_allowed(&conforming(EXPECTED), &[Arc::from(EXPECTED)]));
    }

    #[test]
    fn svid_id_matches_the_pinned_id_and_rejects_another() {
        let der = conforming(EXPECTED);
        assert!(svid_id_matches(&der, EXPECTED), "the pinned id matches");
        assert!(
            !svid_id_matches(&der, "spiffe://grid.internal/other"),
            "a different id does not match"
        );
    }

    #[test]
    fn an_empty_allowlist_accepts_a_conforming_svid() {
        assert!(
            svid_id_allowed(&conforming(EXPECTED), &[]),
            "empty allowlist accepts any valid leaf"
        );
    }

    #[test]
    fn a_multi_segment_path_is_accepted() {
        let id = "spiffe://grid.internal/site/pool-a/node-1";
        assert!(svid_id_allowed(&conforming(id), &[Arc::from(id)]));
    }

    #[test]
    fn an_absent_eku_is_accepted() {
        // EKU is SHOULD, not MUST: a leaf with a conforming keyUsage but no EKU is valid.
        let der = leaf(&[EXPECTED], &[KeyUsagePurpose::DigitalSignature], &[], false);
        assert!(svid_id_allowed(&der, &[]));
    }

    #[test]
    fn a_ca_flagged_leaf_is_rejected() {
        let der = leaf(
            &[EXPECTED],
            &[KeyUsagePurpose::DigitalSignature],
            &[ExtendedKeyUsagePurpose::ServerAuth, ExtendedKeyUsagePurpose::ClientAuth],
            true,
        );
        assert!(!svid_id_allowed(&der, &[]));
    }

    #[test]
    fn a_key_cert_sign_leaf_is_rejected() {
        let der = leaf(
            &[EXPECTED],
            &[KeyUsagePurpose::DigitalSignature, KeyUsagePurpose::KeyCertSign],
            &[],
            false,
        );
        assert!(!svid_id_allowed(&der, &[]));
    }

    #[test]
    fn a_crl_sign_leaf_is_rejected() {
        let der = leaf(
            &[EXPECTED],
            &[KeyUsagePurpose::DigitalSignature, KeyUsagePurpose::CrlSign],
            &[],
            false,
        );
        assert!(!svid_id_allowed(&der, &[]));
    }

    #[test]
    fn an_absent_key_usage_is_rejected() {
        // Section 4.3: keyUsage MUST be present. rcgen omits it when empty.
        let der = leaf(&[EXPECTED], &[], &[], false);
        assert!(!svid_id_allowed(&der, &[]));
    }

    #[test]
    fn a_key_usage_without_digital_signature_is_rejected() {
        let der = leaf(&[EXPECTED], &[KeyUsagePurpose::KeyEncipherment], &[], false);
        assert!(!svid_id_allowed(&der, &[]));
    }

    #[test]
    fn a_non_critical_key_usage_is_rejected() {
        // Section 4.3: keyUsage MUST be marked critical.
        let der = leaf_with_custom_ext(EXPECTED, noncritical_key_usage(), false);
        assert!(!svid_id_allowed(&der, &[]));
    }

    #[test]
    fn an_eku_with_only_client_auth_is_rejected() {
        let der = leaf(
            &[EXPECTED],
            &[KeyUsagePurpose::DigitalSignature],
            &[ExtendedKeyUsagePurpose::ClientAuth],
            false,
        );
        assert!(
            !svid_id_allowed(&der, &[]),
            "a present EKU must set both server and client auth"
        );
    }

    #[test]
    fn an_eku_with_only_server_auth_is_rejected() {
        let der = leaf(
            &[EXPECTED],
            &[KeyUsagePurpose::DigitalSignature],
            &[ExtendedKeyUsagePurpose::ServerAuth],
            false,
        );
        assert!(!svid_id_allowed(&der, &[]));
    }

    #[test]
    fn a_malformed_basic_constraints_is_rejected_critical_or_not() {
        // A known extension that failed to parse must not read as absent-permissive.
        assert!(!svid_id_allowed(
            &leaf_with_custom_ext(EXPECTED, malformed_basic_constraints(true), true),
            &[]
        ));
        assert!(!svid_id_allowed(
            &leaf_with_custom_ext(EXPECTED, malformed_basic_constraints(false), true),
            &[]
        ));
    }

    #[test]
    fn a_non_spiffe_uri_is_rejected() {
        let der = conforming("https://grid.internal/signals");
        assert!(!svid_id_allowed(&der, &[]));
    }

    #[test]
    fn a_leaf_without_a_uri_san_is_rejected() {
        let der = leaf(
            &[],
            &[KeyUsagePurpose::DigitalSignature],
            &[ExtendedKeyUsagePurpose::ServerAuth, ExtendedKeyUsagePurpose::ClientAuth],
            false,
        );
        assert!(!svid_id_allowed(&der, &[]));
    }

    #[test]
    fn a_two_uri_san_leaf_names_nobody() {
        let der = leaf(
            &["spiffe://grid.internal/site/a", "spiffe://grid.internal/site/b"],
            &[KeyUsagePurpose::DigitalSignature],
            &[],
            false,
        );
        assert!(
            !svid_id_allowed(&der, &[]),
            "a multi-SAN leaf names nobody and is not a valid SVID"
        );
    }

    #[test]
    fn spiffe_id_shape_rules_accept_and_reject() {
        assert!(is_leaf_spiffe_id("spiffe://example.org/workload"));
        assert!(is_leaf_spiffe_id("spiffe://example.org/site/pool-a/node-1"));
        // The path is case-sensitive: a mixed-case path is already canonical.
        assert!(is_leaf_spiffe_id("spiffe://example.org/Workload"));
        for bad in [
            "spiffe://example.org",                 // no path
            "spiffe://example.org/",                // empty path
            "spiffe:///workload",                   // empty trust domain
            "https://example.org/workload",         // wrong scheme
            "SPIFFE://example.org/workload",        // parser normalizes case, lowercase guard rejects
            "spiffe://EXAMPLE.ORG/workload",        // parser lowercases the trust domain, noncanonical
            "spiffe://Example.org/workload",        // mixed-case trust domain, noncanonical
            "spiffe://example.org:8443/workload",   // a port is not part of a SPIFFE id
            "spiffe://user@example.org/workload",   // userinfo is not part of a SPIFFE id
            "spiffe://exam\u{0440}le.org/workload", // Cyrillic homograph, non-ASCII trust domain
            "spiffe://example.org/work%6eoad",      // percent-encoding is not decoded
            "spiffe://example.org/workload?x=1",    // query string smuggled onto the path
            "spiffe://example.org/workload#frag",   // fragment smuggled onto the path
            "spiffe://example.org//workload",       // empty path segment
            "spiffe://example.org/work\nload",      // control byte
            "spiffe://example.org/work\0load",      // NUL byte
            " spiffe://example.org/workload",       // leading space, no prefix match
            "spiffe://",                            // nothing
            "",                                     // empty
        ] {
            assert!(!is_leaf_spiffe_id(bad), "must reject {bad:?}");
        }
    }

    #[test]
    fn a_noncanonical_trust_domain_pin_is_rejected() {
        // SPIFFE trust domains are case-insensitive and canonically lowercase, so
        // the parser normalizes GRID.INTERNAL to grid.internal. Accepting the
        // uppercase form as a pin would then reject a conforming lowercase SVID at
        // the byte compare, so it is rejected at the boundary instead.
        assert!(!is_leaf_spiffe_id("spiffe://GRID.INTERNAL/signals"));
        assert!(is_leaf_spiffe_id(EXPECTED));
    }

    #[test]
    fn a_cert_with_a_noncanonical_trust_domain_fails_closed() {
        // A SAN carrying an uppercase trust domain is not a conforming SVID:
        // validation rejects it rather than normalizing it into a match.
        let der = conforming("spiffe://GRID.INTERNAL/signals");
        assert!(!svid_id_matches(&der, EXPECTED), "must not match the canonical pin");
        assert!(!svid_id_allowed(&der, &[]), "must be an invalid leaf");
    }

    #[test]
    fn a_conforming_svid_with_an_extra_dns_san_still_matches() {
        // A leaf MAY carry a DNS SAN, and only URI SANs are read, so the single
        // SPIFFE URI still names the workload and the pin matches.
        let der = conforming_with_sans(&[EXPECTED], &["peer.grid.internal"]);
        assert!(svid_id_matches(&der, EXPECTED));
    }

    #[test]
    fn a_spiffe_id_in_a_dns_san_is_not_the_identity() {
        // The identity MUST be a URI SAN. A spiffe-looking value in a DNS SAN is
        // ignored, so a leaf carrying it but no URI SAN is not a valid SVID.
        let der = conforming_with_sans(&[], &[EXPECTED]);
        assert!(!svid_id_matches(&der, EXPECTED), "a DNS SAN is not a SPIFFE id");
        assert!(!svid_id_allowed(&der, &[]), "no URI SAN means no valid leaf");
    }

    #[test]
    fn duplicate_uri_sans_name_nobody() {
        // Two URI SANs name nobody even when identical: exactly one is required, so
        // duplication cannot smuggle a second identity past the count.
        let der = conforming_with_sans(&[EXPECTED, EXPECTED], &[]);
        assert!(!svid_id_matches(&der, EXPECTED));
        assert!(!svid_id_allowed(&der, &[]));
    }

    #[test]
    fn a_path_is_matched_case_sensitively() {
        // The path case is preserved, so it distinguishes two workloads.
        let der = conforming("spiffe://grid.internal/Signals");
        assert!(
            svid_id_matches(&der, "spiffe://grid.internal/Signals"),
            "exact path matches"
        );
        assert!(
            !svid_id_matches(&der, "spiffe://grid.internal/signals"),
            "a different path case is a different workload"
        );
    }

    #[test]
    fn allowed_accepts_a_listed_id() {
        let allow: [Arc<str>; 2] = [Arc::from("spiffe://grid.internal/other"), Arc::from(EXPECTED)];
        assert!(svid_id_allowed(&conforming(EXPECTED), &allow));
    }

    #[test]
    fn allowed_rejects_an_unlisted_id() {
        let allow: [Arc<str>; 1] = [Arc::from("spiffe://grid.internal/other")];
        assert!(
            !svid_id_allowed(&conforming(EXPECTED), &allow),
            "an id not in the allowlist is rejected"
        );
    }

    #[test]
    fn allowed_rejects_an_invalid_leaf_even_when_listed() {
        // A CA-flagged leaf is not a valid SVID, so membership cannot rescue it.
        let der = leaf(&[EXPECTED], &[KeyUsagePurpose::DigitalSignature], &[], true);
        let allow: [Arc<str>; 1] = [Arc::from(EXPECTED)];
        assert!(!svid_id_allowed(&der, &allow));
    }

    #[test]
    fn authorize_peer_reports_invalid_leaf() {
        // A non-SVID leaf is InvalidLeaf, distinct from an allowlist miss.
        let der = leaf(&[EXPECTED], &[], &[], false); // no keyUsage
        assert!(matches!(authorize_peer(&der, &[]), PeerAuth::InvalidLeaf));
    }

    #[test]
    fn authorize_peer_reports_not_allowed_with_the_id() {
        let allow: [Arc<str>; 1] = [Arc::from("spiffe://grid.internal/other")];
        let auth = authorize_peer(&conforming(EXPECTED), &allow);
        assert!(
            matches!(&auth, PeerAuth::NotAllowed(id) if id == EXPECTED),
            "expected NotAllowed({EXPECTED}), got {auth:?}"
        );
    }

    #[test]
    fn authorize_peer_reports_allowed_for_a_listed_conforming_svid() {
        assert!(matches!(
            authorize_peer(&conforming(EXPECTED), &[Arc::from(EXPECTED)]),
            PeerAuth::Allowed
        ));
    }

    #[test]
    fn a_garbage_der_is_invalid_leaf() {
        assert!(matches!(
            authorize_peer(b"not a certificate", &[]),
            PeerAuth::InvalidLeaf
        ));
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// A self-signed leaf with the given URI SANs, key usages, extended key usages,
    /// and cA flag. Empty `key_usages` / `ekus` omit that extension entirely.
    fn leaf(uris: &[&str], key_usages: &[KeyUsagePurpose], ekus: &[ExtendedKeyUsagePurpose], ca: bool) -> Vec<u8> {
        let key = KeyPair::generate().expect("key");
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
        params.distinguished_name.push(DnType::CommonName, "peer");
        for uri in uris {
            params
                .subject_alt_names
                .push(SanType::URI((*uri).try_into().expect("uri san")));
        }
        if ca {
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        }
        params.key_usages = key_usages.to_vec();
        params.extended_key_usages = ekus.to_vec();
        params.self_signed(&key).expect("self signed").der().to_vec()
    }

    /// A conforming X.509-SVID leaf: critical keyUsage with digitalSignature, EKU
    /// with serverAuth and clientAuth, no basicConstraints (cA false by default).
    fn conforming(uri: &str) -> Vec<u8> {
        leaf(
            &[uri],
            &[KeyUsagePurpose::DigitalSignature],
            &[ExtendedKeyUsagePurpose::ServerAuth, ExtendedKeyUsagePurpose::ClientAuth],
            false,
        )
    }

    /// A conforming leaf carrying the given URI and DNS SANs, to exercise SAN-shape
    /// cases (extra, missing, or duplicated names).
    fn conforming_with_sans(uris: &[&str], dns: &[&str]) -> Vec<u8> {
        let key = KeyPair::generate().expect("key");
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
        params.distinguished_name.push(DnType::CommonName, "peer");
        for uri in uris {
            params
                .subject_alt_names
                .push(SanType::URI((*uri).try_into().expect("uri san")));
        }
        for dns_name in dns {
            params
                .subject_alt_names
                .push(SanType::DnsName((*dns_name).try_into().expect("dns san")));
        }
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth, ExtendedKeyUsagePurpose::ClientAuth];
        params.self_signed(&key).expect("self signed").der().to_vec()
    }

    /// A leaf carrying a raw extension (OID 2.5.29.x content) plus a conforming
    /// keyUsage, to exercise one malformed or non-standard extension in isolation.
    fn leaf_with_custom_ext(uri: &str, ext: CustomExtension, with_key_usage: bool) -> Vec<u8> {
        let key = KeyPair::generate().expect("key");
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
        params.distinguished_name.push(DnType::CommonName, "peer");
        params
            .subject_alt_names
            .push(SanType::URI(uri.try_into().expect("uri")));
        if with_key_usage {
            params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        }
        params.custom_extensions.push(ext);
        params.self_signed(&key).expect("self signed").der().to_vec()
    }

    /// A present-but-unparseable basicConstraints (a bare NULL where a SEQUENCE
    /// belongs). rcgen cannot emit this, so it is hand-built.
    fn malformed_basic_constraints(critical: bool) -> CustomExtension {
        let mut bc = CustomExtension::from_oid_content(&[2, 5, 29, 19], vec![0x05, 0x00]);
        bc.set_criticality(critical);
        bc
    }

    /// A non-critical keyUsage with digitalSignature (BIT STRING 03 02 07 80). The
    /// standard requires keyUsage be critical, so this must be rejected.
    fn noncritical_key_usage() -> CustomExtension {
        let mut ku = CustomExtension::from_oid_content(&[2, 5, 29, 15], vec![0x03, 0x02, 0x07, 0x80]);
        ku.set_criticality(false);
        ku
    }

    /// Test-only bool wrapper over [`authorize_peer`] for the leaf-validation cases.
    fn svid_id_allowed(leaf_der: &[u8], allowed: &[Arc<str>]) -> bool {
        matches!(authorize_peer(leaf_der, allowed), PeerAuth::Allowed)
    }

    // -------------------------------------------------------------------------
    // Integration Tests: Full mTLS Handshakes
    // -------------------------------------------------------------------------

    /// Functional mTLS handshake tests for `RequireNamed` (X.509-SVID) listeners.
    ///
    /// Drives a real rustls handshake against a `ServerConfig` built the production
    /// way, from YAML through [`crate::ListenerTls`] and
    /// [`crate::setup::build_server_config`], and asserts that the SPIFFE
    /// allowlist admits or rejects a peer at the handshake, before any request.
    #[cfg(feature = "spiffe")]
    mod handshake_integration {
        use rcgen::Issuer;
        use rustls::{
            ClientConfig, ClientConnection, RootCertStore, ServerConnection,
            pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject as _},
        };

        use super::*;
        use crate::{ListenerTls, setup::build_server_config};

        /// A SPIFFE ID present in the server's trust allowlist.
        const ALLOWED_ID: &str = "spiffe://grid.internal/signals";

        /// A SPIFFE ID the server does not allowlist.
        const OTHER_ID: &str = "spiffe://grid.internal/other";

        #[test]
        fn an_allowlisted_svid_completes_the_handshake() {
            let pki = TestPki::new();
            let server = server_config(&pki, &[ALLOWED_ID]);
            let client = client_config(&pki, Some(pki.mint_client(ALLOWED_ID, true)));
            handshake(server, client).expect("an allowlisted SVID should complete the handshake");
        }

        #[test]
        fn an_empty_allowlist_admits_any_conforming_svid() {
            let pki = TestPki::new();
            let server = server_config(&pki, &[]);
            let client = client_config(&pki, Some(pki.mint_client(OTHER_ID, true)));
            handshake(server, client).expect("an empty allowlist admits any valid SVID the CA signs");
        }

        #[test]
        fn an_unlisted_svid_fails_the_handshake() {
            let pki = TestPki::new();
            let server = server_config(&pki, &[ALLOWED_ID]);
            let client = client_config(&pki, Some(pki.mint_client(OTHER_ID, true)));
            let err = handshake(server, client).expect_err("an unlisted SVID must be rejected");
            assert!(matches!(err, rustls::Error::InvalidCertificate(_)), "got {err:?}");
        }

        #[test]
        fn a_non_conforming_leaf_fails_the_handshake() {
            let pki = TestPki::new();
            let server = server_config(&pki, &[ALLOWED_ID]);
            let client = client_config(&pki, Some(pki.mint_client(ALLOWED_ID, false)));
            let err = handshake(server, client).expect_err("a non-conforming leaf (no keyUsage/EKU) must be rejected");
            assert!(matches!(err, rustls::Error::InvalidCertificate(_)), "got {err:?}");
        }

        #[test]
        fn a_missing_client_certificate_fails_the_handshake() {
            let pki = TestPki::new();
            let server = server_config(&pki, &[ALLOWED_ID]);
            let client = client_config(&pki, None);
            handshake(server, client).expect_err("require_named must reject a peer with no certificate");
        }

        /// Install the process-default provider. Idempotent.
        fn install_provider() {
            crate::provider::install();
        }

        /// A test CA that signs the server certificate and mints client SVID leaves.
        struct TestPki {
            ca_pem: String,
            issuer: Issuer<'static, KeyPair>,
            server_key_pem: String,
            server_pem: String,
        }

        impl TestPki {
            fn new() -> Self {
                let ca_key = KeyPair::generate().expect("test CA key generation must succeed");
                let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("test CA params must be valid");
                ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
                ca_params.distinguished_name.push(DnType::CommonName, "grid test CA");
                let ca_cert = ca_params
                    .self_signed(&ca_key)
                    .expect("test CA self-signing must succeed");
                let ca_pem = ca_cert.pem();
                let issuer = Issuer::new(ca_params, ca_key);

                let server_key = KeyPair::generate().expect("test server key generation must succeed");
                let mut server_params =
                    CertificateParams::new(vec!["localhost".to_owned()]).expect("test server params must be valid");
                server_params.distinguished_name.push(DnType::CommonName, "localhost");
                let server_cert = server_params
                    .signed_by(&server_key, &issuer)
                    .expect("test server cert signing must succeed");

                Self {
                    ca_pem,
                    issuer,
                    server_key_pem: server_key.serialize_pem(),
                    server_pem: server_cert.pem(),
                }
            }

            /// Mint a client leaf signed by the CA with the given URI SAN. A conforming
            /// SVID carries a critical keyUsage with digitalSignature and an EKU with both
            /// serverAuth and clientAuth.
            fn mint_client(
                &self,
                uri: &str,
                conforming: bool,
            ) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
                let key = KeyPair::generate().expect("test client key generation must succeed");
                let mut params =
                    CertificateParams::new(Vec::<String>::new()).expect("test client params must be valid");
                params.distinguished_name.push(DnType::CommonName, "peer");
                params
                    .subject_alt_names
                    .push(SanType::URI(uri.try_into().expect("test URI must be valid")));
                if conforming {
                    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
                    params.extended_key_usages =
                        vec![ExtendedKeyUsagePurpose::ServerAuth, ExtendedKeyUsagePurpose::ClientAuth];
                }
                let cert = params
                    .signed_by(&key, &self.issuer)
                    .expect("test client cert signing must succeed");
                let chain = vec![cert.der().clone()];
                let key_der = PrivateKeyDer::Pkcs8(key.serialize_der().into());
                (chain, key_der)
            }
        }

        /// Write the PKI to disk and build a production `ServerConfig` from YAML with
        /// `require_named` and the given allowlist.
        fn server_config(pki: &TestPki, allowlist: &[&str]) -> Arc<rustls::ServerConfig> {
            install_provider();
            let dir = tempfile::TempDir::new().expect("test temp dir must be created");
            let ca = dir.path().join("ca.pem");
            let cert = dir.path().join("server.pem");
            let key = dir.path().join("server-key.pem");
            std::fs::write(&ca, &pki.ca_pem).expect("test CA write must succeed");
            std::fs::write(&cert, &pki.server_pem).expect("test cert write must succeed");
            std::fs::write(&key, &pki.server_key_pem).expect("test key write must succeed");

            let ids = allowlist
                .iter()
                .map(|id| format!("      - {id}"))
                .collect::<Vec<_>>()
                .join("\n");
            let yaml = format!(
                "certificates:\n  - cert_path: {cert}\n    key_path: {key}\nclient_ca:\n  ca_path: {ca}\n\
                 client_cert_mode: require_named\ntrusted_spiffe_ids:\n{ids}\nhot_reload: false\n",
                cert = cert.display(),
                key = key.display(),
                ca = ca.display(),
            );
            let tls: ListenerTls = serde_yaml::from_str(&yaml).expect("valid require_named listener config");
            // build_server_config reads the cert, key, and CA eagerly, so the temp dir may drop.
            build_server_config(&tls, false).expect("build server config")
        }

        /// A client config trusting the test CA, optionally presenting a client leaf.
        fn client_config(
            pki: &TestPki,
            identity: Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>,
        ) -> Arc<ClientConfig> {
            install_provider();
            let mut roots = RootCertStore::empty();
            roots
                .add(CertificateDer::from_pem_slice(pki.ca_pem.as_bytes()).expect("test CA PEM must parse"))
                .expect("test CA must be added to root store");
            let provider = Arc::new(rustls_openssl::default_provider());
            let builder = ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .expect("test protocol versions must be valid")
                .with_root_certificates(roots);
            let config = match identity {
                Some((chain, key)) => builder
                    .with_client_auth_cert(chain, key)
                    .expect("test client auth cert must be valid"),
                None => builder.with_no_client_auth(),
            };
            Arc::new(config)
        }

        /// Drive an in-memory handshake to completion or error. `Ok` means both sides
        /// finished; `Err` is the rustls error that ended it (an mTLS rejection).
        #[allow(
            clippy::panic,
            reason = "panic signals test infrastructure failure, not handshake failure"
        )]
        fn handshake(
            server_cfg: Arc<rustls::ServerConfig>,
            client_cfg: Arc<ClientConfig>,
        ) -> Result<(), rustls::Error> {
            let mut server = ServerConnection::new(server_cfg).expect("test server connection must be created");
            let mut client = ClientConnection::new(
                client_cfg,
                ServerName::try_from("localhost").expect("test server name must be valid"),
            )
            .expect("test client connection must be created");

            for _ in 0..32 {
                let mut c2s = Vec::new();
                while client.wants_write() {
                    client.write_tls(&mut c2s).expect("test TLS write must succeed");
                }
                let mut c2s_rd: &[u8] = &c2s;
                while !c2s_rd.is_empty() {
                    server.read_tls(&mut c2s_rd).expect("test TLS read must succeed");
                }
                server.process_new_packets()?;

                let mut s2c = Vec::new();
                while server.wants_write() {
                    server.write_tls(&mut s2c).expect("test TLS write must succeed");
                }
                let mut s2c_rd: &[u8] = &s2c;
                while !s2c_rd.is_empty() {
                    client.read_tls(&mut s2c_rd).expect("test TLS read must succeed");
                }
                client.process_new_packets()?;

                if !client.is_handshaking() && !server.is_handshaking() {
                    return Ok(());
                }
            }
            panic!("handshake did not settle within the round budget");
        }
    }
}
