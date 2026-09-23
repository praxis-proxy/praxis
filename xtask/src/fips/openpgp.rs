// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Just enough OpenPGP (RFC 4880) to compute the fingerprint of a public key,
//! so the bundled Red Hat key can be checked against the fingerprint Red Hat
//! publishes without a gpg installation.

use base64::{Engine as _, prelude::BASE64_STANDARD};
use openssl::hash::{MessageDigest, hash};

/// The packet tag of a public key packet.
const PUBLIC_KEY_PACKET: u8 = 6;

/// Compute the v4 fingerprint (RFC 4880 section 12.2: SHA-1 over `0x99`, the
/// two-octet packet length and the packet body) of the first public key
/// packet in an ASCII-armored key block, as uppercase hex.
pub(crate) fn v4_fingerprint(armored: &str) -> Result<String, String> {
    let bytes = dearmor(armored)?;
    let (tag, body) = first_packet(&bytes)?;
    if tag != PUBLIC_KEY_PACKET {
        return Err(format!(
            "first packet is tag {tag}, expected a public key packet ({PUBLIC_KEY_PACKET})"
        ));
    }
    if body.first() != Some(&4) {
        return Err(format!("public key packet version {:?}, expected 4", body.first()));
    }
    let len = u16::try_from(body.len()).map_err(|err| format!("public key packet longer than 65535 bytes: {err}"))?;
    let mut hashed = vec![0x99];
    hashed.extend_from_slice(&len.to_be_bytes());
    hashed.extend_from_slice(body);
    let digest = hash(MessageDigest::sha1(), &hashed).map_err(|err| format!("sha1: {err}"))?;
    Ok(digest.iter().map(|byte| format!("{byte:02X}")).collect())
}

/// Decode the base64 payload of an armored block (RFC 4880 section 6.2):
/// everything between the armor headers and the CRC line.
fn dearmor(armored: &str) -> Result<Vec<u8>, String> {
    let mut lines = armored.lines().map(str::trim);
    lines
        .by_ref()
        .find(|line| line.starts_with("-----BEGIN PGP"))
        .ok_or("no armor header")?;
    let mut payload = String::new();
    let mut in_headers = true;
    for line in lines {
        // Armor headers are `Key: Value` lines; base64 never contains a colon.
        if in_headers && (line.is_empty() || line.contains(':')) {
            continue;
        }
        in_headers = false;
        if line.starts_with('=') || line.starts_with("-----END") {
            break;
        }
        payload.push_str(line);
    }
    BASE64_STANDARD
        .decode(payload)
        .map_err(|err| format!("armor payload is not base64: {err}"))
}

/// Split the first packet off an OpenPGP message: its tag and body.
fn first_packet(bytes: &[u8]) -> Result<(u8, &[u8]), String> {
    let &first = bytes.first().ok_or("empty key block")?;
    if first & 0x80 == 0 {
        return Err("not an OpenPGP packet".to_owned());
    }
    let (tag, header_len, body_len) = if first & 0x40 == 0 {
        old_format(first, bytes)?
    } else {
        new_format(first, bytes)?
    };
    let body = bytes
        .get(header_len..header_len + body_len)
        .ok_or("packet body is truncated")?;
    Ok((tag, body))
}

/// Old-format packet header (RFC 4880 section 4.2.1): the tag in bits 2-5
/// and the number of length octets in bits 0-1.
fn old_format(first: u8, bytes: &[u8]) -> Result<(u8, usize, usize), String> {
    let tag = (first >> 2) & 0x0F;
    let len_octets = match first & 0x03 {
        0 => 1,
        1 => 2,
        2 => 4,
        _ => return Err("indeterminate packet length".to_owned()),
    };
    let octets = bytes.get(1..1 + len_octets).ok_or("packet header is truncated")?;
    Ok((tag, 1 + len_octets, big_endian(octets)))
}

/// New-format packet header (RFC 4880 section 4.2.2): the tag in bits 0-5
/// and one, two or five length octets.
fn new_format(first: u8, bytes: &[u8]) -> Result<(u8, usize, usize), String> {
    let tag = first & 0x3F;
    let &second = bytes.get(1).ok_or("packet header is truncated")?;
    match second {
        0..=191 => Ok((tag, 2, usize::from(second))),
        192..=223 => {
            let &third = bytes.get(2).ok_or("packet header is truncated")?;
            Ok((tag, 3, ((usize::from(second) - 192) << 8) + usize::from(third) + 192))
        },
        255 => {
            let octets = bytes.get(2..6).ok_or("packet header is truncated")?;
            Ok((tag, 6, big_endian(octets)))
        },
        _ => Err("partial body lengths are not supported".to_owned()),
    }
}

/// A big-endian unsigned integer of up to four octets.
fn big_endian(octets: &[u8]) -> usize {
    octets.iter().fold(0, |acc, &octet| (acc << 8) | usize::from(octet))
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fips::assets;

    /// Wrap raw packet bytes in armor the way gpg would.
    fn armor(packet: &[u8]) -> String {
        format!(
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\nVersion: test\n\n{}\n=AAAA\n-----END PGP PUBLIC KEY BLOCK-----\n",
            BASE64_STANDARD.encode(packet)
        )
    }

    #[test]
    fn bundled_red_hat_key_has_the_published_fingerprint() {
        let fingerprint = v4_fingerprint(assets::REDHAT_RELEASE_KEY_2).expect("the bundled key parses");
        assert_eq!(
            fingerprint,
            assets::REDHAT_RELEASE_KEY_2_FINGERPRINT,
            "the bundled key must be Red Hat, Inc. (release key 2)"
        );
    }

    #[test]
    fn a_packet_that_is_not_a_public_key_is_rejected() {
        // Old format, tag 11 (literal data), one-octet length, one byte of body.
        let armored = armor(&[0x80 | (11 << 2), 1, 0x00]);
        let err = v4_fingerprint(&armored).expect_err("a literal data packet is not a key");
        assert!(err.contains("tag 11"), "the error names the tag: {err}");
    }

    #[test]
    fn a_key_that_is_not_version_4_is_rejected() {
        let armored = armor(&[0x80 | (PUBLIC_KEY_PACKET << 2), 2, 3, 0x00]);
        let err = v4_fingerprint(&armored).expect_err("a v3 key has no v4 fingerprint");
        assert!(err.contains("version Some(3)"), "the error names the version: {err}");
    }

    #[test]
    fn new_format_lengths_are_decoded() {
        // Two-octet length: 192 + 1 = 193 bytes of body.
        let mut packet = vec![0xC0 | PUBLIC_KEY_PACKET, 192, 1];
        packet.extend(std::iter::repeat_n(0x42, 193));
        let (tag, body) = first_packet(&packet).expect("a well-formed packet");
        assert_eq!(tag, PUBLIC_KEY_PACKET, "tag comes from the low six bits");
        assert_eq!(body.len(), 193, "two-octet new-format length");
    }

    #[test]
    fn truncated_and_garbage_input_is_rejected() {
        assert!(v4_fingerprint("hello").is_err(), "no armor header");
        assert!(
            v4_fingerprint(&armor(&[0x80 | (6 << 2), 5, 1])).is_err(),
            "body shorter than its length"
        );
        assert!(
            v4_fingerprint(&armor(&[0x00])).is_err(),
            "high bit clear is not a packet"
        );
    }
}
