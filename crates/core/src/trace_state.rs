// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Shared W3C `tracestate` validation and normalization.

/// Maximum `list-member`s in a W3C `tracestate` header.
const MAX_TRACESTATE_MEMBERS: usize = 32;

/// Combined `tracestate` size vendors SHOULD propagate.
const MAX_TRACESTATE_LEN: usize = 512;

/// Parse and normalize a W3C `tracestate` list-member string.
///
/// Empty list members are ignored, optional whitespace is accepted around
/// members and `=`, duplicate keys and malformed members are rejected, and
/// right-most members are omitted when the serialized state would exceed 512
/// bytes. Returns `None` when the input is invalid or contains no members.
#[must_use]
pub fn parse_tracestate(combined: &str) -> Option<String> {
    let mut members: Vec<(&str, &str)> = Vec::new();
    for member in combined.split(',') {
        let member = trim_ows(member);
        if member.is_empty() {
            continue;
        }
        let (key, value) = member.split_once('=')?;
        let key = trim_ows(key);
        let value = trim_ows(value);
        if !is_valid_tracestate_key(key) || !is_valid_tracestate_value(value) {
            return None;
        }
        if members.iter().any(|(existing, _)| *existing == key) {
            return None;
        }
        members.push((key, value));
        if members.len() > MAX_TRACESTATE_MEMBERS {
            return None;
        }
    }
    serialize_tracestate(&members)
}

/// Serialize validated members, dropping right-most entries to stay within 512 bytes.
fn serialize_tracestate(members: &[(&str, &str)]) -> Option<String> {
    let mut serialized = String::new();
    for &(key, value) in members {
        let extra = if serialized.is_empty() { 0 } else { 1 };
        let candidate = serialized
            .len()
            .saturating_add(extra)
            .saturating_add(key.len())
            .saturating_add(1)
            .saturating_add(value.len());
        if candidate > MAX_TRACESTATE_LEN {
            break;
        }
        if !serialized.is_empty() {
            serialized.push(',');
        }
        serialized.push_str(key);
        serialized.push('=');
        serialized.push_str(value);
    }
    (!serialized.is_empty()).then_some(serialized)
}

/// Strip W3C OWS (`SP` / `HTAB`) from both ends of `value`.
fn trim_ows(value: &str) -> &str {
    value.trim_matches([' ', '\t'])
}

/// W3C Trace Context Level 2 `simple-key` / `tenant-key`.
fn is_valid_tracestate_key(key: &str) -> bool {
    match key.split_once('@') {
        None => is_simple_tracestate_key(key),
        Some((tenant_id, system_id)) => !system_id.contains('@') && is_tenant_id(tenant_id) && is_system_id(system_id),
    }
}

/// `simple-key = lcalpha 0*255(lcalpha / DIGIT / "_" / "-" / "*" / "/")`.
fn is_simple_tracestate_key(key: &str) -> bool {
    let len = key.len();
    if len == 0 || len > 256 {
        return false;
    }
    let mut bytes = key.bytes();
    bytes.next().is_some_and(is_lcalpha) && bytes.all(is_simple_keychar)
}

/// `tenant-id = (lcalpha / DIGIT) 0*240(lcalpha / DIGIT / "_" / "-" / "*" / "/")`.
fn is_tenant_id(id: &str) -> bool {
    let len = id.len();
    if len == 0 || len > 241 {
        return false;
    }
    let mut bytes = id.bytes();
    bytes
        .next()
        .is_some_and(|byte| is_lcalpha(byte) || byte.is_ascii_digit())
        && bytes.all(is_simple_keychar)
}

/// `system-id = lcalpha 0*13(lcalpha / DIGIT / "_" / "-" / "*" / "/")`.
fn is_system_id(id: &str) -> bool {
    let len = id.len();
    if len == 0 || len > 14 {
        return false;
    }
    let mut bytes = id.bytes();
    bytes.next().is_some_and(is_lcalpha) && bytes.all(is_simple_keychar)
}

/// Subsequent `simple-key` / tenant / system identifier characters.
fn is_simple_keychar(byte: u8) -> bool {
    is_lcalpha(byte) || byte.is_ascii_digit() || matches!(byte, b'_' | b'-' | b'*' | b'/')
}

/// ASCII lowercase letter.
fn is_lcalpha(byte: u8) -> bool {
    byte.is_ascii_lowercase()
}

/// W3C `tracestate` value: up to 256 printable ASCII chars except `,` / `=`, not ending in space.
fn is_valid_tracestate_value(value: &str) -> bool {
    let len = value.len();
    if len == 0 || len > 256 {
        return false;
    }
    value.bytes().all(is_tracestate_value_byte) && !value.ends_with(' ')
}

/// Printable ASCII except comma and equals.
fn is_tracestate_value_byte(byte: u8) -> bool {
    (0x20..=0x7E).contains(&byte) && byte != b',' && byte != b'='
}
