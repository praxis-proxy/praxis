// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Fast JSON structural skipping (memchr strings, recursive container walk).

use bytes::Bytes;
use memchr::memchr2;

use super::error::{JsonError, MAX_JSON_DEPTH};

// -----------------------------------------------------------------------------
// JSON string encoding
// -----------------------------------------------------------------------------

/// Encode `s` as a JSON string token (quotes + escapes).
pub(super) fn encode_json_string(s: &str) -> Bytes {
    let mut out = Vec::with_capacity(s.len() + 2);
    out.push(b'"');
    for b in s.bytes() {
        match b {
            b'"' => out.extend_from_slice(br#"\""#),
            b'\\' => out.extend_from_slice(br"\\"),
            b'\n' => out.extend_from_slice(br"\n"),
            b'\r' => out.extend_from_slice(br"\r"),
            b'\t' => out.extend_from_slice(br"\t"),
            0x00..=0x1F => {
                out.push(b'\\');
                out.push(b'u');
                out.push(b'0');
                out.push(b'0');
                out.push(hex(b >> 4));
                out.push(hex(b & 0x0F));
            },
            _ => out.push(b),
        }
    }
    out.push(b'"');
    Bytes::from(out)
}

/// Map 0..=15 to a lowercase hex ASCII digit.
fn hex(digit: u8) -> u8 {
    match digit {
        0..=9 => digit + b'0',
        10..=15 => digit - 10 + b'a',
        _ => b'0',
    }
}

// -----------------------------------------------------------------------------
// Scanner primitives
// -----------------------------------------------------------------------------

/// Skip a UTF-8 BOM if present. Returns the start index of the JSON payload.
pub(super) fn skip_bom(input: &[u8]) -> usize {
    match input {
        [0xEF, 0xBB, 0xBF, ..] => 3,
        _ => 0,
    }
}

/// Advance past JSON insignificant whitespace (space, tab, LF, CR).
pub(super) fn skip_ws(input: &[u8], i: &mut usize) {
    while let Some(&b) = input.get(*i) {
        if !matches!(b, b' ' | b'\t' | b'\n' | b'\r') {
            break;
        }
        *i += 1;
    }
}

/// Next byte at `i`, or invalid JSON if past the end.
pub(super) fn next_byte(input: &[u8], i: usize) -> Result<u8, JsonError> {
    input.get(i).copied().ok_or(JsonError::InvalidJson)
}

/// Consume `expected` at `i`, or fail if the next byte differs.
pub(super) fn expect_byte(input: &[u8], i: &mut usize, expected: u8) -> Result<(), JsonError> {
    let b = next_byte(input, *i)?;
    if b != expected {
        return Err(JsonError::InvalidJson);
    }
    *i += 1;
    Ok(())
}

// -----------------------------------------------------------------------------
// String skip / parse
// -----------------------------------------------------------------------------

/// Skip a JSON string; returns whether escape sequences were present.
pub(super) fn skip_string_with_meta(input: &[u8], i: &mut usize) -> Result<bool, JsonError> {
    expect_byte(input, i, b'"')?;
    let mut escaped = false;
    loop {
        let tail = input.get(*i..).ok_or(JsonError::InvalidJson)?;
        let Some(rel_off) = memchr2(b'"', b'\\', tail) else {
            return Err(JsonError::InvalidJson);
        };
        *i += rel_off;
        let b = *input.get(*i).ok_or(JsonError::InvalidJson)?;
        if b == b'"' {
            *i += 1;
            return Ok(escaped);
        }
        escaped = true;
        *i += 1;
        let esc = next_byte(input, *i)?;
        *i += 1;
        if esc == b'u' {
            for _ in 0..4 {
                let h = next_byte(input, *i)?;
                if !h.is_ascii_hexdigit() {
                    return Err(JsonError::InvalidJson);
                }
                *i += 1;
            }
        }
    }
}

/// Skip a JSON string, including escapes.
pub(super) fn skip_string(input: &[u8], i: &mut usize) -> Result<(), JsonError> {
    skip_string_with_meta(input, i).map(|_| ())
}

// -----------------------------------------------------------------------------
// Value skip
// -----------------------------------------------------------------------------

/// Skip one JSON value without copying it.
///
/// Recursive tokenizer walk; faster than flat scanning on large unchanged spans
/// (e.g. multi-megabyte `messages` arrays in chat completion bodies).
pub(super) fn skip_value(input: &[u8], i: &mut usize, depth: u32) -> Result<(), JsonError> {
    skip_ws(input, i);
    match next_byte(input, *i)? {
        b'{' => skip_object(input, i, depth),
        b'[' => skip_array(input, i, depth),
        b'"' => skip_string(input, i),
        b't' => skip_literal(input, i, b"true"),
        b'f' => skip_literal(input, i, b"false"),
        b'n' => skip_literal(input, i, b"null"),
        b'-' | b'0'..=b'9' => skip_number(input, i),
        _ => Err(JsonError::InvalidJson),
    }
}

/// Skip an object `{...}` including nested values.
fn skip_object(input: &[u8], i: &mut usize, depth: u32) -> Result<(), JsonError> {
    let depth = bump_depth(depth)?;
    expect_byte(input, i, b'{')?;
    let mut seen_member = false;
    loop {
        skip_ws(input, i);
        if next_byte(input, *i)? == b'}' {
            *i += 1;
            return Ok(());
        }
        if seen_member {
            expect_byte(input, i, b',')?;
            skip_ws(input, i);
            if next_byte(input, *i)? == b'}' {
                return Err(JsonError::InvalidJson);
            }
        }
        skip_string(input, i)?;
        skip_ws(input, i);
        expect_byte(input, i, b':')?;
        skip_value(input, i, depth)?;
        seen_member = true;
    }
}

/// Skip an array `[...]` including nested values.
fn skip_array(input: &[u8], i: &mut usize, depth: u32) -> Result<(), JsonError> {
    let depth = bump_depth(depth)?;
    expect_byte(input, i, b'[')?;
    let mut seen_elem = false;
    loop {
        skip_ws(input, i);
        if next_byte(input, *i)? == b']' {
            *i += 1;
            return Ok(());
        }
        if seen_elem {
            expect_byte(input, i, b',')?;
            skip_ws(input, i);
            if next_byte(input, *i)? == b']' {
                return Err(JsonError::InvalidJson);
            }
        }
        skip_value(input, i, depth)?;
        seen_elem = true;
    }
}

/// Increment nesting; fail if [`MAX_JSON_DEPTH`] would be exceeded.
pub(super) fn bump_depth(depth: u32) -> Result<u32, JsonError> {
    let next = depth.saturating_add(1);
    if next > MAX_JSON_DEPTH {
        return Err(JsonError::Depth);
    }
    Ok(next)
}

/// Skip a JSON literal (`true`, `false`, or `null`).
pub(super) fn skip_literal(input: &[u8], i: &mut usize, lit: &[u8]) -> Result<(), JsonError> {
    let slice = input.get(*i..).ok_or(JsonError::InvalidJson)?;
    let prefix = slice.get(..lit.len()).ok_or(JsonError::InvalidJson)?;
    if prefix != lit {
        return Err(JsonError::InvalidJson);
    }
    *i += lit.len();
    Ok(())
}

/// Advance past consecutive ASCII digits.
fn skip_digits(input: &[u8], i: &mut usize) {
    while input.get(*i).copied().is_some_and(|b| b.is_ascii_digit()) {
        *i += 1;
    }
}

/// Skip a JSON number (integer, fraction, exponent).
pub(super) fn skip_number(input: &[u8], i: &mut usize) -> Result<(), JsonError> {
    let start = *i;
    if next_byte(input, *i)? == b'-' {
        *i += 1;
    }
    let first = next_byte(input, *i)?;
    if first == b'0' {
        *i += 1;
    } else if first.is_ascii_digit() {
        skip_digits(input, i);
    } else {
        return Err(JsonError::InvalidJson);
    }
    skip_number_frac_exp(input, i)?;
    if *i == start {
        return Err(JsonError::InvalidJson);
    }
    Ok(())
}

/// Skip optional fraction and exponent after the integer part of a number.
fn skip_number_frac_exp(input: &[u8], i: &mut usize) -> Result<(), JsonError> {
    if input.get(*i).copied() == Some(b'.') {
        *i += 1;
        if !input.get(*i).copied().is_some_and(|b| b.is_ascii_digit()) {
            return Err(JsonError::InvalidJson);
        }
        skip_digits(input, i);
    }
    if matches!(input.get(*i).copied(), Some(b'e' | b'E')) {
        *i += 1;
        if matches!(input.get(*i).copied(), Some(b'+' | b'-')) {
            *i += 1;
        }
        if !input.get(*i).copied().is_some_and(|b| b.is_ascii_digit()) {
            return Err(JsonError::InvalidJson);
        }
        skip_digits(input, i);
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::format_push_string,
    reason = "tests"
)]
mod tests {
    use super::*;

    #[test]
    fn skip_string_memchr_long_no_escapes() {
        let payload = format!("\"{}\"", "a".repeat(10_000));
        let input = payload.as_bytes();
        let mut i = 0;
        assert!(!skip_string_with_meta(input, &mut i).unwrap());
        assert_eq!(i, input.len());
    }

    #[test]
    fn skip_string_with_escape() {
        let input = br#""a\"b""#;
        let mut i = 0;
        assert!(skip_string_with_meta(input, &mut i).unwrap());
        assert_eq!(i, input.len());
    }

    #[test]
    fn skip_large_array() {
        let mut body = String::from("[");
        for n in 0..1000 {
            if n > 0 {
                body.push(',');
            }
            body.push_str(&format!(r#"{{"k":{n},"v":"x"}}"#));
        }
        body.push(']');
        let input = body.as_bytes();
        let mut i = 0;
        skip_value(input, &mut i, 0).unwrap();
        assert_eq!(i, input.len());
    }

    #[test]
    fn encode_json_string_escapes() {
        let encoded = encode_json_string("te\"nt\n");
        assert_eq!(encoded.as_ref(), br#""te\"nt\n""#);
    }
}
