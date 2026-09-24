// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

#![forbid(unsafe_code)]

//! Criterion benchmarks for TLS SNI parsing and certificate resolution.
//!
//! Covers `ClientHello` SNI extraction (varying sizes, SNI positions,
//! malformed inputs) and certificate lookup (exact hostname, wildcard
//! matching, fallback paths).

#![expect(
    clippy::arithmetic_side_effects,
    clippy::min_ident_chars,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    reason = "benchmarks"
)]

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};

// -----------------------------------------------------------------------------
// Benchmarks
// -----------------------------------------------------------------------------

criterion_group!(benches, bench_sni_parsing, bench_sni_parsing_errors);
criterion_main!(benches);

/// Benchmark SNI parsing with varying `ClientHello` sizes and SNI positions.
fn bench_sni_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("sni_parse");

    // Valid SNI at early position (minimal extensions)
    for &(label, size) in &[("128B", 128), ("512B", 512), ("4KiB", 4096), ("16KiB", 16384)] {
        let hello = make_client_hello(size, "api.example.com", ExtensionPosition::Early);
        group.bench_with_input(BenchmarkId::new("early_sni", label), &hello, |b, hello| {
            b.iter(|| black_box(praxis_tls::sni::parse_sni(black_box(hello)).unwrap()));
        });
    }

    // Valid SNI at mid position (some extensions before SNI)
    for &(label, size) in &[("512B", 512), ("4KiB", 4096)] {
        let hello = make_client_hello(size, "app.example.com", ExtensionPosition::Mid);
        group.bench_with_input(BenchmarkId::new("mid_sni", label), &hello, |b, hello| {
            b.iter(|| black_box(praxis_tls::sni::parse_sni(black_box(hello)).unwrap()));
        });
    }

    // Valid SNI at late position (many extensions before SNI)
    for &(label, size) in &[("4KiB", 4096), ("16KiB", 16384)] {
        let hello = make_client_hello(size, "backend.example.com", ExtensionPosition::Late);
        group.bench_with_input(BenchmarkId::new("late_sni", label), &hello, |b, hello| {
            b.iter(|| black_box(praxis_tls::sni::parse_sni(black_box(hello)).unwrap()));
        });
    }

    // Valid ClientHello without SNI extension (returns None)
    let hello_no_sni = make_client_hello(512, "", ExtensionPosition::NoSni);
    group.bench_function("no_sni", |b| {
        b.iter(|| black_box(praxis_tls::sni::parse_sni(black_box(&hello_no_sni)).unwrap()));
    });

    group.finish();
}

/// Benchmark SNI parsing error paths (fast-reject).
fn bench_sni_parsing_errors(c: &mut Criterion) {
    let mut group = c.benchmark_group("sni_parse_errors");

    // Too short (< 5 bytes)
    group.bench_function("too_short", |b| {
        let buf = vec![22, 3, 3];
        b.iter(|| black_box(praxis_tls::sni::parse_sni(black_box(&buf)).unwrap_err()));
    });

    // Not a handshake record (wrong ContentType)
    group.bench_function("not_handshake", |b| {
        let buf = vec![23, 3, 3, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        b.iter(|| black_box(praxis_tls::sni::parse_sni(black_box(&buf)).unwrap_err()));
    });

    // Not a ClientHello (wrong HandshakeType)
    group.bench_function("not_client_hello", |b| {
        let buf = make_server_hello();
        b.iter(|| black_box(praxis_tls::sni::parse_sni(black_box(&buf)).unwrap_err()));
    });

    // Malformed SNI extension (truncated)
    group.bench_function("malformed_sni", |b| {
        let buf = make_malformed_sni_hello();
        b.iter(|| black_box(praxis_tls::sni::parse_sni(black_box(&buf)).unwrap_err()));
    });

    group.finish();
}

// -----------------------------------------------------------------------------
// ClientHello Construction
// -----------------------------------------------------------------------------

/// Where the SNI extension appears in the extensions list.
#[derive(Clone, Copy)]
enum ExtensionPosition {
    /// SNI is the first extension.
    Early,
    /// SNI is after ~3 other extensions.
    Mid,
    /// SNI is after many filler extensions.
    Late,
    /// No SNI extension present.
    NoSni,
}

/// Build a minimal TLS 1.3 `ClientHello` with the SNI hostname at the given position.
///
/// The `target_size` is approximate; the actual size may vary by a few bytes due to
/// extension header overhead.
fn make_client_hello(target_size: usize, hostname: &str, position: ExtensionPosition) -> Vec<u8> {
    let mut buf = Vec::with_capacity(target_size.saturating_add(128));

    // TLS record header: ContentType(22) | Version(0x0303) | Length(u16)
    buf.push(22);
    buf.push(3);
    buf.push(3);
    let record_len_offset = buf.len();
    buf.extend_from_slice(&[0, 0]);

    // Handshake header: HandshakeType(1) | Length(u24)
    buf.push(1);
    let hs_len_offset = buf.len();
    buf.extend_from_slice(&[0, 0, 0]);

    // ClientHello fixed fields: Version(0x0303) | Random(32 bytes)
    buf.push(3);
    buf.push(3);
    buf.extend_from_slice(&[0_u8; 32]);

    // SessionID (length 0)
    buf.push(0);

    // CipherSuites (length 2, one suite: TLS_AES_128_GCM_SHA256)
    buf.extend_from_slice(&[0, 2, 0x13, 0x01]);

    // CompressionMethods (length 1, null compression)
    buf.extend_from_slice(&[1, 0]);

    // Extensions
    let extensions_len_offset = buf.len();
    buf.extend_from_slice(&[0, 0]);

    match position {
        ExtensionPosition::Early => {
            if !hostname.is_empty() {
                append_sni_extension(&mut buf, hostname);
            }
            let current_len = buf.len();
            append_filler_extensions(&mut buf, target_size.saturating_sub(current_len));
        },
        ExtensionPosition::Mid => {
            append_filler_extensions(&mut buf, 60);
            if !hostname.is_empty() {
                append_sni_extension(&mut buf, hostname);
            }
            let current_len = buf.len();
            append_filler_extensions(&mut buf, target_size.saturating_sub(current_len));
        },
        ExtensionPosition::Late => {
            let current_len = buf.len();
            let sni_size = hostname.len() + 20;
            append_filler_extensions(&mut buf, target_size.saturating_sub(current_len + sni_size));
            if !hostname.is_empty() {
                append_sni_extension(&mut buf, hostname);
            }
        },
        ExtensionPosition::NoSni => {
            let current_len = buf.len();
            append_filler_extensions(&mut buf, target_size.saturating_sub(current_len));
        },
    }

    // Patch extensions length
    let extensions_len = buf.len() - extensions_len_offset - 2;
    buf[extensions_len_offset] = ((extensions_len >> 8) & 0xFF) as u8;
    buf[extensions_len_offset + 1] = (extensions_len & 0xFF) as u8;

    // Patch handshake length (u24)
    let hs_len = buf.len() - hs_len_offset - 3;
    buf[hs_len_offset] = ((hs_len >> 16) & 0xFF) as u8;
    buf[hs_len_offset + 1] = ((hs_len >> 8) & 0xFF) as u8;
    buf[hs_len_offset + 2] = (hs_len & 0xFF) as u8;

    // Patch record length
    let record_len = buf.len() - record_len_offset - 2;
    buf[record_len_offset] = ((record_len >> 8) & 0xFF) as u8;
    buf[record_len_offset + 1] = (record_len & 0xFF) as u8;

    buf
}

/// Append an SNI extension with the given hostname.
fn append_sni_extension(buf: &mut Vec<u8>, hostname: &str) {
    // Extension type: server_name (0)
    buf.extend_from_slice(&[0, 0]);
    // Extension length (2 + 1 + 2 + hostname.len())
    let ext_len = 5 + hostname.len();
    buf.push(((ext_len >> 8) & 0xFF) as u8);
    buf.push((ext_len & 0xFF) as u8);
    // ServerNameList length
    let list_len = 3 + hostname.len();
    buf.push(((list_len >> 8) & 0xFF) as u8);
    buf.push((list_len & 0xFF) as u8);
    // NameType: host_name (0)
    buf.push(0);
    // Hostname length
    let name_len = hostname.len();
    buf.push(((name_len >> 8) & 0xFF) as u8);
    buf.push((name_len & 0xFF) as u8);
    // Hostname
    buf.extend_from_slice(hostname.as_bytes());
}

/// Append `supported_versions`, `supported_groups`, and padding extensions.
fn append_filler_extensions(buf: &mut Vec<u8>, min_bytes: usize) {
    let initial_len = buf.len();

    // supported_versions extension (8 bytes total)
    buf.extend_from_slice(&[0, 43, 0, 3, 2, 3, 4]);

    // supported_groups extension (10 bytes total)
    buf.extend_from_slice(&[0, 10, 0, 4, 0, 2, 0, 23]);

    // key_share extension (minimal, 40 bytes total)
    buf.extend_from_slice(&[
        0, 51, 0, 36, 0, 34, 0, 23, 0, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0,
    ]);

    // Pad with additional extension(s) if needed
    let added = buf.len() - initial_len;
    if added < min_bytes {
        let pad_len = min_bytes - added;
        // Use padding extension (type 21)
        buf.extend_from_slice(&[0, 21]);
        buf.push(((pad_len >> 8) & 0xFF) as u8);
        buf.push((pad_len & 0xFF) as u8);
        buf.resize(buf.len() + pad_len, 0);
    }
}

/// Build a `ServerHello` (HandshakeType=2) for the error path bench.
fn make_server_hello() -> Vec<u8> {
    let mut buf = Vec::new();
    // TLS record header
    buf.extend_from_slice(&[22, 3, 3, 0, 50]);
    // Handshake header: ServerHello (type 2)
    buf.push(2);
    buf.extend_from_slice(&[0, 0, 46]);
    // Version + Random
    buf.extend_from_slice(&[3, 3]);
    buf.extend_from_slice(&[0_u8; 32]);
    // SessionID length 0
    buf.push(0);
    // CipherSuite
    buf.extend_from_slice(&[0x13, 0x01]);
    // CompressionMethod
    buf.push(0);
    // Extensions length
    buf.extend_from_slice(&[0, 6]);
    // supported_versions extension
    buf.extend_from_slice(&[0, 43, 0, 2, 3, 4]);
    buf
}

/// Build a `ClientHello` with a malformed SNI extension (truncated hostname).
fn make_malformed_sni_hello() -> Vec<u8> {
    let mut buf = Vec::new();
    // TLS record header
    buf.extend_from_slice(&[22, 3, 3, 0, 60]);
    // Handshake header: ClientHello
    buf.push(1);
    buf.extend_from_slice(&[0, 0, 56]);
    // Version + Random
    buf.extend_from_slice(&[3, 3]);
    buf.extend_from_slice(&[0_u8; 32]);
    // SessionID length 0
    buf.push(0);
    // CipherSuites
    buf.extend_from_slice(&[0, 2, 0x13, 0x01]);
    // CompressionMethods
    buf.extend_from_slice(&[1, 0]);
    // Extensions length
    buf.extend_from_slice(&[0, 14]);
    // SNI extension with length mismatch (claims 10 bytes, provides 2)
    buf.extend_from_slice(&[0, 0, 0, 10, 0, 8, 0, 0, 6, 65, 66]);
    buf
}
