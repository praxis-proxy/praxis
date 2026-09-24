// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

#![forbid(unsafe_code)]

//! Criterion benchmarks for TLS SNI parsing.
//!
//! Covers `ClientHello` SNI extraction as the extension count grows, with
//! SNI first and last, and the fast-reject error paths. Certificate lookup
//! is in `tls_cert_resolution`.

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

/// Benchmark SNI parsing as the number of other extensions grows.
///
/// The parser walks the whole extension block to reject duplicates, so its
/// cost follows the extension count, not the padding size or the SNI
/// position; the sweeps vary the count with SNI first and last.
fn bench_sni_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("sni_parse");

    for &count in &[4, 16, 64] {
        let sni_first = make_client_hello(Some("api.example.com"), 0, count);
        assert_eq!(
            praxis_tls::sni::parse_sni(&sni_first).unwrap().sni.as_deref(),
            Some("api.example.com"),
            "the sni_first fixture must parse to its hostname"
        );
        group.bench_with_input(BenchmarkId::new("sni_first", count), &sni_first, |b, hello| {
            b.iter(|| black_box(praxis_tls::sni::parse_sni(black_box(hello)).unwrap()));
        });

        let sni_last = make_client_hello(Some("backend.example.com"), count, 0);
        assert_eq!(
            praxis_tls::sni::parse_sni(&sni_last).unwrap().sni.as_deref(),
            Some("backend.example.com"),
            "the sni_last fixture must parse to its hostname"
        );
        group.bench_with_input(BenchmarkId::new("sni_last", count), &sni_last, |b, hello| {
            b.iter(|| black_box(praxis_tls::sni::parse_sni(black_box(hello)).unwrap()));
        });
    }

    let hello_no_sni = make_client_hello(None, 16, 0);
    assert_eq!(
        praxis_tls::sni::parse_sni(&hello_no_sni).unwrap().sni,
        None,
        "the no_sni fixture must parse without a hostname"
    );
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

    // Malformed SNI extension (server_name_list overruns the extension)
    group.bench_function("malformed_sni", |b| {
        let buf = make_malformed_sni_hello();
        assert_eq!(
            praxis_tls::sni::parse_sni(&buf).unwrap_err(),
            praxis_tls::sni::SniParseError::MalformedExtension,
            "the fixture must reach the SNI extension parser, not fail at the record layer"
        );
        b.iter(|| black_box(praxis_tls::sni::parse_sni(black_box(&buf)).unwrap_err()));
    });

    group.finish();
}

// -----------------------------------------------------------------------------
// ClientHello Construction
// -----------------------------------------------------------------------------

/// Build a TLS 1.3 `ClientHello` with `before` filler extensions, the SNI
/// extension for `hostname` (if any), then `after` filler extensions.
fn make_client_hello(hostname: Option<&str>, before: usize, after: usize) -> Vec<u8> {
    let mut buf = Vec::new();

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
    append_filler_extensions(&mut buf, 0, before);
    if let Some(hostname) = hostname {
        append_sni_extension(&mut buf, hostname);
    }
    append_filler_extensions(&mut buf, before, after);

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

/// Append `count` small extensions with distinct private-use types
/// (0xFF00 + index, starting at `first`), since RFC 8446 forbids repeats.
fn append_filler_extensions(buf: &mut Vec<u8>, first: usize, count: usize) {
    for index in first..first + count {
        buf.extend_from_slice(&[0xFF, index as u8, 0, 4, 0, 0, 0, 0]);
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

/// Build a `ClientHello` whose outer lengths are consistent but whose
/// `server_name_list` claims more bytes than the SNI extension holds.
fn make_malformed_sni_hello() -> Vec<u8> {
    let mut buf = Vec::new();
    // TLS record header
    buf.extend_from_slice(&[22, 3, 3, 0, 58]);
    // Handshake header: ClientHello
    buf.push(1);
    buf.extend_from_slice(&[0, 0, 54]);
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
    buf.extend_from_slice(&[0, 11]);
    // SNI extension of 7 bytes whose server_name_list claims 8
    buf.extend_from_slice(&[0, 0, 0, 7, 0, 8, 0, 0, 6, 65, 66]);
    buf
}
