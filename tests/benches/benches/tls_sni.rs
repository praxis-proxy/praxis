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
    clippy::too_many_lines,
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    reason = "benchmarks"
)]

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Record content type of a handshake record.
const CONTENT_TYPE_HANDSHAKE: u8 = 22; // ContentType.handshake

/// Record content type of an application data record.
const CONTENT_TYPE_APPLICATION_DATA: u8 = 23; // ContentType.application_data

/// The legacy version that TLS 1.3 records and hellos carry.
const LEGACY_VERSION: [u8; 2] = [3, 3]; // TLS 1.2 (0x0303)

/// Handshake message type of a `ClientHello`.
const HANDSHAKE_CLIENT_HELLO: u8 = 1; // HandshakeType.client_hello

/// Handshake message type of a `ServerHello`.
const HANDSHAKE_SERVER_HELLO: u8 = 2; // HandshakeType.server_hello

/// The hello random; the parser never reads it.
const RANDOM: [u8; 32] = [0; 32];

/// An empty legacy session id: its one-byte length, zero.
const EMPTY_SESSION_ID: u8 = 0;

/// The one cipher suite the fixtures carry.
const TLS_AES_128_GCM_SHA256: [u8; 2] = [0x13, 0x01];

/// The null compression method.
const COMPRESSION_NULL: u8 = 0;

/// The compression methods a `ClientHello` offers: a one-byte length, then
/// the null method.
const COMPRESSION_METHODS: [u8; 2] = [1, COMPRESSION_NULL]; // one method: null

/// Extension type of `server_name`.
const EXTENSION_SERVER_NAME: [u8; 2] = [0, 0]; // ExtensionType.server_name

/// Server name type of a DNS host name.
const NAME_TYPE_HOST_NAME: u8 = 0; // NameType.host_name

/// First byte of the private-use extension types the filler extensions take.
const PRIVATE_USE_EXTENSION: u8 = 0xFF; // types 0xFF00 to 0xFFFF

/// The data of a filler extension.
const FILLER_EXTENSION_DATA: [u8; 4] = [0; 4];

/// A `supported_versions` extension selecting TLS 1.3, as a `ServerHello`
/// carries it.
const SUPPORTED_VERSIONS_TLS13: [u8; 6] = [0, 43, 0, 2, 3, 4]; // type 43, length 2, 0x0304

/// A `server_name` extension of 7 bytes whose `server_name_list` claims 8, so
/// the list overruns the extension. Its one entry, a host name, claims 6
/// bytes and holds "AB".
const OVERRUNNING_SNI_EXTENSION: [u8; 11] = [0, 0, 0, 7, 0, 8, 0, 0, 6, b'A', b'B'];

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

    group.bench_function("too_short", |b| {
        let buf = [&[CONTENT_TYPE_HANDSHAKE][..], &LEGACY_VERSION].concat();
        b.iter(|| black_box(praxis_tls::sni::parse_sni(black_box(&buf)).unwrap_err()));
    });

    group.bench_function("not_handshake", |b| {
        let buf = record(CONTENT_TYPE_APPLICATION_DATA, &[0; 10]);
        b.iter(|| black_box(praxis_tls::sni::parse_sni(black_box(&buf)).unwrap_err()));
    });

    group.bench_function("not_client_hello", |b| {
        let buf = make_server_hello();
        b.iter(|| black_box(praxis_tls::sni::parse_sni(black_box(&buf)).unwrap_err()));
    });

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
    let mut extensions = Vec::new();
    append_filler_extensions(&mut extensions, 0, before);
    if let Some(hostname) = hostname {
        append_sni_extension(&mut extensions, hostname);
    }
    append_filler_extensions(&mut extensions, before, after);

    client_hello(&extensions)
}

/// Build a `ClientHello` record around an extension block.
fn client_hello(extensions: &[u8]) -> Vec<u8> {
    let mut body = LEGACY_VERSION.to_vec();
    body.extend_from_slice(&RANDOM);
    body.push(EMPTY_SESSION_ID);
    append_u16_prefixed(&mut body, &TLS_AES_128_GCM_SHA256);
    body.extend_from_slice(&COMPRESSION_METHODS);
    append_u16_prefixed(&mut body, extensions);

    handshake_record(HANDSHAKE_CLIENT_HELLO, &body)
}

/// Append an SNI extension with the given hostname.
fn append_sni_extension(buf: &mut Vec<u8>, hostname: &str) {
    let mut entry = vec![NAME_TYPE_HOST_NAME];
    append_u16_prefixed(&mut entry, hostname.as_bytes());
    let mut server_name_list = Vec::new();
    append_u16_prefixed(&mut server_name_list, &entry);

    buf.extend_from_slice(&EXTENSION_SERVER_NAME);
    append_u16_prefixed(buf, &server_name_list);
}

/// Append `count` small extensions with distinct private-use types
/// (0xFF00 + index, starting at `first`), since RFC 8446 forbids repeats.
fn append_filler_extensions(buf: &mut Vec<u8>, first: usize, count: usize) {
    for index in first..first + count {
        buf.extend_from_slice(&[PRIVATE_USE_EXTENSION, index as u8]);
        append_u16_prefixed(buf, &FILLER_EXTENSION_DATA);
    }
}

/// Build a `ServerHello` for the error path bench.
fn make_server_hello() -> Vec<u8> {
    let mut body = LEGACY_VERSION.to_vec();
    body.extend_from_slice(&RANDOM);
    body.push(EMPTY_SESSION_ID);
    body.extend_from_slice(&TLS_AES_128_GCM_SHA256);
    body.push(COMPRESSION_NULL);
    append_u16_prefixed(&mut body, &SUPPORTED_VERSIONS_TLS13);

    handshake_record(HANDSHAKE_SERVER_HELLO, &body)
}

/// Build a `ClientHello` whose outer lengths are consistent but whose
/// `server_name_list` claims more bytes than the SNI extension holds.
fn make_malformed_sni_hello() -> Vec<u8> {
    client_hello(&OVERRUNNING_SNI_EXTENSION)
}

/// Wrap a handshake message body in its handshake header (type and
/// three-byte length) and a handshake record.
fn handshake_record(handshake_type: u8, body: &[u8]) -> Vec<u8> {
    let [_, high, middle, low] = u32::try_from(body.len()).unwrap().to_be_bytes();
    let mut message = vec![handshake_type, high, middle, low];
    message.extend_from_slice(body);

    record(CONTENT_TYPE_HANDSHAKE, &message)
}

/// A TLS record of `content_type` carrying `fragment`.
fn record(content_type: u8, fragment: &[u8]) -> Vec<u8> {
    let mut buf = vec![content_type];
    buf.extend_from_slice(&LEGACY_VERSION);
    append_u16_prefixed(&mut buf, fragment);
    buf
}

/// Append `bytes` after their length as a big-endian `u16`.
fn append_u16_prefixed(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&u16::try_from(bytes.len()).unwrap().to_be_bytes());
    buf.extend_from_slice(bytes);
}
