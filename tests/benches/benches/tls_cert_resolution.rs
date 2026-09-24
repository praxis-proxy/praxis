// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Criterion benchmarks for TLS certificate resolution by SNI hostname.
//!
//! Covers exact hostname lookup, wildcard matching, case-insensitive
//! matching, and default certificate fallback paths with varying
//! certificate pool sizes.

#![expect(clippy::min_ident_chars, clippy::unwrap_used, reason = "benchmarks")]

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use praxis_tls::{CertKeyPair, setup::sni, test_utils::gen_test_certs};

// -----------------------------------------------------------------------------
// Benchmarks
// -----------------------------------------------------------------------------

criterion_group!(
    benches,
    bench_exact_hostname_lookup,
    bench_wildcard_lookup,
    bench_fallback_lookup,
    bench_case_insensitive_lookup
);
criterion_main!(benches);

/// Benchmark exact hostname lookup with varying pool sizes.
fn bench_exact_hostname_lookup(c: &mut Criterion) {
    let mut group = c.benchmark_group("cert_resolve/exact");

    for &(label, count) in &[("10", 10), ("100", 100), ("1000", 1000)] {
        let resolver = build_resolver_with_exact_hostnames(count);
        let target = format!("host-{}.example.com", count / 2);

        group.bench_with_input(
            BenchmarkId::from_parameter(label),
            &(resolver, target),
            |b, (resolver, target)| {
                b.iter(|| black_box(resolver.lookup(black_box(Some(target))).unwrap()));
            },
        );
    }

    group.finish();
}

/// Benchmark wildcard matching with varying pool sizes.
fn bench_wildcard_lookup(c: &mut Criterion) {
    let mut group = c.benchmark_group("cert_resolve/wildcard");

    for &(label, count) in &[("10", 10), ("100", 100), ("1000", 1000)] {
        let resolver = build_resolver_with_wildcards(count);
        let target = format!("app-{}.domain-{}.com", count / 2, count / 2);

        group.bench_with_input(
            BenchmarkId::from_parameter(label),
            &(resolver, target),
            |b, (resolver, target)| {
                b.iter(|| black_box(resolver.lookup(black_box(Some(target))).unwrap()));
            },
        );
    }

    // Wildcard miss path (multi-level subdomain should not match single-level wildcard)
    let resolver = build_resolver_with_wildcards(100);
    group.bench_function("miss_multi_level", |b| {
        b.iter(|| black_box(resolver.lookup(black_box(Some("a.b.domain-50.com"))).is_none()));
    });

    // Wildcard miss path (bare domain should not match wildcard)
    group.bench_function("miss_bare_domain", |b| {
        b.iter(|| black_box(resolver.lookup(black_box(Some("domain-50.com"))).is_none()));
    });

    group.finish();
}

/// Benchmark default certificate fallback paths.
fn bench_fallback_lookup(c: &mut Criterion) {
    let mut group = c.benchmark_group("cert_resolve/fallback");

    // Miss with default (returns default cert)
    let resolver = build_resolver_with_default(100);
    group.bench_function("default_hit", |b| {
        b.iter(|| black_box(resolver.lookup(black_box(Some("unknown.example.com"))).unwrap()));
    });

    // Miss without default (returns None)
    let resolver_no_default = build_resolver_with_exact_hostnames(100);
    group.bench_function("no_default_miss", |b| {
        b.iter(|| {
            black_box(
                resolver_no_default
                    .lookup(black_box(Some("unknown.example.com")))
                    .is_none(),
            )
        });
    });

    // No SNI with default (returns default cert)
    group.bench_function("no_sni_default", |b| {
        b.iter(|| black_box(resolver.lookup(black_box(None)).unwrap()));
    });

    // No SNI without default (returns None)
    let resolver_no_sni_no_default = build_resolver_with_exact_hostnames(100);
    group.bench_function("no_sni_no_default", |b| {
        b.iter(|| black_box(resolver_no_sni_no_default.lookup(black_box(None)).is_none()));
    });

    group.finish();
}

/// Benchmark case-insensitive hostname matching.
fn bench_case_insensitive_lookup(c: &mut Criterion) {
    let mut group = c.benchmark_group("cert_resolve/case");

    let resolver = build_resolver_with_exact_hostnames(100);

    // Lowercase SNI (common case, no copy)
    group.bench_function("lowercase", |b| {
        b.iter(|| black_box(resolver.lookup(black_box(Some("host-50.example.com"))).unwrap()));
    });

    // Mixed-case SNI (requires to_ascii_lowercase, triggers copy)
    group.bench_function("mixed_case", |b| {
        b.iter(|| black_box(resolver.lookup(black_box(Some("Host-50.Example.COM"))).unwrap()));
    });

    // Uppercase SNI (requires to_ascii_lowercase, triggers copy)
    group.bench_function("uppercase", |b| {
        b.iter(|| black_box(resolver.lookup(black_box(Some("HOST-50.EXAMPLE.COM"))).unwrap()));
    });

    group.finish();
}

// -----------------------------------------------------------------------------
// Resolver Construction
// -----------------------------------------------------------------------------

/// Build a resolver with `n` exact hostnames (host-0.example.com .. host-{n-1}.example.com).
fn build_resolver_with_exact_hostnames(count: usize) -> sni::SniCertResolver {
    let certificates: Vec<CertKeyPair> = (0..count)
        .map(|i| {
            let certs = gen_test_certs();
            CertKeyPair {
                cert_path: certs.cert_path.to_str().unwrap().to_owned(),
                key_path: certs.key_path.to_str().unwrap().to_owned(),
                server_names: vec![format!("host-{i}.example.com")],
                default: false,
            }
        })
        .collect();
    sni::build_sni_resolver(&certificates).unwrap()
}

/// Build a resolver with `n` wildcard entries (*.domain-0.com .. *.domain-{n-1}.com).
fn build_resolver_with_wildcards(count: usize) -> sni::SniCertResolver {
    let certificates: Vec<CertKeyPair> = (0..count)
        .map(|i| {
            let certs = gen_test_certs();
            CertKeyPair {
                cert_path: certs.cert_path.to_str().unwrap().to_owned(),
                key_path: certs.key_path.to_str().unwrap().to_owned(),
                server_names: vec![format!("*.domain-{i}.com")],
                default: false,
            }
        })
        .collect();
    sni::build_sni_resolver(&certificates).unwrap()
}

/// Build a resolver with `n` exact hostnames plus a default certificate.
fn build_resolver_with_default(count: usize) -> sni::SniCertResolver {
    let mut certificates: Vec<CertKeyPair> = (0..count)
        .map(|i| {
            let certs = gen_test_certs();
            CertKeyPair {
                cert_path: certs.cert_path.to_str().unwrap().to_owned(),
                key_path: certs.key_path.to_str().unwrap().to_owned(),
                server_names: vec![format!("host-{i}.example.com")],
                default: false,
            }
        })
        .collect();

    // Add default cert
    let default_certs = gen_test_certs();
    certificates.push(CertKeyPair {
        cert_path: default_certs.cert_path.to_str().unwrap().to_owned(),
        key_path: default_certs.key_path.to_str().unwrap().to_owned(),
        server_names: Vec::new(),
        default: true,
    });

    sni::build_sni_resolver(&certificates).unwrap()
}
