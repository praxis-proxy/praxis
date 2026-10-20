// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Client-only heap totals and separate unprofiled timings for real subrequests.
//!
//! Run one case per process. Build without `dhat-heap` for `--mode timing`,
//! and with that feature for `--mode allocations`. Two attempts means two
//! concurrent outbound calls through one pool, not the full hedge scheduler.

#![forbid(unsafe_code)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::missing_docs_in_private_items,
    clippy::too_many_lines,
    clippy::arithmetic_side_effects,
    reason = "standalone benchmark setup, assertions and measurement arithmetic"
)]

mod subrequest_backend;
mod subrequest_peer;

#[cfg(not(feature = "dhat-heap"))]
use std::time::Instant;
use std::{net::SocketAddr, time::Duration};

use bytes::Bytes;
use praxis_core::subrequest::{SubRequest, SubRequestClient, SubRequestConnector, SubRequestError, SubResponse};
use serde_json::json;
use subrequest_backend::Backend;
use subrequest_peer::{BenchPeer, build_peer};

#[cfg(feature = "dhat-heap")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

/// Fixed response body, shared by both subprocess protocols.
const BODY: [u8; 64] = [b'x'; 64];

/// One explicitly selected workload, with bounded defaults.
struct Config {
    mode: String,
    protocol: String,
    headers: usize,
    attempts: usize,
    iterations: usize,
    samples: usize,
}

impl Config {
    fn parse<Args: Iterator<Item = String>>(mut args: Args) -> Self {
        let mut config = Self {
            mode: if cfg!(feature = "dhat-heap") {
                "allocations"
            } else {
                "timing"
            }
            .to_owned(),
            protocol: "h1".to_owned(),
            headers: 16,
            attempts: 1,
            iterations: 1000,
            samples: 7,
        };
        while let Some(flag) = args.next() {
            if flag == "--bench" {
                continue;
            }
            let value = args.next().expect("every benchmark flag requires a value");
            match flag.as_str() {
                "--mode" => config.mode = value,
                "--protocol" => config.protocol = value,
                "--headers" => config.headers = value.parse().unwrap(),
                "--attempts" => config.attempts = value.parse().unwrap(),
                "--iterations" => config.iterations = value.parse().unwrap(),
                "--samples" => config.samples = value.parse().unwrap(),
                _ => panic!("unknown benchmark flag: {flag}"),
            }
        }
        assert!(
            matches!(config.protocol.as_str(), "h1" | "h2"),
            "protocol must be h1 or h2"
        );
        assert!(matches!(config.headers, 16 | 64), "extra headers must be 16 or 64");
        assert!(matches!(config.attempts, 1 | 2), "attempts must be one or two");
        assert!(
            (1..=100_000).contains(&config.iterations),
            "iteration count is out of bounds"
        );
        assert!((1..=100).contains(&config.samples), "sample count is out of bounds");
        config
    }
}

/// One warmed connector, request and peer retained across all measurements.
struct Workload {
    client: SubRequestClient,
    peer: BenchPeer,
    request: SubRequest,
    attempts: usize,
    headers: usize,
}

impl Workload {
    fn new(config: &Config, address: SocketAddr) -> Self {
        praxis_tls::provider::install();
        Self {
            client: SubRequestClient::new(SubRequestConnector::new(8, None)),
            peer: build_peer(address, config.protocol == "h2"),
            request: SubRequest {
                method: http::Method::GET,
                uri: "/bench".parse().unwrap(),
                headers: http::HeaderMap::new(),
                body: Bytes::new(),
            },
            attempts: config.attempts,
            headers: config.headers,
        }
    }

    async fn cycle(&self) -> [u64; 2] {
        let first_future = self.request_future();
        if self.attempts == 1 {
            return [self.validate(&first_future.await.unwrap()), 0];
        }
        let second_future = self.request_future();
        let (first_response, second_response) = tokio::join!(first_future, second_future);
        [
            self.validate(&first_response.unwrap()),
            self.validate(&second_response.unwrap()),
        ]
    }

    /// Box each large executor future before composing the concurrent cycle.
    fn request_future(&self) -> impl Future<Output = Result<SubResponse, SubRequestError>> + Send {
        Box::pin(
            self.client
                .execute(&self.peer, &self.request, 1024, Duration::from_secs(5), None),
        )
    }

    fn validate(&self, response: &SubResponse) -> u64 {
        assert_eq!(response.status, 200, "backend must return success");
        assert_eq!(
            response.body.as_ref(),
            BODY.as_slice(),
            "backend body must match the workload"
        );
        assert_eq!(
            response.headers.get("content-length").unwrap(),
            "64",
            "response framing metadata must survive"
        );
        assert_eq!(
            response.headers.len(),
            self.headers + 2,
            "extra headers, Content-Length and the connection ID must survive"
        );
        response
            .headers
            .get("x-bench-connection")
            .unwrap()
            .to_str()
            .unwrap()
            .parse()
            .unwrap()
    }

    async fn cycles(&self, iterations: usize, known: [u64; 2]) {
        for _ in 0..iterations {
            let connections = self.cycle().await;
            for connection in connections.into_iter().filter(|connection| *connection != 0) {
                assert!(known.contains(&connection), "measurement opened a new connection");
            }
        }
    }
}

fn main() {
    let mut args = std::env::args().skip(1).peekable();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    if args.peek().map(String::as_str) == Some("--backend") {
        let _flag = args.next();
        let protocol = args.next().unwrap();
        let headers = args.next().unwrap().parse().unwrap();
        runtime.block_on(subrequest_backend::serve(&protocol, headers));
        return;
    }
    let config = Config::parse(args);
    assert_eq!(
        config.mode,
        if cfg!(feature = "dhat-heap") {
            "allocations"
        } else {
            "timing"
        },
        "allocation profiling and timing require separately built binaries"
    );
    let backend = Backend::start(&config.protocol, config.headers);
    let workload = {
        let _entered = runtime.enter();
        Workload::new(&config, backend.address())
    };
    let known = runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(120), async {
            let known = workload.cycle().await;
            workload.cycles(100, known).await;
            known
        })
        .await
        .unwrap()
    });
    measure(&runtime, &config, &workload, known);
}

#[cfg(not(feature = "dhat-heap"))]
fn measure(runtime: &tokio::runtime::Runtime, config: &Config, workload: &Workload, known: [u64; 2]) {
    let calls = config.iterations.checked_mul(config.attempts).unwrap();
    let denominator = f64::from(u32::try_from(calls).unwrap());
    let mut samples = Vec::with_capacity(config.samples);
    for _ in 0..config.samples {
        let start = Instant::now();
        runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(120), workload.cycles(config.iterations, known))
                .await
                .unwrap();
        });
        samples.push(start.elapsed().as_secs_f64() * 1_000_000_000.0 / denominator);
    }
    println!(
        "{}",
        json!({
            "mode": "timing", "protocol": config.protocol, "headers": config.headers,
            "attempts": config.attempts, "iterations": config.iterations,
            "total_calls": calls.checked_mul(config.samples).unwrap(),
            "calls_per_sample": calls, "sample_ns_per_call": samples,
            "warmed_connections": warmed_connections(known),
        })
    );
}

#[cfg(feature = "dhat-heap")]
fn measure(runtime: &tokio::runtime::Runtime, config: &Config, workload: &Workload, known: [u64; 2]) {
    let calls = config.iterations.checked_mul(config.attempts).unwrap();
    let profiler = dhat::Profiler::builder().testing().build();
    runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(120), workload.cycles(config.iterations, known))
            .await
            .unwrap();
    });
    let stats = dhat::HeapStats::get();
    drop(profiler);
    let denominator = f64::from(u32::try_from(calls).unwrap());
    println!(
        "{}",
        json!({
            "mode": "allocations", "protocol": config.protocol, "headers": config.headers,
            "attempts": config.attempts, "iterations": config.iterations, "total_calls": calls,
            "allocations": stats.total_blocks, "bytes": stats.total_bytes,
            "allocations_per_call": stats.total_blocks.to_string().parse::<f64>().unwrap() / denominator,
            "bytes_per_call": stats.total_bytes.to_string().parse::<f64>().unwrap() / denominator,
            "warmed_connections": warmed_connections(known),
        })
    );
}

fn warmed_connections(known: [u64; 2]) -> usize {
    if matches!(known, [first, second] if second != 0 && first != second) {
        2
    } else {
        1
    }
}
