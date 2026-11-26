# Benchmarks

Praxis has two benchmark systems:

- **Microbenchmarks**: Criterion benches for individual components.
- **Scenario benchmarks**: the full proxy under load from Vegeta or Fortio,
  optionally side by side with Envoy, NGINX, and HAProxy.

## Prerequisites

- [Fortio](https://fortio.org/) v1.75.1+ (HTTP echo backend, TCP workloads,
  connection-count workloads)
- [Vegeta](https://github.com/tsenart/vegeta) v12.13.0+ (HTTP load
  generator; open-loop mode)
- [Docker](https://www.docker.com/) or Podman (required for comparison
  mode; optional for Praxis-only runs)
- `perf` and `inferno` (flamegraph profiling; Linux only;
  `cargo install inferno`)

## Microbenchmarks

Location: `tests/benches/benches/`

| Benchmark | What it measures |
| --- | --- |
| `router_lookup` | Path-prefix matching at 10/100/500 routes (early, mid, fallback) |
| `filter_pipeline` | Pipeline build time (1/5/20 filters) and request execution |
| `condition_eval` | Condition matching: empty, path prefix, header, method |
| `config_parsing` | YAML config deserialization at varying complexity |
| `load_balancer` | Round-robin, least-connections, consistent-hash with varying upstreams |
| `headers` | Request/response header injection (1/5/20 headers) |
| `token_bucket` | Mutex, locked split-field, packed 128-bit CAS, and `governor` rate-limit state under sequential and concurrent load |

Run all of them, or one suite with `--bench`:

```console
cargo bench -p praxis-tests-benches
cargo bench -p praxis-tests-benches --bench token_bucket
cargo bench -p praxis-tests-benches --bench router_lookup
```

Results land in `target/criterion/` as Criterion HTML reports. CI uploads
that directory as a workflow artifact; raw run logs and host-specific
snapshots are not committed.

### `token_bucket`

The suite measures candidates against the mutex implementation from
PR #1173:

- `split_atomics_locked`: a correctness-preserving split-field
  implementation guarded by an atomic spin lock. It measures serialization
  overhead; it is not a lock-free design.
- `packed_128_cas`: an exact compound-state CAS prototype. It uses
  `portable-atomic`, so each host must report whether it ran native or
  fallback.
- `governor 0.10.4`: the real direct in-memory `RateLimiter::check()` path.
  Governor uses integer-cell virtual-time semantics and has no equivalent
  token-count introspection API, so it is a performance comparison, not an
  API-equivalent replacement.

There are 55 benchmark IDs: 8 isolated operations, 4 rejection paths,
3 introspection paths, and 40 contention cases. Introspection covers only
candidates that expose the production token-count operation. The unsafe
split-atomic implementation from the PR investigation is not in the
runnable suite or the decision tables, and its logs are not committed.

## Scenario Benchmarks

`cargo xtask benchmark` builds the proxy (or uses a Docker container),
starts a Fortio echo backend, warms up, runs several measurement runs, and
keeps the median. It wraps the published
[`praxis-proxy-benchmarks`](https://crates.io/crates/praxis-proxy-benchmarks)
crate (developed in the
[benchmarks repository](https://github.com/praxis-proxy/benchmarks)) for
local runs against the in-tree comparison configs.

### Workloads

| Workload name | What it measures | Load generator | Key parameters |
| --- | --- | --- | --- |
| `high-concurrency-small-requests` | Small GET requests at high concurrency: baseline proxy overhead, dominated by scheduling and connection management | Vegeta | `--concurrency` (default 100) |
| `large-payloads` | Large POST requests: data-plane throughput, body buffering, memory allocation, and copy paths | Vegeta | `--body-size` (default 65536) |
| `large-payloads-high-concurrency` | Large POST at high concurrency: contention under memory pressure | Vegeta | `--concurrency`, `--body-size` |
| `high-connection-count` | HTTP/1.1 connection stress: accept-loop throughput and connection pool behavior | Fortio | `--connections` (default 100) |
| `sustained` | Continuous load: memory leaks, connection exhaustion, degradation over time | Vegeta | `--sustained-duration` (default 60s) |
| `ramp` | Low to high QPS: the saturation point where latency inflects | Vegeta | `--start-qps`, `--end-qps`, `--step` |
| `tcp-throughput` | Raw L4 forwarding with no HTTP parsing: the floor overhead of the proxy's I/O path | Fortio | (none) |
| `tcp-connection-rate` | TCP connection setup rate (1 conn/req): accept/close churn cost | Fortio | (none) |

### Running workloads

Pass `--workload` for one workload, or omit it to run all of them in
sequence. Workload parameters override the defaults above:

```console
cargo xtask benchmark \
    --workload high-concurrency-small-requests \
    --duration 30 --warmup 10 --runs 3

cargo xtask benchmark --runs 3 --warmup 10 --duration 30

cargo xtask benchmark \
    --workload large-payloads \
    --body-size 131072 \
    --duration 60 --runs 5

cargo xtask benchmark \
    --workload high-concurrency-small-requests \
    --concurrency 500 \
    --duration 30 --runs 3

cargo xtask benchmark \
    --workload ramp \
    --start-qps 500 --end-qps 50000 --step 500 \
    --duration 60

cargo xtask benchmark \
    --workload high-connection-count \
    --connections 1000

cargo xtask benchmark \
    --workload sustained \
    --sustained-duration 300 --runs 1
```

## Comparison Benchmarks

`--proxy` adds Envoy, NGINX, or HAProxy; Praxis is always included. Each
proxy runs in a Docker container with the same limits (4 CPUs, 2GB RAM)
against a shared Fortio echo backend, one proxy at a time. The configs are
equivalent minimal reverse proxies (one listener, one route, one upstream).

### Comprehensive Praxis vs Envoy

The most common comparison runs every workload against both proxies, with
tuned parameters and enough runs for statistical confidence:

```console
cargo xtask benchmark \
    --proxy envoy \
    --workload high-concurrency-small-requests \
    --workload large-payloads \
    --workload large-payloads-high-concurrency \
    --workload high-connection-count \
    --workload sustained \
    --workload ramp \
    --workload tcp-throughput \
    --workload tcp-connection-rate \
    --concurrency 200 \
    --body-size 131072 \
    --connections 500 \
    --start-qps 100 --end-qps 20000 --step 200 \
    --sustained-duration 120 \
    --runs 5 --warmup 15 --duration 60 \
    --include-raw-report \
    --output results/praxis-vs-envoy.yaml
```

This takes about 90 minutes (8 workloads x 2 proxies x 5 runs x 60s each,
plus warmup). With `--runs 3` and `--duration 30` it takes about 30 minutes.

Then chart the results:

```console
cargo xtask benchmark visualize \
    results/praxis-vs-envoy.yaml \
    --output results/charts
```

### Quick Praxis vs Envoy

A faster run over the most informative workloads:

```console
cargo xtask benchmark \
    --proxy envoy \
    --workload high-concurrency-small-requests \
    --workload large-payloads \
    --workload tcp-throughput \
    --concurrency 200 --body-size 131072 \
    --runs 3 --warmup 10 --duration 30 \
    --output results/quick-comparison.yaml
```

### Praxis vs All Proxies

Without `--workload`, this runs all eight workloads:

```console
cargo xtask benchmark \
    --proxy envoy --proxy nginx --proxy haproxy \
    --runs 5 --warmup 15 --duration 60 \
    --output results/all-proxies.yaml
```

### Using Custom Docker Images

```console
cargo xtask benchmark \
    --proxy envoy \
    --image ghcr.io/praxis-proxy/praxis:latest \
    --envoy-image envoyproxy/envoy:v1.32-latest

cargo xtask benchmark \
    --proxy nginx --proxy haproxy \
    --nginx-image nginx:1.27-alpine \
    --haproxy-image haproxy:3.1
```

| Proxy | Default image |
| --- | --- |
| Praxis | Built from local `Containerfile` |
| Envoy | `envoyproxy/envoy:v1.31-latest` |
| NGINX | `nginx:alpine` |
| HAProxy | `haproxy:latest` |

### Comparison Configs

The configs in `xtask/comparison/configs/` all listen on their own port and
route `/` to the Fortio echo backend at `127.0.0.1:18080`.

| Proxy | Config | Port |
| --- | --- | --- |
| Praxis | `praxis.yaml` | 18090 |
| Envoy | `envoy.yaml` | 18091 |
| NGINX | `nginx.conf` | 18092 |
| HAProxy | `haproxy.cfg` | 18093 |

You can also use the Docker Compose file directly:

```console
docker compose -f xtask/comparison/docker-compose.yml \
    up -d backend
docker compose -f xtask/comparison/docker-compose.yml \
    up -d envoy
```

## Output and Reports

Reports are YAML (default) or JSON:

```console
cargo xtask benchmark --format json --output report.json
cargo xtask benchmark --format yaml --output report.yaml
```

`--include-raw-report` embeds the raw Vegeta or Fortio JSON next to the
normalized metrics. Each report holds:

- **Environment**: CPU model, OS, git commit SHA
- **Settings**: all workload parameters used
- **Per-scenario, per-proxy results**: latency
  (min/max/mean/p50/p90/p95/p99/p99.9), throughput (req/s, bytes/s), errors
  (non-2xx, timeouts, connection failures)
- **Median selection**: with multiple runs, the run with the median p99
  latency is kept

## Visualization

Generate SVG charts from a report. `--output` names a directory (default:
`target/criterion`):

```console
cargo xtask benchmark visualize report.yaml
cargo xtask benchmark visualize report.yaml \
    --output results/charts
```

The command writes eight files named `<report-stem>-<metric>.svg`: p99,
minimum, mean, and maximum latency; request and data throughput; average
CPU; and peak memory. For `report.yaml`, one is
`results/charts/report-p99-latency.svg`. Proxy colors: Praxis=green,
Envoy=blue, NGINX=red, HAProxy=purple.

## Regression Detection

Compare two reports; the command exits non-zero if a stable, matching Praxis
scenario regresses:

```console
cargo xtask benchmark compare baseline.yaml current.yaml
cargo xtask benchmark compare baseline.yaml current.yaml \
    --threshold 0.10
```

Default threshold: 5%. A scenario fails only when p99 latency increases
**and** throughput decreases, each strictly beyond the threshold; movement
in one alone is noise. At a 5% threshold, a 20% latency increase with
unchanged throughput passes, while a 20% latency increase with a 10%
throughput decrease fails. Current-run results with a coefficient of
variation above 0.15 are skipped. The output shows each scenario's
percentage changes and PASS, FAIL, or SKIP.

## Flamegraph Profiling

Profile Praxis under load and write a CPU flamegraph to
`target/criterion/flamegraph-{timestamp}.svg` (needs `perf` and `inferno`,
see [Prerequisites](#prerequisites)):

```console
cargo xtask benchmark flamegraph \
    --workload high-concurrency-small-requests \
    --duration 30

cargo xtask benchmark flamegraph \
    --workload large-payloads --duration 15
```

## Tips for Reliable Results

- Isolate the machine: close other applications and disable frequency
  scaling (`cpupower frequency-set -g performance`).
- Use `--runs 5`; median selection reduces noise.
- Warm up for `--warmup 15` or longer so connection pools and JIT-like
  effects settle.
- Check errors: non-zero error counts invalidate throughput and latency
  comparisons.

## CI

GitHub Actions workflows in this repository. `conventions.yaml`,
`coverage.yaml`, `msrv.yaml`, `supply-chain.yaml`,
`pull-request-conventions.yaml`, and a few others are short callers of
shared workflows in `praxis-proxy/conventions`.

| Workflow | Runs | Trigger |
| --- | --- | --- |
| `tests.yaml` | Unit lint and test | push/PR |
| `integration.yaml` | Integration test suites | push/PR |
| `conformance.yaml` | HTTP/2 conformance (h2spec, RFC compliance) | push/PR |
| `conventions.yaml` | Coding conventions enforcement | PRs |
| `supply-chain.yaml` | Supply chain checks (`cargo audit`, `cargo deny`) | push/PR |
| `container.yaml` | Build, run, and health-check the container image | push/PR |
| `microbenchmarks.yaml` | Criterion microbenchmarks, `target/criterion/` uploaded as an artifact; no push/PR baseline comparison | daily, manual dispatch |
| `benchmarks.yaml` | Comparative benchmarks (Praxis vs Envoy) | push to main |
| `coverage.yaml` | Coverage; the `make coverage-check` floor is 97% | push/PR |
| `codeql.yaml` | CodeQL security analysis | push/PR, weekly |
| `documentation.yaml` | Rustdoc generation | push/PR |
| `msrv.yaml` | Minimum supported Rust version check | push/PR |
| `nightly.yaml` | Comprehensive nightly test runs | nightly |
| `pull-request-conventions.yaml` | PR lifecycle management (draft on failure, close stale) | PRs |
| `release.yaml` | Release | tag |
| `publish.yaml` | Container build and push to GHCR | manual |
