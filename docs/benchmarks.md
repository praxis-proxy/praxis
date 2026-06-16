# Benchmarks

Praxis has two benchmark systems:

- **Microbenchmarks**: Criterion benches for individual
  components (filter pipeline, config parsing, router
  lookup, condition evaluation, load balancer, headers).
- **Scenario benchmarks**: full proxy benchmarks driven
  by external load generators (Vegeta, Fortio) with
  optional side-by-side comparison against Envoy,
  NGINX, and HAProxy.

## Prerequisites

- [Fortio](https://fortio.org/) v1.75.1+ (HTTP echo
  backend, TCP workloads, connection-count workloads)
- [Vegeta](https://github.com/tsenart/vegeta) v12.13.0+
  (HTTP load generator; open-loop mode)
- [Docker](https://www.docker.com/) or Podman (required
  for comparison mode; optional for Praxis-only runs)
- `perf` and `inferno` (flamegraph profiling; Linux
  only; `cargo install inferno`)

## Microbenchmarks

Location: `benchmarks/microbenchmarks/`

| Benchmark | What it measures |
| --- | --- |
| `router_lookup` | Path-prefix matching at 10/100/500 routes (early, mid, fallback) |
| `filter_pipeline` | Pipeline build time (1/5/20 filters) and request execution |
| `condition_eval` | Condition matching: empty, path prefix, header, method |
| `config_parsing` | YAML config deserialization at varying complexity |
| `load_balancer` | Round-robin, least-connections, random with varying upstreams |
| `headers` | Request/response header injection (1/5/20 headers) |

Run all microbenchmarks:

```console
cargo bench -p benchmarks
```

Run a single suite:

```console
cargo bench -p benchmarks --bench router_lookup
```

Results land in `target/criterion/` with HTML reports.

## Scenario Benchmarks

Scenario benchmarks run a full Praxis binary (or Docker
container) with real traffic from external load
generators. The xtask orchestrator handles: building the
proxy, starting a Fortio echo backend, warming up,
executing multiple measurement runs, and selecting the
median result.

### Workloads

Eight workload types cover different traffic patterns:

| Workload name | Description | Load generator | Key parameters |
| --- | --- | --- | --- |
| `high-concurrency-small-requests` | Small GET requests at high concurrency | Vegeta | `--concurrency` (default 100) |
| `large-payloads` | Large POST requests | Vegeta | `--body-size` (default 65536) |
| `large-payloads-high-concurrency` | Large POST at high concurrency | Vegeta | `--concurrency`, `--body-size` |
| `high-connection-count` | HTTP/1.1 connection stress test | Fortio | `--connections` (default 100) |
| `sustained` | Sustained load for leak detection | Vegeta | `--sustained-duration` (default 60s) |
| `ramp` | Ramp from low to high QPS | Vegeta | `--start-qps`, `--end-qps`, `--step` |
| `tcp-throughput` | Raw TCP forwarding throughput | Fortio | (none) |
| `tcp-connection-rate` | TCP connection setup rate (1 conn/req) | Fortio | (none) |

### Running a Single Workload

```console
cargo xtask benchmark \
    --workload high-concurrency-small-requests \
    --duration 30 --warmup 10 --runs 3
```

### Running All Workloads

Omit `--workload` to run every workload in sequence:

```console
cargo xtask benchmark --runs 3 --warmup 10 --duration 30
```

### Tuning Workload Parameters

Override defaults for specific workload types:

```console
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

Compare Praxis against Envoy, NGINX, and/or HAProxy.
Each proxy runs inside a Docker container with identical
resource constraints (4 CPUs, 2GB RAM) against a shared
Fortio echo backend. Configs are functionally equivalent
minimal reverse proxies (one listener, one route, one
upstream).

### Comprehensive Praxis vs Envoy

This is the most common comparative benchmark. It
runs every workload against both proxies with tuned
parameters and enough runs for statistical
confidence:

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

What each workload tests:

- **high-concurrency-small-requests**: baseline
  proxy overhead; 200 concurrent GET requests
  through the proxy to the echo backend; dominated
  by scheduling and connection management.
- **large-payloads**: data-plane throughput; 128KB
  POST bodies; stresses body buffering, memory
  allocation, and copy paths.
- **large-payloads-high-concurrency**: combines
  large bodies with high concurrency; reveals
  contention under memory pressure.
- **high-connection-count**: connection management
  at scale; 500 concurrent HTTP/1.1 connections;
  tests accept-loop throughput and connection pool
  behavior.
- **sustained**: stability under continuous load for
  120s; exposes memory leaks, connection exhaustion,
  and degradation over time.
- **ramp**: progressive load increase from 100 to
  20,000 QPS in steps of 200; identifies the
  saturation point where latency inflects.
- **tcp-throughput**: raw L4 forwarding throughput
  with no HTTP parsing; measures the floor overhead
  of the proxy's I/O path.
- **tcp-connection-rate**: new TCP connection per
  request; measures accept/close churn cost.

This takes about 90 minutes (8 workloads x 2 proxies
x 5 runs x 60s each, plus warmup). For a faster
iteration cycle, reduce `--runs` to 3 and
`--duration` to 30 (about 30 minutes).

After the run completes, visualize and compare:

```console
cargo xtask benchmark visualize \
    results/praxis-vs-envoy.yaml \
    --output results/praxis-vs-envoy.svg
```

### Quick Praxis vs Envoy

A faster run covering the most informative workloads:

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

```console
cargo xtask benchmark \
    --proxy envoy --proxy nginx --proxy haproxy \
    --runs 5 --warmup 15 --duration 60 \
    --output results/all-proxies.yaml
```

Praxis is always included automatically. Omitting
`--workload` runs all eight workloads.

### Using Custom Docker Images

Override any proxy image:

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

Default images:

| Proxy | Default image |
| --- | --- |
| Praxis | Built from local `Containerfile` |
| Envoy | `envoyproxy/envoy:v1.31-latest` |
| NGINX | `nginx:alpine` |
| HAProxy | `haproxy:latest` |

### Comparison Configs

All proxy configs live in
`benchmarks/comparison/configs/` and implement the
same topology: listen on a dedicated port, route
`/` to the Fortio echo backend at `127.0.0.1:18080`.

| Proxy | Config | Port |
| --- | --- | --- |
| Praxis | `praxis.yaml` | 18090 |
| Envoy | `envoy.yaml` | 18091 |
| NGINX | `nginx.conf` | 18092 |
| HAProxy | `haproxy.cfg` | 18093 |

The Docker Compose file
(`benchmarks/comparison/docker-compose.yml`) can also
be used directly:

```console
docker compose -f benchmarks/comparison/docker-compose.yml \
    up -d backend
docker compose -f benchmarks/comparison/docker-compose.yml \
    up -d envoy
```

## Output and Reports

Reports are written in YAML (default) or JSON:

```console
cargo xtask benchmark --format json --output report.json
cargo xtask benchmark --format yaml --output report.yaml
```

Use `--include-raw-report` to embed the raw Vegeta or
Fortio JSON output alongside the normalized metrics.

Each report contains:

- **Environment**: CPU model, OS, git commit SHA
- **Settings**: all workload parameters used
- **Per-scenario, per-proxy results**: latency
  (min/max/mean/p50/p90/p95/p99/p99.9), throughput
  (req/s, bytes/s), errors (non-2xx, timeouts,
  connection failures)
- **Median selection**: when multiple runs are
  performed, the median by p99 latency is selected

## Visualization

Generate an SVG chart from a report:

```console
cargo xtask benchmark visualize report.yaml
cargo xtask benchmark visualize report.yaml \
    --output comparison.svg
```

Produces two panels: latency percentiles and
throughput. Proxy colors: Praxis=green, Envoy=blue,
NGINX=red, HAProxy=purple.

## Regression Detection

Compare two reports and exit non-zero if any metric
regressed beyond the threshold:

```console
cargo xtask benchmark compare baseline.yaml current.yaml
cargo xtask benchmark compare baseline.yaml current.yaml \
    --threshold 0.10
```

Default threshold: 5%. A regression is flagged when
p99 latency increases or throughput decreases beyond
the threshold. The output includes per-scenario
change percentages and improvement/regression flags.

## Flamegraph Profiling

Profile Praxis under load and generate a CPU
flamegraph:

```console
cargo xtask benchmark flamegraph \
    --workload high-concurrency-small-requests \
    --duration 30

cargo xtask benchmark flamegraph \
    --workload large-payloads --duration 15
```

Prerequisites: `perf` (Linux only), `inferno`
(`cargo install inferno`).

Output: `target/criterion/flamegraph-{timestamp}.svg`

## Tips for Reliable Results

- **Isolate the machine**: close unnecessary
  applications, disable frequency scaling
  (`cpupower frequency-set -g performance`).
- **Use multiple runs**: `--runs 5` with median
  selection reduces noise.
- **Warm up sufficiently**: `--warmup 15` or longer
  lets connection pools and JIT-like effects settle.
- **Consistent resource limits**: comparison mode
  enforces 4 CPUs and 2GB RAM per proxy via Docker
  resource constraints.
- **Run proxies sequentially**: the orchestrator runs
  one proxy at a time to avoid CPU contention.
- **Check errors**: non-zero error counts invalidate
  throughput/latency comparisons.

## CI

GitHub Actions workflows run on this repository:

- `tests.yaml`: unit lint and test on push/PR
- `integration.yaml`: integration test suites on
  push/PR
- `conformance.yaml`: HTTP/2 conformance (h2spec, RFC
  compliance) on push/PR
- `conventions.yaml`: coding conventions and PR
  hygiene enforcement on PRs
- `supply-chain.yaml`: supply chain safety checks
  (`cargo audit`, `cargo deny`) on push/PR
- `container.yaml`: build, run, and health-check the
  container image on push/PR
- `microbenchmarks.yaml`: Criterion microbenchmarks
  with baseline comparison on push/PR
- `benchmarks.yaml`: comparative benchmarks (Praxis
  vs Envoy) on push to main
- `coverage.yaml`: code coverage gate (90% minimum)
  on push/PR
- `codeql.yaml`: CodeQL security analysis on push/PR
  and weekly schedule
- `documentation.yaml`: rustdoc generation on push/PR
- `msrv.yaml`: minimum supported Rust version check
  on push/PR
- `nightly.yaml`: comprehensive nightly test runs
- `pull-request-hygiene.yaml`: automated PR lifecycle
  management (draft on failure, close stale)
- `release.yaml`: tag-triggered release workflow
- `publish.yaml`: manual container build and push to
  GHCR
