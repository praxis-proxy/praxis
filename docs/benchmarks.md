# Benchmarks

Praxis has three benchmark systems:

- Performance tests: in-process proxy throughput
- Microbenchmarks: component-level benchmarks
- Benchmarks: scenario-based benchmarks

## Microbenchmarks

Criterion benches for individual components: filter
pipeline, config parsing, router lookup, condition
evaluation, load balancer, headers.

```console
cargo bench -p benchmarks
cargo bench -p benchmarks --bench router_lookup
```

Location: `benchmarks/benches/`

## Performance Tests

In-process proxy throughput tests covering passthrough,
filter chain scaling, and payload sizes.

```console
cargo test -p praxis-tests-performance
```

Location: `tests/performance/`

## Benchmark Xtask

Scenario-based benchmarks with external load generators.
Supports comparison with Envoy, NGINX, and HAProxy.

### Prerequisites

- [Fortio](https://fortio.org/) v1.75.1+
- [Vegeta](https://github.com/tsenart/vegeta) v12.13.0+
- [Docker](https://www.docker.com/) (comparison mode only)

### Usage

```console
cargo xtask benchmark \
    --workload high-concurrency-small-requests \
    --runs 3 --warmup 10 --duration 30

cargo xtask benchmark --proxy envoy --proxy nginx

cargo xtask benchmark --include-raw-report
```

### Visualization

```console
cargo xtask benchmark visualize <REPORT> [--output OUT.svg]
```

Two panels: latency percentiles and throughput. Proxy
colors: Praxis=green, Envoy=blue, NGINX=red,
HAProxy=purple.

### Regression Detection

```console
cargo xtask benchmark compare <BASELINE> <CURRENT> \
    [--threshold 0.05]
```

Exits non-zero on regression (default threshold: 5%).

### Flamegraph Profiling

Generate a CPU flamegraph of Praxis under load:

```console
cargo xtask benchmark flamegraph \
    --workload large-payloads --duration 15
```

Prerequisites: `perf`, `inferno`
(`cargo install inferno`). Linux only.

Output: `target/criterion/flamegraph-{timestamp}.svg`

## CI

Four GitHub Actions workflows run on this repository:

- `tests.yaml`: lint, build, and test on every push/PR
- `container.yaml`: build, run, and health-check the
  container image on every push/PR
- `benchmarks.yaml`: microbenchmarks and full-scale
  benchmarks on manual dispatch (results uploaded as
  artifacts)
- `publish.yml`: build and push the container image to
  GHCR on manual dispatch
