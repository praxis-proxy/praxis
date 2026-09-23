# Agent Guidance

This file provides guidance to coding agents when working with code in this
repository.

Tools may assist with implementation, but **do not add any tool as a commit
collaborator, co-author, or signatory**. Commit sign-off belongs to the human
contributor responsible for the change.

## Requirements

- Rust stable 1.92+
- Rust nightly (for `rustfmt`)
- CMake 3.31+
- Docker 29.3.0+ or Podman (for container builds)

## Quick Reference

### Dev Utilities

```console
cargo xtask echo              # quick HTTP test server (static responses)
cargo xtask debug             # run with dev settings (debug logs, single-threaded)
cargo xtask debug config.yaml # run example with dev settings
```

### Build & Test

```console
make setup-hooks    # install git pre-commit hook (fmt + lint)
make build          # workspace build (includes benches)
make test           # tests outside tests/ (single pass, all features)
make fmt            # format with nightly rustfmt
make lint           # clippy + nightly fmt check + xtask lint-deps
make doc            # rustdoc with -D warnings, including private items
make audit          # cargo audit + cargo deny check
make coverage-check # fail if line coverage < 96%
make container      # container image build
cargo run -p praxis-proxy # run the proxy
```

### Targeted Testing

**Prefer targeted test runs over full test suites.** Run only the tests relevant
to your changes unless doing a final verification before commit.

Run a single test:

```console
cargo test -p praxis-tests-integration --test suite -- test_name
make test-integration V=1   # with --nocapture
```

Skip tests entirely for documentation-only changes (README, docs/*.md).

Individual test suites:

```console
make test-unit          # alias for make test (everything outside tests/)
make test-schema        # config parsing + example validation
make test-integration   # all tests/ suites: schema, security, resilience, integration
make test-conformance   # RFC conformance (h2spec, HTTP semantics)
make test-security      # request smuggling, header injection
make test-resilience    # load, failure recovery, throughput
```

See `docs/developing/getting-started.md` for the full
command reference and dev tool usage.

## Architecture

See `docs/architecture/overview.md` for the full design.

**Crate dependency flow:**

```text
server -> protocol -> filter -> core -> tls
```

- **server** (`praxis`): binary entry point, config
  loading, pipeline resolution, hot-reload watcher
- **core** (`praxis-core`): YAML config (serde),
  validation, error types, health state, KV store
  registry, `PingoraServerRuntime`
- **filter** (`praxis-filter`): `HttpFilter` and
  `TcpFilter` traits, pipeline engine, condition
  evaluation, body access/buffering, all built-in
  filter implementations, `FilterRegistry`
- **protocol** (`praxis-protocol`): `Protocol` trait,
  Pingora HTTP/TCP adapters, health check probes,
  admin endpoints
- **tls** (`praxis-tls`): TLS config types, SNI
  resolution (including wildcards), cert loading

**Test crates** (under `tests/`):

- `tests/utils`: shared test harness (`free_port`,
  `start_backend`, `start_proxy_with_registry`)
- `tests/schema`: config parsing and example validation
- `tests/integration`: end-to-end filter and proxy tests
- `tests/conformance`: RFC conformance (h2spec)
- `tests/security`: request smuggling, header injection
- `tests/resilience`: load, failure recovery

## Conventions

See `docs/developing/conventions.md` for the full
coding style guide, and
`docs/developing/review-criteria.md` for the criteria
used in deep analysis and audit passes over the
codebase. Praxis-specific coding conventions:

- Prefer `Option`/`Result` combinator chains
  (`strip_prefix()`, `filter()`, `map()`) over
  `if/else` blocks when the logic is a linear
  transform
- Pre-computed numeric literals with trailing
  comments for human-readable meaning
  (e.g. `10_485_760; // 10 MiB`)
- Use enums, not strings, for fixed value sets
  in config; `#[serde(deny_unknown_fields)]` on
  config structs; `#[serde(try_from)]` for
  constrained numerics; `#[serde(default)]`
  instead of `Option<T>` with `unwrap_or`.
  See `docs/developing/type-design.md`.

## Test Requirements

New capabilities require:

1. Unit tests
2. Integration tests
3. Example config in `examples/configs/`
4. Functional integration test for the example config
   in `tests/integration/tests/suite/examples/`
5. Run `cargo xtask sync-example-readme --fix` to
   regenerate `examples/README.md`

Example configs must use this header comment format
so the README generator can extract descriptions:

```yaml
# Title
#
# One-line or multi-line description used in the
# README table (first sentence is taken).
#
# Usage:
#   cargo run -p praxis-proxy -- -c examples/configs/...
```

Example config tests must exercise the actual
functionality end-to-end (e.g. a WebSocket config
must perform a real WebSocket handshake and message
exchange). Parse-only validation is not sufficient;
every example must prove its feature works with all
configured variants.

## Adding a Filter

See `docs/filters/extensions.md` for the full guide.

**Choosing a category**: HTTP filters go under `observability`,
`payload_processing`, `security`, `traffic_management`, or `transformation`.
TCP filters use `observability` or `traffic_management`. Review the category
README files in `examples/configs/<category>/` to understand each category's
scope and choose the best fit.

1. Create module under
   `crates/filter/src/builtins/<protocol>/<category>/`
2. Implement `HttpFilter` or `TcpFilter` with a
   `from_config` factory (`fn(&serde_yaml::Value)
   -> Result<Box<dyn HttpFilter>, FilterError>`)
3. Register in `crates/filter/src/registry.rs`
4. Add unit tests and doctests
5. Add example config in `examples/configs/<category>/`
   (follow the header comment format below)
6. Add functional integration test in
   `tests/integration/tests/suite/examples/`
   (must exercise actual functionality end-to-end)
7. Run `cargo xtask sync-example-readme --fix`

## Adding a Protocol

1. Implement `Protocol` trait under `crates/protocol/src/`
2. Add variant to `ProtocolKind` in
   `crates/core/src/config/listener.rs`
3. Wire in `crates/server/src/server.rs`

## Branch Chains

Conditional branching in filter pipelines based on
filter results. Key files:

- `crates/core/src/config/branch_chain.rs`: config types
- `crates/core/src/config/chain_ref.rs`: `ChainRef` enum
- `crates/core/src/config/validate/branch_chain.rs`: validation
- `crates/filter/src/results.rs`: `FilterResultSet` type
- `crates/filter/src/pipeline/filter.rs`: `PipelineFilter`
- `crates/filter/src/pipeline/branch.rs`: runtime types
- `crates/filter/src/pipeline/build_branch.rs`: resolution
- `crates/filter/src/pipeline/evaluate.rs`: execution

Filters write results to `FilterResultSet` without
knowing about branches. The pipeline executor reads
results to evaluate branch conditions and dispatch.
Branches rejoin at configurable points (next,
terminal, named filter, re-entrance with iteration
limits).

## Terminology: Routing vs Pipelining

These two concepts are distinct, take care to not conflate them.

- **Routing** (runtime): the `router` filter selects
  an upstream cluster at request time based on path,
  host, and headers. This decides *where* a request
  goes.
- **Pipelining** (config-time): the operator composes
  named filter chains per listener; chains are
  resolved and concatenated into a single
  `FilterPipeline` at startup. This decides *what
  processing* a request receives. Branch chains add
  conditional paths within a pipeline.

## Reserved Headers

**Client-unspoofable headers**: Headers with `x-praxis-*` or `x-ext-*` prefixes
are reserved and automatically stripped from incoming requests. Use these for
metadata promoted from request bodies or set by trusted filters (like
`json_body_field`). Clients cannot forge these headers, making them safe for
security-sensitive routing and filtering decisions.

Example: `json_body_field` promotes a body field to `x-praxis-guard-model`,
which `guardrails` then uses in a condition. The client cannot bypass guardrails
by sending an `x-praxis-guard-model` header directly.

## Key Patterns

- **Classify → route → branch**: classifier filters
  promote facts to internal headers (`x-praxis-*`)
  and the router matches those headers to select
  clusters (routing). Branch chains split pipelines
  (pipelining).
- **The inference path is proxy-parsed, not
  classified** (AI-specific): the `policy` filter attributes an
  OpenAI-style call to a model by reading the
  top-level `model` out of the buffered body itself
  (no classifier, no header), then dispatches PPE's
  `cmf.llm_input`. Classifier metadata still wins
  where it exists. This pattern is specific to AI workloads;
  most filters should use `json_body_field` to promote
  body fields to headers.
- **Branch on filter results**: branch chains split
  or rejoin request-phase pipelines based on filter
  results (`on_result`). See
  `examples/configs/pipeline/branch-chains.yaml`.
  Branch sub-chains only run `on_request`;
  `on_request_body` and `on_response_body` are not
  executed for filters inside branch chains.
  Body-transforming filters must be in the main
  pipeline path or gated with normal filter
  conditions.
- **Prefer existing routing mechanisms**: use
  classifier-promoted headers, router matches,
  filter conditions, and branch chains before
  adding new routing or capability mechanisms.
- **Do not buffer full streaming responses**:
  streaming and SSE filters should use
  `BodyMode::Stream` and process chunks
  incrementally unless the feature explicitly
  requires buffering.
- **Validate only proxy-needed fields**: let the
  backend handle parameter ranges, model
  availability, and role ordering.
- **Use dedicated rewrite filters for URL/path
  translation**: use `path_rewrite` or `url_rewrite`;
  provider and protocol filters should not set
  `ctx.rewritten_path` directly.

## Filter Organization

Filters live under
`crates/filter/src/builtins/<protocol>/<category>/`.
See `docs/filters/README.md` for the filter system
documentation and `docs/filters/reference.md`
for built-in filter configurations.

Categories: `observability`, `payload_processing`,
`security`, `traffic_management`,
`transformation` (HTTP); `observability`,
`traffic_management` (TCP).

Example configs: `examples/configs/<category>/`.

## Dynamic Config Reload

Praxis swaps filter pipelines at runtime without
restarting. Each handler holds
`Arc<ArcSwap<FilterPipeline>>`; a file watcher
(500ms debounce, hardcoded) monitors the config file, validates,
rebuilds pipelines, and swaps atomically. Listener
topology and TLS toggle changes cannot be applied
dynamically (logged as warnings); a protocol change
on a bound listener rejects the whole reload.

**What reloads**: Filter pipelines, filter configurations, routing rules.
**What does not reload**: Listener addresses/ports, protocol types (HTTP/TCP),
TLS on/off state, runtime worker count.

## CI Workflows

CI workflows that post PR comments must use the
`praxis-bot-app` GitHub App token (via
`actions/create-github-app-token`), not the default
`github.token`.

## Pingora Boundary

See `docs/operating/security-hardening.md` for details.

**Pingora handles** (upstream library, do not modify):
- Request smuggling prevention
- H2 backpressure
- Connection pool safety
- HTTP/1.1 upgrade detection and bidirectional forwarding (WebSocket, etc.)

**Praxis handles** (our code):
- Hop-by-hop header stripping (with conditional preservation for upgrade requests)
- Host validation
- X-Forwarded-* injection
- Retry logic
- Filter pipeline execution
- Routing and load balancing decisions

**When adding features**: If it's HTTP protocol compliance, connection management,
or core request/response handling, check if Pingora already provides it before
implementing in Praxis. If it's business logic, routing, filtering, or
observability, implement in Praxis.
