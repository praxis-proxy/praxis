# CLAUDE.md

This file provides guidance to Claude Code
(claude.ai/code) when working with code in this
repository.

## Requirements

- Rust stable 1.94+
- Rust nightly (for `rustfmt`)
- CMake 3.31+
- Docker 29.3.0+ or Podman (for container builds)

## Quick Reference

```console
make setup-hooks    # install git pre-commit hook (fmt + lint)
make build          # workspace build (includes benches)
make test           # all tests (downloads h2spec if needed)
make fmt            # format with nightly rustfmt
make lint           # clippy + nightly fmt check + xtask lint-deps
make doc            # rustdoc with -D warnings, including private items
make audit          # cargo audit + cargo deny check
make coverage-check # fail if line coverage < 95%
make container      # container image build
cargo run -p praxis # run the proxy
```

Run a single test:

```console
cargo test -p praxis-tests-integration --test suite -- test_name
make test-integration V=1   # with --nocapture
```

Individual test suites:

```console
make test-unit          # core, filter, protocol, server
make test-schema        # config parsing + example validation
make test-integration   # end-to-end filter and proxy tests
make test-conformance   # RFC conformance (h2spec, HTTP semantics)
make test-security      # request smuggling, header injection
make test-resilience    # load, failure recovery, throughput
make test-smoke         # quick startup and round-trip sanity
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
- **proto** (`praxis-proto`): vendored Envoy ext_proc
  protobuf definitions (opt-in `ext-proc` feature)

**Test crates** (under `tests/`):

- `tests/utils`: shared test harness (`free_port`,
  `start_backend`, `start_proxy_with_registry`)
- `tests/schema`: config parsing and example validation
- `tests/integration`: end-to-end filter and proxy tests
- `tests/conformance`: RFC conformance (h2spec)
- `tests/security`: request smuggling, header injection
- `tests/resilience`: load, failure recovery
- `tests/smoke`: quick startup round-trip

## Conventions

See `docs/developing/conventions.md` for the full
coding style guide. Key points:

- `unsafe_code = "deny"` in workspace lints
- All items (public and private) require `///` doc
  comments; enforced by `missing_docs` and
  `missing_docs_in_private_items` lints
- Comments answer "why?", never "what?"; use
  `tracing` for runtime narration
- Prefer `to_owned()` over `to_string()` for
  `&str` to `String`
- Use inline format args: `format!("{var}")`
- Use let-chains, `is_some_and()`, `strip_prefix()`,
  `filter()`, `map()`; prefer `Option`/`Result`
  combinator chains over `if/else` blocks when the
  logic is a linear transform
- Reference-style rustdoc links, not inline
- Do not document memory efficiency in rustdoc
  (e.g. "avoids allocation", "zero-copy", "cheap
  clone"). Correct memory use is expected; it does
  not need narration.
- Do not create re-export-only files. Import
  directly from the source module.
- Pre-computed numeric literals with trailing
  comments for human-readable meaning
- Use enums, not strings, for fixed value sets
  in config; `#[serde(deny_unknown_fields)]` on
  config structs; `#[serde(try_from)]` for
  constrained numerics; `#[serde(default)]`
  instead of `Option<T>` with `unwrap_or`.
  See `docs/developing/type-design.md`.
  (e.g. `10_485_760; // 10 MiB`)

## Workspace Lints

The workspace enforces an extensive lint policy in
`Cargo.toml` under `[workspace.lints.rust]` and
`[workspace.lints.clippy]`. Key constraints:

- `#[clippy::unwrap_used]` is denied; use `?` or
  explicit error handling
- `clippy::too_many_lines` and
  `clippy::cognitive_complexity` are denied
- All cast operations (`cast_lossless`,
  `cast_possible_truncation`, etc.) are denied
- `clippy::dbg_macro`, `print_stdout`,
  `print_stderr` are denied
- `missing_assert_message` is denied: every
  `assert!` needs a message string
- `clippy::str_to_string` is denied: use
  `to_owned()` for `&str` to `String`

## File Ordering

1. Constants (with separator comment)
2. Public types, impls, functions
3. Private types and impls
4. Private utility functions (with separator)
5. `#[cfg(test)] mod tests` (always last)

Inside `mod tests`: imports, test functions, then
test utilities (with `// Test Utilities` separator).

Struct fields: `name` first (if present), then
alphabetical. Impl blocks: `new()` first, then
`name()`, then alphabetical.

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
#   cargo run -p praxis -- -c examples/configs/...
```

Example config tests must exercise the actual
functionality end-to-end (e.g. a WebSocket config
must perform a real WebSocket handshake and message
exchange). Parse-only validation is not sufficient;
every example must prove its feature works with all
configured variants.

See `docs/developing/conventions.md` for full test
conventions (no inline comments in test bodies, no
doc comments on test functions, full-width separators
only).

## Adding a Filter

See `docs/filters/extensions.md` for the full guide.

1. Create module under
   `filter/src/builtins/<protocol>/<category>/`
2. Implement `HttpFilter` or `TcpFilter` with a
   `from_config` factory (`fn(&serde_yaml::Value)
   -> Result<Box<dyn HttpFilter>, FilterError>`)
3. Register in `filter/src/registry.rs`
4. Add unit tests and doctests
5. Add example config in `examples/configs/<category>/`
6. Add functional integration test in
   `tests/integration/tests/suite/examples/`
7. Run `cargo xtask sync-example-readme --fix`

## Adding a Protocol

1. Implement `Protocol` trait under `protocol/src/`
2. Add variant to `ProtocolKind` in
   `core/src/config/listener.rs`
3. Wire in `server/src/server.rs`

## Branch Chains

Conditional branching in filter pipelines based on
filter results. Key files:

- `core/src/config/branch_chain.rs`: config types
- `core/src/config/chain_ref.rs`: `ChainRef` enum
- `core/src/config/validate/branch_chain.rs`: validation
- `filter/src/results.rs`: `FilterResultSet` type
- `filter/src/pipeline/filter.rs`: `PipelineFilter`
- `filter/src/pipeline/branch.rs`: runtime types
- `filter/src/pipeline/build_branch.rs`: resolution
- `filter/src/pipeline/evaluate.rs`: execution

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

## Key Patterns

- **Classify → route → branch**: classifier filters
  promote facts to internal headers
  (`x-praxis-ai-*`) and the router matches those
  headers to select clusters (routing). Branch
  chains split pipelines (pipelining). See
  `examples/configs/ai/openai/responses/format-routing.yaml`.
- **Branch on filter results**: branch chains split
  or rejoin request-phase pipelines based on filter
  results (`on_result`). See
  `examples/configs/pipeline/branch-chains.yaml`
  and `tests/integration/tests/suite/responses_format.rs`.
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
`filter/src/builtins/<protocol>/<category>/`.
See `docs/filters/README.md` for the filter system
documentation and `docs/operating/filter-reference.md`
for built-in filter configurations.

Categories: `ai`, `observability`,
`payload_processing`, `security`,
`traffic_management`, `transformation` (HTTP);
`observability`, `traffic_management` (TCP).

Example configs: `examples/configs/<category>/`.

## Dynamic Config Reload

Praxis swaps filter pipelines at runtime without
restarting. Each handler holds
`Arc<ArcSwap<FilterPipeline>>`; a file watcher
(500ms debounce) monitors the config file, validates,
rebuilds pipelines, and swaps atomically. Listener
topology, protocol type, and TLS toggle changes
cannot be applied dynamically (logged as warnings).

## CI Workflows

CI workflows that post PR comments must use the
`praxis-bot-app` GitHub App token (via
`actions/create-github-app-token`), not the default
`github.token`.

## Pingora Boundary

See `docs/operating/security-hardening.md` for details.

Pingora handles: request smuggling prevention, H2
backpressure, connection pool safety, HTTP/1.1
upgrade detection and bidirectional forwarding
(WebSocket, etc.).

Praxis handles: hop-by-hop header stripping (with
conditional preservation for upgrade requests),
Host validation, X-Forwarded-* injection, retry
logic.
