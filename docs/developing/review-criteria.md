# Deep Review Criteria

Criteria for periodic, whole-subsystem review passes (audits, pre-release
reviews, agent-driven analysis) that look for latent defects, drift, and
structural improvements. Per-change style and mechanics are in
[Conventions](conventions.md). File findings as issues or proposals; fixes
follow the normal [test requirements](conventions.md#testing).

## 1. Protocol Correctness and the Pingora Boundary

A proxy's worst bugs are silent protocol violations. Praxis splits
responsibility with Pingora (see
[HTTP Correctness](../architecture/http-correctness.md)), and that boundary
drifts as Pingora versions change.

- Verify every "Pingora handles this" claim (smuggling prevention,
  backpressure, pool safety, upgrade handling) against the *pinned* Pingora
  version in `Cargo.toml`, not memory or old docs.
- Check the Praxis-owned invariants end to end: hop-by-hop stripping on both
  paths, `Host` validation, `x-praxis-*` reserved-header rejection and
  stripping in *both* directions (`crates/core/src/reserved_headers.rs`,
  `crates/protocol/src/http/`).
- Retries replay only idempotent methods, or when the upstream provably
  processed nothing: a stale pooled connection (Pingora `ReusedOnly`) is
  replayable for any method, a truncated replay buffer never is.
- Each RFC-specified behavior needs a conformance test in `tests/conformance/`
  citing the RFC section; gaps are findings.
- Edge cases: duplicate or conflicting headers, obs-fold, absolute-form request
  targets, a `Connection` header listing custom hop-by-hop names, 1xx
  responses, trailers, upgrade requests mixed with body filters.

## 2. Hot-Path Performance

The request path (`crates/filter/src/pipeline/evaluate.rs`,
`crates/filter/src/pipeline/http.rs`, `crates/protocol/src/http/`) runs on
every request; the config path runs once. Hold them to different standards.

- Per-request allocations and clones: header maps, path strings, `String`
  formatting. Prefer borrowing and `bytes::Bytes` reuse.
- Regexes, path matchers, lowercased header names, and route tables are
  compiled when the pipeline is built (`crates/filter/src/pipeline/build.rs`),
  never per request.
- Any `Mutex`/`RwLock` on the request path is suspect; prefer per-request
  context or atomics. Call `ArcSwap::load` once per request, not per filter.
- Linear scans that grow with config size (filter lists, route tables, SNI
  names) are fine at small N; flag O(filters × headers) or worse.
- Check that the scenario benchmarks (`cargo xtask benchmark`) still cover the
  filters most configs enable. A hot-path change without a benchmark delta is
  unverified.

## 3. Resource Bounds and DoS Resilience

Every buffer, queue, and map that grows with client input needs an explicit
bound and a defined behavior at the bound.

- Every `BodyMode::Buffer` user respects
  `crates/core/src/config/body_limits.rs`, enforced *while streaming in*, not
  after assembly (`crates/filter/src/body/`).
- Unbounded growth: KV stores (`crates/core/src/kv/`), rate-limit and
  circuit-breaker state, health registries, metrics label sets. What evicts
  entries? What is the cardinality under hostile input (e.g. per-IP keys from
  spoofable headers)?
- Bounded channels only, and every spawned task (watcher, health checks, log
  writers) has an owner that cancels it.
- Connect, read, write, and total timeouts on both TCP and HTTP paths:
  `docs/architecture/tcp-proxy.md` documents the intended layering; confirm
  each layer is wired.
- Slowloris-style clients, oversized headers, and pathological chunk sizes
  belong in `tests/security/` and `tests/resilience/`; missing cases are
  findings.

## 4. Streaming Discipline

Streaming and SSE traffic must not be quietly buffered; violations creep in
through convenience.

- Grep payload-processing filters
  (`crates/filter/src/builtins/http/payload_processing/`) for full-body
  assembly on paths that should be `BodyMode::Stream`.
- Filters that inspect or rewrite bodies handle tokens split across chunks
  (the `json_body_field` stream extraction is the model).
- Incremental processing keeps the producer coupled to the consumer: no
  read-all-then-forward loops, no intermediate unbounded queues.
- Response-body filters inside branch chains do not run (`on_request` only);
  confirm no config can silently rely on one.

## 5. Security Invariants

Review as an attacker who controls client traffic, backend responses, and
part of the config.

- Trust boundaries: `forwarded_headers` trust settings, IP-based ACLs fed by
  spoofable inputs, anything reading `X-Forwarded-*` before trust is
  established.
- Injection: header values flowing into logs, error responses, or rewritten
  paths. `crates/filter/src/builtins/http/value_safety.rs` is the chokepoint;
  find writes that bypass it.
- TLS: SNI resolution including wildcard precedence (`crates/tls/src/sni.rs`),
  client-auth enforcement, cert hot-reload atomicity
  (`crates/tls/src/reload.rs`), and what a reload with a broken cert does.
- Error responses and admin endpoints must not leak internals (paths,
  versions, upstream addresses) to clients; admin surfaces need explicit
  exposure review (`crates/protocol/src/` admin, `crates/server/src/dump.rs`).
- Denied-by-default postures hold. Config knobs that widen behavior
  (`insecure_options.rs`) are opt-in and named accordingly.

## 6. Config Type Design and Validation Completeness

Invalid states are unrepresentable, and anything checkable at startup is not
deferred to request time.

- Audit `crates/core/src/config/` against [Type Design](type-design.md): stray
  `String` where an enum belongs, `Option<T>` + `unwrap_or` where
  `#[serde(default)]` belongs, maps where structs belong, missing
  `deny_unknown_fields`.
- Cross-field invariants live in `crates/core/src/config/validate/`. For each
  config feature, ask what nonsensical combination parses today (e.g. a
  branch chain referencing a chain that buffers bodies, a cluster with zero
  endpoints, a timeout of zero).
- Validation errors name the offending key path and say what would be valid.
  An error that requires reading source code is a defect.
- Every example in `examples/configs/` has a functional test in
  `tests/integration/tests/suite/examples/` that exercises the feature, not
  just parses it.

## 7. Hot Reload and Concurrency Lifecycle

`ArcSwap` swaps, watcher debounce, task respawn, and in-flight drain all
interact here (`crates/server/src/reload.rs`, `crates/server/src/watcher.rs`).

- A request observes exactly one pipeline generation end to end; a second
  `load()` mid-request is a race.
- Health-check tasks, KV stores, and metrics from the previous config are
  cancelled or carried over deliberately, never leaked or double-running.
- Non-reloadable changes (listener topology, protocol, TLS toggle) are
  *detected* by the diff and warned; look for new config fields the diff
  silently misses (`crates/server/src/reload_diagnostics.rs`).
- A config that fails validation, or a cert that fails to load, leaves the old
  state fully intact, including partially-applied side effects.
- Guards across `.await`, task cancellation at shutdown, and drop order of
  runtime handles deserve a dedicated pass; the lints catch only the easy
  cases.

## 8. Error Taxonomy and Failure Modes

- Error enums (`crates/core/src/errors.rs`, `FilterError`) distinguish
  operator errors (bad config), client errors (4xx), and upstream or internal
  errors (5xx). Review any variant, or any `map_err`, that conflates them.
- Every fallible data-plane path has a defined client-visible outcome: which
  status, which body, whether it is retryable, whether the circuit breaker
  counts it.
- When a dependency (upstream, DNS, cert, KV) fails, does the proxy fail open
  or closed, and is that the documented intent per filter?
- No `unwrap`/`expect`/panic paths reachable from request handling; scan for
  `expect(` suppressions and stale `#[expect]` reasons.

## 9. Pipeline and Branch-Chain Semantics

The pipeline engine is the composition kernel; its invariants are easy to
break from a distance.

- Request filters run in declared order, response filters in reverse, and
  short-circuits skip exactly the right hooks, including body hooks on early
  responses.
- Branch chains: rejoin targets, iteration limits, and the `on_request`-only
  restriction (`crates/filter/src/pipeline/branch.rs`, `build_branch.rs`,
  `evaluate.rs`). What can a config express that the executor does not handle
  (cycles, branch-into-branch, rejoining past a terminal filter)?
- Filters stay ignorant of branching (`FilterResultSet`); a filter that reads
  branch state directly is a layering violation.
- New features reuse classifier headers, router matches, conditions, or branch
  chains before inventing a mechanism; flag parallel mechanisms that overlap
  them.

## 10. Observability Quality

- Spans and events on the request path carry the request id and enough
  structure to answer "why did this request get this response?" without a
  debugger.
- Client-controlled values never become metric labels. Every
  traffic-management filter (rate limit, circuit breaker, load balancer)
  exposes the counters an operator needs to see it acting.
- Access logs are complete on every exit path, including short-circuits,
  upstream failures, and streamed responses.
- Runtime narration at `debug`/`trace`, state changes at `info`, actionable
  problems at `warn`/`error`. Hot-path logging is lazy and cheap when
  disabled.

## 11. Test Depth Beyond Coverage

The 97% line-coverage floor proves execution, not correctness. Review what the
suite would *fail to notice*.

- Mutation results (`make mutants`): surviving mutants are missing
  assertions; triage them per subsystem, not globally.
- Every parser, matcher, and encoder (path match, SNI wildcards, condition
  expressions, header canonicalization) has a `proptest` round-trip or
  invariant test; example-only coverage is a gap.
- Reload-under-load, drain-on-swap, and watcher debounce tests belong in
  `tests/resilience/`; a green unit suite says nothing about them.
- Each security claim in the docs has a test proving the *rejection*
  (smuggling attempts, reserved-header injection, oversized bodies).
- A retried test is a masked bug until proven otherwise.

## 12. Public API and Extensibility

- The `HttpFilter`/`TcpFilter` traits and `FilterRegistry` are the extension
  contract: review each trait change for what it forces on downstream
  implementors, and keep `crates/filter/src/extensions.rs` ergonomic for the
  tutorial path.
- Anything `pub` that no external consumer needs is `pub(crate)`;
  `cargo-semver-checks` findings gate releases.
- Every trait method states its call ordering, its relationship to body
  modes, and what a returned action does. The tutorial
  (`docs/developing/http-filter-tutorial.md`) stays buildable against the
  current API.

## 13. Dependency and Supply-Chain Hygiene

- `cargo audit` / `cargo deny` are clean. Review new dependencies against the
  [dependency policy](dependencies.md#policy): reputation, maintenance, and
  whether an existing dependency already covers the need.
- Full semver pins with patch versions, workspace dependencies for version
  consistency, no unused dependencies (`cargo-machete`).
- Dependency default features often pull in more than intended; look for
  `default-features = false` opportunities on heavy deps.

## 14. Documentation–Code Drift

Docs state invariants; code moves, and drift turns docs into misinformation.

- Cross-check numeric claims (coverage floors, size limits, debounce
  intervals, defaults) against the enforcing source (`Makefile`, CI workflows,
  config defaults). Example: `AGENTS.md` once advertised a 95% coverage floor
  while the `Makefile` enforced 97%.
- Cross-check boundary claims: the "Pingora handles / Praxis handles" split,
  filter reference docs (`docs/filters/reference.md`) against `from_config`
  implementations, and `examples/README.md` regeneration
  (`cargo xtask sync-example-readme`).
- Proposals marked implemented match what shipped; divergence is a doc fix or
  a missing follow-up issue.

## Running a Review Pass

Pick **one criterion** and apply it across the codebase, or **one subsystem**
and apply every criterion to it. Sweeping everything at once produces shallow
findings.

For each finding, record the invariant violated, the file and line, a
concrete failure scenario, and the smallest fix that restores the invariant.
Try to prove the code correct before filing.
