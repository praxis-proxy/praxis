# Deep Review Criteria

This document lists the criteria that matter most when
deeply analyzing the Praxis codebase to find improvements.
It complements [Conventions](conventions.md), which governs
per-change style and mechanics: these criteria are for
periodic, whole-subsystem review passes (audits, pre-release
reviews, or agent-driven analysis), where the goal is to
find latent defects, drift, and structural improvements
rather than style issues.

Each criterion states why it matters for a proxy, where to
look, and the questions a reviewer should ask. Findings
should be filed as issues or proposals; fixes follow the
normal [test requirements](conventions.md#testing).

## 1. Protocol Correctness and the Pingora Boundary

A proxy's worst bugs are silent protocol violations. Praxis
deliberately splits responsibility with Pingora (see
[HTTP Correctness](../architecture/http-correctness.md)),
and that boundary is an assumption that drifts as Pingora
versions change.

- Verify every "Pingora handles this" claim (smuggling
  prevention, backpressure, pool safety, upgrade handling)
  against the *pinned* Pingora version in `Cargo.toml`,
  not against memory or old docs.
- Check the Praxis-owned invariants end to end: hop-by-hop
  stripping on both paths, `Host` validation, `x-praxis-*`
  reserved-header rejection and stripping in *both*
  directions (`core/src/reserved_headers.rs`,
  `protocol/src/http/`).
- Retry logic must never replay a request after bytes were
  written upstream, and only for idempotent methods.
- For each RFC-specified behavior, does a conformance test
  in `tests/conformance/` cite the RFC section? Gaps in
  conformance coverage are findings in themselves.
- Edge cases: duplicate/conflicting headers, obs-fold,
  absolute-form request targets, `Connection` header
  listing custom hop-by-hop names, 1xx responses,
  trailers, upgrade requests mixed with body filters.

## 2. Hot-Path Performance

The request path (`filter/src/pipeline/evaluate.rs`,
`filter/src/pipeline/http.rs`, `protocol/src/http/`)
runs on every request; the config path runs once. Review
them to different standards.

- Per-request allocations and clones: header maps, path
  strings, `String` formatting in the hot path. Prefer
  borrowing and `bytes::Bytes` reuse.
- Work that belongs at build time: regexes, path matchers,
  lowercased header names, and route tables must be
  compiled when the pipeline is built
  (`filter/src/pipeline/build.rs`), never per request.
- Locks and shared state: anything `Mutex`/`RwLock` on the
  request path is suspect; prefer per-request context or
  atomics. `ArcSwap::load` once per request, not per
  filter.
- Linear scans that grow with config size (filter lists,
  route tables, SNI names): acceptable at small N, but
  flag any O(filters × headers) or worse pattern.
- Are `benchmarks/` scenarios still representative of the
  filters most configs enable? A hot-path change without a
  benchmark delta is unverified.

## 3. Resource Bounds and DoS Resilience

Every buffer, queue, and map that grows with client input
needs an explicit bound and a defined behavior at the
bound.

- Body buffering: every `BodyMode::Buffer` user must
  respect `core/src/config/body_limits.rs`; verify the
  limit is enforced *while streaming in*, not after
  assembly (`filter/src/body/`).
- Unbounded growth: KV stores (`core/src/kv/`), rate-limit
  and circuit-breaker state, health registries, metrics
  label sets. What evicts entries? What is the cardinality
  under hostile input (e.g. per-IP keys from spoofable
  headers)?
- Channels and tasks: bounded channels only; every spawned
  task must have an owner that cancels it (watcher,
  health checks, log writers).
- Timeouts: connect, read, write, and total limits on both
  TCP and HTTP paths (`docs/architecture/tcp-proxy.md`
  documents the intended layering); confirm each layer is
  actually wired.
- Slowloris-style clients, oversized headers, and
  pathological chunk sizes belong in `tests/security/` and
  `tests/resilience/`; missing cases are findings.

## 4. Streaming Discipline

Streaming and SSE traffic must not be quietly buffered.
This is a standing project rule, and violations tend to
creep in through convenience.

- Grep payload-processing filters for full-body assembly
  on paths that should be `BodyMode::Stream`
  (`filter/src/builtins/http/payload_processing/`).
- Chunk-boundary correctness: filters that inspect or
  rewrite bodies must handle tokens split across chunks
  (the `json_body_field` stream extraction is the model).
- Backpressure: incremental processing must not detach the
  producer from the consumer (no read-all-then-forward
  loops, no intermediate unbounded queues).
- Response-body filters inside branch chains do not run
  (`on_request` only); confirm no config can silently rely
  on one.

## 5. Security Invariants

Praxis is security-first; review as an attacker with
control of client traffic, backend responses, and
(partially) config.

- Trust boundaries: `forwarded_headers` trust settings,
  IP-based ACLs fed by spoofable inputs, and anything that
  reads `X-Forwarded-*` before trust is established.
- Injection surfaces: header values flowing into logs,
  error responses, or rewritten paths
  (`filter/src/builtins/http/value_safety.rs` is the
  chokepoint; find writes that bypass it).
- TLS: SNI resolution including wildcard precedence
  (`tls/src/sni.rs`), client-auth enforcement, cert
  hot-reload atomicity (`tls/src/reload.rs`), and what
  happens when a reload delivers a broken cert.
- Error responses and admin endpoints must not leak
  internals (paths, versions, upstream addresses) to
  clients; admin surfaces need explicit exposure review
  (`protocol/src/` admin, `server/src/dump.rs`).
- Do denied-by-default postures hold? New config knobs
  that widen behavior (`insecure_options.rs`) must be
  opt-in and named accordingly.

## 6. Config Type Design and Validation Completeness

Invalid states should be unrepresentable, and every
invariant that can be checked at startup must not be
deferred to request time.

- Audit `core/src/config/` against
  [Type Design](type-design.md): stray `String` where an
  enum belongs, `Option<T>` + `unwrap_or` where
  `#[serde(default)]` belongs, maps where structs belong,
  missing `deny_unknown_fields`.
- Cross-field invariants live in `core/src/config/validate/`;
  for each config feature, ask "what nonsensical combination
  parses today?" (e.g. a branch chain referencing a chain
  that buffers bodies, a cluster with zero endpoints, a
  timeout of zero).
- Validation errors must name the offending key path and
  say what would be valid. An error that requires reading
  source code is a defect.
- Every example in `examples/configs/` must have a
  functional test in
  `tests/integration/tests/suite/examples/` that exercises
  the feature, not just parses it.

## 7. Hot Reload and Concurrency Lifecycle

Reload is the most concurrency-sensitive subsystem:
`ArcSwap` swaps, watcher debounce, task respawn, and
in-flight drain all interact
(`server/src/reload.rs`, `server/src/watcher.rs`).

- Snapshot discipline: a request must observe exactly one
  pipeline generation end to end. Any second `load()` mid
  request is a race.
- Old-generation cleanup: health-check tasks, KV stores,
  and metrics from the previous config must be cancelled
  or carried over deliberately — never leaked, never
  double-running.
- Non-reloadable changes (listener topology, protocol,
  TLS toggle) must be *detected* by the diff and warned;
  review the diff logic for new config fields it silently
  misses (`server/src/reload_diagnostics.rs`).
- Failure atomicity: a config that fails validation, or a
  cert that fails to load, must leave the old state fully
  intact — including partially-applied side effects.
- Guards across `.await`, task cancellation at shutdown,
  and drop order of runtime handles are worth a dedicated
  pass; the lints catch the easy cases only.

## 8. Error Taxonomy and Failure Modes

- Error enums (`core/src/errors.rs`, `FilterError`) should
  distinguish operator errors (bad config), client errors
  (4xx), and upstream/internal errors (5xx); review any
  variant that conflates them, and any `map_err` that
  erases the distinction.
- Every fallible path on the data plane needs a defined
  client-visible outcome: which status, which body, is it
  retryable, is it counted by the circuit breaker?
- Degradation order: when a dependency (upstream, DNS,
  cert, KV) fails, does the proxy fail open or closed, and
  is that the documented intent per filter?
- No `unwrap`/`expect`/panic paths reachable from request
  handling; scan for `expect(` suppressions and stale
  `#[expect]` reasons.

## 9. Pipeline and Branch-Chain Semantics

The pipeline engine is the composition kernel; its
invariants are easy to break from a distance.

- Ordering: request filters in declared order, response
  filters in reverse, short-circuits skip exactly the
  right hooks — including body hooks on early responses.
- Branch chains: rejoin targets, iteration limits, and the
  `on_request`-only restriction
  (`filter/src/pipeline/branch.rs`,
  `build_branch.rs`, `evaluate.rs`). Ask what a config can
  express that the executor does not handle (cycles,
  branch-into-branch, rejoining past a terminal filter).
- `FilterResultSet` coupling: filters must stay ignorant
  of branching; any filter that reads branch state directly
  is a layering violation.
- Routing vs pipelining: new features must reuse
  classifier headers, router matches, conditions, or
  branch chains before inventing a new mechanism; flag
  parallel mechanisms that overlap these.

## 10. Observability Quality

- Spans and events on the request path should carry the
  request id and enough structure to answer "why did this
  request get this response?" without a debugger.
- Metrics: review label cardinality (client-controlled
  values must never become labels), and check that every
  traffic-management filter (rate limit, circuit breaker,
  load balancer) exposes the counters an operator needs
  to see it acting.
- Access logs must be complete under every exit path:
  short-circuits, upstream failures, and streamed
  responses included.
- Log levels: runtime narration at `debug`/`trace`, state
  changes at `info`, actionable problems at `warn`/`error`;
  hot-path logging must be lazy and cheap when disabled.

## 11. Test Depth Beyond Coverage

The 96% line-coverage floor proves execution, not
correctness. Review what the suite would *fail to notice*.

- Mutation results (`make mutants`): surviving mutants are
  missing assertions; triage them per subsystem rather
  than globally.
- Property tests: every parser, matcher, and encoder
  (path match, SNI wildcards, condition expressions,
  header canonicalization) should have a `proptest`
  round-trip or invariant test; example-only coverage is a
  gap.
- Concurrency tests: reload-under-load, drain-on-swap, and
  watcher debounce belong in `tests/resilience/`; a green
  unit suite says nothing about them.
- Negative-space tests: for each security claim in the
  docs, a test must prove the *rejection* (smuggling
  attempts, reserved-header injection, oversized bodies).
- Flake honesty: a retried test is a masked bug until
  proven otherwise.

## 12. Public API and Extensibility

- The `HttpFilter`/`TcpFilter` traits and
  `FilterRegistry` are the extension contract: review each
  trait change for what it forces on downstream
  implementors, and keep `filter/src/extensions.rs`
  ergonomic for the tutorial path.
- Public surface minimalism: anything `pub` that no
  external consumer needs should be `pub(crate)`;
  `cargo-semver-checks` findings gate releases.
- Doc quality at the contract: every trait method should
  state its call ordering, its relationship to body modes,
  and what a returned action does — the tutorial
  (`docs/filters/http-filter-tutorial.md`) must stay
  buildable against the current API.

## 13. Dependency and Supply-Chain Hygiene

- `cargo audit` / `cargo deny` must be clean; review new
  dependencies for reputation, maintenance, and whether
  existing dependencies already cover the need.
- Full semver pins with patch versions, workspace
  dependencies for version consistency, and no unused
  dependencies (`cargo-machete`).
- Feature-flag surface: default features of dependencies
  pull in more than intended surprisingly often; audit
  `default-features = false` opportunities on heavy deps.

## 14. Documentation–Code Drift

Docs state invariants; code moves. Drift converts
documentation into misinformation.

- Cross-check numeric claims (coverage floors, size
  limits, debounce intervals, defaults) against the
  enforcing source (`Makefile`, CI workflows, config
  defaults). Example of the failure mode: `AGENTS.md`
  advertised a 95% coverage floor while the `Makefile`
  enforced 96%.
- Cross-check boundary claims: the "Pingora handles /
  Praxis handles" split, filter reference docs
  (`docs/filters/reference.md`) vs `from_config`
  implementations, and `examples/README.md` regeneration
  (`cargo xtask sync-example-readme`).
- Proposals marked implemented must match what shipped;
  divergence is either a doc fix or a missing follow-up
  issue.

## Running a Review Pass

A useful deep review picks **one criterion** and applies it
across the codebase, or picks **one subsystem** and applies
every criterion to it. Sweeping everything at once produces
shallow findings.

For each finding, record: the invariant violated, the file
and line, concrete failure scenario, and the smallest fix
that restores the invariant. Verify findings adversarially
(try to prove the code correct) before filing them.
