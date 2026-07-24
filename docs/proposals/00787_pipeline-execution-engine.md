---
status: retroactive
authors:
  - shaneutt
graduation_criteria: []
stakeholders:
  - shaneutt
---

# Pipeline Execution Engine

## What?

The pipeline execution engine is the runtime core of
Praxis's filter processing. It transforms YAML filter
chain configuration into an executable
`FilterPipeline` - a flat `Vec<PipelineFilter>` that
is invoked on every request. The engine handles HTTP
request/response/body phases, TCP connect/disconnect
phases, conditional branch evaluation, body capability
merging, per-filter metrics, and failure mode
handling.

### Goals

- Flat, allocation-free pipeline representation with
  no runtime chain boundaries
- Symmetric execution: request filters run forward,
  response filters run in reverse over the same list
- Branch chains that add conditional control flow
  without filters knowing about branching
- Pre-computed body capabilities so the protocol
  layer can skip body hooks when no filter needs them
- Per-filter failure mode (open/closed) for graceful
  degradation
- Extension point for injecting pipeline-scoped
  resources into per-request state

## Why?

### Motivation

A proxy filter pipeline must be both flexible (varied
filter compositions per listener) and fast (zero
unnecessary allocation on the request path). The
execution engine solves three problems:

1. **Config-time composition, runtime simplicity.**
   Operators compose named chains in YAML. At
   startup, chains are concatenated and flattened
   into a single vector. Runtime execution is a
   simple index-advancing while loop with no HashMap
   lookups or dynamic dispatch beyond the filter
   trait itself.

2. **Conditional branching without filter coupling.**
   Filters need to influence pipeline flow (retries,
   fallbacks, cache hit/miss paths) without importing
   branch types. The engine introduces
   `FilterResultSet` as a decoupled feedback channel:
   filters write key-value pairs, and the engine
   reads them to evaluate branch conditions. Filters
   remain branch-unaware.

3. **Body capability negotiation.** Different filters
   require different body access modes (streaming,
   buffered, read-only, read-write). The engine
   pre-computes merged capabilities at build time so
   the protocol adapter can configure Pingora's body
   handling once, rather than re-negotiating per
   chunk.

### User Stories

- As a proxy operator, I want to define filter chains
  in YAML and have them execute as a single optimized
  pipeline per listener.
- As a filter author, I want to signal outcomes
  (cache hit, policy decision) without knowing how
  the pipeline will branch on those outcomes.
- As a platform engineer, I want body buffering
  limits enforced automatically based on which
  filters are in the pipeline.

## How?

### Design

The engine is implemented across ten modules under
`filter/src/pipeline/`. This section documents the
shipped design.

#### FilterPipeline Structure

`FilterPipeline` is the top-level type. Its core
field is `filters: Vec<PipelineFilter>`, plus
pre-computed state that is expensive to derive per
request:

```rust
pub struct FilterPipeline {
    body_capabilities: BodyCapabilities,
    compression: Option<CompressionConfig>,
    filters: Vec<PipelineFilter>,
    record_filter_duration_metrics: bool,
    health_registry: Option<HealthRegistry>,
    id_generator: Arc<IdGenerator>,
    kv_stores: Option<KvStoreRegistry>,
    pipeline_extensions: Vec<Box<dyn PipelineExtension>>,
    time_source: Arc<dyn TimeSource>,
}
```

The pipeline is built once at startup (or on config
reload) and shared across request handlers via
`Arc<ArcSwap<FilterPipeline>>`. Handlers load a
snapshot for each request; in-flight requests are
unaffected by swaps.

#### PipelineFilter Wrapping

Each filter in the vector is wrapped in
`PipelineFilter`, which bundles execution metadata:

- `filter: AnyFilter` - the `HttpFilter` or
  `TcpFilter` trait object
- `conditions: Vec<Condition>` - request-phase skip
  conditions (`when`/`unless`)
- `response_conditions: Vec<ResponseCondition>` -
  response-phase skip conditions
- `branches: Vec<ResolvedBranch>` - resolved branch
  chains evaluated after this filter runs
- `failure_mode: FailureMode` - `Open` (swallow
  errors) or `Closed` (propagate errors)
- `filter_id: usize` - monotonically assigned at
  build time; used as the key for per-request filter
  state so multiple instances of the same filter type
  get independent state
- `name: Option<Arc<str>>` - user-assigned name from
  YAML, used for branch rejoin targeting (distinct
  from `filter.name()` which returns the type name)

#### Construction

Two build paths exist:

- `FilterPipeline::build()` - simple path without
  branch resolution. Instantiates filters from
  `FilterEntry` slices via the `FilterRegistry` and
  computes body capabilities.
- `FilterPipeline::build_with_chains()` - branch-
  aware path. Delegates to
  `build_branch::resolve_chain_filters()` which
  recursively resolves `BranchChainConfig` entries
  into runtime `ResolvedBranch` types.

Both paths end at `from_filters()`, which computes
`BodyCapabilities`, extracts compression config, and
initializes shared resources.

After construction, the server layer attaches:
health registry, KV stores, ID generator, insecure
options, body limits, and pipeline extensions.

#### Ordering Validation

`ordering_errors()` runs structural checks at
startup and on reload, each individually skippable
via `SkipPipelineChecks`:

- Load balancer without a preceding cluster selector
- Unconditional `static_response` blocking later
  filters
- Security filters with request conditions (bypass
  risk)
- Security filters with `failure_mode: open`
- Duplicate routers or load balancers
- Conflicting cluster selectors before a load
  balancer
- Cluster name mismatches between selectors and load
  balancers
- Duplicate path rewrite filters
- `SkipTo` branches that bypass security filters

`ordering_warnings()` detects non-fatal issues like
all routers being conditional with no fallback.

### HTTP Execution

The HTTP path has four phases, each a method on
`FilterPipeline`.

**`execute_http_request`** - runs filters forward
(index 0 to N) in a while loop:

1. Skip TCP filters (wrong variant)
2. Evaluate request conditions; skip if unmet
3. Set `ctx.current_filter_id` for state access
4. Call `on_request` via `run_request_filter` (with
   optional duration metrics)
5. On `Reject`, return immediately
6. Mark the filter index as executed
7. Evaluate branch chains via `evaluate_branches`
8. Handle `BranchOutcome`: `Continue` advances,
   `SkipTo` jumps forward, `ReEnter` loops back
   (clearing executed indices), `Terminal` stops,
   `Reject` aborts

The `executed_filter_indices` bitvector tracks which
filters ran, so the response phase can skip filters
that were bypassed.

**`execute_http_response`** - runs filters in
reverse (N to 0):

1. Skip filters not marked in
   `executed_filter_indices`
2. Skip TCP filters
3. Evaluate response conditions; skip if unmet
4. Call `on_response` via `run_response_filter`
5. Track whether response headers were modified

**`execute_http_request_body`** - runs body filters
forward:

1. Skip filters marked `body_done`
2. Check `request_body_access() != None`
3. Check request conditions
4. Call `on_request_body` via
   `run_request_body_filter`
5. Handle `BodyDone` (mark, skip on future chunks),
   `Release`, `Reject`

**`execute_http_response_body`** - runs body
filters in reverse with the same `BodyDone` tracking.
An alternative entry point
`execute_http_response_body_with_response_header`
accepts an explicit response header for evaluating
`response_conditions` after the protocol layer has
left the response-header phase.

### TCP Execution

TCP execution is simpler - no conditions, no
branches, no body phases:

- `execute_tcp_connect` - runs `TcpFilter::on_connect`
  forward, stopping on `Reject`
- `execute_tcp_disconnect` - runs
  `TcpFilter::on_disconnect` in reverse

Both phases skip HTTP filter variants and apply
failure mode handling. TCP filters with conditions
or branch chains in YAML produce build-time warnings
since those features are ignored at runtime.

### Branch Evaluation

Branch evaluation is documented in detail in
[proposal 00036][p36]. The execution engine
integrates it as follows.

After each filter executes in `execute_http_request`,
`evaluate_branches()` is called with the filter's
resolved branches. The function:

1. Iterates branches in order (first-match-wins)
2. Checks `on_result` condition against
   `ctx.filter_results` via `should_branch_fire()`
3. Checks re-entrance limits via
   `check_reentrance_limit()` (iteration count
   tracked in `ctx.branch_iterations`)
4. Executes the branch's filter list sequentially
5. Maps the rejoin target to a `BranchOutcome`:
   - `Next` - continue to next filter
   - `Terminal` - stop the parent chain
   - `SkipTo(idx)` - jump forward in parent
   - `ReEnter(idx)` - loop back; clears
     `filter_results` to prevent stale triggers

Nested branches are evaluated recursively. Nested
`SkipTo` and `ReEnter` outcomes are discarded
(logged as warnings) because they reference parent
pipeline indices. Only `Terminal` and `Reject`
propagate upward.

After all branches on a filter are evaluated,
`ctx.filter_results` is cleared so stale results do
not affect subsequent filters.

Branch sub-chains only execute `on_request`; body
hooks (`on_request_body`, `on_response_body`) are
not invoked for filters inside branches. Body-
transforming filters must be in the main pipeline
path.

### Body Capabilities

At build time, `compute_body_capabilities()` scans
every filter's `BodyAccess` and `BodyMode`
declarations (including recursing into branches) to
produce a single `BodyCapabilities`:

- `needs_request_body` / `needs_response_body` -
  whether body hooks should be called at all
- `request_body_mode` / `response_body_mode` - the
  merged delivery mode
- `any_request_body_writer` /
  `any_response_body_writer` - whether any filter
  writes to the body
- `needs_request_context` - whether original request
  headers are needed during body phases
- `any_response_body_condition` /
  `any_response_condition_uses_headers` - whether
  response conditions need header snapshots

**Mode merging** follows a precedence rule:
`StreamBuffer` > `SizeLimit` > `Stream`. When two
`StreamBuffer` modes merge, the larger `max_bytes`
limit wins so every filter gets enough buffer. `None`
(unbounded) beats any finite limit.

After build, `apply_body_limits()` enforces global
size ceilings. For `Stream` mode with no filter-
declared body access, it converts to `SizeLimit`.
For `StreamBuffer`, it tightens the limit to the
ceiling. Unbounded `StreamBuffer` without explicit
opt-in is rejected at startup.

Three `BodyMode` variants exist:

- `Stream` - deliver chunks as they arrive; low
  latency, low memory
- `SizeLimit { max_bytes }` - enforce a size ceiling
  without buffering (rejects oversized bodies)
- `StreamBuffer { max_bytes }` - accumulate chunks,
  defer upstream forwarding until `Release` or
  end-of-stream; enables body transformation

### Metrics Integration

When `record_filter_duration_metrics` is enabled,
each filter hook invocation is timed and recorded via
`record_filter_duration()` with dimensions:

- Filter name (type name)
- Phase: `request` or `response`
- Stream: `headers` or `body`

The measurement wraps the actual filter call with
`Instant::now()` / `elapsed()` and records
`as_secs_f64()`. Metrics are opt-in per pipeline to
avoid overhead when not needed.

### Extension Points

`PipelineExtension` is a trait for injecting
pipeline-scoped resources into per-request state:

```rust
pub trait PipelineExtension: Send + Sync {
    fn prepare(
        &self,
        extensions: &mut RequestExtensions,
    );
}
```

Extensions are registered after construction via
`add_pipeline_extension()` and called once per
request from `prepare_extensions()`. External filter
crates (e.g., AI filters) use this to attach
pipeline-level singletons (stores, registries,
caches) that their filters retrieve via
`RequestExtensions::get()` during request processing.

### Failure Mode Handling

Every filter has a configurable `FailureMode`:

- `Closed` (default) - errors propagate, aborting
  the pipeline
- `Open` - errors are logged as warnings and
  swallowed; the pipeline continues

`check_failure_mode()` is the shared dispatcher
used by all execution paths (HTTP request, response,
body, TCP, and branch evaluation).

### Implementation

- `filter/src/pipeline/mod.rs` -
  `FilterPipeline` struct, body limit utilities,
  failure mode dispatcher
- `filter/src/pipeline/build.rs` -
  `build()` and `build_with_chains()` constructors,
  ordering validation
- `filter/src/pipeline/build_branch.rs` -
  recursive branch resolution from config to runtime
  types
- `filter/src/pipeline/http.rs` -
  HTTP request, response, and body execution loops
- `filter/src/pipeline/http_utils.rs` -
  per-filter dispatch, metrics, condition evaluation
- `filter/src/pipeline/tcp.rs` -
  TCP connect/disconnect execution
- `filter/src/pipeline/evaluate.rs` -
  branch condition checking and dispatch
- `filter/src/pipeline/branch.rs` -
  `ResolvedBranch`, `RejoinTarget`, `BranchOutcome`
- `filter/src/pipeline/filter.rs` -
  `PipelineFilter` wrapper type
- `filter/src/pipeline/body.rs` -
  body capability computation and mode merging
- `filter/src/pipeline/checks.rs` -
  ordering validation checks
- `filter/src/pipeline/extension.rs` -
  `PipelineExtension` trait

[p36]: 00036_branch-chains.md
