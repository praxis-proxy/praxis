# Filters

## Filter Model

A filter inspects or transforms traffic at one point in the request/response
lifecycle. Filters are chained into pipelines: the pipeline calls each filter
in order on requests and in reverse on responses.

New to filter development? The
[HTTP Filter Tutorial](../developing/http-filter-tutorial.md) builds,
registers, tests, and runs a small filter end to end. For listener and chain
resolution, see the [architecture overview](../architecture/overview.md).

### Lifecycle Hooks

| Hook | Direction | Phase |
| --- | --- | --- |
| `on_request_head` | Forward (pipeline order), at most once | Request head, before any `stream_buffer` pre-read and before the request phase (top-level filters only) |
| `on_request` | Forward (pipeline order) | Request |
| `on_response` | Reverse (pipeline order) | Response |
| `on_request_body` | Forward | Request body chunks |
| `on_bound_upstream_request_body` | Forward, at most once | Complete body after logical binding, before endpoint selection (experimental `bound-upstream-request-body` builds only) |
| `on_selected_upstream_request_body` | Forward, per exchange | Complete body after endpoint selection |
| `on_response_body` | Reverse | Response body chunks |

`on_request_head` runs once, before any body is read, for filters that opt in
via `runs_request_head`. Only top-level filters run it: a filter nested in a
branch chain never does (a `head_classifier` placed there silently does
nothing). A head filter inside an `iterative_request_router` step is rejected
at config build, because the head phase runs once at ingress and never inside
an iterative exchange, unless it declares `repeats_request_head` (its
`on_request` does the same work). What the head hook publishes (extensions,
metadata, filter results, trusted header mutations) is visible to a later
`stream_buffer` pre-read and to the request phase.

A filter whose head hook may reject the request, such as an admission check,
declares `admits_at_request_head`. The pipeline skips that head hook, and the
filter admits in `on_request` instead, in two cases:

- An earlier top-level filter, or a filter in one of its branches, can end the
  request in its request phase: one that answers, like `static_response` or
  `redirect`, or any filter that does not declare `may_end_request` false (as
  `forwarded_headers` and `headers` do). This keeps the earlier filter
  running first. A `stream_buffer` pre-read runs body hooks before any
  request phase, so the pipeline holds the admitting filter's body-phase
  rejection until the request phase reaches it, and runs no later body hook.
- The filter has request `conditions`. Admitting in `on_request` lets those
  conditions see the headers head filters publish. A pre-read still runs its
  body hook first when the conditions already match.

The `policy` filter uses the head phase this way: where it can, it
rate-limits and authenticates before any filter reads the body. When a route
replaces or extends authentication in a way the head can't match, the head
only rate-limits, and identity waits for the route with the body buffered
until then; see [`policy`](http/security/policy.md).

Request `conditions` gate `on_request` and the ordinary body hooks;
`response_conditions` gate only the response hooks. A filter skipped on
request is also skipped on response and on every body hook, ordinary and
selected-upstream. There are two exceptions:

- A `stream_buffer` pre-read runs the request-body hooks *before* the request
  phase. Request conditions are evaluated then, but no branch has run yet, so
  a filter that `SkipTo` later skips still runs its body hook.
- The bound-upstream body hook's conditions are evaluated at the freeze, right
  after the binding router. A later top-level participant receives the body
  before its own `on_request` position, so a condition on a header or result
  that a later filter would produce does not match: that filter has not run
  yet.

Filters that need the logical route declare
`bound_upstream_request_body_access` and implement
`on_bound_upstream_request_body` (experimental `bound-upstream-request-body`
build feature). The hook runs at most once, after the binding router freezes
`BoundUpstream`. A read-write participant replaces the canonical body used by
direct dispatch, IRR, retries, and selected-upstream adaptation. Use
`binds_upstream`, `consumes_bound_upstream`, `bound_upstream_clusters`,
`declared_cluster_metadata`, and `nested_bound_upstream_readers` only for
routing filters whose capabilities must be visible to pipeline validation.

A filter may declare both `request_body_access` (pre-read) and
`bound_upstream_request_body_access` (the barrier). Core picks one effective
phase per filter from whether it carries a `bound_upstream` request condition,
and runs the hook only in that phase:

| Declared access | Has `bound_upstream` condition | Runs at |
| --- | --- | --- |
| Pre-read only | No | pre-read (`on_request_body`) |
| Pre-read only | Yes | rejected at load |
| Bound-upstream only | Either | barrier (`on_bound_upstream_request_body`) |
| Both | No | pre-read (`on_request_body`) |
| Both | Yes | barrier (`on_bound_upstream_request_body`) |

### Common Patterns

[`examples/configs/`] has a working example of every pattern, including:

- Host-based routing: [hosts.yaml]
- Path-based routing with rewriting: [path-based-routing.yaml]
- Security chain (guardrails + IP ACL): [guardrails.yaml], [ip-acl.yaml]
- Rate limiting with headers: [rate-limiting.yaml]
- Composed filter chains: [composed-chains.yaml]
- Conditional filters: [conditional-filters.yaml]
- Production gateway: [production-gateway.yaml]

[`examples/configs/`]: ../../examples/configs/
[hosts.yaml]: ../../examples/configs/traffic-management/hosts.yaml
[path-based-routing.yaml]: ../../examples/configs/traffic-management/path-based-routing.yaml
[guardrails.yaml]: ../../examples/configs/security/guardrails.yaml
[ip-acl.yaml]: ../../examples/configs/security/ip-acl.yaml
[rate-limiting.yaml]: ../../examples/configs/traffic-management/rate-limiting.yaml
[composed-chains.yaml]: ../../examples/configs/pipeline/composed-chains.yaml
[conditional-filters.yaml]: ../../examples/configs/pipeline/conditional-filters.yaml
[production-gateway.yaml]: ../../examples/configs/operations/production-gateway.yaml
[inherited-conditions.yaml]: ../../examples/configs/pipeline/inherited-conditions.yaml

## Filter Chains (Pipelining)

Filter chains are named groups of filters defined at the top level of the
config. A listener references one or more chains by name, and their filters
are concatenated in order into that listener's pipeline, so a "security" chain
can serve every public listener while internal listeners skip it. This
config-time assembly is **pipelining**: it decides *what processing* a request
receives. **Routing** is separate: the `router` filter picks an upstream
cluster at request time.

[Pipeline Concepts](../architecture/pipeline-concepts.md) explains how chains
become a pipeline; [Branch Chains](branch-chains.md) covers conditional
branching inside one.

### Inherited Chain Conditions

A chain-level `conditions:` block is inherited by every filter in the chain,
so a shared gate is written once:

```yaml
filter_chains:
  - name: api-enrichment
    conditions:
      - when:
          path_prefix: "/api/"
    filters:
      - filter: json_body_field
        field: model
        header: X-Model
        conditions:
          - when:
              methods: ["POST"]
      - filter: headers
        response_set:
          - name: "X-Enriched"
            value: "true"
```

Chain conditions are prepended to each filter's own conditions and ANDed
with them (effective = chain AND filter). Here `json_body_field` runs only for
`/api/` paths and `POST`, while `headers` runs on any `/api/` request.
Because a request-phase condition gates a filter's request and response hooks,
the inherited condition skips every hook in the chain (request-body promotion
and response tagging alike) for non-matching traffic.

Listener-wide effects are not gated. A `StreamBuffer` body filter in a gated
chain still buffers and size-limits every request (or response) body on the
listener, and `compression` still applies to every eligible response. In this
example, `json_body_field` pre-reads even `/health` request bodies to end of
stream before forwarding.

Chain-level conditions get the same well-formedness and metadata validation
as per-filter conditions and behave exactly like conditions repeated on each
filter, so existing configs are unaffected. Inheritance applies wherever a
named chain is expanded: from a listener's `filter_chains`, and from named
references in branch chains and outbound bindings. Only request-phase
conditions are inherited. A branch child still runs `on_request` and
`on_response` but not `on_request_body` or `on_response_body`. See
[inherited-conditions.yaml].

### Protocol-Specific Filters

Every filter belongs to exactly one protocol level. HTTP filters implement
`HttpFilter` (`on_request`, `on_response`, body hooks); TCP filters implement
`TcpFilter` (`on_connect`, `on_disconnect`). No filter operates at both
levels. Built-in filters are organized by protocol, then category:

```text
builtins/
  http/                       HTTP protocol filters
    observability/            Access logs, request IDs, trace context
    payload_processing/       Compression, JSON body rewrite, body field extraction, JSON-RPC, gRPC-Web
    security/                 Basic auth, CORS, credential injection, CSRF, forwarded headers, guardrails, IP ACL, peer identity trust, policy
    traffic_management/       Circuit breaker, endpoint selector, gRPC detection, gRPC deadlines, iterative request router, load balancer, rate limit, redirect, router, sticky sessions, static response, timeout
    transformation/           gRPC error envelope, header, path rewrite, URL rewrite
  tcp/                        TCP protocol filters
    observability/            Connection logging
    traffic_management/       SNI router, TCP load balancer
```

HTTP execution (`execute_http_request`, `execute_http_response`, body hooks)
calls only HTTP filters; TCP execution (`execute_tcp_connect`,
`execute_tcp_disconnect`) calls only TCP filters. Each skips the other kind's
entries.

An HTTP listener's protocol stack includes TCP, so it accepts both kinds of
filter; a TCP listener accepts only TCP filters. Validation enforces this via
`ProtocolKind::supports()`.

| Listener Protocol | HTTP Filters | TCP Filters |
| --- | --- | --- |
| `http` (default) | Yes | Yes |
| `tcp` | No | Yes |

## What Stays Outside Filters

- TCP/TLS, HTTP framing, connection pooling: adapters
- Config loading and validation: `praxis-core`
- Pipeline executor and `HttpFilterContext`: `praxis-filter`

## HttpFilter Trait

Every HTTP behavior in Praxis is an `HttpFilter`:

```rust
#[async_trait]
pub trait HttpFilter: Send + Sync {
    fn name(&self) -> &'static str;
    async fn on_request(
        &self, ctx: &mut HttpFilterContext<'_>,
    ) -> Result<FilterAction, FilterError>;
    async fn on_response(
        &self, ctx: &mut HttpFilterContext<'_>,
    ) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }
    // Body hooks and access/mode methods omitted for
    // brevity; see "Body Access" section below.
}
```

The body access, body mode, and body hook methods are under
[Body Access](#body-access-http-only).

## TcpFilter Trait

```rust
#[async_trait]
pub trait TcpFilter: Send + Sync {
    fn name(&self) -> &'static str;
    async fn on_connect(
        &self, ctx: &mut TcpFilterContext<'_>,
    ) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }
    async fn on_disconnect(
        &self, ctx: &mut TcpFilterContext<'_>,
    ) -> Result<(), FilterError> {
        Ok(())
    }
}
```

`on_connect` fires when a TCP connection is accepted and `on_disconnect` when
it closes. Both default to passing through.

## FilterAction

Every filter hook returns a `FilterAction`:

- `Continue`: pass to the next filter.
- `Reject(rejection)`: stop the pipeline and respond now (status code,
  optional headers and body). Used by `static_response`, `redirect`,
  `rate_limit`, `guardrails`, `cors` preflight, and similar filters.
- `Release`: forward accumulated `StreamBuffer` data to upstream. Behaves as
  `Continue` outside `StreamBuffer` mode.
- `BodyDone`: this filter has finished body processing. Later body chunks skip
  it while other filters continue normally.

```rust
FilterAction::Reject(Rejection::status(429)
    .with_header("Retry-After", "60")
    .with_body(b"rate limit exceeded" as &[u8]))
```

## HttpFilterContext

Shared state flowing through HTTP filters for a request:

```rust
pub struct HttpFilterContext<'a> {
    pub client_addr: Option<IpAddr>,
    pub cluster: Option<Arc<str>>,
    pub downstream_tls: bool,
    pub extensions: RequestExtensions,
    pub extra_request_headers: Vec<(Cow<'static, str>, String)>,
    pub filter_metadata: FilterMetadata,
    pub filter_results: HashMap<&'static str, FilterResultSet>,
    pub filter_state: HashMap<usize, Box<dyn Any + Send + Sync>>,
    pub health_registry: Option<&'a HealthRegistry>,
    pub id_generator: &'a IdGenerator,
    pub kv_stores: Option<&'a KvStoreRegistry>,
    pub pre_read_mutations: Vec<TrustedHeaderMutation>,
    pub request: &'a Request,
    pub request_body_bytes: u64,
    pub request_body_mode: BodyMode,
    pub request_headers_to_remove: Vec<HeaderName>,
    pub request_headers_to_set: Vec<(HeaderName, HeaderValue)>,
    pub request_start: Instant,
    pub response_body_bytes: u64,
    pub response_body_mode: BodyMode,
    pub response_header: Option<&'a mut Response>,
    pub response_headers_modified: bool,
    pub rewritten_path: Option<String>,
    pub selected_endpoint_index: Option<usize>,
    pub structured_metadata: HashMap<String, serde_json::Value>,
    pub time_source: &'a dyn TimeSource,
    pub upstream: Option<Upstream>,
    // Internal pipeline tracking fields omitted.
}
```

The fields filters most often read or write:

- `request` is the method, URI, and headers. `client_addr` is the downstream
  IP from the TCP connection, `downstream_tls` says whether the client
  connection uses TLS, and `health_registry` holds endpoint health state.
- `ctx.cluster` and `ctx.upstream` select the upstream cluster and a specific
  endpoint. Earlier filters may already have set them.
- `ctx.rewritten_path` rewrites the upstream request path, and the router
  routes on it (see [Rewrite and Routing
  Interaction](#rewrite-and-routing-interaction)).
- `ctx.extra_request_headers`, `ctx.request_headers_to_set`, and
  `ctx.request_headers_to_remove` inject, overwrite, and remove upstream
  request headers.
- `ctx.filter_metadata` holds durable per-request metadata (`FilterMetadata`:
  keys up to 64 bytes, values up to 256 bytes, at most 128 entries).
- `ctx.filter_results` holds key-value results for
  [branch chain](branch-chains.md) evaluation, keyed by the filter's type name
  (the return value of `HttpFilter::name()`). See
  [Pipeline Concepts: Filter Results](../architecture/pipeline-concepts.md#filter-results)
  for the full lifecycle.
- `ctx.response_header` holds the response status and headers, only in the
  response phase; `on_response` can mutate it directly.
  `ctx.response_headers_modified` is an optional hint that response headers
  changed. It isn't needed for correctness: the protocol layer detects changes
  on its own.

Body chunks reach a filter only if it declares `BodyAccess::ReadOnly` or
`BodyAccess::ReadWrite`.

## TcpFilterContext

Per-connection state for TCP filters:

```rust
pub struct TcpFilterContext<'a> {
    pub remote_addr: &'a str,
    pub local_addr: &'a str,
    pub sni: Option<&'a str>,
    pub upstream_addr: Option<Cow<'a, str>>,
    pub cluster: Option<Arc<str>>,
    pub connect_time: Instant,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub health_registry: Option<&'a HealthRegistry>,
    pub kv_stores: Option<&'a KvStoreRegistry>,
}
```

The TCP proxy fills `sni` by peeking at the first bytes of a TLS connection
and extracting the SNI hostname from the ClientHello; filters like
`sni_router` use it to select an upstream. `upstream_addr` is `None` until a
static upstream or a filter provides one, and filters can replace it with an
owned value. `cluster` names the selected cluster, and `health_registry` /
`kv_stores` give access to shared runtime state.

## AnyFilter

`AnyFilter` wraps both kinds for storage in a unified registry and pipeline:

```rust
pub enum AnyFilter {
    Http(Box<dyn HttpFilter>),
    Tcp(Box<dyn TcpFilter>),
}
```

Each variant reports its `protocol_level()` as `ProtocolKind::Http` or
`ProtocolKind::Tcp`.

## Body Access (HTTP only)

Filters see headers only, unless they opt in:

```rust
fn request_body_access(&self) -> BodyAccess {
    BodyAccess::ReadOnly(BodyRequirement::Optional) // or ReadWrite(...)
}
```

| Access           | Hooks? | Modify? |
| ---------------- | ------ | ------- |
| `None` (default) | No     | No      |
| `ReadOnly(requirement)`  | Yes | No  |
| `ReadWrite(requirement)` | Yes | Yes |

`requirement` is `BodyRequirement::Optional` or `BodyRequirement::Required`.
`Required` also prevents an admitted opaque WebSocket tunnel from bypassing
that selected HTTP body processing. See the
[filter extension guide](../developing/extensions.md#declare-body-access-accurately).

### Body Mode

| Mode                          | Behavior        | Use case                  |
| ----------------------------- | --------------- | ------------------------- |
| `Stream` (default)            | Per chunk       | Logging, transforms       |
| `StreamBuffer { max_bytes }`  | Deferred stream | Inspection before forward |
| `SizeLimit { max_bytes }`     | Stream + ceiling | Global size enforcement  |

Precedence: `StreamBuffer` > `SizeLimit` > `Stream`.

`StreamBuffer` gives filters each chunk as it arrives, like `Stream`, but the
protocol layer accumulates the chunks and forwards nothing upstream until a
filter returns `FilterAction::Release` from `on_request_body` or
`on_response_body`, or end-of-stream is reached. After release, the remaining
chunks flow through in stream mode. If any filter requests `StreamBuffer`, the
pipeline defers forwarding this way. It suits API and security gateways that
inspect bodies before forwarding (routing on a JSON model field, content
policy, scanning for PII or injection with early rejection).

```rust
fn request_body_mode(&self) -> BodyMode {
    // No limit (default):
    BodyMode::StreamBuffer { max_bytes: None }

    // With a limit (413 on overflow):
    // BodyMode::StreamBuffer { max_bytes: Some(1_048_576) }
}
```

With `max_bytes: None` (the default), `StreamBuffer` accumulates without
limit; with `Some(n)`, requests over `n` bytes get 413.

`SizeLimit` streams chunks without buffering but enforces a byte ceiling,
returning 413 on overflow. The pipeline uses it when no filter needs body
access but a global size limit is configured.

### Body Hooks

```rust
// Async
async fn on_request_body(
    &self, ctx: &mut HttpFilterContext<'_>,
    body: &mut Option<Bytes>,
    end_of_stream: bool,
) -> Result<FilterAction, FilterError>;

// Sync (upstream constraint)
fn on_response_body(
    &self, ctx: &mut HttpFilterContext<'_>,
    body: &mut Option<Bytes>,
    end_of_stream: bool,
) -> Result<FilterAction, FilterError>;
```

Override `needs_request_context() -> true` to access request headers in body
hooks.

## Conditional Execution

Add `conditions` to any HTTP filter chain entry. Fields within a condition are
ANDed, and all conditions must pass. TCP filters take no `conditions`,
`response_conditions` or `branch_chains`; a config that sets them on a TCP
filter is rejected. A filter skipped on request is skipped on its other hooks
too, with the exceptions in [Lifecycle Hooks](#lifecycle-hooks).

| Field               | Matches when                                    |
| ------------------- | ----------------------------------------------- |
| `grpc`              | Request is (`true`) or is not (`false`) gRPC    |
| `path`              | URI exactly equals value                        |
| `path_prefix`       | URI path matches at a segment boundary         |
| `methods`           | Method in list                                  |
| `headers`           | All listed headers match                        |
| `headers_present`   | All listed headers are present, any value       |
| `selected_upstream` | Load-balancer-selected upstream metadata match  |

`grpc` classifies the request from its `content-type` header
(`application/grpc`, `application/grpc+proto`, `application/grpc+json`, or
any other `application/grpc+<codec>`). It reads the header directly, so it
works without the `grpc_detection` filter and does not depend on filter
ordering. `application/grpc-web` is a distinct protocol and does not match.

`path` matches exactly (for example, health checks on `/`). For
`path_prefix`, `/api` matches `/api` and `/api/v1`, but not `/apikeys`. One
trailing slash on a configured prefix is ignored, so `/api/` is equivalent to
`/api`.

```yaml
# Rate limit only gRPC calls.
- filter: rate_limit
  conditions:
    - when:
        grpc: true
  mode: global
  scope: local
  rate: 100
  burst: 200
```

```yaml
filter_chains:
  - name: main
    filters:
      - filter: headers
        conditions:
          - when:
              path_prefix: "/api"
          - unless:
              headers:
                x-internal: "true"
        request_add:
          - name: "X-Api-Version"
            value: "v2"
```

```yaml
- filter: static_response
  conditions:
    - when:
        path: "/"
  status: 200
  body: "ok"
```

`headers_present` takes a list of header names and matches when every one is
on the request, whatever the value (an empty value counts). Names are
case-insensitive. Under `unless` it runs a filter only when a header is
missing, which suits filling in defaults without overwriting what the client
sent. In the pre-read body phase it also sees headers that earlier body
filters promoted. Request headers come from the client, so any client can skip
a filter gated this way by sending the header; only use it where that's fine
or where a trusted hop sets or strips the header. See
[header-presence-condition.yaml].

```yaml
# Set a default model only when the client didn't pick one.
- filter: headers
  conditions:
    - unless:
        headers_present: ["X-Model"]
  request_set:
    - name: "X-Model"
      value: "default"
```

[header-presence-condition.yaml]: ../../examples/configs/pipeline/header-presence-condition.yaml

### Selected-Upstream Conditions

`selected_upstream` matches the application metadata
(`http.application_protocol`, `http.application_provider`) of the routed
cluster (the one the router selected). The load balancer publishes it when it
selects an upstream, and also when an earlier filter such as
`endpoint_selector` has already set the endpoint. Both sub-fields are
optional and ANDed when both are set:

| Sub-field              | Matches when                              |
| ---------------------- | ----------------------------------------- |
| `application_protocol` | Selected upstream's protocol equals value |
| `application_provider` | Selected upstream's provider equals value |

```yaml
- filter: path_rewrite
  conditions:
    - when:
        selected_upstream:
          application_protocol: openai_chat_completions
          application_provider: vllm
  # ...path_rewrite config...
```

The metadata comes only from the load balancer's selection, never from a
request header or filter-writable metadata. If no upstream has been selected
yet, or the cluster does not set the field, the predicate fails closed: an
unset value never satisfies a `when` and never trips an `unless`.

Pipeline validation therefore requires an *unconditional* `load_balancer` to
run before the gated filter on every reachable path. A conditional load
balancer may not run, so it does not count; one in an unconditional branch, or
one that hosts the branch containing the gated filter, does.

Selected-upstream predicates are resolved in the request phase. The pre-read
body path runs before any selection exists, so validation rejects a
request-body filter that combines a `selected_upstream` condition with the
`StreamBuffer` body mode.

#### Routed Embeddings and Decisions APIs

Set `http.application_protocol` on each logical cluster to the identifier its
consuming filters expect. The proposed identifiers are `openai_embeddings` for
Embeddings and `openai_decisions` for Decisions. Praxis core carries these
values as opaque strings; downstream filters own their interpretation, API
behavior, and protocol-specific tests.

In this chain one upstream address serves both APIs and the router picks a
cluster by path. Both clusters declare `vllm` as their provider, and each its
own application protocol:

```yaml
filter_chains:
  - name: routed_apis
    filters:
      - filter: router
        routes:
          - path: "/v1/embeddings"
            cluster: embeddings
          - path: "/v1/decisions"
            cluster: decisions

      - filter: load_balancer
        clusters:
          - name: embeddings
            endpoints: ["api.example.com:443"]
            tls: {}
            http:
              authority: { from: endpoint }
              application_provider: vllm
              application_protocol: openai_embeddings
          - name: decisions
            endpoints: ["api.example.com:443"]
            tls: {}
            http:
              authority: { from: endpoint }
              application_provider: vllm
              application_protocol: openai_decisions
```

After the load balancer selects an endpoint, a later filter can match
`selected_upstream.application_protocol` to tell the two APIs apart, and
`selected_upstream.application_provider` when its behavior depends on the
provider.

#### Routed vLLM System One API

vLLM serves System One at `POST /v1/systemone` and OpenAI Decisions at
`POST /v1/decisions`, each with its own request format. For a filter that
consumes the System One format, use `vllm_systemone` as a proposed protocol
identifier and keep `vllm` as the provider. See the
[vLLM Structured Decisions documentation][vllm-structured-decisions].

To route System One to the same upstream address, add a route and a cluster
to the chain above:

```yaml
# router routes:
- path: "/v1/systemone"
  cluster: systemone

# load_balancer clusters:
- name: systemone
  endpoints: ["api.example.com:443"]
  tls: {}
  http:
    authority: { from: endpoint }
    application_provider: vllm
    application_protocol: vllm_systemone
```

[vllm-structured-decisions]: https://docs.vllm.ai/en/latest/models/structured_decisions_models/#typesafe-system-one-endpoint

### Response Conditions

`response_conditions` gate `on_response`. The predicates are `status` (a list
of status codes), `headers`, and `headers_present`. A filter can have both
`conditions` (request phase) and `response_conditions` (response phase).

```yaml
- filter: headers
  response_conditions:
    - when:
        status: [200, 201]
  response_set:
    - name: "Cache-Control"
      value: "public, max-age=60"
```

### Security Filter Restrictions

Filters registered as `SecurityClass::Security` (built-in examples: `ip_acl`,
`forwarded_headers`; also custom filters registered as Security) reject
`failure_mode: open` by default, because open failure mode would let runtime
errors bypass security enforcement. Setting
`insecure_options.allow_open_security_filters: true` demotes the error to a
warning.

### Rewrite and Routing Interaction

Both `path_rewrite` and `url_rewrite` set `ctx.rewritten_path`, and the router
checks `rewritten_path` before the original URI, so a pipeline can rewrite and
then route. If both rewrite filters are in one pipeline, only the last takes
effect. Validation rejects this by default; set `allow_rewrite_override: true`
on the later filter to permit it.

## Related

- [Filter Reference](reference.md): configuration for all built-in filters
- [Extensions](../developing/extensions.md): writing custom filters
- [Payload Processing](../architecture/payload-processing.md): body access
  architecture
