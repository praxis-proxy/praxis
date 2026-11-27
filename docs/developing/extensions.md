# Extensions

Custom filters plug into Praxis the same way built-ins do: same ordering,
context access, and short-circuit behavior. For a first filter, follow the
[HTTP Filter Tutorial](http-filter-tutorial.md), which builds a complete
filter crate. The [filter system documentation](../filters/README.md) is the
API reference.

## Auto-Discovery (Recommended)

An external filter crate registers itself at build time. Praxis needs a
`Cargo.toml` dependency and YAML config, with no Rust changes.

1. The crate declares its filters with `export_filters!`.
2. Its `Cargo.toml` carries an empty `[package.metadata.praxis-filters]`
   marker.
3. The server's `build.rs` runs `cargo metadata`, finds marked crates, and
   generates registration code.
4. At startup, discovered filters are registered alongside the built-ins.

```rust
export_filters! {
    http "my_auth" => MyAuthFilter::from_config,
}
```

The tutorial shows the full
[crate setup](http-filter-tutorial.md#1-create-the-filter-crate) and how to
[add the crate to the server](http-filter-tutorial.md#4-add-the-filter-to-the-praxis-server).
Once it is a dependency, reference the filter by name in YAML:

```yaml
filter_chains:
  - name: main
    filters:
      - filter: my_auth
        some_option: "value"
```

### Duplicate Detection

Filter names must be unique across built-ins and all external crates. A
collision panics at startup with the duplicate name.

## Rust Extensions (Manual Registration)

To build a custom Praxis binary with inline filters that don't need to ship
as a separate crate, implement `HttpFilter` (`on_request`, `on_response`,
body hooks) or `TcpFilter` (`on_connect`, `on_disconnect`), register it with
`register_filters!`, and reference it by name in YAML filter chains.

### HTTP Filter

```rust
use async_trait::async_trait;
use serde::Deserialize;
use praxis_filter::{
    FilterAction, FilterError, HttpFilter,
    HttpFilterContext, Rejection, register_filters,
};

struct MaxBodyGuard {
    max_content_length: u64,
    reject_status: u16,
}

impl MaxBodyGuard {
    pub fn from_config(
        config: &serde_yaml::Value,
    ) -> Result<Box<dyn HttpFilter>, FilterError> {
        #[derive(Deserialize)]
        struct Cfg {
            max_content_length: u64,
            #[serde(default = "default_status")]
            reject_status: u16,
        }
        fn default_status() -> u16 { 413 }

        let cfg: Cfg =
            serde_yaml::from_value(config.clone())?;
        Ok(Box::new(Self {
            max_content_length: cfg.max_content_length,
            reject_status: cfg.reject_status,
        }))
    }
}

#[async_trait]
impl HttpFilter for MaxBodyGuard {
    fn name(&self) -> &'static str { "max_body_guard" }

    async fn on_request(
        &self, ctx: &mut HttpFilterContext<'_>,
    ) -> Result<FilterAction, FilterError> {
        let too_large = ctx.request.headers
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
            .is_some_and(|len| {
                len > self.max_content_length
            });

        if too_large {
            return Ok(FilterAction::Reject(
                Rejection::status(self.reject_status),
            ));
        }
        Ok(FilterAction::Continue)
    }
}

// In your binary:
register_filters! {
    http "max_body_guard" => MaxBodyGuard::from_config,
}
```

Every key next to `filter:` in a chain entry reaches `from_config` as a
`serde_yaml::Value`, except the entry keys `branch_chains`, `conditions`,
`failure_mode`, `name`, and `response_conditions`, which the pipeline
consumes:

```yaml
filter_chains:
  - name: security
    filters:
      - filter: max_body_guard
        max_content_length: 1048576   # 1 MiB
        reject_status: 413
        conditions:
          - when:
              methods: ["POST", "PUT", "PATCH"]
```

`MaxBodyGuard` only checks the declared `Content-Length`, so chunked uploads
and other requests without that header pass. For a cumulative request
ceiling, set `body_limits.max_request_bytes`
([payload size limits](../operating/configuration.md#payload-size-limits)).
On a streaming request, a body-limit rejection can arrive after the headers
or part of the body has already reached the upstream.

### TCP Filter

TCP filters implement `TcpFilter` and register with the `tcp` keyword
(`tcp "name" => factory`):

```rust
use async_trait::async_trait;
use praxis_filter::{
    FilterAction, FilterError, TcpFilter, TcpFilterContext,
};

struct ConnectionCounter { /* ... */ }

#[async_trait]
impl TcpFilter for ConnectionCounter {
    fn name(&self) -> &'static str {
        "connection_counter"
    }

    async fn on_connect(
        &self, ctx: &mut TcpFilterContext<'_>,
    ) -> Result<FilterAction, FilterError> {
        // Track connection metrics
        Ok(FilterAction::Continue)
    }
}
```

### Registration

`register_filters!` generates a `custom_registry()` function that returns a
`FilterRegistry` holding the built-ins plus your filters. Pass it to the test
utilities (`start_proxy_with_registry`) or to your own server bootstrap built
from the workspace crates (`praxis-core`, `praxis-filter`,
`praxis-protocol`).

### Custom Load Balancer

A load balancer is an ordinary HTTP filter. It reads `ctx.cluster` (set by
the router, which runs first), picks an endpoint, and sets `ctx.upstream`.
The protocol layer connects to whatever `Upstream` you set (address, TLS,
SNI, timeouts). An algorithm that tracks in-flight requests releases its
counters in `on_response`.

```rust
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

use async_trait::async_trait;
use praxis_core::connectivity::{ConnectionOptions, Upstream};
use praxis_filter::{
    FilterAction, FilterError, HttpFilter, HttpFilterContext,
};

/// Picks the endpoint that has handled the fewest
/// total requests (lifetime, not in-flight).
pub struct FewestServedFilter {
    clusters: HashMap<String, Vec<EndpointCounter>>,
}

struct EndpointCounter {
    address: Arc<str>,
    served: AtomicUsize,
}

impl FewestServedFilter {
    pub fn from_config(
        config: &serde_yaml::Value,
    ) -> Result<Box<dyn HttpFilter>, FilterError> {
        #[derive(serde::Deserialize)]
        struct ClusterCfg {
            name: String,
            endpoints: Vec<String>,
        }

        let cfgs: Vec<ClusterCfg> = serde_yaml::from_value(
            config
                .get("clusters")
                .cloned()
                .unwrap_or_default(),
        )?;

        let clusters = cfgs
            .into_iter()
            .map(|c| {
                let counters = c
                    .endpoints
                    .into_iter()
                    .map(|addr| EndpointCounter {
                        address: Arc::from(addr.as_str()),
                        served: AtomicUsize::new(0),
                    })
                    .collect();
                (c.name, counters)
            })
            .collect();

        Ok(Box::new(Self { clusters }))
    }
}

#[async_trait]
impl HttpFilter for FewestServedFilter {
    fn name(&self) -> &'static str { "fewest_served" }

    async fn on_request(
        &self,
        ctx: &mut HttpFilterContext<'_>,
    ) -> Result<FilterAction, FilterError> {
        let cluster = ctx.cluster.as_deref().ok_or(
            "fewest_served: no cluster set",
        )?;
        let endpoints =
            self.clusters.get(cluster).ok_or_else(|| {
                format!("fewest_served: unknown cluster \
                         '{cluster}'")
            })?;

        // Pick endpoint with lowest lifetime count.
        let pick = endpoints
            .iter()
            .min_by_key(|e| e.served.load(Ordering::Relaxed))
            .expect("cluster must have endpoints");

        pick.served.fetch_add(1, Ordering::Relaxed);

        ctx.upstream = Some(Upstream {
            address: Arc::clone(&pick.address),
            tls: None,
            connection: Arc::new(ConnectionOptions::default()),
        });

        Ok(FilterAction::Continue)
    }
}

// Register alongside the built-in filters:
register_filters! {
    http "fewest_served" => FewestServedFilter::from_config,
}
```

```yaml
filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend

      - filter: fewest_served
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:3001"
              - "127.0.0.1:3002"
```

If `ctx.cluster` is `None`, return an error as above
(`.ok_or("my_filter: no cluster set")?`) rather than panicking.

## Best Practices

### Header trust boundaries

Don't trust `X-Forwarded-For` or `X-Forwarded-Proto` unless the trusted
upstream sources are defined explicitly. Clients can spoof both.

### Keep filters stateless when possible

Filters are shared across requests and must be `Send + Sync`. Read all
configuration in `from_config` and keep the struct immutable. When you need
shared mutable state (counters, connection tracking), use atomics or
interior mutability with the smallest possible lock scope.

### Validate in `from_config`

Parse and type-check every field in `from_config` so bad config fails at
startup with a descriptive error, not at request time. Use
`#[serde(default)]` for optional fields.

### Return early with `Reject`, not panics

Stop a request with `FilterAction::Reject(Rejection::status(code))`. A panic
takes down the worker thread. For unexpected failures, return `Err(...)` and
the pipeline sends a 500 response.

### Declare body access accurately

Declare `request_body_access()` or `response_body_access()` only if the
filter reads or changes the body: `ReadOnly` to inspect, `ReadWrite` to
mutate chunks in place. Each declaration also says whether body processing
is optional or required:

```rust
fn request_body_access(&self) -> BodyAccess {
    BodyAccess::ReadOnly(BodyRequirement::Required)
}
```

With `Required`, an explicitly permitted opaque WebSocket upgrade is refused
when this selected filter would otherwise need HTTP body processing. Use
`Optional` when skipping body hooks on an opaque upgraded connection is
acceptable, as for a best-effort observer. The default `BodyAccess::None`
takes no requirement.

### Choose the right body mode

- `Stream`: lowest latency. Chunks flow through as they arrive. Use it for
  header-only filters or ones that handle each chunk on its own.
- `StreamBuffer`: filters still see chunks as they arrive, but forwarding to
  the upstream waits for `Release` or end-of-stream. Use it when the body
  decides routing, when you need the whole body (signature verification), or
  when you must inspect it before upstream selection. Set `max_bytes` to
  bound memory.

During incremental body handling, `Release` flushes the buffer and switches
the context's runtime body mode to `Stream` for later chunks. The global body
size ceiling still applies. A static request pre-read keeps buffering until
end-of-stream even after `Release`, so body writers see the complete request
before routing runs.

Declare `StreamBuffer` statically when the filter always needs the body, or
per request from `on_request`:

```rust
// Static: the filter always needs the body.
fn request_body_mode(&self) -> BodyMode {
    BodyMode::StreamBuffer { max_bytes: Some(1_048_576) }
}

// Per request: buffer only when needed.
async fn on_request(
    &self, ctx: &mut HttpFilterContext<'_>,
) -> Result<FilterAction, FilterError> {
    if needs_body_inspection(ctx) {
        ctx.set_request_body_mode(
            BodyMode::StreamBuffer {
                max_bytes: Some(1_048_576),
            },
        );
    }
    Ok(FilterAction::Continue)
}
```

### `on_response_body` is synchronous

`on_request_body` is async, but `on_response_body` is a plain `fn` that runs
inline on the worker thread proxying the response. Don't block it with
`block_on` or heavy computation. For async I/O during response processing,
spawn a background task and talk to it over a channel.

### Use conditions instead of internal checks

Gate the filter with YAML conditions instead of checks like
`if req.method != "POST" { return Continue }` in code. Operators can then
change the gating without a rebuild:

```yaml
- filter: my_filter
  conditions:
    - when:
        methods: ["POST", "PUT"]
```

### Use `extra_request_headers` for metadata

Promote values extracted from the body, or derived data, to a request header
through `ctx.extra_request_headers`. Later filters such as the router can
then read it without depending on your filter.

### Access KV stores for runtime mappings

`ctx.kv_stores` gives access to key-value data that changes at runtime
without a restart. Read a store the embedder configured with `get`, which
returns `None` for a missing name instead of creating one. Call
`get_or_create_memory` only when the filter owns an in-memory store on
purpose.

```rust
async fn on_request(
    &self,
    ctx: &mut HttpFilterContext<'_>,
) -> Result<FilterAction, FilterError> {
    // `get` returns `None` when the store is not configured.
    if let Some(store) = ctx.kv_stores.and_then(|registry| registry.get("routing_overrides")) {
        if let Some(cluster) = store.get("preferred_cluster") {
            ctx.cluster = Some(Arc::from(cluster.as_ref()));
        }
    }
    Ok(FilterAction::Continue)
}
```

Operators update stores through the admin API, without a config reload:

```console
curl -X PUT http://127.0.0.1:9901/api/kv/routing_overrides/preferred_cluster \
     -d 'us-east-cluster'
```

### Test with the integration harness

Write end-to-end tests with the harness utilities (`free_port`,
`start_backend`, `start_proxy_with_registry`): register the filter with
`FilterFactory::Http(Arc::new(factory))`, build a minimal YAML config, and
assert on status codes and response bodies. `tests/integration/` has
examples.

Built-in filter reference pages are generated from source. After changing a
filter config struct, run `cargo xtask generate-filter-docs`. `make lint`
runs `cargo xtask lint-filter-docs` in CI.

## Advanced: Iterative Request Router

The `iterative_request_router` filter runs named step chains. Each step is a
pre-built `FilterPipeline` that runs independently and makes an upstream
exchange through Pingora's native `Connector`. Transition rules on each
step's response drive the loop.

Each step pipeline runs the full request-header, request-body,
response-header, and response-body lifecycle around its sub-request. The
caller's filter registry and request extensions carry over, so external
filters and pipeline-scoped resources stay available. Step chain filters
read `IterationState` from request extensions
(`ctx.extensions.get::<IterationState>()`): the original request, the
previous response, and a cross-step accumulator. A filter sets the next
iteration's body by inserting `NextIterationBody` into extensions. Config
validation rejects an `iterative_request_router` nested inside another one's
step chain.

### Streaming step responses

By default a step buffers the whole sub-request response before transition
rules run (`SubRequestResponseMode::Buffered`). A filter switches a step to a
pull-based streamed response by calling
`ctx.set_subrequest_response_mode(SubRequestResponseMode::Streaming)` from
`on_request`. That filter must also override
`may_select_streaming_subrequest_response()` to return `true`. Pipeline
validation rejects a streaming step whose response pipeline requires
`BodyMode::StreamBuffer`, and a runtime guard rejects an undeclared
streaming action.

Inside a step, `ctx.emit_stream_chunk(bytes)` adds bytes to the
router-owned logical stream. Emitted chunks go out in FIFO order ahead of the
callback's own body output, and Praxis never inspects them. Emission only
works inside an `iterative_request_router` step. Pending chunks count toward
the same bound as the retained `IterationState`; going over it returns an
error and enqueues nothing.

`IterationState`, `NextIterationBody`, `SubRequestResponseMode`, and the
streaming utilities are exported from `praxis_filter`. See the
[`iterative_request_router` reference](../filters/http/traffic_management/iterative_request_router.md)
and [proposal 00786](https://github.com/praxis-proxy/enhancements/blob/main/proposals/00786_iterative-request-router.md)
for the full design.

## Advanced: Callouts to a Named Cluster

With the `chain-binding` build feature, a chain-binding filter can send a
`FilteredSubrequestExecutor` callout to a top-level cluster instead of a URL.
That `clusters:` entry supplies the callout's endpoints, load-balancing
strategy, health, slow start, TLS (including client certificates), authority,
base path, timeouts, and retry policy.

Resolve the cluster once, when the filter is built, and stage it on each
callout:

```rust,ignore
// In the factory passed to `register_chain_binding`:
let cluster = binding.cluster("weather-mcp")?; // unknown name fails config load
let outbound = Arc::new(binding.bind_chain(&chain_ref)?);

// Per request:
let mut extensions = RequestExtensions::default();
extensions.insert(StagedCluster::new(&cluster));
let response = executor.run(&outbound, &request, extensions, deadline).await?;
```

Like any chain-binding filter, the owning filter must forward
`visit_nested_pipelines` to its bound outbound pipeline. The staged cluster's
health comes from that pipeline's health registry, so without forwarding,
endpoint selection runs without health and nothing reports to passive health.

What the executor does with a staged cluster:

- **Selection.** Before the request phase it picks an endpoint with the
  cluster's strategy, using health from the pipeline's health registry
  (panic mode and slow start apply as in `load_balancer`), and sets
  `ctx.cluster` and `ctx.upstream`. Outbound-chain filters that key on the
  cluster, such as `credential_injection`, work unchanged.
- **Admission.** Staging a callout claims one of the cluster's
  `max_connections` slots, held across retries until its response ends (for
  a streaming callout, until the body finishes or is dropped). A callout
  staged at a cluster at its ceiling fails without dialing.
- **Pinning.** `ctx.upstream` is re-pinned after the request phase and after
  the selected-upstream body phase, so a chain filter cannot retarget the
  callout. If a chain filter changes `ctx.cluster` (a `router`, say), the
  callout fails before anything is sent, because later filters may already
  have picked headers for the other cluster, such as a `credential_injection`
  secret. Staging `StagedCluster` together with `StagedUpstream` fails the
  callout.
- **Retries.** The cluster's `retry_policy` applies, with the same decision the
  main proxy path makes. A connect error counts as `connect_failure` and an
  I/O error as `reset`. HTTP/2 errors are classified as on the main path:
  `REFUSED_STREAM` is `refused_stream`, a GOAWAY is `reset`, and any other
  HTTP/2 stream or connection error is never retried, since the endpoint may
  have acted on the request. Other transport errors (circuit open, admission
  timeout, deadline or idle timeout, oversized response, an expired
  `per_try_timeout_ms`) are never retried, and neither is an attempt that
  never reached its endpoint (a refused private address, a failed lookup, a
  TLS peer with no name). A configured policy prefers an endpoint it has not
  tried and, like the main path, redials the same one when none is left; the
  legacy default always redials. Non-idempotent methods (most callouts
  are `POST`) are retried only when the policy sets `allow_non_idempotent`.
  Backoff never runs past the callout's step deadline. The retry budget is
  charged only for a retry that actually runs. Response filters run
  once, on the final attempt. A streaming callout can retry only before its
  response headers are handed to the response phase.
- **Credentials on retry.** Staged `PendingCredentials` are matched against
  each attempt's destination. If another endpoint would receive a different
  set of credentials than the first attempt did, the retry redials the first
  endpoint instead. When a selected-upstream request-body filter rewrote the
  body for the first endpoint, every retry redials that endpoint, since the
  body may carry its credential.
- **Timeouts.** The policy's `per_try_timeout_ms` caps each attempt, from
  peer construction (including DNS resolution) to the response, inside the
  step deadline. Its `request_timeout_ms` caps the whole callout, every
  attempt and backoff included.
- **Passive health.** Every attempt that reached an endpoint, including a
  failed attempt that is retried, counts toward the cluster's
  `passive_unhealthy_threshold` and `passive_healthy_threshold`. Outcomes
  decided on the caller's side (a request that could not be built, the callout
  client's admission limit or circuit breaker, or a response over the caller's
  size limit) are not counted, and a request that could not be built is never
  retried. A streamed response counts when its body ends, so a failure after
  the headers counts against the endpoint, including a stream that sends
  nothing for the stream idle timeout. A stream that ends on the caller's own
  step deadline is not counted.

Limitations: callout retries and passive-health transitions are logged but do
not update `praxis_upstream_retries_total` or the health-transition metrics,
which the main proxy path records. A `ClusterRef` keeps its own balancer
state, separate from any `load_balancer` filter that declares the same
cluster.
