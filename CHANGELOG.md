# Changelog

<!-- markdownlint-disable MD013 -->

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

> **Types of changes:**
>
> - **Added**: for new features.
> - **Changed**: for changes in existing functionality.
> - **Deprecated**: for soon-to-be removed features.
> - **Removed**: for now removed features.
> - **Fixed**: for any bug fixes.
> - **Security**: in case of vulnerabilities.

## [Unreleased]

### Added

- Core policy-enforcement guide with PPE use cases, integration conditions,
  and links from onboarding, architecture, and security documentation.
- Expose compact JSON sizing and capped serialization utilities in
  `praxis_filter::json_size` for built-in and external filters.
- Experimental `bandwidth` server support paces HTTP request and response
  bodies on Pingora and Hyper, and both TCP payload directions, including
  local responses and the prefix inspected for SNI routing.

- Experimental `bandwidth` filter-library support for independent upload
  and download budgets, per downstream connection or source IP, with burst
  allowances, bounded tracking, and cancellable prefix reservations. Optional
  `ipv6_prefix_len` groups IPv6 clients by a configured network prefix.
- Add `shutdown_drain_delay_secs` for readiness-first SIGTERM handoff. The
  process becomes unready, waits for the configured delay, then begins
  graceful connection shutdown; HTTP/1 responses during the drain advertise
  `Connection: close`. The orchestrator's termination timeout must cover
  `shutdown_timeout_secs` (which already includes this delay), any `preStop`
  hook, and final cleanup.

- Add configurable `/ready` policy: `admin.readiness: serving` (the default)
  keeps a serving replica ready during upstream degradation, while
  `admin.readiness: upstreams` preserves upstream-dependent readiness.
  `/ready` also reports the `initializing`, `draining`, and `stopped`
  lifecycle phases with `503` instead of claiming readiness.

- Experimental CloudEvents `on: request_complete` publishes one best-effort
  event when a request ends, including aborted responses and early failures.
- Add a Kubernetes rollout acceptance harness covering pod loss,
  rollouts, config reloads, TLS rotation, node drain, and upstream failure
  under continuous HTTP/1.1, HTTP/2, and HTTPS traffic.

### Changed

- Temporarily disable KIND rollout acceptance in CI and local commands
  because the cluster exhausts the shared inotify instance budget, pending
  migration to [gateway-controller](https://github.com/praxis-proxy/gateway-controller).
- CloudEvents `on: response_complete` publishes only after a final bodyless
  response or response-body end-of-stream; use `request_complete` to observe
  terminal failures and aborted streams.
- **Breaking:** FilterPipeline::emit_deferred_records is replaced by emit_deferred_access_record, which dispatches only eligible access_log instances.
- **Breaking:** HttpFilterContext now carries request_header_mutations for ordered header operations; custom constructors must initialize the field.
- **Breaking:** BodyReadError includes TimedOut; exhaustive matches in custom management request implementations must handle it.
- **Breaking:** SessionStoreRegistry replaces cluster-only get/insert access with explicit candidate generation binding and publication.
- Reuse owned bytes for nonfinal gRPC-Web response chunks.
- **Breaking:** Pingora helpers `apply_cached_tls`, `ca_from_cached`,
  `client_cert_from_cached`, and `http_peer` now return `Result`; embedding
  callers must handle invalid material.
- **Breaking:** `TcpFilterContext` now carries `lb_selection`; custom
  constructors must initialize it to `None`. Built-in TCP load balancing
  retains each acquired endpoint claim through timeout and cancellation
  cleanup.
- Update the Pingora fork dependencies to v0.11.4.
- **Breaking:** `HttpFilterContext::filter_metadata` is now a
  `FilterMetadata` instead of a `HashMap<String, String>`. Its `insert`
  enforces the key, value and entry limits and returns
  `Result<Option<String>, MetadataRejected>`, so writes through the field can
  no longer bypass them. A rejection names the `MetadataLimit` it exceeded
  and hands back the key and value (`MetadataRejected::into_entry`).
  `get` returns `Option<&str>`, and there is no `entry`, `get_mut` or
  `iter_mut`. Custom Rust filters that hold large or growing state in
  `filter_metadata` should move it to `insert_filter_state`.
- **Breaking:** `HttpFilterContext::get_metadata` and `set_metadata` are
  removed. Read with `ctx.filter_metadata.get(key)`. Write with
  `ctx.filter_metadata.insert(key, value)`, adding
  `.unwrap_or_else(FilterMetadata::log_loss)` to keep `set_metadata`'s
  behavior of dropping a rejected write with a warning.
- **Breaking:** `BodyAccess::ReadOnly` and `BodyAccess::ReadWrite` now require
  an explicit `BodyRequirement::Optional` or `BodyRequirement::Required`.
  Custom Rust filters must choose whether their body processing may be skipped
  when admitting a transport that bypasses HTTP body hooks. `BodyAccess::None`
  remains the default. Pipeline introspection exposes this declaration as
  `requirement: "optional"` or `"required"`, omitted when there is no body access.
- **Breaking:** Rust API: `ServerRuntime` implementations must implement
  `lifecycle()`, explicit `Config` struct literals must set
  `shutdown_drain_delay_secs`, and `UnavailableRuntime` is no longer a unit
  value or `Copy`; use `UnavailableRuntime::default()` or `from_config`, and
  `clone()` where a copy was relied on.
- **Behavior change:** `/ready` defaults to `admin.readiness: serving`, so a
  serving replica stays ready when a checked cluster has no healthy endpoints.
  Set `admin.readiness: upstreams` to preserve upstream-dependent readiness.

### Fixed

- Return gRPC `DEADLINE_EXCEEDED` when Pingora's rounded upstream timeout fires just before the call's exact deadline, while preserving earlier transport timeouts.
- Check every logical subrequest output against its size limit before pacing,
  including output following empty emissions or consuming callbacks.

- Bound buffered IRR emissions retained across steps by the overall request
  deadline rather than the timeout of their completed producing step.

- Pace chunks emitted by buffered IRR steps using their originating download
  budgets, including selected abnormal terminal output.

- Preserve bandwidth accounting for successful body-consuming transforms,
  reject ordinary IRR output above its ceiling before pacing, and allow
  independent writers to use burst allowance not held by pending writes.

- Keep transformed bandwidth charges as unreserved plans until each bounded
  portion is admitted, preventing oversized shared debt when another writer
  reserves concurrently.

- Pace strongly shrinking bodies without oversized admission stalls, isolate
  nested-body bandwidth attachments, and check completion output limits before
  pacing. Completion output within an available burst survives a step timeout.
- Preserve bandwidth charges across body transformations and release streaming
  completion output in refundable, bounded prefixes. HTTP `per_connection`
  library hosts must supply a stable identity and a live `ConnectionAlive` watch.
- Resolve the pinned Pingora upload APIs for external source consumers without
  requiring their workspaces to inherit dependency patches.
- Strip reserved and hop-by-hop headers from preformatted gRPC rejections while retaining safe gRPC fields, and frame empty HTTP/1 responses with one correct zero length even when filters supply stale or conflicting lengths.
- Preserve final body-filter bytes with forwarded trailers on Hyper; abort Pingora delivery when both outputs cannot be represented or EOF filtering fails, while retaining ordinary trailers and deliberate conversion.
- Keep requests streaming when any repeated Accept field contains text/event-stream.
- Correct the multi-listener body example description to match its field extraction and routing behavior.
- Clarify request ID handling, rewrite scope, and routing order in the logging and transformation examples.
- Record the final response after informational headers, including a fallback access record when a later stream aborts.
- Preserve every headers.request_add field value in upstream requests, including duplicates and opaque existing values.
- Clarify that the MaxBodyGuard extension example checks declared Content-Length and point to cumulative request body limits.
- Describe the retry-policy example as capped connection/reset retries with backoff, without an unconfigured token-bucket budget.
- Keep Hyper upstream response read deadlines active while a streaming request upload makes progress.
- Honor final filtered response status in Hyper body delivery and framing, including safe conversion of bodyless 304 responses to 200.
- Classify failed Hyper terminal EOF sends as downstream disconnects while preserving request state through cancellation and completion.
- Preserve sticky-session bindings across reloads and conflicting listener bounds while retiring stores no longer used by serving pipelines.
- Create header affinity only for the selected endpoint with forwarding evidence, including nested and hedged requests; failed dials and local responses cannot establish a binding.
- Settle nested circuit-breaker tokens on filtered subrequest timeout or cancellation without changing neutral half-open recovery policy.
- Correct guardrails example commands and documentation to describe request
  inspection and 403 responses.
- Configure required client-certificate TLS in the peer identity trust example
  and verify certificate digest and organization matching end to end.
- Propagate verified mTLS client identity through Hyper, enabling certificate
  digest, organization, and serial matching on HTTP/1.1 and HTTP/2.
- Reject inline Basic Auth usernames containing a colon during configuration
  loading.
- Apply CORS requested-header policy to every preflight field line, including
  undecodable values.
- Configure active health checks in zone-aware and priority load-balancing
  examples and verify fallback and recovery.
- Describe unmatched SNI routing as connection closure without promising a
  TLS alert.
- Document session-affinity remapping when endpoint membership changes.
- Clarify endpoint weight behavior and P2C selection costs in load-balancing
  guidance.
- Use reserved metadata in the body-based tenant routing example so client
  tenant headers cannot override missing or extracted body fields.
- Correct payload documentation for transfer limits, buffering limits, and
  reserved metadata headers.
- Pass through non-native gRPC response media types in the gRPC-Web filter.
- Prevent JSON body add operations from duplicating an existing member when
  source metadata is extracted later in the same object.
- `/api/pipelines` keeps still-bound HTTP listeners visible after their removal
  from a reloaded config and reports bound transport settings with the applied
  chains.
- Reloaded hedged HTTPS requests retain the global upstream CA loaded at
  startup while applying new response body limits.
- Returning server calls stop their config watcher, health checks, and
  housekeeping after shutdown or startup failure.
- Failed cross-protocol listener registration stops certificate watchers
  started by earlier successful registrations; returning servers explicitly
  stop certificate watchers.
- Reject configured upstream CA bundles with no usable trust anchor during
  configuration, while retaining valid roots in mixed bundles.
- Reject malformed upstream mTLS client certificate chains and invalid raw
  keys before Pingora peer construction can abort the proxy.
- Expose divergent routed endpoint declarations alongside the endpoint-health
  view in `/api/stats`.
- Validate complete initial HTTP/2 SETTINGS frames before reporting a healthy
  upstream.
- Apply TCP maximum durations across setup and forwarding, including Hyper
  TLS setup. Pingora's initial TLS handshake retains its separate timeout.
- Stop certificate watchers started by earlier listeners when HTTP or TCP
  listener registration fails.
- Preserve unmodified MCP request and response bodies, and emit inference
  mutation warnings only when policy reports a payload change.
- `cargo xtask fips verify-image --pinned-in` binds the verified image reference
  to the Containerfile's supported base stage and named digest argument.
- `cargo xtask sync-example-readme --fix` rejects an unreadable README or
  missing `## Configs` marker before writing.
- `cargo xtask benchmark flamegraph` stops and reaps owned child processes on
  profiling failure or cancellation.
- Show possible request-head and response hooks in pipeline introspection.
- Nightly images now require lint and functional-test success before publication.
- Concurrent new-key KV writes and compiled-regex cache admissions now stay
  within their capacity limits.
- Unreadable `grpc-timeout` headers now follow the malformed-header policy;
  `on_invalid: ignore` still uses the configured fallback.
- **Breaking:** Reject branch `on_result.key` values over 64 bytes, matching
  the limit enforced when filters insert results.
- The `policy` filter's entity-less response fallback now stamps configured
  `context_meta` and `context_headers`, so response-phase rules see the same
  operator context as the request path when no request-phase identity was
  stashed.
- **Breaking:** Reject invalid header names for `consistent_hash`, `maglev`,
  and `ring_hash` instead of silently hashing by request path.
- **Breaking:** Reject HTTP-only downstream read and keepalive timeouts on TCP
  listeners instead of silently ignoring them.
- **Breaking:** statically buffered request pipelines now reject a finite
  `body_limits.max_request_bytes` above `body_limits.max_buffer_bytes` at
  startup, config validation, and reload, naming both fields and byte values.
  Lower the request limit or raise the buffer cap to correct the configuration.
  Streaming requests can still use transfer limits above the buffering cap.

- Poll TLS certificate, key, CA, and CRL files alongside filesystem
  notifications, including when a projected Kubernetes Secret update
  produces no usable notification. Polling applies to single-certificate
  listeners with TLS hot-reload enabled in builds that include the
  `config-reload` feature. A changed or unreadable file triggers a reload
  of the server certificate and configured client verifier. A stable,
  successful notification reload updates the polling baseline.

### Security

- Keep incomplete-request access logging scoped to one eligible access-log instance and prevent CloudEvents fallback publication outside its configured conditions.
- Bound total request-body read time for enabled Hyper admin PUT routes and return 408 without applying partial KV or log-level updates.
- Count pending TCP TLS handshakes against global and listener-group connection
  limits.
- Policy content scanners now receive secondary MCP tool text alongside
  structured results.
- Inference output policy now inspects recognized Responses text and Chat and
  Responses function-call arguments.
- Inference output policy now withholds nonempty malformed declared JSON
  completions instead of forwarding uninspected content.
- Inference output policy rejects unsupported encoded declared JSON completions
  before committing upstream response headers.
- Early Hints can no longer release a later JSON completion before policy
  inspection.
- Reject Terminal branches that can select an upstream endpoint while
  bypassing later security filters.
- Keep pre-request results bound to their filter instance so a later
  classifier cannot suppress an earlier instance's branch-gated security
  checks.
- LLM policies now apply HTTP authorization, delegation and request assertions
  to accepted unclassified requests without a model when
  `llm.require_model: false`. Adding a body to a discovery request no longer
  skips the HTTP policy. Move inference-only global rules into `llm:` routes
  or `global.defaults.llm`; MCP-only and classified non-entity MCP admission
  retain their existing behavior.
- Policy credential stripping, delegation and asserted headers now survive
  preceding ordered body-filter mutations, including stripped headers
  introduced during earlier pre-read passes.

## [0.8.0] - 2026-11-06

### Added

- The `policy` filter accepts trusted metadata-only inference response context
  from host filters and dispatches it through `cmf.llm_output` at end of stream.
  With `body_access: read_only`, or for SSE responses, response content is not
  buffered. Non-SSE responses under `body_access: read_write` stay buffered and
  are evaluated as content. Plugin-written custom values reach downstream
  response filters.
- Policy rate limiting (experimental): the policy filter runs a policy's
  `rate_limits:` before identity resolution, keyed on the client address,
  and after it, keyed on the resolved identity, each once per request. A
  denial returns 429 with `Retry-After` (or 400, 401 or 503), fixed text and
  only the limit counters, never the limiter's own message, and does not
  reach the upstream. Counters are per replica and reset on reload. See the
  example `security/policy-rate-limit.yaml`.
- Query-parameter credentials for the policy filter
  (`credential: { kind: query_param, name: ... }` with `read_query`), with
  the example `security/policy-query-credential.yaml`. A repeated or
  percent-encoded repeated parameter is denied as ambiguous. Query strings
  can appear in access logs outside Policy; prefer a header where the client
  can send one.

- Implicit cluster references: an inline load-balancer cluster that shares
  its name with a top-level cluster may omit its endpoints, which are
  filled in from the declaration at validation time, keeping the routed
  and health-checked addresses together. A divergent endpoint list now
  warns at startup and on reload, and an inline `health_check` is
  rejected: probes are configured only at top level. Filling is capped at
  16 MiB of copied endpoint data in validation and again in each pipeline
  build, so many references to one large declaration cannot expand a small
  config into an out-of-memory reload.
- A [support diagnostics reference](docs/operating/diagnostics.md) covering
  config checks, live state, logging, reloads and draining before shutdown.
- `SUPPORT.md` with guidance on where to ask questions, report bugs,
  report security vulnerabilities, and propose enhancements.
- `runtime.overload_gauges` publishes `praxis_overload_pressure`
  for cgroup memory, anonymous resident memory, CPU stall time,
  connections, and file descriptors. The gauges do not shed load.
- A `forward_proxy` block on `protocol: http` listeners, behind the
  experimental `forward-proxy` cargo feature (off by default; config
  surface for CONNECT-based forward proxying): destination allowlisting with
  wildcard host patterns and optional ports, tunnel idle timeout and
  optional max duration. Validation rejects the block on TCP listeners
  and requires egress control (a non-empty `allow_destinations` list or
  an `ip_acl`/`policy` filter without `conditions` in the listener's
  chains); the check is structural — that the configured control actually
  restricts egress remains the operator's responsibility. Destination
  patterns ending in a numeric label (`*.0.1`) are rejected so no pattern
  can match an IP literal. A reload that changes a bound listener's
  `forward_proxy` block, removes a listener that has one, or changes
  `insecure_options.allow_private_upstreams` while a bound listener has
  an enabled block, is rejected. The CONNECT runtime is a follow-up
 change; the block is inert until it lands.
- An experimental network backend behind the `hyper` feature, off by
  default: the proxy data path, TCP forwarder, admin surface and sub-request
  client on hyper 1.x. See `docs/architecture/hyper-backend.md`.
- Experimental `tls-health-check` feature for TLS handshake probes and HTTPS
  health endpoints using cluster certificates and startup runtime trust.
  Handshake probes detect client-certificate rejection alerts after sending
  `close_notify`, allowing the greater of 100 ms and the connection and
  handshake duration, capped by the remaining probe timeout. Completed
  handshakes remain healthy when that deadline expires without a response.
  Rust consumers matching `HealthCheckType` exhaustively must handle the new
  `Tls` variant even when the feature is disabled.
- Granular Policy Engine Cargo features. `policy-builtins` (on by default)
  is the complete bundle; a `--no-default-features` build names
  `policy-engine` or individual builtins (`policy-api-key`, `policy-jwt`,
  `policy-oauth`, `policy-cedar`, ...) plus exactly one shared crypto backend,
  `policy-crypto-default` or `policy-crypto-fips`. A policy naming a plugin
  kind the build did not compile in fails to load. `praxis --version` lists
  the compiled Policy features. See `docs/operating/build-features.md`.
- The default build includes Policy's experimental rate limiter
  (`ratelimit/limitador`, feature `policy-experimental-ratelimit`). It counts
  nothing unless a policy declares the plugin and lists it under
  `rate_limits:`, and loading such a policy logs a warning at startup and on
  every reload. Because the default build now carries an experimental
  feature, it logs the experimental-features warning at startup, which now
  names each experimental feature compiled in.
- Opt-in Policy FIPS profiles: `FIPS_POLICY_PROFILE=engine|api-key|jwt|both`
  selects Policy on its OpenSSL FIPS backend for every FIPS Make target,
  including `container-fips` (a separately tagged image) and
  `fips-runtime-probe`, which then sends API-key, JWT and DPoP traffic
  through the image. `make test-fips-provider` runs a profile's suites on
  Red Hat's FIPS module on any host. The default FIPS build and image stay
  policy-free. New example: `security/policy-jwt-fips.yaml`.
- `make fips-deps` also checks the FIPS unit-test graph: test edges may not
  unify crypto features into `jsonwebtoken`, Policy, rustls or openssl, never
  bring in `aws-lc-rs`, and bring in another denied crate only with a
  recorded reason.
- The policy filter registers the `env` secret provider, so a policy
  document's `secrets:` block using `env` now loads instead of failing at
  startup. Any other provider kind, including `file` and `vault`, is still
  refused. Values are read when the filter is built, so a changed value
  takes effect on the next restart.

### Changed

- Clarify that the default Pingora shutdown grace period is capped at five
  seconds, including for streaming responses, regardless of a larger
  `shutdown_timeout_secs` value.
- Bodyless requests on LLM policies, such as `GET /v1/models`, now run HTTP
  authorization, delegation and request assertions before they reach the
  upstream: a matching `http:` route, or the `global` rules otherwise.
  Before, a valid identity alone admitted them. Migration: a global rule
  that requires `llm.request` now denies discovery; move inference-only
  rules into `llm:` routes or `global.defaults.llm`. A startup warning
  names the `llm.require_model: false` and `require_protocol_metadata:
  false` fallbacks, which still admit on identity alone.
- The policy filter refuses to build when a JWT trusted issuer enables DPoP
  (`dpop.mode: optional` or `required`) without `dpop.external_base_url`,
  so the proof's `htu` never depends on the client-sent `Host` header. The
  error names the plugin and the issuer. Set the URL clients address, such
  as `https://api.example.com`. A reload with such a document is rejected
  and the previous pipeline keeps serving.
- A Policy crypto backend failure (no SHA-256 provider, non-FIPS OpenSSL
  defaults under FIPS JWT, or another `jsonwebtoken` provider installed
  first) now fails policy filter construction with a `policy.crypto_failed`
  error naming the remedy, at startup and on reload, instead of surfacing
  as request-time denials.
- `PRAXIS_REQUIRE_FIPS` judges a registered `policy` filter by Policy's
  compiled crypto capability report instead of refusing it outright. It
  still refuses the default build, any host policy plugin factory, and the
  unvalidated combination of `policy-experimental-ratelimit` with
  `policy-crypto-fips`. The default FIPS build stays policy-free.
- Default accumulated bodies and buffered subrequest responses to a 64 MiB
  cap, configurable through `body_limits.max_buffer_bytes`. The cap covers
  explicit filter limits, runtime-selected buffering, nested pipelines, and
  iterative-router state, including after reload. Request and response transfer
  limits retain their 10 MiB defaults and remain independent for streams.
  Larger JSON, policy, gRPC-Web, and iterative-router buffer settings are
  accepted subject to the configured cap.
- Keep Pingora uploads open while runtime-selected buffering withholds
  non-final chunks, instead of sending a premature upstream end marker.

- The policy engine is updated to PPE 0.6.0. Its OAuth `delegate(...)`
  validation is stricter by default: a token-exchange response must name
  an access-token or JWT `issued_token_type`, unrequested scopes outside
  `allowed_extra_scopes` are refused, and a minted JWT's `aud` and `sub`
  must match. `strict_response_validation: false` turns these checks off.
  JWTs with an unsupported `crit` header are rejected, an `env` secret
  provider with unused settings fails to load, and CEL `size()` and
  `exists()` change in ways that can allow requests that were denied. See
  `docs/filters/http/security/policy.md`.
- `KvStoreRegistry::register` adds a caller-supplied `KvBackend` under a
  name, rejecting duplicates with `KvRegistryError::AlreadyRegistered`.
- `KvStoreRegistry::get_or_create_memory` deliberately creates an
  in-memory store.
- **Breaking:** every `sticky_sessions` cluster now requires a `storage`
  field, and startup fails with `missing field 'storage'` when it is
  omitted. The only value is `local`, which keeps session bindings in the
  proxy process: they are not shared between replicas and do not survive a
  restart, so stickiness behind a load balancer is per-process. That was
  already the behaviour; it is now a stated choice rather than a silent
  default. Add `storage: local` to each cluster to keep the current
  behaviour. See `docs/filters/http/traffic_management/sticky_sessions.md`.
- `FilterPipeline::build_with_chains` takes a new required
  `top_level_clusters: &[Cluster]` argument. Rust callers pass the
  config's top-level `clusters:` list, or `&[]` when none exists.
- **Breaking**: the `rate_limit` filter now requires `scope`, whose only
  supported value is `local`. Counters are process-local, so each replica
  enforces its own `rate` and `burst`. Add `scope: local` to existing
  configs. See `docs/filters/http/traffic_management/rate_limit.md`.

### Removed

- `KvStoreRegistry::get_or_create`, which silently created an in-memory
  store for any unknown name. Use `get` to look up a configured store, or
  `get_or_create_memory` to choose memory explicitly.

### Fixed

- Pingora sub-request connections now respect the cluster
  `idle_timeout_ms` when returned to the pool, avoiding reuse of idle
  connections silently dropped by NAT or firewall state.
- The policy filter resolves `http.client_address` through
  `trusted_proxies` on every request path.
- On inference requests a `ratelimit.post_identity` limiter can bind
  `llm.model_id`, `llm.provider` and `custom.llm.*`; such a limiter used to
  deny every request.
- Remove forbidden `Content-Length` and `Transfer-Encoding` headers from
  204 responses after response filters run, preserving valid downstream
  framing for the following response.

- Preserve valid `Content-Length` metadata on Hyper HTTP/1 304 responses
  while keeping them bodyless, including responses with huge hypothetical
  lengths.

- Count an original request-body prefix once across Pingora retries while
  continuing to count newly received tail bytes. Stale-connection retries also
  respect the 64 KiB original and final transformed body retention ceiling.
  Requests whose streaming writer output was not retained now return the
  upstream error instead of retrying with an unsafe reconstruction.

- Decode `grpc-web-text` request bodies during pre-read inspection before
  forwarding them to HTTP/2 backends. Invalid base64 now follows the filter
  rejection policy even before request-phase state is initialized.

- Flush small HTTP/1.1 server-sent events promptly when the upstream supplies
  `Content-Length`. Body-bearing event streams use chunked downstream framing;
  the upstream length still detects truncated responses.

- A delegated credential is sent with its own prefix rather than always
  `Bearer `, so a Vault credential with no `scheme_prefix` goes out bare
  and a custom prefix such as `token ` is kept.
- A request header asserted from `secret.<name>` stays redacted in the
  views that request-body and response policy hooks receive, rather than
  reaching those plugins and PDPs in plaintext.

- Request-body limit rejections log structured warnings and return JSON 413
  responses across buffering and streaming paths. Body-phase rejections
  for requests armed by `grpc_status` return gRPC Trailers-Only responses
  instead. Oversized declared Content-Length values, including validated
  matching comma-separated lengths, are rejected before reading the body
  or sending 100 Continue. Local body-limit rejections are not retried upstream,
  even when 413 is configured as retriable. HEAD rejection responses retain
  representation headers without sending payload bytes, including over HTTP/2.
  Streaming rejections also cancel HTTP/2 upstream streams promptly instead of
  waiting for an upstream response or allowing it to replace the rejection.
- Early HTTP/1 responses with unread uploads use Pingora's write-side
  shutdown and bounded cleanup before closing, including authentication
  and rate-limit rejections and successful terminal responses. Cleanup has
  a 30-second deadline and a 128 MiB discard budget checked between body
  reads. Streaming rejections release the upstream before responding;
  access logs and request duration metrics are recorded before downstream
  cleanup. Expected client-error filter rejections no longer produce a
  duplicate Pingora error log.
- The FIPS runtime probe selects the Pingora backend when compiling its
  listener tests with default features disabled.
- The Hyper backend rejects reserved client trailer names before forwarding
  or retaining them for replay, including streamed and pre-read uploads.
- The Hyper backend applies the retry policy to failures on pooled
  connections, preventing POST replays without opt-in and enforcing the
  configured retry limit.
- The Hyper backend stops the runtime if a required listener exits during
  startup or serving, including a failed socket in a TCP listener group.
- The Hyper backend preserves request trailers through pre-read and retries
  to HTTP/2 upstreams, and rejects unsupported HTTP/1 uploads with trailers.
- The Hyper backend rejects strict HTTP/2 TLS upstreams that do not negotiate
  `h2` through ALPN. Automatic HTTP version selection still allows HTTP/1.1.

### Security

- `trusted_proxies` in the policy and `forwarded_headers` filters matches a
  proxy range only within its address family. `0.0.0.0/0` no longer trusts
  IPv6 peers (nor `::/0` IPv4 ones), so on a dual-stack listener a direct
  client of the other family cannot set `X-Forwarded-For` to choose its
  client address.
- Updated `ctutils` to address `RUSTSEC-2026-0385`.
- The policy filter no longer forwards a delegated token while the caller's
  credential sits where it cannot be stripped from the upstream request,
  such as a query parameter. That request now receives HTTP 500
  (`policy.unstrippable_credential`) instead of reaching the upstream with
  both credentials. A policy that reads a query credential and also
  delegates fails to load.
- Every policy hook now sees the request as the client sent it: the raw
  query, the effective client address as `http.client_address` (the TCP
  peer, or with `trusted_proxies` the rightmost untrusted `X-Forwarded-For`
  hop; absent when a trusted chain cannot be resolved because of a malformed
  hop, which denies address-keyed rate limits), the validated bare host as
  `http.host` (lowercased, no port), and a scheme taken from the downstream
  TLS state, never from `X-Forwarded-Proto`. Before, response and body-phase hooks rebuilt
  this from a request that earlier phases could already have changed, and
  the scheme was usually missing. Place `policy` before `path_rewrite`,
  `url_rewrite` and header-rewriting filters.
- A policy with request assertions but no `http.request` rules and no
  entity routes now applies its header set and strip rules instead of
  admitting the request on identity alone.
- A delegation where no minted token forms a valid upstream header now
  receives HTTP 500 (`policy.delegation_failed`) instead of forwarding the
  inbound credential.
- With `PRAXIS_REQUIRE_FIPS` set, building the policy filter refuses a build
  that is not FIPS-capable (such as a host plugin factory registered after
  startup), so that reload fails and the previous pipeline stays in place.

- Apply the policy filter's configured failure mode when a classified tool
  response is malformed JSON or lacks both a result and a valid JSON-RPC error.
  Policies with tool response hooks no longer silently skip those inputs;
  fail-closed pipelines stop delivery before the buffered payload escapes.
- Validate the complete input's UTF-8 before `json_body` rewrites or
  `json_body_field` header promotion. Invalid bytes in ignored JSON values
  can no longer produce trusted metadata or bypass the configured invalid-input
  behavior.
- Disable TLS session resumption on listeners with client authentication
  and TLS hot-reload. A handshake authenticated before a CA/CRL reload
  could finish afterward and cache stale authentication, allowing new
  connections to bypass the updated trust. New connections now perform
  full certificate verification; static mTLS and non-mTLS listeners
  retain resumption.

## [0.7.5] - 2026-10-21

### Added

- `policy` filter accepts `context_headers` and `context_meta` configuration.
  `context_headers` maps reserved-prefix HTTP headers to typed `agent.*` /
  `framework.*` extension fields (via a closed `ContextField` enum) so APL
  rules can reference host-injected values. `context_meta` stamps operator-
  defined `scope`, `tags`, and `properties` onto every policy evaluation;
  `scope` feeds the PPE's scoped route resolver for both authentication and
  authorization. ([#1388](https://github.com/praxis-proxy/praxis/pull/1388))
- A network backend contract, so an alternative to Pingora can be dropped
  in behind a Cargo feature: `praxis_core::server::ServerRuntime`,
  `praxis_core::egress::{PeerSpec, Connector, Session}`,
  `praxis_protocol::http::health::AdminRequest`, and the `backend` modules
  in `praxis-proxy-core` and `praxis-proxy-protocol` that resolve to the
  selected backend. `docs/developing/adding-backends.md` describes what a
  backend implements. ([#1407](https://github.com/praxis-proxy/praxis/pull/1407))
- With the `hedged-requests` feature, an eligible idempotent request is raced
  across healthy endpoints and the first 2xx, 3xx, or 4xx response is
  returned. The feature is off by default; when it is off, a configured
  `hedge_policy` is still parsed and every request stays on one upstream.
  ([#1372](https://github.com/praxis-proxy/praxis/pull/1372))
- Clusters accept an optional `slow_start` (`window_ms`, `aggression`) when
  built with the `slow-start` feature. Round robin, random, least-connections,
  and power-of-two-choices apply the ramp, including inside subset, priority,
  and zone-aware selection. Hash strategies keep the configured weight.
  ([#1364](https://github.com/praxis-proxy/praxis/pull/1364),
  [#1406](https://github.com/praxis-proxy/praxis/pull/1406),
  [#110](https://github.com/praxis-proxy/praxis/issues/110))
- FIPS crypto-readiness settings that let an operator require and verify
  FIPS-mode cryptography, with tests covering the readiness checks.
  ([#1365](https://github.com/praxis-proxy/praxis/pull/1365))
- A request-head filter lifecycle phase and a `head_classifier` filter that
  run on the request head before the body phase.
  ([#1380](https://github.com/praxis-proxy/praxis/pull/1380))

### Changed

- **Breaking:** the Pingora backend is now the `pingora` Cargo feature of
  `praxis-proxy`, `praxis-proxy-protocol` and `praxis-proxy-core`, on by
  default. A `--no-default-features` build (the FIPS build included) names
  it: `--features pingora,config-reload,admin-api`. A build with no backend
  feature refuses to compile the binary.
  ([#1407](https://github.com/praxis-proxy/praxis/pull/1407))
- **Breaking:** sub-request peers are `praxis_core::egress::PeerSpec` instead
  of Pingora's `HttpPeer`: `SubRequestClient::execute`, `send_streaming`,
  `HttpFilterContext::execute_subrequest`, `send_streaming_subrequest` and
  `PreparedSubrequest::{peers, peer_at}` take or return it, and
  `SubRequestClient::with_upstream_ca` takes the cached CA certificates
  rather than Pingora's parsed form. `praxis-proxy-filter` no longer depends
  on Pingora. ([#1407](https://github.com/praxis-proxy/praxis/pull/1407))
- **Breaking:** `Protocol::register` takes `&mut praxis_core::backend::Runtime`
  (the same type as before under the default feature). The admin, health and
  metrics listeners are registered through `praxis_protocol::backend::admin`;
  the `*_to_pingora_server` functions remain for callers holding a raw
  Pingora `Server`. The Praxis-owned health, metrics and KV modules are
  reachable as `praxis_protocol::http::{health, metrics, kv}`.
  ([#1407](https://github.com/praxis-proxy/praxis/pull/1407))
- **Breaking:** Rust API: `SubResponse` has a new public `version` field, so
  struct literals need `version`.
  ([#1372](https://github.com/praxis-proxy/praxis/pull/1372))

### Fixed

- `praxis-proxy-filter` exposes the streaming body mode after a buffered body
  is released. ([#1382](https://github.com/praxis-proxy/praxis/pull/1382))
- A stalled per-call DNS lookup is bounded so it no longer holds its admission
  slot indefinitely. ([#1383](https://github.com/praxis-proxy/praxis/pull/1383))
- The `policy` filter dispatches prompt and resource post hooks on the
  response. ([#1356](https://github.com/praxis-proxy/praxis/pull/1356))

### Security

- Updated `rustls-webpki` to 0.103.16 to reject certificate paths containing
  distrusted emSign intermediate public keys (`RUSTSEC-2026-0382`).
- `rustls` is 0.23.46, which fixes buffered application data sent after ECH
  rejection, Brotli certificate decompression allocating before
  authentication, an unauthenticated ServerHello downgrading later
  connections, and `Debug` impls exposing TLS secrets
  (`RUSTSEC-2026-0347`, `RUSTSEC-2026-0348`, `RUSTSEC-2026-0349`,
  `RUSTSEC-2026-0346`).
- URL-mode sub-requests no longer include their path in debug connection
  events. Paths supplied by clients can contain bearer tokens or signed
  download identifiers; the actual outbound request target is unchanged.
  ([#1419](https://github.com/praxis-proxy/praxis/pull/1419))

## [0.7.4] - 2026-10-12

### Added

- Named filter chains take a `conditions:` list that every filter in the chain
  inherits, ANDed with the filter's own conditions, wherever the chain is used
  (listeners, branch chains, outbound bindings).
  ([#1286](https://github.com/praxis-proxy/praxis/pull/1286))
- `access_log` takes an optional `template` that renders each record as one
  text line from `{field}` placeholders, such as
  `'{method} {path} {status} {duration_ms}ms'`. It can't be combined with
  `fields`. ([#1323](https://github.com/praxis-proxy/praxis/pull/1323))
- `access_log` takes an optional `sink` that writes records to stdout or to a
  file opened for append, as NDJSON (or the `template` line, if one is set),
  bypassing the tracing subscriber. Delivery is best effort: if the writer
  falls behind, records are dropped rather than blocking requests.
  ([#1324](https://github.com/praxis-proxy/praxis/pull/1324))
- `url_rewrite` has a `preserve_query_params_only` operation that keeps only
  the listed query parameters and drops the rest.
  ([#1339](https://github.com/praxis-proxy/praxis/pull/1339))
- With the `otel` feature and an OTLP exporter, Praxis continues a valid
  inbound W3C `traceparent` and exports a client span for each upstream
  attempt, so traces link across Praxis hops. The forwarded `traceparent` now
  names that client span instead of a synthetic hop ID.
  ([#1347](https://github.com/praxis-proxy/praxis/pull/1347))
- Filter conditions take `headers_present`, a list of header names that must
  all be present (any value), in both request and response conditions.
  ([#1348](https://github.com/praxis-proxy/praxis/pull/1348))
- Rust API: `praxis-proxy-filter` adds the `ClientResponseHeadersCommitted` and
  `StreamBodySuppressed` request extension markers, a typed
  `CalloutResponseTooLarge` error, and
  `FilteredSubrequestExecutor::for_callout_with_limits` for separate buffered
  and streaming callout limits.
  ([#1349](https://github.com/praxis-proxy/praxis/pull/1349))
- `router` routes accept an optional `hedge_policy` (`initial_requests`,
  `max_attempts`, `per_try_timeout_ms`, `budget_percent`), validated at load.
  The policy is parsed but, without the `hedged-requests` feature, every
  request still stays on one upstream.
  ([#1361](https://github.com/praxis-proxy/praxis/pull/1361))

### Changed

- **Breaking:** `/healthy`, `/ready` and `/metrics` moved off `admin.address`
  to their own listener, `admin.metrics_address`, which may bind a non-loopback
  address without `insecure_options.allow_public_admin`. Set it and move probes
  and scrapes there. The container image now exposes and health-checks port
  9902 instead of 9901.
  ([#1342](https://github.com/praxis-proxy/praxis/pull/1342))
- Config validation rejects an `admin.address` or `admin.metrics_address` that
  overlaps the other or a proxy listener.
  ([#1342](https://github.com/praxis-proxy/praxis/pull/1342))
- **Breaking:** Rust API: `ConditionMatch` and `ResponseConditionMatch` have a
  new public `headers_present` field, so struct literals need
  `headers_present: None`.
  ([#1348](https://github.com/praxis-proxy/praxis/pull/1348))

### Removed

- **Breaking:** Rust API: `praxis-proxy-protocol` drops
  `add_admin_endpoints_to_pingora_server` and
  `add_admin_endpoints_to_pingora_server_with_recorder`. Use
  `add_admin_api_to_pingora_server`,
  `add_health_endpoint_to_pingora_server_with_pipelines` and
  `add_prometheus_upkeep_to_pingora_server`.
  ([#1342](https://github.com/praxis-proxy/praxis/pull/1342))
- **Breaking:** Rust API: `praxis-proxy-filter` drops
  `set_policy_subrequest_connector` and
  `registered_policy_subrequest_connector`. Call
  `FilterRegistry::set_policy_connector` on the registry you build pipelines
  from. ([#1344](https://github.com/praxis-proxy/praxis/pull/1344))

### Fixed

- HTTP/1.1 responses with a body go out chunked when a response filter removes
  the upstream `Content-Length`. Before, they were delimited by closing the
  connection, so clients couldn't reuse it.
  ([#1284](https://github.com/praxis-proxy/praxis/pull/1284))
- A retry that moves to another endpoint keeps the SNI the first attempt took
  from the cluster authority or the client `Host`, instead of using the new
  endpoint's address (or no SNI at all for an IP endpoint).
  ([#1343](https://github.com/praxis-proxy/praxis/pull/1343))
- Policy filters built for two runtimes in one process no longer end up on
  each other's sub-request pool, admission limit and circuit breaker.
  ([#1344](https://github.com/praxis-proxy/praxis/pull/1344))
- A TLS cluster that reaches an IP endpoint without `tls.sni` now verifies it
  against the certificate's IP SAN; before, every request failed with a 502,
  verify on or off. `authority: { from: endpoint }` with IP endpoints no
  longer needs `allow_tls_without_sni`.
  ([#1345](https://github.com/praxis-proxy/praxis/pull/1345))
- Rust API: `Config::from_yaml` and `Config::validate` reject a bad
  `runtime.log_overrides` entry. Before, such a config loaded fine and failed
  later unless the caller ran the logging validators itself.
  ([#1346](https://github.com/praxis-proxy/praxis/pull/1346))
- Bodies buffered in `StreamBuffer` mode now hold memory in proportion to the
  payload. Before, lots of tiny chunks (small HTTP/2 DATA frames, say) could
  keep far more memory alive than the body limit allowed.
  ([#1351](https://github.com/praxis-proxy/praxis/pull/1351))

### Security

- `--dump` and the admin `/api/pipelines` view now redact credential-looking
  header matcher values (`authorization`, `x-session-id` and the like) in
  filter and chain conditions, and `--dump` redacts `credential_injection`
  values nested in `iterative_request_router` steps. Both used to print them
  as configured. ([#1286](https://github.com/praxis-proxy/praxis/pull/1286))

Releases 0.1.0 through 0.7.3 came out before this file existed; their notes
are on [GitHub Releases](https://github.com/praxis-proxy/praxis/releases).

[Unreleased]: https://github.com/praxis-proxy/praxis/compare/v0.8.0...HEAD
[0.8.0]: https://github.com/praxis-proxy/praxis/compare/v0.7.5...v0.8.0
[0.7.5]: https://github.com/praxis-proxy/praxis/compare/v0.7.4...v0.7.5
[0.7.4]: https://github.com/praxis-proxy/praxis/compare/v0.7.3...v0.7.4
