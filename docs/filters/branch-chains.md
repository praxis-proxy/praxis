# Branch Chains

Branch chains add conditional paths to a filter pipeline. A filter writes a
result, and a branch condition reads it to divert, short-circuit, skip ahead,
or loop back. Uses include returning a static response without reaching the
backend, skipping browser middleware (CORS, headers) for API requests,
re-running part of the pipeline after mutating headers or refreshing tokens,
and sending gRPC and JSON-RPC requests through different filter chains.

## Quick Start

This config blocks requests when the `guardrails` filter detects a dangerous
header:

```yaml
filter_chains:
  - name: main
    filters:
      - filter: guardrails
        action: flag
        rules:
          - target: header
            name: "X-Danger"
            contains: "true"
        branch_chains:
          - name: block_banned
            on_result:
              filter: guardrails
              result: blocked
            rejoin: terminal
            chains:
              - name: blocked_response
                filters:
                  - filter: static_response
                    status: 403

      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints: ["127.0.0.1:3000"]
```

When guardrails flags a request, it writes `status=blocked` to its filter
results. The branch condition matches, the static 403 fires, and
`rejoin: terminal` stops the pipeline. Other requests continue to routing.
The runnable config is
`examples/configs/branching/conditional-terminal.yaml`.

## How It Works

### Writing Filter Results

Filters write key-value pairs to a `FilterResultSet` keyed by the filter's
type name, and the pipeline clears them after branch evaluation; see
[Pipeline Concepts: Filter Results](../architecture/pipeline-concepts.md#filter-results)
for the lifecycle and API. Results a filter writes while the request body is
buffered ahead of the request phase (for example `json_rpc`, or `guardrails`
body rules) are held until that filter's turn in the pipeline, so its branches
see them wherever it sits.

Built-in filters that write results:

- `guardrails`: `status` = `blocked` | `passed`
- `json_rpc`: `kind`, `method`, `id`, `id_kind`, `batch_len`
- `grpc_detection`: `kind` = `grpc` | `grpc+proto` | `grpc+json` |
  `grpc+other`

### Defining Branches

Branches go in the `branch_chains` field of a filter entry:

```yaml
- filter: guardrails
  branch_chains:
    - name: block_banned          # Globally unique
      on_result:                  # Condition (omit for unconditional)
        filter: guardrails        # Filter TYPE name
        result: blocked           # Expected value
      rejoin: terminal            # Where to resume
      chains:                     # Filters to execute
        - name: response
          filters:
            - filter: static_response
              status: 403
```

`on_result.filter` must name the host filter the branch is attached to, by
its type name (the return value of `HttpFilter::name()`, e.g.
`"guardrails"`), not the `name:` on the entry and not another filter in the
chain. The pipeline clears `filter_results` after each filter's branch
evaluation, so a condition naming a different filter could never match, and
startup rejects it. See
[Pipeline Concepts: Two Meanings of "Name"][names].

[names]: ../architecture/pipeline-concepts.md#the-two-meanings-of-name

`on_result.result` is the expected value: a plain value matches exactly, and
an operator matches a family of values (see [Result Matchers](#result-matchers)).
The Rust field is `value`, serialized as `result` in YAML.

`on_result.key` defaults to `"status"`. Override it to match another result
key (e.g., `key: kind` for `grpc_detection`).

A branch without `on_result` is unconditional and always fires. Several
branches on one filter are evaluated in order, and the first match with a
non-`next` rejoin wins. A filter can have up to 16 branches.

### Result Matchers

A plain `result:` matches one exact value. When a filter reports a family of
values (a guardrail that answers `safe` or `unsafe01` through `unsafe13`, or a
severity of `0`, `2`, `4`, or `6`), use a single-key mapping that names an
operator:

```yaml
on_result:
  filter: content_check            # any filter that writes a verdict
  key: verdict
  result: safe                     # exact match
  # result: { contains: unsafe }   # the value contains this text
  # result: { not: safe }          # any other value, or no value at all
  # result: { any_of: [2, 4, 6] }  # equals one of these values
```

| Form | Fires when | Fires with no value |
|------|-----------|---------------------|
| `result: <value>` | the value equals it | no |
| `contains: <text>` | the value contains the text | no |
| `not: <value>` | the value is anything else | **yes** |
| `any_of: [<value>, ...]` | the value equals one entry | no |

`not` fires when the filter wrote no value for the key, so a deny branch
written as `not: safe` doesn't let a request through just because the
guardrail gave no verdict. It replaces the older two-branch pattern (a
`result: safe` branch that skips ahead past an unconditional deny branch),
which fails closed the same way. If a missing value should let the request
through, list the bad values with `contains` or `any_of`, which never fire
without a value.

Every value follows the rules for a plain `result:`: not empty, at most 256
bytes, ASCII letters, digits, `_`, and `-`. Matching is case-sensitive.
Unquoted numbers and booleans are read as their plain text (`0`, `true`);
quote anything YAML would rewrite, like `"007"`. See
`examples/configs/branching/result-matchers.yaml`.

### Rejoin Points

After a branch's filters run, the pipeline resumes at the rejoin point:

| Rejoin value | Behavior |
|-------------|----------|
| `next` (default) | Continue with the filter after the branch point |
| `terminal` or `client` | Stop the pipeline (see below) |
| `<filter_name>` (forward) | Skip to the named filter (must be after the branch point) |
| `<filter_name>` (backward) | Re-enter at the named filter; requires `max_iterations` |

A `terminal` branch either produces the response (e.g. a `static_response`
filter) or, in an ordinary routing pipeline, selects a cluster via `router` +
`load_balancer` and forwards upstream. A binding-enabled pipeline must publish
its request-scoped binding from a top-level router; branch routers are
rejected there. A terminal branch that does neither fails closed with a 500,
and a cluster or upstream chosen before the branch does not count. A nested
terminal branch must always produce a response; selecting an upstream there
fails closed with a 500.

Named rejoin targets use the entry name (the `name:` on a filter entry), not
the filter type name.

Re-entrance (backward rejoin) requires `max_iterations` to prevent infinite
loops. The counter increments each time the branch fires; once it is
exceeded, the branch falls through to `Continue`.

### Chain References

`chains:` takes named references to top-level chains, inline definitions
(an object with `name` and `filters`), or a mix of both, concatenated in
order:

```yaml
chains:
  - utility_chain           # named reference
  - name: inline_chain      # inline definition
    filters:
      - filter: static_response
        status: 403
```

See `examples/configs/branching/named-chain-ref.yaml`.

## Patterns

The conditional terminal pattern is the [Quick Start](#quick-start).

### Unconditional Sub-Chain

Always run an audit chain, then continue:

```yaml
branch_chains:
  - name: always_audit
    chains:
      - audit
```

See `examples/configs/branching/unconditional-branch.yaml`.

### Skip-Forward

Skip browser middleware for API requests:

```yaml
- filter: headers
  name: classify
  branch_chains:
    - name: skip_browser
      on_result:
        filter: headers
        key: status
        result: api
      rejoin: routing    # Named filter ahead
      chains:
        - name: api_prep
          filters:
            - filter: headers
              request_add:
                - name: X-API
                  value: "true"

- filter: cors           # Skipped for API requests
- filter: forwarded_headers  # Skipped for API requests

- filter: router
  name: routing           # rejoin target
  routes: [...]
```

See `examples/configs/branching/conditional-skip-to.yaml`.

### Re-Entrance Loop

Re-run classification after mutating headers, at most 2 iterations:

```yaml
- filter: headers
  name: classify
  branch_chains:
    - name: reclassify
      on_result:
        filter: headers
        key: action
        result: retry
      rejoin: classify    # Loop back
      max_iterations: 2
      chains:
        - name: retry_prep
          filters:
            - filter: headers
              request_add:
                - name: X-Retry
                  value: "true"
```

See `examples/configs/branching/reentrance.yaml`.

### Multiple Branches

Several conditional branches on one filter are checked in order. A matching
branch with `rejoin: next` runs and evaluation moves on to the next branch.
The first matching branch with any other rejoin ends evaluation, as does a
branch chain that rejects or sends a terminal response:

```yaml
branch_chains:
  - name: blocked
    on_result:
      filter: guardrails
      result: blocked
    rejoin: terminal
    chains: [blocked_response]
  - name: flagged
    on_result:
      filter: guardrails
      result: flagged
    rejoin: next
    chains: [flag_handler]
```

See `examples/configs/branching/multiple-branches.yaml`.

### Cross-Chain Rejoin

All of a listener's chains are concatenated into one flat pipeline, so a
branch in one chain can rejoin at a named filter in another:

```yaml
listeners:
  - name: web
    filter_chains: [preprocessing, routing]

filter_chains:
  - name: preprocessing
    filters:
      - filter: headers
        branch_chains:
          - name: skip_to_route
            rejoin: route  # In the 'routing' chain
            chains: [utility]
  - name: routing
    filters:
      - filter: router
        name: route        # Target for rejoin
        routes: [...]
```

See `examples/configs/branching/cross-chain-flat.yaml`.

## Constraints

| Limit | Value |
|-------|-------|
| Maximum branch nesting depth | 10 |
| `max_iterations` range | 1-100 |
| Branches per filter | 16 |
| Total branches across config | 256 |

### Response Hooks

`on_response` runs for every branch filter whose
`on_request` ran, so `cors`, `headers` response operations, and
`credential_injection` behave the same inside a branch as on the main path.
They unwind in reverse like top-level filters: a branch's filters run
`on_response` in reverse order just before their host filter's
`on_response`, and a nested branch unwinds just before the branch filter that
hosts it.

- A branch filter that rejected or answered the request still runs
  `on_response`. One skipped by its `conditions`, left unreached because the
  branch stopped early, or whose error propagated under
  `failure_mode: closed` does not.
- `response_conditions` and `failure_mode` apply as at top level, and a
  rejection from a branch filter's `on_response` stops the response phase.
- Re-entrance (`max_iterations` loops) does not repeat the hook: each branch
  filter runs `on_response` at most once per request, however many passes ran
  its `on_request`.
- Filters that `rejoin` skips over, or that a `terminal` rejoin never reaches,
  do not run `on_response`.

### Body Hooks

`on_request_body` and `on_response_body` do not run for
filters inside branch chains, so body-transforming filters must be on the
main pipeline path. The build enforces this: a filter that declares body
access inside a branch chain is rejected as a pipeline ordering error, and
body access declared by branch filters never enables pipeline-wide body
buffering.

### Security Filters

Inside branch sub-chains, security filters follow the
top-level rules: a security-critical filter (for example `ip_acl` or
`rate_limit`) that carries request `conditions` or sets
`failure_mode: open` is rejected at build time, however deeply it is nested.
The branch executor honours both settings, so otherwise such a filter would
be skipped silently for non-matching requests or have its errors swallowed.
The same overrides apply:
`insecure_options.skip_pipeline_checks.conditional_security` and
`insecure_options.allow_open_security_filters`.

The branch's own `on_result` gate is separate. A security filter in a
conditional branch is skipped for every request the condition doesn't match,
even when the filter itself is unconditional and fail-closed. That is often
deliberate (the branch is the operator's admission decision, as in
`examples/configs/branching/nested-branches.yaml`), so startup reports it as
an advisory, not an error:

```text
security filter 'ip_acl' is reached only through
conditional branch 'gated'; it runs only for matching
requests
```

The gate is inherited: the advisory also fires for a security filter in an
unconditional branch nested inside a conditional one, and names the outermost
gating branch. Put the filter on the main pipeline path, or in an
unconditional branch, when it must apply to every request.

### Nested Control Flow

`SkipTo` and `ReEnter` from nested branches
(branches within branches) are discarded. Only `Terminal` and `Reject`
propagate upward from nested branches.

### Results From Pre-Request Hooks

`on_result.filter` uses the filter type
name, but results published by head or pre-read body hooks are held for the
instance that published them. Each instance receives only its own staged
results before its request hook and branches run, including when it publishes
no result or its hook is skipped. Promoted headers and flat metadata remain
shared request values, so later writes to them still take precedence.

## Configuration Reference

### BranchChainConfig

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | string | required | Globally unique branch name |
| `chains` | list | required | [Chain references](#chain-references) (named or inline) |
| `on_result` | object | `null` | Condition; omit for unconditional |
| `rejoin` | string | `"next"` | Where to resume (`next`, `terminal`, `client`, or filter name) |
| `max_iterations` | integer | `null` | Required for backward rejoin; range 1-100 |

### BranchCondition (`on_result`)

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `filter` | string | required | Filter TYPE name (from `HttpFilter::name()`) |
| `key` | string | `"status"` | Result key to check |
| `result` | string | required | Expected value |

## Related

- [Pipeline Concepts](../architecture/pipeline-concepts.md):
  how chains become pipelines, filter results
  lifecycle, naming
- [Filter System](README.md):
  HttpFilter/TcpFilter traits, context, body access
- [Life of a Request](../architecture/life-of-a-request.md):
  step-by-step request walkthrough
- Example configs:
  [`examples/configs/branching/`](../../examples/configs/branching/),
  [`examples/configs/pipeline/branch-chains.yaml`](../../examples/configs/pipeline/branch-chains.yaml)
