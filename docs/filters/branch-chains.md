# Branch Chains

Branch chains add conditional paths to your filter
pipeline. A filter produces a result, and a branch
condition reads it to decide whether to divert,
short-circuit, skip ahead, or loop back.

## What Branch Chains Do

- **Short-circuit responses**: block a request and
  return a static response without reaching the
  backend
- **Skip filters**: bypass middleware (CORS, headers)
  for requests that don't need it
- **Retry loops**: re-run a section of the pipeline
  after mutating headers or refreshing tokens
- **Protocol-specific paths**: route gRPC and
  JSON-RPC requests through different filter chains

## Quick Start

This example blocks requests when the `guardrails`
filter detects a dangerous header:

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

When guardrails flags a request, it writes
`status=blocked` to its filter results. The branch
condition matches, the static 403 fires, and
`rejoin: terminal` stops the pipeline. Normal
requests pass through to routing.

See
`examples/configs/branching/conditional-terminal.yaml`
for the complete runnable config.

## How It Works

### Writing Filter Results

Filters write key-value pairs to a
`FilterResultSet`, keyed by the filter's **type
name** (from `HttpFilter::name()`). Results are
cleared after branch evaluation. For the full
lifecycle and API, see
[Pipeline Concepts: Filter Results](../architecture/pipeline-concepts.md#filter-results).

Built-in filters that write results:
- `guardrails`: `status` = `blocked` | `passed`
- `json_rpc`: `kind`, `method`, `id`, `id_kind`,
  `batch_len`
- `grpc_detection`: `kind` = `grpc` | `grpc-web`

### Defining Branches

Branches are defined in the `branch_chains` field on
a filter entry:

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

**`on_result.filter`** must name the **host filter**
the branch is attached to — its filter **type name**
(the return value of `HttpFilter::name()`, e.g.
`"guardrails"`), not the user-assigned `name:` on the
entry, and not some other filter in the chain. A
branch only ever sees its own host filter's results:
the pipeline clears `filter_results` after each
filter's branch evaluation, so a condition naming a
different filter could never match and is rejected at
startup. See
[Pipeline Concepts: Two Meanings of "Name"][names].

[names]: ../architecture/pipeline-concepts.md#the-two-meanings-of-name

**`on_result.result`** is the expected value. In the
Rust code, this field is called `value` but is
serialized as `result` in YAML for readability.

**`on_result.key`** defaults to `"status"`. Override
it to match other result keys (e.g., `key: kind`
for `grpc_detection`).

**Unconditional branches** omit `on_result` entirely
and always fire.

**Multiple branches** on one filter are evaluated in
order; the first match with a non-`next` rejoin wins.
Up to 16 branches per filter.

### Rejoin Points

After a branch's filters execute, the pipeline
resumes at the rejoin point:

| Rejoin value | Behavior |
|-------------|----------|
| `next` (default) | Continue with the filter after the branch point |
| `terminal` or `client` | Stop the pipeline. If the branch selected a cluster (via `router` + `load_balancer`), the request is forwarded upstream. Otherwise the branch must produce the response (e.g. a `static_response` filter); a terminal branch that neither selects a cluster nor produces a response fails closed with a 500. |
| `<filter_name>` (forward) | Skip to the named filter (must be after the branch point) |
| `<filter_name>` (backward) | Re-enter at the named filter; requires `max_iterations` |

Named rejoin targets use the **entry name** (the
user-assigned `name:` on a filter entry), not the
filter type name.

**Re-entrance** (backward rejoin) requires
`max_iterations` to prevent infinite loops. The
counter increments each time the branch fires; when
exceeded, the branch falls through to `Continue`.

### Chain References

Branch chains reference filters via `chains:`, which
accepts two formats:

**Named reference** — points to a top-level chain:

```yaml
chains:
  - utility_chain
```

**Inline definition** — defines filters directly:

```yaml
chains:
  - name: inline_chain
    filters:
      - filter: static_response
        status: 403
```

Both can be mixed and are concatenated in order.

## Patterns

### Unconditional Sub-Chain

Always run an audit chain, then continue:

```yaml
branch_chains:
  - name: always_audit
    chains:
      - audit
```

See `examples/configs/branching/unconditional-branch.yaml`.

### Conditional Terminal

Short-circuit on a condition — block and respond
without reaching the backend:

```yaml
branch_chains:
  - name: block_request
    on_result:
      filter: guardrails
      result: blocked
    rejoin: terminal
    chains:
      - name: response
        filters:
          - filter: static_response
            status: 403
```

See `examples/configs/branching/conditional-terminal.yaml`.

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

Re-run classification after mutating headers, capped
at 2 iterations:

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

Multiple conditional branches on one filter act like
a switch/case with first-match-wins:

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

A branch in one chain can rejoin at a named filter
in another chain, because all listener chains are
concatenated into one flat pipeline:

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

**Body hooks** (`on_request_body`, `on_response_body`)
do **not** run for filters inside branch chains.
Body-transforming filters must be in the main
pipeline path. This is enforced at build time: a
filter that declares body access inside a branch
chain is rejected as a pipeline ordering error, and
body access declared by branch filters never enables
pipeline-wide body buffering.

**Nested control flow**: `SkipTo` and `ReEnter` from
nested branches (branches within branches) are
discarded. Only `Terminal` and `Reject` propagate
upward from nested branches.

**Same-type result sharing**: two instances of the
same filter type in a pipeline share the same
`filter_results` key. The second instance's results
overwrite the first's.

## Configuration Reference

### BranchChainConfig

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | string | required | Globally unique branch name |
| `chains` | list | required | Chain references (named or inline) |
| `on_result` | object | `null` | Condition; omit for unconditional |
| `rejoin` | string | `"next"` | Where to resume (`next`, `terminal`, `client`, or filter name) |
| `max_iterations` | integer | `null` | Required for backward rejoin; range 1-100 |

### BranchCondition (`on_result`)

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `filter` | string | required | Filter TYPE name (from `HttpFilter::name()`) |
| `key` | string | `"status"` | Result key to check |
| `result` | string | required | Expected value |

### ChainRef

Named reference (plain string):

```yaml
chains:
  - utility_chain
```

Inline definition (object with `name` and `filters`):

```yaml
chains:
  - name: inline
    filters:
      - filter: static_response
        status: 200
```

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
