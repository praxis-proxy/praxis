# Agentic Protocols

JSON-RPC 2.0 envelope parsing and protocol-specific
metadata extraction for MCP and A2A agent traffic.

## Overview

Three filters form a layered stack for agentic
protocol support. Each parses the JSON-RPC envelope
from request bodies and promotes protocol-specific
metadata to headers, metadata, and filter results.

```text
                    JSON-RPC 2.0 Envelope
                           |
              +------------+------------+
              |                         |
           MCP Filter              A2A Filter
              |                         |
     +--------+--------+       +-------+-------+
     |                  |       |               |
  Broker           Tool/       Task          SSE
  (catalog,      Resource     Routing      Scanner
   session)      metadata                (streaming)
```

## JSON-RPC Foundation

The `json_rpc` filter extracts JSON-RPC 2.0 envelope
metadata from HTTP POST request bodies:

- **Kind**: Request, Notification, Response, or Batch
- **Method**: the `method` string field
- **ID**: the `id` field (string, integer, or null)
- **Batch length**: element count for batch requests

Both MCP and A2A filters reuse `parse_json_rpc_value`
as their first parsing step, then layer
protocol-specific extraction on top.

### Configuration

- `max_body_bytes`: maximum body size to parse
  (default 1 MiB)
- `batch_policy`: `reject` (default) or `first`
  (extract metadata from the first element)
- `on_invalid`: `continue` (default), `reject`
  (400), or `error` (JSON-RPC error response)
- Header names are configurable (default
  `X-Json-Rpc-Method`, `X-Json-Rpc-Id`,
  `X-Json-Rpc-Kind`)

## MCP Protocol

The `mcp` filter extracts Model Context Protocol
metadata and optionally acts as a tool catalog
broker.

### Metadata Extraction

From the JSON-RPC envelope, the filter extracts:

- **Method**: 14 known MCP methods
  (`initialize`, `tools/list`, `tools/call`,
  `resources/read`, `prompts/get`, `ping`, etc.)
  plus `Other(String)` for extensions
- **Name**: tool, resource, or prompt name from
  `params` (for methods like `tools/call`)
- **Protocol version**: from `initialize` params or
  `Mcp-Protocol-Version` header
- **Session ID**: from `Mcp-Session-Id` header

### Header Validation

The filter validates `Mcp-Method` and `Mcp-Name`
headers against body-derived values. Configurable
behavior on mismatch (`reject` or `ignore`) and on
missing headers (`ignore`, `synthesize`, or
`reject`).

### Broker Architecture

When the `servers` key is present in config, the
filter activates as an MCP broker with a static
tool catalog:

```text
Client --> MCP Broker Filter
             |
             +-- initialize: session + version
             |                negotiation
             +-- tools/list:  aggregated catalog
             |                from all servers
             +-- ping:        local response
             +-- tools/call:  not yet supported
             |                (returns -32601)
             +-- DELETE:      session termination
```

Each server entry specifies a name, upstream cluster,
path prefix, tool prefix (for namespace isolation),
and tool list. The broker aggregates tools from all
configured servers into a single catalog response.

### Filter Results

Written under key `"mcp"` with fields: `method`,
`name`, `protocol_version`, `session_present`,
`kind`.

## A2A Protocol

The `a2a` filter extracts Agent-to-Agent protocol
metadata with optional task-ownership routing.

### Metadata Extraction

From the JSON-RPC envelope, the filter extracts:

- **Method**: 11 known A2A methods (`SendMessage`,
  `SendStreamingMessage`, `GetTask`, `ListTasks`,
  `CancelTask`, `SubscribeToTask`, push notification
  config methods, `GetExtendedAgentCard`) plus
  `Unknown(String)`
- **Family**: `Message`, `Task`,
  `PushNotification`, `AgentCard`, or `Unknown`
- **Streaming**: whether the method produces SSE
- **Task ID**: from request params (for task
  methods) or response bodies
- **Version**: from `A2A-Version` header
- **Method aliases**: configurable mapping for
  alternative method names (e.g. slash-style to
  PascalCase)

### Task Routing

When enabled, the filter maintains an in-process
task-to-cluster mapping for routing follow-up
requests to the agent that owns a task:

```text
1. SendMessage --> upstream A
     response contains task_id: "t1"
     store: t1 -> cluster A

2. GetTask(t1) --> route to cluster A
     (looked up from store)

3. CancelTask(t1) [terminal] --> cluster A
     remove: t1 from store (after TTL)
```

The `LocalTaskRouteStore` uses `RwLock<HashMap>`
with TTL-based expiry. Non-terminal task states
default to 3600s TTL; terminal states (`completed`,
`failed`, `canceled`, `rejected`) default to 300s.

### SSE Response Scanning

For streaming A2A methods, the filter scans response
bodies incrementally using `SseScanState`. The
scanner handles arbitrary chunk boundaries,
CRLF/LF/CR line endings, multi-line `data:` fields,
and scratch buffer overflow. Extracted task routes
from SSE payloads are written to the task route
store.

### Response Body Processing

The A2A filter captures response bodies to extract
task routes via two paths:

- **JSON responses**: hex-encoded buffering in
  `filter_metadata`, parsed at end-of-stream
- **SSE responses**: incremental line scanning via
  `SseScanState`, routes extracted per event

### Filter Results

Written under key `"a2a"` with fields: `method`,
`family`, `streaming`, `kind`, `task_id`, `version`.

## Shared Patterns

All three filters share these conventions:

- **Body access**: `BodyAccess::ReadOnly` +
  `BodyMode::StreamBuffer` with configurable
  `max_body_bytes`
- **Value length limit**: 256 bytes for any
  promoted header or metadata value
- **Control character check**: values are validated
  before promotion
- **`on_invalid` policy**: configurable behavior
  when the request body is not valid JSON-RPC
  (`continue`, `reject`, or `error`)
- **Feature gating**: agentic filters are always
  compiled (not behind a feature flag)

## Key Files

- `filter/src/builtins/http/ai/agentic/json_rpc/`:
  JSON-RPC 2.0 envelope parser and filter
- `filter/src/builtins/http/ai/agentic/mcp/`:
  MCP filter, broker, envelope, protocol
- `filter/src/builtins/http/ai/agentic/a2a/`:
  A2A filter, task routing, SSE scanner
- `filter/src/builtins/http/ai/agentic/mcp/broker/`:
  MCP broker with static catalog
- `filter/src/builtins/http/ai/agentic/a2a/task_routing.rs`:
  in-process task route store with TTL

## Related

- [AI Inference](ai-inference.md)
- [Payload Processing](payload-processing.md)
- [Architecture Overview](overview.md)
