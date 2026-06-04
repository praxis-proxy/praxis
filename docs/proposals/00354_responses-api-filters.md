---
issue: https://github.com/praxis-proxy/praxis/issues/354
status: proposed
authors:
  - leseb
graduation_criteria:
  - Tier decomposition accepted by stakeholders
  - State management dependency resolved (see #99)
  - How? section refinements complete
stakeholders:
  - shaneutt
  - nerdalert
  - twghu
---

# Responses API Filters

## What?

Implement the OpenAI Responses API agentic loop as
composable Praxis filters in Rust. Each filter is a
small, single-purpose unit implementing `HttpFilter`.
The agentic loop is composed by chaining filters in
YAML and using branch chains for tool-call re-entry,
not hardcoded in a monolithic orchestrator. Every step
is a public Rust function that can be called
independently.

A stateless request to a native Responses backend
(e.g. vLLM) bypasses the entire filter chain and
proxies directly with zero transformation. The filter
chain only activates when the request needs stateful
orchestration: multi-turn history, tool execution,
background processing, or persistence.

### Goals

- Decompose the Responses API into independent,
  single-purpose `HttpFilter` implementations that
  communicate via `filter_metadata` and a shared
  request-scoped state struct.
- Express the agentic tool-call loop as a branch chain
  with configurable iteration limits, not as control
  flow inside a filter.
- Provide a pass-through fast path for native Responses
  backends with sub-millisecond proxy overhead.
- Validate only what the proxy needs for its own
  operation. Let the inference server handle all
  other validation. Forward unknown fields as-is.
- Support incremental deployment: each implementation
  tier produces a working system, from stateless proxy
  (tier 0) through full agentic orchestration (tier 9).
- Persist responses, conversation history, and hidden
  messages in a pluggable store (SQLite, PostgreSQL)
  with tenant isolation from day one.
- Execute server-side tools (MCP, web search, file
  search) within the proxy loop, returning results
  to inference without client round-trips.
- Handle mixed tool calls: execute server-side tools
  immediately, then return to the client with pending
  client-side function calls for the next request.
- Transform Chat Completions streaming into Responses
  API SSE events when the backend does not speak the
  Responses protocol natively.

## Why?

### Motivation

The OpenAI Responses API is becoming the standard
interface for agentic AI workloads. Unlike Chat
Completions, it adds multi-turn state management,
server-side tool execution, background processing,
and structured streaming events. AI gateway operators
need to support this protocol whether their backends
speak it natively or only support Chat Completions.

Praxis already classifies Responses API requests via
the `openai_responses_format` filter (#372). The next step
is processing them: parsing requests, managing
conversation state, calling inference, transforming
streaming responses, dispatching tools, and looping
until the model is done. Building this as a monolithic
handler would violate Praxis's filter-pipeline
architecture and make the feature impossible to
customize, extend, or partially deploy.

Decomposing the Responses API into composable filters
means operators can:

- Deploy only the filters they need (e.g. stateless
  proxy without persistence, multi-turn without tools).
- Replace individual filters (e.g. swap the web search
  provider, use a custom file search backend).
- Insert additional filters at any point in the chain
  (e.g. guardrails before inference, logging after
  tool dispatch).
- Reuse filters in different chain configurations for
  different routes or tenants.

The pass-through mode is critical for performance.
When the backend supports `/v1/responses` natively,
simple inference calls should not pay the cost of
parsing, state management, or event transformation.
The classifier in #372 already determines the routing
decision; this proposal defines what happens on the
stateful path.

### User Stories

- As a platform engineer, I want to route
  `/v1/responses` requests to inference backends that
  only support Chat Completions so that my users get a
  consistent Responses API regardless of backend
  capabilities.
- As a proxy operator, I want to configure which
  Responses API features are active per route so that
  I can deploy incrementally without an all-or-nothing
  commitment.
- As an AI application developer, I want multi-turn
  conversations via `previous_response_id` so that my
  application does not need to manage conversation
  state client-side.
- As a platform engineer, I want the proxy to execute
  MCP tools server-side so that the agentic loop
  completes without client round-trips for each tool
  call.
- As an SRE, I want the proxy to stream Responses API
  events even when the backend only supports Chat
  Completions streaming so that clients get a uniform
  event protocol.
- As a security engineer, I want tenant isolation in
  the response store so that multi-tenant deployments
  do not leak conversation history across tenants.
- As an AI gateway operator, I want background
  response processing so that long-running agentic
  loops do not block the client connection.

## How?

### Source Material

- OpenAI Responses API spec: `docs/static/openresponses-spec.json`
- Target: `filter/src/builtins/http/ai/openai/responses/` in praxis

### Pass-Through Mode

**Owner:** [#361](https://github.com/praxis-proxy/praxis/issues/361) (Responses API format detection and routing)

When the backend supports `/v1/responses` natively (e.g., vLLM), stateless requests should bypass the entire filter chain and proxy directly to the backend with zero transformation. This is the highest-performance path and the default for simple inference calls.

**Routing decision in #361:**

```
Request arrives at POST /v1/responses
  → #361 inspects body via StreamBuffer
  → Classify: does it need stateful orchestration?

  IF any of these are true → route to STATEFUL filter chain:
    - previous_response_id is set
    - tools array is non-empty
    - store = true (default)
    - background = true
    - conversation_id is set
    - prompt_id is set

  IF none are true AND backend speaks Responses API → PASS-THROUGH:
    - Forward request body unchanged to backend /v1/responses
    - Stream SSE response back to client unchanged
    - No parsing, no state, no persistence
    - Equivalent to a reverse proxy with content-type awareness
```

**Pass-through is the fast path.** A simple `POST /v1/responses` with `store=false` and a string input hits vLLM directly with sub-millisecond proxy overhead. The filter chain only activates when the request actually needs stateful processing.

**What #361 promotes to headers for downstream routing:**
- `x-praxis-api-format: openai_responses | openai_chat_completions` — detected API format
- `x-praxis-responses-mode: passthrough | stateful` — routing decision
- Model name extracted from body for cluster routing

**Pass-through config example:**

```yaml
routes:
  - path: /v1/responses
    filters:
      - filter: responses_detect  # #361
        name: detect
        branch_chains:
          - name: stateful
            on_result:
              filter: detect
              key: mode
              result: stateful
            chain: responses-api  # our full filter chain

    # Default (no branch match) = pass-through to cluster
    cluster: vllm-backend
```

When `mode=stateful`, traffic enters our filter chain. When `mode=passthrough` (default/no match), Praxis proxies directly to the vLLM cluster — no filters touch the request or response.

---

### Architecture

Each filter implements `HttpFilter` from `praxis_filter`. Filters communicate via `HttpFilterContext`:
- `filter_metadata` — durable key-value state that persists across all lifecycle phases
- `filter_results` — ephemeral key-value pairs consumed by branch conditions
- `extra_request_headers` — headers injected into upstream requests
- Request/response body access via `on_request_body` / `on_response_body`

The agentic loop uses Praxis branch chains for tool-call re-entry. Each filter reads from and writes to well-defined metadata keys. No filter knows about the others.

### Shared State Contract

Filters communicate through two mechanisms:

#### Filter Metadata (routing keys)

Small string values in `filter_metadata` for routing decisions and branch conditions. These are lightweight — never more than a short string each:

```
responses.response_id      — current response ID (set by request_validate)
responses.conversation_id  — conversation ID (set by request_validate)
responses.store            — whether to persist (set by request_validate)
responses.background       — whether this is a background request (set by request_validate)
responses.stream           — whether client requested streaming (set by request_validate)
responses.tenant_id        — tenant ID for isolation (set by upstream auth/multi-tenancy filter)
responses.status           — response status: queued|in_progress|completed|incomplete|failed|cancelled (set by background_jobs, stream_events, tool_dispatch)
responses.iteration        — current loop iteration count (set/read by tool_dispatch)
```

#### Orchestrator State

A request-scoped `Arc<Mutex<ResponsesState>>` struct created by `response_store` during `on_request` and shared across all Responses filters. Holds the heavy data that would be too large for filter metadata (conversation history, tool definitions, streamed response state, etc.):

```rust
struct ResponsesState {
    request: ResponsesRequest,                      // parsed request body
    messages: Vec<Message>,                         // conversation history, mutated by rehydrate/tool_dispatch
    tools: Vec<ToolDefinition>,                     // registered tool definitions
    tool_choice: ToolChoice,                        // normalized tool choice, reset after first iteration
    tool_calls: Vec<ToolCall>,                      // tool calls from current inference response
    response_object: ResponseResource,              // built incrementally during streaming
    output_items: Vec<OutputItem>,                  // accumulated output items
    usage: Usage,                                   // token usage
    mcp_sessions: MCPSessionManager,                // MCP session reuse within request
    mcp_tool_map: HashMap<String, MCPServerConfig>, // tool_name → server config
    previous_tools: Vec<MCPToolListing>,            // reusable MCP tool listings from previous response
    reasoning: Option<String>,                      // accumulated reasoning content
    connector_urls: HashMap<String, String>,        // connector_id → server_url (see Parking Lot)
}
```

Filters access the orchestrator state via a well-known handle. Since filters run sequentially within a request, a full `Mutex` may not be necessary — simpler interior mutability (e.g., `RefCell` or just `&mut` access) could suffice. The exact synchronization primitive can be determined during implementation.

**Relationship to #372 (`openai_responses_format` classifier):** The #372 classifier runs upstream of our filter chain. It uses `StreamBuffer` in read-only mode to classify the request format (Responses vs Chat Completions) and promotes routing facts to metadata/headers/filter_results, but does NOT retain the parsed body. Our `request_validate` filter parses the body independently via its own `StreamBuffer`, creates `ResponsesState`, and makes it available to the rest of the chain. This means the JSON body is parsed twice (once by #372 for classification, once by `request_validate` for validation) — sub-millisecond cost, clean separation of concerns.

### Filter Specifications

#### Filter 0: `request_validate`

**Purpose:** Parse the incoming Responses API request. Extract fields the proxy needs for its own operation. Create `ResponsesState` and make it available to downstream filters. Forward all parameters to the inference server — do not validate what the proxy doesn't need.

**Validation principle:** Only validate parameters the proxy must act upon. Let the inference server handle all other validation. Different inference servers have different validation rules — if the proxy validates beyond its own needs, it either blocks valid requests (too strict) or allows invalid ones that fail downstream anyway (too loose). Unknown fields are expected and must be forwarded, never filtered.

The proxy validates:
- HTTP/JSON correctness (valid JSON syntax, correct content types)
- Parameters the proxy needs to read for its own operation (see below)

The proxy does NOT:
- Validate inference server requirements (required fields, parameter types, ranges)
- Validate nested field structures (message contents, tool schemas)
- Filter unknown parameters — forward all fields, even if unrecognized
- Enforce strict schema compliance or reject requests for unknown fields
- Selectively remove parameters before forwarding (may block entire requests for security/policy reasons, but never strip fields)

**Praxis trait methods:**
- `on_request_body` — parse JSON body, extract proxy-needed fields, create `ResponsesState`, write routing metadata
- `request_body_mode` → `StreamBuffer { max_bytes: 64MB }` (must accommodate inline `file_data` up to 32 MiB and `image_url` up to 20 MiB per the OpenAI spec)

**Behavior:**

Proxy-needed fields (read and act upon):
- `stream` — determines response delivery mode (SSE vs JSON). If `stream=false`: run the full filter chain synchronously, collect all events internally, return the final `ResponseResource` as a single JSON response.
- `store` — determines whether to persist the response
- `background` — determines whether to enqueue for async processing
- `stream` + `background` — reject `stream=true && background=true`
- `store` + `background` — reject `background=true && store=false`
- `model` — read for routing decisions (use default if null/omitted)
- `previous_response_id` — triggers rehydration in downstream filters
- `conversation_id` — triggers conversation context loading
- `tools` — proxy needs to read tool types to know which tool backends to invoke
- `tool_choice` — proxy reads to determine tool dispatch behavior
- `instructions` — preserved in state (do NOT inject as system message — in pass-through mode the inference server handles it; in conversion mode `responses_proxy` injects it during Responses → Chat Completions transformation)

Preserved and forwarded (proxy reads but does not validate):
- `include`, `metadata`, `text`, `temperature`, `top_p`, `presence_penalty`, `frequency_penalty`, `parallel_tool_calls`, `stream_options`, `max_output_tokens`, `max_tool_calls`, `reasoning`, `safety_identifier`, `prompt_cache_key`, `service_tier`, `top_logprobs`, `truncation`

Generated by proxy:
- `response_id` (UUID) — needed for persistence and rehydration
- `conversation_id` — created if not provided

State setup:
- Set routing keys in `filter_metadata`: `responses.response_id`, `responses.conversation_id`, `responses.store`, `responses.background`, `responses.stream`
- Create `ResponsesState` with the full parsed request (all fields preserved), make it accessible to all downstream filters in the chain

**Config:**
```yaml
filter: request_validate
max_body_bytes: 67108864  # 64MB — accommodates inline file_data (32 MiB) + image_url (20 MiB) per OpenAI spec
```



---

#### Filter 1: `response_store`

**Purpose:** Owns the response persistence layer. Provides the shared `ResponseStore` instance used by other filters (rehydrate, compact, background_jobs) for reads. Handles incremental upsert during streaming, final persistence, and CRUD HTTP endpoints (GET/DELETE/LIST/input_items).

**Praxis trait methods:**
- `on_request` — initialize store connection, make shared `Arc<ResponseStore>` available to other filters
- `on_response_body` — intercept SSE events for incremental upserts (`response.in_progress` → INSERT, `output_item.done` → UPDATE, terminal events → final UPDATE)
- `on_response` — persist final response state if non-streaming (`stream=false`)
- Separate route handlers (not in the agentic filter chain — registered as standalone Praxis routes):
  - `GET /v1/responses/{id}` — retrieve a stored response by ID
  - `DELETE /v1/responses/{id}` — delete a stored response
  - `GET /v1/responses` — list stored responses
  - `GET /v1/responses/{id}/input_items` — list input items with cursor-based pagination


**Behavior:**
- Schema: 2 tables
  - `responses`: id (PK), tenant_id (indexed), created_at, model, response_object (JSON), input (JSON), messages (JSON)
  - `conversation_messages`: conversation_id (PK), tenant_id (indexed), messages (JSON)
- Incremental upsert during streaming:
  - `response.in_progress` → initial INSERT with empty output
  - `output_item.done` → UPDATE with accumulated outputs
  - `response.completed/incomplete/failed` → final UPDATE
- Store hidden messages alongside public response object — this is the source of truth for future turns, not the public input/output
- Synthesize stable input item IDs (deterministic, not random)
- Access control: auth-aware fetch (return None for both "not found" and "access denied")
- `input_items` pagination: list input items with cursor-based pagination, hide compaction items
- `conversation_messages`: store/retrieve per-conversation message cache
- `store=false`: skip persistence entirely
- **Shared access:** other filters (rehydrate, compact, background_jobs) access the store via a shared `Arc<ResponseStore>` registered during `on_request`. This is why the filter must be early in the chain.

**Config:**
```yaml
filter: response_store
backend: sqlite  # sqlite | postgres
database_url: ${DATABASE_URL}  # e.g. postgres://user:pass@host:5432/db or sqlite:///path/to/db
# For postgres with TLS:
# ssl_mode: require  # disable | prefer | require | verify-ca | verify-full
# ssl_root_cert: /path/to/ca.pem
```

**Dependencies:** SQL database (authenticated)



---

#### Filter 2: `rehydrate`

**Purpose:** Load conversation context from `previous_response_id` or `conversation_id`. Reconstruct message history. Recover MCP tool listings from previous responses.

**Praxis trait methods:**
- `on_request` — read metadata, fetch from store, write enriched messages


**Behavior:**
- If `previous_response_id`: fetch stored response + hidden messages from response store
  - Prefer stored messages over reconstructing from public input/output
  - Reject if previous response is incomplete/background/in-progress
  - Extract `previous_usage` for auto-compaction
  - Recover MCP tool listings from previous output items
  - Concatenate previous input + output, then append current input — the inference server sees exactly the same items it produced as output on the previous turn, plus the new user content
- If `conversation_id` (no previous_response_id): fetch stored conversation messages, append current input
- If neither: pass current input through as-is
- Fallback: if stored messages missing (backward compat), reconstruct from public objects

**Dependencies:** Response store (SQL read)



---

#### Filter 3: `file_resolve`

**Purpose:** Resolve `file_id`, `file_data`, `file_url`, and `image_url` references in input messages to inline content.

**Praxis trait methods:**
- `on_request` — walk messages, resolve file references


**Behavior:**
- Walk all messages in `responses.messages`
- For `file_id`: fetch file content + MIME type from file store, base64 encode, build data URL
- For `file_data`: wrap in data URL format
- For `file_url`: pass through as-is
- For `input_file.filename`: preserve original filename through resolution (needed for citations)
- For `image_url` with `file_id`: resolve to data URL
- For `input_image.detail`: preserve detail level enum (`low|high|auto`, default `auto`) and pass to inference
- For tool outputs containing images/files: resolve file references in-place, preserve multi-modal content as-is (never create synthetic user messages)
- Update `responses.messages`

**Dependencies:** File store (read)



---

#### Filter 4: `tool_parse`

**Purpose:** Parse tool definitions from the request. List MCP tools. Synthesize built-in tool definitions. Normalize tool choice. Register all tools for inference.

**Praxis trait methods:**
- `on_request` — parse tools, list MCP, write tool metadata


**Behavior:**
- Parse `tools` from request: function tools, MCP tools, `web_search`, `file_search`
- For MCP tools:
  - Use `responses.connector_urls` to resolve server URLs
  - Check `responses.previous_tools` for reusable listings (keyed on `server_label + allowed_tools`)
  - If not reusable: call MCP server `tools/list` and cache results (events are NOT emitted here — `mcp_list_tools.in_progress/completed` events are emitted later by `stream_events` after `response.created`, matching OpenAI behavior)
  - Reject duplicate tool names across MCP servers
  - Apply `allowed_tools` filter
  - Build `mcp_tool_map`: tool_name → server config
- For built-in tools: synthesize function tool definitions for `web_search`, `file_search`
- `tool_choice` — read to understand dispatch behavior (e.g., `"none"` means skip tool execution entirely) but forward as-is to the inference server. Do not normalize or validate the value — the inference server handles `tool_choice` semantics.
- Response-side `tools` array: only include function tool definitions (no MCP/web_search/file_search leaking into public schema)
- Treat hallucinated/unknown tool names in responses as client-side function calls (not errors)
- Write `responses.tools`, `responses.tool_choice`, `responses.mcp_tool_map`

**Dependencies:** MCP servers (HTTP). For MCP tools with `connector_id`, requires Connectors API (see Parking Lot).



---

#### Filter 5: `responses_proxy`

**Purpose:** Call the inference backend. Pass-through to `/v1/responses` if backend supports it, or convert to `/v1/chat/completions` and proxy.

**Praxis trait methods:**
- `on_request` — build inference request, set upstream headers
- `on_request_body` — rewrite body if converting to chat completions format
- `on_response_body` — stream response body to stream_events filter


**Behavior:**
- Read `responses.messages`, `responses.tools`, `responses.tool_choice` from metadata
- If backend supports `/v1/responses`: pass through (minimal transformation)
- If backend only supports `/v1/chat/completions`:
  - Build chat completion request from messages + tools
  - Map: `temperature`, `top_p`, `frequency_penalty`, `max_completion_tokens`, `reasoning_effort`, `service_tier`, `parallel_tool_calls`, `top_logprobs`, `presence_penalty`, `extra_body`
  - Respect client's `stream` setting — if `stream=false`, send `stream=false` upstream and return the JSON response directly. If `stream=true`, set `stream_options.include_usage=true`
  - Omit `text` response_format when tools are present
  - Pass `prompt_cache_key` if configured
- Map provider SDK errors → Responses API error codes

**Config:**
```yaml
filter: responses_proxy
backend_api: auto  # auto | responses | chat_completions
```

**Dependencies:** Upstream inference backend



---

#### Filter 6: `stream_events`

**Purpose:** Transform inference streaming chunks into Responses API SSE events. Maintain the streaming state machine. Accumulate content, tool calls, and usage. Assign sequence numbers.

**Praxis trait methods:**
- `on_response_body` — process each SSE chunk, emit Responses events


**Full SSE event catalog (24 event types):**

Response lifecycle:
- `response.created` — on first chunk, carries full response snapshot
- `response.in_progress` — after created
- `response.completed` — terminal success, carries final response snapshot
- `response.incomplete` — terminal, carries `incomplete_details.reason`
- `response.failed` — terminal, carries `error` object
- `response.queued` — for background jobs, returned as JSON response (not SSE — since `stream=true && background=true` is rejected, this event only appears in the non-streaming JSON response body)

Output items:
- `response.output_item.added` — new output item started
- `response.output_item.done` — output item finalized

Content parts:
- `response.content_part.added` — new content part started
- `response.content_part.done` — content part finalized

Text:
- `response.output_text.delta` — text token, with optional `logprobs` and `obfuscation`
- `response.output_text.done` — text content finalized, carries full text + annotations
- `response.output_text.annotation.added` — citation annotation emitted inline

Function calls:
- `response.function_call_arguments.delta` — argument chunk, with optional `obfuscation`
- `response.function_call_arguments.done` — arguments finalized, carries full arguments string

Refusal:
- `response.refusal.delta` — refusal text chunk
- `response.refusal.done` — refusal finalized

Reasoning:
- `response.reasoning.delta` — reasoning text chunk
- `response.reasoning.done` — reasoning finalized
- `response.reasoning_summary_text.delta` — reasoning summary chunk
- `response.reasoning_summary_text.done` — reasoning summary finalized
- `response.reasoning_summary_part.added` — reasoning summary part started
- `response.reasoning_summary_part.done` — reasoning summary part finalized

Error:
- `error` — streaming error with `type`, `code`, `message`, `param`, optional `headers`, `sequence_number`

**Behavior:**
- If backend sent native Responses SSE: pass through (minimal transformation)
- If backend sent Chat Completion chunks, transform:
  - Track state: `message_item_added`, `content_part_emitted`, `reasoning_part_emitted`, `refusal_part_emitted`
  - Emit `response.created` on first chunk (carries full response snapshot with all request echo-back fields)
  - Emit `response.in_progress`
  - Per text chunk: emit `output_item.added` (first), `content_part.added` (first), `response.output_text.delta` (every token)
  - On text stream end: emit `response.output_text.done` (carries full text, `logprobs` array — always present, empty if not requested)
  - Per annotation: emit `response.output_text.annotation.added` inline as citations are extracted
  - Per tool call chunk: emit `output_item.added` (first per tool), `response.function_call_arguments.delta` (every chunk)
  - On tool call end: emit `response.function_call_arguments.done` (carries full arguments string)
  - Per refusal chunk: emit `response.refusal.delta` (every chunk)
  - On refusal end: emit `response.refusal.done`
  - Accumulate text into content list, tool call arguments into tool call map
  - Track `finish_reason`, `service_tier`, `model`, `usage`
  - On stream end: emit `content_part.done`, `output_item.done`, `response.completed` / `response.incomplete` / `response.failed`
  - Extract citations from text → `url_citation` annotations with `start_index`, `end_index`, `url`, `title`
  - Obfuscation on delta events: deferred (see Deferred Items)
  - Assign monotonic `sequence_number` to every event
  - Every lifecycle event (`created`, `in_progress`, `completed`, `incomplete`, `failed`) carries a full `ResponseResource` snapshot
- On error: emit `error` SSE event with proper error payload
- Write `responses.tool_calls`, `responses.response_object`, `responses.output_items`, `responses.usage`, `responses.status` to metadata
- Enable logprobs when EITHER `include` contains `message.output_text.logprobs` OR `top_logprobs` is set (matching OpenAI behavior). Include `logprobs` array on text delta/done events when enabled.



---

#### Filter 7: `tool_dispatch`

**Purpose:** Inspect inference response for tool calls. Route to appropriate tool filter. Signal loop-back to inference via branch chain. Handle mixed client/server tool calls.

**Praxis trait methods:**
- `on_response` — read tool calls, classify, dispatch, control loop


**Behavior:**
- Read `responses.tool_calls` from metadata
- Classify each tool call:
  - Function tool (client-side) → add to output items, do NOT loop
  - MCP tool → dispatch to `mcp_tool` filter
  - `web_search` → dispatch to `web_search` filter
  - `file_search` → dispatch to `file_search` filter
- For server-side tools:
  - Execute (dispatch to sub-filters or call directly)
  - Build tool-result messages, append to `responses.messages`
  - Emit `output_item.added` / `output_item.done` events for each tool result
  - Increment `responses.iteration`
  - Enforce `max_tool_calls` (built-in/MCP only, not function tools)
    - When limit hit: inject synthetic "skipped" tool message for model, no client output item
  - Reset `tool_choice` to `auto` after first iteration
**Hybrid tool call handling:** A single inference response can contain a mix of server-side tool calls (MCP, web_search, file_search) and client-side function calls. The dispatch logic must handle this:
  - Execute all server-side tool calls, collect results
  - If client-side function calls are also present: execute server-side tools first, then exit the loop and return to the client with both the server-side tool results and the pending client-side function calls. The client provides `function_call_output` items in a follow-up request, and the loop continues from there via `previous_response_id`.
  - Never assume all tool calls in a turn are the same type.

- Loop control via `filter_results`:
  - `tool_dispatch.action = "loop"` → branch back to `responses_proxy` (Praxis branch chain). Only when ALL tool calls in the turn were server-side and results are ready for the next inference call.
  - `tool_dispatch.action = "done"` → exit loop. Happens when client-side function calls are present (client must provide results before the loop can continue) or when no tool calls remain.
- Exit conditions:
  - No tool calls → done
  - Any function tool calls present → done (client must execute and send results back)
  - `responses.iteration >= max_infer_iters` → incomplete
  - `finish_reason == "length"` → incomplete

**Config:**
```yaml
filter: tool_dispatch
max_infer_iters: 10
max_tool_calls: 128
```

**Dependencies:** Tool sub-filters, response store (for output item persistence)



---

#### Filter 8: `mcp_tool`

**Purpose:** Execute a single MCP tool call against an MCP server. Handle session reuse, approval policy, and event emission.

**Praxis trait methods:**
- Called by `tool_dispatch` (direct function call, not via filter chain)
- Or: standalone filter for use in custom chains


**Request parameters supported (from MCP tool definition):**
- `type`: `"mcp"`
- `server_label`: `str` (required) — human-readable label for the server
- `server_url`: `str` (optional) — MCP server endpoint URL
- `connector_id`: `str` (optional) — resolved to `server_url` by `connector_resolve`
- `headers`: `dict` (optional) — HTTP headers for connection. `Authorization` header is explicitly rejected here (must use `authorization` field)
- `authorization`: `str` (optional, excluded from serialization) — OAuth bearer token
- `require_approval`: `"always"` | `"never"` | `ApprovalFilter` (default: `"always"` — approval required unless explicitly opted out)
  - `ApprovalFilter.always`: `list[str]` — tool names always requiring approval
  - `ApprovalFilter.never`: `list[str]` — tool names never requiring approval
- `allowed_tools`: `list[str]` | `AllowedToolsFilter` (optional) — restrict which tools from this server are available
  - `AllowedToolsFilter.tool_names`: `list[str]`

**Behavior:**
- Look up server config from `responses.mcp_tool_map`
- Check approval policy: `always` (require approval), `never` (auto-approve), filter list
  - Default: approval required
  - If approval required: emit `mcp_call.approval_request` event, check `approval_responses` in context
- Reuse MCP session from `responses.mcp_sessions` (keyed on endpoint + headers hash)
  - Create new session if not cached (protocol auto-detection: STREAMABLE_HTTP → SSE fallback)
- Call `tools/call` on MCP server
- Emit `mcp_call.in_progress`, `mcp_call.completed` / `mcp_call.failed` events- Parse result: text content, image content
- Return tool result message for next inference turn

**Dependencies:** MCP servers (HTTP/SSE)



---

#### Filter 9: `web_search`

**Purpose:** Execute a web search tool call.

**Praxis trait methods:**
- Called by `tool_dispatch`


**Request parameters supported:**
- `type`: `"web_search"` | `"web_search_preview"` | `"web_search_preview_2025_03_11"` | `"web_search_2025_08_26"` (all treated equivalently)
- `search_context_size`: `"low"` | `"medium"` | `"high"` (default: `"medium"`) — controls how much surrounding context to include with search results
- `user_location`: defined in the OpenAI spec — should be planned for (city, country, region, timezone)

**Behavior:**
- Normalize all tool type variants to `web_search`
- Pass `search_context_size` to search backend to control result depth
- Emit `web_search_call.in_progress`, `web_search_call.searching`, `web_search_call.completed` events- Execute search via configured search backend (Brave, Tavily, etc.)
- Format results as tool result message
- Return for next inference turn

**Config:**
```yaml
filter: web_search
provider: brave  # brave | tavily | etc.
api_key: ${WEB_SEARCH_API_KEY}
default_context_size: medium  # low | medium | high
```

**Dependencies:** Search API (HTTP)



---

#### Filter 10: `file_search`

**Purpose:** Execute a file search / knowledge search tool call against vector stores.

**Praxis trait methods:**
- Called by `tool_dispatch`


**Request parameters supported:**
- `type`: `"file_search"`
- `vector_store_ids`: `list[str]` (required) — IDs of vector stores to search
- `max_num_results`: `int` (default: 10, range: 1-50) — max results per store
- `filters`: `dict` (optional) — metadata filters applied to search
- `ranking_options`: (optional)
  - `ranker`: `"weighted"` | `"rrf"` | `"neural"` | custom string
  - `score_threshold`: `float` (default: 0.0) — minimum score cutoff
  - `alpha`: `float` (0.0-1.0) — weight factor for weighted ranker
  - `impact_factor`: `float` (default: 60.0) — RRF algorithm parameter
  - `weights`: `dict[str, float]` — keys: `"vector"`, `"keyword"`, `"neural"`, values must sum to 1.0
  - `model`: `str` (optional) — model for neural reranker (e.g., `"transformers/Qwen/Qwen3-Reranker-0.6B"`)

**Behavior:**
- Accept `file_search` tool type
- Fan out across all configured vector stores in parallel
- Preserve `filters`, `ranking_options`, `max_num_results` from tool call
- Force `rewrite_query=false`
- Use config-driven templates:
  - Search template: formats the search query
  - Annotation template: formats each result chunk
  - Context template: wraps all results for model consumption
- Build model-facing context prompt from results
- Extract citation markers `<|file-xxx|>` from model text → `OpenAIResponseAnnotationFileCitation` annotations
- Track `citation_files` mapping: file_id → filename
- Emit `file_search_call.in_progress`, `file_search_call.searching`, `file_search_call.completed` events- Return tool result message + citation files for annotation extraction

**Config:**
```yaml
filter: file_search
vector_store_url: http://localhost:8001
api_key: ${VECTOR_STORE_API_KEY}
auth_type: bearer  # bearer | api_key | none
search_template: "..."
annotation_template: "..."
context_template: "..."
```

**Dependencies:** Vector store API (HTTP, authenticated)



---

#### Filter 11: `compact`

**Purpose:** Token counting and context window management. Summarize conversation history when threshold is exceeded.

**Praxis trait methods:**
- `on_request` — check token count, compact if needed


**Behavior:**
- Check `context_management` parameter for compaction config
- Count tokens via provider usage (from `previous_usage`) or tiktoken estimate
- If token count > threshold:
  - Build summarization prompt from conversation messages
  - Prepend `instructions` to summarization prompt
  - Call inference API with configured `compaction_model`
  - Extract summary text
  - Apply `summary_prefix` if configured
  - Create `OpenAIResponseCompaction` item with summary as `encrypted_content` (misleading name — it's plain text)
  - Replace conversation history with compaction item + preserved user messages
  - Store compaction response in response store (hidden, usable as `previous_response_id`)
  - Hide compaction items from `input_items` API response
- Update `responses.messages` with compacted messages
- Also handles explicit `POST /v1/responses/compact` requests

**Config:**
```yaml
filter: compact
default_model: gpt-4o-mini  # model for summarization
tiktoken_encoding: cl100k_base
```

**Dependencies:** Inference backend (for summarization), response store



---

#### Filter 12: `reasoning`

**Purpose:** Post-streaming reasoning summarization. The reasoning accumulation and streaming events (`response.reasoning.delta/done`) are handled by `stream_events`. The reasoning endpoint fallback (`openai_chat_completions_with_reasoning` → `openai_chat_completion`) is handled by `responses_proxy`. This filter only runs after streaming completes to optionally generate a reasoning summary via a second inference call.

**Praxis trait methods:**
- `on_response` — after streaming completes, check if summarization is needed, make second inference call


**Behavior:**
- During inference call: try `openai_chat_completions_with_reasoning` first, fall back to regular `openai_chat_completion` on `NotImplementedError`
- During streaming: accumulate reasoning content from chunks
- After streaming: if `reasoning.generate_summary` is configured:
  - Build summary prompt from accumulated reasoning text
  - Make second inference call for summarization
  - Emit `reasoning_summary_text.delta`, `reasoning_summary_text.done` events
  - Track summary usage separately
- Add reasoning item to output items with or without summary
- **Safety note:** Reasoning summaries are meant to be safe to show to end users, unlike raw reasoning content which is not considered user-safe. The summarization step may need guardrailing or safety filtering to ensure the summary does not expose unsafe content from the raw reasoning chain of thought — it should be a user-safe distillation, not a strict reproduction.

**Config:**
```yaml
filter: reasoning
summary_model: gpt-4o-mini  # model for reasoning summarization
```

**Dependencies:** Inference backend (for summarization)



---

#### Filter 13: `background_jobs`

**Purpose:** Handle background response processing. Queue, workers, timeout, cancellation, polling.

**Praxis trait methods:**
- `on_request` — if `background=true`, enqueue and return immediately with queued response
- Separate: worker loop that processes queued requests through the full filter chain
- HTTP handler: `POST /v1/responses/{id}/cancel`


**Behavior:**
- Queue: bounded channel (capacity 100)
- Workers: 10 long-lived tokio tasks pulling from queue
- Per-request timeout: 5 minutes
- On enqueue:
  - Store response with `status=queued` in response store
  - Return immediately with queued response object
  - Worker picks up, runs full filter chain, updates store
  - Handle `QueueFull` → reject (ensure no orphaned queued responses are left in storage)
- Cancellation:
  - Fetch response, check status
  - If `queued`: update to `cancelled`
  - If `in_progress`: cancel tokio task + update to `cancelled`
  - If already terminal: conflict error
  - Idempotent for already-cancelled
- Polling: clients GET the response to check status

**Config:**
```yaml
filter: background_jobs
queue_size: 100
num_workers: 10
timeout_seconds: 300
```

**Dependencies:** Response store, tokio runtime



---

---

#### Filter 14: `code_interpreter` (future)

**Purpose:** Execute code in a sandboxed container environment. Return stdout/stderr and generated files.

**Status:** Not yet implemented. Part of the OpenAI Responses API spec.

**Request parameters (from OpenAI spec):**
- `type`: `"code_interpreter"`
- `container`: container/sandbox configuration
  - `image`: container image to use
  - `resources`: CPU/memory limits
  - `timeout`: execution timeout
- `allowed_languages`: optional list of permitted languages

**Behavior:**
- Receive code from model's tool call
- Spin up sandboxed container (or reuse existing session)
- Execute code with timeout and resource limits
- Capture stdout, stderr, and any generated files
- Emit `code_interpreter_call.in_progress`, `code_interpreter_call.interpreting`, `code_interpreter_call.completed` events
- Return execution results + file outputs as tool result message

**Config:**
```yaml
filter: code_interpreter
runtime: docker  # docker | kata | firecracker | wasm
default_image: python:3.12-slim
timeout_seconds: 30
max_memory_mb: 512
max_cpu_cores: 1
sandbox_network: none  # none | restricted | full
```

**Dependencies:** Container runtime



---

#### Filter 15: `computer_use` (future)

**Purpose:** Execute computer use actions (screenshots, clicks, typing) in a virtual desktop environment.

**Status:** Not yet implemented. Part of the OpenAI Responses API spec.



---

### Tool Type Coverage

| Tool type | Filter | Status |
|-----------|--------|--------|
| `function` | `tool_parse` + `tool_dispatch` (client-side) | Covered |
| `mcp` | `tool_parse` + `mcp_tool` | Covered |
| `web_search` (+ preview variants) | `web_search` | Covered |
| `file_search` | `file_search` | Covered |
| `code_interpreter` | `code_interpreter` | Future (filter 14) |
| `computer_use` | `computer_use` | Future (filter 15) |

---

### Filter Chain Configuration

#### Full agentic loop:

```yaml
filter_chains:
  - name: responses-api
    filters:
      - filter: request_validate
        name: validate

      - filter: response_store
        name: store
        # Initializes shared store, persists on response

      - filter: background_jobs
        name: background
        # Returns immediately for background requests

      - filter: rehydrate
        name: rehydrate

      - filter: file_resolve
        name: files

      - filter: compact
        name: compact

      - filter: tool_parse
        name: tools

      - filter: responses_proxy
        name: inference

      - filter: stream_events
        name: events

      - filter: tool_dispatch
        name: dispatch
        max_infer_iters: 10
        max_tool_calls: 128
        branch_chains:
          - name: tool-loop
            on_result:
              filter: dispatch
              key: action
              result: loop
            rejoin: inference  # re-enter at responses_proxy
            max_iterations: 10

      - filter: reasoning
        name: reasoning
        # Runs AFTER tool_dispatch decides the loop is done
```

#### Minimal (no tools, no history):

```yaml
filter_chains:
  - name: responses-simple
    filters:
      - filter: request_validate
      - filter: response_store
      - filter: responses_proxy
      - filter: stream_events
```

#### Multi-turn with MCP tools:

```yaml
filter_chains:
  - name: responses-mcp
    filters:
      - filter: request_validate
      - filter: response_store
      - filter: rehydrate
      - filter: tool_parse
      - filter: responses_proxy
      - filter: stream_events
      - filter: tool_dispatch
        branch_chains:
          - name: tool-loop
            on_result:
              filter: tool_dispatch
              key: action
              result: loop
            rejoin: responses_proxy
            max_iterations: 10
```

### Implementation Tiers

Build order, each tier produces a working system:

| Tier | Filters | What works after | External deps |
|------|---------|-----------------|---------------|
| 0 | `request_validate`, `response_store`, `responses_proxy`, `stream_events` | Stateless proxy with persistence. Text streaming. CRUD works. | Inference backend, SQL |
| 1 | + `rehydrate` | Multi-turn via `previous_response_id` and `conversation_id`. | None (reads from response_store) |
| 2 | + `tool_parse`, `tool_dispatch` | Tool definitions parsed, loop control. Client-side function tools. | None |
| 3 | + `web_search` | Server-side web search tool execution. | Search API (Brave/Tavily) |
| 4 | + `mcp_tool` | MCP server-side tool execution with session reuse and approval. | MCP servers, #24 foundation |
| 5 | + `file_search` | Vector store search with citations. | Vector Store API, Files API |
| 6 | + `file_resolve` | File references in input resolved to inline content. | Files API |
| 7 | + `reasoning` | Reasoning endpoint fallback and summarization. | Inference backend (second call) |
| 8 | + `compact` | Context window management and auto-compaction. | Inference backend (summarization) |
| 9 | + `background_jobs` | Background processing with queue, workers, cancellation. | None (internal) |

### Filter Count

| Category | Count |
|----------|-------|
| MVP filters | 14 |
| Future filters | 2 (`code_interpreter`, `computer_use`) |
| Parking lot (requires API support) | 2 (`prompt_resolve`, `connector_resolve`) + Conversations API |

### File Structure in Praxis

```
filter/src/builtins/http/ai/openai/responses/
  mod.rs                    # Module exports
  types.rs                  # Shared types: ResponsesRequest, ResponseObject, SSE events, etc.
  request_validate/
    mod.rs                  # Filter impl
    config.rs               # YAML config
  rehydrate/
    mod.rs
    config.rs
  file_resolve/
    mod.rs
    config.rs
  tool_parse/
    mod.rs
    config.rs
  responses_proxy/
    mod.rs
    config.rs
    convert.rs              # Chat Completion ↔ Responses conversion
  stream_events/
    mod.rs
    config.rs
    state_machine.rs        # Chunk processing state machine
  tool_dispatch/
    mod.rs
    config.rs
  mcp_tool/
    mod.rs
    config.rs
    session.rs              # MCP session management
    approval.rs             # Approval policy
  web_search/
    mod.rs
    config.rs
  file_search/
    mod.rs
    config.rs
    citations.rs            # Citation extraction
  compact/
    mod.rs
    config.rs
  reasoning/
    mod.rs
    config.rs
  response_store/
    mod.rs
    config.rs
    schema.rs               # SQL schema + migrations
    store.rs                # CRUD operations
  background_jobs/
    mod.rs
    config.rs
    queue.rs                # Bounded channel + workers
```

### Shared Crate Dependencies

```toml
[dependencies]
tokio = { version = "1", features = ["full"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
sqlx = { version = "0.8", features = ["runtime-tokio", "sqlite", "postgres", "json"] }
reqwest = { version = "0.12", features = ["stream", "json"] }
reqwest-eventsource = "0.6"
uuid = { version = "1", features = ["v4"] }
tiktoken-rs = "0.6"
async-trait = "0.1"
bytes = "1"
thiserror = "2"
tracing = "0.1"
```

### Praxis Integration Dependencies

This design does not exist in isolation. Several Praxis epics provide foundational capabilities that our Responses filters must build on rather than reimplementing.

#### MCP Foundation ([#24](https://github.com/praxis-proxy/praxis/issues/24))

The MCP epic has a 9-PR implementation plan covering JSON-RPC parsing, MCP classification, gateway, and sessions. Our `mcp_tool` filter must depend on this foundation:

- **PRs 1-2** (`agentic-foundation`, `agentic-safety`): JSON-RPC parser and header hygiene — already landed as the `json_rpc` and `mcp` filters in `filter/src/builtins/http/ai/agentic/`. Our filters reuse these for MCP envelope parsing.
- **PRs 3-4** (`mcp-classifier`, `mcp-gateway`): Tool discovery, backend registry, catalog aggregation, `tools/list` body mutation. Our `tool_parse` filter's MCP tool listing should delegate to the MCP gateway's tool catalog rather than reimplementing `tools/list` calls directly. When the gateway is available, `tool_parse` reads from the gateway's aggregated catalog. When running without the gateway (standalone mode), `tool_parse` calls MCP servers directly as a fallback.
- **PR 5** (`mcp-sessions`): Session lifecycle, lazy backend init, local session store. Our `mcp_tool` filter's session management (`responses.mcp_sessions` in metadata) should use the session traits defined by this PR. This means `mcp_tool` implements tool invocation and approval logic, but delegates session create/get/cleanup to the MCP session infrastructure.
- **PR 6** (`agentic-state-redis`): Distributed session state via Redis/Valkey. Enables horizontal scaling of MCP sessions across Praxis instances. Our filters don't depend on this directly, but `mcp_tool` automatically benefits when the session backend is Redis instead of local.

**Action:** `mcp_tool` and `tool_parse` should be implemented after PRs 3-5 land, or in parallel with clear trait boundaries so the integration is a swap, not a rewrite.

#### SSE Streaming Inspection ([#143](https://github.com/praxis-proxy/praxis/issues/143), part of [#19](https://github.com/praxis-proxy/praxis/issues/19))

The AI Inference epic (#19) defines SSE streaming inspection capabilities: per-event filter hooks, streaming token extraction from delta content fields, cross-chunk event reassembly, and backpressure-aware buffering.

Our `stream_events` filter is the primary consumer of this infrastructure. Specifically:

- **Per-event hooks**: `stream_events` needs to intercept each SSE event from the upstream inference response, parse it, and either pass through (native Responses backend) or transform (Chat Completion backend) into Responses API events.
- **Cross-chunk reassembly**: SSE events can be split across TCP chunks. The streaming inspection layer must reassemble complete `data:` lines before `stream_events` processes them.
- **Token extraction**: `stream_events` extracts text deltas, tool call argument deltas, and usage from streaming chunks — this is exactly the "streaming token extraction from delta content fields" that #19 describes.

**Action:** If #143 provides a generic SSE parsing/emission framework (parse upstream SSE → per-event callback → emit downstream SSE), `stream_events` should build on it. If #143 is not yet implemented, `stream_events` should implement SSE parsing inline but follow the same pattern so it can be refactored to use the shared infrastructure later.

#### Inference API Translation ([#96](https://github.com/praxis-proxy/praxis/issues/96) → [#213](https://github.com/praxis-proxy/praxis/issues/213))

Our `responses_proxy` filter with `backend_api: chat_completions` mode performs Responses API → Chat Completions conversion. #96 was closed as duplicate of #213 (Provider abstraction: unified request/response types), which defines unified request/response envelopes across OpenAI, Anthropic, and Google with per-provider serialization and streaming normalization.

#213 is open and unassigned. No conversion utilities exist yet.

**Action:** Our `responses_proxy` implements Responses ↔ Chat Completions conversion inline in `convert.rs`. Structure the conversion as a standalone module with clear input/output types so it can adopt #213's unified types when they land. The conversion module should be reusable by other filters or crates — not coupled to Praxis filter internals.

#### Multi-Tenancy ([#91](https://github.com/praxis-proxy/praxis/issues/91))

Tenant-level routing and persistence configuration affects several of our filters:

- **`response_store`**: Needs tenant-scoped database access. Options: (a) per-tenant database/schema, (b) tenant column in shared tables with row-level filtering, (c) tenant ID injected via Praxis context from upstream auth filter. The response store schema should include a `tenant_id` column from day one, even if multi-tenancy enforcement comes later.
- **`rehydrate`**: Must enforce tenant isolation when loading previous responses — a tenant must not access another tenant's conversation history.
- **`file_resolve`**: File storage is tenant-scoped — file IDs resolve within a tenant boundary.
- **`compact`**: Compaction creates stored responses that must be tenant-scoped.
- **`background_jobs`**: Background queue may need per-tenant quotas and isolation.

**Action:** Add `tenant_id` to the response store schema and the `responses.tenant_id` metadata key. The tenant ID is set by Praxis's auth/multi-tenancy filters (upstream of our chain) and read from `filter_metadata` or request headers. Our filters enforce isolation but don't implement tenant management.

### Open Questions

1. **Branch chain API for tool loop.** The `rejoin` directive in branch chains needs to support re-entering mid-chain (at `responses_proxy`) rather than restarting from the top. Validate this works with Praxis's current branch chain implementation. See [praxis#354](https://github.com/praxis-proxy/praxis/issues/354).

2. **Sub-filter invocation.** `tool_dispatch` needs to call `mcp_tool`, `web_search`, `file_search` — but these are peer filters, not nested. Options: (a) direct Rust function calls (not via filter chain), (b) sub-chains, (c) trait objects. Direct function calls are simplest and match ADR-03's "public functions" philosophy.

3. **Streaming SSE emission.** Depends on #143 landing. If not available, `stream_events` implements SSE parsing inline following the same pattern for later refactoring.

4. **Response store shared access.** Multiple filters need the response store (rehydrate reads, response_store writes, compact reads/writes, background_jobs reads/writes). Options: (a) shared `Arc<ResponseStore>` in filter config, (b) Praxis KV store registry, (c) per-filter store instances. `Arc<ResponseStore>` is simplest.

5. **MCP session lifecycle.** Depends on #24 PR 5 landing. Our `mcp_tool` should use the session traits from that PR. If not available, implement inline with the same trait boundary for later swap.

6. **Multi-tenancy schema.** Add `tenant_id` to response store schema proactively. Enforcement depends on #91 landing upstream auth/tenant filters.

### ResponseResource Builder

Every `response.created`, `response.in_progress`, `response.completed`, `response.incomplete`, and `response.failed` SSE event carries a full `ResponseResource` snapshot. The final persisted response also uses this shape. All fields must be sourced correctly:

**From request (echo-back):**
- `model`, `instructions`, `metadata`, `temperature`, `top_p`, `presence_penalty`, `frequency_penalty`, `top_logprobs`, `max_output_tokens`, `max_tool_calls`, `parallel_tool_calls`, `store`, `background`, `service_tier`, `safety_identifier`, `prompt_cache_key`
- `tools` — only function tool definitions (no MCP/web_search/file_search)
- `tool_choice` — normalized per spec union
- `text` — `format` + `verbosity`
- `reasoning` — `effort` + `summary` enum
- `previous_response_id`

**Generated:**
- `id` — from `responses.response_id`
- `object` — always `"response"`
- `created_at` — Unix timestamp at request start
- `completed_at` — Unix timestamp when terminal status reached (null while in-progress)

**From streaming state:**
- `status` — `queued|in_progress|completed|incomplete|failed|cancelled`
- `output` — accumulated output items array
- `usage` — `input_tokens`, `output_tokens`, `total_tokens`, with details:
  - `input_tokens_details.cached_tokens`
  - `output_tokens_details.reasoning_tokens`
- `incomplete_details.reason` — set when status is `incomplete` (e.g., `"max_output_tokens"`, `"max_tool_calls"`)
- `error` — set when status is `failed`, with `code` (string) and `message` (string) per OpenAPI `Error` schema

**Defaulted:**
- `truncation` — default to `"disabled"`, echo back in response. Full truncation behavior deferred (see Deferred Items).

### Parking Lot — Requires API Support

The following filters are part of the full Responses API vision but require backing API services (Prompts API, Connectors API) that don't exist in Praxis yet. They are not part of the MVP filter set.

#### `prompt_resolve`

**Purpose:** Resolve `prompt_id` (with optional version) to system instructions. Handle variable substitution and media variables.

**Requires:** A Prompts API service that stores prompt templates with versions, variables, and media content. Praxis needs either a built-in prompt store or an external Prompts API endpoint.


**Behavior when implemented:**
- Fetch prompt template by ID + version from prompt store
- Validate that provided variables exist in template
- Substitute text variables in template content
- For media variables: insert `[Image: var_name]` placeholder in system message, append actual media as separate user message
- Prompt system message prepended before `instructions` system message

**MVP workaround:** Users pass `instructions` directly in the request instead of referencing a `prompt_id`. The `request_validate` filter already handles `instructions` injection as a system message.



#### `connector_resolve`

**Purpose:** Resolve `connector_id` to `server_url` for MCP tools that don't specify a URL directly.

**Requires:** A Connectors API service that stores connector configurations (MCP server URLs, metadata). Praxis needs either a built-in connector store or an external Connectors API endpoint.


**Behavior when implemented:**
- Scan `tools` in request for MCP tools with `connector_id` but no `server_url`
- Resolve each `connector_id` → `server_url` via Connectors API
- Note: does NOT resolve auth tokens. Auth comes from the tool's own `authorization` field.

**MVP workaround:** MCP tools must specify `server_url` directly instead of using `connector_id`. The `tool_parse` filter accepts `server_url` on MCP tool definitions.



#### Conversations API

Conversations API — currently handled internally by `response_store` via the `conversation_messages` table. A standalone Conversations API with CRUD endpoints would enable external consumers to read/manage conversation state. Not needed for MVP since `rehydrate` reads directly from the store.

---

### Deferred Items

The following spec capabilities are acknowledged but deferred from the initial implementation:

**Input types:**
- `input_video` (`InputVideoContent`) — video input support not yet planned
- `ItemReferenceParam` — internal item references for rehydration
- `ReasoningItemParam` as request input — reasoning rehydration from `encrypted_content`

**Request parameters:**
- `truncation` (`auto|disabled`) — context truncation strategy
- `reasoning.summary` alignment — spec uses `auto|concise|detailed` enum; needs mapping to internal summarization config

**Streaming:**
- `stream_options.include_obfuscation` — obfuscation field on delta events (spec default: `true`)
- Reasoning summary part events (`response.reasoning_summary_part.added/done`) — pending reasoning filter maturity

**Response fields:**
- Full `reasoning` object in response (`effort`, `summary` enum, content with `encrypted_content`)
- `truncation` echo-back in `ResponseResource`

**Guardrails:**
- Input guardrails (pre-inference safety check on input messages)
- Output guardrails (per-chunk or batched safety check on generated content, with refusal replacement)
- Guardrail ID resolution (`safety_api.routing_table.list_shields()`)
- Deferred pending Praxis guardrails integration ([#138](https://github.com/praxis-proxy/praxis/issues/138))

**Tool types:**
- `code_interpreter` — requires container runtime (filter 16)
- `computer_use` — requires virtual desktop environment (filter 17)
