# Response Store

Durable persistence for OpenAI Responses API responses,
enabling retrieval (`GET`), deletion (`DELETE`), and
input-item pagination across proxy restarts.

## Design

The response store is split into two layers:

```text
ResponseStoreFilter (filter layer)
  |
  |-- classifies request (POST/GET/DELETE)
  |-- gates persistence via metadata
  |-- persists at end-of-stream via block_in_place
  v
ResponseStore trait (storage layer)
  |
  +-- SqliteResponseStore
  +-- PostgresResponseStore
```

The filter layer lives in the OpenAI responses module
and handles HTTP lifecycle concerns. The storage layer
is a generic async trait shared across providers.

## Request Phases

The filter spans three Pingora phases, each refining
the persistence decision as new information arrives:

### `on_request`

- Reads classifier metadata to determine if the
  request is persistable (POST, responses format,
  store enabled, non-streaming).
- Handles `GET /v1/responses/{id}` retrieval and
  `GET /v1/responses/{id}/input_items` pagination
  directly from the store.
- Handles `DELETE /v1/responses/{id}` locally.
- Lazily initializes the store backend.
- Sets `responses.skip_persist` metadata on init
  failure.

### `on_response`

- Re-checks skip conditions with response headers.
- Non-2xx or non-JSON responses set
  `responses.skip_persist` and bail early.

### `on_response_body`

- At end-of-stream, extracts the record from the
  buffered response JSON.
- Persists synchronously via `block_in_place`
  before returning to Pingora.
- Non-persistable exchanges release chunks via
  `FilterAction::Release` to avoid holding
  pass-through traffic.

## Threading Model

The response body hook (`on_response_body`) is a
synchronous `fn`, not `async fn`. The filter bridges
to the async store trait using:

```rust
let handle = tokio::runtime::Handle::current();
tokio::task::block_in_place(|| {
    handle.block_on(store.upsert_response(record))
})
```

This guarantees the record is durable before the
client observes the completed response, preventing
races where a subsequent `DELETE` arrives before the
upsert completes.

## Store Initialization

Store backends are lazily initialized via
`tokio::sync::OnceCell`:

- **SQLite**: Failed init is cached permanently as
  `None` and never retried (local file; unlikely to
  recover without config change).
- **PostgreSQL**: Uses `get_or_try_init` so transient
  connection failures are retried on subsequent
  requests.

## Storage Backends

### SQLite

File-backed or in-memory. In-memory databases use a
single-connection pool to avoid cross-connection
isolation. JSON columns stored as `TEXT`.

### PostgreSQL

Connection-pooled via `sqlx::PgPool`. Upsert uses
`ON CONFLICT (tenant_id, id) DO UPDATE SET ...` for
idempotent persistence. Supports configurable
`SslMode` (`disable`, `prefer`, `require`,
`verify-ca`, `verify-full`) and custom root CA
certificates.

SSRF protections reject DNS hostnames, localhost,
loopback, private, link-local, and unspecified
addresses by default. `allow_private_database_url`
opts in for development. Host validation is re-run
on every connection attempt to guard against DNS
rebinding.

## Tenant Isolation

Every query is scoped by `tenant_id`. The composite
primary key `(tenant_id, id)` enforces isolation at
the database level. `get_response` returns `None` for
wrong-tenant lookups to prevent information leakage.
Single-tenant deployments use a `"default"` sentinel.

## Body Buffering

The filter declares `BodyMode::StreamBuffer` with a
64 MiB ceiling globally. Non-streaming Responses API
payloads are bounded by output token limits (typically
under 2 MiB). Non-persistable exchanges release chunks
immediately via `FilterAction::Release` so
pass-through traffic is not held.

## Key Files

- `filter/src/builtins/http/ai/openai/responses/store/filter.rs`:
  filter implementation and lifecycle
- `filter/src/builtins/http/ai/openai/responses/store/config.rs`:
  configuration, SSRF validation
- `filter/src/builtins/http/ai/store/trait_def.rs`:
  `ResponseStore` trait
- `filter/src/builtins/http/ai/store/types.rs`:
  `ResponseRecord`, `StoreError`
- `filter/src/builtins/http/ai/store/sqlite.rs`:
  SQLite backend
- `filter/src/builtins/http/ai/store/postgres.rs`:
  PostgreSQL backend
- `filter/src/builtins/http/ai/store/schemas.rs`:
  DDL generation and identifier validation

## Related

- [Payload Processing](payload-processing.md)
- [AI Inference](ai-inference.md)
