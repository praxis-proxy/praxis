# Plan: Core type system for `filter_metadata` (#1232, #1233, #1234)

## What

Introduce `praxis_core::value::Value` — a closed, typed scalar enum — and replace
`HashMap<String, String>` in `filter_metadata` with a `FilterMetadata` newtype that owns
the map, enforces limits inside its methods, and exposes a `HashMap`-shaped API so most
existing call sites compile with minimal changes.

---

## Blocking dependency

>[!IMPORTANT]
>**Do not freeze `Value` or land the `FilterMetadata` PR until the KvStore value model in
>enhancements PR #17 is settled.** `Value` is intended as shared infrastructure across
>`filter_metadata`, the KvStore, and eventually the expression language. If the KvStore
>design adds variants (e.g. `List`, `Map`) after `Value` has shipped, that is a breaking
>change. The graduation criterion "KvStore value model (typed values, per-backend encoding)"
>must be resolved first.

---

## Design decisions

### `Value` — variant set

```rust
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    String(String),
    Bytes(Vec<u8>),
    Bool(bool),
    Int(i64),
    UInt(u64),
    // Double is intentionally absent for v1:
    // raw f64 breaks Eq (NaN != NaN), and ordered_float::NotNan<f64>
    // would be the right path when a concrete use case requires floats.
    // Defer until then to keep Value: Eq without a new dependency.
}
```

`From` impls for all lossless source types (`i8`..`i64`, `u8`..`u64`, `bool`, `String`,
`&str`, `Vec<u8>`, `&[u8]`). `TryFrom` for `isize`, `usize`, `i128`, `u128`.

`Value` implements `Display` with human-readable coercion (`42`, `true`, `hello` — not
`"hello"`). A "literal" renderer that quotes strings is deferred for the expression
language.

### `FilterMetadata` — public newtype

```rust
pub struct FilterMetadata { inner: HashMap<String, Value> }

impl FilterMetadata {
    pub fn get(&self, key: &str) -> Option<&Value>
    pub fn get_str(&self, key: &str) -> Option<Cow<str>>  // Display coercion for all variants
    pub fn insert(&mut self, key: impl Into<String>, value: impl Into<Value>) -> Option<Value>
    pub fn remove(&mut self, key: &str) -> Option<Value>
    pub fn contains_key(&self, key: &str) -> bool
    pub fn len(&self) -> usize
    pub fn is_empty(&self) -> bool
    pub fn iter(&self) -> impl Iterator<Item = (&str, &Value)>
}
```

`filter_metadata: FilterMetadata` stays a **public field** on `HttpFilterContext` and
`PingoraRequestCtx`. Limits are enforced inside `insert()`, not on the context.

No `DerefMut` — that would bypass limits.

### Size limits

Static `const`s inside `FilterMetadata`:

| Variant | Limit | Rationale |
|---|---|---|
| `Value::String` | 256 B | Unchanged from today |
| `Value::Bytes` | 1 MB | Matches current unrestrained practice; **will tighten** as large blob use cases migrate to the storage layer |
| Fixed-width (`Bool`, `Int`, `UInt`) | No size check | Fixed size, always accepted |
| Entry count | 128 | Unchanged |

>[!IMPORTANT]
>The Bytes limit carries a doc comment: *"This limit reflects current usage and will be
>tightened in a future release as large per-request blob use cases migrate to the storage
>layer (see enhancement #99)."*

### Context accessors

`HttpFilterContext::get_metadata()` and `set_metadata()` stay but are marked
`#[deprecated]`. They become one-line delegators into `ctx.filter_metadata`. Call sites
are burned incrementally — no mandatory atomic migration.

### `JsonOpStore` trait

Updated now: `set_metadata(&mut self, key: String, value: Value)`. `MapStore`'s internal
map becomes `HashMap<String, Value>`. `HttpJsonStore` delegates to
`filter_metadata.insert()`. 

>[#NOTE]
>Noted as a touch point to revisit when the storage API
>(enhancements PR #17) settles.

### `structured_metadata`

Stays `HashMap<String, serde_json::Value>` — a deliberate JSON blob store. Separate from
`Value` by design: `structured_metadata` is for passing arbitrary JSON between filters;
`Value` is the fast typed scalar path for conditions and logging.

---

## Blast radius

| Repo | Impact | Notes |
|---|---|---|
| `praxis` | Main work | All internal call sites updated atomically with the PRs |
| `ai` | Significant | `.get()` / `.remove()` return types change; `.insert()` / `.contains_key()` unchanged; initialization → `FilterMetadata::default()`; `a2a` hex-encoding can become `Value::Bytes` (nice-to-have) |
| `experimental` | Trivial | One initialization site |

---

## Sequencing — two options

>[#IMPORTANT]
>Decision between options is deferred to implementation time.

### Option A — sequential PRs to `main`

1. **PR 1 (praxis):** `praxis_core::value::Value` type only. No breaking changes —
   nothing uses it yet. Standalone and reviewable.
2. **PR 2 (praxis):** `FilterMetadata` newtype + update `filter_metadata` field in
   `HttpFilterContext` and `PingoraRequestCtx` + `JsonOpStore` update + `access_log` fix
   + deprecate context accessors. Internal call sites migrated here.
3. **PR 3 (ai):** Migrate AI repo call sites. `a2a` bytes improvement as nice-to-have.
4. **PR 4 (experimental):** Single initialization fix.

Gap between PR 1 and PR 2 is safe — the AI repo is never broken by PR 1 alone.

### Option B — feature branch in `praxis`

Stack PR 1 + PR 2 on a `feat/type-system` branch, merge to `main` once the AI repo PR is
also ready. Avoids a window where `Value` exists but nothing uses it. Downside:
longer-lived branch, more rebase friction.

---

## Deferred

- `Double(NotNan<f64>)` — `ordered_float` not added until a concrete use case requires
  float values. Raw `f64` is excluded because it breaks `Eq`; `ordered_float::NotNan` is
  the documented path forward.
- "Literal" `Value` rendering — quoting strings for expression language use (distinguishes
  `Value::String("42")` from `Value::UInt(42)` at the display layer).
- Configurable per-field size limits — revisited as part of #1266 (context collapse).
- Large blob migration from `filter_metadata` to the storage layer — tracked under
  enhancement #99.
- `Value: Serialize/Deserialize` — not needed for v1 (access_log uses `get_str`).

---

## Risks

| Risk | Mitigation |
|---|---|
| KvStore value model (enhancements PR #17) adds variants after `Value` is frozen | Hard blocker — don't freeze until graduation criterion is met |
| Storage API churn makes `JsonOpStore` update premature | Note `JsonOpStore` as a touch point; revisit on storage PR |
| AI repo migration lags and `main` is temporarily broken | Option A PR 2 is compatible for most callers; `#[deprecated]` eases the transition |
| Bytes 1 MB limit enables memory abuse per request (128 entries × 1 MB = 128 MB) | Acceptable near-term; tighten with storage layer arrival |
