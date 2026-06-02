# Type Design

Make invalid states unrepresentable. The type system
and serde should enforce constraints at parse time,
not at runtime.

- **Enums over strings for fixed value sets.** Never
  use `String` where the valid values are known. Use
  `#[serde(rename_all = "snake_case")]` enums. This
  gives serde-level validation and eliminates manual
  string matching:

  ```rust
  // Bad:
  mode: String, // "per_ip" | "global"

  // Good:
  #[derive(Deserialize)]
  #[serde(rename_all = "snake_case")]
  enum Mode { PerIp, Global }
  ```

- **Structs over maps for known keys.** Never use
  `BTreeMap`/`HashMap` for config deserialization when
  the key set is known. Use a struct with
  `#[serde(deny_unknown_fields)]`. Maps silently absorb
  unknown keys. Only use maps when the key set is
  genuinely open (e.g. user-defined header names).

- **Enums over multiple `Option<T>` fields.** When
  exactly one of N fields must be set, use an N-variant
  enum. Three `Option` fields with "exactly one must be
  `Some`" invariants should be a three-variant enum.
  Serde's `#[serde(rename_all = "snake_case")]` with
  external tagging handles YAML naturally.

- **`#[serde(default)]` over `Option<T>` with
  `unwrap_or`.** If an `Option<T>` is always resolved
  with `.unwrap_or(DEFAULT)`, use the concrete type with
  `#[serde(default = "fn_name")]` instead.

- **`#[serde(try_from)]` for constrained numerics.**
  When a numeric field only accepts specific values
  (e.g. HTTP redirect status 301/302/307/308), define
  an enum with `TryFrom<u16>` and
  `#[serde(try_from = "u16")]`. Validation moves to
  parse time.

- **`#[serde(deny_unknown_fields)]` by default.** Apply
  to all config structs unless the struct intentionally
  accepts arbitrary keys (extension points). Catches
  typos at parse time.
