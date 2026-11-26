# Type Design

Make invalid states unrepresentable: the type system and serde enforce
constraints at parse time, not at runtime.

- **Enums over strings for fixed value sets.** Never use `String` where the
  valid values are known. A `#[serde(rename_all = "snake_case")]` enum gets
  serde-level validation and needs no manual string matching:

  ```rust
  // Bad:
  mode: String, // "per_ip" | "global"

  // Good:
  #[derive(Deserialize)]
  #[serde(rename_all = "snake_case")]
  enum Mode { PerIp, Global }
  ```

- **Structs over maps for known keys.** Never deserialize config into a
  `BTreeMap`/`HashMap` when the key set is known; maps silently absorb unknown
  keys. Use a struct with `#[serde(deny_unknown_fields)]`. Maps are for
  genuinely open key sets (e.g. user-defined header names).

- **Enums over multiple `Option<T>` fields.** When exactly one of N fields
  must be set, use an N-variant enum instead of N `Option` fields that must
  have exactly one `Some`. `#[serde(rename_all = "snake_case")]` with external
  tagging handles the YAML.

- **`#[serde(default)]` over `Option<T>` with `unwrap_or`.** If an `Option<T>`
  is always resolved with `.unwrap_or(DEFAULT)`, use the concrete type with
  `#[serde(default = "fn_name")]`.

- **`#[serde(try_from)]` for constrained numerics.** When a numeric field
  accepts only specific values (e.g. HTTP redirect status 301/302/307/308),
  define an enum with `TryFrom<u16>` and `#[serde(try_from = "u16")]`, which
  moves validation to parse time.

- **`#[serde(deny_unknown_fields)]` by default** on every config struct, so
  typos fail at parse time, unless the struct intentionally accepts arbitrary
  keys (extension points).
