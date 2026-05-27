---
issue: https://github.com/praxis-proxy/praxis/issues/191
discussion: https://github.com/praxis-proxy/praxis/discussions/185
status: proposed
authors:
  - mariusdanciu
stakeholders:
  - shaneutt
  - twghu
---

# Filter Chain Condition Expressions

### What?

This proposal introduces conditional expressions for filter chains in Praxis proxy, enabling dynamic filter execution based on request properties such as path, HTTP method, headers, and other contextual attributes.

#### Goals

- Enable conditional filter execution based on request context
- Evaluate multiple expression language options (OPA Rego, CEL, Custom DSL)
- Benchmark performance of candidate implementations
- Select an expression language that balances flexibility, familiarity, and performance
- Provide a configuration syntax that is intuitive for administrators

### Why?

#### Motivation

Currently, filter chains in Praxis have simple conditionals (e.g. `When`/`Unless`). However, more expressive conditions are needed:

- Apply different filters based on request path prefixes (e.g., `/api` vs `/public`)
- Filter requests differently based on HTTP methods (POST vs GET)
- Conditionally execute filters based on header presence or values
- Combine multiple conditions with boolean logic (AND, OR, NOT)

Without conditional expressions, users must create multiple filter chains with overlapping configurations or resort to external routing logic, leading to configuration duplication and reduced maintainability.

#### User Stories

- As a proxy administrator, I want to apply rate limiting only to POST requests to `/api` endpoints so that read operations remain unrestricted.

- As a security engineer, I want to enforce authentication filters only when the `x-admin` header is not present so that trusted internal services can bypass authentication overhead.

- As a platform operator, I want to apply different filter chains based on path prefixes without duplicating common filter configurations.

- As a developer, I want to combine multiple conditions using boolean expressions (AND, OR) so that I can express complex routing logic concisely.

- As a system administrator familiar with policy languages, I want to use a widely-adopted expression syntax (like CEL) so that I can leverage existing knowledge and tooling.

---

**Example Configuration:**

```yaml
---
- filter: json_body_field
  field: model_id
  header: X-Model-Id
  conditions:
    - expr: method("POST") && (path_prefix("/v1/chat/completions") || path_prefix("/v1/responses") || path_prefix("/v1/messages"))
```

---

> **Note**: The "How?" section will be added in a follow-up PR after evaluating the spike results from POCs and benchmarks for OPA Rego (Option 1), CEL (Option 2), and potentially a Custom DSL (Option 3).
