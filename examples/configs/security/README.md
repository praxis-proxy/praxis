# Security Examples

Security filters protect against threats, enforce access control, and validate requests before they reach upstream services.

## When to Use

- Block requests containing forbidden patterns (prompt injection, PII)
- Enforce CORS policies for browser-based clients
- Validate request structure and reject malformed payloads
- Implement authentication and authorization workflows
- Apply per-model guardrails for AI inference endpoints
- Restrict which destinations `HTTPS_PROXY` clients can tunnel to through a forward proxy (requires the `forward-proxy` build feature)

## Key Filters

**Guardrails**: Inspects request and response bodies for forbidden content patterns. Supports regex matching, size limits, and conditional execution (e.g., per-model gating).

**CORS**: Handles cross-origin resource sharing with configurable origins, methods, headers, and credentials.

**Policy**: Integrates with external policy engines (PPE) for complex authorization decisions based on identity, resource attributes, and environmental context.

**Forward proxy**: A listener's `forward_proxy` block accepts CONNECT tunnels, gated by a destination allowlist, by `ip_acl`/`policy` filters on the client, or both. An enabled block with neither is rejected at load, so the listener is never an open relay.

## Best Practices

- Use reserved headers (`x-praxis-*`) for metadata promoted from request bodies to prevent client spoofing
- Enable `insecure_options.skip_pipeline_checks.conditional_security` when intentionally skipping security filters for some requests
- Combine classifiers with routing and branching for defense-in-depth
- Read upstream credentials from the environment (`credential_injection` with `env_var`) rather than committing them as `value:`; see [credential-injection-env-vars.yaml](credential-injection-env-vars.yaml)

## Related Documentation

- [Security Hardening](../../../docs/operating/security-hardening.md)
- [Guardrails Filter](../../../docs/filters/http/security/guardrails.md)
- [Policy Integration](../../../docs/filters/http/security/policy.md)
