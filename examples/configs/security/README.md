# Security Examples

Security filters block threats, enforce access control, and validate requests
before they reach upstream services.

## When to Use

- Block requests containing forbidden patterns (prompt injection, PII)
- Enforce CORS policies for browser clients
- Validate request structure and reject malformed payloads
- Authenticate and authorize requests
- Apply per-model guardrails to AI inference endpoints
- Restrict which destinations `HTTPS_PROXY` clients can tunnel to through a
  forward proxy (requires the `forward-proxy` build feature)

## Key Filters

**Guardrails**: inspects request headers and bodies for forbidden content,
with regex matching, size limits, and conditional execution (for example,
per-model gating).

**CORS**: cross-origin resource sharing with configurable origins, methods,
headers, and credentials.

**Policy**: authorization through the Praxis Policy Engine (PPE), based on
identity, resource attributes, and environment.

**Forward proxy**: a listener's `forward_proxy` block accepts CONNECT tunnels,
gated by a destination allowlist, by `ip_acl`/`policy` filters on the client,
or both. An enabled block with neither is rejected at load. That check is for
the presence of a control, not its strictness: an `ip_acl` with no entries
admits every client, so keep its `allow` list narrow.

The category also holds `basic_auth`, `csrf`, `ip_acl`, `credential_injection`,
`forwarded_headers`, and `peer_identity_trust`.

## Best Practices

- Promote body metadata to reserved headers (`x-praxis-*`) so clients cannot
  spoof it.
- Set `insecure_options.skip_pipeline_checks.conditional_security` when you
  skip security filters for some requests on purpose.
- Read upstream credentials from the environment (`credential_injection` with
  `env_var`) rather than committing them as `value:`; see
  [credential-injection-env-vars.yaml](credential-injection-env-vars.yaml).

## Related Documentation

- [Security Hardening](../../../docs/operating/security-hardening.md)
- [Guardrails Filter](../../../docs/filters/http/security/guardrails.md)
- [Policy Integration](../../../docs/filters/http/security/policy.md)
