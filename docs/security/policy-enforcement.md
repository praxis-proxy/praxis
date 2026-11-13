# Using the Praxis Policy Engine in Core

Praxis Core's `policy` filter embeds the [Praxis Policy Engine (PPE)][ppe]. Use
it to authorize API and tool calls, obtain upstream credentials, redact
sensitive fields, require approval, or restrict actions after a session reads
sensitive data. These rules run inside the proxy, before requests reach the
backend or responses return to the caller.

## Core, PPE, and Praxis AI

- **Praxis Core** runs the filter on HTTP requests and responses and applies
  its decisions when forwarding traffic.
- **PPE** reads the policy document and runs its identity checks,
  authorization rules, delegation steps, transformations, and approvals.
  It can also be embedded directly in other Rust hosts.
- **Praxis AI** adds model-provider and agent-protocol filters. MCP policy
  needs its protocol classifier before `policy`. Core can authorize
  inference requests by reading their top-level `model` without that
  classifier. See the [Praxis AI quickstart][ai-quickstart] for AI pipelines.

Core's standard build includes PPE and its builtin plugins. Add `policy` to a
listener's filter chain and give it a policy document to enable enforcement.
Depending on the plugins you configure, you may also need an identity provider,
secret store, approval service, or session store. The [build
features][build-features] guide explains how to select plugins for a smaller
build.

## Policy use cases

### API and tool authorization

An HR employee can read compensation records; an engineer's request is denied
before it reaches the backend. Route rules make this decision using attributes
from verified JWT or API-key identities. PPE can resolve the user, client, and
workload identities independently. Rules can also call embedded Cedar, CEL, or
OPA/Rego decision points.

The [tool-access example][tool-access] shows the HR rule in action. [HTTP
routing][http] covers API routes, and [PDP integration][pdp] explains how to
call Cedar, CEL, and OPA.

### Model access and inference inputs

An application can be limited to approved models. By default, a request with a
missing or unlisted model is denied. Rules can also inspect the parsed request's
tool definitions and message content. The filter reads these requests directly,
without an MCP classifier.

[LLM routes][llm] describes the available request fields. Core's
[inference input example][llm-example] includes rules for checking them.

### Upstream credentials and delegation

A delegation rule can exchange a user's token for an upstream credential with
the requested audience and permissions. It can also retrieve a personal access
token or API key from Vault. The rule selects whose identity the credential
represents and who is acting on their behalf.

See [credential custody and token exchange][token-exchange] and [identity and
delegation recipes][delegation].

### Redaction by caller permission

Two HR employees can request the same compensation record. Only the employee
with permission to view SSNs receives that field. PPE field pipelines redact or
mask MCP tool arguments and tool results in the proxy. Enable `body_access:
read_write` to apply the changes to the forwarded messages.

See [on-the-wire redaction][redaction] and [effects and sequencing][effects].

### Data flow across tool calls

A policy can block external email after a session reads compensation data. The
read adds a session taint label; the email route checks that label and denies
the call, even if the email contains no recognizable sensitive pattern. A
persistent session store keeps the label across requests and proxy restarts.

The [data-flow example][data-flow] demonstrates the read-then-send block.
[Session taint][taint] explains label storage and policy syntax.

### Sensitive data in tool arguments

A validator plugin can reject tool arguments containing an SSN or credit card
number before the tool runs. The host supplies the scanner, and the policy
determines when to call it. Core's guardrails filter can handle simple request
matching; use a PPE validator when scanning belongs in a tool's policy alongside
authorization or session checks.

See [PII guardrails on arguments][pii] for a scanner and audit example.

### Human approval and auditing

A salary adjustment above a threshold can require a manager's approval. OIDC
CIBA sends the approval request through a separate channel and suspends the tool
call. Once approved, the caller retries with the approval identifier. Audit
sinks record policy decisions and effects; the host can supply a custom
destination.

The [approval example][approval] walks through a salary adjustment.
[Auditing][audit] covers decision records and audit sinks.

### Rate limits by address or identity

Limit unauthenticated requests by client address, then apply limits to resolved
identities and claims before authorization and forwarding. Policy routes can
select different limits. The bundled limiter is experimental and should not be
relied on in production. Its counters belong to each limiter instance, are not
shared between replicas, and reset on configuration reload. For production
request limits, use Core's [rate_limit filter][rate-limit].

See [policy rate limiting][limits] for configuration and denial behavior.

## When to use other Core filters

For simpler rules, Core provides dedicated filters:

- [IP ACL][ip-acl] allows or denies source IPs and CIDR ranges.
- [Guardrails][guardrails] matches strings, regexes, or PII patterns in
  headers and request bodies.
- [Credential injection][credentials] attaches a fixed per-cluster credential.

Use `policy` when rules depend on verified identity, caller permissions,
approval, or session history. You can combine these filters: an IP ACL can
restrict source networks while policy decides which tools a caller may use.

## Proxy and policy configuration

The proxy and the engine have separate configuration documents:

1. **`praxis.yaml`** declares listeners, upstreams, and the filter chain.
   The `policy` entry sets `config_path` and the filter's options.
2. **`policy.yaml`** declares PPE plugins, identity sources, routes, and
   rules. The filter loads this file from `config_path`.

This fragment belongs inside a proxy filter chain:

```yaml
- filter: policy
  config_path: /etc/praxis/policy.yaml
  body_access: read_write
```

Filter fields sit directly under `filter`, without a nested `config` key. For a
complete configuration, use the [Core policy example][core-example] or the
[gateway demo][demo]. The demo provides both files, an identity provider, a
session store, and scripted allow, deny, redaction, delegation, and approval
scenarios.

### Requirements and limitations

| Control | Required integration |
| --- | --- |
| HTTP authorization and delegation | A policy document with HTTP or global controls. |
| MCP tool, prompt, and resource policy | Praxis AI classifier before `policy`; keep `require_protocol_metadata: true`. |
| MCP body rewriting and response rules | `body_access: read_write`; tool results support field pipelines, prompt and resource results do not. |
| Inference request authorization | A top-level `model` and matching `llm:` route; no MCP classifier required. |
| Inference response content inspection | `body_access: read_write` and a non-streaming JSON response; inference bodies are not rewritten by field mutators. |
| Streaming inference response metadata | A host filter supplies trusted metadata; response content is not exposed on this path. |
| Cross-call session labels | A configured session store; use persistent storage when labels must survive restarts. |
| Plugins and decision points | The corresponding build features and any services those plugins need. |

Keep body-processing policy filters in the main pipeline: branch chains do not
execute body hooks. For MCP, order the classifier before `policy` and upstream
dispatch after it. For inference, order any body rewriting before `policy` so it
evaluates the request that will reach the backend. Consult the [policy-filter
reference][filter-reference] for header/path ordering, timeouts, body limits,
trusted endpoints, and response behavior.

## Getting started

1. Choose a scenario in [PPE use cases][use-cases].
2. Configure Core using the [policy-filter reference][filter-reference].
3. Write rules with the [PPE quick start][ppe-quickstart] and [APL guide][apl].
4. Run the [gateway demo][demo] and check both allowed and denied outcomes.

[ppe]: https://github.com/praxis-proxy/policy
[ai-quickstart]: https://github.com/praxis-proxy/ai/blob/main/docs/quickstart.md
[build-features]: ../operating/build-features.md#selecting-policy-features
[tool-access]: https://github.com/praxis-proxy/policy/blob/main/docs/content/use-cases.md#1-identity-aware-tool-access
[http]: https://github.com/praxis-proxy/policy/blob/main/docs/content/http-routing.md
[pdp]: https://github.com/praxis-proxy/policy/blob/main/docs/content/apl/pdp.md
[llm]: https://github.com/praxis-proxy/policy/blob/main/docs/content/llm-routes.md
[llm-example]: ../../examples/configs/security/policy-llm-input.yaml
[token-exchange]: https://github.com/praxis-proxy/policy/blob/main/docs/content/use-cases.md#3-credential-custody-and-token-exchange
[delegation]: https://github.com/praxis-proxy/policy/blob/main/docs/content/identity-delegation.md
[redaction]: https://github.com/praxis-proxy/policy/blob/main/docs/content/use-cases.md#2-on-the-wire-redaction
[effects]: https://github.com/praxis-proxy/policy/blob/main/docs/content/apl/effects.md
[data-flow]: https://github.com/praxis-proxy/policy/blob/main/docs/content/use-cases.md#4-cross-tool-data-flow-control
[taint]: https://github.com/praxis-proxy/policy/blob/main/docs/content/apl/tainting.md
[approval]: https://github.com/praxis-proxy/policy/blob/main/docs/content/use-cases.md#6-human-in-the-loop-approval
[pii]: https://github.com/praxis-proxy/policy/blob/main/docs/content/use-cases.md#5-pii-guardrails-on-arguments
[audit]: https://github.com/praxis-proxy/policy/blob/main/docs/content/auditing.md
[limits]: https://github.com/praxis-proxy/policy/blob/main/docs/content/rate-limiting.md
[ip-acl]: ../filters/http/security/ip_acl.md
[rate-limit]: ../filters/http/traffic_management/rate_limit.md
[guardrails]: ../filters/http/security/guardrails.md
[credentials]: ../filters/http/security/credential_injection.md
[core-example]: ../../examples/configs/security/policy.yaml
[demo]: https://github.com/praxis-proxy/demos/tree/main/demos/policy-engine
[filter-reference]: ../filters/http/security/policy.md
[use-cases]: https://github.com/praxis-proxy/policy/blob/main/docs/content/use-cases.md
[ppe-quickstart]: https://github.com/praxis-proxy/policy/blob/main/docs/content/quickstart.md
[apl]: https://github.com/praxis-proxy/policy/blob/main/docs/content/apl/index.md
