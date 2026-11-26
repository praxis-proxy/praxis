# Using the Praxis Policy Engine in Core

Praxis Core's `policy` filter embeds the [Praxis Policy Engine (PPE)][ppe].
It authorizes API and tool calls, obtains upstream credentials, redacts
sensitive fields, requires approval, and restricts actions after a session
reads sensitive data. Request rules run before the request is forwarded.
Response rules can inspect buffered content; streaming metadata rules run at
EOF, after the chunks have been released.

## Core, PPE, and Praxis AI

- **Praxis Core** runs the filter on HTTP requests and responses and applies
  its decisions when forwarding.
- **PPE** reads the policy document and runs its identity checks,
  authorization rules, delegation steps, transformations, and approvals. It
  can also be embedded in other Rust hosts.
- **Praxis AI** adds model-provider and agent-protocol filters. MCP policy
  needs its protocol classifier before `policy`. Core authorizes inference
  requests by reading their top-level `model`, without that classifier. See
  the [Praxis AI quickstart][ai-quickstart].

Core's standard build includes PPE and its builtin plugins; add `policy` to a
listener's filter chain with a policy document to enable it. Depending on the
plugins you use, you may also need an identity provider, secret store,
approval service, or session store. To build with fewer plugins, see
[build features][build-features].

## Policy use cases

### API and tool authorization

An HR employee can read compensation records; an engineer's request is denied
before it reaches the backend. Route rules decide using attributes from
verified JWT or API-key identities, and PPE can resolve the user, client, and
workload identities independently. Rules can also call embedded Cedar, CEL,
or OPA/Rego decision points. See the [tool-access example][tool-access],
[HTTP routing][http], and [PDP integration][pdp].

### Model access and inference inputs

An application can be limited to approved models. By default, a body-bearing
inference request with a missing or unlisted model is denied. Rules can also
inspect the request's tool definitions and message content, without an MCP
classifier.

Authenticated bodyless requests, such as `GET /v1/models`, use HTTP or global
authorization rules instead of the model requirement. With neither
configured, they reach the upstream on identity alone, so protect other
endpoints on the listener with HTTP/global rules or restricted routing.
[LLM routes][llm] lists the request fields, and Core's
[inference input example][llm-example] has rules that check them.

### Upstream credentials and delegation

A delegation rule can exchange a user's token (RFC 8693) for an upstream
credential with the requested audience and permissions; keep the default
token-response validation. It can also retrieve a personal access token or
API key from Vault KV v2, authenticating with the caller's verified JWT-SVID
through Vault's JWT auth method. That retrieves a stored credential and does
not mint an OAuth token; bind the Vault role to the trusted issuer and
audience, and enforce credential isolation in Vault policy. The rule selects
whose identity the credential represents and who acts on their behalf. See
[credential custody and token exchange][token-exchange],
[identity and delegation recipes][delegation], and the
[workload Vault recipe][vault].

### Redaction by caller permission

Two HR employees request the same compensation record, and only the one
allowed to view SSNs receives that field. PPE field pipelines redact or mask
MCP tool arguments and results in the proxy; `body_access: read_write`
applies the changes to the forwarded messages. See
[on-the-wire redaction][redaction] and [effects and sequencing][effects].

### Data flow across tool calls

A policy can block external email after a session reads compensation data.
The read adds a session taint label, and the email route denies the call when
the label is present, even if the email has no recognizable sensitive
pattern. A persistent session store keeps the label across requests and
proxy restarts. See the [data-flow example][data-flow] and
[session taint][taint].

### Sensitive data in tool arguments

A validator plugin can reject tool arguments containing an SSN or credit card
number before the tool runs. The host supplies the scanner and the policy
decides when to call it. For simple request matching, Core's guardrails
filter is enough; use a PPE validator when scanning belongs next to a tool's
authorization or session checks. See [PII guardrails on arguments][pii].

### Human approval and auditing

A salary adjustment above a threshold can require a manager's approval. OIDC
CIBA sends the request through a separate channel and suspends the tool call;
bind the approval to the permitted action and arguments. Once approved, the
caller retries with the approval identifier. Audit sinks record policy
decisions and effects, including delegation and approval, and the host can
supply a custom destination. See the [approval example][approval],
[approval flows][elicitation], and [auditing][audit].

### Rate limits by address or identity

Limit unauthenticated requests by client address, then limit resolved
identities and claims before authorization and forwarding. Policy routes can
select different limits. The bundled limiter is experimental: its counters
belong to each limiter instance, are not shared between replicas, and reset
on configuration reload. Distributed counting is planned. See
[policy rate limiting][limits].

## When to use other Core filters

- [IP ACL][ip-acl] allows or denies source IPs and CIDR ranges.
- [Guardrails][guardrails] matches strings, regexes, or PII patterns in
  request headers and bodies. It does not inspect response bodies; for
  policy-based output inspection or MCP redaction, use PPE's response
  controls (see the requirements below).
- [Credential injection][credentials] attaches a fixed per-cluster
  credential.

Use `policy` when rules depend on verified identity, caller permissions,
approval, or session history. The filters combine: an IP ACL can restrict
source networks while policy decides which tools a caller may use.

## Proxy and policy configuration

The proxy and the engine have separate configuration documents:

1. **`praxis.yaml`** declares listeners, upstreams, and the filter chain. The
   `policy` entry sets `config_path` and the filter's options, directly under
   `filter` with no nested `config` key.
2. **`policy.yaml`** declares PPE plugins, identity sources, routes, and
   rules. The filter loads it from `config_path`.

```yaml
- filter: policy
  config_path: /etc/praxis/policy.yaml
```

The default `body_access: read_only` keeps responses streaming. `read_write`
enables rewriting and response inspection within the configured buffer
limit. For streaming inference with response rules, chunks are released
before EOF; the full response is not buffered.

For a complete configuration, use the [Core policy example][core-example] or
the [gateway demo][demo], which provides both files, an identity provider, a
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
| Streaming inference response metadata | A host filter supplies trusted metadata, evaluated at EOF after chunks are released. Denials are reported through `PolicyResponseOutput`; this path neither inspects nor blocks streamed content. |
| Cross-call session labels | A configured session store; use persistent storage when labels must survive restarts. |
| Plugins and decision points | The corresponding build features and any services those plugins need. |

Keep body-processing policy filters in the main pipeline, because branch
chains do not run body hooks. For MCP, put the classifier before `policy` and
upstream dispatch after it. For inference, put any body rewriting before
`policy` so it evaluates the request the backend will receive. The
[policy-filter reference][filter-reference] covers header/path ordering,
timeouts, body limits, trusted endpoints, and response behavior.

## Getting started

1. Choose a scenario in [PPE use cases][use-cases].
2. Configure Core using the [policy-filter reference][filter-reference].
3. Write rules with the [PPE quick start][ppe-quickstart] and [APL guide][apl].
4. Run the [gateway demo][demo] and check both allowed and denied outcomes.

[ppe]: https://github.com/praxis-proxy/policy
[ai-quickstart]: https://github.com/praxis-proxy/ai/blob/main/docs/getting-started/quickstart.md
[build-features]: ../operating/build-features.md#selecting-policy-features
[tool-access]:
  https://github.com/praxis-proxy/policy/blob/main/docs/content/concepts/use-cases.md#1-identity-aware-tool-access
[http]:
  https://github.com/praxis-proxy/policy/blob/main/docs/content/guides/http-routing.md
[pdp]: https://github.com/praxis-proxy/policy/blob/main/docs/content/apl/pdp.md
[llm]:
  https://github.com/praxis-proxy/policy/blob/main/docs/content/guides/llm-routes.md
[llm-example]: ../../examples/configs/security/policy-llm-input.yaml
[token-exchange]:
  https://github.com/praxis-proxy/policy/blob/main/docs/content/concepts/use-cases.md#3-credential-custody-and-token-exchange
[delegation]:
  https://github.com/praxis-proxy/policy/blob/main/docs/content/guides/identity-delegation.md
[vault]:
  https://github.com/praxis-proxy/policy/blob/main/docs/content/guides/identity-delegation.md#recipe-9-a-caller-workloads-vault-stored-credential
[redaction]:
  https://github.com/praxis-proxy/policy/blob/main/docs/content/concepts/use-cases.md#2-on-the-wire-redaction
[effects]:
  https://github.com/praxis-proxy/policy/blob/main/docs/content/apl/effects.md
[data-flow]:
  https://github.com/praxis-proxy/policy/blob/main/docs/content/concepts/use-cases.md#4-cross-tool-data-flow-control
[taint]:
  https://github.com/praxis-proxy/policy/blob/main/docs/content/apl/tainting.md
[approval]:
  https://github.com/praxis-proxy/policy/blob/main/docs/content/concepts/use-cases.md#6-human-in-the-loop-approval
[pii]:
  https://github.com/praxis-proxy/policy/blob/main/docs/content/concepts/use-cases.md#5-pii-guardrails-on-arguments
[elicitation]:
  https://github.com/praxis-proxy/policy/blob/main/docs/content/apl/elicitation.md
[audit]:
  https://github.com/praxis-proxy/policy/blob/main/docs/content/guides/auditing.md
[limits]:
  https://github.com/praxis-proxy/policy/blob/main/docs/content/guides/rate-limiting.md
[ip-acl]: ../filters/http/security/ip_acl.md
[guardrails]: ../filters/http/security/guardrails.md
[credentials]: ../filters/http/security/credential_injection.md
[core-example]: ../../examples/configs/security/policy.yaml
[demo]: https://github.com/praxis-proxy/demos/tree/main/demos/policy-engine
[filter-reference]: ../filters/http/security/policy.md
[use-cases]:
  https://github.com/praxis-proxy/policy/blob/main/docs/content/concepts/use-cases.md
[ppe-quickstart]:
  https://github.com/praxis-proxy/policy/blob/main/docs/content/getting-started/quickstart.md
[apl]:
  https://github.com/praxis-proxy/policy/blob/main/docs/content/apl/index.md
