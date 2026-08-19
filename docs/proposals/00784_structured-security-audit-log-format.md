---
issue: https://github.com/praxis-proxy/praxis/issues/784
discussion: https://github.com/praxis-proxy/praxis/issues/784
status: proposed
authors:
  - henschwartz
graduation_criteria:
  - What? and Why? direction accepted by stakeholders
  - Open questions from this proposal answered in a Decisions section
    (format choice, required fields, sink architecture, performance
    posture, relationship to
    [#126](https://github.com/praxis-proxy/praxis/issues/126) /
    dedicated filter)
  - Written comparison of candidate formats (OCSF, ECS, CloudEvents,
    custom structured JSON) with pros/cons for Praxis deployment context
  - Schema draft for the recommended format with at least one sample
    denial event mapped from real Praxis security filters
  - Recommendation on output sink architecture (separate sink vs access
    log extension) with rationale
  - Follow-up implementation issue (or explicit deferral) identified if
    the spike recommends building beyond documentation
stakeholders:
  - shaneutt
  - twghu
  - alexsnaps
---

# Structured Security Audit Log Format Evaluation

## What?

Praxis today surfaces security-relevant decisions through a mix of
**per-request access logs**, **response headers**, and **process
logs**. That is enough for debugging but not for compliance-oriented
deployments that need a **dedicated, machine-parseable audit trail**
of allow/deny decisions with stable identifiers and SIEM-ready schemas.

This proposal, from
[#784](https://github.com/praxis-proxy/praxis/issues/784), is a
**spike** under
[Epic #160 Observability](https://github.com/praxis-proxy/praxis/issues/160).
It evaluates standardized security event formats and recommends how
Praxis should emit **structured security audit records** for
request-path denials and policy decisions. The spike produces
documentation and a schema draft; **implementation is a follow-up**
once the format and sink architecture are agreed.

### Today’s signals (anchor in code)

**Request-path denials and policy outcomes**

- **`policy` filter** — rejects with stable violation codes on the
  `X-Policy-Violation` response header (for example
  `auth.invalid_token`, `policy.deny`, `pii.detected`). Codes are
  part of the public contract for audit/SIEM consumers.
- **`basic_auth`** — HTTP 401 with `WWW-Authenticate`
- **`ip_acl`** — allow/deny by client IP
- **`rate_limit`** — HTTP 429 when quotas are exceeded
- **`csrf`** — reject or log-only mode for cross-origin violations
- **`guardrails`** — configurable reject on policy match
- **`cors`** — reject mode returns HTTP 403 on origin violations

**Observability overlap (not a dedicated audit trail)**

- **`access_log` filter** — structured JSON per request via
  `tracing::info!`; volume-oriented, not scoped to security events.
  Field selection and emit-time conditions are proposed in
  [#799](https://github.com/praxis-proxy/praxis/issues/799); that
  improves access visibility but does not replace an audit schema.
- **Process logging** — for example `config reload audit` in
  `server/src/reload_diagnostics.rs` (listener/cluster/filter-chain
  diffs). That is **control-plane** audit, not per-request security
  enforcement.

**Downstream context**

Agent runtimes (for example OpenShell) audit every allow/deny
decision. When Praxis serves as an egress gateway, enterprise SIEM
pipelines expect **standardized event schemas**, not ad hoc access-log
fields or grep of `X-Policy-Violation` in response captures.

### Spike scope

Evaluate these format families for **denial / policy-decision events**:

| Format | Notes |
| --- | --- |
| **OCSF** | Open Cybersecurity Schema Framework — e.g. category 6003 (API Activity), HTTP Activity class. Versioned, vendor-backed (AWS, Splunk, IBM). |
| **ECS** | Elastic Common Schema — common in Elastic/OpenSearch stacks. |
| **CloudEvents** | CNCF envelope for event metadata; payload schema-agnostic. |
| **Custom structured JSON** | Extend Praxis conventions (violation code, filter name, identity hints, request metadata) without an external schema registry. |

For each candidate, the spike should assess:

- Fit for **denial-focused** records (not full access-log volume)
- Field mapping from Praxis sources above (especially `policy` /
  `X-Policy-Violation`)
- SIEM/OpenShift consumption path for target deployments
- Serialization cost on the hot path (qualitative; micro-benchmark only
  if needed to break a tie)
- Whether output belongs in **access logs**, a **dedicated audit
  sink**, or both

### Spike deliverables (acceptance)

1. **Written comparison** of the formats with pros/cons for Praxis
   (OpenShift egress, SIEM forwarding, operator skill sets).
2. **Schema draft** for the recommended format, including at least one
   **sample denial event** (for example `policy.deny` or
   `auth.invalid_token`) with realistic field values.
3. **Sink architecture recommendation** — separate file/syslog/Kafka
   sink vs extension of access log vs process log — with rationale and
   interaction with
   [#797](https://github.com/praxis-proxy/praxis/issues/797) (process
   log destinations) and
   [#126](https://github.com/praxis-proxy/praxis/issues/126) (custom
   access-log formats / multi-sink).

### Goals

- Pick a **default audit schema direction** (or a short prioritized
  list) that Praxis can implement without re-litigating formats per
  filter
- Define a **minimum denial record** operators and SIEM teams can rely
  on (identity, outcome, violation/rule id, request metadata,
  timestamp, correlation ids)
- Clarify **audit log vs access log** boundaries so
  [#799](https://github.com/praxis-proxy/praxis/issues/799) and
  [#126](https://github.com/praxis-proxy/praxis/issues/126) do not
  absorb compliance audit requirements by accident
- Produce enough specificity that a follow-up implementation issue can
  be estimated (dedicated `audit_log` filter vs shared emitter vs
  process-log target)

### Non-Goals

- Implementing emission, sinks, or filters in this spike
- Replacing or redesigning the `access_log` filter
- Full
  [#126](https://github.com/praxis-proxy/praxis/issues/126) scope
  (templates, per-route formats, syslog/multi-sink productization) —
  only whether [#126](https://github.com/praxis-proxy/praxis/issues/126)
  could **carry** audit events
- **Security audit log for control-plane** events (config reload,
  admin API mutations) — note interactions but out of v1 request-path
  scope unless the spike finds a unified envelope is trivial
- TCP audit parity (HTTP first; align with
  [#799](https://github.com/praxis-proxy/praxis/issues/799) /
  access-log theme)
- Defining retention, encryption, or tamper-evidence for audit files
- Evaluating every OCSF category — focus on API/HTTP activity and
  authentication/authorization outcomes relevant to proxy denials

### Open Questions

1. **Consumer formats.** Which format(s) do target deployment
   environments (OpenShift, enterprise SIEM, SOC tooling) actually
   ingest today — OCSF, ECS, CloudEvents wrapper, or custom JSON?
2. **Minimum fields.** What fields are required for a useful denial
   audit record? (identity/subject, policy rule, violation code,
   filter name, method, path, client IP, status, `request_id`,
   `trace_id`, timestamp, outcome)
3. **Sink model.** Should audit events use a **separate output sink**
   (dedicated file, syslog, Kafka) or extend the existing access log
   / process log paths?
4. **Hot-path cost.** What is acceptable serialization overhead for
   denial-only emission (expected low volume vs access log)?
5. **Vehicle vs dedicated filter.** Can
   [#126](https://github.com/praxis-proxy/praxis/issues/126) serve as
   the implementation vehicle, or does audit logging need a
   **dedicated filter** (for example `audit_log`) with its own
   conditions and schema guarantees?

## Why?

### Motivation

Access logs answer “what traffic flowed through the proxy?” Security
audit answers “**which policy decisions were made, by whom, on what
resource, with what outcome?**” Those questions overlap on denied
requests but diverge on allowed traffic volume, retention, and schema
rigor.

Today, operators stitch together:

- `access_log` lines (if enabled and sampled)
- `X-Policy-Violation` on individual responses
- Ad hoc process-log messages

That breaks down for compliance and centralized SIEM: fields are
inconsistent across filters, allow traffic drowns denials in access
logs, and there is no stable **event type** or **outcome** taxonomy
across `policy`, `ip_acl`, `rate_limit`, and siblings.

A structured audit format positions Praxis as a credible **egress
gateway** for agent workloads and regulated environments, and it
complements (rather than duplicates) work already in flight on process
logging ([#797](https://github.com/praxis-proxy/praxis/issues/797)),
runtime log levels
([#798](https://github.com/praxis-proxy/praxis/issues/798)), and
access-log field selection
([#799](https://github.com/praxis-proxy/praxis/issues/799)).

Trace correlation ([#317](https://github.com/praxis-proxy/praxis/issues/317))
should appear in the recommended schema where OTel is active, but this
spike does not implement correlation — it specifies how audit records
**relate** to traces and access logs.

### User Stories

These are stakeholder needs derived from
[#784](https://github.com/praxis-proxy/praxis/issues/784); they are
not separate tracked issues.

- As a security operator, I want denial events in a **standard schema**
  so that my SIEM can alert on policy violations without custom
  parsers per filter.
- As a compliance reviewer, I want a **dedicated audit trail** of
  enforcements (not sampled access traffic) so that reviews can
  prove what was blocked and why.
- As a platform engineer running Praxis on OpenShift, I want audit
  output that fits **existing log forwarders** (stdout/file/syslog →
  cluster logging stack) without forking Praxis.
- As an SRE, I want audit emission to be **low overhead** because
  only denials and explicit policy events are recorded, not every
  `200 OK`.
- As a Praxis maintainer, I want a spike outcome that clearly states
  whether audit belongs in
  [#126](https://github.com/praxis-proxy/praxis/issues/126), a new
  filter, or the process-log
  pipeline so we do not build three incompatible paths.
