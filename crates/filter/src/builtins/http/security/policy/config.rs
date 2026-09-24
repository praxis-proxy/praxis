// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Deserialized YAML configuration for the policy security filter.

use serde::Deserialize;

// -----------------------------------------------------------------------------
// PolicyFilterConfig
// -----------------------------------------------------------------------------

/// Configuration block for the `policy` filter, which embeds the Praxis
/// Policy Engine in-process (gated behind the `policy-engine` feature,
/// on by default).
///
/// Praxis filter configs are flat: the filter's typed fields sit
/// directly under the `- filter:` entry alongside the structural keys
/// (`name`, `conditions`), not nested under a `config:` wrapper. See
/// `examples/configs/security/policy.yaml` for a runnable example.
///
/// ```yaml
/// filters:
///   - filter: policy
///     config_path: /etc/praxis/policy.yaml
///     body_access: read_write   # optional; default read_only
///     require_protocol_metadata: true
/// ```
///
/// The referenced YAML is the policy document — plugins, routes,
/// and identity-source declarations. The filter loads it once at
/// construction and rejects misconfigured policy at server startup
/// (fail-fast rather than at first request).
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PolicyFilterConfig {
    /// Body-access tier. `ReadOnly` (default) lets APL inspect request
    /// and response bodies for routing / policy decisions but discards
    /// any mutations. `ReadWrite` enables the CMF → JSON-RPC
    /// re-serialization round-trip so APL field mutators
    /// (e.g. `args.ssn: redact(!perm.view_ssn)`) rewrite the upstream
    /// body and response. Pay the round-trip cost only when needed.
    #[serde(default)]
    pub body_access: BodyAccessMode,

    /// Filesystem path to the policy document.
    pub config_path: String,

    /// Maximum time, in seconds, to wait for `PolicyEngine::initialize`
    /// at filter construction. Identity plugins fetch JWKS over HTTPS
    /// during init; a reachable-but-unresponsive identity provider
    /// would otherwise hang startup or hot-reload indefinitely. On
    /// expiry, filter construction returns an error and the server
    /// fails fast.
    ///
    /// 30s is generous for legitimate cold-cache JWKS fetches over the
    /// public internet, while short enough that misbehavior is noticed
    /// during the deploy.
    #[serde(default = "default_init_timeout_secs")]
    pub init_timeout_secs: u64,

    /// Maximum request or response body size in `ReadWrite` mode.
    /// Also used as the default inference request limit.
    #[serde(default = "default_max_buffer_bytes")]
    pub max_buffer_bytes: usize,

    /// Permit every policy endpoint a private or loopback address.
    ///
    /// By default, private DNS answers are skipped and calls with no public
    /// answer are rejected, so a private destination needs one of two opt-ins:
    /// `trusted_private_endpoints` to relax a specific host to the RFC 1918 and
    /// unique-local ranges, or this flag to relax every callout globally. Proxy
    /// upstreams use `insecure_options.allow_private_endpoints` instead.
    #[serde(default)]
    pub allow_private_idp: bool,

    /// Hosts the policy engine may reach at a private address.
    ///
    /// Narrower than `allow_private_idp`. Only a callout whose host matches an
    /// entry reaches a non-public address, and only the RFC 1918 and
    /// unique-local (`fc00::/7`) ranges an in-cluster endpoint resolves to. A
    /// listed host still cannot reach loopback, link-local (including cloud
    /// metadata), the unspecified address, or any other reserved range. Every
    /// unlisted callout stays public-only. Matched on the URL host,
    /// case-insensitive, port excluded. An IPv6 address is a bracketed literal
    /// such as `[fc00::1]`.
    ///
    /// Shared address space (`100.64.0.0/10`) is deliberately not relaxable, so
    /// a pinned endpoint on a cluster that assigns pod addresses there, such as
    /// EKS with the VPC CNI secondary-CIDR pattern, is not reachable by a pin.
    /// Relaxing that range would need a separate per-host opt-in, off by
    /// default.
    #[serde(default)]
    pub trusted_private_endpoints: Vec<String>,

    /// Fail-closed policy gate for misconfigured chains. When `true`
    /// (default), `on_request_body` rejects any request that reaches
    /// it without `mcp.method` filter-metadata. The metadata is set
    /// by the protocol classifier filter (available in the `praxis-ai` package), so
    /// its absence means either (a) the protocol classifier filter is missing from
    /// the chain, or (b) it is ordered AFTER `policy` instead of
    /// before. Either is a misconfiguration that would silently
    /// bypass CMF/APL policy.
    ///
    /// Set to `false` only when intentionally fronting non-classified
    /// traffic through the `policy` filter for identity-only
    /// enforcement (legacy behavior).
    ///
    /// Only applies to policies with MCP entity routes. Inference routes
    /// use their own gates instead.
    ///
    /// JSON-RPC methods that legitimately carry no entity (e.g.
    /// `tools/list`, `initialize`, `prompts/list`) still pass;
    /// `require_protocol_metadata` only rejects when the metadata is
    /// missing entirely.
    #[serde(default = "default_true")]
    pub require_protocol_metadata: bool,

    /// Inference authorization options.
    #[serde(default)]
    pub llm: LlmOptions,
}

/// Serde default for `require_protocol_metadata`: `true`.
fn default_true() -> bool {
    true
}

// -----------------------------------------------------------------------------
// LlmOptions
// -----------------------------------------------------------------------------

/// Inference authorization options for `llm:` routes.
///
/// ```yaml
/// llm:
///   require_model: true
///   provider: openai
///   # Replaces the default list; name every field a rule reads.
///   promote_params: [stream, max_tokens]
/// ```
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LlmOptions {
    /// Maximum buffered inference request size, in bytes.
    /// Requests over this limit receive HTTP 413.
    #[serde(default = "default_llm_max_request_bytes")]
    pub max_request_bytes: usize,

    /// Top-level scalar fields promoted to `custom.llm.<name>`.
    /// A configured list replaces the defaults.
    #[serde(default = "default_promote_params")]
    pub promote_params: Vec<String>,

    /// Operator-supplied provider recorded on `llm.provider`.
    #[serde(default)]
    pub provider: Option<String>,

    /// Deny a request whose body carries no usable top-level `model`.
    ///
    /// Enabled by default. When disabled, the request falls through to
    /// other policy paths.
    #[serde(default = "default_true")]
    pub require_model: bool,

    /// Deny a model no `llm:` route selects.
    ///
    /// Enabled by default. Disable only to admit unlisted models.
    #[serde(default = "default_true")]
    pub require_route: bool,
}

impl Default for LlmOptions {
    fn default() -> Self {
        Self {
            max_request_bytes: default_llm_max_request_bytes(),
            promote_params: default_promote_params(),
            provider: None,
            require_model: true,
            require_route: true,
        }
    }
}

/// Return the default inference request limit.
fn default_llm_max_request_bytes() -> usize {
    default_max_buffer_bytes()
}

/// Return the default promoted inference parameters.
fn default_promote_params() -> Vec<String> {
    [
        "stream",
        "max_tokens",
        "max_completion_tokens",
        "temperature",
        "top_p",
        "n",
    ]
    .iter()
    .map(|s| (*s).to_owned())
    .collect()
}

/// Default upper bound on `PolicyEngine::initialize` (seconds).
fn default_init_timeout_secs() -> u64 {
    30
}

/// Default `ReadWrite` body buffer ceiling. 10 MiB comfortably covers
/// JSON-RPC tool-call payloads while bounding per-request memory.
fn default_max_buffer_bytes() -> usize {
    10_485_760 // 10 MiB
}

/// What APL field-pipeline mutators on `args.<field>` and
/// `result.<field>` are allowed to do to the upstream body and
/// downstream response.
///
/// Mirrors `praxis_filter::BodyAccess` but lifts the decision to
/// operator configuration: the choice changes pipeline behavior (and
/// cost), so a per-filter knob is the right granularity.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum BodyAccessMode {
    /// Body is buffered for inspection / routing; mutations are
    /// discarded. APL `require()` predicates over body content
    /// (`args.amount > 1000`) work; `redact()` / `assign()` are
    /// silently dropped at the executor's write boundary.
    #[default]
    ReadOnly,

    /// Body is buffered + APL mutations to `args.*` and `result.*` are
    /// re-serialized back into the JSON-RPC body so the upstream and
    /// the downstream client see them. Costs one JSON parse +
    /// serialize per mutated request or response.
    ReadWrite,
}

/// Reject a `trusted_private_endpoints` entry that is not a bare host.
///
/// Entries match a URL host with the port excluded, so an entry that carries a
/// port, scheme, path, userinfo, wildcard, or whitespace can never match and
/// most likely hides a misconfiguration that would silently fail to pin. A
/// bracketed IPv6 literal (`[fc00::1]`) is the one form allowed a colon,
/// matching the bracketed host the URI parser produces. The error names the
/// field and the offending entry so an operator can find it.
pub(crate) fn validate_trusted_private_endpoints(entries: &[String]) -> Result<(), String> {
    for entry in entries {
        let fault = if entry.is_empty() {
            "is empty"
        } else if entry.contains(char::is_whitespace) {
            "contains whitespace"
        } else if entry.contains('/') {
            "contains '/'"
        } else if entry.contains('@') {
            "contains '@'"
        } else if entry.contains('*') {
            "contains '*'"
        } else if entry.contains(':') && !(entry.starts_with('[') && entry.ends_with(']')) {
            "contains an unbracketed ':' (use [ipv6] for a literal, and no port)"
        } else {
            continue;
        };
        return Err(format!("policy: trusted_private_endpoints entry {entry:?} {fault}"));
    }
    Ok(())
}

#[cfg(test)]
#[expect(clippy::expect_used, reason = "tests")]
mod tests {
    use super::validate_trusted_private_endpoints;

    #[test]
    fn a_bare_host_or_bracketed_ipv6_is_accepted() {
        let ok = ["maas-api.svc".to_owned(), "10.0.0.1".to_owned(), "[fc00::1]".to_owned()];
        assert!(
            validate_trusted_private_endpoints(&ok).is_ok(),
            "bare hosts and a bracketed IPv6 are valid"
        );
    }

    #[test]
    fn a_malformed_entry_is_rejected_naming_the_field_and_the_entry() {
        // A port, an unbracketed IPv6, a bracketed IPv6 with a port, a scheme,
        // a path, userinfo, a wildcard, whitespace, and an empty entry.
        for bad in [
            "host:8080",
            "::1",
            "[fc00::1]:80",
            "http://x",
            "a/b",
            "u@h",
            "wild*",
            "has space",
            "",
        ] {
            let err = validate_trusted_private_endpoints(&[bad.to_owned()]).expect_err("must reject");
            assert!(
                err.contains("trusted_private_endpoints"),
                "error names the field: {err}"
            );
            assert!(err.contains(bad), "error names the offending entry: {err}");
        }
    }
}
