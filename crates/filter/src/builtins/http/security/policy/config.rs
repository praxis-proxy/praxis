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

    /// Permit private or loopback policy endpoints.
    ///
    /// By default, private DNS answers are skipped and calls with no public
    /// answer are rejected. Proxy upstreams use
    /// `insecure_options.allow_private_endpoints` instead.
    #[serde(default)]
    pub allow_private_idp: bool,

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
    /// Note: JSON-RPC methods that legitimately carry no entity (e.g.
    /// `tools/list`, `initialize`, `prompts/list`) still pass —
    /// `require_protocol_metadata` only rejects when the metadata is
    /// missing entirely.
    #[serde(default = "default_true")]
    pub require_protocol_metadata: bool,

    /// Inference authorization options.
    #[serde(default)]
    pub llm: LlmOptions,
}

/// `#[serde(default = ...)]` requires a free function for primitives
/// without a `Default` impl that returns the desired value.
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
