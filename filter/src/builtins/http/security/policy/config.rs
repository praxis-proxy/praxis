// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Deserialized YAML configuration for the policy security filter.

use serde::Deserialize;

// -----------------------------------------------------------------------------
// PolicyFilterConfig
// -----------------------------------------------------------------------------

/// Configuration block for the experimental `policy` filter, which
/// embeds the CPEX policy engine in-process (gated behind the
/// `cpex-policy-engine` feature, off by default).
///
/// Praxis filter configs are flat: the filter's typed fields sit
/// directly under the `- filter:` entry alongside the structural keys
/// (`name`, `conditions`), not nested under a `config:` wrapper. See
/// `examples/configs/security/policy.yaml` for a runnable example.
///
/// ```yaml
/// filters:
///   - filter: policy
///     config_path: /etc/praxis/cpex-policy.yaml
///     body_access: read_write   # optional; default read_only
///     require_protocol_metadata: true
/// ```
///
/// The referenced YAML is the CPEX policy document — plugins, routes,
/// and identity-source declarations. The filter loads it once at
/// construction and rejects misconfigured policy at server startup
/// (fail-fast rather than at first request).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyFilterConfig {
    /// Body-access tier. `ReadOnly` (default) lets APL inspect request
    /// and response bodies for routing / policy decisions but discards
    /// any mutations. `ReadWrite` enables the CMF → JSON-RPC
    /// re-serialization round-trip so APL field mutators
    /// (e.g. `args.ssn: redact(!perm.view_ssn)`) rewrite the upstream
    /// body and response. Pay the round-trip cost only when needed.
    #[serde(default)]
    pub body_access: BodyAccessMode,

    /// Filesystem path to the CPEX YAML policy document.
    pub config_path: String,

    /// Maximum time, in seconds, to wait for `PluginManager::initialize`
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

    /// Maximum request/response body bytes buffered in `ReadWrite`
    /// mode. `ReadWrite` uses `StreamBuffer` to accumulate the whole
    /// body before APL field mutators run; without a cap an oversized
    /// payload could exhaust memory. Ignored in `ReadOnly` mode, which
    /// streams. The pipeline rejects an unbounded buffer at config
    /// load, so this always carries a concrete ceiling.
    #[serde(default = "default_max_buffer_bytes")]
    pub max_buffer_bytes: usize,

    /// Fail-closed policy gate for misconfigured chains. When `true`
    /// (default), `on_request_body` rejects any request that reaches
    /// it without `protocol.method` filter-metadata. The metadata is set
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
    /// Note: JSON-RPC methods that legitimately carry no entity (e.g.
    /// `service/list`, `initialize`, `template/list`) still pass —
    /// `require_protocol_metadata` only rejects when the metadata is
    /// missing entirely.
    #[serde(default = "default_true")]
    pub require_protocol_metadata: bool,
}

/// `#[serde(default = ...)]` requires a free function for primitives
/// without a `Default` impl that returns the desired value.
fn default_true() -> bool {
    true
}

/// Default upper bound on `PluginManager::initialize` (seconds).
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
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BodyAccessMode {
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
