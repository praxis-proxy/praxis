// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Consolidated security override flags.
//!
//! All options default to `false` (secure by default). Each flag
//! demotes one specific security check from an error to a warning.

use serde::Deserialize;

// -----------------------------------------------------------------------------
// SkipPipelineChecks
// -----------------------------------------------------------------------------

/// Per-check flags for pipeline validation bypass.
///
/// Each flag skips one specific ordering check in the filter pipeline.
/// Prefer these granular flags over the blanket
/// [`InsecureOptions::skip_pipeline_validation`] flag.
///
/// ```
/// use praxis_core::config::SkipPipelineChecks;
///
/// let checks = SkipPipelineChecks::default();
/// assert!(!checks.any());
///
/// let all = SkipPipelineChecks::all();
/// assert!(all.conditional_security);
/// assert!(all.misaligned_clusters);
/// ```
#[expect(clippy::struct_excessive_bools, reason = "per-check skip flags")]
#[derive(Clone, Debug, Default, Deserialize, serde::Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct SkipPipelineChecks {
    /// Skip check: security filters with request conditions (bypass risk).
    pub conditional_security: bool,

    /// Skip check: multiple cluster-selecting filters before load balancer.
    pub conflicting_cluster_selectors: bool,

    /// Skip check: duplicate `load_balancer` filters.
    pub duplicate_load_balancers: bool,

    /// Skip check: multiple path rewriting filters.
    pub duplicate_rewrite_filters: bool,

    /// Skip check: duplicate `router` filters.
    pub duplicate_routers: bool,

    /// Skip check: `load_balancer` without a preceding router.
    pub lb_without_router: bool,

    /// Skip check: cluster references not matching load balancer config.
    pub misaligned_clusters: bool,

    /// Skip check: unconditional `static_response` blocking subsequent
    /// filters.
    pub unreachable_filters: bool,
}

impl SkipPipelineChecks {
    /// Returns a [`SkipPipelineChecks`] with all flags set to `true`.
    ///
    /// ```
    /// use praxis_core::config::SkipPipelineChecks;
    ///
    /// let all = SkipPipelineChecks::all();
    /// assert!(all.any());
    /// assert!(all.lb_without_router);
    /// assert!(all.duplicate_routers);
    /// ```
    pub fn all() -> Self {
        Self {
            conditional_security: true,
            conflicting_cluster_selectors: true,
            duplicate_load_balancers: true,
            duplicate_rewrite_filters: true,
            duplicate_routers: true,
            lb_without_router: true,
            misaligned_clusters: true,
            unreachable_filters: true,
        }
    }

    /// Returns `true` if any check is skipped.
    ///
    /// ```
    /// use praxis_core::config::SkipPipelineChecks;
    ///
    /// assert!(!SkipPipelineChecks::default().any());
    ///
    /// let mut checks = SkipPipelineChecks::default();
    /// checks.duplicate_routers = true;
    /// assert!(checks.any());
    /// ```
    pub fn any(&self) -> bool {
        self.conditional_security
            || self.conflicting_cluster_selectors
            || self.duplicate_load_balancers
            || self.duplicate_rewrite_filters
            || self.duplicate_routers
            || self.lb_without_router
            || self.misaligned_clusters
            || self.unreachable_filters
    }
}

// -----------------------------------------------------------------------------
// InsecureFlag
// -----------------------------------------------------------------------------

/// Build the [`InsecureOptions::flags`] table, naming each flag after its field.
///
/// Destructures exhaustively, so a new [`InsecureOptions`] field fails to
/// compile until it is listed as a flag or explicitly skipped.
macro_rules! insecure_flags {
    ($opts:expr; $($field:ident: $description:literal,)* ; $($skipped:ident),*) => {{
        #[expect(clippy::unneeded_field_pattern, reason = "`..` would defeat the exhaustiveness check")]
        let InsecureOptions { $($field,)* $($skipped: _,)* } = *$opts;
        [$(InsecureFlag { name: stringify!($field), active: $field, description: $description },)*]
    }};
}

/// One top-level boolean [`InsecureOptions`] flag and its current state.
///
/// Produced by [`InsecureOptions::flags`], the single list every warning
/// and reload diagnostic iterates, so a new flag cannot be missed by one
/// of them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InsecureFlag {
    /// YAML key under `insecure_options`.
    pub name: &'static str,

    /// Whether the flag is enabled.
    pub active: bool,

    /// What enabling the flag weakens.
    pub description: &'static str,
}

// -----------------------------------------------------------------------------
// InsecureOptions
// -----------------------------------------------------------------------------

/// Consolidated security overrides for Praxis.
///
/// Every field defaults to `false`. Setting a flag to `true`
/// demotes the corresponding security check from an error to a warning.
///
/// Only intended for use in development and testing.
///
/// ```
/// use praxis_core::config::InsecureOptions;
///
/// let opts = InsecureOptions::default();
/// assert!(!opts.allow_open_security_filters);
/// assert!(!opts.allow_private_endpoints);
/// assert!(!opts.allow_private_health_checks);
/// assert!(!opts.allow_private_upstreams);
/// assert!(!opts.allow_public_admin);
/// assert!(!opts.allow_root);
/// assert!(!opts.allow_tls_no_verify);
/// assert!(!opts.allow_tls_without_sni);
/// assert!(!opts.allow_unbounded_body);
/// assert!(!opts.csrf_log_only);
/// assert!(!opts.skip_pipeline_validation);
/// assert!(!opts.skip_pipeline_checks.any());
/// ```
///
/// ```
/// use praxis_core::config::InsecureOptions;
///
/// let opts: InsecureOptions =
///     serde_yaml::from_str("allow_root: true\nallow_public_admin: true\n").unwrap();
/// assert!(opts.allow_root);
/// assert!(opts.allow_public_admin);
/// assert!(!opts.allow_unbounded_body);
/// ```
#[expect(clippy::struct_excessive_bools, reason = "security override flags")]
#[derive(Clone, Debug, Default, Deserialize, serde::Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct InsecureOptions {
    /// Allow security-critical filters to use `failure_mode: open`,
    /// demoting the validation error to a warning.
    pub allow_open_security_filters: bool,

    /// Allow cluster endpoints to resolve to loopback, link-local,
    /// or cloud metadata addresses.
    pub allow_private_endpoints: bool,

    /// Allow health checks to loopback/metadata addresses.
    pub allow_private_health_checks: bool,

    /// Allow upstream connections to resolve to private or reserved IP
    /// addresses at runtime. Without this flag, DNS-resolved upstream
    /// addresses in RFC 1918, loopback, link-local, CGNAT, and IPv6
    /// unique-local ranges are rejected to prevent DNS rebinding and
    /// SSRF attacks, on the TCP and HTTP data planes alike.
    ///
    /// Literal `host:port` upstreams are not affected: they cannot be
    /// substituted by a resolver, and are gated at config time by
    /// [`allow_private_endpoints`].
    ///
    /// [`allow_private_endpoints`]: InsecureOptions::allow_private_endpoints
    pub allow_private_upstreams: bool,

    /// Allow admin endpoint on non-loopback addresses (`0.0.0.0`, LAN IPs, etc.).
    pub allow_public_admin: bool,

    /// Allow running as root (UID 0).
    pub allow_root: bool,

    /// Allow disabling upstream TLS certificate verification (`tls.verify: false`).
    ///
    /// Without this flag, setting `verify: false` on a cluster is a hard
    /// validation error. Enabling it demotes the error to a warning.
    pub allow_tls_no_verify: bool,

    /// Allow TLS without SNI hostname verification.
    pub allow_tls_without_sni: bool,

    /// Allow startup without `body_limits.max_request_bytes` or
    /// `body_limits.max_response_bytes` configured. Without this
    /// flag, missing body limits are a hard validation error.
    pub allow_unbounded_body: bool,

    /// Run the CSRF filter in log-only mode: evaluate all rules
    /// but log violations as warnings instead of rejecting requests.
    pub csrf_log_only: bool,

    /// Granular pipeline validation bypass flags.
    ///
    /// Prefer these over the blanket [`skip_pipeline_validation`]
    /// flag for targeted overrides.
    ///
    /// [`skip_pipeline_validation`]: InsecureOptions::skip_pipeline_validation
    pub skip_pipeline_checks: SkipPipelineChecks,

    /// **Deprecated.** Skip ALL pipeline ordering validation checks.
    ///
    /// Prefer [`skip_pipeline_checks`] for granular control. When this
    /// flag is `true`, [`effective_pipeline_checks`] returns
    /// [`SkipPipelineChecks::all`], overriding individual flags.
    ///
    /// [`skip_pipeline_checks`]: InsecureOptions::skip_pipeline_checks
    /// [`effective_pipeline_checks`]: InsecureOptions::effective_pipeline_checks
    pub skip_pipeline_validation: bool,
}

impl InsecureOptions {
    /// Returns the effective pipeline check skip flags.
    ///
    /// When [`skip_pipeline_validation`] is `true`, all checks are
    /// skipped (backward compatibility). Otherwise, returns the
    /// granular [`skip_pipeline_checks`] flags.
    ///
    /// ```
    /// use praxis_core::config::InsecureOptions;
    ///
    /// let blanket: InsecureOptions = serde_yaml::from_str("skip_pipeline_validation: true").unwrap();
    /// let checks = blanket.effective_pipeline_checks();
    /// assert!(checks.lb_without_router);
    /// assert!(checks.conditional_security);
    ///
    /// let granular: InsecureOptions =
    ///     serde_yaml::from_str("skip_pipeline_checks:\n  duplicate_routers: true").unwrap();
    /// let checks = granular.effective_pipeline_checks();
    /// assert!(checks.duplicate_routers);
    /// assert!(!checks.lb_without_router);
    /// ```
    ///
    /// [`skip_pipeline_validation`]: InsecureOptions::skip_pipeline_validation
    /// [`skip_pipeline_checks`]: InsecureOptions::skip_pipeline_checks
    pub fn effective_pipeline_checks(&self) -> SkipPipelineChecks {
        if self.skip_pipeline_validation {
            SkipPipelineChecks::all()
        } else {
            self.skip_pipeline_checks.clone()
        }
    }

    /// Every top-level boolean flag, in declaration order.
    ///
    /// The granular [`skip_pipeline_checks`] are not included; they are
    /// reported by name under the `skip_pipeline_checks.` prefix.
    ///
    /// ```
    /// use praxis_core::config::InsecureOptions;
    ///
    /// let opts: InsecureOptions = serde_yaml::from_str("allow_root: true").unwrap();
    /// let active: Vec<_> = opts
    ///     .flags()
    ///     .into_iter()
    ///     .filter(|flag| flag.active)
    ///     .collect();
    /// assert_eq!(active.len(), 1);
    /// assert_eq!(active[0].name, "allow_root");
    /// ```
    ///
    /// [`skip_pipeline_checks`]: InsecureOptions::skip_pipeline_checks
    pub fn flags(&self) -> [InsecureFlag; 11] {
        insecure_flags!(self;
            allow_open_security_filters: "open failure_mode allowed on security filters",
            allow_private_endpoints: "SSRF-sensitive endpoint addresses allowed",
            allow_private_health_checks: "loopback health checks allowed",
            allow_private_upstreams: "runtime SSRF protection disabled for upstream connections",
            allow_public_admin: "admin may bind non-loopback addresses",
            allow_root: "running as root (UID 0) allowed",
            allow_tls_no_verify: "upstream TLS certificate verification may be disabled",
            allow_tls_without_sni: "TLS hostname verification weakened",
            allow_unbounded_body: "body size ceiling relaxed",
            csrf_log_only: "CSRF violations logged, not rejected",
            skip_pipeline_validation: "pipeline errors demoted to warnings",
        ; skip_pipeline_checks)
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::needless_raw_strings,
    clippy::needless_raw_string_hashes,
    clippy::too_many_lines,
    reason = "tests use unwrap/expect/indexing/raw strings for brevity"
)]
mod tests {
    use super::*;

    #[test]
    fn all_flags_default_to_false() {
        let opts = InsecureOptions::default();
        assert!(
            !opts.allow_open_security_filters,
            "allow_open_security_filters should default to false"
        );
        assert!(
            !opts.allow_private_endpoints,
            "allow_private_endpoints should default to false"
        );
        assert!(
            !opts.allow_private_health_checks,
            "allow_private_health_checks should default to false"
        );
        assert!(
            !opts.allow_private_upstreams,
            "allow_private_upstreams should default to false"
        );
        assert!(!opts.allow_public_admin, "allow_public_admin should default to false");
        assert!(!opts.allow_root, "allow_root should default to false");
        assert!(!opts.allow_tls_no_verify, "allow_tls_no_verify should default to false");
        assert!(
            !opts.allow_tls_without_sni,
            "allow_tls_without_sni should default to false"
        );
        assert!(
            !opts.allow_unbounded_body,
            "allow_unbounded_body should default to false"
        );
        assert!(!opts.csrf_log_only, "csrf_log_only should default to false");
        assert!(
            !opts.skip_pipeline_validation,
            "skip_pipeline_validation should default to false"
        );
        assert!(
            !opts.skip_pipeline_checks.any(),
            "skip_pipeline_checks should all default to false"
        );
    }

    #[test]
    fn deserializes_partial_overrides() {
        let yaml = "allow_root: true\nskip_pipeline_validation: true\n";
        let opts: InsecureOptions = serde_yaml::from_str(yaml).unwrap();
        assert!(opts.allow_root, "allow_root should be true");
        assert!(opts.skip_pipeline_validation, "skip_pipeline_validation should be true");
        assert!(!opts.allow_public_admin, "allow_public_admin should still be false");
    }

    #[test]
    fn deserializes_empty_to_defaults() {
        let opts: InsecureOptions = serde_yaml::from_str("{}").unwrap();
        assert!(!opts.allow_root, "empty YAML should produce defaults");
    }

    #[test]
    fn skip_pipeline_checks_all_sets_every_flag() {
        let checks = SkipPipelineChecks::all();
        assert!(checks.conditional_security, "conditional_security should be true");
        assert!(
            checks.conflicting_cluster_selectors,
            "conflicting_cluster_selectors should be true"
        );
        assert!(
            checks.duplicate_load_balancers,
            "duplicate_load_balancers should be true"
        );
        assert!(
            checks.duplicate_rewrite_filters,
            "duplicate_rewrite_filters should be true"
        );
        assert!(checks.duplicate_routers, "duplicate_routers should be true");
        assert!(checks.lb_without_router, "lb_without_router should be true");
        assert!(checks.misaligned_clusters, "misaligned_clusters should be true");
        assert!(checks.unreachable_filters, "unreachable_filters should be true");
    }

    #[test]
    fn skip_pipeline_checks_any_detects_single_flag() {
        let mut checks = SkipPipelineChecks::default();
        assert!(!checks.any(), "default checks should have no flags set");
        checks.duplicate_routers = true;
        assert!(checks.any(), "any() should detect single flag");
    }

    #[test]
    fn effective_pipeline_checks_blanket_overrides_granular() {
        let opts = InsecureOptions {
            skip_pipeline_validation: true,
            ..Default::default()
        };
        let checks = opts.effective_pipeline_checks();
        assert!(checks.lb_without_router, "blanket flag should set all checks");
        assert!(checks.conditional_security, "blanket flag should set all checks");
        assert!(checks.misaligned_clusters, "blanket flag should set all checks");
    }

    #[test]
    fn effective_pipeline_checks_uses_granular_when_blanket_off() {
        let opts = InsecureOptions {
            skip_pipeline_checks: SkipPipelineChecks {
                duplicate_routers: true,
                ..Default::default()
            },
            ..Default::default()
        };
        let checks = opts.effective_pipeline_checks();
        assert!(checks.duplicate_routers, "granular flag should be preserved");
        assert!(!checks.lb_without_router, "other flags should remain false");
    }

    #[test]
    fn deserializes_granular_pipeline_checks() {
        let yaml = "skip_pipeline_checks:\n  duplicate_routers: true\n  misaligned_clusters: true\n";
        let opts: InsecureOptions = serde_yaml::from_str(yaml).unwrap();
        assert!(
            opts.skip_pipeline_checks.duplicate_routers,
            "duplicate_routers should be true"
        );
        assert!(
            opts.skip_pipeline_checks.misaligned_clusters,
            "misaligned_clusters should be true"
        );
        assert!(
            !opts.skip_pipeline_checks.lb_without_router,
            "lb_without_router should remain false"
        );
        assert!(!opts.skip_pipeline_validation, "blanket flag should remain false");
    }

    #[test]
    fn flags_cover_every_bool_field_in_declaration_order() {
        let value = serde_yaml::to_value(InsecureOptions::default()).unwrap();
        let fields = value
            .as_mapping()
            .expect("InsecureOptions should serialize to a mapping");
        let bool_fields: Vec<&str> = fields
            .iter()
            .filter(|(_, field)| field.is_bool())
            .map(|(key, _)| key.as_str().unwrap())
            .collect();
        let names: Vec<&str> = InsecureOptions::default()
            .flags()
            .iter()
            .map(|flag| flag.name)
            .collect();
        assert_eq!(
            names, bool_fields,
            "flags() must list every bool field in declaration order"
        );
    }

    #[test]
    fn flags_all_active_after_all_true_round_trip() {
        let mut value = serde_yaml::to_value(InsecureOptions::default()).unwrap();
        let fields = value
            .as_mapping_mut()
            .expect("InsecureOptions should serialize to a mapping");
        for field in fields.values_mut().filter(|field| field.is_bool()) {
            *field = serde_yaml::Value::Bool(true);
        }
        let all: InsecureOptions = serde_yaml::from_value(value).unwrap();
        for flag in all.flags() {
            assert!(flag.active, "{} should be active in an all-true config", flag.name);
        }
    }

    #[test]
    fn flags_all_inactive_by_default() {
        for flag in InsecureOptions::default().flags() {
            assert!(!flag.active, "{} should be inactive by default", flag.name);
        }
    }

    #[test]
    fn each_flag_reads_its_own_field() {
        for name in InsecureOptions::default().flags().map(|flag| flag.name) {
            let opts: InsecureOptions = serde_yaml::from_str(&format!("{name}: true")).unwrap();
            let active: Vec<&str> = opts
                .flags()
                .iter()
                .filter(|flag| flag.active)
                .map(|flag| flag.name)
                .collect();
            assert_eq!(active, vec![name], "setting only {name} should activate only {name}");
        }
    }

    #[test]
    fn flags_ignore_granular_pipeline_checks() {
        let opts = InsecureOptions {
            skip_pipeline_checks: SkipPipelineChecks::all(),
            ..Default::default()
        };
        assert!(
            opts.flags().iter().all(|flag| !flag.active),
            "granular pipeline checks are reported separately, not as top-level flags"
        );
    }

    #[test]
    fn flags_have_descriptions() {
        for flag in InsecureOptions::default().flags() {
            assert!(!flag.description.is_empty(), "{} should have a description", flag.name);
        }
    }

    #[test]
    fn rejects_unknown_skip_pipeline_checks_field() {
        let yaml = "skip_pipeline_checks:\n  nonexistent_check: true\n";
        let err = serde_yaml::from_str::<InsecureOptions>(yaml).unwrap_err();
        assert!(
            err.to_string().contains("nonexistent_check"),
            "unknown skip_pipeline_checks field should be rejected: {err}"
        );
    }
}
