// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Reload diagnostics: restart-required detection, insecure option escalation,
//! stateful filter warnings, and config change auditing.

use praxis_core::config::Config;
use tracing::{info, warn};

// -----------------------------------------------------------------------------
// Restart-Required Detection
// -----------------------------------------------------------------------------

/// Compare old and new configs, logging warnings for changes that
/// require a process restart to take effect.
pub(crate) fn log_restart_required_changes(old: &Config, new: &Config) {
    detect_listener_topology_changes(old, new);
    detect_protocol_changes(old, new);
    detect_compression_additions(old, new);
    detect_tls_toggles(old, new);
}

/// Detect listener additions, removals, and address rebinds.
pub(crate) fn detect_listener_topology_changes(old: &Config, new: &Config) {
    let old_names: std::collections::HashSet<&str> = old.listeners.iter().map(|l| l.name.as_str()).collect();
    let new_names: std::collections::HashSet<&str> = new.listeners.iter().map(|l| l.name.as_str()).collect();

    for name in new_names.difference(&old_names) {
        warn!(
            listener = %name,
            "listener added in config; requires restart to bind"
        );
    }
    for name in old_names.difference(&new_names) {
        warn!(
            listener = %name,
            "listener removed in config; requires restart to unbind"
        );
    }

    for new_l in &new.listeners {
        if let Some(old_l) = old.listeners.iter().find(|l| l.name == new_l.name)
            && old_l.address != new_l.address
        {
            warn!(
                listener = %new_l.name,
                old_address = %old_l.address,
                new_address = %new_l.address,
                "listener address changed; requires restart to rebind"
            );
        }
    }
}

/// Detect protocol changes (e.g. HTTP to TCP).
pub(crate) fn detect_protocol_changes(old: &Config, new: &Config) {
    for new_l in &new.listeners {
        if let Some(old_l) = old.listeners.iter().find(|l| l.name == new_l.name)
            && old_l.protocol != new_l.protocol
        {
            warn!(
                listener = %new_l.name,
                old_protocol = ?old_l.protocol,
                new_protocol = ?new_l.protocol,
                "protocol changed; requires restart"
            );
        }
    }
}

/// Detect compression being added to a previously uncompressed listener.
pub(crate) fn detect_compression_additions(old: &Config, new: &Config) {
    let old_chains_with_compression = find_chains_with_compression(old);
    let new_chains_with_compression = find_chains_with_compression(new);

    for new_l in &new.listeners {
        if let Some(old_l) = old.listeners.iter().find(|l| l.name == new_l.name) {
            let old_had_compression = old_l
                .filter_chains
                .iter()
                .any(|c| old_chains_with_compression.contains(c.as_str()));

            let new_has_compression = new_l
                .filter_chains
                .iter()
                .any(|c| new_chains_with_compression.contains(c.as_str()));

            if !old_had_compression && new_has_compression {
                warn!(
                    listener = %new_l.name,
                    "compression added; requires restart (module registration is one-shot)"
                );
            }
        }
    }
}

/// Collect chain names that contain a compression filter.
pub(crate) fn find_chains_with_compression(config: &Config) -> std::collections::HashSet<&str> {
    config
        .filter_chains
        .iter()
        .filter(|c| c.filters.iter().any(|f| f.filter_type == "compression"))
        .map(|c| c.name.as_str())
        .collect()
}

/// Detect TLS enable/disable toggles.
pub(crate) fn detect_tls_toggles(old: &Config, new: &Config) {
    for new_l in &new.listeners {
        if let Some(old_l) = old.listeners.iter().find(|l| l.name == new_l.name) {
            match (&old_l.tls, &new_l.tls) {
                (None, Some(_)) => {
                    warn!(
                        listener = %new_l.name,
                        "TLS enabled; requires restart"
                    );
                },
                (Some(_), None) => {
                    warn!(
                        listener = %new_l.name,
                        "TLS disabled; requires restart"
                    );
                },
                _ => {},
            }
        }
    }
}

// -----------------------------------------------------------------------------
// Insecure Option Escalation Detection
// -----------------------------------------------------------------------------

/// Produce `(name, old_val, new_val)` tuples for every [`InsecureOptions`] flag.
///
/// [`InsecureOptions`]: praxis_core::config::InsecureOptions
macro_rules! insecure_flag_pairs {
    ($old:expr, $new:expr, [$($field:ident),* $(,)?]) => {
        [$(  (stringify!($field), $old.$field, $new.$field)  ),*]
    };
}

/// Like [`insecure_flag_pairs!`] but for [`SkipPipelineChecks`] sub-fields,
/// prefixing each name with `skip_pipeline_checks.`.
///
/// [`SkipPipelineChecks`]: praxis_core::config::SkipPipelineChecks
macro_rules! pipeline_check_pairs {
    ($old:expr, $new:expr, [$($field:ident),* $(,)?]) => {
        [$(  (concat!("skip_pipeline_checks.", stringify!($field)), $old.$field, $new.$field)  ),*]
    };
}

/// Log a warning when insecure options are newly enabled during a reload.
///
/// Compares each [`InsecureOptions`] flag between the old and new configs.
/// Any flag that transitions from `false` to `true` is reported as a
/// security escalation. The reload proceeds regardless; this is
/// detection, not prevention.
///
/// [`InsecureOptions`]: praxis_core::config::InsecureOptions
pub(crate) fn warn_insecure_option_escalations(old: &Config, new: &Config) {
    let escalated = collect_escalated_flags(&old.insecure_options, &new.insecure_options);

    if !escalated.is_empty() {
        warn!(
            options = ?escalated,
            "insecure options escalated during reload; \
             security overrides were newly enabled"
        );
    }
}

/// Collect names of insecure flags that transitioned from `false` to `true`.
pub(crate) fn collect_escalated_flags(
    old: &praxis_core::config::InsecureOptions,
    new: &praxis_core::config::InsecureOptions,
) -> Vec<&'static str> {
    let mut result: Vec<&str> = insecure_flag_pairs!(
        old,
        new,
        [
            allow_open_security_filters,
            allow_private_endpoints,
            allow_private_health_checks,
            allow_private_upstreams,
            allow_public_admin,
            allow_root,
            allow_tls_no_verify,
            allow_tls_without_sni,
            allow_unbounded_body,
            csrf_log_only,
            skip_pipeline_validation,
        ]
    )
    .into_iter()
    .filter(|(_, old_val, new_val)| !old_val && *new_val)
    .map(|(name, ..)| name)
    .collect();

    collect_escalated_pipeline_checks(&old.skip_pipeline_checks, &new.skip_pipeline_checks, &mut result);
    result
}

/// Collect escalated granular pipeline check flags.
pub(crate) fn collect_escalated_pipeline_checks(
    old: &praxis_core::config::SkipPipelineChecks,
    new: &praxis_core::config::SkipPipelineChecks,
    result: &mut Vec<&'static str>,
) {
    result.extend(
        pipeline_check_pairs!(
            old,
            new,
            [
                conditional_security,
                conflicting_cluster_selectors,
                duplicate_load_balancers,
                duplicate_rewrite_filters,
                duplicate_routers,
                lb_without_router,
                misaligned_clusters,
                unreachable_filters,
            ]
        )
        .into_iter()
        .filter(|(_, o, n)| !o && *n)
        .map(|(name, ..)| name),
    );
}

// -----------------------------------------------------------------------------
// Stateful Filter Warnings
// -----------------------------------------------------------------------------

/// Log a warning when the new config contains stateful filters
/// whose state will reset on reload (e.g. rate limiters).
pub(crate) fn warn_stateful_filter_reset(config: &Config) {
    let has_stateful = config
        .filter_chains
        .iter()
        .any(|c| c.filters.iter().any(is_stateful_recursive));

    if has_stateful {
        warn!(
            "stateful filters (rate_limit, circuit_breaker) have been \
             reset; in-flight requests retain old state via Arc guard"
        );
    }
}

/// Check a filter entry and its inline branch chain filters.
pub(crate) fn is_stateful_recursive(f: &praxis_core::config::FilterEntry) -> bool {
    if f.filter_type == "rate_limit" || f.filter_type == "circuit_breaker" {
        return true;
    }
    f.branch_chains.as_ref().is_some_and(|branches| {
        branches.iter().any(|b| {
            b.chains.iter().any(|chain_ref| {
                if let praxis_core::config::ChainRef::Inline { filters, .. } = chain_ref {
                    filters.iter().any(is_stateful_recursive)
                } else {
                    false
                }
            })
        })
    })
}

// -----------------------------------------------------------------------------
// Config Change Audit
// -----------------------------------------------------------------------------

/// Emit a structured audit log summarizing config changes during reload.
///
/// Compares old and new configs section by section, reporting the
/// number of items added, removed, or modified in each. Complements
/// the specific escalation warnings from [`warn_insecure_option_escalations`]
/// with a general-purpose change summary for incident investigation
/// and config drift tracking.
pub(crate) fn log_config_change_audit(old: &Config, new: &Config) {
    let (la, lr, lm) = diff_named_items(&old.listeners, &new.listeners, |l| &l.name);
    let (ca, cr, cm) = diff_named_items(&old.clusters, &new.clusters, |c| &c.name);
    let (fa, fr, fm) = diff_named_items(&old.filter_chains, &new.filter_chains, |c| &c.name);

    let insecure_changed =
        serde_yaml::to_string(&old.insecure_options).ok() != serde_yaml::to_string(&new.insecure_options).ok();

    info!(
        listeners_added = la,
        listeners_removed = lr,
        listeners_modified = lm,
        clusters_added = ca,
        clusters_removed = cr,
        clusters_modified = cm,
        chains_added = fa,
        chains_removed = fr,
        chains_modified = fm,
        insecure_options_changed = insecure_changed,
        "config reload audit"
    );
}

/// Compare two sets of named serializable items and return change counts.
///
/// Returns `(added, removed, modified)` where:
/// - `added` -- items in `new` not present in `old`
/// - `removed` -- items in `old` not present in `new`
/// - `modified` -- items present in both with different serialized content
pub(crate) fn diff_named_items<T: serde::Serialize>(
    old: &[T],
    new: &[T],
    name_fn: impl Fn(&T) -> &str,
) -> (usize, usize, usize) {
    use std::collections::HashMap;

    let serialize = |item: &T| serde_yaml::to_string(item).unwrap_or_default();

    let old_map: HashMap<&str, String> = old.iter().map(|i| (name_fn(i), serialize(i))).collect();
    let new_map: HashMap<&str, String> = new.iter().map(|i| (name_fn(i), serialize(i))).collect();

    let added = new_map.keys().filter(|k| !old_map.contains_key(*k)).count();
    let removed = old_map.keys().filter(|k| !new_map.contains_key(*k)).count();
    let modified = new_map
        .iter()
        .filter(|(k, v)| old_map.get(*k).is_some_and(|old_v| old_v != *v))
        .count();

    (added, removed, modified)
}
