// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Hot config reload: validate, build, and atomically swap filter pipelines.

use std::sync::{Arc, Mutex};

use praxis_core::{
    config::{Config, ProtocolKind},
    health::{HealthRegistry, build_health_registry},
};
use praxis_filter::FilterRegistry;
use praxis_protocol::ListenerPipelines;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

#[cfg(test)]
use crate::pipelines::resolve_pipelines;
#[cfg(test)]
use crate::reload_diagnostics::{
    collect_escalated_flags, detect_compression_additions, diff_named_items, find_chains_with_compression,
    is_stateful_recursive,
};
use crate::{
    composition::PipelineComposition,
    pipelines::resolve_pipelines_with_composition,
    reload_diagnostics::{
        log_config_change_audit, log_restart_required_changes, warn_insecure_option_escalations,
        warn_stateful_filter_reset,
    },
    server::HealthTaskLifecycle,
    startup_checks::{
        warn_insecure_key_permissions, warn_insecure_log_file_permissions, warn_insecure_sink_file_permissions,
    },
};

// -----------------------------------------------------------------------------
// Reload
// -----------------------------------------------------------------------------

/// Result of accessing live reload state or publishing a staged generation.
type ReloadResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// Access live state only outside downstream pipeline construction.
pub(crate) trait ReloadTarget {
    /// Run a bounded live-state operation, or reject it after watcher shutdown.
    fn with_live<T, Operation>(&self, operation: Operation) -> ReloadResult<T>
    where
        Operation: FnOnce(&ListenerPipelines) -> ReloadResult<T>;
}

impl ReloadTarget for ListenerPipelines {
    fn with_live<T, Operation>(&self, operation: Operation) -> ReloadResult<T>
    where
        Operation: FnOnce(&ListenerPipelines) -> ReloadResult<T>,
    {
        operation(self)
    }
}

impl<L: ReloadTarget> ReloadTarget for Arc<L> {
    fn with_live<T, Operation>(&self, operation: Operation) -> ReloadResult<T>
    where
        Operation: FnOnce(&ListenerPipelines) -> ReloadResult<T>,
    {
        self.as_ref().with_live(operation)
    }
}

/// Revocable watcher access; a stalled build never retains the controller.
pub(crate) struct WatcherReloadTarget(Mutex<Option<Arc<ListenerPipelines>>>);

impl WatcherReloadTarget {
    /// Prepare live state; cleanup uses the existing config-watcher thread.
    pub(crate) fn new(live: Arc<ListenerPipelines>) -> Self {
        Self(Mutex::new(Some(live)))
    }

    /// Pin pipeline slots, not the controller, until the watcher exits.
    pub(crate) fn retain_pipelines(self: &Arc<Self>) -> PipelineRetention {
        let live = self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let slots = live
            .as_ref()
            .into_iter()
            .flat_map(|live| {
                live.listener_names()
                    .filter_map(|name| live.get(name))
                    .cloned()
                    .map(|slot| -> Arc<dyn Send + Sync> { slot })
            })
            .collect();
        drop(live);
        PipelineRetention {
            target: Arc::clone(self),
            slots,
        }
    }

    /// Revoke publication; the watcher still owns slots that can run user drops.
    pub(crate) fn stop(&self) {
        drop(self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner).take());
    }
}

/// Runs downstream destructors on the watcher, including early exit or unwinding.
pub(crate) struct PipelineRetention {
    /// Revoke live state before releasing the last retained slots.
    target: Arc<WatcherReloadTarget>,
    /// Type-erased slot Arcs avoid retaining the server controller.
    slots: Vec<Arc<dyn Send + Sync>>,
}

impl Drop for PipelineRetention {
    fn drop(&mut self) {
        self.target.stop();
        self.slots.clear();
    }
}
impl ReloadTarget for WatcherReloadTarget {
    fn with_live<T, Operation>(&self, operation: Operation) -> ReloadResult<T>
    where
        Operation: FnOnce(&ListenerPipelines) -> ReloadResult<T>,
    {
        let guard = self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        operation(
            guard
                .as_ref()
                .ok_or("config watcher stopped; discarding staged reload")?,
        )
    }
}

/// Validate a new config, rebuild pipelines, and atomically swap them
/// into the running server.
///
/// On success, cancels old health check tasks and spawns replacements.
/// On failure, logs the error and returns `Err` without modifying any
/// live state.
///
/// # Errors
///
/// Returns an error if the new config fails validation or pipeline
/// construction, if it changes the protocol of a listener whose handler
/// is already bound (that change takes effect only on restart), if its
/// grouped TCP listeners are inconsistent, if it changes or removes a
/// bound TCP listener's startup-captured settings, or if it changes a
/// bound listener's `forward_proxy` block or removes a listener that has
/// one. The running server is unaffected.
#[expect(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "orchestration function"
)]
pub(crate) fn reload_pipelines(
    new_config: &Config,
    old_config: &Config,
    registry: &FilterRegistry,
    live: &impl ReloadTarget,
    listener_meta: &praxis_protocol::http::health::ListenerMetaStore,
    cluster_meta: &praxis_protocol::http::health::ClusterMetaStore,
    health_shutdown: &Arc<Mutex<CancellationToken>>,
    health_lifecycle: Option<&HealthTaskLifecycle>,
    kv_stores: &praxis_core::kv::KvStoreRegistry,
    session_stores: &Arc<praxis_filter::SessionStoreRegistry>,
    slow_start_registry: &Arc<praxis_filter::SlowStartRegistry>,
    subrequest_client: &praxis_core::subrequest::SubRequestClient,
    log_level: Option<&Arc<praxis_core::logging::LogLevelState>>,
    composition: &PipelineComposition,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    info!("building new pipelines from reloaded config");

    live.with_live(|live| {
        reject_protocol_changes(new_config, live)?;
        praxis_protocol::tcp::validate_tcp_groups(new_config)?;
        reject_tcp_group_changes(new_config, old_config)?;
        reject_forward_proxy_changes(new_config, old_config, live)?;
        Ok(())
    })
    .inspect_err(|error| error!(%error, "config reload rejected; live state unchanged"))?;

    let health_registry = build_health_registry(&new_config.clusters);

    let new_ceiling = new_config
        .body_limits
        .max_response_bytes
        .unwrap_or(usize::MAX)
        .min(new_config.body_limits.max_buffer_bytes.get());
    let updated_client = subrequest_client.with_response_ceiling(new_ceiling);

    // Hold the generation across the last fallible step. Publishing it inside
    // pipeline construction would retire live tables when a later step fails.
    let slow_start_generation = slow_start_registry.enter_generation();
    let candidate_session_stores = Arc::new(session_stores.candidate());
    let new_pipelines = match resolve_pipelines_with_composition(
        new_config,
        registry,
        &health_registry,
        kv_stores,
        &candidate_session_stores,
        slow_start_registry,
        &updated_client,
        composition,
    ) {
        Ok(pipelines) => pipelines,
        Err(err) => {
            error!(error = %err, "config reload failed: pipeline build error");
            return Err(err);
        },
    };

    // Filesystem metadata can block. Keep advisory permission checks outside
    // the publication lock and before a new logging baseline can hide warnings.
    warn_insecure_key_permissions(new_config);
    warn_insecure_log_file_permissions(new_config);
    warn_insecure_sink_file_permissions(new_config);

    // Keep diagnostics under the old logging baseline, outside the publication
    // mutex so a blocked synchronous log sink cannot hold up watcher shutdown.
    log_restart_required_changes(old_config, new_config);
    warn_insecure_option_escalations(old_config, new_config);
    warn_stateful_filter_reset(new_config);
    log_config_change_audit(old_config, new_config);

    let health = PreparedHealth::new(
        new_config,
        &health_registry,
        health_lifecycle,
        subrequest_client.upstream_ca(),
    )?;
    let publish = || {
        live.with_live(|live| {
            // Removed listeners keep serving through their old bound pipelines. Their
            // stores must remain discoverable for a later reintroduction, even though
            // the configured candidate has no filter for them in this generation.
            for name in live.listener_names() {
                if new_pipelines.get(name).is_none()
                    && let Some(old) = live.get(name)
                {
                    let old_pipeline = old.load();
                    if let Some(stores) = old_pipeline.session_stores() {
                        candidate_session_stores.retain_used_from(stores);
                    }
                }
            }
            session_stores.publish(&candidate_session_stores);
            slow_start_generation.commit();

            // Copy known-down endpoint state into the new registry BEFORE the
            // swap: afterwards `live` already serves the new pipelines and the
            // old registry is no longer reachable through them.
            let carried = carry_over_health_state(live, old_config, new_config, &health_registry);

            let mut swapped: Vec<&str> = Vec::new();
            let mut skipped: Vec<&str> = Vec::new();
            let mut retired = Vec::new();

            for name in new_pipelines.listener_names() {
                let Some(new_slot) = new_pipelines.get(name) else {
                    continue;
                };
                let Some(slot) = live.get(name) else {
                    skipped.push(name);
                    continue;
                };
                retired.push(slot.swap(new_slot.load_full()));
                swapped.push(name);
            }

            listener_meta.store(Arc::new(merged_listener_meta(new_config, live, listener_meta)));
            cluster_meta.store(Arc::new(praxis_protocol::http::health::cluster_meta_from_config(
                new_config,
            )));

            health.commit(health_shutdown);
            Ok((swapped, skipped, carried, retired))
        })
    };
    let (swapped, skipped, carried, retired) = match log_level {
        Some(log_level) => log_level.refresh_baseline_with(new_config, publish)?,
        None => publish()?,
    };
    // Reloads execute serially on the config watcher. Keep gauge reconciliation
    // here, outside publication, rather than on cancellable generation workers:
    // a later reload cannot skip pending removals or overtake an older seed.
    praxis_protocol::http::metrics::clear_stale_upstream_health_gauges(
        health_checked_cluster_names(old_config),
        health_checked_cluster_names(new_config),
    );
    praxis_protocol::http::metrics::seed_upstream_health_gauges(&health_registry);
    drop(retired);
    if carried > 0 {
        info!(
            endpoints = carried,
            "carried unhealthy endpoint state across reload; probes must confirm recovery"
        );
    }
    info!(swapped = ?swapped, skipped = ?skipped, "config reload complete");
    Ok(())
}

/// Keep bound transport metadata for live slots across a filter-only reload.
///
/// A removed HTTP listener remains bound with its old pipeline. A changed
/// address or TLS block also cannot rebind a live slot, while its new chains
/// are applied above. Newly configured, unbound listeners remain in the
/// configured metadata map but cannot appear in `/api/pipelines` without a
/// live slot.
fn merged_listener_meta(
    config: &Config,
    live: &ListenerPipelines,
    store: &praxis_protocol::http::health::ListenerMetaStore,
) -> std::collections::HashMap<String, praxis_protocol::http::health::ListenerMeta> {
    let previous = store.load();
    let mut next = praxis_protocol::http::health::listener_meta_from_config(config);
    for name in live.listener_names() {
        let Some(bound) = previous.get(name) else {
            continue;
        };
        if let Some(applied) = next.get_mut(name) {
            applied.address.clone_from(&bound.address);
            applied.protocol = bound.protocol;
            applied.tls = bound.tls;
        } else {
            let mut retained = bound.clone();
            retained.configured_in_current_generation = false;
            next.insert(name.to_owned(), retained);
        }
    }
    next
}

/// Refuse a config that changes the protocol of a listener whose handler
/// is already bound.
///
/// Each handler is bound once at startup and executes only filters of its
/// own protocol, so a pipeline resolved for the other protocol would have
/// every filter skipped (#1113). The reference is the protocol recorded in
/// the live pipelines, not the previous config: the watcher keeps the
/// previous config only across `Ok` reloads, and a listener removed by one
/// reload and re-added by a later one is absent from it while its handler
/// is still bound. Rejecting the whole reload keeps the live pipelines,
/// health probes, and admin metadata on one generation.
fn reject_protocol_changes(
    new_config: &Config,
    live: &ListenerPipelines,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let Some((listener, bound)) = new_config.listeners.iter().find_map(|listener| {
        live.protocol(&listener.name)
            .filter(|bound| *bound != listener.protocol)
            .map(|bound| (listener, bound))
    }) else {
        return Ok(());
    };
    let name = &listener.name;
    let requested = listener.protocol;
    Err(format!("listener '{name}' protocol changed from {bound:?} to {requested:?}; a bound handler cannot switch protocols without a restart").into())
}

/// Reject reloads that change what a bound TCP listener captured at startup.
///
/// A TCP listener group's backend service captures its upstream, cluster,
/// timeouts, and `allow_private_upstreams` by value when it is built, and
/// reads the pipeline slot of the group's first listener only. Changing
/// the group key of a bound TCP listener, removing one, or flipping
/// `allow_private_upstreams` while TCP listeners exist would be silently
/// ignored (or leave a group reading a slot no longer swapped), so the
/// whole reload is rejected. Listeners new to this reload are not bound and
/// are not compared.
fn reject_tcp_group_changes(
    new_config: &Config,
    old_config: &Config,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut old_tcp = old_config
        .listeners
        .iter()
        .filter(|listener| listener.protocol == ProtocolKind::Tcp)
        .peekable();
    if old_tcp.peek().is_some()
        && old_config.insecure_options.allow_private_upstreams != new_config.insecure_options.allow_private_upstreams
    {
        return Err("allow_private_upstreams is captured by TCP listeners at startup; requires restart".into());
    }
    for old in old_tcp {
        let name = &old.name;
        let Some(new) = new_config.listeners.iter().find(|listener| listener.name == old.name) else {
            return Err(format!("TCP listener '{name}' removed; TCP listener topology requires a restart").into());
        };
        if new.protocol != ProtocolKind::Tcp {
            continue;
        }
        if tcp_group_key(old) != tcp_group_key(new) {
            return Err(format!("TCP listener '{name}' changed upstream/cluster/timeouts; requires restart").into());
        }
    }
    Ok(())
}

/// Reject reloads that change what a bound HTTP handler captured from its
/// listener's `forward_proxy` block, or that remove a listener carrying one.
///
/// The handler builds its CONNECT runtime (destination matcher, timeouts)
/// and the CONNECT gate once, when it is bound. The pipeline swap would
/// still apply the new config's filters, so a warn-only diagnostic would let
/// a reload that drops the `ip_acl` the open-relay check relied on, while
/// disabling the block, leave the startup runtime accepting CONNECT with no
/// egress control.
///
/// `old_config` stands in for what the handlers captured. Removing a bound
/// listener keeps its startup pipeline and runtime, but a later reload
/// re-adding it would swap in a new pipeline, so removal is rejected while
/// the listener carries a block. With changes and removals both rejected, a
/// bound listener absent from `old_config` was removed without a block and
/// so started without one; it is compared as blockless. Only listeners with
/// a live pipeline slot are compared; ones new to the config are not bound.
fn reject_forward_proxy_changes(
    new_config: &Config,
    old_config: &Config,
    live: &ListenerPipelines,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    reject_private_upstreams_flip_with_connect(new_config, old_config, live)?;
    let old_block = |name: &str| {
        old_config
            .listeners
            .iter()
            .find(|listener| listener.name == name)
            .and_then(|listener| listener.forward_proxy.as_ref())
    };
    if let Some(changed) = new_config.listeners.iter().find(|listener| {
        live.get(&listener.name).is_some() && listener.forward_proxy.as_ref() != old_block(&listener.name)
    }) {
        let name = &changed.name;
        return Err(format!("listener '{name}' forward_proxy changed; requires restart").into());
    }
    if let Some(removed) = old_config.listeners.iter().find(|old| {
        old.forward_proxy.is_some()
            && live.get(&old.name).is_some()
            && !new_config.listeners.iter().any(|listener| listener.name == old.name)
    }) {
        let name = &removed.name;
        return Err(format!("listener '{name}' with a forward_proxy block removed; requires restart").into());
    }
    Ok(())
}

/// Reject flipping `insecure_options.allow_private_upstreams` while a bound
/// listener has an enabled `forward_proxy` block: the CONNECT runtime captures
/// it when bound, as the TCP service does, so turning it off would leave
/// tunnels dialing private addresses until restart.
fn reject_private_upstreams_flip_with_connect(
    new_config: &Config,
    old_config: &Config,
    live: &ListenerPipelines,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let bound_connect = old_config.listeners.iter().any(|listener| {
        live.get(&listener.name).is_some() && listener.forward_proxy.as_ref().is_some_and(|fp| fp.enabled)
    });
    let flipped =
        old_config.insecure_options.allow_private_upstreams != new_config.insecure_options.allow_private_upstreams;
    if bound_connect && flipped {
        return Err(
            "allow_private_upstreams is captured by forward_proxy listeners at startup; requires restart".into(),
        );
    }
    Ok(())
}

/// Borrowed TCP group key: `(upstream, cluster, session_timeout_ms, max_duration_secs)`.
type TcpGroupKeyRef<'cfg> = (Option<&'cfg str>, Option<&'cfg str>, Option<u64>, Option<u64>);

/// The startup-captured settings that place a TCP listener in its group.
fn tcp_group_key(listener: &praxis_core::config::Listener) -> TcpGroupKeyRef<'_> {
    (
        listener.upstream.as_deref(),
        listener.cluster.as_deref(),
        listener.tcp_session_timeout_ms,
        listener.tcp_max_duration_secs,
    )
}

// -----------------------------------------------------------------------------
// Health Check Lifecycle
// -----------------------------------------------------------------------------

/// The health registry pinned by the currently live pipelines.
///
/// Only listeners present in the previous config are considered:
/// `ListenerPipelines` keeps its startup key set forever, so a listener
/// removed or renamed in an earlier reload still holds an old-generation
/// pipeline pinned to a registry whose probe tasks were cancelled. Reading
/// from that frozen registry would carry over stale health verdicts.
fn live_health_registry(live: &ListenerPipelines, old_config: &Config) -> Option<HealthRegistry> {
    old_config
        .listeners
        .iter()
        .filter_map(|listener| live.get(&listener.name))
        .find_map(|slot| slot.load().health_registry().cloned())
}

/// Carry endpoint health state from the live registry into the new one.
///
/// The rebuilt registry starts every endpoint healthy, which would route
/// live traffic to known-down upstreams until the new probe generation
/// re-detects them. For each cluster present in both configs with an
/// unchanged `health_check` config, copy each endpoint's unhealthy flag
/// by address so known-down endpoints stay out of rotation. Return the number
/// carried so the caller can log it after releasing the publication lock.
fn carry_over_health_state(
    live: &ListenerPipelines,
    old_config: &Config,
    new_config: &Config,
    new_registry: &HealthRegistry,
) -> usize {
    let Some(old_registry) = live_health_registry(live, old_config) else {
        return 0;
    };

    let old_by_name: std::collections::HashMap<&str, &praxis_core::config::Cluster> = old_config
        .clusters
        .iter()
        .map(|cluster| (cluster.name.as_ref(), cluster))
        .collect();
    let mut carried: usize = 0;
    for cluster in &new_config.clusters {
        let unchanged_check = old_by_name.get(cluster.name.as_ref()).is_some_and(|old_c| {
            !crate::reload_diagnostics::config_value_changed(&old_c.health_check, &cluster.health_check)
        });

        if !unchanged_check {
            continue;
        }

        let (Some(old_entry), Some(new_entry)) = (
            old_registry.get(cluster.name.as_ref()),
            new_registry.get(cluster.name.as_ref()),
        ) else {
            continue;
        };

        carried = carried.saturating_add(carry_cluster_endpoints(cluster, old_entry, new_entry));
    }

    carried
}

/// Copy unhealthy endpoint flags for one cluster; returns how many carried.
fn carry_cluster_endpoints(
    cluster: &praxis_core::config::Cluster,
    old_entry: &praxis_core::health::ClusterHealthEntry,
    new_entry: &praxis_core::health::ClusterHealthEntry,
) -> usize {
    let mut carried: usize = 0;
    for endpoint in &cluster.endpoints {
        let addr = endpoint.address();
        if let (Some(old_idx), Some(new_idx)) = (old_entry.endpoint_index(addr), new_entry.endpoint_index(addr))
            && let (Some(old_ep), Some(new_ep)) =
                (old_entry.endpoints().get(old_idx), new_entry.endpoints().get(new_idx))
            && !old_ep.is_healthy()
        {
            new_ep.mark_unhealthy();
            carried = carried.saturating_add(1);
        }
    }
    carried
}

/// Cluster names that currently have an active health-check config.
fn health_checked_cluster_names(config: &Config) -> Vec<&str> {
    config
        .clusters
        .iter()
        .filter(|cluster| cluster.health_check.is_some())
        .map(|cluster| cluster.name.as_ref())
        .collect()
}

/// Prepared health generation; no probes or metric callbacks run before commit.
struct PreparedHealth {
    /// Root-owned cancellation scope, also used to abandon rejected candidates.
    token: CancellationToken,
    /// Nonblocking handoff to the already-running health runtime.
    activate: Option<tokio::sync::oneshot::Sender<()>>,
    /// A committed generation is cancelled by its server, not this guard.
    committed: bool,
}

impl PreparedHealth {
    /// Prepare fallible runtime resources while the old probes are still active.
    fn new(
        config: &Config,
        registry: &HealthRegistry,
        owner: Option<&HealthTaskLifecycle>,
        upstream_ca: Option<Arc<praxis_tls::CachedCaCerts>>,
    ) -> std::io::Result<Self> {
        let token = owner.map_or_else(CancellationToken::new, HealthTaskLifecycle::new_token);
        let mut prepared = Self {
            token: token.clone(),
            activate: None,
            committed: false,
        };
        if registry.is_empty() {
            return Ok(prepared);
        }
        let work = HealthWork {
            clusters: config
                .clusters
                .iter()
                .filter(|cluster| cluster.health_check.is_some())
                .cloned()
                .collect(),
            registry: Arc::clone(registry),
            token,
            upstream_ca,
        };
        let (activate, wait) = tokio::sync::oneshot::channel();
        let handle = spawn_health_worker(work, wait)?;
        if let Some(owner) = owner {
            owner.track(handle);
        }
        prepared.activate = Some(activate);
        Ok(prepared)
    }

    /// Replace cancellation state and activate probes only after a successful swap.
    fn commit(mut self, health_shutdown: &Arc<Mutex<CancellationToken>>) {
        let old = {
            let mut guard = health_shutdown
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            std::mem::replace(&mut *guard, self.token.clone())
        };
        old.cancel();
        self.committed = true;
        if let Some(activate) = self.activate.take() {
            let _activated = activate.send(());
        }
    }
}

impl Drop for PreparedHealth {
    fn drop(&mut self) {
        if !self.committed {
            self.token.cancel();
        }
    }
}

/// Data owned by the prepared health runtime, with no live-pipeline reference.
struct HealthWork {
    /// Health-checked clusters for the new generation.
    clusters: Vec<praxis_core::config::Cluster>,
    /// New endpoint state, carried over before activation.
    registry: HealthRegistry,
    /// Server root child, already cancelled if shutdown won the race.
    token: CancellationToken,
    /// Runtime CA bundle reused by replacement TLS probes.
    upstream_ca: Option<Arc<praxis_tls::CachedCaCerts>>,
}

impl HealthWork {
    /// Await commitment without probing; then own all probe tasks until cancellation.
    async fn run(self, activate: tokio::sync::oneshot::Receiver<()>) {
        tokio::select! {
            biased;
            () = self.token.cancelled() => return,
            ready = activate => if ready.is_err() { return; },
        }
        if self.token.is_cancelled() {
            return;
        }
        praxis_protocol::http::health::runner::spawn_health_checks_with_ca(
            &self.clusters,
            &self.registry,
            &self.token,
            self.upstream_ca.as_deref(),
        );
        self.token.cancelled().await;
    }
}

/// Build the runtime before publication; a failed preparation leaves old probes intact.
fn spawn_health_worker(
    work: HealthWork,
    activate: tokio::sync::oneshot::Receiver<()>,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    let (ready, wait) = std::sync::mpsc::sync_channel(1);
    #[cfg(test)]
    let observation = crate::server::background_observation::capture();
    let handle = std::thread::Builder::new()
        .name("health check runtime".to_owned())
        .spawn(move || {
            #[cfg(test)]
            let _observation = crate::server::background_observation::start("health check runtime", observation);
            match tokio::runtime::Builder::new_current_thread().enable_all().build() {
                Ok(runtime) => {
                    if ready.send(Ok(())).is_ok() {
                        runtime.block_on(work.run(activate));
                    }
                },
                Err(error) => {
                    let _failed = ready.send(Err(error));
                },
            }
        })?;
    wait.recv().map_err(std::io::Error::other)??;
    Ok(handle)
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
    clippy::too_many_lines,
    clippy::significant_drop_tightening,
    reason = "tests"
)]
mod tests {
    use std::{
        collections::{BTreeMap, HashMap},
        sync::atomic::{AtomicUsize, Ordering},
    };

    use praxis_core::config::{InsecureOptions, SkipPipelineChecks};
    use praxis_filter::{CircuitBreakerFilter, FilterFactory, PipelineExtension, RequestExtensions};
    use tracing_subscriber::layer::SubscriberExt as _;

    use super::*;
    use crate::composition::ServerComposition;

    /// A marker resource a composed extension injects into per-request state.
    #[derive(Clone, Debug, Eq, PartialEq)]
    struct ReloadMarker(u8);

    /// Simulate an embedder whose pipeline destructor waits for its worker.
    struct BlockingPipelineDrop {
        /// Observe entry into the destructor.
        started: std::sync::mpsc::Sender<()>,
        /// Release on a message or sender drop during test unwinding.
        release: Mutex<std::sync::mpsc::Receiver<()>>,
    }

    impl PipelineExtension for BlockingPipelineDrop {
        fn prepare(&self, _extensions: &mut RequestExtensions) {}
    }

    impl Drop for BlockingPipelineDrop {
        fn drop(&mut self) {
            let _sent = self.started.send(());
            let _released = self.release.lock().unwrap().recv();
        }
    }

    #[test]
    #[expect(
        clippy::disallowed_methods,
        reason = "synchronous probe polling while another thread holds the destructor"
    )]
    fn retired_pipeline_destructors_do_not_hold_publication() {
        let (live, config, registry, shutdown, meta, cluster_meta) = setup_live_pipelines();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let mut next = config.clone();
        next.clusters = serde_yaml::from_str(&format!(
            "- name: checked\n  endpoints: ['{}']\n  health_check:\n    type: tcp\n    interval_ms: 60000\n",
            listener.local_addr().unwrap()
        ))
        .unwrap();
        let health_shutdown = Arc::clone(&shutdown);
        let (started, entered) = std::sync::mpsc::channel();
        let (release, wait) = std::sync::mpsc::channel();
        let mut old = praxis_filter::FilterPipeline::build(&mut [], &registry).unwrap();
        old.add_pipeline_extension(Box::new(BlockingPipelineDrop {
            started,
            release: Mutex::new(wait),
        }));
        live.swap("web", Arc::new(old));
        let target = Arc::new(WatcherReloadTarget::new(Arc::new(live)));
        let reload_target = Arc::clone(&target);
        let worker = std::thread::spawn(move || {
            reload_pipelines(
                &next,
                &config,
                &registry,
                &reload_target,
                &meta,
                &cluster_meta,
                &shutdown,
                None,
                &empty_kv_stores(),
                &empty_session_stores(),
                &empty_slow_start_registry(),
                &empty_subrequest_client(),
                None,
                &PipelineComposition::default(),
            )
            .unwrap();
        });
        entered.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let probed = loop {
            match listener.accept() {
                Ok(_) => break true,
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock && std::time::Instant::now() < deadline =>
                {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                },
                _ => break false,
            }
        };
        let publication_unlocked = target.0.try_lock().is_ok();
        release.send(()).unwrap();
        worker.join().unwrap();
        health_shutdown.lock().unwrap().cancel();
        assert!(
            probed,
            "replacement probes must start while the retired pipeline destructor is blocked"
        );
        assert!(publication_unlocked, "user destructors must run outside publication");
        target.stop();
        assert!(target.with_live(|_| Ok(())).is_err());
    }

    #[test]
    fn revocation_does_not_run_downstream_destructors_on_stopping_thread() {
        let registry = FilterRegistry::with_builtins();
        let (started, entered) = std::sync::mpsc::channel();
        let (release, wait) = std::sync::mpsc::channel();
        let mut pipeline = praxis_filter::FilterPipeline::build(&mut [], &registry).unwrap();
        pipeline.add_pipeline_extension(Box::new(BlockingPipelineDrop {
            started,
            release: Mutex::new(wait),
        }));
        let target = Arc::new(WatcherReloadTarget::new(Arc::new(ListenerPipelines::new(
            HashMap::from([("web".to_owned(), Arc::new(pipeline))]),
        ))));
        let retention = target.retain_pipelines();
        let worker = std::thread::spawn(move || drop(retention));
        target.stop();
        entered.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
        assert!(
            target.with_live(|_| Ok(())).is_err(),
            "revocation precedes slow destruction"
        );
        release.send(()).unwrap();
        worker.join().unwrap();
    }

    impl PipelineExtension for ReloadMarker {
        fn prepare(&self, extensions: &mut RequestExtensions) {
            extensions.insert(self.clone());
        }
    }

    #[test]
    #[cfg(unix)]
    fn permission_warning_can_revoke_reload_before_publication() {
        use std::os::unix::fs::PermissionsExt as _;
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::set_permissions(file.path(), std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_diagnostic_revokes("startup_checks", None, "discarding staged reload", |config| {
            config.runtime.logging.output = praxis_core::config::LogOutput::File;
            config.runtime.logging.file_path = Some(file.path().display().to_string());
        });
    }

    #[test]
    fn change_diagnostics_can_revoke_reload_before_publication() {
        assert_diagnostic_revokes("reload_diagnostics", None, "discarding staged reload", |config| {
            config.runtime.overload_purge = !config.runtime.overload_purge;
        });
    }

    #[test]
    fn rejection_diagnostic_does_not_hold_publication() {
        assert_diagnostic_revokes("reload", Some(tracing::Level::ERROR), "protocol", |config| {
            config.listeners[0].protocol = ProtocolKind::Tcp;
        });
    }

    /// Exercise distinct diagnostics with identical publication/rollback invariants.
    fn assert_diagnostic_revokes<Prepare>(
        diagnostic_target: &'static str,
        level: Option<tracing::Level>,
        error: &str,
        prepare: Prepare,
    ) where
        Prepare: FnOnce(&mut Config),
    {
        let (pipelines, old, registry, shutdown, meta, cluster_meta) = setup_live_pipelines();
        let pipelines = Arc::new(pipelines);
        let original = pipelines.get("web").unwrap().load_full();
        let token = shutdown.lock().unwrap().clone();
        let target = Arc::new(WatcherReloadTarget::new(Arc::clone(&pipelines)));
        let mut candidate = old.clone();
        prepare(&mut candidate);
        let observations = Arc::new(AtomicUsize::new(0));
        let locked = Arc::new(AtomicUsize::new(0));
        let subscriber = tracing_subscriber::registry().with(PublicationLockProbe {
            diagnostic_target,
            level,
            target: Arc::clone(&target),
            observations: Arc::clone(&observations),
            locked: Arc::clone(&locked),
        });
        let result = tracing::subscriber::with_default(subscriber, || {
            reload_pipelines(
                &candidate,
                &old,
                &registry,
                &target,
                &meta,
                &cluster_meta,
                &shutdown,
                None,
                &empty_kv_stores(),
                &empty_session_stores(),
                &empty_slow_start_registry(),
                &empty_subrequest_client(),
                None,
                &PipelineComposition::default(),
            )
        });
        assert!(
            result.unwrap_err().to_string().contains(error),
            "diagnostic must preserve its rejection reason"
        );
        assert!(
            observations.load(Ordering::Relaxed) > 0,
            "the intended diagnostic must run"
        );
        assert_eq!(
            locked.load(Ordering::Relaxed),
            0,
            "diagnostics must not hold publication"
        );
        assert!(
            Arc::ptr_eq(&original, &pipelines.get("web").unwrap().load_full()),
            "rejected reload must preserve pipelines"
        );
        assert!(!token.is_cancelled(), "rejected reload must preserve health tasks");
    }
    #[test]
    fn incompatible_buffered_request_reload_preserves_live_state() {
        let (live, old_config, registry, shutdown, meta, cluster_meta) = setup_live_pipelines();
        let old_pipeline = live.get("web").unwrap().load_full();
        let old_meta = meta.load_full();
        let old_cluster_meta = cluster_meta.load_full();
        let old_token = shutdown.lock().unwrap().clone();
        let new_config = Config::from_yaml(
            r#"
body_limits:
  max_buffer_bytes: 4096
  max_request_bytes: 8192
listeners:
  - name: web
    address: "127.0.0.1:9090"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: json_body_field
        field: model
        header: x-praxis-model
      - filter: static_response
        status: 204
"#,
        )
        .unwrap();
        let error = reload_pipelines(
            &new_config,
            &old_config,
            &registry,
            &live,
            &meta,
            &cluster_meta,
            &shutdown,
            None,
            &empty_kv_stores(),
            &empty_session_stores(),
            &empty_slow_start_registry(),
            &empty_subrequest_client(),
            None,
            &PipelineComposition::default(),
        )
        .unwrap_err();
        let message = error.to_string();
        assert!(message.contains("body_limits.max_request_bytes (8192)"), "{message}");
        assert!(message.contains("body_limits.max_buffer_bytes (4096)"), "{message}");
        assert!(Arc::ptr_eq(&live.get("web").unwrap().load_full(), &old_pipeline));
        assert!(Arc::ptr_eq(&meta.load_full(), &old_meta));
        assert!(Arc::ptr_eq(&cluster_meta.load_full(), &old_cluster_meta));
        assert!(
            !old_token.is_cancelled(),
            "failed reload must keep the old health tasks"
        );
        assert_eq!(
            old_pipeline.request_body_ceiling(),
            old_config.body_limits.max_request_bytes
        );
        assert_eq!(old_pipeline.buffer_cap(), old_config.body_limits.max_buffer_bytes.get());
    }

    #[test]
    fn valid_reload_swaps_pipeline() {
        let (live, old_config, registry, shutdown, meta, cluster_meta) = setup_live_pipelines();
        let old_ptr = Arc::as_ptr(&live.get("web").unwrap().load());
        assert_eq!(
            meta.load().get("web").unwrap().address,
            "127.0.0.1:8080",
            "initial meta should reflect setup listener address"
        );

        let new_config = Config::from_yaml(
            r#"
listeners:
  - name: web
    address: "127.0.0.1:9090"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 204
"#,
        )
        .unwrap();
        let result = reload_pipelines(
            &new_config,
            &old_config,
            &registry,
            &live,
            &meta,
            &cluster_meta,
            &shutdown,
            None,
            &empty_kv_stores(),
            &empty_session_stores(),
            &empty_slow_start_registry(),
            &empty_subrequest_client(),
            None,
            &PipelineComposition::default(),
        );

        assert!(result.is_ok(), "valid reload should succeed");
        let new_ptr = Arc::as_ptr(&live.get("web").unwrap().load());
        assert_ne!(old_ptr, new_ptr, "pipeline pointer should change after reload");

        let loaded = meta.load();
        let expected_names: std::collections::HashSet<&str> = new_config
            .listeners
            .iter()
            .map(|listener| listener.name.as_str())
            .collect();
        let actual_names: std::collections::HashSet<&str> = loaded.keys().map(String::as_str).collect();
        assert_eq!(
            actual_names, expected_names,
            "meta listener names should match reload config"
        );
        assert_eq!(
            loaded.get("web").unwrap().address,
            "127.0.0.1:8080",
            "meta should retain the bound listener address"
        );
        assert_eq!(
            loaded.get("web").unwrap().chain_names,
            ["main"],
            "meta should preserve chain names after reload"
        );
    }

    #[test]
    fn reload_preserves_upstream_ca_and_updates_ceiling() {
        praxis_tls::provider::install();
        let mut startup = valid_config();
        startup.runtime.upstream_ca_file = Some(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../tests/integration/fixtures/fips/ca-cert.pem"
            )
            .to_owned(),
        );
        let client = crate::pipelines::build_subrequest_client(&startup).expect("test CA must load");
        let startup_ca = client.upstream_ca().expect("startup client has global CA");
        let (live, old_config, registry, shutdown, meta, cluster_meta) = setup_live_pipelines_from(startup);
        let mut next = old_config.clone();
        next.body_limits.max_response_bytes = Some(8192);

        reload_pipelines(
            &next,
            &old_config,
            &registry,
            &live,
            &meta,
            &cluster_meta,
            &shutdown,
            None,
            &empty_kv_stores(),
            &empty_session_stores(),
            &empty_slow_start_registry(),
            &client,
            None,
            &PipelineComposition::default(),
        )
        .expect("limit-only reload must succeed");
        let applied = live.get("web").unwrap().load_full();
        let applied_client = applied.subrequest_client().expect("reloaded pipeline has client");
        assert_eq!(applied_client.max_response_bytes(), 8192, "new ceiling is applied");
        assert!(
            Arc::ptr_eq(&applied_client.upstream_ca().unwrap(), &startup_ca),
            "global CA must retain its startup identity"
        );
        assert_ne!(client.max_response_bytes(), 8192, "original client must stay unchanged");

        let mut changed_path = next.clone();
        changed_path.runtime.upstream_ca_file = Some("/nonexistent/replacement-ca.pem".to_owned());
        changed_path.body_limits.max_response_bytes = Some(4096);
        let warnings = capture_warnings(|| log_restart_required_changes(&next, &changed_path));
        assert_warning(
            &warnings,
            "startup-only runtime setting changed; requires restart",
            &[("field", "runtime.upstream_ca_file")],
        );
        reload_pipelines(
            &changed_path,
            &next,
            &registry,
            &live,
            &meta,
            &cluster_meta,
            &shutdown,
            None,
            &empty_kv_stores(),
            &empty_session_stores(),
            &empty_slow_start_registry(),
            &client,
            None,
            &PipelineComposition::default(),
        )
        .expect("changed CA path remains startup-only");
        let second_applied = live.get("web").unwrap().load_full();
        let second_applied_client = second_applied
            .subrequest_client()
            .expect("reloaded pipeline has client");
        assert_eq!(
            second_applied_client.max_response_bytes(),
            4096,
            "later ceiling is applied"
        );
        assert!(
            Arc::ptr_eq(&second_applied_client.upstream_ca().unwrap(), &startup_ca),
            "new CA path must not hot-load or replace startup trust"
        );
        assert!(
            empty_subrequest_client()
                .with_response_ceiling(4096)
                .upstream_ca()
                .is_none(),
            "no global CA keeps the default trust behavior"
        );
    }

    /// Startup bound the `web` handler for HTTP. A reload that turns `web`
    /// into a TCP listener yields a TCP-validated pipeline; installed behind
    /// the HTTP handler, every one of its filters would be skipped (#1113).
    #[test]
    fn protocol_change_rejects_reload_and_leaves_live_state_untouched() {
        let (live, old_config, registry, shutdown, meta, cluster_meta) = setup_live_pipelines();
        let old_ptr = Arc::as_ptr(&live.get("web").unwrap().load());
        let old_meta = meta.load_full();
        let old_cluster_meta = cluster_meta.load_full();
        let old_token = shutdown.lock().unwrap().clone();

        let new_config = tcp_web_config();
        let result = reload_pipelines(
            &new_config,
            &old_config,
            &registry,
            &live,
            &meta,
            &cluster_meta,
            &shutdown,
            None,
            &empty_kv_stores(),
            &empty_session_stores(),
            &empty_slow_start_registry(),
            &empty_subrequest_client(),
            None,
            &PipelineComposition::default(),
        );

        let err = result.expect_err("a protocol change cannot be applied to a bound handler");
        assert!(
            err.to_string().contains("web") && err.to_string().contains("protocol"),
            "error should name the listener and the cause: {err}"
        );
        assert_eq!(
            Arc::as_ptr(&live.get("web").unwrap().load()),
            old_ptr,
            "the HTTP handler must keep executing the HTTP pipeline"
        );
        assert!(
            Arc::ptr_eq(&meta.load_full(), &old_meta),
            "listener metadata must not advance on a rejected reload"
        );
        assert!(
            Arc::ptr_eq(&cluster_meta.load_full(), &old_cluster_meta),
            "cluster metadata must not advance on a rejected reload"
        );
        assert!(
            !old_token.is_cancelled(),
            "the live health probes must keep running on a rejected reload"
        );
    }

    /// The watcher keeps the previous config after an `Err`, so the operator
    /// sees the same rejection on every reload until the edit is reverted.
    #[test]
    fn protocol_change_is_rejected_again_on_the_next_reload() {
        let (live, old_config, registry, shutdown, meta, cluster_meta) = setup_live_pipelines();
        let old_ptr = Arc::as_ptr(&live.get("web").unwrap().load());
        let new_config = tcp_web_config();

        for _ in 0..2 {
            let result = reload_pipelines(
                &new_config,
                &old_config,
                &registry,
                &live,
                &meta,
                &cluster_meta,
                &shutdown,
                None,
                &empty_kv_stores(),
                &empty_session_stores(),
                &empty_slow_start_registry(),
                &empty_subrequest_client(),
                None,
                &PipelineComposition::default(),
            );
            assert!(result.is_err(), "every reload carrying the protocol change is rejected");
        }
        assert_eq!(
            Arc::as_ptr(&live.get("web").unwrap().load()),
            old_ptr,
            "no reload may install the TCP pipeline behind the HTTP handler"
        );
    }

    #[test]
    fn protocol_change_from_tcp_rejects_reload() {
        let (live, old_config, registry, shutdown, meta, cluster_meta) = setup_live_pipelines_from(tcp_web_config());
        let old_ptr = Arc::as_ptr(&live.get("web").unwrap().load());

        let new_config = valid_config();
        let result = reload_pipelines(
            &new_config,
            &old_config,
            &registry,
            &live,
            &meta,
            &cluster_meta,
            &shutdown,
            None,
            &empty_kv_stores(),
            &empty_session_stores(),
            &empty_slow_start_registry(),
            &empty_subrequest_client(),
            None,
            &PipelineComposition::default(),
        );

        assert!(
            result.is_err(),
            "a protocol change cannot be applied to a bound handler"
        );
        assert_eq!(
            Arc::as_ptr(&live.get("web").unwrap().load()),
            old_ptr,
            "the TCP handler must keep executing the TCP pipeline"
        );
        assert_eq!(
            meta.load().get("web").unwrap().protocol,
            ProtocolKind::Tcp,
            "meta must report the protocol the bound socket honors"
        );
    }

    #[test]
    fn tcp_group_with_divergent_filter_chains_rejects_reload() {
        let (live, old_config, registry, shutdown, meta, cluster_meta) =
            setup_live_pipelines_from(tcp_group_config("tcp_lb", "tcp_lb", "db_pool", false));
        let db1_ptr = Arc::as_ptr(&live.get("db1").unwrap().load());
        let db2_ptr = Arc::as_ptr(&live.get("db2").unwrap().load());

        let new_config = tcp_group_config("tcp_lb", "tcp_lb_alt", "db_pool", false);
        let result = reload_tcp(
            &new_config,
            &old_config,
            &registry,
            &live,
            &meta,
            &cluster_meta,
            &shutdown,
            None,
        );

        assert!(result.is_err(), "grouped TCP listeners must keep identical chains");
        assert_eq!(
            Arc::as_ptr(&live.get("db1").unwrap().load()),
            db1_ptr,
            "db1 slot must be untouched"
        );
        assert_eq!(
            Arc::as_ptr(&live.get("db2").unwrap().load()),
            db2_ptr,
            "db2 slot must be untouched"
        );
    }

    #[test]
    fn tcp_listener_cluster_change_rejects_reload() {
        let (live, old_config, registry, shutdown, meta, cluster_meta) =
            setup_live_pipelines_from(tcp_group_config("tcp_lb", "tcp_lb", "db_pool", false));
        let db1_ptr = Arc::as_ptr(&live.get("db1").unwrap().load());

        let new_config = tcp_group_config("tcp_lb", "tcp_lb", "db_pool_alt", false);
        let result = reload_tcp(
            &new_config,
            &old_config,
            &registry,
            &live,
            &meta,
            &cluster_meta,
            &shutdown,
            None,
        );

        assert!(
            result.is_err(),
            "a bound TCP listener's group key is captured at startup"
        );
        assert_eq!(
            Arc::as_ptr(&live.get("db1").unwrap().load()),
            db1_ptr,
            "rejected reload must not swap the slot"
        );
    }

    #[test]
    fn tcp_listener_removal_rejects_reload() {
        let (live, old_config, registry, shutdown, meta, cluster_meta) =
            setup_live_pipelines_from(tcp_group_config("tcp_lb", "tcp_lb", "db_pool", false));
        let original_meta = meta.load_full();

        let new_config = tcp_web_config();
        let result = reload_tcp(
            &new_config,
            &old_config,
            &registry,
            &live,
            &meta,
            &cluster_meta,
            &shutdown,
            None,
        );

        assert!(
            result.is_err(),
            "removing a bound TCP listener cannot be applied without a restart"
        );
        assert!(
            Arc::ptr_eq(&meta.load_full(), &original_meta),
            "rejected TCP removal must preserve live listener metadata"
        );
    }

    #[test]
    fn tcp_filter_chain_content_change_is_applied() {
        let (live, old_config, registry, shutdown, meta, cluster_meta) =
            setup_live_pipelines_from(tcp_group_config("tcp_lb", "tcp_lb", "db_pool", false));
        let db1_ptr = Arc::as_ptr(&live.get("db1").unwrap().load());

        let new_config = tcp_group_config("tcp_lb_alt", "tcp_lb_alt", "db_pool", false);
        let result = reload_tcp(
            &new_config,
            &old_config,
            &registry,
            &live,
            &meta,
            &cluster_meta,
            &shutdown,
            None,
        );

        assert!(result.is_ok(), "consistent chain edits must reload: {result:?}");
        assert_ne!(
            Arc::as_ptr(&live.get("db1").unwrap().load()),
            db1_ptr,
            "the group leader slot must be swapped"
        );
    }

    #[test]
    fn allow_private_upstreams_flip_with_tcp_listener_rejects_reload() {
        let (live, old_config, registry, shutdown, meta, cluster_meta) =
            setup_live_pipelines_from(tcp_group_config("tcp_lb", "tcp_lb", "db_pool", false));

        let new_config = tcp_group_config("tcp_lb", "tcp_lb", "db_pool", true);
        let result = reload_tcp(
            &new_config,
            &old_config,
            &registry,
            &live,
            &meta,
            &cluster_meta,
            &shutdown,
            None,
        );

        assert!(
            result.is_err(),
            "allow_private_upstreams is captured by TCP listeners at startup"
        );
    }

    #[cfg(feature = "forward-proxy")]
    #[test]
    fn allow_private_upstreams_flip_with_forward_proxy_listener_rejects_reload() {
        // The CONNECT runtime captures the flag when the handler is bound, so
        // turning it off on reload would leave tunnels dialing private and
        // reserved addresses until restart. No TCP listener is configured.
        let (live, old_config, registry, shutdown, meta, cluster_meta) =
            setup_live_pipelines_from(forward_proxy_config_with_private(true, true));

        let new_config = forward_proxy_config_with_private(true, false);
        let err = reload_tcp(
            &new_config,
            &old_config,
            &registry,
            &live,
            &meta,
            &cluster_meta,
            &shutdown,
            None,
        )
        .expect_err("allow_private_upstreams is captured by forward_proxy listeners at startup");
        assert!(err.to_string().contains("allow_private_upstreams"), "{err}");
    }

    #[cfg(feature = "forward-proxy")]
    #[test]
    fn allow_private_upstreams_flip_with_disabled_forward_proxy_reloads() {
        // An `enabled: false` block builds no CONNECT runtime, so nothing
        // captured the flag.
        let (live, old_config, registry, shutdown, meta, cluster_meta) =
            setup_live_pipelines_from(forward_proxy_config_with_private(false, true));

        let new_config = forward_proxy_config_with_private(false, false);
        let result = reload_tcp(
            &new_config,
            &old_config,
            &registry,
            &live,
            &meta,
            &cluster_meta,
            &shutdown,
            None,
        );
        assert!(result.is_ok(), "{result:?}");
    }

    #[test]
    fn allow_private_upstreams_flip_without_forward_proxy_or_tcp_reloads() {
        // An HTTP-only config without forward proxying captures nothing.
        let (live, old_config, registry, shutdown, meta, cluster_meta) = setup_live_pipelines();

        let mut new_config = valid_config();
        new_config.insecure_options.allow_private_upstreams = !old_config.insecure_options.allow_private_upstreams;
        let result = reload_tcp(
            &new_config,
            &old_config,
            &registry,
            &live,
            &meta,
            &cluster_meta,
            &shutdown,
            None,
        );
        assert!(result.is_ok(), "{result:?}");
    }

    /// The open-relay hole a warn-only diagnostic leaves: startup enabled
    /// CONNECT gated only by `ip_acl`; a reload that disables the block and
    /// drops the filter validates, but the handler's startup CONNECT runtime
    /// would keep tunneling under the new, filterless pipeline.
    #[cfg(feature = "forward-proxy")]
    #[test]
    fn forward_proxy_disable_with_egress_filter_removal_rejects_reload() {
        let (live, old_config, registry, shutdown, meta, cluster_meta) =
            setup_live_pipelines_from(forward_proxy_config("enabled: true", true));
        let old_ptr = Arc::as_ptr(&live.get("web").unwrap().load());

        let new_config = forward_proxy_config("enabled: false", false);
        let result = reload_tcp(
            &new_config,
            &old_config,
            &registry,
            &live,
            &meta,
            &cluster_meta,
            &shutdown,
            None,
        );

        let err = result.expect_err("the CONNECT runtime is captured at startup");
        assert!(
            err.to_string().contains("forward_proxy"),
            "error names the field: {err}"
        );
        assert_eq!(
            Arc::as_ptr(&live.get("web").unwrap().load()),
            old_ptr,
            "the ip_acl pipeline must stay live"
        );
    }

    #[cfg(feature = "forward-proxy")]
    #[test]
    fn forward_proxy_destination_change_rejects_reload() {
        let (live, old_config, registry, shutdown, meta, cluster_meta) =
            setup_live_pipelines_from(forward_proxy_config(
                "enabled: true\n      allow_destinations: [{host: a.example.com}]",
                false,
            ));

        let new_config = forward_proxy_config(
            "enabled: true\n      allow_destinations: [{host: b.example.com}]",
            false,
        );
        let result = reload_tcp(
            &new_config,
            &old_config,
            &registry,
            &live,
            &meta,
            &cluster_meta,
            &shutdown,
            None,
        );

        assert!(result.is_err(), "the destination matcher is built at startup");
    }

    #[cfg(feature = "forward-proxy")]
    #[test]
    fn forward_proxy_added_to_bound_listener_rejects_reload() {
        let (live, old_config, registry, shutdown, meta, cluster_meta) = setup_live_pipelines();

        let new_config = forward_proxy_config("enabled: true", true);
        let result = reload_tcp(
            &new_config,
            &old_config,
            &registry,
            &live,
            &meta,
            &cluster_meta,
            &shutdown,
            None,
        );

        assert!(result.is_err(), "the CONNECT gate is set when the handler is bound");
    }

    #[cfg(feature = "forward-proxy")]
    #[test]
    fn forward_proxy_listener_removal_rejects_reload() {
        let (live, old_config, registry, shutdown, meta, cluster_meta) =
            setup_live_pipelines_from(forward_proxy_config("enabled: true", true));

        let without_web = Config::from_yaml(
            r#"
listeners:
  - name: other
    address: "127.0.0.1:8081"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#,
        )
        .unwrap();
        let result = reload_tcp(
            &without_web,
            &old_config,
            &registry,
            &live,
            &meta,
            &cluster_meta,
            &shutdown,
            None,
        );

        assert!(
            result.is_err(),
            "a removed listener keeps its CONNECT runtime; a later re-add could not be compared"
        );
    }

    /// A listener removed without a block (accepted) and re-added with one
    /// must not slip past: its handler was bound without CONNECT.
    #[cfg(feature = "forward-proxy")]
    #[test]
    fn forward_proxy_added_after_remove_and_readd_rejects_reload() {
        let (live, old_config, registry, shutdown, meta, cluster_meta) = setup_live_pipelines();

        let without_web = Config::from_yaml(
            r#"
listeners:
  - name: other
    address: "127.0.0.1:8081"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#,
        )
        .unwrap();
        reload_tcp(
            &without_web,
            &old_config,
            &registry,
            &live,
            &meta,
            &cluster_meta,
            &shutdown,
            None,
        )
        .expect("removing a listener without forward_proxy is accepted");

        let readded = forward_proxy_config("enabled: true", true);
        let result = reload_tcp(
            &readded,
            &without_web,
            &registry,
            &live,
            &meta,
            &cluster_meta,
            &shutdown,
            None,
        );

        assert!(
            result.is_err(),
            "the re-added listener's handler was bound without CONNECT"
        );
    }

    #[cfg(feature = "forward-proxy")]
    #[test]
    fn unchanged_forward_proxy_reloads() {
        let (live, old_config, registry, shutdown, meta, cluster_meta) =
            setup_live_pipelines_from(forward_proxy_config("enabled: true", true));
        let old_ptr = Arc::as_ptr(&live.get("web").unwrap().load());

        let new_config = forward_proxy_config("enabled: true", true);
        let result = reload_tcp(
            &new_config,
            &old_config,
            &registry,
            &live,
            &meta,
            &cluster_meta,
            &shutdown,
            None,
        );

        assert!(result.is_ok(), "an unchanged block must not block reloads: {result:?}");
        assert_ne!(
            Arc::as_ptr(&live.get("web").unwrap().load()),
            old_ptr,
            "the pipeline is still swapped"
        );
    }

    /// Removing `web` from the config and adding it back with the other
    /// protocol must not slip past the check: the handler is still bound,
    /// and the previous config no longer mentions the listener at all.
    #[test]
    fn protocol_change_after_remove_and_readd_rejects_reload() {
        let (live, old_config, registry, shutdown, meta, cluster_meta) = setup_live_pipelines();
        let old_ptr = Arc::as_ptr(&live.get("web").unwrap().load());

        let without_web = Config::from_yaml(
            r#"
listeners:
  - name: other
    address: "127.0.0.1:8081"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#,
        )
        .unwrap();
        reload_pipelines(
            &without_web,
            &old_config,
            &registry,
            &live,
            &meta,
            &cluster_meta,
            &shutdown,
            None,
            &empty_kv_stores(),
            &empty_session_stores(),
            &empty_slow_start_registry(),
            &empty_subrequest_client(),
            None,
            &PipelineComposition::default(),
        )
        .expect("removing a listener from the config is accepted");
        assert!(
            meta.load()
                .get("web")
                .is_some_and(|entry| !entry.configured_in_current_generation),
            "the removed listener remains bound with retained metadata"
        );

        let readded_as_tcp = tcp_web_config();
        let result = reload_pipelines(
            &readded_as_tcp,
            &without_web,
            &registry,
            &live,
            &meta,
            &cluster_meta,
            &shutdown,
            None,
            &empty_kv_stores(),
            &empty_session_stores(),
            &empty_slow_start_registry(),
            &empty_subrequest_client(),
            None,
            &PipelineComposition::default(),
        );

        assert!(result.is_err(), "the re-added listener still targets the HTTP handler");
        assert_eq!(
            Arc::as_ptr(&live.get("web").unwrap().load()),
            old_ptr,
            "the HTTP handler must keep executing the HTTP pipeline"
        );
    }

    /// One listener switching protocol rejects the whole reload: the other
    /// listener's pipeline is not swapped either, so the live pipelines and
    /// both metadata stores stay on a single generation.
    #[test]
    fn protocol_change_on_one_listener_rejects_reload_for_all() {
        let (live, old_config, registry, shutdown, meta, cluster_meta) = setup_live_pipelines_from(
            Config::from_yaml(
                r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
  - name: api
    address: "127.0.0.1:8081"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#,
            )
            .unwrap(),
        );
        let old_web_ptr = Arc::as_ptr(&live.get("web").unwrap().load());
        let old_api_ptr = Arc::as_ptr(&live.get("api").unwrap().load());
        let old_meta = meta.load_full();
        let old_cluster_meta = cluster_meta.load_full();

        let new_config = Config::from_yaml(
            r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    protocol: tcp
    cluster: db_pool
    filter_chains: [tcp_lb]
  - name: api
    address: "127.0.0.1:8081"
    filter_chains: [main]
clusters:
  - name: db_pool
    endpoints:
      - "10.0.0.1:5432"
insecure_options:
  allow_private_endpoints: true
  allow_private_upstreams: true
filter_chains:
  - name: tcp_lb
    filters:
      - filter: tcp_load_balancer
        clusters:
          - name: db_pool
            endpoints:
              - "10.0.0.1:5432"
  - name: main
    filters:
      - filter: static_response
        status: 404
"#,
        )
        .unwrap();
        let result = reload_pipelines(
            &new_config,
            &old_config,
            &registry,
            &live,
            &meta,
            &cluster_meta,
            &shutdown,
            None,
            &empty_kv_stores(),
            &empty_session_stores(),
            &empty_slow_start_registry(),
            &empty_subrequest_client(),
            None,
            &PipelineComposition::default(),
        );

        assert!(
            result.is_err(),
            "a protocol change on any bound listener rejects the reload"
        );
        assert_eq!(
            Arc::as_ptr(&live.get("web").unwrap().load()),
            old_web_ptr,
            "the changed listener keeps its HTTP pipeline"
        );
        assert_eq!(
            Arc::as_ptr(&live.get("api").unwrap().load()),
            old_api_ptr,
            "the unchanged listener is not swapped ahead of the rejected one"
        );
        assert!(
            Arc::ptr_eq(&meta.load_full(), &old_meta),
            "listener metadata must not advance on a rejected reload"
        );
        assert!(
            Arc::ptr_eq(&cluster_meta.load_full(), &old_cluster_meta),
            "cluster metadata must not advance on a rejected reload"
        );
    }

    /// A listener added by reload has no bound handler and therefore no
    /// recorded protocol, so its protocol is not compared against anything.
    /// The reload applies to the bound listener and skips the new one.
    #[test]
    fn new_tcp_listener_alongside_bound_http_listener_is_accepted() {
        let (live, old_config, registry, shutdown, meta, cluster_meta) = setup_live_pipelines();
        let old_web_ptr = Arc::as_ptr(&live.get("web").unwrap().load());

        let new_config = Config::from_yaml(
            r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
  - name: db
    address: "127.0.0.1:5432"
    protocol: tcp
    cluster: db_pool
    filter_chains: [tcp_lb]
clusters:
  - name: db_pool
    endpoints:
      - "10.0.0.1:5432"
insecure_options:
  allow_private_endpoints: true
  allow_private_upstreams: true
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 404
  - name: tcp_lb
    filters:
      - filter: tcp_load_balancer
        clusters:
          - name: db_pool
            endpoints:
              - "10.0.0.1:5432"
"#,
        )
        .unwrap();
        let result = reload_pipelines(
            &new_config,
            &old_config,
            &registry,
            &live,
            &meta,
            &cluster_meta,
            &shutdown,
            None,
            &empty_kv_stores(),
            &empty_session_stores(),
            &empty_slow_start_registry(),
            &empty_subrequest_client(),
            None,
            &PipelineComposition::default(),
        );

        assert!(
            result.is_ok(),
            "adding a TCP listener next to a bound HTTP one is accepted: {result:?}"
        );
        assert_ne!(
            Arc::as_ptr(&live.get("web").unwrap().load()),
            old_web_ptr,
            "the bound HTTP listener receives its rebuilt pipeline"
        );
        assert!(
            live.get("db").is_none(),
            "the new TCP listener has no handler to serve it until restart"
        );
        assert_eq!(
            meta.load().get("db").map(|entry| entry.protocol),
            Some(ProtocolKind::Tcp),
            "the accepted reload publishes the new listener's metadata"
        );
    }

    #[test]
    #[cfg(feature = "chain-binding")]
    fn reload_rebinds_outbound_chain_and_reinjects_runtime_resources() {
        use async_trait::async_trait;
        use praxis_core::config::ChainRef;
        use praxis_filter::{
            ChainBindingContext, FilterAction, FilterError, FilterPipeline, HttpFilter, HttpFilterContext,
        };

        // Per-configuration snapshot of what the framework injected into the
        // bound outbound pipeline: whether the KV registry landed, and the
        // identity (pointer) of the session-store registry that reached it.
        type Injection = (bool, Option<usize>, usize, Option<usize>);

        // A reference chain-binding callout: it binds an outbound chain once and
        // owns the resulting pipeline, delegating `visit_nested_pipelines` so the
        // bound pipeline participates in runtime-resource propagation. After each
        // visit it records what the nested pipeline now holds, so a test can prove
        // the *server's* configure/reload path reaches the outbound chain.
        struct ObservingCallout {
            outbound: Arc<FilterPipeline>,
            injections: Arc<Mutex<Vec<Injection>>>,
        }

        #[async_trait]
        impl HttpFilter for ObservingCallout {
            fn name(&self) -> &'static str {
                "observing_callout"
            }

            fn visit_nested_pipelines(&mut self, visitor: &mut dyn FnMut(&mut FilterPipeline)) {
                if let Some(pipeline) = Arc::get_mut(&mut self.outbound) {
                    visitor(pipeline);
                    let snapshot = (
                        pipeline.kv_stores().is_some(),
                        pipeline.session_stores().map(|stores| Arc::as_ptr(stores).addr()),
                        pipeline.buffer_cap(),
                        pipeline
                            .subrequest_client()
                            .map(praxis_core::subrequest::SubRequestClient::max_response_bytes),
                    );
                    self.injections.lock().unwrap().push(snapshot);
                }
            }

            async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
                Ok(FilterAction::Continue)
            }
        }

        praxis_tls::provider::install();
        let injections: Arc<Mutex<Vec<Injection>>> = Arc::new(Mutex::new(Vec::new()));
        let mut registry = FilterRegistry::with_builtins();
        let factory_injections = Arc::clone(&injections);
        registry
            .register_chain_binding(
                "observing_callout",
                Arc::new(move |config: &serde_yaml::Value, ctx: &ChainBindingContext<'_>| {
                    let raw = config
                        .get("outbound_chain")
                        .cloned()
                        .ok_or_else(|| FilterError::from("missing outbound_chain"))?;
                    let chain_ref: ChainRef = serde_yaml::from_value(raw)
                        .map_err(|err| FilterError::from(format!("bad outbound_chain: {err}")))?;
                    let outbound = ctx.bind_chain(&chain_ref)?;
                    let filter: Box<dyn HttpFilter> = Box::new(ObservingCallout {
                        outbound: Arc::new(outbound),
                        injections: Arc::clone(&factory_injections),
                    });
                    Ok(filter)
                }),
            )
            .expect("register observing_callout");

        let session_stores = empty_session_stores();
        let publication_session_ptr = Arc::as_ptr(&session_stores).addr();
        let kv_stores = empty_kv_stores();
        let health_registry: HealthRegistry = Arc::new(HashMap::new());

        let old_config = Config::from_yaml(
            r#"
body_limits:
  max_buffer_bytes: 4096
  max_response_bytes: 100000000
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: observing_callout
        outbound_chain:
          name: outbound
          filters:
            - filter: request_id
"#,
        )
        .unwrap();

        let subrequest_client = crate::pipelines::build_subrequest_client(&old_config).unwrap();

        let live = resolve_pipelines(
            &old_config,
            &registry,
            &health_registry,
            &kv_stores,
            &session_stores,
            &subrequest_client,
        )
        .unwrap();

        let expected_session_ptr = live
            .get("web")
            .unwrap()
            .load()
            .session_stores()
            .map(|stores| Arc::as_ptr(stores).addr())
            .unwrap();
        assert_ne!(
            expected_session_ptr, publication_session_ptr,
            "listener must own an isolated store registry"
        );
        let after_build = injections.lock().unwrap().clone();
        let build_count = after_build.len();
        assert!(
            after_build.iter().any(|(kv, session, cap, client)| *kv
                && *session == Some(expected_session_ptr)
                && *cap == 4096
                && *client == Some(4096)),
            "resolve_pipelines must inject KV and session stores into the bound outbound pipeline"
        );

        let pinned_old = live.get("web").unwrap().load_full();
        let old_ptr = Arc::as_ptr(&pinned_old);

        let new_config = Config::from_yaml(
            r#"
body_limits:
  max_buffer_bytes: 67108865
  max_response_bytes: 100000000
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: observing_callout
        outbound_chain:
          name: outbound
          filters:
            - filter: request_id
            - filter: headers
"#,
        )
        .unwrap();

        let shutdown = Arc::new(Mutex::new(CancellationToken::new()));
        let meta = praxis_protocol::http::health::new_listener_meta_store(
            praxis_protocol::http::health::listener_meta_from_config(&old_config),
        );
        let cluster_meta = praxis_protocol::http::health::new_cluster_meta_store(
            praxis_protocol::http::health::cluster_meta_from_config(&old_config),
        );

        reload_pipelines(
            &new_config,
            &old_config,
            &registry,
            &live,
            &meta,
            &cluster_meta,
            &shutdown,
            None,
            &kv_stores,
            &session_stores,
            &empty_slow_start_registry(),
            &subrequest_client,
            None,
            &PipelineComposition::default(),
        )
        .unwrap();

        let new_ptr = Arc::as_ptr(&live.get("web").unwrap().load());
        assert_ne!(old_ptr, new_ptr, "reload must swap in a rebuilt pipeline");
        assert_eq!(pinned_old.buffer_cap(), 4096, "in-flight requests keep their old cap");
        assert_eq!(pinned_old.subrequest_client().unwrap().max_response_bytes(), 4096);
        assert_eq!(live.get("web").unwrap().load().buffer_cap(), 67_108_865);
        let published_session_ptr = live
            .get("web")
            .unwrap()
            .load()
            .session_stores()
            .map(|stores| Arc::as_ptr(stores).addr());
        assert_ne!(
            published_session_ptr,
            Some(expected_session_ptr),
            "candidate generation has distinct registry ownership"
        );

        let after_reload = injections.lock().unwrap().clone();
        assert!(
            after_reload.len() > build_count,
            "reload must re-run configuration over the rebuilt outbound pipeline"
        );
        assert!(
            after_reload[build_count..].iter().any(|(kv, session, cap, client)| *kv
                && *session == published_session_ptr
                && *cap == 67_108_865
                && *client == Some(67_108_865)),
            "reload must re-inject KV and session stores into the rebuilt bound outbound pipeline"
        );
    }

    #[test]
    fn invalid_filter_returns_err_old_pipeline_untouched() {
        let (live, old_config, registry, shutdown, meta, cluster_meta) = setup_live_pipelines();
        let old_ptr = Arc::as_ptr(&live.get("web").unwrap().load());

        let bad_config = Config::from_yaml(
            r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: nonexistent_filter_xyz
"#,
        )
        .unwrap();

        let result = reload_pipelines(
            &bad_config,
            &old_config,
            &registry,
            &live,
            &meta,
            &cluster_meta,
            &shutdown,
            None,
            &empty_kv_stores(),
            &empty_session_stores(),
            &empty_slow_start_registry(),
            &empty_subrequest_client(),
            None,
            &PipelineComposition::default(),
        );
        assert!(result.is_err(), "invalid filter should return Err");

        let current_ptr = Arc::as_ptr(&live.get("web").unwrap().load());
        assert_eq!(old_ptr, current_ptr, "pipeline should be untouched after failure");
    }

    #[test]
    fn failed_reload_does_not_publish_sticky_candidate() {
        let (live, old_config, registry, shutdown, meta, cluster_meta) = setup_live_pipelines();
        let old_ptr = Arc::as_ptr(&live.get("web").unwrap().load());
        let stores = empty_session_stores();
        let new_config = Config::from_yaml(
            r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: sticky_sessions
        clusters:
          - name: backend
            type: header
            header_name: X-Session-Id
            ttl_secs: 3600
            max_entries: 1000
            storage: local
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints: ["127.0.0.1:9"]
insecure_options:
  allow_private_endpoints: true
"#,
        )
        .unwrap();
        let (_factory, failing) = ServerComposition::standard()
            .add_pipeline_validator(|_ctx| Err(crate::composition::CompositionError::new("late validator failure")))
            .into_parts();

        let result = reload_pipelines(
            &new_config,
            &old_config,
            &registry,
            &live,
            &meta,
            &cluster_meta,
            &shutdown,
            None,
            &empty_kv_stores(),
            &stores,
            &empty_slow_start_registry(),
            &empty_subrequest_client(),
            None,
            &failing,
        );
        assert!(result.is_err(), "the late validator must reject the candidate");
        assert!(stores.is_empty(), "a failed build cannot publish a new sticky store");
        assert_eq!(
            Arc::as_ptr(&live.get("web").unwrap().load()),
            old_ptr,
            "live pipeline remains unchanged"
        );

        reload_pipelines(
            &new_config,
            &old_config,
            &registry,
            &live,
            &meta,
            &cluster_meta,
            &shutdown,
            None,
            &empty_kv_stores(),
            &stores,
            &empty_slow_start_registry(),
            &empty_subrequest_client(),
            None,
            &PipelineComposition::default(),
        )
        .unwrap();
        assert!(
            !stores.is_empty(),
            "successful publication must carry the candidate store"
        );
        assert_ne!(
            Arc::as_ptr(&live.get("web").unwrap().load()),
            old_ptr,
            "successful reload swaps pipeline"
        );
    }

    #[tokio::test]
    async fn removed_listener_retains_only_its_bound_stores_across_reloads() {
        let mut previous = sticky_listener_config(true, 100);
        let mut registry = FilterRegistry::with_builtins();
        registry
            .register(
                "observe_sticky_binding",
                FilterFactory::Http(Arc::new(|_| Ok(Box::new(ObserveStickyBinding)))),
            )
            .unwrap();
        let stores = empty_session_stores();
        let client = empty_subrequest_client();
        let kv = empty_kv_stores();
        let slow = empty_slow_start_registry();
        let live = resolve_pipelines(&previous, &registry, &Arc::new(HashMap::new()), &kv, &stores, &client).unwrap();
        let shutdown = Arc::new(Mutex::new(CancellationToken::new()));
        let meta = praxis_protocol::http::health::new_listener_meta_store(
            praxis_protocol::http::health::listener_meta_from_config(&previous),
        );
        let cluster_meta = praxis_protocol::http::health::new_cluster_meta_store(
            praxis_protocol::http::health::cluster_meta_from_config(&previous),
        );
        let initial = live.get("retained").unwrap().load_full();
        let retained_registry = Arc::clone(initial.session_stores().unwrap());
        assert_eq!(
            retained_registry.len(),
            1,
            "startup listener must not own its sibling's stores"
        );
        assert_eq!(stores.len(), 2, "publication owns both configured listeners");
        assert!(
            exercise_sticky_binding(&initial, true).await.is_none(),
            "first request is unbound"
        );
        assert_eq!(
            exercise_sticky_binding(&initial, false).await.as_deref(),
            Some("127.0.0.1:9"),
            "the initial response must establish a binding before reload"
        );
        drop(initial);
        for ttl in 101..105 {
            let retiring = Arc::downgrade(live.get("changing").unwrap().load().session_stores().unwrap());
            let next = sticky_listener_config(false, ttl);
            reload_pipelines(
                &next,
                &previous,
                &registry,
                &live,
                &meta,
                &cluster_meta,
                &shutdown,
                None,
                &kv,
                &stores,
                &slow,
                &client,
                None,
                &PipelineComposition::default(),
            )
            .unwrap();
            assert_eq!(
                stores.len(),
                2,
                "only removed A and current B stores may remain published"
            );
            assert_eq!(
                retained_registry.len(),
                1,
                "retained A must not acquire any B generation"
            );
            assert!(
                retiring.upgrade().is_none(),
                "no retained listener may own B's retired registry"
            );
            let retained = live.get("retained").unwrap().load_full();
            assert!(Arc::ptr_eq(retained.session_stores().unwrap(), &retained_registry));
            assert_eq!(
                exercise_sticky_binding(&retained, false).await.as_deref(),
                Some("127.0.0.1:9"),
                "removed listener must keep its original session binding while it serves"
            );
            previous = next;
        }
        let restored = sticky_listener_config(true, 104);
        reload_pipelines(
            &restored,
            &previous,
            &registry,
            &live,
            &meta,
            &cluster_meta,
            &shutdown,
            None,
            &kv,
            &stores,
            &slow,
            &client,
            None,
            &PipelineComposition::default(),
        )
        .unwrap();
        let current = live.get("retained").unwrap().load_full();
        assert!(
            !Arc::ptr_eq(current.session_stores().unwrap(), &retained_registry),
            "reintroduction must construct a new listener pipeline registry"
        );
        assert_eq!(
            exercise_sticky_binding(&current, false).await.as_deref(),
            Some("127.0.0.1:9"),
            "reintroduced listener must reuse the actual old store binding"
        );
        assert_eq!(stores.len(), 2);
    }

    /// Build distinct sticky configurations for a retained listener and its changing sibling.
    fn sticky_listener_config(include_retained: bool, ttl: u64) -> Config {
        let retained = if include_retained {
            "  - name: retained\n    address: '127.0.0.1:8081'\n    filter_chains: [retained]\n"
        } else {
            ""
        };
        let chains: String = [("retained", 3600), ("changing", ttl)].into_iter().map(|(name, lifetime)| format!(
            "  - name: {name}\n    filters:\n      - filter: router\n        routes:\n          - path_prefix: /\n            cluster: {name}\n      - filter: sticky_sessions\n        clusters:\n          - name: {name}\n            type: header\n            header_name: X-Session-Id\n            ttl_secs: {lifetime}\n            max_entries: 100\n            storage: local\n      - filter: observe_sticky_binding\n      - filter: load_balancer\n        clusters:\n          - name: {name}\n            endpoints: ['127.0.0.1:9']\n")).collect();
        Config::from_yaml(&format!("listeners:\n{retained}  - name: changing\n    address: '127.0.0.1:8082'\n    filter_chains: [changing]\nfilter_chains:\n{chains}insecure_options:\n  allow_private_endpoints: true\n")).unwrap()
    }

    /// Sticky lookup result captured before the load balancer consumes the pin.
    struct ObservedStickyBinding(Option<Arc<str>>);

    /// Observe the real sticky decision without changing upstream selection.
    struct ObserveStickyBinding;

    #[async_trait::async_trait]
    impl praxis_filter::HttpFilter for ObserveStickyBinding {
        fn name(&self) -> &'static str {
            "observe_sticky_binding"
        }

        async fn on_request(
            &self,
            ctx: &mut praxis_filter::HttpFilterContext<'_>,
        ) -> Result<praxis_filter::FilterAction, praxis_filter::FilterError> {
            ctx.extensions
                .insert(ObservedStickyBinding(ctx.pinned_endpoint_address.clone()));
            Ok(praxis_filter::FilterAction::Continue)
        }
    }

    /// Exercise real request/response filter ownership without a network adapter.
    async fn exercise_sticky_binding(pipeline: &praxis_filter::FilterPipeline, bind: bool) -> Option<Arc<str>> {
        let request = praxis_filter::Request {
            method: "GET".parse().unwrap(),
            uri: "/".parse().unwrap(),
            headers: [("x-session-id".parse().unwrap(), "retained-key".parse().unwrap())]
                .into_iter()
                .collect(),
        };
        let mut adapter = praxis_protocol::http::pingora::context::PingoraRequestCtx::default();
        let mut ctx = adapter.build_filter_context(pipeline, &request, None);
        assert!(matches!(
            pipeline.execute_http_request(&mut ctx).await.unwrap(),
            praxis_filter::FilterAction::Continue
        ));
        let pinned = ctx.extensions.get::<ObservedStickyBinding>().unwrap().0.clone();
        if bind {
            let endpoint = Arc::clone(&ctx.upstream.as_ref().unwrap().address);
            ctx.upstream_reached = true;
            ctx.extensions
                .insert(praxis_filter::UpstreamForwardedEndpoint(endpoint));
            assert!(matches!(
                pipeline.execute_http_response(&mut ctx).await.unwrap(),
                praxis_filter::FilterAction::Continue
            ));
        }
        pinned
    }

    #[cfg(any(feature = "policy-builtins", feature = "policy-crypto-default"))]
    #[test]
    fn a_policy_that_fails_construction_keeps_the_previous_policy_serving() {
        let dir = tempfile::TempDir::new().unwrap();
        let good = dir.path().join("good.yaml");
        std::fs::write(&good, "plugins: []\n").unwrap();
        let (live, old_config, registry, shutdown, meta, cluster_meta) =
            setup_live_pipelines_from(policy_config(&good));
        let serving = live.get("web").unwrap().load_full();

        let bad = dir.path().join("bad.yaml");
        std::fs::write(
            &bad,
            "plugins:
  - name: jwt-user
    kind: identity/jwt
    hooks: [identity.resolve]
    config:
      trusted_issuers:
        - issuer: https://idp.test.local
          audiences: [api]
          algorithms: [RS256]
          decoding_key: { kind: pem_file, path: /unused.pem }
          dpop: { mode: required }
",
        )
        .unwrap();
        let reload = |config: &Config| {
            reload_pipelines(
                config,
                &old_config,
                &registry,
                &live,
                &meta,
                &cluster_meta,
                &shutdown,
                None,
                &empty_kv_stores(),
                &empty_session_stores(),
                &empty_slow_start_registry(),
                &empty_subrequest_client(),
                None,
                &PipelineComposition::default(),
            )
        };
        let error = reload(&policy_config(&bad)).expect_err("a refused policy must fail the reload");
        assert!(
            error.to_string().contains("dpop.external_base_url"),
            "the reload error must carry the construction refusal: {error}"
        );
        assert!(
            Arc::ptr_eq(&serving, &live.get("web").unwrap().load_full()),
            "a failed policy reload must keep the previous pipeline serving"
        );

        for attempt in 1..=2 {
            let result = reload(&policy_config(&good));
            assert!(result.is_ok(), "valid reload {attempt} must succeed: {result:?}");
        }
        assert!(
            !Arc::ptr_eq(&serving, &live.get("web").unwrap().load_full()),
            "a valid policy reload must swap the pipeline"
        );
    }

    #[test]
    fn old_cancellation_token_cancelled_on_success() {
        let (live, old_config, registry, shutdown, meta, cluster_meta) = setup_live_pipelines();
        let old_token = shutdown.lock().unwrap().clone();

        let new_config = valid_config();
        reload_pipelines(
            &new_config,
            &old_config,
            &registry,
            &live,
            &meta,
            &cluster_meta,
            &shutdown,
            None,
            &empty_kv_stores(),
            &empty_session_stores(),
            &empty_slow_start_registry(),
            &empty_subrequest_client(),
            None,
            &PipelineComposition::default(),
        )
        .unwrap();

        assert!(
            old_token.is_cancelled(),
            "old token should be cancelled after successful reload"
        );
    }

    #[test]
    fn new_cancellation_token_created_on_success() {
        let (live, old_config, registry, shutdown, meta, cluster_meta) = setup_live_pipelines();
        let old_token = shutdown.lock().unwrap().clone();

        let new_config = valid_config();
        reload_pipelines(
            &new_config,
            &old_config,
            &registry,
            &live,
            &meta,
            &cluster_meta,
            &shutdown,
            None,
            &empty_kv_stores(),
            &empty_session_stores(),
            &empty_slow_start_registry(),
            &empty_subrequest_client(),
            None,
            &PipelineComposition::default(),
        )
        .unwrap();

        let new_token = shutdown.lock().unwrap().clone();
        assert!(
            !new_token.is_cancelled(),
            "new token should not be cancelled after successful reload"
        );
        assert!(old_token.is_cancelled(), "old token should be cancelled");
    }

    #[test]
    fn health_checks_not_cancelled_on_failure() {
        let (live, old_config, registry, shutdown, meta, cluster_meta) = setup_live_pipelines();
        let old_token = shutdown.lock().unwrap().clone();

        let bad_config = Config::from_yaml(
            r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: nonexistent_filter_xyz
"#,
        )
        .unwrap();

        let _err = reload_pipelines(
            &bad_config,
            &old_config,
            &registry,
            &live,
            &meta,
            &cluster_meta,
            &shutdown,
            None,
            &empty_kv_stores(),
            &empty_session_stores(),
            &empty_slow_start_registry(),
            &empty_subrequest_client(),
            None,
            &PipelineComposition::default(),
        );
        assert!(
            !old_token.is_cancelled(),
            "health check token should not be cancelled on validation failure"
        );
    }

    #[test]
    fn new_listener_in_config_is_skipped() {
        let (live, old_config, registry, shutdown, meta, cluster_meta) = setup_live_pipelines();

        let new_config = Config::from_yaml(
            r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
  - name: new_listener
    address: "127.0.0.1:9090"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#,
        )
        .unwrap();

        let result = reload_pipelines(
            &new_config,
            &old_config,
            &registry,
            &live,
            &meta,
            &cluster_meta,
            &shutdown,
            None,
            &empty_kv_stores(),
            &empty_session_stores(),
            &empty_slow_start_registry(),
            &empty_subrequest_client(),
            None,
            &PipelineComposition::default(),
        );
        assert!(result.is_ok(), "reload with new listener should succeed");
        assert!(
            live.get("new_listener").is_none(),
            "new listener should not appear in live pipelines"
        );
    }

    #[test]
    fn listener_added_detected() {
        let old = valid_config();
        let new = Config::from_yaml(
            r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
  - name: api
    address: "127.0.0.1:9090"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#,
        )
        .unwrap();

        let warnings = capture_warnings(|| log_restart_required_changes(&old, &new));
        assert_warning(&warnings, "listener added in config", &[("listener", "api")]);
    }

    #[test]
    fn listener_removed_detected() {
        let old = Config::from_yaml(
            r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
  - name: api
    address: "127.0.0.1:9090"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#,
        )
        .unwrap();
        let new = valid_config();

        let warnings = capture_warnings(|| log_restart_required_changes(&old, &new));
        assert_warning(&warnings, "listener removed in config", &[("listener", "api")]);
    }

    #[test]
    fn listener_address_changed_detected() {
        let old = valid_config();
        let new = Config::from_yaml(
            r#"
listeners:
  - name: web
    address: "127.0.0.1:9999"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#,
        )
        .unwrap();

        let warnings = capture_warnings(|| log_restart_required_changes(&old, &new));
        assert_warning(
            &warnings,
            "listener address changed",
            &[
                ("listener", "web"),
                ("old_address", "127.0.0.1:8080"),
                ("new_address", "127.0.0.1:9999"),
            ],
        );
    }

    #[test]
    fn tls_toggle_detected() {
        let old = valid_config();
        let new = config_with_tls_toggle();

        let warnings = capture_warnings(|| log_restart_required_changes(&old, &new));
        assert_warning(&warnings, "TLS enabled; requires restart", &[("listener", "web")]);
    }

    #[test]
    fn tls_disable_detected() {
        let plain = valid_config();
        let tls = config_with_tls_toggle();
        let warnings = capture_warnings(|| log_restart_required_changes(&tls, &plain));
        assert_warning(&warnings, "TLS disabled; requires restart", &[("listener", "web")]);
    }

    #[test]
    fn no_restart_required_no_warnings() {
        let old = valid_config();
        let new = valid_config();
        let warnings = capture_warnings(|| log_restart_required_changes(&old, &new));
        assert!(
            warnings.is_empty(),
            "identical configs need no restart warning: {warnings:?}"
        );
    }

    #[test]
    fn is_stateful_detects_rate_limit() {
        let entry: praxis_core::config::FilterEntry = serde_yaml::from_str("filter: rate_limit").unwrap();
        assert!(is_stateful_recursive(&entry), "rate_limit should be stateful");
    }

    #[test]
    fn is_stateful_detects_circuit_breaker() {
        let entry: praxis_core::config::FilterEntry = serde_yaml::from_str("filter: circuit_breaker").unwrap();
        assert!(is_stateful_recursive(&entry), "circuit_breaker should be stateful");
    }

    #[test]
    fn is_stateful_ignores_non_stateful_filter() {
        let entry: praxis_core::config::FilterEntry = serde_yaml::from_str("filter: static_response").unwrap();
        assert!(!is_stateful_recursive(&entry), "static_response should not be stateful");
    }

    #[test]
    fn is_stateful_detects_nested_in_branch_chains() {
        let entry: praxis_core::config::FilterEntry = serde_yaml::from_str(
            "\
filter: router
branch_chains:
  - name: branch1
    chains:
      - name: inline1
        filters:
          - filter: rate_limit
",
        )
        .unwrap();
        assert!(
            is_stateful_recursive(&entry),
            "rate_limit nested in a branch chain should be detected"
        );
    }

    #[test]
    fn is_stateful_ignores_non_stateful_in_branch_chains() {
        let entry: praxis_core::config::FilterEntry = serde_yaml::from_str(
            "\
filter: router
branch_chains:
  - name: branch1
    chains:
      - name: inline1
        filters:
          - filter: static_response
",
        )
        .unwrap();
        assert!(
            !is_stateful_recursive(&entry),
            "non-stateful filters in branch chains should not trigger"
        );
    }

    #[test]
    fn find_chains_with_compression_identifies_compressed_chains() {
        let config = Config::from_yaml(
            r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [compressed, plain]
filter_chains:
  - name: compressed
    filters:
      - filter: compression
      - filter: static_response
        status: 200
  - name: plain
    filters:
      - filter: static_response
        status: 200
"#,
        )
        .unwrap();

        let result = find_chains_with_compression(&config);
        assert!(
            result.contains("compressed"),
            "chain with compression filter should be found"
        );
        assert!(
            !result.contains("plain"),
            "chain without compression filter should not be found"
        );
    }

    #[test]
    fn find_chains_with_compression_empty_when_no_compression() {
        let config = valid_config();
        let result = find_chains_with_compression(&config);
        assert!(result.is_empty(), "no chains should have compression in base config");
    }

    #[test]
    fn compression_addition_detected() {
        let old = valid_config();
        let new = Config::from_yaml(
            r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: compression
"#,
        )
        .unwrap();

        let warnings = capture_warnings(|| log_restart_required_changes(&old, &new));
        assert_warning(&warnings, "compression added; requires restart", &[("listener", "web")]);
        let direct = capture_warnings(|| detect_compression_additions(&old, &new));
        assert_warning(&direct, "compression added; requires restart", &[("listener", "web")]);
    }

    #[test]
    fn compression_not_flagged_when_already_present() {
        let config = Config::from_yaml(
            r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: compression
"#,
        )
        .unwrap();

        let warnings = capture_warnings(|| log_restart_required_changes(&config, &config));
        assert!(
            warnings.is_empty(),
            "already registered compression needs no restart warning: {warnings:?}"
        );
        let direct = capture_warnings(|| detect_compression_additions(&config, &config));
        assert!(
            direct.is_empty(),
            "direct compression detector must also stay silent: {direct:?}"
        );
    }

    #[test]
    fn escalation_single_flag_detected() {
        let old = InsecureOptions::default();
        let new = InsecureOptions {
            allow_root: true,
            ..Default::default()
        };

        let escalated = collect_escalated_flags(&old, &new);
        assert_eq!(
            escalated,
            vec!["allow_root"],
            "single escalated flag should be reported"
        );
    }

    #[test]
    fn escalation_multiple_flags_detected() {
        let old = InsecureOptions::default();
        let new = InsecureOptions {
            allow_public_admin: true,
            allow_root: true,
            skip_pipeline_validation: true,
            ..Default::default()
        };

        let escalated = collect_escalated_flags(&old, &new);
        assert_eq!(
            escalated,
            vec!["allow_public_admin", "allow_root", "skip_pipeline_validation"],
            "all escalated flags should be reported in declaration order"
        );
    }

    #[test]
    fn escalation_detects_every_flag() {
        for name in InsecureOptions::default().flags().map(|flag| flag.name) {
            let new: InsecureOptions = serde_yaml::from_str(&format!("{name}: true")).unwrap();
            assert_eq!(
                collect_escalated_flags(&InsecureOptions::default(), &new),
                vec![name],
                "enabling {name} should be reported as an escalation"
            );
        }
    }

    #[test]
    fn no_escalation_when_identical() {
        let opts = InsecureOptions::default();
        let escalated = collect_escalated_flags(&opts, &opts);
        assert!(escalated.is_empty(), "identical options should produce no escalations");
    }

    #[test]
    fn deescalation_not_flagged() {
        let old = InsecureOptions {
            allow_root: true,
            skip_pipeline_validation: true,
            ..Default::default()
        };
        let new = InsecureOptions::default();

        let escalated = collect_escalated_flags(&old, &new);
        assert!(escalated.is_empty(), "true-to-false transitions should not be flagged");
    }

    #[test]
    fn escalation_only_newly_enabled_reported() {
        let old = InsecureOptions {
            allow_root: true,
            ..Default::default()
        };
        let new = InsecureOptions {
            allow_root: true,
            skip_pipeline_validation: true,
            ..Default::default()
        };

        let escalated = collect_escalated_flags(&old, &new);
        assert_eq!(
            escalated,
            vec!["skip_pipeline_validation"],
            "only newly enabled flags should be reported"
        );
    }

    #[test]
    fn escalation_detects_granular_pipeline_check() {
        let old = InsecureOptions::default();
        let new = InsecureOptions {
            skip_pipeline_checks: SkipPipelineChecks {
                duplicate_routers: true,
                ..Default::default()
            },
            ..Default::default()
        };

        let escalated = collect_escalated_flags(&old, &new);
        assert_eq!(
            escalated,
            vec!["skip_pipeline_checks.duplicate_routers"],
            "granular pipeline check escalation should be detected"
        );
    }

    #[test]
    fn audit_identical_configs_all_zeros() {
        let config = valid_config();
        assert_eq!(
            diff_named_items(&config.listeners, &config.listeners, |listener| &listener.name),
            (0, 0, 0),
            "identical listeners should show no changes"
        );
        assert_eq!(
            diff_named_items(&config.clusters, &config.clusters, |cluster| &cluster.name),
            (0, 0, 0),
            "identical clusters should show no changes"
        );
        assert_eq!(
            diff_named_items(&config.filter_chains, &config.filter_chains, |chain| &chain.name),
            (0, 0, 0),
            "identical chains should show no changes"
        );
    }

    #[test]
    fn audit_cluster_added() {
        let old = valid_config();
        let new = Config::from_yaml(
            r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
clusters:
  - name: backend
    endpoints: ["10.0.0.1:80"]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#,
        )
        .unwrap();

        let (added, removed, modified) = diff_named_items(&old.clusters, &new.clusters, |cluster| &cluster.name);
        assert_eq!(added, 1, "one cluster should be added");
        assert_eq!(removed, 0, "no clusters should be removed");
        assert_eq!(modified, 0, "no clusters should be modified");
    }

    #[test]
    fn audit_cluster_removed() {
        let old = Config::from_yaml(
            r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
clusters:
  - name: backend
    endpoints: ["10.0.0.1:80"]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#,
        )
        .unwrap();
        let new = valid_config();

        let (added, removed, modified) = diff_named_items(&old.clusters, &new.clusters, |cluster| &cluster.name);
        assert_eq!(added, 0, "no clusters should be added");
        assert_eq!(removed, 1, "one cluster should be removed");
        assert_eq!(modified, 0, "no clusters should be modified");
    }

    #[test]
    fn audit_filter_chain_modified() {
        let old = valid_config();
        let new = Config::from_yaml(
            r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 404
"#,
        )
        .unwrap();

        let (added, removed, modified) = diff_named_items(&old.filter_chains, &new.filter_chains, |chain| &chain.name);
        assert_eq!(added, 0, "no chains should be added");
        assert_eq!(removed, 0, "no chains should be removed");
        assert_eq!(modified, 1, "one chain should be modified");
    }

    #[test]
    fn audit_insecure_options_change_detected() {
        let old = valid_config();
        let mut new = valid_config();
        new.insecure_options.allow_root = true;

        let changed =
            serde_yaml::to_string(&old.insecure_options).ok() != serde_yaml::to_string(&new.insecure_options).ok();
        assert!(changed, "insecure_options change should be detected");
    }

    #[test]
    fn audit_insecure_options_identical() {
        let config = valid_config();
        let changed = serde_yaml::to_string(&config.insecure_options).ok()
            != serde_yaml::to_string(&config.insecure_options).ok();
        assert!(!changed, "identical insecure_options should not flag change");
    }

    #[test]
    fn audit_mixed_changes() {
        let old = Config::from_yaml(
            r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
  - name: api
    address: "127.0.0.1:9090"
    filter_chains: [main]
clusters:
  - name: old_cluster
    endpoints: ["10.0.0.1:80"]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#,
        )
        .unwrap();

        let new = Config::from_yaml(
            r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
  - name: grpc
    address: "127.0.0.1:7070"
    filter_chains: [main]
clusters:
  - name: new_cluster
    endpoints: ["10.0.0.2:80"]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 404
"#,
        )
        .unwrap();

        let (la, lr, lm) = diff_named_items(&old.listeners, &new.listeners, |listener| &listener.name);
        assert_eq!(la, 1, "one listener added (grpc)");
        assert_eq!(lr, 1, "one listener removed (api)");
        assert_eq!(lm, 0, "web listener unchanged");

        let (ca, cr, cm) = diff_named_items(&old.clusters, &new.clusters, |cluster| &cluster.name);
        assert_eq!(ca, 1, "one cluster added (new_cluster)");
        assert_eq!(cr, 1, "one cluster removed (old_cluster)");
        assert_eq!(cm, 0, "no clusters modified");

        let (fa, fr, fm) = diff_named_items(&old.filter_chains, &new.filter_chains, |chain| &chain.name);
        assert_eq!(fa, 0, "no chains added");
        assert_eq!(fr, 0, "no chains removed");
        assert_eq!(fm, 1, "main chain modified (status 200->404)");
    }

    #[test]
    fn audit_log_does_not_panic() {
        let old = valid_config();
        let new = valid_config();
        log_config_change_audit(&old, &new);
    }

    #[test]
    fn no_escalation_when_all_already_true() {
        let opts = InsecureOptions {
            allow_open_security_filters: true,
            allow_private_endpoints: true,
            allow_private_health_checks: true,
            allow_private_upstreams: true,
            allow_public_admin: true,
            allow_root: true,
            allow_tls_no_verify: true,
            allow_tls_without_sni: true,
            allow_unbounded_body: true,
            csrf_log_only: true,
            skip_pipeline_checks: SkipPipelineChecks::all(),
            skip_pipeline_validation: true,
        };

        let escalated = collect_escalated_flags(&opts, &opts);
        assert!(escalated.is_empty(), "already-true flags should not be reported");
    }

    #[test]
    fn reload_carries_unhealthy_endpoint_state() {
        let config = health_checked_config();
        let registry = FilterRegistry::with_builtins();
        let old_health = build_health_registry(&config.clusters);
        let live = resolve_pipelines(
            &config,
            &registry,
            &old_health,
            &empty_kv_stores(),
            &empty_session_stores(),
            &empty_subrequest_client(),
        )
        .unwrap();
        let shutdown = Arc::new(Mutex::new(CancellationToken::new()));
        let meta = praxis_protocol::http::health::new_listener_meta_store(
            praxis_protocol::http::health::listener_meta_from_config(&config),
        );
        let cluster_meta = praxis_protocol::http::health::new_cluster_meta_store(
            praxis_protocol::http::health::cluster_meta_from_config(&config),
        );

        old_health.get("backend").unwrap().endpoints()[1].mark_unhealthy();

        reload_pipelines(
            &config,
            &config,
            &registry,
            &live,
            &meta,
            &cluster_meta,
            &shutdown,
            None,
            &empty_kv_stores(),
            &empty_session_stores(),
            &empty_slow_start_registry(),
            &empty_subrequest_client(),
            None,
            &PipelineComposition::default(),
        )
        .unwrap();

        let new_registry = live.get("web").unwrap().load().health_registry().cloned().unwrap();
        assert!(
            !Arc::ptr_eq(&new_registry, &old_health),
            "reload must install a fresh registry"
        );
        let entry = new_registry.get("backend").unwrap();
        assert!(
            !entry.endpoints()[1].is_healthy(),
            "known-down endpoint must stay down across reload"
        );
        assert!(
            entry.endpoints()[0].is_healthy(),
            "healthy endpoint must stay healthy across reload"
        );
    }

    #[test]
    fn carry_over_ignores_stale_pipeline_of_removed_listener() {
        let two = health_checked_config_two_listeners();
        let one = health_checked_config();
        let registry = FilterRegistry::with_builtins();
        let stale_health = build_health_registry(&two.clusters);
        let live = resolve_pipelines(
            &two,
            &registry,
            &stale_health,
            &empty_kv_stores(),
            &empty_session_stores(),
            &empty_subrequest_client(),
        )
        .unwrap();
        let shutdown = Arc::new(Mutex::new(CancellationToken::new()));
        let meta = praxis_protocol::http::health::new_listener_meta_store(
            praxis_protocol::http::health::listener_meta_from_config(&two),
        );
        let cluster_meta = praxis_protocol::http::health::new_cluster_meta_store(
            praxis_protocol::http::health::cluster_meta_from_config(&two),
        );

        reload_pipelines(
            &one,
            &two,
            &registry,
            &live,
            &meta,
            &cluster_meta,
            &shutdown,
            None,
            &empty_kv_stores(),
            &empty_session_stores(),
            &empty_slow_start_registry(),
            &empty_subrequest_client(),
            None,
            &PipelineComposition::default(),
        )
        .unwrap();

        stale_health.get("backend").unwrap().endpoints()[0].mark_unhealthy();

        reload_pipelines(
            &one,
            &one,
            &registry,
            &live,
            &meta,
            &cluster_meta,
            &shutdown,
            None,
            &empty_kv_stores(),
            &empty_session_stores(),
            &empty_slow_start_registry(),
            &empty_subrequest_client(),
            None,
            &PipelineComposition::default(),
        )
        .unwrap();

        let new_registry = live.get("web").unwrap().load().health_registry().cloned().unwrap();
        assert!(
            new_registry.get("backend").unwrap().endpoints()[0].is_healthy(),
            "a stale verdict from a removed listener's frozen registry must not be carried over"
        );
    }

    #[test]
    fn reload_resets_health_when_check_config_changes() {
        let config = health_checked_config();
        let registry = FilterRegistry::with_builtins();
        let old_health = build_health_registry(&config.clusters);
        let live = resolve_pipelines(
            &config,
            &registry,
            &old_health,
            &empty_kv_stores(),
            &empty_session_stores(),
            &empty_subrequest_client(),
        )
        .unwrap();
        let shutdown = Arc::new(Mutex::new(CancellationToken::new()));
        let meta = praxis_protocol::http::health::new_listener_meta_store(
            praxis_protocol::http::health::listener_meta_from_config(&config),
        );
        let cluster_meta = praxis_protocol::http::health::new_cluster_meta_store(
            praxis_protocol::http::health::cluster_meta_from_config(&config),
        );

        old_health.get("backend").unwrap().endpoints()[1].mark_unhealthy();

        let mut new_config = health_checked_config();
        if let Some(hc) = &mut new_config.clusters[0].health_check {
            hc.interval_ms = 30_000;
        }

        reload_pipelines(
            &new_config,
            &config,
            &registry,
            &live,
            &meta,
            &cluster_meta,
            &shutdown,
            None,
            &empty_kv_stores(),
            &empty_session_stores(),
            &empty_slow_start_registry(),
            &empty_subrequest_client(),
            None,
            &PipelineComposition::default(),
        )
        .unwrap();

        let new_registry = live.get("web").unwrap().load().health_registry().cloned().unwrap();
        assert!(
            new_registry.get("backend").unwrap().endpoints()[1].is_healthy(),
            "changed health_check config must reset endpoint state"
        );
    }

    // -------------------------------------------------------------------------
    // Server composition (issue #1085)
    // -------------------------------------------------------------------------

    #[test]
    fn reload_reuses_provided_registry_including_custom_filters() {
        let mut registry = FilterRegistry::with_builtins();
        registry
            .register(
                "my_custom_breaker",
                FilterFactory::Http(Arc::new(|cfg: &serde_yaml::Value| {
                    CircuitBreakerFilter::from_config(cfg)
                })),
            )
            .unwrap();

        let config = valid_config();
        let health_registry: HealthRegistry = Arc::new(HashMap::new());
        let live = resolve_pipelines(
            &config,
            &registry,
            &health_registry,
            &empty_kv_stores(),
            &empty_session_stores(),
            &empty_subrequest_client(),
        )
        .unwrap();
        let shutdown = Arc::new(Mutex::new(CancellationToken::new()));
        let meta = praxis_protocol::http::health::new_listener_meta_store(
            praxis_protocol::http::health::listener_meta_from_config(&config),
        );
        let cluster_meta = praxis_protocol::http::health::new_cluster_meta_store(
            praxis_protocol::http::health::cluster_meta_from_config(&config),
        );

        let new_config = Config::from_yaml(
            r#"
insecure_options:
  skip_pipeline_validation: true
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: my_custom_breaker
        clusters:
          - name: backend
            consecutive_failures: 3
            recovery_window_secs: 30
      - filter: static_response
        status: 200
"#,
        )
        .unwrap();

        reload_pipelines(
            &new_config,
            &config,
            &registry,
            &live,
            &meta,
            &cluster_meta,
            &shutdown,
            None,
            &empty_kv_stores(),
            &empty_session_stores(),
            &empty_slow_start_registry(),
            &empty_subrequest_client(),
            None,
            &PipelineComposition::default(),
        )
        .expect("reload must reuse the custom registry and resolve the custom filter");
    }

    #[test]
    fn reload_preserves_downstream_extensions() {
        let (live, old_config, registry, shutdown, meta, cluster_meta) = setup_live_pipelines();

        let calls = Arc::new(AtomicUsize::new(0));
        let calls_in_factory = Arc::clone(&calls);
        let (_registry_factory, composition) = ServerComposition::standard()
            .add_pipeline_extension_factory(move |_ctx| {
                calls_in_factory.fetch_add(1, Ordering::SeqCst);
                let ext: Box<dyn PipelineExtension> = Box::new(ReloadMarker(3));
                Ok(ext)
            })
            .into_parts();

        let new_config = valid_config();
        reload_pipelines(
            &new_config,
            &old_config,
            &registry,
            &live,
            &meta,
            &cluster_meta,
            &shutdown,
            None,
            &empty_kv_stores(),
            &empty_session_stores(),
            &empty_slow_start_registry(),
            &empty_subrequest_client(),
            None,
            &composition,
        )
        .unwrap();

        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "the extension factory must run for the listener pipeline on reload"
        );

        let pipeline = live.get("web").unwrap().load();
        let mut request_extensions = RequestExtensions::new();
        pipeline.prepare_extensions(&mut request_extensions);
        assert_eq!(
            request_extensions.get::<ReloadMarker>(),
            Some(&ReloadMarker(3)),
            "the reloaded pipeline must still carry the downstream extension"
        );
    }

    // -----------------------------------------------------------------------------
    // Test Utilities
    // -----------------------------------------------------------------------------

    /// Captured warning and its structured tracing fields.
    #[derive(Clone, Debug)]
    struct WarningEvent {
        /// Field values rendered by the tracing visitor.
        fields: BTreeMap<String, String>,
    }

    /// Layer that records warning events for one synchronous detector call.
    struct WarningCapture(Arc<Mutex<Vec<WarningEvent>>>);

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for WarningCapture {
        fn on_event(&self, event: &tracing::Event<'_>, _ctx: tracing_subscriber::layer::Context<'_, S>) {
            if *event.metadata().level() != tracing::Level::WARN {
                return;
            }
            let mut visitor = WarningFieldVisitor(BTreeMap::new());
            event.record(&mut visitor);
            self.0.lock().unwrap().push(WarningEvent { fields: visitor.0 });
        }
    }

    /// Visitor that keeps warning messages and named fields.
    struct WarningFieldVisitor(BTreeMap<String, String>);

    impl tracing::field::Visit for WarningFieldVisitor {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            self.0.insert(field.name().to_owned(), format!("{value:?}"));
        }
    }

    /// Capture warnings emitted in the calling thread.
    fn capture_warnings(run: impl FnOnce()) -> Vec<WarningEvent> {
        let events = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::registry().with(WarningCapture(Arc::clone(&events)));
        tracing::subscriber::with_default(subscriber, run);
        let guard = events.lock().unwrap();
        guard.clone()
    }

    /// Assert that one event carries a message and all named field values.
    fn assert_warning(warnings: &[WarningEvent], message: &str, fields: &[(&str, &str)]) {
        let found = warnings.iter().any(|warning| {
            warning
                .fields
                .get("message")
                .is_some_and(|value| value.contains(message))
                && fields
                    .iter()
                    .all(|(name, expected)| warning.fields.get(*name).is_some_and(|value| value.contains(expected)))
        });
        assert!(
            found,
            "expected warning {message:?} with {fields:?}; observed {warnings:?}"
        );
    }

    /// TLS-enabled variant of the minimal reload config.
    fn config_with_tls_toggle() -> Config {
        Config::from_yaml(
            r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
    tls:
      certificates:
        - cert_path: "/tmp/cert.pem"
          key_path: "/tmp/key.pem"
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#,
        )
        .unwrap()
    }

    /// Try revoking publication while a synchronous diagnostic sink is running.
    struct PublicationLockProbe {
        /// Diagnostic module to observe.
        diagnostic_target: &'static str,
        /// Restrict observation when testing rejection-only diagnostics.
        level: Option<tracing::Level>,
        /// The publication target whose lock must remain available.
        target: Arc<WatcherReloadTarget>,
        /// Number of diagnostics observed.
        observations: Arc<AtomicUsize>,
        /// Number of diagnostics emitted while publication was locked.
        locked: Arc<AtomicUsize>,
    }

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for PublicationLockProbe {
        fn on_event(&self, event: &tracing::Event<'_>, _ctx: tracing_subscriber::layer::Context<'_, S>) {
            if event.metadata().target().ends_with(self.diagnostic_target)
                && self.level.is_none_or(|level| *event.metadata().level() == level)
            {
                self.observations.fetch_add(1, Ordering::Relaxed);
                if let Ok(mut live) = self.target.0.try_lock() {
                    live.take();
                } else {
                    self.locked.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }

    /// A policy-filter config whose policy document is `policy_path`.
    #[cfg(any(feature = "policy-builtins", feature = "policy-crypto-default"))]
    fn policy_config(policy_path: &std::path::Path) -> Config {
        Config::from_yaml(&format!(
            r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: policy
        config_path: "{}"
      - filter: static_response
        status: 200
"#,
            policy_path.display()
        ))
        .unwrap()
    }

    /// Minimal valid config for reload tests.
    fn valid_config() -> Config {
        Config::from_yaml(
            r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#,
        )
        .unwrap()
    }

    /// [`valid_config`] with `web` as a TCP listener running a TCP-only chain.
    fn tcp_web_config() -> Config {
        Config::from_yaml(
            r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    protocol: tcp
    cluster: db_pool
    filter_chains: [tcp_lb]
clusters:
  - name: db_pool
    endpoints:
      - "10.0.0.1:5432"
insecure_options:
  allow_private_endpoints: true
  allow_private_upstreams: true
filter_chains:
  - name: tcp_lb
    filters:
      - filter: tcp_load_balancer
        clusters:
          - name: db_pool
            endpoints:
              - "10.0.0.1:5432"
"#,
        )
        .unwrap()
    }

    /// [`valid_config`] with the given `forward_proxy` body on `web`, and an
    /// `ip_acl` ahead of the static response when `with_ip_acl` is set.
    #[cfg(feature = "forward-proxy")]
    fn forward_proxy_config(forward_proxy: &str, with_ip_acl: bool) -> Config {
        let ip_acl = if with_ip_acl {
            "      - filter: ip_acl\n        allow: [\"127.0.0.0/8\"]\n"
        } else {
            ""
        };
        Config::from_yaml(&format!(
            r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
    forward_proxy:
      {forward_proxy}
filter_chains:
  - name: main
    filters:
{ip_acl}      - filter: static_response
        status: 200
"#
        ))
        .unwrap()
    }

    /// [`forward_proxy_config`] with an `ip_acl`, the block `enabled` or not,
    /// and `allow_private_upstreams` set as given.
    #[cfg(feature = "forward-proxy")]
    fn forward_proxy_config_with_private(enabled: bool, allow_private_upstreams: bool) -> Config {
        let mut config = forward_proxy_config(&format!("enabled: {enabled}"), true);
        config.insecure_options.allow_private_upstreams = allow_private_upstreams;
        config
    }

    /// Two grouped TCP listeners `db1`/`db2` with the given chains and cluster.
    ///
    /// `flip_private` toggles `allow_private_upstreams` off (it is on by
    /// default here so the private test endpoints validate).
    fn tcp_group_config(chain_a: &str, chain_b: &str, cluster: &str, flip_private: bool) -> Config {
        let allow_private_upstreams = !flip_private;
        Config::from_yaml(&format!(
            r#"
listeners:
  - name: db1
    address: "127.0.0.1:5432"
    protocol: tcp
    cluster: {cluster}
    filter_chains: [{chain_a}]
  - name: db2
    address: "127.0.0.1:5433"
    protocol: tcp
    cluster: {cluster}
    filter_chains: [{chain_b}]
clusters:
  - name: db_pool
    endpoints:
      - "10.0.0.1:5432"
  - name: db_pool_alt
    endpoints:
      - "10.0.0.2:5432"
insecure_options:
  allow_private_endpoints: true
  allow_private_upstreams: {allow_private_upstreams}
filter_chains:
  - name: tcp_lb
    filters:
      - filter: tcp_load_balancer
        clusters:
          - name: {cluster}
            endpoints:
              - "10.0.0.1:5432"
  - name: tcp_lb_alt
    filters:
      - filter: tcp_load_balancer
        clusters:
          - name: {cluster}
            endpoints:
              - "10.0.0.3:5432"
"#
        ))
        .unwrap()
    }

    /// Run [`reload_pipelines`] with empty runtime resources.
    #[expect(clippy::too_many_arguments, reason = "mirrors reload_pipelines")]
    fn reload_tcp(
        new_config: &Config,
        old_config: &Config,
        registry: &FilterRegistry,
        live: &ListenerPipelines,
        meta: &praxis_protocol::http::health::ListenerMetaStore,
        cluster_meta: &praxis_protocol::http::health::ClusterMetaStore,
        shutdown: &Arc<Mutex<CancellationToken>>,
        health_lifecycle: Option<&HealthTaskLifecycle>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        reload_pipelines(
            new_config,
            old_config,
            registry,
            live,
            meta,
            cluster_meta,
            shutdown,
            health_lifecycle,
            &empty_kv_stores(),
            &empty_session_stores(),
            &empty_slow_start_registry(),
            &empty_subrequest_client(),
            None,
            &PipelineComposition::default(),
        )
    }

    fn health_checked_config() -> Config {
        Config::from_yaml(
            r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
clusters:
  - name: backend
    endpoints: ["10.0.0.1:80", "10.0.0.2:80"]
    health_check:
      type: tcp
      interval_ms: 60000
filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: "backend"
      - filter: load_balancer
        clusters:
          - name: "backend"
            endpoints:
              - "10.0.0.1:80"
              - "10.0.0.2:80"
"#,
        )
        .unwrap()
    }

    /// Same cluster/chain as [`health_checked_config`] plus a second
    /// listener that a later reload removes from the config.
    fn health_checked_config_two_listeners() -> Config {
        Config::from_yaml(
            r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
  - name: legacy
    address: "127.0.0.1:8081"
    filter_chains: [main]
clusters:
  - name: backend
    endpoints: ["10.0.0.1:80", "10.0.0.2:80"]
    health_check:
      type: tcp
      interval_ms: 60000
filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: "backend"
      - filter: load_balancer
        clusters:
          - name: "backend"
            endpoints:
              - "10.0.0.1:80"
              - "10.0.0.2:80"
"#,
        )
        .unwrap()
    }

    /// Set up live pipelines, registry, and shutdown token for reload tests.
    fn setup_live_pipelines() -> (
        ListenerPipelines,
        Config,
        FilterRegistry,
        Arc<Mutex<CancellationToken>>,
        praxis_protocol::http::health::ListenerMetaStore,
        praxis_protocol::http::health::ClusterMetaStore,
    ) {
        setup_live_pipelines_from(valid_config())
    }

    /// Like [`setup_live_pipelines`], with the given config as the startup config.
    fn setup_live_pipelines_from(
        config: Config,
    ) -> (
        ListenerPipelines,
        Config,
        FilterRegistry,
        Arc<Mutex<CancellationToken>>,
        praxis_protocol::http::health::ListenerMetaStore,
        praxis_protocol::http::health::ClusterMetaStore,
    ) {
        let registry = FilterRegistry::with_builtins();
        let health_registry: HealthRegistry = Arc::new(HashMap::new());
        let pipelines = resolve_pipelines(
            &config,
            &registry,
            &health_registry,
            &empty_kv_stores(),
            &empty_session_stores(),
            &empty_subrequest_client(),
        )
        .unwrap();
        let shutdown = Arc::new(Mutex::new(CancellationToken::new()));
        let meta = praxis_protocol::http::health::new_listener_meta_store(
            praxis_protocol::http::health::listener_meta_from_config(&config),
        );
        let cluster_meta = praxis_protocol::http::health::new_cluster_meta_store(
            praxis_protocol::http::health::cluster_meta_from_config(&config),
        );
        (pipelines, config, registry, shutdown, meta, cluster_meta)
    }

    /// Empty KV store registry for tests without KV stores.
    fn empty_kv_stores() -> praxis_core::kv::KvStoreRegistry {
        praxis_core::kv::KvStoreRegistry::new()
    }

    /// Empty session store registry for tests.
    fn empty_session_stores() -> Arc<praxis_filter::SessionStoreRegistry> {
        Arc::new(praxis_filter::SessionStoreRegistry::new())
    }

    /// Fresh slow-start registry for reload tests.
    fn empty_slow_start_registry() -> Arc<praxis_filter::SlowStartRegistry> {
        Arc::new(praxis_filter::SlowStartRegistry::new())
    }

    /// Empty sub-request client for tests.
    fn empty_subrequest_client() -> praxis_core::subrequest::SubRequestClient {
        praxis_core::subrequest::SubRequestClient::new(crate::test_support::connector(8))
    }
}
