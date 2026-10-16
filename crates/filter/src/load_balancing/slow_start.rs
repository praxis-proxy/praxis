// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Slow-start ramp shared by the weighted load-balancing strategies.
//!
//! The registry survives config reload, so an endpoint added in a later
//! generation is ramped and an endpoint that was already present keeps the
//! clock it started with. Health transitions are applied on each selection.

#![cfg_attr(
    not(feature = "slow-start"),
    expect(
        dead_code,
        reason = "bindings and the ramp engine are installed only with the slow-start feature"
    )
)]

use std::{
    collections::{HashMap, HashSet},
    sync::{
        Arc, Mutex, MutexGuard, OnceLock, PoisonError,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use praxis_core::{
    config::{LoadBalancerStrategy, ParameterisedStrategy, SlowStartConfig},
    health::ClusterHealthState,
};
use tracing::debug;

/// Fixed-point scale so a fractional ramp still yields a positive bucket.
const WEIGHT_SCALE: u64 = 1_000_000;

/// [`WEIGHT_SCALE`] as `f64`. `1_000_000` is exactly representable.
const WEIGHT_SCALE_F64: f64 = 1_000_000.0;

/// Shared ramp tables, keyed by cluster name and endpoint set.
type RampTable = HashMap<RampKey, Arc<Mutex<ClusterRamp>>>;

// -----------------------------------------------------------------------------
// SlowStartParams
// -----------------------------------------------------------------------------

/// Ramp settings copied from [`SlowStartConfig`].
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct SlowStartParams {
    /// Duration over which weight grows from 0 to the configured weight.
    window: Duration,
    /// Curve input. `1.0` is linear.
    aggression: f64,
}

impl SlowStartParams {
    /// Build ramp settings from cluster config.
    pub(crate) fn from_config(config: SlowStartConfig) -> Self {
        Self {
            window: Duration::from_millis(config.window_ms),
            aggression: config.aggression,
        }
    }
}

// -----------------------------------------------------------------------------
// EffectiveWeights
// -----------------------------------------------------------------------------

/// Per-endpoint weight for one selection.
///
/// Values are in [`WEIGHT_SCALE`] units so a fractional ramp is still a
/// positive integer. Round robin must not use those units as contiguous
/// buckets (`slot = tick % total`): two settled endpoints at weight 1 would
/// each take a million requests in a row. While the ramp is scaling, round
/// robin uses smooth weighted round robin, which interleaves endpoints
/// instead of treating the scaled total as the bucket size.
#[derive(Clone)]
pub(crate) struct EffectiveWeights {
    /// Scaled weight keyed by endpoint address.
    ///
    /// Shared so a settled ramp can hand the same map to the next pick.
    by_address: Arc<HashMap<Arc<str>, u64>>,
    /// Use configured weights for this pick.
    ///
    /// Set when every healthy endpoint's ramp weight is still 0, so the
    /// cluster can still serve traffic.
    fallback: bool,
    /// At least one healthy endpoint is still inside its window.
    ///
    /// An idle ramp, where every endpoint is at full weight or down, is
    /// false so selection keeps the configured pickers.
    scaling: bool,
}

impl EffectiveWeights {
    /// Weight units for `address`.
    ///
    /// A fallback pick returns the configured weight. Otherwise the value is
    /// the scaled ramp weight, or 0 when the address is not ramping into this
    /// pick.
    pub(crate) fn of(&self, address: &str, configured: u32) -> u64 {
        if self.fallback {
            return u64::from(configured);
        }
        self.by_address.get(address).copied().unwrap_or(0)
    }

    /// Whether load-aware pickers should treat weight as capacity.
    ///
    /// False for a fallback pick and for an idle ramp. Both keep the
    /// configured weights.
    pub(crate) fn scales_capacity(&self) -> bool {
        self.scaling
    }

    /// Scaled weights for a test pick that does not go through the registry.
    #[cfg(test)]
    pub(crate) fn from_scaled(entries: &[(&str, u64)]) -> Self {
        Self::from_scaled_with(entries, true)
    }

    /// A snapshot whose ramp is idle, so selection keeps configured weights.
    #[cfg(test)]
    pub(crate) fn idle(entries: &[(&str, u64)]) -> Self {
        Self::from_scaled_with(entries, false)
    }

    /// Test snapshot. `scaling` is false for an idle ramp.
    #[cfg(test)]
    fn from_scaled_with(entries: &[(&str, u64)], scaling: bool) -> Self {
        let by_address = entries
            .iter()
            .map(|(address, weight)| (Arc::<str>::from(*address), *weight))
            .collect();
        Self {
            by_address: Arc::new(by_address),
            fallback: false,
            scaling,
        }
    }
}

/// Ramp weights that should change a pick, or `None` to keep configured weights.
///
/// `None` when the snapshot is missing, when every healthy endpoint is still
/// at zero, and when the ramp is idle. An idle cluster has `slow_start` set
/// and every endpoint at full weight or down, so the configured pickers run.
pub(crate) fn scaling_weights(weights: Option<&EffectiveWeights>) -> Option<&EffectiveWeights> {
    weights.filter(|weights| weights.scales_capacity())
}

/// Cost of the next request on an endpoint, compared across a pair.
///
/// `(load + 1) * configured * other_scaled`. Two endpoints at full weight
/// cancel to raw load. A small ramp stays more expensive than a busier peer
/// that has already reached its configured weight.
pub(crate) fn ramp_load_cost(load: usize, configured: u32, other_scaled: u64) -> u128 {
    let load = u128::try_from(load.saturating_add(1)).unwrap_or(u128::MAX);
    load.saturating_mul(u128::from(configured))
        .saturating_mul(u128::from(other_scaled))
}

/// Snapshot for `cluster` when one of `bindings` ramps it.
pub(crate) fn weights_for(
    bindings: &[SlowStartBinding],
    cluster: &str,
    health: Option<&ClusterHealthState>,
) -> Option<EffectiveWeights> {
    bindings
        .iter()
        .find(|binding| binding.cluster_name() == cluster)
        .map(|binding| binding.snapshot(None, health))
}

/// Weight units for one endpoint, using the ramp when one is active.
pub(crate) fn endpoint_weight(address: &str, configured: u32, weights: Option<&EffectiveWeights>) -> u64 {
    match weights {
        Some(weights) => weights.of(address, configured),
        None => u64::from(configured),
    }
}

// -----------------------------------------------------------------------------
// Strategy gate
// -----------------------------------------------------------------------------

/// Whether this strategy consumes the ramped weight.
///
/// Hash strategies keep the configured weight so the ring stays put while a
/// ramp moves.
pub(crate) fn strategy_ramps(strategy: &LoadBalancerStrategy) -> bool {
    match strategy {
        LoadBalancerStrategy::Simple(_) => true,
        LoadBalancerStrategy::Parameterised(inner) => parameterised_ramps(inner),
    }
}

/// Whether a parameterised strategy consumes the ramped weight.
fn parameterised_ramps(strategy: &ParameterisedStrategy) -> bool {
    match strategy {
        ParameterisedStrategy::ConsistentHash(_)
        | ParameterisedStrategy::Maglev(_)
        | ParameterisedStrategy::RingHash(_) => false,
        ParameterisedStrategy::Subset(_) | ParameterisedStrategy::ZoneAware(_) | ParameterisedStrategy::Priority(_) => {
            true
        },
    }
}

// -----------------------------------------------------------------------------
// Registry
// -----------------------------------------------------------------------------

/// Where a manual test clock is, or the live clock.
enum Clock {
    /// [`Instant::now`] on every read.
    System,
    /// Frozen instant tests advance explicitly.
    #[cfg(test)]
    Manual(Instant),
}

/// Process-lived ramp state for every cluster that has slow start enabled.
///
/// One registry is shared across config reloads. The membership present when
/// `slow_start` is first enabled for a cluster name is the baseline and stays
/// at full weight. Addresses that appear in a later build, and endpoints that
/// return from unhealthy, start a window.
///
/// The table key is the cluster name, the endpoint set, and the ramp settings.
/// Two live bindings that share a name but differ in addresses or settings keep
/// separate ramps, so one binding cannot drop the other's endpoints or rewrite
/// its window. A later build copies clocks only from tables the previous
/// installed build claimed, including while that build's pipeline is still held.
pub struct SlowStartRegistry {
    /// Ramp table per cluster name, endpoint set, and ramp settings.
    clusters: Mutex<RampTable>,
    /// Clock used to measure windows.
    clock: Mutex<Clock>,
    /// Bumped once per pipeline build so idle tables from older configs can be dropped.
    generation: AtomicU64,
    /// Generation of the last finished pipeline build. `0` means none yet.
    ///
    /// Clock inheritance reads this, not [`generation`](Self::generation), so a
    /// table opened earlier in the current build is not history.
    installed: AtomicU64,
}

impl SlowStartRegistry {
    /// Registry that measures windows with [`Instant::now`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            clusters: Mutex::new(HashMap::new()),
            clock: Mutex::new(Clock::System),
            generation: AtomicU64::new(0),
            installed: AtomicU64::new(0),
        }
    }

    /// Start a pipeline build. Tables bound before the matching [`end_generation`](Self::end_generation)
    /// and no longer held are removed.
    fn begin_generation(&self) {
        self.generation.fetch_add(1, Ordering::AcqRel);
    }

    /// Drop idle tables this build did not leave held.
    ///
    /// A table an in-flight pipeline still holds, and that this build did not
    /// claim, is marked retired and removed when that pipeline drops it.
    fn end_generation(&self) {
        let current = self.generation.load(Ordering::Acquire);
        let mut clusters = lock_map(&self.clusters);
        clusters.retain(|_, ramp| {
            let mut guard = lock_ramp(ramp);
            if guard.holders == 0 {
                return false;
            }
            if guard.generation == current {
                guard.origin = Some(current);
            } else {
                guard.retired = true;
            }
            true
        });
        drop(clusters);
        self.installed.store(current, Ordering::Release);
    }

    /// Start a pipeline build.
    ///
    /// [`SlowStartGeneration::commit`] publishes the build. Dropping the guard
    /// without committing leaves the installed build unchanged.
    pub fn enter_generation(&self) -> SlowStartGeneration<'_> {
        self.begin_generation();
        SlowStartGeneration {
            registry: self,
            committed: false,
        }
    }

    /// Drop tables this abandoned build created. Installed history stays as it was.
    fn abort_generation(&self) {
        let current = self.generation.load(Ordering::Acquire);
        let mut clusters = lock_map(&self.clusters);
        clusters.retain(|_, ramp| {
            let mut guard = lock_ramp(ramp);
            let unpublished = guard.generation == current && guard.origin.is_none();
            if !unpublished {
                return true;
            }
            if guard.holders == 0 {
                return false;
            }
            guard.retired = true;
            true
        });
        drop(clusters);
    }

    /// Whether `name` has a live table whose endpoints are all at full weight.
    ///
    /// Pipeline install records that baseline before the first request. The
    /// example test uses this to tell a configured ramp from a config that
    /// omitted `slow_start`.
    #[must_use]
    pub fn baseline_seeded(&self, name: &str) -> bool {
        let clusters = lock_map(&self.clusters);
        clusters.iter().any(|(key, ramp)| {
            if key.name.as_ref() != name {
                return false;
            }
            let guard = lock_ramp(ramp);
            guard.holders > 0 && guard.seeded && guard.endpoints.values().all(|entry| entry.started_at.is_none())
        })
    }

    /// Ramp for this binding.
    ///
    /// An exact key reuses that table. Otherwise clocks are copied from the
    /// best same-name predecessor, or the endpoints are seeded as the baseline
    /// when this name has not been seen.
    fn attach(
        &self,
        name: &Arc<str>,
        params: SlowStartParams,
        endpoints: &[(Arc<str>, u32)],
    ) -> (RampKey, Arc<Mutex<ClusterRamp>>) {
        let key = RampKey::from_endpoints(name, endpoints, params);
        let now = self.now();
        let generation = self.generation.load(Ordering::Acquire);
        let installed = self.installed.load(Ordering::Acquire);
        let mut clusters = lock_map(&self.clusters);
        if let Some(existing) = clusters.get(&key)
            && claims_existing(existing, installed, generation)
        {
            let claimed = claim(existing, params, generation);
            drop(clusters);
            return (key, claimed);
        }
        let ramp = match best_predecessor(&clusters, name, endpoints, installed) {
            Some(previous) => fork_ramp(previous, params, endpoints, now),
            None => fresh_ramp(params, endpoints),
        };
        let claimed = claim(&ramp, params, generation);
        clusters.insert(key.clone(), Arc::clone(&claimed));
        drop_idle_except(&mut clusters, name, &key);
        drop(clusters);
        (key, claimed)
    }

    /// Instant used for the current selection.
    pub(crate) fn now(&self) -> Instant {
        match *lock_clock(&self.clock) {
            Clock::System => Instant::now(),
            #[cfg(test)]
            Clock::Manual(instant) => instant,
        }
    }

    /// Freeze the clock at `instant`.
    #[cfg(test)]
    pub(crate) fn pin(&self, instant: Instant) {
        *lock_clock(&self.clock) = Clock::Manual(instant);
    }

    /// Move a frozen clock forward.
    #[cfg(test)]
    pub(crate) fn advance(&self, by: Duration) {
        let mut clock = lock_clock(&self.clock);
        let Clock::Manual(instant) = *clock else {
            return;
        };
        *clock = Clock::Manual(instant + by);
    }
}

impl Default for SlowStartRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Recover a poisoned map lock. The ramp data is still the last consistent write.
fn lock_map(clusters: &Mutex<RampTable>) -> MutexGuard<'_, RampTable> {
    clusters.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Recover a poisoned ramp lock.
fn lock_ramp(ramp: &Mutex<ClusterRamp>) -> MutexGuard<'_, ClusterRamp> {
    ramp.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Recover a poisoned clock lock.
fn lock_clock(clock: &Mutex<Clock>) -> MutexGuard<'_, Clock> {
    clock.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Registry key: cluster name, endpoint set, and the ramp settings.
///
/// Settings are part of the key so two bindings that list the same addresses
/// with different windows do not overwrite each other's curve.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
struct RampKey {
    /// Cluster name.
    name: Arc<str>,
    /// Addresses, sorted so order in the config does not change the key.
    endpoints: Vec<Arc<str>>,
    /// Window length in milliseconds.
    window_ms: u64,
    /// [`f64::to_bits`] of the aggression, so the key can be hashed.
    aggression_bits: u64,
}

impl RampKey {
    /// Key for `name`, the addresses in `endpoints`, and `params`.
    fn from_endpoints(name: &Arc<str>, endpoints: &[(Arc<str>, u32)], params: SlowStartParams) -> Self {
        let mut addresses: Vec<Arc<str>> = endpoints.iter().map(|(address, _)| Arc::clone(address)).collect();
        addresses.sort();
        addresses.dedup();
        Self {
            name: Arc::clone(name),
            endpoints: addresses,
            window_ms: u64::try_from(params.window.as_millis()).unwrap_or(u64::MAX),
            aggression_bits: params.aggression.to_bits(),
        }
    }
}

/// Record one binding on `ramp` and apply `params`.
fn claim(ramp: &Arc<Mutex<ClusterRamp>>, params: SlowStartParams, generation: u64) -> Arc<Mutex<ClusterRamp>> {
    let mut guard = lock_ramp(ramp);
    guard.params = params;
    guard.holders = guard.holders.saturating_add(1);
    guard.generation = generation;
    guard.retired = false;
    guard.settled = None;
    drop(guard);
    Arc::clone(ramp)
}

/// Predecessor to copy clocks from, if this name was already observed.
///
/// A live table with no addresses in common is a different membership that is
/// still in use, so it is not this binding's history. An idle table from the
/// installed build is the previous generation, including one whose addresses
/// were all replaced. A retired table, and a table opened earlier in this
/// build, are not history. Ties use the sorted address list so the choice
/// does not follow map order.
fn best_predecessor<'a>(
    clusters: &'a RampTable,
    name: &str,
    endpoints: &[(Arc<str>, u32)],
    installed: u64,
) -> Option<&'a Arc<Mutex<ClusterRamp>>> {
    if installed == 0 {
        return None;
    }
    let wanted: HashSet<&str> = endpoints.iter().map(|(address, _)| address.as_ref()).collect();
    let mut best: Option<Predecessor<'a>> = None;
    for (key, ramp) in clusters {
        if key.name.as_ref() != name || !from_installed_build(ramp, installed) {
            continue;
        }
        let overlap = shared_addresses(&key.endpoints, &wanted);
        if overlap == 0 && lock_ramp(ramp).holders > 0 {
            continue;
        }
        if best
            .as_ref()
            .is_none_or(|current| beats(current, overlap, &key.endpoints))
        {
            best = Some(Predecessor {
                endpoints: key.endpoints.as_slice(),
                ramp,
                overlap,
            });
        }
    }
    best.map(|found| found.ramp)
}

/// Whether `ramp` was claimed by the build recorded in `installed`.
fn from_installed_build(ramp: &Arc<Mutex<ClusterRamp>>, installed: u64) -> bool {
    lock_ramp(ramp).origin == Some(installed)
}

/// Whether an exact key should keep this table's clocks.
///
/// A retired table still held by a draining pipeline keeps its old clocks, so
/// reclaiming it would bring a removed endpoint back at full weight. A table
/// claimed earlier in this build is the same membership, and is shared.
fn claims_existing(ramp: &Arc<Mutex<ClusterRamp>>, installed: u64, generation: u64) -> bool {
    let guard = lock_ramp(ramp);
    if guard.retired {
        return false;
    }
    (installed != 0 && guard.origin == Some(installed)) || guard.generation == generation
}

/// How many of `addresses` are in `wanted`.
fn shared_addresses(addresses: &[Arc<str>], wanted: &HashSet<&str>) -> usize {
    addresses
        .iter()
        .filter(|address| wanted.contains(address.as_ref()))
        .count()
}

/// Whether `overlap` and `endpoints` should replace `current`.
fn beats(current: &Predecessor<'_>, overlap: usize, endpoints: &[Arc<str>]) -> bool {
    overlap > current.overlap || (overlap == current.overlap && endpoints < current.endpoints)
}

/// One candidate table to copy clocks from.
struct Predecessor<'a> {
    /// Sorted addresses, used to break ties.
    endpoints: &'a [Arc<str>],
    /// Table those addresses belong to.
    ramp: &'a Arc<Mutex<ClusterRamp>>,
    /// How many of the new binding's addresses this table already has.
    overlap: usize,
}

/// Copy `previous` clocks into a new table for `endpoints`.
///
/// Addresses already on `previous` keep their clock. An address `previous`
/// does not have starts a window now. `previous` itself is left unchanged,
/// so a pipeline that still holds it cannot drop this binding's endpoints.
fn fork_ramp(
    previous: &Arc<Mutex<ClusterRamp>>,
    params: SlowStartParams,
    endpoints: &[(Arc<str>, u32)],
    now: Instant,
) -> Arc<Mutex<ClusterRamp>> {
    let previous = lock_ramp(previous);
    let mut ramp = ClusterRamp::new(params);
    ramp.seeded = true;
    for (address, _) in endpoints {
        let entry = match previous.endpoints.get(address) {
            Some(existing) => existing.clone(),
            None => EndpointRamp {
                started_at: Some(now),
                healthy: true,
            },
        };
        ramp.endpoints.insert(Arc::clone(address), entry);
    }
    drop(previous);
    Arc::new(Mutex::new(ramp))
}

/// First observation of this name: every current endpoint is the baseline.
fn fresh_ramp(params: SlowStartParams, endpoints: &[(Arc<str>, u32)]) -> Arc<Mutex<ClusterRamp>> {
    let mut ramp = ClusterRamp::new(params);
    ramp.seed(endpoints, None);
    Arc::new(Mutex::new(ramp))
}

/// Remove idle tables for `name` other than `keep`.
fn drop_idle_except(clusters: &mut RampTable, name: &str, keep: &RampKey) {
    clusters.retain(|key, ramp| key.name.as_ref() != name || key == keep || lock_ramp(ramp).holders > 0);
}

// -----------------------------------------------------------------------------
// Binding
// -----------------------------------------------------------------------------

/// One cluster generation's slow-start inputs, sharing the registry's table.
pub(crate) struct SlowStartBinding {
    /// Cluster name. Combined with the endpoint set and settings, this is the registry key.
    cluster: Arc<str>,
    /// Ramp settings from this generation's config.
    params: SlowStartParams,
    /// Endpoint address and configured weight.
    endpoints: Vec<(Arc<str>, u32)>,
    /// Registry this binding attached to, when one was supplied.
    registry: OnceLock<Arc<SlowStartRegistry>>,
    /// Key of [`ramp`](Self::ramp) in the registry.
    key: OnceLock<RampKey>,
    /// Table filled when the binding attaches, shared across reloads via the registry.
    ramp: OnceLock<Arc<Mutex<ClusterRamp>>>,
}

impl SlowStartBinding {
    /// Binding for `cluster` and its current endpoints.
    pub(crate) fn new(cluster: Arc<str>, params: SlowStartParams, endpoints: Vec<(Arc<str>, u32)>) -> Self {
        Self {
            cluster,
            params,
            endpoints,
            registry: OnceLock::new(),
            key: OnceLock::new(),
            ramp: OnceLock::new(),
        }
    }

    /// Cluster this binding ramps.
    pub(crate) fn cluster_name(&self) -> &str {
        &self.cluster
    }

    /// Attach to `registry` now, so the baseline is recorded before the first request.
    ///
    /// Fills this binding's locks in place. Callers keep the binding in a
    /// plain list and share it across requests without a second mutex.
    pub(crate) fn open(&self, registry: &Arc<SlowStartRegistry>) {
        drop(self.registry.set(Arc::clone(registry)));
        drop(self.ramp_handle(Some(registry)));
    }

    /// Attach and hand the binding back. Tests keep the value they opened.
    #[cfg(test)]
    fn opened(self, registry: &Arc<SlowStartRegistry>) -> Self {
        self.open(registry);
        self
    }

    /// Weights for this pick, updating membership and health on the shared table.
    ///
    /// Once every endpoint is at full weight or down, later picks with the
    /// same addresses, weights, health, and ramp settings reuse that result
    /// and skip membership reconciliation.
    pub(crate) fn snapshot(
        &self,
        registry: Option<&SlowStartRegistry>,
        health: Option<&ClusterHealthState>,
    ) -> EffectiveWeights {
        let ramp = self.ramp_handle(registry);
        let now = registry.map_or_else(Instant::now, SlowStartRegistry::now);
        let mut guard = lock_ramp(&ramp);
        guard.params = self.params;
        guard.weights(&self.endpoints, health, now)
    }

    /// Table for this cluster, private when no registry was installed.
    fn ramp_handle(&self, registry: Option<&SlowStartRegistry>) -> Arc<Mutex<ClusterRamp>> {
        let ramp = self.ramp.get_or_init(|| match registry {
            Some(registry) => {
                let (key, attached) = registry.attach(&self.cluster, self.params, &self.endpoints);
                drop(self.key.set(key));
                attached
            },
            None => fresh_ramp(self.params, &self.endpoints),
        });
        Arc::clone(ramp)
    }
}

/// RAII scope for one pipeline build.
///
/// [`commit`](Self::commit) publishes the build as installed history. Dropping
/// the guard without committing leaves that history unchanged, so a failed
/// reload cannot retire tables the live pipelines still hold.
pub struct SlowStartGeneration<'a> {
    /// Registry whose generation this scope opened.
    registry: &'a SlowStartRegistry,
    /// Set once [`commit`](Self::commit) has published this build.
    committed: bool,
}

impl SlowStartGeneration<'_> {
    /// Publish this build. Tables it claimed become history; other held tables retire.
    pub fn commit(mut self) {
        self.committed = true;
        self.registry.end_generation();
    }
}

impl Drop for SlowStartGeneration<'_> {
    fn drop(&mut self) {
        if !self.committed {
            self.registry.abort_generation();
        }
    }
}

/// Binding for `cluster` when it configures a strategy that consumes the ramp.
#[cfg(feature = "slow-start")]
pub(crate) fn binding_for_cluster(cluster: &praxis_core::config::Cluster) -> Option<SlowStartBinding> {
    let config = cluster.slow_start?;
    if !strategy_ramps(&cluster.load_balancer_strategy) {
        return None;
    }
    let endpoints: Vec<(Arc<str>, u32)> = crate::load_balancing::endpoint::build_weighted_endpoints(cluster)
        .into_iter()
        .map(|endpoint| (endpoint.address, endpoint.weight))
        .collect();
    if endpoints.is_empty() {
        return None;
    }
    Some(SlowStartBinding::new(
        Arc::clone(&cluster.name),
        SlowStartParams::from_config(config),
        endpoints,
    ))
}

impl Drop for SlowStartBinding {
    /// Release this binding's hold. A retired table with no holders left is removed.
    fn drop(&mut self) {
        let Some(ramp) = self.ramp.get() else {
            return;
        };
        let mut guard = lock_ramp(ramp);
        guard.holders = guard.holders.saturating_sub(1);
        let remove = guard.holders == 0 && guard.retired;
        drop(guard);
        if remove
            && let Some(registry) = self.registry.get()
            && let Some(key) = self.key.get()
        {
            let mut clusters = lock_map(&registry.clusters);
            if clusters.get(key).is_some_and(|current| Arc::ptr_eq(current, ramp)) {
                clusters.remove(key);
            }
        }
    }
}

// -----------------------------------------------------------------------------
// ClusterRamp
// -----------------------------------------------------------------------------

/// Per-endpoint ramp clock for one cluster.
struct ClusterRamp {
    /// Current window and curve.
    params: SlowStartParams,
    /// Live bindings using this table.
    holders: u32,
    /// Pipeline-build generation that last claimed this table.
    generation: u64,
    /// Build that published this table as history. `None` until that build finishes.
    origin: Option<u64>,
    /// In-flight table whose cluster left the latest config. Removed once holders hit zero.
    retired: bool,
    /// Whether the baseline membership has been recorded.
    seeded: bool,
    /// Ramp state keyed by endpoint address.
    endpoints: HashMap<Arc<str>, EndpointRamp>,
    /// Last pick, kept once no endpoint is mid-window.
    settled: Option<SettledPick>,
}

/// A pick that can be reused while membership, health, and settings stay put.
struct SettledPick {
    /// Addresses, configured weights, and health from the cached pick.
    observed: Vec<(Arc<str>, u32, bool)>,
    /// Settings that produced [`weights`](Self::weights).
    params: SlowStartParams,
    /// Cached result.
    weights: EffectiveWeights,
}

/// One endpoint's place on the ramp.
#[derive(Clone)]
struct EndpointRamp {
    /// When the current window started. `None` means full weight.
    started_at: Option<Instant>,
    /// Last observed health. A rising edge restarts the window.
    healthy: bool,
}

impl ClusterRamp {
    /// Empty table. Attach seeds it before the first snapshot.
    fn new(params: SlowStartParams) -> Self {
        Self {
            params,
            holders: 0,
            generation: 0,
            origin: None,
            retired: false,
            seeded: false,
            endpoints: HashMap::new(),
            settled: None,
        }
    }

    /// Reconcile membership and health, then return this pick's weights.
    ///
    /// A settled ramp returns the previous pick when the inputs match, and
    /// does not scan membership or build a new map.
    fn weights(
        &mut self,
        endpoints: &[(Arc<str>, u32)],
        health: Option<&ClusterHealthState>,
        now: Instant,
    ) -> EffectiveWeights {
        if let Some(settled) = &self.settled
            && settled.matches(self.params, endpoints, health)
        {
            return settled.weights.clone();
        }
        self.settled = None;
        self.reconcile(endpoints, health, now);
        let weights = self.scaled_weights(endpoints, now);
        if self.ramp_is_idle(endpoints) {
            self.settled = Some(SettledPick::capture(self.params, endpoints, health, weights.clone()));
        }
        weights
    }

    /// Whether every current endpoint is at full weight or down.
    fn ramp_is_idle(&self, endpoints: &[(Arc<str>, u32)]) -> bool {
        endpoints.iter().all(|(address, _)| {
            self.endpoints
                .get(address)
                .is_some_and(|entry| entry.started_at.is_none())
        })
    }

    /// Record new and removed addresses, then apply health edges.
    fn reconcile(&mut self, endpoints: &[(Arc<str>, u32)], health: Option<&ClusterHealthState>, now: Instant) {
        if self.seeded {
            self.admit_new(endpoints, health, now);
            self.drop_removed(endpoints);
        } else {
            self.seed(endpoints, health);
        }
        self.track_health(endpoints, health, now);
    }

    /// First observation: every current endpoint is already in service.
    fn seed(&mut self, endpoints: &[(Arc<str>, u32)], health: Option<&ClusterHealthState>) {
        for (address, _) in endpoints {
            let healthy = address_healthy(health, address);
            self.endpoints.insert(
                Arc::clone(address),
                EndpointRamp {
                    started_at: None,
                    healthy,
                },
            );
        }
        self.seeded = true;
    }

    /// Addresses that were not in the baseline or the previous generation.
    fn admit_new(&mut self, endpoints: &[(Arc<str>, u32)], health: Option<&ClusterHealthState>, now: Instant) {
        for (address, _) in endpoints {
            self.admit_one(address, health, now);
        }
    }

    /// Start a window for a healthy address the table has not seen.
    fn admit_one(&mut self, address: &Arc<str>, health: Option<&ClusterHealthState>, now: Instant) {
        if self.endpoints.contains_key(address) {
            return;
        }
        let healthy = address_healthy(health, address);
        let started_at = healthy.then_some(now);
        self.endpoints
            .insert(Arc::clone(address), EndpointRamp { started_at, healthy });
        if healthy {
            debug!(endpoint = %address, "endpoint entered slow start");
        }
    }

    /// Drop addresses that left the cluster.
    fn drop_removed(&mut self, endpoints: &[(Arc<str>, u32)]) {
        let present: HashSet<&str> = endpoints.iter().map(|(address, _)| address.as_ref()).collect();
        self.endpoints.retain(|address, _| present.contains(address.as_ref()));
    }

    /// Restart the window on recovery and clear it while an endpoint is down.
    fn track_health(&mut self, endpoints: &[(Arc<str>, u32)], health: Option<&ClusterHealthState>, now: Instant) {
        for (address, _) in endpoints {
            self.observe(address, address_healthy(health, address), now);
        }
    }

    /// Apply one endpoint's health edge.
    fn observe(&mut self, address: &Arc<str>, healthy: bool, now: Instant) {
        let Some(entry) = self.endpoints.get_mut(address) else {
            return;
        };
        if !healthy {
            entry.healthy = false;
            entry.started_at = None;
            return;
        }
        if !entry.healthy {
            entry.healthy = true;
            entry.started_at = Some(now);
            debug!(endpoint = %address, "endpoint entered slow start");
            return;
        }
        if entry.finished(now, self.params) {
            entry.started_at = None;
        }
    }

    /// Scaled weights, falling back to configured weights when every healthy
    /// endpoint is still at zero.
    fn scaled_weights(&self, endpoints: &[(Arc<str>, u32)], now: Instant) -> EffectiveWeights {
        let mut by_address = HashMap::with_capacity(endpoints.len());
        let mut healthy_total = 0_u64;
        for (address, configured) in endpoints {
            let weight = self.endpoint_weight(address, *configured, now);
            healthy_total = add_if_healthy(&self.endpoints, address, weight, healthy_total);
            by_address.insert(Arc::clone(address), weight);
        }
        let idle = self.ramp_is_idle(endpoints);
        EffectiveWeights {
            by_address: Arc::new(by_address),
            fallback: healthy_total == 0,
            scaling: !idle && healthy_total > 0,
        }
    }

    /// Scaled weight for one address.
    fn endpoint_weight(&self, address: &Arc<str>, configured: u32, now: Instant) -> u64 {
        let Some(entry) = self.endpoints.get(address) else {
            return 0;
        };
        scaled_weight(entry, configured, now, self.params)
    }
}

impl SettledPick {
    /// Remember a pick whose ramp clocks are idle.
    fn capture(
        params: SlowStartParams,
        endpoints: &[(Arc<str>, u32)],
        health: Option<&ClusterHealthState>,
        weights: EffectiveWeights,
    ) -> Self {
        let observed = endpoints
            .iter()
            .map(|(address, weight)| (Arc::clone(address), *weight, address_healthy(health, address)))
            .collect();
        Self {
            observed,
            params,
            weights,
        }
    }

    /// Whether this pick is still the one `endpoints` and `health` would produce.
    fn matches(
        &self,
        params: SlowStartParams,
        endpoints: &[(Arc<str>, u32)],
        health: Option<&ClusterHealthState>,
    ) -> bool {
        if self.params != params || self.observed.len() != endpoints.len() {
            return false;
        }
        self.observed
            .iter()
            .zip(endpoints)
            .all(|((address, weight, was_healthy), (next_address, next_weight))| {
                address.as_ref() == next_address.as_ref()
                    && *weight == *next_weight
                    && *was_healthy == address_healthy(health, next_address)
            })
    }
}

/// Add `weight` when the endpoint is currently healthy.
fn add_if_healthy(endpoints: &HashMap<Arc<str>, EndpointRamp>, address: &Arc<str>, weight: u64, total: u64) -> u64 {
    let healthy = endpoints.get(address).is_some_and(|entry| entry.healthy);
    if healthy { total.saturating_add(weight) } else { total }
}

/// Scaled weight from one endpoint's ramp state.
fn scaled_weight(entry: &EndpointRamp, configured: u32, now: Instant, params: SlowStartParams) -> u64 {
    if !entry.healthy {
        return 0;
    }
    let factor = entry
        .started_at
        .map_or(1.0, |started| ramp_factor(started, now, params));
    scale(configured, factor)
}

impl EndpointRamp {
    /// Whether the window that started at [`started_at`](Self::started_at) has elapsed.
    fn finished(&self, now: Instant, params: SlowStartParams) -> bool {
        self.started_at
            .is_some_and(|started| now.saturating_duration_since(started) >= params.window)
    }
}

/// `time_factor ^ (1 / aggression)`, clamped to `[0, 1]`.
fn ramp_factor(started: Instant, now: Instant, params: SlowStartParams) -> f64 {
    let elapsed = now.saturating_duration_since(started);
    if elapsed >= params.window {
        return 1.0;
    }
    let window_secs = params.window.as_secs_f64();
    if window_secs <= 0.0 {
        return 1.0;
    }
    let time_factor = elapsed.as_secs_f64() / window_secs;
    if time_factor <= 0.0 || !params.aggression.is_finite() || params.aggression <= 0.0 {
        return 0.0;
    }
    let factor = time_factor.powf(1.0 / params.aggression);
    if factor.is_finite() { factor } else { 0.0 }
}

/// `configured * factor`, in [`WEIGHT_SCALE`] units.
fn scale(configured: u32, factor: f64) -> u64 {
    if !factor.is_finite() || factor <= 0.0 {
        return 0;
    }
    if factor >= 1.0 {
        return u64::from(configured).saturating_mul(WEIGHT_SCALE);
    }
    round_nonnegative(f64::from(configured) * factor * WEIGHT_SCALE_F64)
}

/// Nearest non-negative integer, or 0 when `value` is not a usable weight.
fn round_nonnegative(value: f64) -> u64 {
    if !value.is_finite() || value <= 0.0 {
        return 0;
    }
    let rounded = value.round();
    if rounded >= 9_007_199_254_740_992.0 {
        return u64::MAX;
    }
    #[expect(clippy::cast_possible_truncation, reason = "rounded is finite and below 2^53")]
    #[expect(clippy::cast_sign_loss, reason = "rounded is non-negative")]
    let units = rounded as u64;
    units
}

/// Health of `address`, treating a missing registry as healthy.
fn address_healthy(health: Option<&ClusterHealthState>, address: &str) -> bool {
    health.is_none_or(|state| state.is_address_healthy(address))
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
    clippy::panic,
    clippy::too_many_lines,
    clippy::float_cmp,
    reason = "tests"
)]
mod tests {
    use praxis_core::{
        config::SimpleStrategy,
        health::{ClusterHealthEntry, EndpointHealth},
    };

    use super::*;

    fn params(window_ms: u64, aggression: f64) -> SlowStartParams {
        SlowStartParams::from_config(SlowStartConfig { window_ms, aggression })
    }

    fn close(actual: f64, expected: f64) {
        let delta = (actual - expected).abs();
        assert!(delta < 0.000_001, "factor {actual} should be near {expected}");
    }

    #[test]
    fn linear_ramp_is_the_fraction_of_the_window() {
        let settings = params(1_000, 1.0);
        let started = Instant::now();
        close(
            ramp_factor(started, started + Duration::from_millis(250), settings),
            0.25,
        );
        close(
            ramp_factor(started, started + Duration::from_millis(1_000), settings),
            1.0,
        );
    }

    #[test]
    fn aggression_bends_the_curve() {
        let started = Instant::now();
        let at = started + Duration::from_millis(250);
        close(ramp_factor(started, at, params(1_000, 2.0)), 0.5);
        close(ramp_factor(started, at, params(1_000, 0.5)), 0.0625);
    }

    #[test]
    fn half_factor_is_half_the_scaled_weight() {
        assert_eq!(
            scale(1, 0.5),
            WEIGHT_SCALE / 2,
            "weight 1 at halfway should be half scale"
        );
        assert_eq!(scale(4, 0.0), 0, "the origin of the curve is zero weight");
    }

    #[test]
    fn a_settled_snapshot_is_not_scaling() {
        let registry = Arc::new(SlowStartRegistry::new());
        registry.pin(Instant::now());
        let started = registry.enter_generation();
        let binding = binding(&["10.0.0.1:80", "10.0.0.2:80"]).opened(&registry);
        started.commit();
        let weights = binding.snapshot(Some(&registry), None);
        assert!(
            scaling_weights(Some(&weights)).is_none(),
            "an idle ramp keeps the configured pickers"
        );
    }

    #[test]
    fn baseline_endpoints_stay_at_full_weight() {
        let registry = SlowStartRegistry::new();
        let now = Instant::now();
        registry.pin(now);
        let binding = binding(&["10.0.0.1:80", "10.0.0.2:80"]);
        let weights = binding.snapshot(Some(&registry), None);
        assert_eq!(
            weights.of("10.0.0.1:80", 1),
            WEIGHT_SCALE,
            "baseline endpoint stays at full weight"
        );
        assert_eq!(
            weights.of("10.0.0.2:80", 1),
            WEIGHT_SCALE,
            "second baseline endpoint stays at full weight"
        );
    }

    #[test]
    fn added_endpoint_ramps_while_the_previous_binding_is_still_held() {
        let registry = Arc::new(SlowStartRegistry::new());
        registry.pin(Instant::now());
        registry.begin_generation();
        let first = binding(&["10.0.0.1:80"]).opened(&registry);
        registry.end_generation();
        registry.begin_generation();
        let second = binding(&["10.0.0.1:80", "10.0.0.2:80"]).opened(&registry);
        let added = second.snapshot(Some(&registry), None);
        assert_eq!(
            added.of("10.0.0.1:80", 1),
            WEIGHT_SCALE,
            "the endpoint that was already in the cluster stays at full weight"
        );
        assert_eq!(
            added.of("10.0.0.2:80", 1),
            0,
            "an endpoint added while the old binding is alive starts a window"
        );
        let original = first.snapshot(Some(&registry), None);
        assert_eq!(
            original.of("10.0.0.1:80", 1),
            WEIGHT_SCALE,
            "the old binding keeps its own table"
        );
    }

    #[test]
    fn different_windows_keep_separate_clocks() {
        let registry = Arc::new(SlowStartRegistry::new());
        registry.pin(Instant::now());
        registry.begin_generation();
        let origin = binding(&["10.0.0.1:80"]).opened(&registry);
        registry.end_generation();
        registry.begin_generation();
        let long = SlowStartBinding::new(
            Arc::from("backend"),
            params(30_000, 1.0),
            vec![(Arc::from("10.0.0.1:80"), 1), (Arc::from("10.0.0.2:80"), 1)],
        )
        .opened(&registry);
        let short = SlowStartBinding::new(
            Arc::from("backend"),
            params(1, 1.0),
            vec![(Arc::from("10.0.0.1:80"), 1), (Arc::from("10.0.0.2:80"), 1)],
        )
        .opened(&registry);
        registry.advance(Duration::from_millis(1));
        assert_eq!(
            short.snapshot(Some(&registry), None).of("10.0.0.2:80", 1),
            WEIGHT_SCALE,
            "the one-millisecond window is already finished"
        );
        let long_weight = long.snapshot(Some(&registry), None).of("10.0.0.2:80", 1);
        assert!(
            long_weight < WEIGHT_SCALE / 100,
            "the thirty-second window is still at the start, got {long_weight}"
        );
        drop(origin);
    }

    #[test]
    fn an_abandoned_generation_keeps_the_installed_build() {
        let registry = Arc::new(SlowStartRegistry::new());
        registry.pin(Instant::now());
        let started = registry.enter_generation();
        let live = binding(&["10.0.0.1:80", "10.0.0.2:80"]).opened(&registry);
        started.commit();
        let installed = registry.installed.load(Ordering::Acquire);

        let abandoned = registry.enter_generation();
        let failed = binding(&["10.0.0.1:80", "10.0.0.3:80"]).opened(&registry);
        drop(failed);
        drop(abandoned);

        assert_eq!(
            registry.installed.load(Ordering::Acquire),
            installed,
            "a build that is not committed does not become history"
        );
        let weights = live.snapshot(Some(&registry), None);
        assert_eq!(
            weights.of("10.0.0.2:80", 1),
            WEIGHT_SCALE,
            "the installed build stays at full weight"
        );

        let next = registry.enter_generation();
        let added = binding(&["10.0.0.1:80", "10.0.0.2:80", "10.0.0.4:80"]).opened(&registry);
        next.commit();
        let weights = added.snapshot(Some(&registry), None);
        assert_eq!(
            weights.of("10.0.0.2:80", 1),
            WEIGHT_SCALE,
            "clocks survive a failed build"
        );
        assert_eq!(
            weights.of("10.0.0.4:80", 1),
            0,
            "the endpoint added by the successful build ramps"
        );
    }

    #[test]
    fn round_robin_uses_the_ramp_for_a_newly_added_endpoint() {
        use crate::load_balancing::{endpoint::WeightedEndpoint, round_robin::RoundRobin};

        let registry = Arc::new(SlowStartRegistry::new());
        registry.pin(Instant::now());
        let started = registry.enter_generation();
        let baseline = binding(&["10.0.0.1:80"]).opened(&registry);
        started.commit();
        let next = registry.enter_generation();
        let added = binding(&["10.0.0.1:80", "10.0.0.2:80"]).opened(&registry);
        next.commit();
        let weights = added.snapshot(Some(&registry), None);
        let rr = RoundRobin::new(vec![
            WeightedEndpoint::simple(Arc::from("10.0.0.1:80"), 1),
            WeightedEndpoint::simple(Arc::from("10.0.0.2:80"), 1),
        ]);
        for _ in 0..4 {
            let picked = rr
                .select_weighted(None, &[], Some(&weights))
                .expect("the baseline endpoint is at full weight");
            assert_eq!(&*picked, "10.0.0.1:80", "a just-added endpoint stays out of rotation");
        }
        registry.advance(Duration::from_millis(30_000));
        let settled = added.snapshot(Some(&registry), None);
        let mut seen_new = false;
        for _ in 0..4 {
            let picked = rr.select_weighted(None, &[], Some(&settled)).expect("both endpoints");
            seen_new |= &*picked == "10.0.0.2:80";
        }
        assert!(seen_new, "the new endpoint joins rotation once its window ends");
        drop(baseline);
    }

    #[test]
    fn listeners_opened_in_one_build_keep_their_own_baseline() {
        let registry = Arc::new(SlowStartRegistry::new());
        registry.pin(Instant::now());
        // Finish an empty build first. The listeners below are a later build
        // that turns slow start on, so installed != 0 and a sibling opened
        // in this same build is not history.
        registry.begin_generation();
        registry.end_generation();
        registry.begin_generation();
        let left = binding(&["10.0.0.1:80", "10.0.0.2:80"]).opened(&registry);
        let right = binding(&["10.0.0.2:80", "10.0.0.3:80"]).opened(&registry);
        let weights = right.snapshot(Some(&registry), None);
        assert_eq!(
            weights.of("10.0.0.3:80", 1),
            WEIGHT_SCALE,
            "an endpoint that exists only on the second listener is part of the first enabled membership"
        );
        drop(left);
    }

    #[test]
    fn a_retired_table_does_not_restore_a_removed_endpoint() {
        let registry = Arc::new(SlowStartRegistry::new());
        registry.pin(Instant::now());
        registry.begin_generation();
        let original = binding(&["10.0.0.1:80", "10.0.0.2:80"]).opened(&registry);
        registry.end_generation();
        registry.begin_generation();
        let narrowed = binding(&["10.0.0.1:80"]).opened(&registry);
        registry.end_generation();
        registry.begin_generation();
        let restored = binding(&["10.0.0.1:80", "10.0.0.2:80"]).opened(&registry);
        assert_eq!(
            restored.snapshot(Some(&registry), None).of("10.0.0.2:80", 1),
            0,
            "an endpoint removed and re-added starts a window instead of keeping the retired clock"
        );
        drop(original);
        drop(narrowed);
    }

    #[test]
    fn baseline_is_recorded_when_the_binding_opens() {
        let registry = Arc::new(SlowStartRegistry::new());
        let held = binding(&["10.0.0.1:80", "10.0.0.2:80"]).opened(&registry);
        assert!(
            registry.baseline_seeded("backend"),
            "opening the binding records the baseline before any snapshot"
        );
        drop(held);
    }

    #[test]
    fn removed_cluster_leaves_the_registry_when_its_pipeline_drops() {
        let registry = Arc::new(SlowStartRegistry::new());
        registry.begin_generation();
        let held = binding(&["10.0.0.1:80"]).opened(&registry);
        registry.end_generation();
        assert!(registry.baseline_seeded("backend"), "the installed cluster stays");
        registry.begin_generation();
        registry.end_generation();
        assert!(
            registry.baseline_seeded("backend"),
            "an in-flight pipeline keeps its table until it drops"
        );
        drop(held);
        assert!(
            !registry.baseline_seeded("backend"),
            "a cluster missing from the new config is removed once its pipeline drops"
        );
    }

    #[test]
    fn newly_added_endpoint_starts_at_zero_then_reaches_full_weight() {
        let registry = SlowStartRegistry::new();
        let now = Instant::now();
        registry.pin(now);
        registry.begin_generation();
        let first = binding(&["10.0.0.1:80"]);
        drop(first.snapshot(Some(&registry), None));
        registry.end_generation();
        drop(first);

        registry.begin_generation();
        let second = binding(&["10.0.0.1:80", "10.0.0.2:80"]);
        let added = second.snapshot(Some(&registry), None);
        assert_eq!(
            added.of("10.0.0.1:80", 1),
            WEIGHT_SCALE,
            "existing endpoint keeps full weight"
        );
        assert_eq!(added.of("10.0.0.2:80", 1), 0, "a just-added endpoint starts at zero");

        registry.advance(Duration::from_millis(30_000));
        let done = second.snapshot(Some(&registry), None);
        assert_eq!(
            done.of("10.0.0.2:80", 1),
            WEIGHT_SCALE,
            "the new endpoint reaches full weight"
        );
    }

    #[test]
    fn recovery_restarts_the_window() {
        let registry = SlowStartRegistry::new();
        let now = Instant::now();
        registry.pin(now);
        let binding = binding(&["10.0.0.1:80", "10.0.0.2:80"]);
        drop(binding.snapshot(Some(&registry), None));

        let down = health(&["10.0.0.1:80", "10.0.0.2:80"], &[1]);
        drop(binding.snapshot(Some(&registry), Some(&down)));
        let up = health(&["10.0.0.1:80", "10.0.0.2:80"], &[]);
        let recovered = binding.snapshot(Some(&registry), Some(&up));
        assert_eq!(recovered.of("10.0.0.2:80", 1), 0, "recovery starts the ramp over");
        assert_eq!(
            recovered.of("10.0.0.1:80", 1),
            WEIGHT_SCALE,
            "the endpoint that stayed up is not ramped"
        );
    }

    #[test]
    fn removing_and_readding_an_address_starts_a_new_window() {
        let registry = SlowStartRegistry::new();
        registry.pin(Instant::now());
        registry.begin_generation();
        let both = binding(&["10.0.0.1:80", "10.0.0.2:80"]);
        drop(both.snapshot(Some(&registry), None));
        registry.end_generation();
        drop(both);
        registry.begin_generation();
        let only_first = binding(&["10.0.0.1:80"]);
        drop(only_first.snapshot(Some(&registry), None));
        registry.end_generation();
        drop(only_first);
        registry.begin_generation();
        let restored = binding(&["10.0.0.1:80", "10.0.0.2:80"]).snapshot(Some(&registry), None);
        assert_eq!(
            restored.of("10.0.0.2:80", 1),
            0,
            "an address that left and came back is new"
        );
    }

    #[test]
    fn every_endpoint_at_zero_falls_back_to_configured_weights() {
        let registry = SlowStartRegistry::new();
        registry.pin(Instant::now());
        registry.begin_generation();
        let first = binding(&["10.0.0.1:80"]);
        drop(first.snapshot(Some(&registry), None));
        registry.end_generation();
        drop(first);
        registry.begin_generation();
        let replaced = binding(&["10.0.0.2:80", "10.0.0.3:80"]);
        let weights = replaced.snapshot(Some(&registry), None);
        assert!(
            !weights.scales_capacity(),
            "a pick where every ramp weight is zero falls back"
        );
        assert_eq!(
            weights.of("10.0.0.2:80", 4),
            4,
            "fallback returns the configured weight"
        );
    }

    #[test]
    fn distinct_endpoint_sets_keep_separate_ramps() {
        let registry = SlowStartRegistry::new();
        registry.pin(Instant::now());
        let first = binding(&["10.0.0.1:80", "10.0.0.2:80"]);
        drop(first.snapshot(Some(&registry), None));

        let other = binding(&["10.0.0.3:80"]);
        let other_weights = other.snapshot(Some(&registry), None);
        assert_eq!(
            other_weights.of("10.0.0.3:80", 1),
            WEIGHT_SCALE,
            "a different endpoint set is its own baseline"
        );

        let first_weights = first.snapshot(Some(&registry), None);
        assert_eq!(
            first_weights.of("10.0.0.1:80", 1),
            WEIGHT_SCALE,
            "the other binding must not drop this endpoint"
        );
        assert_eq!(
            first_weights.of("10.0.0.2:80", 1),
            WEIGHT_SCALE,
            "the other binding must not restart this ramp"
        );
    }

    #[test]
    fn settled_ramp_stays_at_full_weight_on_the_next_pick() {
        let registry = SlowStartRegistry::new();
        registry.pin(Instant::now());
        let binding = binding(&["10.0.0.1:80"]);
        drop(binding.snapshot(Some(&registry), None));
        let again = binding.snapshot(Some(&registry), None);
        assert_eq!(
            again.of("10.0.0.1:80", 1),
            WEIGHT_SCALE,
            "a settled baseline stays at full weight"
        );
    }

    #[test]
    fn hash_strategies_do_not_consume_the_ramp() {
        assert!(strategy_ramps(&LoadBalancerStrategy::Simple(
            SimpleStrategy::RoundRobin
        )));
        assert!(!strategy_ramps(&LoadBalancerStrategy::Parameterised(
            ParameterisedStrategy::ConsistentHash(praxis_core::config::ConsistentHashOpts { header: None })
        )));
    }

    fn binding(addresses: &[&str]) -> SlowStartBinding {
        let endpoints = addresses
            .iter()
            .map(|address| (Arc::<str>::from(*address), 1_u32))
            .collect();
        SlowStartBinding::new(Arc::from("backend"), params(30_000, 1.0), endpoints)
    }

    fn health(addresses: &[&str], unhealthy: &[usize]) -> ClusterHealthState {
        let endpoints: Vec<EndpointHealth> = addresses.iter().map(|_| EndpointHealth::new()).collect();
        for index in unhealthy {
            endpoints[*index].mark_unhealthy();
        }
        let names = addresses.iter().map(|address| Arc::<str>::from(*address)).collect();
        Arc::new(ClusterHealthEntry::new(endpoints, names, None, None))
    }
}
