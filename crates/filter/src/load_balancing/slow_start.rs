// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

#![expect(
    dead_code,
    reason = "load-balancer strategies consume this ramp in the follow-up change"
)]

//! Slow-start ramp shared by the weighted load-balancing strategies.
//!
//! The registry survives config reload, so an endpoint added in a later
//! generation is ramped and an endpoint that was already present keeps the
//! clock it started with. Health transitions are applied on each selection.

use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError},
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
    /// False for a fallback pick, which uses the configured weights as today.
    pub(crate) fn scales_capacity(&self) -> bool {
        !self.fallback
    }
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
/// One registry is shared across config reloads. The first time a cluster is
/// observed, its current endpoints are the baseline and stay at full weight.
/// Addresses that appear later, and endpoints that return from unhealthy,
/// start a window.
///
/// The table key is the cluster name plus the endpoint set. Two live bindings
/// that share a name but list different addresses keep separate ramps, so one
/// binding cannot drop the other's endpoints. A reload that replaces a binding
/// reuses the idle ramp for that name, so the new address still starts a window.
pub struct SlowStartRegistry {
    /// Ramp table per cluster name and endpoint set.
    clusters: Mutex<RampTable>,
    /// Clock used to measure windows.
    clock: Mutex<Clock>,
}

impl SlowStartRegistry {
    /// Registry that measures windows with [`Instant::now`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            clusters: Mutex::new(HashMap::new()),
            clock: Mutex::new(Clock::System),
        }
    }

    /// Ramp for this binding.
    ///
    /// The same name and the same addresses share one table. A different
    /// address list gets its own table while another binding is still using
    /// the name. After that binding is gone, the idle table is reused so a
    /// reload still ramps addresses that were not in the previous set.
    fn attach(
        &self,
        name: &Arc<str>,
        params: SlowStartParams,
        endpoints: &[(Arc<str>, u32)],
    ) -> Arc<Mutex<ClusterRamp>> {
        let key = RampKey::from_endpoints(name, endpoints);
        let mut clusters = lock_map(&self.clusters);
        if let Some(existing) = clusters.get(&key) {
            return claim(existing, params);
        }
        if let Some(idle) = take_idle(&mut clusters, name) {
            clusters.insert(key, Arc::clone(&idle));
            return claim(&idle, params);
        }
        let ramp = Arc::new(Mutex::new(ClusterRamp::new(params)));
        claim(&ramp, params);
        clusters.insert(key, Arc::clone(&ramp));
        ramp
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

/// Registry key: cluster name plus the set of endpoint addresses.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
struct RampKey {
    /// Cluster name.
    name: Arc<str>,
    /// Addresses, sorted so order in the config does not change the key.
    endpoints: Vec<Arc<str>>,
}

impl RampKey {
    /// Key for `name` and the addresses in `endpoints`.
    fn from_endpoints(name: &Arc<str>, endpoints: &[(Arc<str>, u32)]) -> Self {
        let mut addresses: Vec<Arc<str>> = endpoints.iter().map(|(address, _)| Arc::clone(address)).collect();
        addresses.sort();
        addresses.dedup();
        Self {
            name: Arc::clone(name),
            endpoints: addresses,
        }
    }
}

/// Record one binding on `ramp` and apply `params`.
fn claim(ramp: &Arc<Mutex<ClusterRamp>>, params: SlowStartParams) -> Arc<Mutex<ClusterRamp>> {
    let mut guard = lock_ramp(ramp);
    guard.params = params;
    guard.holders = guard.holders.saturating_add(1);
    guard.settled = None;
    drop(guard);
    Arc::clone(ramp)
}

/// Remove idle ramps for `name` and return one of them.
///
/// An idle ramp is a table whose bindings have all been dropped. Reusing it
/// keeps a reload on the same clock. Other idle tables for the name are
/// dropped so a replaced binding does not leave a second table behind.
fn take_idle(clusters: &mut RampTable, name: &str) -> Option<Arc<Mutex<ClusterRamp>>> {
    let idle_keys: Vec<RampKey> = clusters
        .iter()
        .filter(|(key, ramp)| key.name.as_ref() == name && lock_ramp(ramp).holders == 0)
        .map(|(key, _)| key.clone())
        .collect();
    let mut reused = None;
    for key in idle_keys {
        if let Some(ramp) = clusters.remove(&key)
            && reused.is_none()
        {
            reused = Some(ramp);
        }
    }
    reused
}

// -----------------------------------------------------------------------------
// Binding
// -----------------------------------------------------------------------------

/// One cluster generation's slow-start inputs, sharing the registry's table.
pub(crate) struct SlowStartBinding {
    /// Cluster name. Combined with the endpoint set, this is the registry key.
    cluster: Arc<str>,
    /// Ramp settings from this generation's config.
    params: SlowStartParams,
    /// Endpoint address and configured weight.
    endpoints: Vec<(Arc<str>, u32)>,
    /// Table filled on the first snapshot, shared across reloads via the registry.
    ramp: OnceLock<Arc<Mutex<ClusterRamp>>>,
}

impl SlowStartBinding {
    /// Binding for `cluster` and its current endpoints.
    pub(crate) fn new(cluster: Arc<str>, params: SlowStartParams, endpoints: Vec<(Arc<str>, u32)>) -> Self {
        Self {
            cluster,
            params,
            endpoints,
            ramp: OnceLock::new(),
        }
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
        let created = self
            .ramp
            .get_or_init(|| open_ramp(&self.cluster, self.params, &self.endpoints, registry));
        Arc::clone(created)
    }
}

impl Drop for SlowStartBinding {
    /// Release this binding's hold on the shared ramp.
    ///
    /// A later binding with the same cluster name can then reuse the table
    /// when its endpoint set differs, which is how a reload keeps the clock.
    fn drop(&mut self) {
        if let Some(ramp) = self.ramp.get() {
            let mut guard = lock_ramp(ramp);
            guard.holders = guard.holders.saturating_sub(1);
        }
    }
}

/// Open the shared table, or a private one when the caller has no registry.
fn open_ramp(
    cluster: &Arc<str>,
    params: SlowStartParams,
    endpoints: &[(Arc<str>, u32)],
    registry: Option<&SlowStartRegistry>,
) -> Arc<Mutex<ClusterRamp>> {
    match registry {
        Some(registry) => registry.attach(cluster, params, endpoints),
        None => Arc::new(Mutex::new(ClusterRamp::new(params))),
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
struct EndpointRamp {
    /// When the current window started. `None` means full weight.
    started_at: Option<Instant>,
    /// Last observed health. A rising edge restarts the window.
    healthy: bool,
}

impl ClusterRamp {
    /// Empty table. The next snapshot records the baseline.
    fn new(params: SlowStartParams) -> Self {
        Self {
            params,
            holders: 0,
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
        EffectiveWeights {
            by_address: Arc::new(by_address),
            fallback: healthy_total == 0,
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
    fn newly_added_endpoint_starts_at_zero_then_reaches_full_weight() {
        let registry = SlowStartRegistry::new();
        let now = Instant::now();
        registry.pin(now);
        let first = binding(&["10.0.0.1:80"]);
        drop(first.snapshot(Some(&registry), None));
        drop(first);

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
        let both = binding(&["10.0.0.1:80", "10.0.0.2:80"]);
        drop(both.snapshot(Some(&registry), None));
        drop(both);
        let only_first = binding(&["10.0.0.1:80"]);
        drop(only_first.snapshot(Some(&registry), None));
        drop(only_first);
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
        let first = binding(&["10.0.0.1:80"]);
        drop(first.snapshot(Some(&registry), None));
        drop(first);
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
