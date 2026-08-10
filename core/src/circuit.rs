// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Circuit breaker state machine with generation-bearing tokens.
//!
//! Provides a three-state machine (Closed → Open → HalfOpen → Closed)
//! with per-probe generation tracking so that stale completions from
//! timed-out probes are silently ignored.

use std::{
    net::SocketAddr,
    sync::Mutex,
    time::{Duration, Instant},
};

use dashmap::DashMap;

// ---------------------------------------------------------------------------
// CircuitState
// ---------------------------------------------------------------------------

/// The three states of a circuit breaker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CircuitState {
    /// Requests pass through; failures are counted.
    Closed,

    /// Requests are rejected; waiting for recovery window.
    Open,

    /// One probe request is allowed through.
    HalfOpen,
}

// ---------------------------------------------------------------------------
// CircuitCheck / CircuitToken
// ---------------------------------------------------------------------------

/// Result of a [`CircuitBreaker::try_acquire`] call.
pub enum CircuitCheck {
    /// Request allowed; carry this token to record the outcome.
    Allowed(CircuitToken),

    /// Circuit is open; request rejected.
    Rejected,
}

/// Opaque token binding a request to a circuit breaker generation.
///
/// Pass to [`CircuitBreaker::record_success`] or
/// [`CircuitBreaker::record_failure`] after the exchange completes.
/// Dropping without recording is a deliberate no-op (used for local
/// construction errors that are not peer faults).
pub struct CircuitToken {
    /// The generation at which this token was issued.
    generation: u64,
}

// ---------------------------------------------------------------------------
// CircuitBreakerConfig
// ---------------------------------------------------------------------------

/// Configuration for a [`CircuitBreaker`].
#[derive(Clone, Debug)]
pub struct CircuitBreakerConfig {
    /// Consecutive failure threshold to trip the circuit.
    pub threshold: u32,

    /// How long the circuit stays open before allowing a `HalfOpen` probe.
    pub recovery_window: Duration,

    /// How long a `HalfOpen` probe may remain in-flight before the
    /// circuit resets to Open with a fresh recovery window.
    pub half_open_timeout: Duration,
}

// ---------------------------------------------------------------------------
// CircuitBreaker
// ---------------------------------------------------------------------------

/// Per-peer circuit breaker with generation-bearing tokens.
///
/// Thread-safe via internal [`Mutex`]. The critical section is small
/// (a few field reads/writes), so contention is negligible.
#[derive(Debug)]
pub struct CircuitBreaker {
    /// Guarded interior state.
    inner: Mutex<CircuitInner>,
    /// Shared configuration.
    config: CircuitBreakerConfig,
}

/// Mutable interior state.
#[derive(Debug)]
struct CircuitInner {
    /// Running tally of consecutive failures.
    consecutive_failures: u32,
    /// When the circuit entered `HalfOpen`.
    half_opened_at: Option<Instant>,
    /// When the circuit transitioned to `Open`.
    opened_at: Option<Instant>,
    /// When the last outcome was recorded (success or failure).
    last_activity: Instant,
    /// Current state machine position.
    state: CircuitState,
    /// Monotonic generation counter; incremented on state transitions.
    generation: u64,
}

impl CircuitInner {
    /// Issue a token at the current generation.
    fn issue_token(&self) -> CircuitCheck {
        CircuitCheck::Allowed(CircuitToken {
            generation: self.generation,
        })
    }

    /// Bump the generation and transition to `HalfOpen`, issuing a
    /// probe token.
    fn transition_to_half_open(&mut self) -> CircuitCheck {
        self.generation = self.generation.wrapping_add(1);
        self.state = CircuitState::HalfOpen;
        self.half_opened_at = Some(Instant::now());
        self.issue_token()
    }

    /// If the recovery window has elapsed, transition from `Open` to
    /// `HalfOpen` and issue a probe token. Otherwise reject.
    fn try_open_to_half_open(&mut self, config: &CircuitBreakerConfig) -> CircuitCheck {
        if self.opened_at.is_some_and(|t| t.elapsed() >= config.recovery_window) {
            self.transition_to_half_open()
        } else {
            CircuitCheck::Rejected
        }
    }

    /// If the half-open probe has timed out, reset to `Open` and
    /// re-attempt recovery. Otherwise reject (probe still in flight).
    fn try_reset_stale_probe(&mut self, config: &CircuitBreakerConfig) -> CircuitCheck {
        if self
            .half_opened_at
            .is_some_and(|t| t.elapsed() >= config.half_open_timeout)
        {
            self.state = CircuitState::Open;
            self.opened_at = Some(Instant::now());
            self.half_opened_at = None;
            self.try_open_to_half_open(config)
        } else {
            CircuitCheck::Rejected
        }
    }
}

impl CircuitBreaker {
    /// Create a new circuit breaker starting in Closed.
    pub fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            inner: Mutex::new(CircuitInner {
                consecutive_failures: 0,
                half_opened_at: None,
                opened_at: None,
                last_activity: Instant::now(),
                state: CircuitState::Closed,
                generation: 0,
            }),
            config,
        }
    }

    /// Non-mutating peek at whether a request would likely be allowed.
    ///
    /// Returns `true` for `Closed`, `Open` with elapsed recovery
    /// window, or `HalfOpen` with elapsed probe timeout. Does **not**
    /// transition state -- use this to fast-fail before consuming an
    /// admission slot.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    #[expect(clippy::expect_used, reason = "poisoned mutex is unrecoverable")]
    pub fn precheck(&self) -> bool {
        let inner = self.inner.lock().expect("circuit breaker lock poisoned");
        match inner.state {
            CircuitState::Closed => true,
            CircuitState::Open => inner
                .opened_at
                .is_some_and(|t| t.elapsed() >= self.config.recovery_window),
            CircuitState::HalfOpen => inner
                .half_opened_at
                .is_some_and(|t| t.elapsed() >= self.config.half_open_timeout),
        }
    }

    /// Attempt to acquire a circuit token for a request.
    ///
    /// Transitions `Open` to `HalfOpen` when the recovery window has
    /// elapsed, incrementing the generation. Returns
    /// [`CircuitCheck::Rejected`] when the circuit is definitively
    /// closed to traffic.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    #[expect(clippy::expect_used, reason = "poisoned mutex is unrecoverable")]
    pub fn try_acquire(&self) -> CircuitCheck {
        let mut inner = self.inner.lock().expect("circuit breaker lock poisoned");
        match inner.state {
            CircuitState::Closed => inner.issue_token(),
            CircuitState::Open => inner.try_open_to_half_open(&self.config),
            CircuitState::HalfOpen => inner.try_reset_stale_probe(&self.config),
        }
    }

    /// Record a successful exchange for the given token.
    ///
    /// Stale tokens (generation mismatch) are silently ignored.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    #[expect(clippy::expect_used, reason = "poisoned mutex is unrecoverable")]
    #[expect(clippy::needless_pass_by_value, reason = "consumed to prevent double-recording")]
    pub fn record_success(&self, token: CircuitToken) {
        let mut inner = self.inner.lock().expect("circuit breaker lock poisoned");
        if token.generation != inner.generation {
            return;
        }
        inner.last_activity = Instant::now();
        match inner.state {
            CircuitState::Closed => {
                inner.consecutive_failures = 0;
            },
            CircuitState::HalfOpen => {
                inner.state = CircuitState::Closed;
                inner.consecutive_failures = 0;
                inner.half_opened_at = None;
                inner.opened_at = None;
            },
            CircuitState::Open => {},
        }
    }

    /// Record a failed exchange for the given token.
    ///
    /// Stale tokens (generation mismatch) are silently ignored.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    #[expect(clippy::expect_used, reason = "poisoned mutex is unrecoverable")]
    #[expect(clippy::needless_pass_by_value, reason = "consumed to prevent double-recording")]
    pub fn record_failure(&self, token: CircuitToken) {
        let mut inner = self.inner.lock().expect("circuit breaker lock poisoned");
        if token.generation != inner.generation {
            return;
        }
        inner.last_activity = Instant::now();
        match inner.state {
            CircuitState::Closed => {
                inner.consecutive_failures = inner.consecutive_failures.saturating_add(1);
                if inner.consecutive_failures >= self.config.threshold {
                    inner.state = CircuitState::Open;
                    inner.opened_at = Some(Instant::now());
                }
            },
            CircuitState::HalfOpen => {
                inner.state = CircuitState::Open;
                inner.opened_at = Some(Instant::now());
                inner.half_opened_at = None;
            },
            CircuitState::Open => {},
        }
    }

    /// Whether the breaker is `Closed` with no failures and idle
    /// for at least `idle_threshold`.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    #[expect(clippy::expect_used, reason = "poisoned mutex is unrecoverable")]
    fn is_idle(&self, idle_threshold: Duration) -> bool {
        let inner = self.inner.lock().expect("circuit breaker lock poisoned");
        inner.state == CircuitState::Closed
            && inner.consecutive_failures == 0
            && inner.last_activity.elapsed() >= idle_threshold
    }

    /// Returns the current state without side effects.
    ///
    /// Used by filter-layer metrics to publish open/closed gauges
    /// without duplicating the state machine.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    #[expect(clippy::expect_used, reason = "poisoned mutex is unrecoverable")]
    pub fn state(&self) -> CircuitState {
        self.inner.lock().expect("circuit breaker lock poisoned").state
    }
}

// ---------------------------------------------------------------------------
// PeerKey
// ---------------------------------------------------------------------------

/// Logical identity of an upstream peer for circuit breaker keying.
///
/// Combines the socket address with an optional SNI so that peers
/// behind the same IP:port but serving different hostnames get
/// independent circuit breakers.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct PeerKey {
    /// Socket address of the peer.
    addr: SocketAddr,
    /// TLS SNI, empty when not applicable.
    sni: String,
}

impl PeerKey {
    /// Create a peer key from an address and optional SNI.
    pub fn new(addr: SocketAddr, sni: impl Into<String>) -> Self {
        Self { addr, sni: sni.into() }
    }
}

impl std::fmt::Display for PeerKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.sni.is_empty() {
            write!(f, "{}", self.addr)
        } else {
            write!(f, "{} ({})", self.addr, self.sni)
        }
    }
}

// ---------------------------------------------------------------------------
// CircuitBreakerRegistry
// ---------------------------------------------------------------------------

/// Per-peer circuit breaker registry backed by [`DashMap`].
///
/// Lazily creates a [`CircuitBreaker`] per [`PeerKey`] on first
/// access, using the shared [`CircuitBreakerConfig`].
#[derive(Debug)]
pub struct CircuitBreakerRegistry {
    /// Lazily populated per-peer breakers.
    breakers: DashMap<PeerKey, CircuitBreaker>,
    /// Shared config applied to every new breaker.
    config: CircuitBreakerConfig,
}

impl CircuitBreakerRegistry {
    /// Create a new registry with the given config.
    pub fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            breakers: DashMap::new(),
            config,
        }
    }

    /// Non-mutating peek for a peer. Returns `true` if the peer has
    /// no breaker yet or if its breaker would allow a request.
    pub fn precheck(&self, peer: &PeerKey) -> bool {
        self.breakers.get(peer).is_none_or(|cb| cb.precheck())
    }

    /// Attempt to acquire a circuit token for a peer. Creates the
    /// breaker on first access.
    pub fn try_acquire(&self, peer: PeerKey) -> CircuitCheck {
        self.breakers
            .entry(peer)
            .or_insert_with(|| CircuitBreaker::new(self.config.clone()))
            .try_acquire()
    }

    /// Record a successful exchange for a peer.
    pub fn record_success(&self, peer: &PeerKey, token: CircuitToken) {
        if let Some(cb) = self.breakers.get(peer) {
            cb.record_success(token);
        }
    }

    /// Record a failed exchange for a peer.
    pub fn record_failure(&self, peer: &PeerKey, token: CircuitToken) {
        if let Some(cb) = self.breakers.get(peer) {
            cb.record_failure(token);
        }
    }

    /// Evict idle breakers that have been `Closed` with zero failures
    /// for at least `idle_threshold`.
    ///
    /// Returns the number of entries removed. The caller is
    /// responsible for scheduling periodic invocations.
    pub fn evict_idle(&self, idle_threshold: Duration) -> usize {
        let stale: Vec<PeerKey> = self
            .breakers
            .iter()
            .filter(|entry| entry.value().is_idle(idle_threshold))
            .map(|entry| entry.key().clone())
            .collect();
        let count = stale.len();
        for key in &stale {
            self.breakers.remove(key);
        }
        count
    }

    /// Number of tracked peers.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.breakers.len()
    }

    /// Whether the registry has no tracked peers.
    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.breakers.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]
mod tests {
    use super::*;

    fn config(threshold: u32, recovery_ms: u64, half_open_ms: u64) -> CircuitBreakerConfig {
        CircuitBreakerConfig {
            threshold,
            recovery_window: Duration::from_millis(recovery_ms),
            half_open_timeout: Duration::from_millis(half_open_ms),
        }
    }

    // --- State machine basics ---

    #[test]
    fn starts_in_closed_state() {
        let cb = CircuitBreaker::new(config(3, 30_000, 9_999_000));
        assert_eq!(cb.state(), CircuitState::Closed);
    }

    #[test]
    fn stays_closed_below_threshold() {
        let cb = CircuitBreaker::new(config(3, 30_000, 9_999_000));
        let t1 = cb.try_acquire();
        record_failure_from_check(&cb, t1);
        let t2 = cb.try_acquire();
        record_failure_from_check(&cb, t2);
        assert_eq!(cb.state(), CircuitState::Closed);
    }

    #[test]
    fn trips_to_open_at_threshold() {
        let cb = CircuitBreaker::new(config(3, 30_000, 9_999_000));
        for _ in 0..3 {
            let t = cb.try_acquire();
            record_failure_from_check(&cb, t);
        }
        assert_eq!(cb.state(), CircuitState::Open);
    }

    #[test]
    fn success_resets_failure_count() {
        let cb = CircuitBreaker::new(config(3, 30_000, 9_999_000));
        let t1 = cb.try_acquire();
        record_failure_from_check(&cb, t1);
        let t2 = cb.try_acquire();
        record_failure_from_check(&cb, t2);
        let t3 = cb.try_acquire();
        record_success_from_check(&cb, t3);
        let t4 = cb.try_acquire();
        record_failure_from_check(&cb, t4);
        let t5 = cb.try_acquire();
        record_failure_from_check(&cb, t5);
        assert_eq!(cb.state(), CircuitState::Closed);
    }

    #[test]
    fn open_rejects_via_try_acquire() {
        let cb = CircuitBreaker::new(config(1, 9_999_000, 9_999_000));
        let t = cb.try_acquire();
        record_failure_from_check(&cb, t);
        assert!(matches!(cb.try_acquire(), CircuitCheck::Rejected));
    }

    #[test]
    fn half_open_after_recovery_window() {
        let cb = CircuitBreaker::new(config(1, 0, 9_999_000));
        let t = cb.try_acquire();
        record_failure_from_check(&cb, t);
        assert_eq!(cb.state(), CircuitState::Open);
        assert!(matches!(cb.try_acquire(), CircuitCheck::Allowed(_)));
        assert_eq!(cb.state(), CircuitState::HalfOpen);
    }

    #[test]
    fn half_open_success_transitions_to_closed() {
        let cb = CircuitBreaker::new(config(1, 0, 9_999_000));
        let t = cb.try_acquire();
        record_failure_from_check(&cb, t);
        let probe = cb.try_acquire();
        record_success_from_check(&cb, probe);
        assert_eq!(cb.state(), CircuitState::Closed);
    }

    #[test]
    fn half_open_failure_transitions_to_open() {
        let cb = CircuitBreaker::new(config(1, 0, 9_999_000));
        let t = cb.try_acquire();
        record_failure_from_check(&cb, t);
        let probe = cb.try_acquire();
        record_failure_from_check(&cb, probe);
        assert_eq!(cb.state(), CircuitState::Open);
    }

    #[test]
    fn half_open_allows_only_one_probe() {
        let cb = CircuitBreaker::new(config(1, 0, 9_999_000));
        let t = cb.try_acquire();
        record_failure_from_check(&cb, t);
        let first = cb.try_acquire();
        assert!(matches!(first, CircuitCheck::Allowed(_)));
        assert!(matches!(cb.try_acquire(), CircuitCheck::Rejected));
        assert!(matches!(cb.try_acquire(), CircuitCheck::Rejected));
    }

    #[test]
    fn open_record_failure_is_noop() {
        let cb = CircuitBreaker::new(config(1, 9_999_000, 9_999_000));
        let t = cb.try_acquire();
        record_failure_from_check(&cb, t);
        assert_eq!(cb.state(), CircuitState::Open);
    }

    #[test]
    fn multiple_successes_keep_closed() {
        let cb = CircuitBreaker::new(config(3, 30_000, 9_999_000));
        for _ in 0..10 {
            let t = cb.try_acquire();
            record_success_from_check(&cb, t);
        }
        assert_eq!(cb.state(), CircuitState::Closed);
    }

    // --- Half-open timeout ---

    #[test]
    fn half_open_timeout_resets_to_open() {
        let cb = CircuitBreaker::new(config(1, 0, 0));
        let t = cb.try_acquire();
        record_failure_from_check(&cb, t);
        let _probe = cb.try_acquire();
        let next = cb.try_acquire();
        assert!(matches!(next, CircuitCheck::Allowed(_)));
    }

    #[test]
    fn half_open_timeout_does_not_fire_before_expiry() {
        let cb = CircuitBreaker::new(config(1, 0, 9_999_000));
        let t = cb.try_acquire();
        record_failure_from_check(&cb, t);
        let _probe = cb.try_acquire();
        assert!(matches!(cb.try_acquire(), CircuitCheck::Rejected));
        assert_eq!(cb.state(), CircuitState::HalfOpen);
    }

    // --- Generation tracking ---

    #[test]
    fn stale_probe_success_ignored() {
        let cb = CircuitBreaker::new(config(1, 0, 0));
        let t = cb.try_acquire();
        record_failure_from_check(&cb, t);
        let stale_probe = cb.try_acquire();
        let fresh_probe = cb.try_acquire();
        record_success_from_check(&cb, stale_probe);
        assert_eq!(
            cb.state(),
            CircuitState::HalfOpen,
            "stale probe success must not close the circuit"
        );
        record_success_from_check(&cb, fresh_probe);
        assert_eq!(cb.state(), CircuitState::Closed);
    }

    #[test]
    fn stale_probe_failure_ignored() {
        let cb = CircuitBreaker::new(config(1, 0, 0));
        let t = cb.try_acquire();
        record_failure_from_check(&cb, t);
        let stale_probe = cb.try_acquire();
        let fresh_probe = cb.try_acquire();
        record_failure_from_check(&cb, stale_probe);
        record_success_from_check(&cb, fresh_probe);
        assert_eq!(cb.state(), CircuitState::Closed);
    }

    #[test]
    fn closed_tokens_always_match_generation() {
        let cb = CircuitBreaker::new(config(3, 30_000, 9_999_000));
        let t1 = cb.try_acquire();
        record_failure_from_check(&cb, t1);
        assert_eq!(cb.state(), CircuitState::Closed);
        let t2 = cb.try_acquire();
        record_failure_from_check(&cb, t2);
        assert_eq!(cb.state(), CircuitState::Closed);
        let t3 = cb.try_acquire();
        record_failure_from_check(&cb, t3);
        assert_eq!(cb.state(), CircuitState::Open);
    }

    // --- Precheck ---

    #[test]
    fn precheck_returns_true_when_closed() {
        let cb = CircuitBreaker::new(config(3, 30_000, 9_999_000));
        assert!(cb.precheck());
    }

    #[test]
    fn precheck_returns_false_when_open_not_recovered() {
        let cb = CircuitBreaker::new(config(1, 9_999_000, 9_999_000));
        let t = cb.try_acquire();
        record_failure_from_check(&cb, t);
        assert!(!cb.precheck());
    }

    #[test]
    fn precheck_returns_true_when_open_recovered() {
        let cb = CircuitBreaker::new(config(1, 0, 9_999_000));
        let t = cb.try_acquire();
        record_failure_from_check(&cb, t);
        assert!(cb.precheck(), "recovery_window=0 means immediately recoverable");
    }

    #[test]
    fn precheck_returns_false_when_half_open_probe_in_flight() {
        let cb = CircuitBreaker::new(config(1, 0, 9_999_000));
        let t = cb.try_acquire();
        record_failure_from_check(&cb, t);
        let _probe = cb.try_acquire();
        assert!(!cb.precheck());
    }

    #[test]
    fn precheck_returns_true_when_half_open_probe_timed_out() {
        let cb = CircuitBreaker::new(config(1, 0, 0));
        let t = cb.try_acquire();
        record_failure_from_check(&cb, t);
        let _probe = cb.try_acquire();
        assert!(cb.precheck(), "half_open_timeout=0 means timed out");
    }

    #[test]
    fn precheck_does_not_mutate_state() {
        let cb = CircuitBreaker::new(config(1, 0, 9_999_000));
        let t = cb.try_acquire();
        record_failure_from_check(&cb, t);
        assert_eq!(cb.state(), CircuitState::Open);
        let _ = cb.precheck();
        assert_eq!(cb.state(), CircuitState::Open);
    }

    // --- Registry ---

    fn peer(addr: &str) -> PeerKey {
        PeerKey::new(addr.parse().unwrap(), "")
    }

    fn peer_with_sni(addr: &str, sni: &str) -> PeerKey {
        PeerKey::new(addr.parse().unwrap(), sni)
    }

    #[test]
    fn registry_creates_breaker_on_first_access() {
        let registry = CircuitBreakerRegistry::new(config(3, 30_000, 9_999_000));
        let key = peer("127.0.0.1:8080");
        assert!(registry.precheck(&key));
    }

    #[test]
    fn registry_isolates_peers() {
        let registry = CircuitBreakerRegistry::new(config(1, 9_999_000, 9_999_000));
        let a = peer("127.0.0.1:8080");
        let b = peer("127.0.0.1:9090");
        let t = registry.try_acquire(a.clone());
        record_registry_failure(&registry, &a, t);
        assert!(!registry.precheck(&a), "peer a should be open");
        assert!(registry.precheck(&b), "peer b should be unaffected");
    }

    #[test]
    fn registry_isolates_peers_by_sni() {
        let registry = CircuitBreakerRegistry::new(config(1, 9_999_000, 9_999_000));
        let a = peer_with_sni("127.0.0.1:443", "api.example.com");
        let b = peer_with_sni("127.0.0.1:443", "web.example.com");
        let t = registry.try_acquire(a.clone());
        record_registry_failure(&registry, &a, t);
        assert!(!registry.precheck(&a), "api peer should be open");
        assert!(registry.precheck(&b), "web peer should be unaffected");
    }

    #[test]
    fn registry_propagates_config() {
        let registry = CircuitBreakerRegistry::new(config(2, 9_999_000, 9_999_000));
        let key = peer("127.0.0.1:8080");
        let t1 = registry.try_acquire(key.clone());
        record_registry_failure(&registry, &key, t1);
        assert!(registry.precheck(&key), "one failure should not trip threshold=2");
        let t2 = registry.try_acquire(key.clone());
        record_registry_failure(&registry, &key, t2);
        assert!(!registry.precheck(&key), "two failures should trip threshold=2");
    }

    // --- Eviction ---

    #[test]
    fn evict_idle_removes_healthy_idle_entries() {
        let registry = CircuitBreakerRegistry::new(config(3, 30_000, 9_999_000));
        let a = peer("127.0.0.1:8080");
        let b = peer("127.0.0.1:9090");
        let ta = registry.try_acquire(a.clone());
        record_registry_success(&registry, &a, ta);
        let tb = registry.try_acquire(b.clone());
        record_registry_success(&registry, &b, tb);
        assert_eq!(registry.len(), 2);
        let evicted = registry.evict_idle(Duration::ZERO);
        assert_eq!(evicted, 2, "both idle entries should be evicted");
        assert_eq!(registry.len(), 0);
    }

    #[test]
    fn evict_idle_preserves_active_entries() {
        let registry = CircuitBreakerRegistry::new(config(1, 9_999_000, 9_999_000));
        let a = peer("127.0.0.1:8080");
        let b = peer("127.0.0.1:9090");
        let ta = registry.try_acquire(a.clone());
        record_registry_failure(&registry, &a, ta);
        let tb = registry.try_acquire(b.clone());
        record_registry_success(&registry, &b, tb);
        let evicted = registry.evict_idle(Duration::ZERO);
        assert_eq!(evicted, 1, "only the healthy idle peer should be evicted");
        assert_eq!(registry.len(), 1);
        assert!(!registry.precheck(&a), "open circuit should survive eviction");
    }

    // --- PeerKey ---

    #[test]
    fn peer_key_display_without_sni() {
        let key = peer("127.0.0.1:8080");
        assert_eq!(key.to_string(), "127.0.0.1:8080");
    }

    #[test]
    fn peer_key_display_with_sni() {
        let key = peer_with_sni("127.0.0.1:443", "api.example.com");
        assert_eq!(key.to_string(), "127.0.0.1:443 (api.example.com)");
    }

    // --- Test Utilities ---

    fn record_success_from_check(cb: &CircuitBreaker, check: CircuitCheck) {
        if let CircuitCheck::Allowed(token) = check {
            cb.record_success(token);
        }
    }

    fn record_failure_from_check(cb: &CircuitBreaker, check: CircuitCheck) {
        if let CircuitCheck::Allowed(token) = check {
            cb.record_failure(token);
        }
    }

    fn record_registry_success(registry: &CircuitBreakerRegistry, key: &PeerKey, check: CircuitCheck) {
        if let CircuitCheck::Allowed(token) = check {
            registry.record_success(key, token);
        }
    }

    fn record_registry_failure(registry: &CircuitBreakerRegistry, key: &PeerKey, check: CircuitCheck) {
        if let CircuitCheck::Allowed(token) = check {
            registry.record_failure(key, token);
        }
    }
}
