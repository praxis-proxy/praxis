// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Per-cluster circuit breaker filter.

mod config;

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::too_many_lines,
    reason = "tests"
)]
mod tests;

use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use praxis_core::circuit::{
    CircuitBreaker, CircuitBreakerConfig as CoreCircuitBreakerConfig, CircuitCheck, CircuitToken,
};
use tracing::{debug, info, warn};

use self::config::CircuitBreakerConfig;
use crate::{
    FilterError,
    actions::{FilterAction, Rejection},
    filter::{HttpFilter, HttpFilterContext},
};

// -----------------------------------------------------------------------------
// ActiveCircuitToken
// -----------------------------------------------------------------------------

/// Token stored in filter state during the request–response lifecycle.
///
/// Binds the cluster name to its circuit breaker generation token
/// so that the response hook can record the correct outcome.
struct ActiveCircuitToken {
    /// Cluster whose breaker issued the token.
    cluster: Arc<str>,
    /// Generation-bearing token from [`CircuitBreaker::try_acquire`].
    token: CircuitToken,
}

// -----------------------------------------------------------------------------
// CircuitBreakerFilter
// -----------------------------------------------------------------------------

/// Rejects requests to clusters whose circuit is open.
///
/// Each configured cluster has an independent circuit
/// breaker state machine. Clusters not listed in the
/// config are unaffected (pass-through).
///
/// When consecutive upstream failures reach the threshold,
/// the circuit opens and subsequent requests receive 503
/// immediately. After the recovery window, a single probe
/// request is forwarded; if it succeeds the circuit closes.
///
/// # YAML configuration
///
/// ```yaml
/// filter: circuit_breaker
/// clusters:
///   - name: backend
///     consecutive_failures: 5
///     recovery_window_secs: 30
/// ```
///
/// # Example
///
/// ```
/// use praxis_filter::CircuitBreakerFilter;
///
/// let yaml: serde_yaml::Value = serde_yaml::from_str(
///     r#"
/// clusters:
///   - name: backend
///     consecutive_failures: 5
///     recovery_window_secs: 30
/// "#,
/// )
/// .unwrap();
/// let filter = CircuitBreakerFilter::from_config(&yaml).unwrap();
/// assert_eq!(filter.name(), "circuit_breaker");
/// ```
pub struct CircuitBreakerFilter {
    /// Per-cluster circuit breaker state.
    breakers: HashMap<Arc<str>, CircuitBreaker>,
}

impl CircuitBreakerFilter {
    /// Create a circuit breaker filter from parsed YAML config.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if any config field is
    /// invalid (zero threshold, zero recovery window).
    ///
    /// [`FilterError`]: crate::FilterError
    pub fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        let cfg: CircuitBreakerConfig = crate::parse_filter_config("circuit_breaker", config)?;

        let mut breakers = HashMap::new();
        for cluster in &cfg.clusters {
            if cluster.consecutive_failures == 0 {
                return Err(format!(
                    "circuit_breaker: cluster '{}': consecutive_failures must be > 0",
                    cluster.name
                )
                .into());
            }
            if cluster.recovery_window_secs == 0 {
                return Err(format!(
                    "circuit_breaker: cluster '{}': recovery_window_secs must be > 0",
                    cluster.name
                )
                .into());
            }
            breakers.insert(
                Arc::clone(&cluster.name),
                CircuitBreaker::new(CoreCircuitBreakerConfig {
                    threshold: cluster.consecutive_failures,
                    recovery_window: std::time::Duration::from_secs(cluster.recovery_window_secs),
                    half_open_timeout: std::time::Duration::from_secs(cluster.half_open_timeout_secs),
                }),
            );
        }

        Ok(Box::new(Self { breakers }))
    }
}

#[async_trait]
impl HttpFilter for CircuitBreakerFilter {
    fn name(&self) -> &'static str {
        "circuit_breaker"
    }

    async fn on_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        let Some(cluster_name) = ctx.cluster.as_deref() else {
            return Ok(FilterAction::Continue);
        };

        let Some(breaker) = self.breakers.get(cluster_name) else {
            return Ok(FilterAction::Continue);
        };

        match breaker.try_acquire() {
            CircuitCheck::Allowed(token) => {
                debug!(cluster = %cluster_name, "circuit closed/half-open, allowing request");
                ctx.insert_filter_state(ActiveCircuitToken {
                    cluster: Arc::from(cluster_name),
                    token,
                });
                Ok(FilterAction::Continue)
            },
            CircuitCheck::Rejected => {
                info!(cluster = %cluster_name, "circuit open, rejecting request");
                Ok(FilterAction::Reject(
                    Rejection::status(503).with_header("X-Circuit-State", "open"),
                ))
            },
        }
    }

    async fn on_response(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        let Some(active) = ctx.remove_filter_state::<ActiveCircuitToken>() else {
            return Ok(FilterAction::Continue);
        };

        let Some(breaker) = self.breakers.get(&active.cluster) else {
            return Ok(FilterAction::Continue);
        };

        let is_success = ctx
            .response_header
            .as_ref()
            .is_some_and(|r| !r.status.is_server_error());

        if is_success {
            debug!(cluster = %active.cluster, "recording upstream success");
            breaker.record_success(active.token);
        } else {
            warn!(cluster = %active.cluster, "recording upstream failure");
            breaker.record_failure(active.token);
        }

        Ok(FilterAction::Continue)
    }
}
