// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Per-cluster circuit breaker filter.

mod config;
mod state;

#[cfg(test)]
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
use tracing::{debug, info, warn};

use self::{
    config::CircuitBreakerConfig,
    state::{CircuitBreaker, CircuitState},
};
use crate::{
    FilterError,
    actions::{FilterAction, Rejection},
    filter::{HttpFilter, HttpFilterContext},
};

// -----------------------------------------------------------------------------
// CircuitBreakerFilter
// -----------------------------------------------------------------------------

/// Rejects requests to clusters whose circuit is open.
///
/// Each configured cluster has an independent circuit
/// breaker state machine. Clusters not listed in the
/// config are unaffected (pass-through).
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
                CircuitBreaker::new(cluster.consecutive_failures, cluster.recovery_window_secs),
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

        match breaker.check() {
            CircuitState::Closed => {
                debug!(cluster = %cluster_name, "circuit closed, allowing request");
                Ok(FilterAction::Continue)
            },
            CircuitState::Open => {
                info!(cluster = %cluster_name, "circuit open, rejecting request");
                Ok(FilterAction::Reject(
                    Rejection::status(503).with_header("X-Circuit-State", "open"),
                ))
            },
            CircuitState::HalfOpen => {
                info!(cluster = %cluster_name, "circuit half-open, allowing probe");
                Ok(FilterAction::Continue)
            },
        }
    }

    async fn on_response(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        let Some(cluster_name) = ctx.cluster.as_deref() else {
            return Ok(FilterAction::Continue);
        };

        let Some(breaker) = self.breakers.get(cluster_name) else {
            return Ok(FilterAction::Continue);
        };

        let is_failure = ctx.response_header.as_ref().is_some_and(|r| r.status.is_server_error());

        if is_failure {
            warn!(cluster = %cluster_name, "recording upstream failure");
            breaker.record_failure();
        } else {
            debug!(cluster = %cluster_name, "recording upstream success");
            breaker.record_success();
        }

        Ok(FilterAction::Continue)
    }
}
