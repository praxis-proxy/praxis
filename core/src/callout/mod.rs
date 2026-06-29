// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Reusable HTTP callout client for Praxis filters.
//!
//! Provides [`CalloutClient`](crate::callout::CalloutClient) — a shared primitive that any filter can use
//! to make outbound HTTP requests with timeout, circuit breaking, and
//! loop-prevention semantics.

mod circuit;

#[cfg(test)]
mod tests;

use std::time::Duration;

use circuit::{CircuitBreaker, CircuitState};
use reqwest::redirect;
use tracing::{debug, warn};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Header injected into outbound callout requests to prevent loops.
pub const DEPTH_HEADER: &str = "x-praxis-callout-depth";

/// Default maximum callout depth (no re-entry).
const DEFAULT_MAX_DEPTH: u32 = 1;

/// Default timeout for callout requests (5 000 ms).
const DEFAULT_TIMEOUT_MS: u64 = 5_000;

/// Default HTTP status returned on error when `failure_mode` is `Closed`.
const DEFAULT_STATUS_ON_ERROR: u16 = 403;

/// Default pool idle connections per host.
const DEFAULT_POOL_MAX_IDLE_PER_HOST: usize = 4;

// -----------------------------------------------------------------------------
// Public types — FailureMode
// -----------------------------------------------------------------------------

/// What happens when a callout fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureMode {
    /// Reject the original request on callout failure.
    Closed,

    /// Allow the original request to proceed on callout failure.
    Open,
}

// -----------------------------------------------------------------------------
// Public types — Rejection
// -----------------------------------------------------------------------------

/// Rejection details returned to the downstream client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rejection {
    /// HTTP status code to return.
    pub status: u16,
}

// -----------------------------------------------------------------------------
// Public types — CalloutResult
// -----------------------------------------------------------------------------

/// Outcome of a callout execution.
#[derive(Debug)]
pub enum CalloutResult {
    /// The callout succeeded with a 2xx response.
    Success(CalloutResponse),

    /// The callout failed but `failure_mode` is `Open`,
    /// so the original request should proceed.
    Failed,

    /// The callout failed and `failure_mode` is `Closed`,
    /// so the original request must be rejected.
    Rejected(Rejection),
}

// -----------------------------------------------------------------------------
// Public types — CalloutResponse
// -----------------------------------------------------------------------------

/// Successful callout response.
#[derive(Debug)]
pub struct CalloutResponse {
    /// Response body bytes.
    pub body: Vec<u8>,

    /// Response headers.
    pub headers: Vec<(http::HeaderName, http::HeaderValue)>,

    /// HTTP status code.
    pub status: u16,
}

// -----------------------------------------------------------------------------
// Public types — CalloutRequest
// -----------------------------------------------------------------------------

/// A single callout request to execute.
#[derive(Debug)]
pub struct CalloutRequest {
    /// Request body (empty for bodiless methods).
    pub body: Option<Vec<u8>>,

    /// Current callout depth (0 = top-level request).
    pub depth: u32,

    /// Request headers to send.
    pub headers: Vec<(http::HeaderName, http::HeaderValue)>,

    /// HTTP method.
    pub method: http::Method,

    /// Target URL.
    pub url: String,
}

// -----------------------------------------------------------------------------
// Public types — CalloutError
// -----------------------------------------------------------------------------

/// Errors that prevent a [`CalloutClient`] from being constructed.
#[derive(Debug, thiserror::Error)]
pub enum CalloutError {
    /// Invalid client configuration.
    #[error("callout config error: {0}")]
    Config(String),

    /// Failed to build the underlying HTTP client.
    #[error("callout client build error: {0}")]
    ClientBuild(#[from] reqwest::Error),
}

// -----------------------------------------------------------------------------
// Public types — CircuitBreakerConfig
// -----------------------------------------------------------------------------

/// Circuit breaker configuration for callout requests.
#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    /// Number of consecutive failures to trip the breaker.
    pub consecutive_failures: u32,

    /// Milliseconds to wait before probing after tripping.
    pub recovery_window_ms: u64,
}

// -----------------------------------------------------------------------------
// Public types — CalloutConfig
// -----------------------------------------------------------------------------

/// Configuration for a [`CalloutClient`].
#[derive(Debug, Clone)]
pub struct CalloutConfig {
    /// Optional circuit breaker settings.
    pub circuit_breaker: Option<CircuitBreakerConfig>,

    /// What happens when a callout fails.
    pub failure_mode: FailureMode,

    /// Maximum callout depth for loop prevention.
    pub max_depth: u32,

    /// Maximum idle connections per host in the pool.
    pub pool_max_idle_per_host: usize,

    /// HTTP status code to return when rejecting.
    pub status_on_error: u16,

    /// Request timeout in milliseconds.
    pub timeout_ms: u64,
}

impl Default for CalloutConfig {
    fn default() -> Self {
        Self {
            circuit_breaker: None,
            failure_mode: FailureMode::Closed,
            max_depth: DEFAULT_MAX_DEPTH,
            pool_max_idle_per_host: DEFAULT_POOL_MAX_IDLE_PER_HOST,
            status_on_error: DEFAULT_STATUS_ON_ERROR,
            timeout_ms: DEFAULT_TIMEOUT_MS,
        }
    }
}

// -----------------------------------------------------------------------------
// CalloutClient
// -----------------------------------------------------------------------------

/// Reusable HTTP callout client.
///
/// Wraps a [`reqwest::Client`] with timeout enforcement, circuit breaking,
/// and callout-depth loop prevention. Filters construct one `CalloutClient`
/// at config time and share it across requests.
///
/// # Errors
///
/// Construction fails with [`CalloutError`] if the configuration is invalid
/// or the underlying HTTP client cannot be built.
///
/// # Example
///
/// ```no_run
/// use praxis_core::callout::{CalloutClient, CalloutConfig};
///
/// let client = CalloutClient::new(CalloutConfig::default()).unwrap();
/// ```
#[derive(Debug)]
pub struct CalloutClient {
    /// Optional circuit breaker.
    circuit_breaker: Option<CircuitBreaker>,

    /// The underlying HTTP client.
    client: reqwest::Client,

    /// What to do on failure.
    failure_mode: FailureMode,

    /// Maximum allowed callout depth.
    max_depth: u32,

    /// HTTP status to return in rejections.
    status_on_error: u16,

    /// Request timeout.
    timeout: Duration,
}

impl CalloutClient {
    /// Build a new callout client from configuration.
    ///
    /// # Errors
    ///
    /// Returns [`CalloutError::Config`] if configuration values are invalid,
    /// or [`CalloutError::ClientBuild`] if the HTTP client fails to build.
    pub fn new(config: CalloutConfig) -> Result<Self, CalloutError> {
        validate_config(&config)?;

        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(redirect::Policy::none())
            .pool_max_idle_per_host(config.pool_max_idle_per_host)
            .build()?;

        let circuit_breaker = config
            .circuit_breaker
            .map(|cb| CircuitBreaker::new(cb.consecutive_failures, cb.recovery_window_ms));

        Ok(Self {
            circuit_breaker,
            client,
            failure_mode: config.failure_mode,
            max_depth: config.max_depth,
            status_on_error: config.status_on_error,
            timeout: Duration::from_millis(config.timeout_ms),
        })
    }

    /// Execute a callout request.
    ///
    /// Checks preconditions (depth, circuit breaker), sends the HTTP
    /// request with a timeout, and maps the outcome to a [`CalloutResult`].
    pub async fn execute(&self, request: CalloutRequest) -> CalloutResult {
        if let Some(result) = self.check_preconditions(&request) {
            return result;
        }

        match self.send_request(request).await {
            Ok(response) => self.process_response(response).await,
            Err(reason) => {
                warn!(reason, "callout request failed");
                self.record_failure();
                self.on_failure()
            },
        }
    }

    // -----------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------

    /// Check depth and circuit breaker before sending.
    fn check_preconditions(&self, request: &CalloutRequest) -> Option<CalloutResult> {
        if request.depth >= self.max_depth {
            warn!(
                depth = request.depth,
                max_depth = self.max_depth,
                "callout depth limit reached"
            );
            return Some(self.on_failure());
        }

        if let Some(cb) = &self.circuit_breaker {
            match cb.check() {
                CircuitState::Open => {
                    debug!("circuit breaker open; skipping callout");
                    return Some(self.on_failure());
                },
                CircuitState::HalfOpen => {
                    debug!("circuit breaker half-open; sending probe");
                },
                CircuitState::Closed => {},
            }
        }

        None
    }

    /// Build and send the HTTP request with timeout.
    ///
    /// Takes ownership of the request to avoid cloning the body.
    async fn send_request(&self, request: CalloutRequest) -> Result<reqwest::Response, String> {
        let mut builder = self.client.request(request.method, &request.url);

        for (name, value) in request.headers {
            builder = builder.header(name, value);
        }

        let next_depth = request.depth.saturating_add(1);
        builder = builder.header(DEPTH_HEADER, next_depth.to_string());

        if let Some(body) = request.body {
            builder = builder.body(body);
        }

        tokio::time::timeout(self.timeout, builder.send())
            .await
            .map_err(|_elapsed| "request timed out".to_owned())?
            .map_err(|e| e.to_string())
    }

    /// Map a raw HTTP response to a [`CalloutResult`].
    ///
    /// Takes ownership of the response to consume the body.
    async fn process_response(&self, response: reqwest::Response) -> CalloutResult {
        let status = response.status();
        if !status.is_success() {
            warn!(status = status.as_u16(), "callout received non-2xx response");
            self.record_failure();
            return self.on_failure();
        }

        let headers = extract_headers(&response);
        let body = match response.bytes().await {
            Ok(b) => b.to_vec(),
            Err(err) => {
                warn!(%err, "failed to read callout response body");
                self.record_failure();
                return self.on_failure();
            },
        };

        self.record_success();
        CalloutResult::Success(CalloutResponse {
            body,
            headers,
            status: status.as_u16(),
        })
    }

    /// Map a failure to the configured failure mode.
    fn on_failure(&self) -> CalloutResult {
        match self.failure_mode {
            FailureMode::Closed => CalloutResult::Rejected(Rejection {
                status: self.status_on_error,
            }),
            FailureMode::Open => CalloutResult::Failed,
        }
    }

    /// Record a successful callout to the circuit breaker.
    fn record_success(&self) {
        if let Some(cb) = &self.circuit_breaker {
            cb.record_success();
        }
    }

    /// Record a failed callout to the circuit breaker.
    fn record_failure(&self) {
        if let Some(cb) = &self.circuit_breaker {
            cb.record_failure();
        }
    }
}

// -----------------------------------------------------------------------------
// Free functions
// -----------------------------------------------------------------------------

/// Validate configuration values.
fn validate_config(config: &CalloutConfig) -> Result<(), CalloutError> {
    if config.timeout_ms == 0 {
        return Err(CalloutError::Config("timeout_ms must be greater than 0".into()));
    }

    if config.status_on_error < 100 || config.status_on_error > 599 {
        return Err(CalloutError::Config(format!(
            "status_on_error must be between 100 and 599, got {status}",
            status = config.status_on_error,
        )));
    }

    if let Some(cb) = &config.circuit_breaker {
        if cb.consecutive_failures == 0 {
            return Err(CalloutError::Config(
                "circuit_breaker.consecutive_failures must be greater than 0".into(),
            ));
        }
        if cb.recovery_window_ms == 0 {
            return Err(CalloutError::Config(
                "circuit_breaker.recovery_window_ms must be greater than 0".into(),
            ));
        }
    }

    Ok(())
}

/// Extract headers from a reqwest response.
fn extract_headers(response: &reqwest::Response) -> Vec<(http::HeaderName, http::HeaderValue)> {
    response
        .headers()
        .iter()
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect()
}
