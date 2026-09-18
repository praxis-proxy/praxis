// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! gRPC deadline filter: honour and propagate `grpc-timeout`.

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests"
)]
mod tests;

use std::time::Duration;

use async_trait::async_trait;
use praxis_core::grpc::{GrpcDeadline, GrpcKind, GrpcStatusCode, GrpcTimeout, MAX_DEADLINE_MS};
use serde::Deserialize;
use tracing::{trace, warn};

use crate::{
    FilterAction, FilterError, Rejection,
    filter::{HttpFilter, HttpFilterContext},
    parse_filter_config,
};

// -----------------------------------------------------------------------------
// Config
// -----------------------------------------------------------------------------

/// How to treat a `grpc-timeout` header the proxy cannot parse.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum InvalidTimeoutAction {
    /// Answer `INTERNAL` without contacting the upstream, as gRPC
    /// implementations do.
    #[default]
    Reject,

    /// Treat the header as absent and fall back to the default timeout.
    Ignore,
}

/// Configuration for the `grpc_timeout` filter.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GrpcTimeoutConfig {
    /// Deadline applied when a request carries no `grpc-timeout` header.
    ///
    /// Omit to leave header-less gRPC calls unbounded.
    #[serde(default)]
    default_timeout_ms: Option<u64>,

    /// Budget withheld from the upstream so the proxy can answer
    /// `DEADLINE_EXCEEDED` before the client's own timer fires.
    #[serde(default)]
    headroom_ms: u64,

    /// Ceiling applied to any client-supplied deadline.
    max_timeout_ms: u64,

    /// What to do with a malformed `grpc-timeout` value.
    #[serde(default)]
    on_invalid: InvalidTimeoutAction,

    /// Whether to rewrite `grpc-timeout` on the upstream request.
    #[serde(default = "default_propagate")]
    propagate: bool,
}

/// Propagation is on by default: a deadline the upstream cannot see
/// leaves it working on a call nobody is waiting for.
const fn default_propagate() -> bool {
    true
}

// -----------------------------------------------------------------------------
// Filter
// -----------------------------------------------------------------------------

/// Honours the `grpc-timeout` request header as a real deadline.
///
/// gRPC clients express a per-call deadline in `grpc-timeout`. Without
/// this filter Praxis forwards the header untouched and applies only its
/// static cluster timeouts, so a client that asked for 100ms can wait on
/// a 30-second upstream read, and each retry restarts the clock.
///
/// The filter clamps the requested deadline to `max_timeout_ms`, holds
/// it as an absolute instant for the life of the request, shrinks every
/// upstream attempt's connect and read budget to what is left, and
/// rewrites `grpc-timeout` upstream with the remaining time. A call that
/// is already past its deadline is answered `DEADLINE_EXCEEDED` without
/// contacting the upstream at all.
///
/// Non-gRPC requests pass through untouched, so the filter is safe on a
/// listener carrying mixed traffic.
///
/// # YAML
///
/// ```yaml
/// filter: grpc_timeout
/// max_timeout_ms: 30000      # ceiling, whatever the client asks for
/// default_timeout_ms: 10000  # optional: applied when the header is absent
/// headroom_ms: 50            # optional: budget kept back for the proxy
/// propagate: true            # optional: rewrite grpc-timeout upstream
/// on_invalid: reject         # optional: reject | ignore
/// ```
pub struct GrpcTimeoutFilter {
    /// Deadline for requests with no `grpc-timeout` header.
    default_timeout: Option<Duration>,

    /// Budget withheld from the upstream.
    headroom: Duration,

    /// Ceiling applied to a client-supplied deadline.
    max_timeout: Duration,

    /// Behaviour on a malformed `grpc-timeout` value.
    on_invalid: InvalidTimeoutAction,

    /// Whether to rewrite `grpc-timeout` upstream.
    propagate: bool,
}

impl GrpcTimeoutFilter {
    /// Create a filter from parsed YAML config.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if the YAML config is invalid.
    pub fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        let cfg: GrpcTimeoutConfig = parse_filter_config("grpc_timeout", config)?;
        Ok(Box::new(Self::build(&cfg)?))
    }

    /// Validate config and build the runtime filter.
    fn build(cfg: &GrpcTimeoutConfig) -> Result<Self, FilterError> {
        validate(cfg)?;
        Ok(Self {
            default_timeout: cfg.default_timeout_ms.map(Duration::from_millis),
            headroom: Duration::from_millis(cfg.headroom_ms),
            max_timeout: Duration::from_millis(cfg.max_timeout_ms),
            on_invalid: cfg.on_invalid,
            propagate: cfg.propagate,
        })
    }

    /// The deadline this request asked for, if any.
    ///
    /// `Err` means the request must be rejected outright.
    fn requested_timeout(&self, ctx: &HttpFilterContext<'_>) -> Result<Option<Duration>, Rejection> {
        match GrpcTimeout::from_headers(&ctx.request.headers) {
            Some(Ok(timeout)) => Ok(Some(timeout.as_duration())),
            Some(Err(error)) => match self.on_invalid {
                InvalidTimeoutAction::Reject => {
                    warn!(%error, "rejecting gRPC request with a malformed grpc-timeout");
                    Err(grpc_rejection(GrpcStatusCode::Internal, "malformed grpc-timeout"))
                },
                InvalidTimeoutAction::Ignore => {
                    trace!(%error, "ignoring malformed grpc-timeout");
                    Ok(self.default_timeout)
                },
            },
            None => Ok(self.default_timeout),
        }
    }

    /// Clamp the requested timeout, install it as an absolute deadline,
    /// and tell the upstream what is left of it.
    fn install_deadline(&self, ctx: &mut HttpFilterContext<'_>, requested: Duration) -> FilterAction {
        let clamped = requested > self.max_timeout;
        let budget = requested.min(self.max_timeout).saturating_sub(self.headroom);

        // The deadline runs from when the request arrived, not from here:
        // time already spent in earlier filters comes out of the client's
        // budget too.
        let spent = ctx.request_start.elapsed();
        let Some(remaining) = budget.checked_sub(spent).filter(|left| !left.is_zero()) else {
            warn!("gRPC deadline already exceeded before the upstream was contacted");
            return FilterAction::Reject(grpc_rejection(GrpcStatusCode::DeadlineExceeded, "deadline exceeded"));
        };

        // `checked_add` cannot realistically fail: `budget` is bounded by
        // the validated one-hour ceiling.
        let Some(deadline) = ctx.request_start.checked_add(budget) else {
            warn!("gRPC deadline is not representable; leaving the request unbounded");
            return FilterAction::Continue;
        };
        ctx.extensions
            .insert(GrpcDeadline::new(deadline, clamped, self.propagate));

        ctx.set_metadata("grpc.deadline_ms", remaining.as_millis().to_string());
        trace!(
            deadline_ms = remaining.as_millis(),
            clamped, "gRPC deadline established"
        );
        FilterAction::Continue
    }
}

/// Reject a configuration that could never behave sensibly.
fn validate(cfg: &GrpcTimeoutConfig) -> Result<(), FilterError> {
    validate_bounds(cfg)?;
    validate_relative(cfg)
}

/// Reject timeouts that are zero or past the proxy-wide ceiling.
fn validate_bounds(cfg: &GrpcTimeoutConfig) -> Result<(), FilterError> {
    if cfg.max_timeout_ms == 0 {
        return Err("grpc_timeout: max_timeout_ms must be greater than 0".into());
    }
    if cfg.max_timeout_ms > MAX_DEADLINE_MS {
        return Err(format!(
            "grpc_timeout: max_timeout_ms ({}) exceeds the {MAX_DEADLINE_MS}ms ceiling",
            cfg.max_timeout_ms
        )
        .into());
    }
    if cfg.default_timeout_ms == Some(0) {
        return Err("grpc_timeout: default_timeout_ms must be greater than 0".into());
    }
    Ok(())
}

/// Reject settings that contradict each other.
fn validate_relative(cfg: &GrpcTimeoutConfig) -> Result<(), FilterError> {
    if let Some(default_ms) = cfg.default_timeout_ms
        && default_ms > cfg.max_timeout_ms
    {
        return Err(format!(
            "grpc_timeout: default_timeout_ms ({default_ms}) exceeds max_timeout_ms ({}); \
             it would be silently clamped",
            cfg.max_timeout_ms
        )
        .into());
    }
    if let Some(default_ms) = cfg.default_timeout_ms
        && default_ms <= cfg.headroom_ms
    {
        return Err(format!(
            "grpc_timeout: default_timeout_ms ({default_ms}) must exceed headroom_ms ({}); \
             every header-less request would be born expired",
            cfg.headroom_ms
        )
        .into());
    }
    if cfg.headroom_ms >= cfg.max_timeout_ms {
        return Err(format!(
            "grpc_timeout: headroom_ms ({}) must be less than max_timeout_ms ({}); \
             every request would be born expired",
            cfg.headroom_ms, cfg.max_timeout_ms
        )
        .into());
    }
    Ok(())
}

#[async_trait]
impl HttpFilter for GrpcTimeoutFilter {
    fn name(&self) -> &'static str {
        "grpc_timeout"
    }

    async fn on_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        // Classify from the content-type directly rather than depending on
        // grpc_detection running first, so the filter works at any position.
        if !GrpcKind::from_headers(&ctx.request.headers).is_grpc() {
            return Ok(FilterAction::Continue);
        }

        let requested = match self.requested_timeout(ctx) {
            Ok(Some(requested)) => requested,
            Ok(None) => return Ok(FilterAction::Continue),
            Err(rejection) => return Ok(FilterAction::Reject(rejection)),
        };
        Ok(self.install_deadline(ctx, requested))
    }

    async fn on_response(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        let Some(deadline) = ctx.extensions.get::<GrpcDeadline>().copied() else {
            return Ok(FilterAction::Continue);
        };
        if deadline.is_expired() {
            warn!("gRPC deadline exceeded while waiting for the upstream response");
            return Ok(FilterAction::Reject(grpc_rejection(
                GrpcStatusCode::DeadlineExceeded,
                "deadline exceeded",
            )));
        }
        Ok(FilterAction::Continue)
    }
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/// Build a Trailers-Only gRPC response carrying `code` and `message`.
///
/// gRPC reports call failures with HTTP 200 and a `grpc-status`: a real
/// HTTP error status would surface to the client as `UNKNOWN` or a
/// transport error instead of the code Praxis chose. The messages here
/// are plain ASCII with no reserved characters, so they need no
/// percent-encoding.
fn grpc_rejection(code: GrpcStatusCode, message: &str) -> Rejection {
    Rejection::status(200)
        .with_header("content-type", "application/grpc")
        // Without an explicit length an HTTP/1.1 client reads a body-less
        // 200 until EOF, and keepalive means EOF never comes.
        .with_header("content-length", "0")
        .with_header("grpc-status", code.as_u32().to_string())
        .with_header("grpc-message", message)
        .preserving_keepalive()
}
