// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! The [`HttpFilter`] trait definition.
//!
//! Every HTTP filter implements this trait.

use async_trait::async_trait;
use bytes::Bytes;
use praxis_core::config::InsecureOptions;

pub(crate) use crate::context::HttpFilterContext;
use crate::{
    actions::FilterAction,
    body::{BodyAccess, BodyMode},
    builtins::http::payload_processing::compression_config::CompressionConfig,
};

// -----------------------------------------------------------------------------
// Backward-compatible Aliases
// -----------------------------------------------------------------------------

/// Backward-compatible alias for [`HttpFilter`].
pub type Filter = dyn HttpFilter;

/// Backward-compatible alias for [`HttpFilterContext`].
///
/// [`HttpFilterContext`]: crate::context::HttpFilterContext
pub type FilterContext<'a> = HttpFilterContext<'a>;

// -----------------------------------------------------------------------------
// HttpFilter Trait
// -----------------------------------------------------------------------------

/// A filter that participates in HTTP request/response processing.
///
/// # Example
///
/// ```
/// use async_trait::async_trait;
/// use praxis_filter::{FilterAction, FilterError, HttpFilter, HttpFilterContext};
///
/// struct NoopFilter;
///
/// #[async_trait]
/// impl HttpFilter for NoopFilter {
///     fn name(&self) -> &'static str {
///         "noop"
///     }
///
///     async fn on_request(
///         &self,
///         _ctx: &mut HttpFilterContext<'_>,
///     ) -> Result<FilterAction, FilterError> {
///         Ok(FilterAction::Continue)
///     }
/// }
///
/// let filter = NoopFilter;
/// assert_eq!(filter.name(), "noop");
/// ```
#[async_trait]
pub trait HttpFilter: Send + Sync {
    /// Unique name identifying this filter type (e.g. `"router"`, `"rate_limit"`).
    fn name(&self) -> &'static str;

    /// Called for each incoming request, in pipeline order.
    async fn on_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError>;

    /// Called for each response, in reverse pipeline order.
    ///
    /// Default: [`FilterAction::Continue`]
    async fn on_response(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        let _ = ctx;
        Ok(FilterAction::Continue)
    }

    // -------------------------------------------------------------------------
    // Body Access Declarations
    // -------------------------------------------------------------------------

    /// Declares what access this filter needs to request bodies.
    ///
    /// Return [`BodyAccess::None`] (the default) when the filter
    /// does not inspect or modify request bodies. Return
    /// [`BodyAccess::ReadOnly`] to receive body chunks in
    /// [`on_request_body`] without modification rights, or
    /// [`BodyAccess::ReadWrite`] to mutate body bytes in place.
    ///
    /// [`on_request_body`]: HttpFilter::on_request_body
    fn request_body_access(&self) -> BodyAccess {
        BodyAccess::None
    }

    /// Declares what access this filter needs to response bodies.
    ///
    /// Return [`BodyAccess::None`] (the default) when the filter
    /// does not inspect or modify response bodies. Return
    /// [`BodyAccess::ReadOnly`] to receive body chunks in
    /// [`on_response_body`] without modification rights, or
    /// [`BodyAccess::ReadWrite`] to mutate body bytes in place.
    ///
    /// [`on_response_body`]: HttpFilter::on_response_body
    fn response_body_access(&self) -> BodyAccess {
        BodyAccess::None
    }

    /// Declares the delivery mode for request body chunks.
    ///
    /// [`BodyMode::Stream`] (the default) delivers chunks as they
    /// arrive with minimal latency. [`BodyMode::StreamBuffer`]
    /// accumulates chunks and defers forwarding until the filter
    /// calls [`FilterAction::Release`] or end-of-stream; use this
    /// when the filter needs the full body before making a decision
    /// (e.g. JSON parsing for routing).
    ///
    /// [`FilterAction::Release`]: crate::FilterAction::Release
    fn request_body_mode(&self) -> BodyMode {
        BodyMode::Stream
    }

    /// Declares the delivery mode for response body chunks.
    ///
    /// [`BodyMode::Stream`] (the default) delivers chunks as they
    /// arrive with minimal latency. [`BodyMode::StreamBuffer`]
    /// accumulates chunks and defers forwarding until the filter
    /// calls [`FilterAction::Release`] or end-of-stream; use this
    /// when the filter needs the complete response body (e.g.
    /// response persistence).
    ///
    /// [`FilterAction::Release`]: crate::FilterAction::Release
    fn response_body_mode(&self) -> BodyMode {
        BodyMode::Stream
    }

    /// Whether this filter needs the original request context
    /// during body phases.
    ///
    /// When `true`, the pipeline preserves the original request
    /// headers and URI so they are available in [`on_request_body`]
    /// and [`on_response_body`]. Enable this when body-phase
    /// decisions depend on request metadata (method, path, headers).
    ///
    /// [`on_request_body`]: HttpFilter::on_request_body
    /// [`on_response_body`]: HttpFilter::on_response_body
    fn needs_request_context(&self) -> bool {
        false
    }

    /// Apply global [`InsecureOptions`] to this filter.
    ///
    /// Filters that support insecure overrides (e.g. CSRF
    /// log-only mode) override this. Default: no-op.
    ///
    /// [`InsecureOptions`]: praxis_core::config::InsecureOptions
    fn apply_insecure_options(&self, _options: &InsecureOptions) {}

    /// Returns the compression configuration if this filter enables
    /// response compression.
    ///
    /// Return `Some` to activate response compression with the
    /// given algorithm and level settings. Return `None` (the
    /// default) to leave compression unmodified. Only one filter
    /// in a pipeline should return `Some`.
    fn compression_config(&self) -> Option<&CompressionConfig> {
        None
    }

    // -------------------------------------------------------------------------
    // Body Hooks
    // -------------------------------------------------------------------------

    /// Called for each chunk of request body data, in pipeline order.
    ///
    /// `body` contains the current chunk (`None` when empty).
    /// `end_of_stream` is `true` on the final chunk. Filters may
    /// safely modify `body` before `end_of_stream` when using
    /// [`BodyAccess::ReadWrite`]; buffered modes guarantee all
    /// bytes arrive in a single call with `end_of_stream = true`.
    /// Return [`FilterAction::Reject`] to abort with an error
    /// response.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if body processing fails. The
    /// pipeline converts errors into 500 responses.
    ///
    /// [`FilterAction::Reject`]: crate::FilterAction::Reject
    async fn on_request_body(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        let _ = (ctx, body, end_of_stream);
        Ok(FilterAction::Continue)
    }

    /// Called for each chunk of response body data, in reverse
    /// pipeline order.
    ///
    /// `body` contains the current chunk (`None` when empty).
    /// `end_of_stream` is `true` on the final chunk. Filters may
    /// safely modify `body` before `end_of_stream` when using
    /// [`BodyAccess::ReadWrite`]; buffered modes guarantee all
    /// bytes arrive in a single call with `end_of_stream = true`.
    /// Return [`FilterAction::Reject`] to abort with an error
    /// response.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if body processing fails. The
    /// pipeline converts errors into 502 responses.
    ///
    /// [`FilterAction::Reject`]: crate::FilterAction::Reject
    fn on_response_body(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        let _ = (ctx, body, end_of_stream);
        Ok(FilterAction::Continue)
    }
}

/// Boxed error type for filter results.
pub type FilterError = Box<dyn std::error::Error + Send + Sync>;

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
    reason = "tests"
)]
mod tests {
    use async_trait::async_trait;

    use super::*;
    use crate::{FilterAction, FilterError};

    #[tokio::test]
    async fn default_on_response_returns_continue() {
        let filter = MinimalFilter;
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let action = filter.on_response(&mut ctx).await.unwrap();

        assert!(
            matches!(action, FilterAction::Continue),
            "default on_response should return Continue"
        );
    }

    #[test]
    fn default_body_access_is_none() {
        let filter = MinimalFilter;
        assert_eq!(
            filter.request_body_access(),
            BodyAccess::None,
            "default request body access should be None"
        );
        assert_eq!(
            filter.response_body_access(),
            BodyAccess::None,
            "default response body access should be None"
        );
        assert_eq!(
            filter.request_body_mode(),
            BodyMode::Stream,
            "default request body mode should be Stream"
        );
        assert_eq!(
            filter.response_body_mode(),
            BodyMode::Stream,
            "default response body mode should be Stream"
        );
        assert!(
            !filter.needs_request_context(),
            "default needs_request_context should be false"
        );
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// Minimal filter for verifying trait defaults.
    struct MinimalFilter;

    #[async_trait]
    impl HttpFilter for MinimalFilter {
        fn name(&self) -> &'static str {
            "minimal"
        }

        async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
            Ok(FilterAction::Continue)
        }
    }
}
