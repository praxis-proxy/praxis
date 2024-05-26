//! The [`HttpFilter`] trait definition.
//!
//! Every HTTP filter implements this trait.

use async_trait::async_trait;
use bytes::Bytes;

pub(crate) use crate::context::HttpFilterContext;
use crate::{
    actions::FilterAction,
    body::{BodyAccess, BodyMode},
    compression_config::CompressionConfig,
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
///     fn name(&self) -> &'static str { "noop" }
///     async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
///         Ok(FilterAction::Continue)
///     }
/// }
///
/// let filter = NoopFilter;
/// assert_eq!(filter.name(), "noop");
/// ```
#[async_trait]
pub trait HttpFilter: Send + Sync {
    /// Unique name identifying this filter type (e.g. `"router"`, `"rate_limiter"`).
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

    // ---------------------------------------------------------
    // Body Access Declarations
    // ---------------------------------------------------------

    /// Declares what access this filter needs to request bodies.
    ///
    /// Default: [`BodyAccess::None`]
    fn request_body_access(&self) -> BodyAccess {
        BodyAccess::None
    }

    /// Declares what access this filter needs to response bodies.
    ///
    /// Default: [`BodyAccess::None`]
    fn response_body_access(&self) -> BodyAccess {
        BodyAccess::None
    }

    /// Declares the delivery mode for request body chunks.
    ///
    /// Default: [`BodyMode::Stream`]
    fn request_body_mode(&self) -> BodyMode {
        BodyMode::Stream
    }

    /// Declares the delivery mode for response body chunks.
    ///
    /// Default: [`BodyMode::Stream`]
    fn response_body_mode(&self) -> BodyMode {
        BodyMode::Stream
    }

    /// Whether this filter needs the original request context during body phases.
    fn needs_request_context(&self) -> bool {
        false
    }

    /// Returns the compression configuration if this filter enables
    /// response compression. Only [`CompressionFilter`] overrides
    /// this; all other filters return `None`.
    ///
    /// Default: `None`
    ///
    /// [`CompressionFilter`]: crate::CompressionFilter
    fn compression_config(&self) -> Option<&CompressionConfig> {
        None
    }

    // ---------------------------------------------------------
    // Body Hooks
    // ---------------------------------------------------------

    /// Called for each chunk of request body data, in pipeline order.
    ///
    /// Default: Passthrough
    async fn on_request_body(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        let _ = (ctx, body, end_of_stream);
        Ok(FilterAction::Continue)
    }

    /// Called for each chunk of response body data, in reverse pipeline order.
    ///
    /// Default: passthrough, returns [`FilterAction::Continue`]
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
mod tests {
    use async_trait::async_trait;

    use super::*;
    use crate::{FilterAction, FilterError};

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
}
