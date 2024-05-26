//! Protocol-tagged filter wrapper for storage in a mixed-protocol pipeline.

use praxis_core::config::ProtocolKind;

use crate::{filter::HttpFilter, tcp_filter::TcpFilter};

// -----------------------------------------------------------------------------
// AnyFilter
// -----------------------------------------------------------------------------

/// A filter of any protocol level, for storage in a pipeline.
///
/// Wraps either an [`HttpFilter`] or a [`TcpFilter`], preserving its
/// protocol level for compatibility checks during pipeline construction.
///
/// [`HttpFilter`]: crate::HttpFilter
/// [`TcpFilter`]: crate::TcpFilter
pub enum AnyFilter {
    /// An HTTP-level filter.
    Http(Box<dyn HttpFilter>),

    /// A TCP-level filter.
    Tcp(Box<dyn TcpFilter>),
}

impl AnyFilter {
    /// The protocol level this filter operates at.
    pub fn protocol_level(&self) -> ProtocolKind {
        match self {
            Self::Http(_) => ProtocolKind::Http,
            Self::Tcp(_) => ProtocolKind::Tcp,
        }
    }

    /// The filter's name.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Http(f) => f.name(),
            Self::Tcp(f) => f.name(),
        }
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use async_trait::async_trait;

    use super::*;
    use crate::{
        actions::FilterAction,
        filter::{FilterError, HttpFilterContext},
    };

    struct StubHttpFilter;

    #[async_trait]
    impl HttpFilter for StubHttpFilter {
        fn name(&self) -> &'static str {
            "stub_http"
        }

        async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
            Ok(FilterAction::Continue)
        }
    }

    struct StubTcpFilter;

    #[async_trait]
    impl TcpFilter for StubTcpFilter {
        fn name(&self) -> &'static str {
            "stub_tcp"
        }
    }

    #[test]
    fn http_variant_protocol_level() {
        let f = AnyFilter::Http(Box::new(StubHttpFilter));
        assert_eq!(
            f.protocol_level(),
            ProtocolKind::Http,
            "Http variant should report Http protocol"
        );
    }

    #[test]
    fn tcp_variant_protocol_level() {
        let f = AnyFilter::Tcp(Box::new(StubTcpFilter));
        assert_eq!(
            f.protocol_level(),
            ProtocolKind::Tcp,
            "Tcp variant should report Tcp protocol"
        );
    }

    #[test]
    fn http_variant_name() {
        let f = AnyFilter::Http(Box::new(StubHttpFilter));
        assert_eq!(
            f.name(),
            "stub_http",
            "Http variant should delegate name to inner filter"
        );
    }

    #[test]
    fn tcp_variant_name() {
        let f = AnyFilter::Tcp(Box::new(StubTcpFilter));
        assert_eq!(f.name(), "stub_tcp", "Tcp variant should delegate name to inner filter");
    }
}
