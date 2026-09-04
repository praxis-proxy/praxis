// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

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
    /// The filter's name.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Http(f) => f.name(),
            Self::Tcp(f) => f.name(),
        }
    }

    /// Filesystem paths this filter reads configuration from, beyond the main
    /// Praxis config. Empty for TCP filters, which have no such surface.
    pub fn referenced_files(&self) -> Vec<std::path::PathBuf> {
        match self {
            Self::Http(f) => f.referenced_files(),
            Self::Tcp(_) => Vec::new(),
        }
    }

    /// The protocol level this filter operates at.
    pub fn protocol_level(&self) -> ProtocolKind {
        match self {
            Self::Http(_) => ProtocolKind::Http,
            Self::Tcp(_) => ProtocolKind::Tcp,
        }
    }

    /// Whether the filter can assign an upstream cluster.
    pub fn selects_cluster(&self) -> bool {
        match self {
            Self::Http(f) => f.selects_cluster(),
            Self::Tcp(_) => false,
        }
    }

    /// Cluster names this filter may assign.
    pub fn selected_clusters(&self) -> Vec<String> {
        match self {
            Self::Http(f) => f.selected_clusters(),
            Self::Tcp(_) => Vec::new(),
        }
    }

    /// Cluster names this filter can load balance.
    pub fn load_balancer_clusters(&self) -> Vec<String> {
        match self {
            Self::Http(f) => f.load_balancer_clusters(),
            Self::Tcp(_) => Vec::new(),
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

    #[test]
    fn http_variant_cluster_capabilities_delegate_to_inner_filter() {
        let f = AnyFilter::Http(Box::new(ClusterSelectingHttpFilter));
        assert!(f.selects_cluster(), "Http variant should delegate selects_cluster");
        assert_eq!(
            f.selected_clusters(),
            vec!["web".to_owned()],
            "Http variant should delegate selected_clusters"
        );
        assert_eq!(
            f.load_balancer_clusters(),
            vec!["web".to_owned(), "api".to_owned()],
            "Http variant should delegate load_balancer_clusters"
        );
    }

    #[test]
    fn http_variant_default_cluster_capabilities_are_empty() {
        let f = AnyFilter::Http(Box::new(StubHttpFilter));
        assert!(
            !f.selects_cluster(),
            "Http variant should default to no cluster selection"
        );
        assert!(
            f.selected_clusters().is_empty(),
            "Http variant should default to no selected clusters"
        );
        assert!(
            f.load_balancer_clusters().is_empty(),
            "Http variant should default to no load-balancer clusters"
        );
    }

    #[test]
    fn tcp_variant_has_no_http_cluster_capabilities() {
        let f = AnyFilter::Tcp(Box::new(StubTcpFilter));
        assert!(
            !f.selects_cluster(),
            "Tcp variant should not report HTTP cluster selection"
        );
        assert!(
            f.selected_clusters().is_empty(),
            "Tcp variant should not report selected HTTP clusters"
        );
        assert!(
            f.load_balancer_clusters().is_empty(),
            "Tcp variant should not report HTTP load-balancer clusters"
        );
    }

    #[test]
    fn http_variant_referenced_files_delegate_to_inner_filter() {
        let f = AnyFilter::Http(Box::new(ReferencingHttpFilter));
        assert_eq!(
            f.referenced_files(),
            vec![std::path::PathBuf::from("/etc/praxis/policy.yaml")],
            "Http variant should delegate referenced_files"
        );
    }

    #[test]
    fn http_variant_default_referenced_files_is_empty() {
        let f = AnyFilter::Http(Box::new(StubHttpFilter));
        assert!(
            f.referenced_files().is_empty(),
            "Http variant should default to no referenced files"
        );
    }

    /// TCP filters have no external-config surface, so the variant answers empty
    /// without consulting the inner filter.
    #[test]
    fn tcp_variant_has_no_referenced_files() {
        let f = AnyFilter::Tcp(Box::new(StubTcpFilter));
        assert!(
            f.referenced_files().is_empty(),
            "Tcp variant should not report referenced files"
        );
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// Stub HTTP filter for protocol level tests.
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

    /// Stub HTTP filter with pipeline cluster capabilities.
    struct ClusterSelectingHttpFilter;

    #[async_trait]
    impl HttpFilter for ClusterSelectingHttpFilter {
        fn name(&self) -> &'static str {
            "cluster_http"
        }

        fn selects_cluster(&self) -> bool {
            true
        }

        fn selected_clusters(&self) -> Vec<String> {
            vec!["web".to_owned()]
        }

        fn load_balancer_clusters(&self) -> Vec<String> {
            vec!["web".to_owned(), "api".to_owned()]
        }

        async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
            Ok(FilterAction::Continue)
        }
    }

    /// Stub HTTP filter that reads config from an external document.
    struct ReferencingHttpFilter;

    #[async_trait]
    impl HttpFilter for ReferencingHttpFilter {
        fn name(&self) -> &'static str {
            "referencing_http"
        }

        fn referenced_files(&self) -> Vec<std::path::PathBuf> {
            vec![std::path::PathBuf::from("/etc/praxis/policy.yaml")]
        }

        async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
            Ok(FilterAction::Continue)
        }
    }

    /// Stub TCP filter for protocol level tests.
    struct StubTcpFilter;

    #[async_trait]
    impl TcpFilter for StubTcpFilter {
        fn name(&self) -> &'static str {
            "stub_tcp"
        }
    }
}
