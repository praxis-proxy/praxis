// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Test-only filters for pipeline capability validation.

use async_trait::async_trait;
use praxis_core::config::{Condition, FailureMode};

use super::filter::PipelineFilter;
use crate::{
    FilterAction, FilterError,
    any_filter::AnyFilter,
    body::{BodyAccess, BodyMode},
    filter::{HttpFilter, HttpFilterContext},
    pipeline::catalog::ClusterMetadataDeclaration,
};

pub(in crate::pipeline) fn selector_filter(name: &'static str, clusters: &[&str]) -> PipelineFilter {
    capability_filter(CapabilityFilter {
        name,
        selected_clusters: owned(clusters),
        selects_cluster: true,
        ..CapabilityFilter::default()
    })
}

pub(in crate::pipeline) fn lb_filter(clusters: &[&str]) -> PipelineFilter {
    capability_filter(CapabilityFilter {
        load_balancer_clusters: owned(clusters),
        name: "load_balancer",
        ..CapabilityFilter::default()
    })
}

pub(in crate::pipeline) fn noop_filter(name: &'static str) -> PipelineFilter {
    capability_filter(CapabilityFilter {
        name,
        ..CapabilityFilter::default()
    })
}

/// A binding router stand-in: selects and *binds* one of `clusters` as the
/// logical upstream.
pub(in crate::pipeline) fn binding_router(clusters: &[&str]) -> PipelineFilter {
    capability_filter(CapabilityFilter {
        name: "router",
        selected_clusters: owned(clusters),
        selects_cluster: true,
        binds_upstream: true,
        ..CapabilityFilter::default()
    })
}

/// A bound-consuming load balancer stand-in: resolves `clusters` from the
/// frozen logical binding.
pub(in crate::pipeline) fn bound_lb(clusters: &[&str]) -> PipelineFilter {
    capability_filter(CapabilityFilter {
        name: "load_balancer",
        load_balancer_clusters: owned(clusters),
        consumes_bound_upstream: true,
        bound_upstream_clusters: owned(clusters),
        ..CapabilityFilter::default()
    })
}

/// A filter participating in the bound-upstream request-body phase with the
/// given access and delivery mode.
pub(in crate::pipeline) fn bound_body_filter(name: &'static str, access: BodyAccess, mode: BodyMode) -> PipelineFilter {
    capability_filter(CapabilityFilter {
        name,
        bound_upstream_request_body_access: access,
        request_body_mode: Some(mode),
        ..CapabilityFilter::default()
    })
}

/// A filter declaring application metadata for one cluster, standing in for a
/// load balancer in catalog tests.
pub(in crate::pipeline) fn metadata_filter(
    name: &'static str,
    cluster: &str,
    protocol: Option<&str>,
    provider: Option<&str>,
) -> PipelineFilter {
    use std::sync::Arc;

    use crate::pipeline::catalog::ClusterApplicationMetadata;

    capability_filter(CapabilityFilter {
        name,
        declared_metadata: vec![ClusterMetadataDeclaration {
            name: Arc::from(cluster),
            metadata: ClusterApplicationMetadata::new(protocol.map(Arc::from), provider.map(Arc::from)),
        }],
        ..CapabilityFilter::default()
    })
}

fn owned(clusters: &[&str]) -> Vec<String> {
    clusters.iter().map(|cluster| (*cluster).to_owned()).collect()
}

pub(in crate::pipeline) fn noop_filter_with_conditions(
    name: &'static str,
    conditions: Vec<Condition>,
) -> PipelineFilter {
    let mut filter = noop_filter(name);
    filter.conditions = conditions;
    filter
}

fn capability_filter(filter: CapabilityFilter) -> PipelineFilter {
    PipelineFilter {
        filter_id: 0,
        is_security: false,
        branches: vec![],
        conditions: vec![],
        failure_mode: FailureMode::default(),
        filter: AnyFilter::Http(Box::new(filter)),
        name: None,
        response_conditions: vec![],
    }
}

#[derive(Default)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "test-only capability record; each flag toggles one independent HttpFilter capability"
)]
struct CapabilityFilter {
    name: &'static str,
    selects_cluster: bool,
    selected_clusters: Vec<String>,
    load_balancer_clusters: Vec<String>,
    binds_upstream: bool,
    consumes_bound_upstream: bool,
    bound_upstream_clusters: Vec<String>,
    bound_upstream_request_body_access: BodyAccess,
    request_body_access: BodyAccess,
    request_body_mode: Option<BodyMode>,
    declared_metadata: Vec<ClusterMetadataDeclaration>,
}

#[async_trait]
impl HttpFilter for CapabilityFilter {
    fn name(&self) -> &'static str {
        self.name
    }

    fn selects_cluster(&self) -> bool {
        self.selects_cluster
    }

    fn selected_clusters(&self) -> Vec<String> {
        self.selected_clusters.clone()
    }

    fn load_balancer_clusters(&self) -> Vec<String> {
        self.load_balancer_clusters.clone()
    }

    fn binds_upstream(&self) -> bool {
        self.binds_upstream
    }

    fn consumes_bound_upstream(&self) -> bool {
        self.consumes_bound_upstream
    }

    fn bound_upstream_clusters(&self) -> Vec<String> {
        self.bound_upstream_clusters.clone()
    }

    fn bound_upstream_request_body_access(&self) -> BodyAccess {
        self.bound_upstream_request_body_access
    }

    fn request_body_access(&self) -> BodyAccess {
        self.request_body_access
    }

    fn request_body_mode(&self) -> BodyMode {
        self.request_body_mode.unwrap_or_default()
    }

    fn declared_cluster_metadata(&self) -> Vec<ClusterMetadataDeclaration> {
        self.declared_metadata.clone()
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }
}

pub(in crate::pipeline) fn streaming_capable_filter() -> PipelineFilter {
    PipelineFilter {
        filter_id: 0,
        is_security: false,
        branches: vec![],
        conditions: vec![],
        failure_mode: FailureMode::default(),
        filter: AnyFilter::Http(Box::new(StreamingCapableFilter)),
        name: None,
        response_conditions: vec![],
    }
}

struct StreamingCapableFilter;

#[async_trait]
impl HttpFilter for StreamingCapableFilter {
    fn name(&self) -> &'static str {
        "streaming_capable"
    }

    fn may_select_streaming_subrequest_response(&self) -> bool {
        true
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }
}
