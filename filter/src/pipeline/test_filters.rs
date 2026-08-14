// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Test-only filters for pipeline capability validation.

use async_trait::async_trait;
use praxis_core::config::{Condition, FailureMode};

use super::filter::PipelineFilter;
use crate::{
    FilterAction, FilterError,
    any_filter::AnyFilter,
    filter::{HttpFilter, HttpFilterContext},
};

pub(in crate::pipeline) fn selector_filter(name: &'static str, clusters: &[&str]) -> PipelineFilter {
    capability_filter(CapabilityFilter {
        load_balancer_clusters: vec![],
        name,
        selected_clusters: clusters.iter().map(|cluster| (*cluster).to_owned()).collect(),
        selects_cluster: true,
    })
}

pub(in crate::pipeline) fn lb_filter(clusters: &[&str]) -> PipelineFilter {
    capability_filter(CapabilityFilter {
        load_balancer_clusters: clusters.iter().map(|cluster| (*cluster).to_owned()).collect(),
        name: "load_balancer",
        selected_clusters: vec![],
        selects_cluster: false,
    })
}

pub(in crate::pipeline) fn noop_filter(name: &'static str) -> PipelineFilter {
    capability_filter(CapabilityFilter {
        load_balancer_clusters: vec![],
        name,
        selected_clusters: vec![],
        selects_cluster: false,
    })
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
        branches: vec![],
        conditions: vec![],
        failure_mode: FailureMode::default(),
        filter: AnyFilter::Http(Box::new(filter)),
        name: None,
        response_conditions: vec![],
    }
}

struct CapabilityFilter {
    load_balancer_clusters: Vec<String>,
    name: &'static str,
    selected_clusters: Vec<String>,
    selects_cluster: bool,
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

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }
}

pub(in crate::pipeline) fn streaming_capable_filter() -> PipelineFilter {
    PipelineFilter {
        filter_id: 0,
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
