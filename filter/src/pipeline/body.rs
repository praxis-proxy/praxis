// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Body capabilities computation for filter pipelines.

use praxis_core::config::ResponseCondition;

use super::filter::PipelineFilter;
use crate::{
    any_filter::AnyFilter,
    body::{BodyAccess, BodyCapabilities, BodyMode},
};

// -----------------------------------------------------------------------------
// Body Mode Merging
// -----------------------------------------------------------------------------

/// Merge two optional size limits, keeping the smallest `Some` value.
pub(super) fn merge_optional_limits(a: Option<usize>, b: Option<usize>) -> Option<usize> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.min(y)),
        (Some(x), None) | (None, Some(x)) => Some(x),
        (None, None) => None,
    }
}

/// Merge a filter's body mode into the current accumulated mode.
///
/// Precedence: `Buffer` > `StreamBuffer` > `SizeLimit` > `Stream`.
/// When two modes of the same variant merge, the stricter (smaller)
/// limit wins. `SizeLimit` is treated as equivalent to `Stream`
/// from a filter perspective (filters never request it directly).
pub(crate) fn merge_body_mode(current: &mut BodyMode, filter_mode: BodyMode) {
    match filter_mode {
        BodyMode::Buffer { max_bytes } => {
            *current = match *current {
                BodyMode::Stream | BodyMode::SizeLimit { .. } | BodyMode::StreamBuffer { .. } => {
                    BodyMode::Buffer { max_bytes }
                },
                BodyMode::Buffer { max_bytes: existing } => BodyMode::Buffer {
                    max_bytes: existing.min(max_bytes),
                },
            };
        },
        BodyMode::StreamBuffer { max_bytes } => {
            *current = match *current {
                BodyMode::Stream | BodyMode::SizeLimit { .. } => BodyMode::StreamBuffer { max_bytes },
                BodyMode::StreamBuffer { max_bytes: existing } => BodyMode::StreamBuffer {
                    max_bytes: merge_optional_limits(existing, max_bytes),
                },
                BodyMode::Buffer { .. } => *current,
            };
        },
        BodyMode::SizeLimit { .. } | BodyMode::Stream => {},
    }
}

// -----------------------------------------------------------------------------
// Body Capabilities
// -----------------------------------------------------------------------------

/// Merge all filters' body access declarations into a single capability set.
pub(super) fn compute_body_capabilities(filters: &[PipelineFilter]) -> BodyCapabilities {
    let mut caps = BodyCapabilities::default();
    accumulate_caps(&mut caps, filters);
    caps
}

/// Recursively accumulate body capabilities from a slice of pipeline filters.
pub(super) fn accumulate_caps(caps: &mut BodyCapabilities, filters: &[PipelineFilter]) {
    for pf in filters {
        let http_filter = match &pf.filter {
            AnyFilter::Http(f) => f.as_ref(),
            AnyFilter::Tcp(_) => continue,
        };

        accumulate_request_body(caps, http_filter);
        accumulate_response_body(caps, http_filter);

        if http_filter.needs_request_context() {
            caps.needs_request_context = true;
        }
        if !caps.any_response_condition_uses_headers {
            caps.any_response_condition_uses_headers = resp_conditions_use_headers(&pf.response_conditions);
        }

        for branch in &pf.branches {
            accumulate_caps(caps, &branch.filters);
        }
    }
}

/// Accumulate request body capabilities from a single filter.
fn accumulate_request_body(caps: &mut BodyCapabilities, filter: &dyn crate::filter::HttpFilter) {
    let access = filter.request_body_access();
    if access != BodyAccess::None {
        caps.needs_request_body = true;
        if access == BodyAccess::ReadWrite {
            caps.any_request_body_writer = true;
        }
        merge_body_mode(&mut caps.request_body_mode, filter.request_body_mode());
    }
}

/// Accumulate response body capabilities from a single filter.
fn accumulate_response_body(caps: &mut BodyCapabilities, filter: &dyn crate::filter::HttpFilter) {
    let access = filter.response_body_access();
    if access != BodyAccess::None {
        caps.needs_response_body = true;
        if access == BodyAccess::ReadWrite {
            caps.any_response_body_writer = true;
        }
        merge_body_mode(&mut caps.response_body_mode, filter.response_body_mode());
    }
}

/// Check whether any response condition references headers.
fn resp_conditions_use_headers(conditions: &[ResponseCondition]) -> bool {
    conditions.iter().any(|c| {
        let m = match c {
            ResponseCondition::When(m) | ResponseCondition::Unless(m) => m,
        };
        m.headers.is_some()
    })
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::too_many_lines,
    reason = "tests"
)]
mod tests {
    use std::collections::HashMap;

    use praxis_core::config::{FailureMode, ResponseConditionMatch};

    use super::*;

    #[test]
    fn merge_body_mode_buffer_wins_over_stream() {
        let mut mode = BodyMode::Stream;
        merge_body_mode(&mut mode, BodyMode::Buffer { max_bytes: 1024 });
        assert_eq!(
            mode,
            BodyMode::Buffer { max_bytes: 1024 },
            "Buffer should replace Stream"
        );
    }

    #[test]
    fn merge_body_mode_buffer_wins_over_stream_buffer() {
        let mut mode = BodyMode::StreamBuffer { max_bytes: Some(2048) };
        merge_body_mode(&mut mode, BodyMode::Buffer { max_bytes: 4096 });
        assert_eq!(
            mode,
            BodyMode::Buffer { max_bytes: 4096 },
            "Buffer should replace StreamBuffer"
        );
    }

    #[test]
    fn merge_body_mode_buffer_keeps_smaller_limit() {
        let mut mode = BodyMode::Buffer { max_bytes: 2048 };
        merge_body_mode(&mut mode, BodyMode::Buffer { max_bytes: 1024 });
        assert_eq!(
            mode,
            BodyMode::Buffer { max_bytes: 1024 },
            "smaller Buffer limit should win"
        );
    }

    #[test]
    fn merge_body_mode_buffer_keeps_existing_when_larger() {
        let mut mode = BodyMode::Buffer { max_bytes: 512 };
        merge_body_mode(&mut mode, BodyMode::Buffer { max_bytes: 4096 });
        assert_eq!(
            mode,
            BodyMode::Buffer { max_bytes: 512 },
            "existing smaller Buffer limit should be kept"
        );
    }

    #[test]
    fn merge_body_mode_stream_buffer_wins_over_stream() {
        let mut mode = BodyMode::Stream;
        merge_body_mode(&mut mode, BodyMode::StreamBuffer { max_bytes: Some(1024) });
        assert_eq!(
            mode,
            BodyMode::StreamBuffer { max_bytes: Some(1024) },
            "StreamBuffer should replace Stream"
        );
    }

    #[test]
    fn merge_body_mode_stream_buffer_wins_over_size_limit() {
        let mut mode = BodyMode::SizeLimit { max_bytes: 4096 };
        merge_body_mode(&mut mode, BodyMode::StreamBuffer { max_bytes: Some(2048) });
        assert_eq!(
            mode,
            BodyMode::StreamBuffer { max_bytes: Some(2048) },
            "StreamBuffer should replace SizeLimit"
        );
    }

    #[test]
    fn merge_body_mode_buffer_wins_over_size_limit() {
        let mut mode = BodyMode::SizeLimit { max_bytes: 4096 };
        merge_body_mode(&mut mode, BodyMode::Buffer { max_bytes: 2048 });
        assert_eq!(
            mode,
            BodyMode::Buffer { max_bytes: 2048 },
            "Buffer should replace SizeLimit"
        );
    }

    #[test]
    fn merge_body_mode_size_limit_is_noop() {
        let mut mode = BodyMode::Stream;
        merge_body_mode(&mut mode, BodyMode::SizeLimit { max_bytes: 4096 });
        assert_eq!(
            mode,
            BodyMode::Stream,
            "SizeLimit should not change Stream (treated as noop in merge)"
        );
    }

    #[test]
    fn merge_body_mode_stream_buffer_merges_limits() {
        let mut mode = BodyMode::StreamBuffer { max_bytes: Some(2048) };
        merge_body_mode(&mut mode, BodyMode::StreamBuffer { max_bytes: Some(1024) });
        assert_eq!(
            mode,
            BodyMode::StreamBuffer { max_bytes: Some(1024) },
            "smaller StreamBuffer limit should win"
        );
    }

    #[test]
    fn merge_body_mode_stream_buffer_none_with_some() {
        let mut mode = BodyMode::StreamBuffer { max_bytes: None };
        merge_body_mode(&mut mode, BodyMode::StreamBuffer { max_bytes: Some(1024) });
        assert_eq!(
            mode,
            BodyMode::StreamBuffer { max_bytes: Some(1024) },
            "Some limit should win over None"
        );
    }

    #[test]
    fn merge_body_mode_stream_buffer_does_not_replace_buffer() {
        let mut mode = BodyMode::Buffer { max_bytes: 2048 };
        merge_body_mode(&mut mode, BodyMode::StreamBuffer { max_bytes: Some(1024) });
        assert_eq!(
            mode,
            BodyMode::Buffer { max_bytes: 2048 },
            "StreamBuffer should not downgrade Buffer"
        );
    }

    #[test]
    fn merge_body_mode_stream_is_noop() {
        let mut mode = BodyMode::Buffer { max_bytes: 1024 };
        merge_body_mode(&mut mode, BodyMode::Stream);
        assert_eq!(
            mode,
            BodyMode::Buffer { max_bytes: 1024 },
            "Stream should not change existing mode"
        );
    }

    #[test]
    fn merge_optional_limits_both_some_picks_smaller() {
        assert_eq!(
            merge_optional_limits(Some(100), Some(50)),
            Some(50),
            "should pick smaller of two Some values"
        );
    }

    #[test]
    fn merge_optional_limits_one_none() {
        assert_eq!(
            merge_optional_limits(Some(100), None),
            Some(100),
            "Some should win over None (left)"
        );
        assert_eq!(
            merge_optional_limits(None, Some(200)),
            Some(200),
            "Some should win over None (right)"
        );
    }

    #[test]
    fn merge_optional_limits_both_none() {
        assert_eq!(merge_optional_limits(None, None), None, "both None should yield None");
    }

    #[test]
    fn resp_conditions_use_headers_true_when_headers_present() {
        let conds = vec![ResponseCondition::When(ResponseConditionMatch {
            status: None,
            headers: Some(HashMap::from([("x-key".to_owned(), "val".to_owned())])),
        })];
        assert!(
            resp_conditions_use_headers(&conds),
            "should return true when a condition has headers"
        );
    }

    #[test]
    fn resp_conditions_use_headers_false_when_status_only() {
        let conds = vec![ResponseCondition::When(ResponseConditionMatch {
            status: Some(vec![200]),
            headers: None,
        })];
        assert!(
            !resp_conditions_use_headers(&conds),
            "should return false when conditions only use status"
        );
    }

    #[test]
    fn resp_conditions_use_headers_false_when_empty() {
        assert!(
            !resp_conditions_use_headers(&[]),
            "should return false when no conditions"
        );
    }

    #[test]
    fn resp_conditions_use_headers_unless_variant() {
        let conds = vec![ResponseCondition::Unless(ResponseConditionMatch {
            status: None,
            headers: Some(HashMap::from([("x-skip".to_owned(), "yes".to_owned())])),
        })];
        assert!(
            resp_conditions_use_headers(&conds),
            "should return true for Unless variant with headers"
        );
    }

    #[test]
    fn body_caps_recurse_into_branches() {
        use std::sync::Arc;

        use async_trait::async_trait;
        use bytes::Bytes;

        use crate::{
            FilterAction, FilterError,
            filter::HttpFilter,
            pipeline::branch::{RejoinTarget, ResolvedBranch},
        };

        struct BranchBodyFilter;

        #[async_trait]
        impl HttpFilter for BranchBodyFilter {
            fn name(&self) -> &'static str {
                "branch_body"
            }

            async fn on_request(&self, _ctx: &mut crate::HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
                Ok(FilterAction::Continue)
            }

            fn request_body_access(&self) -> BodyAccess {
                BodyAccess::ReadWrite
            }

            fn request_body_mode(&self) -> BodyMode {
                BodyMode::Buffer { max_bytes: 4096 }
            }

            async fn on_request_body(
                &self,
                _ctx: &mut crate::HttpFilterContext<'_>,
                _body: &mut Option<Bytes>,
                _eos: bool,
            ) -> Result<FilterAction, FilterError> {
                Ok(FilterAction::Continue)
            }
        }

        let branch_filter = PipelineFilter {
            branches: vec![],
            conditions: vec![],
            failure_mode: FailureMode::default(),
            filter: AnyFilter::Http(Box::new(BranchBodyFilter)),
            name: None,
            response_conditions: vec![],
        };
        let branch = ResolvedBranch {
            condition: None,
            filters: vec![branch_filter],
            max_iterations: None,
            name: Arc::from("body_branch"),
            rejoin: RejoinTarget::Next,
        };
        let parent = PipelineFilter {
            branches: vec![branch],
            conditions: vec![],
            failure_mode: FailureMode::default(),
            filter: AnyFilter::Http(Box::new(NoopHttpFilter)),
            name: None,
            response_conditions: vec![],
        };
        let caps = compute_body_capabilities(&[parent]);
        assert!(
            caps.needs_request_body,
            "body filter in branch should enable request body"
        );
        assert!(
            caps.any_request_body_writer,
            "ReadWrite filter in branch should set writer flag"
        );
        assert_eq!(
            caps.request_body_mode,
            BodyMode::Buffer { max_bytes: 4096 },
            "Buffer mode from branch filter should propagate"
        );
    }

    #[test]
    fn body_caps_no_branch_body_filters_has_no_effect() {
        use std::sync::Arc;

        use crate::pipeline::branch::{RejoinTarget, ResolvedBranch};

        let branch = ResolvedBranch {
            condition: None,
            filters: vec![PipelineFilter::new(
                AnyFilter::Http(Box::new(NoopHttpFilter)),
                vec![],
                vec![],
            )],
            max_iterations: None,
            name: Arc::from("noop_branch"),
            rejoin: RejoinTarget::Next,
        };
        let parent = PipelineFilter {
            branches: vec![branch],
            conditions: vec![],
            failure_mode: FailureMode::default(),
            filter: AnyFilter::Http(Box::new(NoopHttpFilter)),
            name: None,
            response_conditions: vec![],
        };
        let caps = compute_body_capabilities(&[parent]);
        assert!(
            !caps.needs_request_body,
            "branch without body filters should not enable request body"
        );
    }

    /// Noop HTTP filter for body capability branch testing.
    struct NoopHttpFilter;

    #[async_trait::async_trait]
    impl crate::filter::HttpFilter for NoopHttpFilter {
        fn name(&self) -> &'static str {
            "noop"
        }

        async fn on_request(
            &self,
            _ctx: &mut crate::HttpFilterContext<'_>,
        ) -> Result<crate::FilterAction, crate::FilterError> {
            Ok(crate::FilterAction::Continue)
        }
    }
}
