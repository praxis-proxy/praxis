//! Body capabilities computation for filter pipelines.

use praxis_core::config::ResponseCondition;

use super::ConditionalFilter;
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
/// Precedence: `Buffer` > `StreamBuffer` > `Stream`. When two modes
/// of the same variant merge, the stricter (smaller) limit wins.
pub(crate) fn merge_body_mode(current: &mut BodyMode, filter_mode: BodyMode) {
    match filter_mode {
        BodyMode::Buffer { max_bytes } => {
            *current = match *current {
                BodyMode::Stream | BodyMode::StreamBuffer { .. } => BodyMode::Buffer { max_bytes },
                BodyMode::Buffer { max_bytes: existing } => BodyMode::Buffer {
                    max_bytes: existing.min(max_bytes),
                },
            };
        },
        BodyMode::StreamBuffer { max_bytes } => {
            *current = match *current {
                BodyMode::Stream => BodyMode::StreamBuffer { max_bytes },
                BodyMode::StreamBuffer { max_bytes: existing } => BodyMode::StreamBuffer {
                    max_bytes: merge_optional_limits(existing, max_bytes),
                },
                BodyMode::Buffer { .. } => *current,
            };
        },
        BodyMode::Stream => {},
    }
}

// -----------------------------------------------------------------------------
// Body Capabilities
// -----------------------------------------------------------------------------

/// Merge all filters' body access declarations into a single capability set.
pub(super) fn compute_body_capabilities(filters: &[ConditionalFilter]) -> BodyCapabilities {
    let mut caps = BodyCapabilities::default();

    for (filter, _conditions, resp_conditions) in filters {
        let http_filter = match filter {
            AnyFilter::Http(f) => f.as_ref(),
            AnyFilter::Tcp(_) => continue,
        };

        let req_access = http_filter.request_body_access();
        let resp_access = http_filter.response_body_access();

        if req_access != BodyAccess::None {
            caps.needs_request_body = true;
            if req_access == BodyAccess::ReadWrite {
                caps.any_request_body_writer = true;
            }
            merge_body_mode(&mut caps.request_body_mode, http_filter.request_body_mode());
        }

        if resp_access != BodyAccess::None {
            caps.needs_response_body = true;
            if resp_access == BodyAccess::ReadWrite {
                caps.any_response_body_writer = true;
            }
            merge_body_mode(&mut caps.response_body_mode, http_filter.response_body_mode());
        }

        if http_filter.needs_request_context() {
            caps.needs_request_context = true;
        }

        if !caps.any_response_condition_uses_headers {
            caps.any_response_condition_uses_headers = resp_conditions.iter().any(|c| {
                let m = match c {
                    ResponseCondition::When(m) | ResponseCondition::Unless(m) => m,
                };
                m.headers.is_some()
            });
        }
    }

    caps
}
