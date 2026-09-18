// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! HTTP observability filters: structured access logs, request correlation IDs,
//! and W3C Trace Context propagation.

mod access_log;
mod request_id;
mod trace_context;

pub use access_log::{
    AccessLogFilter, access_record_already_emitted, bodyless_response, emit_access_record, mark_access_record_emitted,
};
pub use request_id::RequestIdFilter;
pub use trace_context::TraceContextFilter;

#[cfg(feature = "cloud-events-filter")]
mod cloud_events;
#[cfg(feature = "cloud-events-filter")]
pub use cloud_events::CloudEventsFilter;

/// Header names rejected at config load time in v1.
const SENSITIVE_HEADERS: &[&str] = &["authorization", "proxy-authorization", "cookie", "set-cookie"];
/// Return whether a header is prohibited from observability output.
fn is_sensitive_header(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    SENSITIVE_HEADERS.contains(&lower.as_str())
}
