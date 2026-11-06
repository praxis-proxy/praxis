// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Preserve applied policy mutations when a later hook replaces a response.

use http::{HeaderMap, header::HeaderName};

use crate::RequestExtensions;

/// Preserve explicit response-header writes and removals across local replacements.
///
/// Call from a local [`Policy`]'s [`on_response`] hook after editing the response.
/// For each named field, its final values at hook completion (or its absence)
/// survive later policy denials and precommit error replacements. All values of
/// a named field are preserved together; later policies can still override them.
///
/// Changed fields are detected automatically. Record unchanged writes and
/// removals of absent fields here, since those effects have no value difference.
/// This only records effects; callers must edit the response headers themselves.
/// Calls outside a local response-header hook have no effect.
///
/// ```
/// use http::{
///     HeaderValue,
///     header::{SET_COOKIE, X_FRAME_OPTIONS},
/// };
/// use praxis_filter::{HttpFilterContext, local_http::record_response_header_effects};
///
/// fn secure_response(ctx: &mut HttpFilterContext<'_>) {
///     let Some(head) = ctx.response_header.as_deref_mut() else {
///         return;
///     };
///     head.headers
///         .insert(X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
///     head.headers.remove(SET_COOKIE);
///     record_response_header_effects(&mut ctx.extensions, [X_FRAME_OPTIONS, SET_COOKIE]);
/// }
/// ```
///
/// [`Policy`]: super::LocalCompatibility::Policy
/// [`on_response`]: crate::HttpFilter::on_response
pub fn record_response_header_effects<Names>(extensions: &mut RequestExtensions, names: Names)
where
    Names: IntoIterator<Item = HeaderName>,
{
    if let Some(explicit) = extensions.get_mut::<PolicyHeaders>() {
        explicit.touched.extend(names);
    }
}

/// Only policy edits survive replacement; handler-originated headers do not.
#[derive(Default)]
pub(crate) struct HeaderEdits {
    /// Final values for fields written by policies.
    written: HeaderMap,
    /// Fields removed by policies.
    removed: Vec<HeaderName>,
}

impl HeaderEdits {
    /// Record changes and explicit writes/removals, even when values match.
    pub(crate) fn record(&mut self, before: &HeaderMap, after: &HeaderMap, touched: &[HeaderName]) {
        for name in before.keys().chain(after.keys()).chain(touched) {
            if !touched.contains(name) && before.get_all(name).iter().eq(after.get_all(name).iter()) {
                continue;
            }
            self.written.remove(name);
            self.removed.retain(|removed| removed != name);
            if after.contains_key(name) {
                for value in after.get_all(name) {
                    self.written.append(name.clone(), value.clone());
                }
            } else {
                self.removed.push(name.clone());
            }
        }
    }

    /// Apply accumulated edits over a new denial's headers in phase order.
    pub(crate) fn apply(&self, headers: &mut HeaderMap) {
        for name in &self.removed {
            headers.remove(name);
        }
        for name in self.written.keys() {
            headers.remove(name);
            for value in self.written.get_all(name) {
                headers.append(name.clone(), value.clone());
            }
        }
    }
}

/// Explicit policy effects cannot be inferred from header value differences.
#[derive(Default)]
pub(crate) struct PolicyHeaders {
    /// Fields written or removed by the current response hook.
    pub(crate) touched: Vec<HeaderName>,
}
