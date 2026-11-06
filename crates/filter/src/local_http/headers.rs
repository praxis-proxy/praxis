// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Preserve applied policy mutations when a later hook replaces a response.

use http::{HeaderMap, HeaderValue, header::HeaderName};

use crate::RequestExtensions;

/// Preserve explicit response-header writes and removals across local replacements.
///
/// Call from a local [`Policy`]'s [`on_response`] hook after editing the response.
/// For each named field, its final values at hook completion (or its absence)
/// survive later policy denials and precommit error replacements. All values of
/// a named field are preserved together; later policies can still override them.
///
/// Record whole-field sets and removals, including unchanged writes and removals
/// of absent fields. Append-only edits are detected automatically; do not name
/// those fields here, since doing so also preserves their pre-existing values.
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
    /// Policy operations in response-hook order.
    operations: Vec<HeaderEdit>,
}

impl HeaderEdits {
    /// Record changes and explicit writes/removals, even when values match.
    pub(crate) fn record(&mut self, before: &HeaderMap, after: &HeaderMap, touched: &[HeaderName]) {
        for name in touched {
            self.operations.push(HeaderEdit::replacement(name, after));
        }
        for name in before
            .keys()
            .chain(after.keys().filter(|name| !before.contains_key(*name)))
        {
            if touched.contains(name) || before.get_all(name).iter().eq(after.get_all(name).iter()) {
                continue;
            }
            self.record_change(name, before, after);
        }
    }

    /// Apply accumulated edits over a new denial's headers in phase order.
    pub(crate) fn apply(&self, headers: &mut HeaderMap) {
        for operation in &self.operations {
            match operation {
                HeaderEdit::Append(name, value) => {
                    headers.append(name.clone(), value.clone());
                },
                HeaderEdit::Set(name, values) => {
                    headers.remove(name);
                    for value in values {
                        headers.append(name.clone(), value.clone());
                    }
                },
                HeaderEdit::Remove(name) => {
                    headers.remove(name);
                },
            }
        }
    }

    /// Retain only the added suffix of an append-only edit.
    fn record_change(&mut self, name: &HeaderName, before: &HeaderMap, after: &HeaderMap) {
        let current = after.get_all(name);
        let mut values = current.iter();
        if before.get_all(name).iter().all(|value| Some(value) == values.next()) {
            self.operations
                .extend(values.cloned().map(|value| HeaderEdit::Append(name.clone(), value)));
        } else {
            self.operations.push(HeaderEdit::replacement(name, after));
        }
    }
}

/// Only values introduced by a policy belong in append operations.
enum HeaderEdit {
    /// Add a value without replacing the new response's existing values.
    Append(HeaderName, HeaderValue),
    /// Replace all values with an authoritative policy write.
    Set(HeaderName, Vec<HeaderValue>),
    /// Remove every value, including values introduced by a replacement.
    Remove(HeaderName),
}

impl HeaderEdit {
    /// Preserve an explicit whole-field write or removal.
    fn replacement(name: &HeaderName, headers: &HeaderMap) -> Self {
        if headers.contains_key(name) {
            Self::Set(name.clone(), headers.get_all(name).iter().cloned().collect())
        } else {
            Self::Remove(name.clone())
        }
    }
}

/// Explicit policy effects cannot be inferred from header value differences.
#[derive(Default)]
pub(crate) struct PolicyHeaders {
    /// Fields authoritatively set or removed by the current response hook.
    pub(crate) touched: Vec<HeaderName>,
}
