// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Condition evaluation for gating filter execution on request/response attributes.

use http::header::HeaderName;

mod request;
mod response;

pub use request::should_execute;
pub(crate) use request::{header_map_matches, should_execute_from};
pub use response::{should_execute_response, should_execute_response_ref};

// -----------------------------------------------------------------------------
// Header Source
// -----------------------------------------------------------------------------

/// Where request-condition evaluation reads header values from.
///
/// The request phase reads the real [`Request`] and cannot fail. The pre-read
/// body phase reads the request overlaid with trusted header mutations made by
/// earlier pre-read filters (see [`EffectiveHeaders`]); resolving that overlay
/// can fail when a conditioned header has no single unambiguous value.
///
/// [`Request`]: crate::context::Request
/// [`EffectiveHeaders`]: crate::context::EffectiveHeaders
pub(crate) trait HeaderSource {
    /// Failure returned by a header lookup.
    type Error;

    /// Whether `name` carries `expected` as one of its values.
    ///
    /// A header may occupy several field lines, which is semantically the one
    /// comma-joined list of all of them, so a condition naming one member of
    /// that list has to consider every occurrence and not just the first.
    fn header_matches(&self, name: &HeaderName, expected: &str) -> Result<bool, Self::Error>;
}

// -----------------------------------------------------------------------------
// Condition Error
// -----------------------------------------------------------------------------

/// Failure raised while evaluating request conditions.
///
/// Only the pre-read overlay source can fail: the original request is always
/// unambiguous. An ambiguous overlay value (two pre-read filters promoting
/// different values to one conditioned header, or a non-text pending value)
/// fails closed rather than guessing which value gates the filter.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ConditionError {
    /// The overlaid value of a conditioned header could not be resolved to a
    /// single value.
    #[error("condition header '{header}' cannot resolve a unique pending value")]
    AmbiguousHeader {
        /// The conditioned header name.
        header: HeaderName,
    },
}
