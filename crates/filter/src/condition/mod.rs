// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Condition evaluation for gating filter execution on request/response attributes.

use std::borrow::Cow;

use http::header::HeaderName;

mod request;
mod response;

pub use request::should_execute;
pub(crate) use request::should_execute_from;
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

    /// Return the effective value of `name`, or `None` when it is absent.
    fn header(&self, name: &HeaderName) -> Result<Option<Cow<'_, str>>, Self::Error>;
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
