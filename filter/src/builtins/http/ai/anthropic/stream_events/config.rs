// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Configuration for the Anthropic stream events filter.

use serde::Deserialize;

// -----------------------------------------------------------------------------
// AnthropicStreamEventsConfig
// -----------------------------------------------------------------------------

/// YAML configuration for the [`AnthropicStreamEventsFilter`].
///
/// [`AnthropicStreamEventsFilter`]: super::AnthropicStreamEventsFilter
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[expect(
    clippy::empty_structs_with_brackets,
    reason = "serde empty-map config requires a named empty struct"
)]
pub(crate) struct AnthropicStreamEventsConfig {}
