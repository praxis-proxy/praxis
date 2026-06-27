// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

#![deny(unreachable_pub)]

//! HTTP callout filter for Praxis.
//!
//! Provides an [`HttpFilter`] that makes outbound HTTP requests during
//! request processing, extracts results from the response via `JSONPath`,
//! and feeds them into [`FilterResultSet`] for branch-chain evaluation.
//!
//! [`HttpFilter`]: praxis_filter::HttpFilter
//! [`FilterResultSet`]: praxis_filter::FilterResultSet

praxis_filter::export_filters! {}
