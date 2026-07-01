// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! `OpenAI` API filters: Responses API pipeline.

#[cfg(feature = "ai-inference")]
pub(crate) mod conversations;
pub(crate) mod responses;
#[cfg(feature = "ai-inference")]
pub(crate) mod sse;
#[expect(clippy::allow_attributes, reason = "dead_code expect unfulfilled on module")]
#[allow(
    dead_code,
    reason = "Responses translation helpers are wired into the HTTP filter in a later stack entry"
)]
pub(crate) mod translation;

#[cfg(feature = "ai-inference")]
pub use conversations::OpenaiConversationsFilter;
#[cfg(feature = "ai-inference")]
pub use responses::ModelRewriteFilter;
#[cfg(feature = "ai-inference")]
pub use responses::OpenaiResponsesValidateFilter;
#[cfg(feature = "ai-inference")]
pub use responses::RehydrateFilter;
pub use responses::{ResponseStoreFilter, ResponsesFormatFilter, proxy::ResponsesProxyFilter};
