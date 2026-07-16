// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Reserved internal header prefixes for proxy-owned routing metadata.

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Built-in reserved header prefixes for Praxis routing metadata.
///
/// Headers with these prefixes are proxy-internal metadata used for
/// body-derived routing decisions. Clients must not be able to inject
/// them directly, and they should not be forwarded to upstream
/// backends or mutated by external processors.
///
/// The `x-ext-protocol-*` and `x-ext-agent-*` prefixes are reserved
/// for the AI extension package (`praxis-ai`). They are stripped to
/// prevent clients from spoofing internal AI routing headers even
/// when the AI filters are not loaded.
///
/// ```
/// use praxis_core::reserved_headers::RESERVED_HEADER_PREFIXES;
///
/// assert!(
///     RESERVED_HEADER_PREFIXES
///         .iter()
///         .any(|p| "x-praxis-foo".starts_with(p))
/// );
/// assert!(
///     !RESERVED_HEADER_PREFIXES
///         .iter()
///         .any(|p| "x-custom-foo".starts_with(p))
/// );
/// ```
// TODO(#186) Spike: consider additive operator-managed reserved prefixes
// once the broader config model defines global vs listener/filter-chain
// scope and additive vs override semantics.
pub const RESERVED_HEADER_PREFIXES: &[&str] = &["x-praxis-", "x-ext-protocol-", "x-ext-agent-"];

/// Return whether a lowercased header name matches any reserved prefix.
///
/// ```
/// assert!(praxis_core::reserved_headers::is_reserved("x-praxis-route"));
/// assert!(praxis_core::reserved_headers::is_reserved(
///     "x-ext-agent-task"
/// ));
/// assert!(!praxis_core::reserved_headers::is_reserved("authorization"));
/// ```
pub fn is_reserved(name: &str) -> bool {
    RESERVED_HEADER_PREFIXES.iter().any(|prefix| name.starts_with(prefix))
}
