// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Declarative method/path ownership and route-scoped transfer bounds.

use http::Method;

use crate::path_match::path_prefix_matches;

/// Methods owned by a route; HEAD is never implicitly added to GET.
#[derive(Clone, Debug)]
pub enum LocalMethods {
    /// Every admitted method.
    All,
    /// An explicit, nonempty set of methods.
    Explicit(Vec<Method>),
}

impl LocalMethods {
    /// Whether this scope includes the method.
    pub(crate) fn matches(&self, method: &Method) -> bool {
        match self {
            Self::All => true,
            Self::Explicit(methods) => methods.contains(method),
        }
    }

    /// Whether any method belongs to both scopes.
    pub(crate) fn overlaps(&self, other: &Self) -> bool {
        match other {
            Self::All => true,
            Self::Explicit(methods) => methods.iter().any(|method| self.matches(method)),
        }
    }
}

/// Original admitted path scope, ignoring queries and subsequent rewrites.
#[derive(Clone, Debug)]
pub enum LocalPath {
    /// Exact URI path.
    Exact(String),
    /// Existing segment-boundary prefix semantics, including trailing slash.
    SegmentPrefix(String),
}

impl LocalPath {
    /// Path text for declaration validation.
    pub(crate) fn text(&self) -> &str {
        match self {
            Self::Exact(path) | Self::SegmentPrefix(path) => path,
        }
    }

    /// Whether the admitted path belongs to this scope.
    pub(crate) fn matches(&self, path: &str) -> bool {
        match self {
            Self::Exact(exact) => path == exact,
            Self::SegmentPrefix(prefix) => path_prefix_matches(path, prefix),
        }
    }

    /// Whether exact/prefix scopes share any path; precedence is forbidden.
    pub(crate) fn overlaps(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Exact(path), _) => other.matches(path),
            (_, Self::Exact(path)) => self.matches(path),
            (Self::SegmentPrefix(left), Self::SegmentPrefix(right)) => self.matches(right) || other.matches(left),
        }
    }
}

/// Request-body ownership must explicitly be exclusive.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalBodyOwnership {
    /// Invalid for local routes; retained to diagnose missing declarations.
    Unspecified,
    /// Only the handler may pull request payload bytes.
    Exclusive,
}

/// Stable route declaration. Limits count transferred bytes, never buffers.
#[derive(Clone, Debug)]
pub struct LocalRoute {
    /// Stable, pipeline-unique identifier passed to the handler factory.
    pub id: String,
    /// Explicit methods or all methods.
    pub methods: LocalMethods,
    /// Exact or segment-prefix original path.
    pub path: LocalPath,
    /// Mandatory exclusive request-body ownership.
    pub body: LocalBodyOwnership,
    /// Finite, positive request payload limit; independent of global ceilings.
    pub request_limit: u64,
    /// Finite, positive response limit counted after response filtering.
    pub response_limit: u64,
}
