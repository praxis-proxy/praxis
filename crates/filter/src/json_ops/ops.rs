// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Compiled pointer operations (crate-private).

use bytes::Bytes;

use super::index::OpPathIndex;

/// Kind of pointer operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OpKind {
    /// Insert last token (overwrite existing object keys; insert/append on arrays).
    Add,
    /// Overwrite if the pointer exists; skip if missing.
    Replace,
    /// Omit if present; skip if missing.
    Remove,
    /// Copy the pointer's JSON into the op store; body is unchanged.
    Extract,
}

impl OpKind {
    /// Whether this op mutates the serialized body.
    pub(crate) const fn is_mutating(self) -> bool {
        matches!(self, Self::Add | Self::Replace | Self::Remove)
    }
}

/// Where an extracted JSON span is written.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExtractDest {
    /// `filter_metadata` key.
    Metadata(String),
    /// Structured-metadata namespace and key.
    Structured {
        /// Structured-metadata namespace.
        namespace: String,
        /// Field within the namespace object.
        key: String,
    },
    /// Request header promoted via [`HttpFilterContext::extra_request_headers`].
    ///
    /// [`HttpFilterContext::extra_request_headers`]: crate::HttpFilterContext::extra_request_headers
    Header(String),
}

impl ExtractDest {
    /// Write the captured JSON as `filter_metadata` at `key`.
    #[must_use]
    pub fn metadata(key: impl Into<String>) -> Self {
        Self::Metadata(key.into())
    }

    /// Write the captured JSON as structured metadata.
    #[must_use]
    pub fn structured(namespace: impl Into<String>, key: impl Into<String>) -> Self {
        Self::Structured {
            namespace: namespace.into(),
            key: key.into(),
        }
    }

    /// Promote the captured JSON as a request header value.
    #[must_use]
    pub fn header(name: impl Into<String>) -> Self {
        Self::Header(name.into())
    }
}

/// Where an add/replace value comes from at rewrite time.
#[derive(Clone, Debug)]
pub(crate) enum ValueSource {
    /// Pre-serialized JSON bytes from a static value.
    Static(Bytes),
    /// Metadata key in [`super::JsonOpStore`].
    Metadata(String),
    /// Structured metadata namespace and key.
    Structured {
        /// Structured-metadata namespace.
        namespace: String,
        /// Field within the namespace object.
        key: String,
    },
}

/// One compiled pointer operation.
#[derive(Clone, Debug)]
pub(crate) struct CompiledOp {
    /// Original pointer string, for logs and overlap errors.
    pub pointer: String,
    /// Decoded RFC 6901 tokens (empty = document root).
    pub tokens: Vec<String>,
    /// Operation kind.
    pub kind: OpKind,
    /// Value to inject; `None` for remove and extract.
    pub source: Option<ValueSource>,
    /// Extract destination; `None` unless [`OpKind::Extract`].
    pub dest: Option<ExtractDest>,
    /// JSON-quoted last pointer token for object keys (`"tenant"`).
    pub encoded_last_token: Option<Bytes>,
}

/// Compiled operations plus lookup index.
#[derive(Clone, Debug)]
pub(crate) struct CompiledOpSet {
    /// Operations in builder order.
    pub ops: Vec<CompiledOp>,
    /// Trie index for pointer lookups.
    pub index: OpPathIndex,
    /// Sum of static payload and encoded key sizes for output capacity.
    pub growth_hint: usize,
    /// True when every op is extract (no body rewrite).
    pub extract_only: bool,
}

impl CompiledOpSet {
    /// Empty op set: walk still validates JSON when applied with emit.
    pub(crate) fn empty() -> Self {
        Self {
            ops: Vec::new(),
            index: OpPathIndex::build(&[]),
            growth_hint: 0,
            extract_only: false,
        }
    }

    /// Wrap compiled ops with trie index and growth hint.
    pub(crate) fn finalize(ops: Vec<CompiledOp>) -> Self {
        let growth_hint = ops.iter().map(op_growth_bytes).sum();
        let index = OpPathIndex::build(&ops);
        let extract_only = !ops.is_empty() && ops.iter().all(|op| op.kind == OpKind::Extract);
        Self {
            ops,
            index,
            growth_hint,
            extract_only,
        }
    }
}

/// Bytes contributed by one op to rewritten output size.
pub(crate) fn op_growth_bytes(op: &CompiledOp) -> usize {
    let payload = match &op.source {
        Some(ValueSource::Static(bytes)) => bytes.len(),
        Some(ValueSource::Metadata(_) | ValueSource::Structured { .. }) | None => 0,
    };
    let key = op.encoded_last_token.as_ref().map_or(0, Bytes::len);
    match op.kind {
        OpKind::Add | OpKind::Replace => payload.saturating_add(key),
        OpKind::Remove | OpKind::Extract => 0,
    }
}
