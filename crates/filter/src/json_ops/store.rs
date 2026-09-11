// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Capture/source store for extract and metadata-backed inject.

use std::collections::HashMap;

use crate::HttpFilterContext;

/// Metadata and structured values used as extract destinations and inject sources.
pub trait JsonOpStore {
    /// Read a metadata string by key.
    fn get_metadata(&self, key: &str) -> Option<&str>;

    /// Write a metadata string.
    fn set_metadata(&mut self, key: String, value: String);

    /// Read structured metadata.
    fn get_structured(&self, namespace: &str, key: &str) -> Option<&serde_json::Value>;

    /// Write structured metadata.
    fn set_structured(&mut self, namespace: &str, key: &str, value: serde_json::Value);

    /// Promote a captured value to a request header.
    fn push_request_header(&mut self, name: String, value: String);
}

/// In-memory store for tests, benches, and apply-on-bytes without a request.
#[derive(Clone, Debug, Default)]
pub struct MapStore {
    /// String metadata keyed like `filter_metadata`.
    metadata: HashMap<String, String>,
    /// Structured values keyed by namespace then field.
    structured: HashMap<String, HashMap<String, serde_json::Value>>,
    /// Promoted request headers for tests and benches.
    request_headers: Vec<(String, String)>,
}

impl MapStore {
    /// Empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Borrow captured string metadata.
    #[must_use]
    pub fn metadata(&self) -> &HashMap<String, String> {
        &self.metadata
    }

    /// Borrow promoted request headers.
    #[must_use]
    pub fn request_headers(&self) -> &[(String, String)] {
        &self.request_headers
    }
}

impl JsonOpStore for MapStore {
    fn get_metadata(&self, key: &str) -> Option<&str> {
        self.metadata.get(key).map(String::as_str)
    }

    fn set_metadata(&mut self, key: String, value: String) {
        self.metadata.insert(key, value);
    }

    fn get_structured(&self, namespace: &str, key: &str) -> Option<&serde_json::Value> {
        self.structured.get(namespace)?.get(key)
    }

    fn set_structured(&mut self, namespace: &str, key: &str, value: serde_json::Value) {
        self.structured
            .entry(namespace.to_owned())
            .or_default()
            .insert(key.to_owned(), value);
    }

    fn push_request_header(&mut self, name: String, value: String) {
        self.request_headers.push((name, value));
    }
}

/// [`JsonOpStore`] adapter over [`HttpFilterContext`].
///
/// Inherent context methods keep their names; this wrapper avoids a
/// same-name trait impl on [`HttpFilterContext`].
pub struct HttpJsonStore<'a, 'ctx> {
    /// Borrowed request filter context.
    ctx: &'a mut HttpFilterContext<'ctx>,
}

impl<'a, 'ctx> HttpJsonStore<'a, 'ctx> {
    /// View `ctx` as a JSON op store for one [`super::JsonOps::apply`] call.
    pub fn new(ctx: &'a mut HttpFilterContext<'ctx>) -> Self {
        Self { ctx }
    }
}

use std::borrow::Cow;

impl JsonOpStore for HttpJsonStore<'_, '_> {
    fn get_metadata(&self, key: &str) -> Option<&str> {
        self.ctx.get_metadata(key)
    }

    fn set_metadata(&mut self, key: String, value: String) {
        self.ctx.set_metadata(key, value);
    }

    fn get_structured(&self, namespace: &str, key: &str) -> Option<&serde_json::Value> {
        self.ctx.get_structured_metadata(namespace, key)
    }

    fn set_structured(&mut self, namespace: &str, key: &str, value: serde_json::Value) {
        self.ctx.set_structured_metadata(namespace, key, value);
    }

    fn push_request_header(&mut self, name: String, value: String) {
        self.ctx.extra_request_headers.push((Cow::Owned(name), value));
    }
}
