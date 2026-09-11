// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Programmatic construction of a compiled JSON Pointer op set.

use bytes::Bytes;

use super::{
    error::JsonError,
    ops::{CompiledOp, CompiledOpSet, ExtractDest, OpKind, ValueSource},
    pointer::{compile_pointer, pointers_overlap},
    rewrite::{RewriteOutcome, rewrite_document},
    skip::encode_json_string,
    store::JsonOpStore,
};

/// Injected value for add/replace.
#[derive(Clone, Debug)]
pub struct JsonValue {
    /// Static bytes or a store key resolved at apply time.
    source: ValueSource,
}

impl JsonValue {
    /// Serialize `value` as JSON bytes at construction time.
    ///
    /// # Errors
    ///
    /// Returns [`JsonError::Compile`] if serialization fails.
    pub fn static_json(value: impl serde::Serialize) -> Result<Self, JsonError> {
        let bytes = serde_json::to_vec(&value)
            .map_err(|e| JsonError::compile(format!("failed to serialize static value: {e}")))?;
        Ok(Self {
            source: ValueSource::Static(Bytes::from(bytes)),
        })
    }

    /// Inject `filter_metadata` at `key` as a JSON string.
    #[must_use]
    pub fn metadata(key: impl Into<String>) -> Self {
        Self {
            source: ValueSource::Metadata(key.into()),
        }
    }

    /// Inject structured metadata as JSON as-is.
    #[must_use]
    pub fn structured(namespace: impl Into<String>, key: impl Into<String>) -> Self {
        Self {
            source: ValueSource::Structured {
                namespace: namespace.into(),
                key: key.into(),
            },
        }
    }

    /// Read an environment variable at construction time and inject its value.
    ///
    /// Valid JSON in the variable is injected as-is; otherwise the raw text is
    /// injected as a JSON string (same effective semantics as YAML `value:` for
    /// a plain scalar).
    ///
    /// # Errors
    ///
    /// Returns [`JsonError::Compile`] when `var` is empty, unset, or not
    /// serializable.
    pub fn env_var(var: impl Into<String>) -> Result<Self, JsonError> {
        let var = var.into();
        if var.is_empty() {
            return Err(JsonError::compile("'env_var' must not be empty"));
        }
        Ok(Self {
            source: ValueSource::Static(json_bytes_from_environment(&var)?),
        })
    }
}

/// Result of one document walk.
#[derive(Clone, Debug)]
pub struct JsonRewrite {
    /// Rewritten bytes; `None` when the op set is extract-only.
    pub output: Option<Vec<u8>>,
}

/// Compiled pointer operations for one document.
#[derive(Clone, Debug)]
pub struct JsonOps {
    /// Trie-indexed operations for one document.
    inner: CompiledOpSet,
}

impl JsonOps {
    /// Start a new op set.
    #[must_use]
    pub fn builder() -> JsonOpsBuilder {
        JsonOpsBuilder::default()
    }

    /// No operations. [`apply`](Self::apply) still requires a complete JSON value.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            inner: CompiledOpSet::empty(),
        }
    }

    /// Whether this set has no operations.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.ops.is_empty()
    }

    /// Whether every op is extract (no body rewrite).
    #[must_use]
    pub fn is_extract_only(&self) -> bool {
        self.inner.extract_only
    }

    /// Whether any op is add or replace (can grow the body).
    #[must_use]
    pub fn can_grow(&self) -> bool {
        self.inner
            .ops
            .iter()
            .any(|op| matches!(op.kind, OpKind::Add | OpKind::Replace))
    }

    /// Walk `input` once, capturing extracts and optionally rewriting.
    ///
    /// # Errors
    ///
    /// Returns [`JsonError::InvalidJson`] or [`JsonError::Depth`] when the
    /// document cannot be walked.
    pub fn apply(&self, input: &[u8], store: Option<&mut dyn JsonOpStore>) -> Result<JsonRewrite, JsonError> {
        rewrite_document(input, &self.inner, store).map(|RewriteOutcome { output }| JsonRewrite { output })
    }
}

/// Accumulates pointer operations, then compiles the trie at [`build`](Self::build).
#[derive(Clone, Debug, Default)]
pub struct JsonOpsBuilder {
    /// Ops in call order (extract/add/replace/remove as invoked).
    ops: Vec<CompiledOp>,
}

impl JsonOpsBuilder {
    /// Copy a pointer's JSON into the store.
    ///
    /// # Errors
    ///
    /// Invalid pointer or empty destination keys.
    pub fn extract(mut self, pointer: impl Into<String>, dest: ExtractDest) -> Result<Self, JsonError> {
        let pointer = pointer.into();
        validate_extract_dest(&dest)?;
        let tokens = compile_pointer(&pointer)?;
        self.ops.push(CompiledOp {
            pointer,
            tokens,
            kind: OpKind::Extract,
            source: None,
            dest: Some(dest),
            encoded_last_token: None,
        });
        Ok(self)
    }

    /// Insert or overwrite at `pointer`.
    ///
    /// # Errors
    ///
    /// Invalid pointer, empty metadata keys, or targeting the document root.
    pub fn add(mut self, pointer: impl Into<String>, value: JsonValue) -> Result<Self, JsonError> {
        let pointer = pointer.into();
        let tokens = compile_pointer(&pointer)?;
        if tokens.is_empty() {
            return Err(JsonError::compile("add cannot target the document root (pointer \"\")"));
        }
        validate_value_source(&value.source)?;
        let encoded_last_token = encoded_last_object_token(&tokens);
        self.ops.push(CompiledOp {
            pointer,
            tokens,
            kind: OpKind::Add,
            source: Some(value.source),
            dest: None,
            encoded_last_token,
        });
        Ok(self)
    }

    /// Overwrite `pointer` when present.
    ///
    /// # Errors
    ///
    /// Invalid pointer or empty metadata keys.
    pub fn replace(mut self, pointer: impl Into<String>, value: JsonValue) -> Result<Self, JsonError> {
        let pointer = pointer.into();
        let tokens = compile_pointer(&pointer)?;
        validate_value_source(&value.source)?;
        let encoded_last_token = encoded_last_object_token(&tokens);
        self.ops.push(CompiledOp {
            pointer,
            tokens,
            kind: OpKind::Replace,
            source: Some(value.source),
            dest: None,
            encoded_last_token,
        });
        Ok(self)
    }

    /// Omit `pointer` when present.
    ///
    /// # Errors
    ///
    /// Invalid pointer or targeting the document root.
    pub fn remove(mut self, pointer: impl Into<String>) -> Result<Self, JsonError> {
        let pointer = pointer.into();
        let tokens = compile_pointer(&pointer)?;
        if tokens.is_empty() {
            return Err(JsonError::compile(
                "remove cannot target the document root (pointer \"\")",
            ));
        }
        let encoded_last_token = encoded_last_object_token(&tokens);
        self.ops.push(CompiledOp {
            pointer,
            tokens,
            kind: OpKind::Remove,
            source: None,
            dest: None,
            encoded_last_token,
        });
        Ok(self)
    }

    /// Compile the trie and reject overlapping mutating pointers or equal extracts.
    ///
    /// # Errors
    ///
    /// Overlapping JSON Pointers.
    pub fn build(self) -> Result<JsonOps, JsonError> {
        reject_overlaps(&self.ops)?;
        Ok(JsonOps {
            inner: CompiledOpSet::finalize(self.ops),
        })
    }
}

/// JSON-quoted last pointer token, used when injecting a missing object member.
fn encoded_last_object_token(tokens: &[String]) -> Option<Bytes> {
    tokens.last().map(|last| encode_json_string(last))
}

/// Serialize environment text for injection as JSON bytes.
fn json_bytes_from_env_text(raw: &str) -> Result<Bytes, JsonError> {
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(raw) {
        let bytes = serde_json::to_vec(&value)
            .map_err(|e| JsonError::compile(format!("failed to serialize environment value as JSON: {e}")))?;
        return Ok(Bytes::from(bytes));
    }
    let bytes = serde_json::to_vec(raw)
        .map_err(|e| JsonError::compile(format!("failed to serialize environment value as JSON string: {e}")))?;
    Ok(Bytes::from(bytes))
}

/// Serialize an environment variable for injection as JSON bytes.
fn json_bytes_from_environment(var: &str) -> Result<Bytes, JsonError> {
    let raw =
        std::env::var(var).map_err(|e| JsonError::compile(format!("environment variable '{var}' not set: {e}")))?;
    json_bytes_from_env_text(&raw)
}

/// Reject empty metadata keys on extract destinations.
fn validate_extract_dest(dest: &ExtractDest) -> Result<(), JsonError> {
    match dest {
        ExtractDest::Metadata(key) if key.is_empty() => Err(JsonError::compile("extract 'metadata' must not be empty")),
        ExtractDest::Header(name) if name.is_empty() => Err(JsonError::compile("extract 'header' must not be empty")),
        ExtractDest::Header(name) if http::header::HeaderName::from_bytes(name.as_bytes()).is_err() => Err(
            JsonError::compile(format!("extract 'header' has invalid header name '{name}'")),
        ),
        ExtractDest::Structured { namespace, key } if namespace.is_empty() || key.is_empty() => Err(
            JsonError::compile("extract structured_metadata namespace and key must not be empty"),
        ),
        ExtractDest::Metadata(_) | ExtractDest::Structured { .. } | ExtractDest::Header(_) => Ok(()),
    }
}

/// Reject empty metadata keys on inject sources.
fn validate_value_source(source: &ValueSource) -> Result<(), JsonError> {
    match source {
        ValueSource::Metadata(key) if key.is_empty() => Err(JsonError::compile("'metadata' must not be empty")),
        ValueSource::Structured { namespace, key } if namespace.is_empty() || key.is_empty() => Err(
            JsonError::compile("structured_metadata namespace and key must not be empty"),
        ),
        ValueSource::Static(_) | ValueSource::Metadata(_) | ValueSource::Structured { .. } => Ok(()),
    }
}

/// Reject overlapping mutating pointers and duplicate extract pointers.
fn reject_overlaps(ops: &[CompiledOp]) -> Result<(), JsonError> {
    for (i, a) in ops.iter().enumerate() {
        for b in ops.iter().skip(i + 1) {
            if overlapping_ops(a, b) {
                return Err(JsonError::compile(format!(
                    "overlapping JSON Pointers: '{}' and '{}'",
                    a.pointer, b.pointer
                )));
            }
        }
    }
    Ok(())
}

/// Whether two compiled ops conflict under the overlap rules.
fn overlapping_ops(a: &CompiledOp, b: &CompiledOp) -> bool {
    let a_mut = a.kind.is_mutating();
    let b_mut = b.kind.is_mutating();
    match (a_mut, b_mut) {
        (true, true) => pointers_overlap(&a.tokens, &b.tokens),
        (false, false) => a.tokens == b.tokens,
        _ => false,
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod env_text_tests {
    use super::json_bytes_from_env_text;

    #[test]
    fn plain_string_becomes_json_string() {
        assert_eq!(json_bytes_from_env_text("acme").unwrap().as_ref(), br#""acme""#);
    }

    #[test]
    fn json_document_is_injected_as_is() {
        assert_eq!(json_bytes_from_env_text(r#"{"k":1}"#).unwrap().as_ref(), br#"{"k":1}"#);
    }
}
