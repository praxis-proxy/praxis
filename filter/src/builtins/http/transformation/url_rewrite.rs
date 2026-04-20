// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! URL rewrite filter: regex-based path transformation and query string manipulation.

use std::{
    borrow::Cow,
    collections::{BTreeMap, HashSet},
};

use async_trait::async_trait;
use percent_encoding::{AsciiSet, CONTROLS};
use regex::Regex;
use serde::Deserialize;
use tracing::{debug, trace};

use super::path_sanitize::normalize_rewritten_path;
use crate::{
    FilterAction, FilterError,
    factory::parse_filter_config,
    filter::{HttpFilter, HttpFilterContext},
};

// -----------------------------------------------------------------------------
// Url Rewrite Constants
// -----------------------------------------------------------------------------

/// Characters unsafe in query values that must be percent-encoded:
/// space, `"`, `#`, `&`, `+`, and `=`.
const QUERY_VALUE_ENCODE_SET: &AsciiSet = &CONTROLS.add(b' ').add(b'"').add(b'#').add(b'&').add(b'+').add(b'=');

// -----------------------------------------------------------------------------
// UrlRewriteConfig
// -----------------------------------------------------------------------------

/// Deserialized YAML configuration for the URL rewrite filter.
///
/// ```ignore
/// let yaml = r#"
/// operations:
///   - regex_replace:
///       pattern: "^/v1/(.*)"
///       replacement: "/v2/$1"
///   - strip_query_params:
///       - debug
///       - trace
///   - add_query_params:
///       version: "2"
/// "#;
/// let cfg: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
/// let filter = UrlRewriteFilter::from_config(&cfg).unwrap();
/// assert_eq!(filter.name(), "url_rewrite");
/// ```
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UrlRewriteConfig {
    /// Ordered list of rewrite operations to apply.
    #[serde(default)]
    operations: Vec<OperationConfig>,

    /// When `true`, suppresses the duplicate-rewrite validation
    /// error if another rewrite filter precedes this one.
    #[serde(default)]
    #[allow(dead_code, reason = "consumed by pipeline validation")]
    allow_rewrite_override: bool,
}

/// A single rewrite operation in deserialized form.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum OperationConfig {
    /// A keyed operation: `regex_replace`, `strip_query_params`,
    /// or `add_query_params`.
    Map(BTreeMap<String, serde_yaml::Value>),
}

// -----------------------------------------------------------------------------
// UrlRewriteFilter
// -----------------------------------------------------------------------------

/// Rewrites request URLs using regex substitution and query parameter
/// manipulation before the request reaches upstream.
///
/// Operations are applied in declaration order, allowing complex
/// multi-step transformations.
///
/// # YAML configuration
///
/// ```yaml
/// filter: url_rewrite
/// operations:
///   - regex_replace:
///       pattern: "^/api/v1/(.*)"
///       replacement: "/api/v2/$1"
///   - strip_query_params:
///       - debug
///   - add_query_params:
///       source: gateway
/// ```
///
/// # Example
///
/// ```ignore
/// use praxis_filter::UrlRewriteFilter;
///
/// let yaml: serde_yaml::Value = serde_yaml::from_str(
///     r#"
/// operations:
///   - regex_replace:
///       pattern: "^/old/(.*)"
///       replacement: "/new/$1"
/// "#,
/// )
/// .unwrap();
/// let filter = UrlRewriteFilter::from_config(&yaml).unwrap();
/// assert_eq!(filter.name(), "url_rewrite");
/// ```
pub struct UrlRewriteFilter {
    /// Compiled operations applied in order.
    operations: Vec<Operation>,
}

impl UrlRewriteFilter {
    /// Create a URL rewrite filter from parsed YAML config.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if the YAML config is invalid or
    /// a regex pattern fails to compile.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use praxis_filter::UrlRewriteFilter;
    ///
    /// let yaml: serde_yaml::Value = serde_yaml::from_str(
    ///     r#"
    /// operations:
    ///   - strip_query_params:
    ///       - secret
    ///   - add_query_params:
    ///       gateway: praxis
    /// "#,
    /// )
    /// .unwrap();
    /// let filter = UrlRewriteFilter::from_config(&yaml).unwrap();
    /// assert_eq!(filter.name(), "url_rewrite");
    /// ```
    ///
    /// [`FilterError`]: crate::FilterError
    pub fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        let cfg: UrlRewriteConfig = parse_filter_config("url_rewrite", config)?;
        let operations = compile_operations(cfg.operations)?;
        Ok(Box::new(Self { operations }))
    }
}

#[async_trait]
impl HttpFilter for UrlRewriteFilter {
    fn name(&self) -> &'static str {
        "url_rewrite"
    }

    async fn on_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        let original_path = ctx.request.uri.path();
        let original_query = ctx.request.uri.query();

        let (path, query) = apply_operations(&self.operations, original_path, original_query);

        let changed = !matches!(&path, Cow::Borrowed(_)) || query.as_deref() != original_query;

        if changed {
            let normalized_path = normalize_rewritten_path(&path);
            let rewritten = build_path_and_query(&normalized_path, query.as_deref());
            debug!(rewritten = %rewritten, "url rewrite applied");
            ctx.rewritten_path = Some(rewritten);
        }

        Ok(FilterAction::Continue)
    }
}

// -----------------------------------------------------------------------------
// Compiled Operations
// -----------------------------------------------------------------------------

/// A compiled rewrite operation ready for per-request execution.
enum Operation {
    /// Replace matches of a regex pattern in the path.
    RegexReplace {
        /// Compiled regex pattern.
        pattern: Regex,
        /// Replacement template (supports `$1`, `$2`, etc.).
        replacement: String,
    },

    /// Remove named query parameters.
    StripQueryParams(HashSet<String>),

    /// Append query parameters.
    AddQueryParams(Vec<(String, String)>),
}

// -----------------------------------------------------------------------------
// Operation Execution
// -----------------------------------------------------------------------------

/// Apply all operations to a path and query string, returning the
/// (possibly rewritten) path and query.
fn apply_operations<'a>(
    operations: &[Operation],
    original_path: &'a str,
    original_query: Option<&'a str>,
) -> (Cow<'a, str>, Option<Cow<'a, str>>) {
    let mut path: Cow<'a, str> = Cow::Borrowed(original_path);
    let mut query: Option<Cow<'a, str>> = original_query.map(Cow::Borrowed);

    for op in operations {
        match op {
            Operation::RegexReplace { pattern, replacement } => {
                path = apply_regex(path, pattern, replacement);
            },
            Operation::StripQueryParams(names) => {
                query = apply_strip(query, names);
            },
            Operation::AddQueryParams(pairs) => {
                let base = query.take().unwrap_or(Cow::Borrowed(""));
                query = Some(Cow::Owned(append_params(&base, pairs)));
                trace!(added = ?pairs, "added query params");
            },
        }
    }

    (path, query)
}

// -----------------------------------------------------------------------------
// Apply Manipulations
// -----------------------------------------------------------------------------

/// Apply a single regex replacement to a path, preserving the
/// borrowed variant when no match occurs.
fn apply_regex<'a>(path: Cow<'a, str>, pattern: &Regex, replacement: &str) -> Cow<'a, str> {
    let replaced = pattern.replace_all(&path, replacement);
    match replaced {
        Cow::Borrowed(_) => path,
        Cow::Owned(new_path) => {
            trace!(pattern = %pattern.as_str(), old = %path, new = %new_path, "regex replaced path");
            Cow::Owned(new_path)
        },
    }
}

/// Strip named query parameters, returning `None` if the result
/// is empty.
fn apply_strip<'a>(query: Option<Cow<'a, str>>, names: &HashSet<String>) -> Option<Cow<'a, str>> {
    let qs = query?;
    let filtered = strip_params(&qs, names);
    trace!(removed = ?names, "stripped query params");
    if filtered.is_empty() {
        None
    } else {
        Some(Cow::Owned(filtered))
    }
}

// -----------------------------------------------------------------------------
// Compilation
// -----------------------------------------------------------------------------

/// Compile raw operation configs into executable operations.
fn compile_operations(configs: Vec<OperationConfig>) -> Result<Vec<Operation>, FilterError> {
    let mut ops = Vec::with_capacity(configs.len());
    for config in configs {
        let OperationConfig::Map(map) = config;
        for (key, value) in map {
            match key.as_str() {
                "regex_replace" => ops.push(compile_regex_replace(&value)?),
                "strip_query_params" => ops.push(compile_strip_query_params(&value)?),
                "add_query_params" => ops.push(compile_add_query_params(&value)?),
                other => {
                    return Err(format!("url_rewrite: unknown operation '{other}'").into());
                },
            }
        }
    }
    Ok(ops)
}

/// Compile a `regex_replace` operation from its YAML value.
fn compile_regex_replace(value: &serde_yaml::Value) -> Result<Operation, FilterError> {
    #[derive(Deserialize)]
    struct RegexReplace {
        /// The regex pattern to match against the path.
        pattern: String,
        /// The replacement string (supports group references).
        replacement: String,
    }

    let rr: RegexReplace =
        serde_yaml::from_value(value.clone()).map_err(|e| format!("url_rewrite: regex_replace config: {e}"))?;

    let pattern = regex::RegexBuilder::new(&rr.pattern)
        .size_limit(1 << 20)
        .build()
        .map_err(|e| format!("url_rewrite: invalid regex '{pat}': {e}", pat = rr.pattern))?;

    Ok(Operation::RegexReplace {
        pattern,
        replacement: rr.replacement,
    })
}

/// Compile a `strip_query_params` operation from its YAML value.
fn compile_strip_query_params(value: &serde_yaml::Value) -> Result<Operation, FilterError> {
    let names: HashSet<String> =
        serde_yaml::from_value(value.clone()).map_err(|e| format!("url_rewrite: strip_query_params config: {e}"))?;
    Ok(Operation::StripQueryParams(names))
}

/// Compile an `add_query_params` operation from its YAML value.
///
/// Uses [`BTreeMap`] for deterministic (sorted) parameter ordering.
fn compile_add_query_params(value: &serde_yaml::Value) -> Result<Operation, FilterError> {
    let map: BTreeMap<String, String> =
        serde_yaml::from_value(value.clone()).map_err(|e| format!("url_rewrite: add_query_params config: {e}"))?;
    let pairs: Vec<(String, String)> = map.into_iter().collect();
    Ok(Operation::AddQueryParams(pairs))
}

// -----------------------------------------------------------------------------
// Query String Manipulation
// -----------------------------------------------------------------------------

/// Remove named parameters from a query string.
fn strip_params(qs: &str, remove: &HashSet<String>) -> String {
    qs.split('&')
        .filter(|pair| {
            let key = pair.split('=').next().unwrap_or("");
            !remove.contains(key)
        })
        .collect::<Vec<_>>()
        .join("&")
}

/// Append key-value pairs to a query string, percent-encoding values.
///
/// Uses [`percent_encoding::utf8_percent_encode`] with a set that
/// encodes characters unsafe in query values: space, `"`, `#`, `&`,
/// `+`, and `=`.
///
/// [`percent_encoding::utf8_percent_encode`]: percent_encoding::utf8_percent_encode
fn append_params(qs: &str, pairs: &[(String, String)]) -> String {
    use percent_encoding::utf8_percent_encode;

    let mut result = qs.to_owned();
    for (k, v) in pairs {
        if !result.is_empty() {
            result.push('&');
        }
        result.push_str(k);
        result.push('=');
        result.push_str(&utf8_percent_encode(v, QUERY_VALUE_ENCODE_SET).to_string());
    }
    result
}

/// Reassemble a path and optional query string into a URI
/// path-and-query component.
fn build_path_and_query(path: &str, query: Option<&str>) -> String {
    let effective_path = if path.is_empty() { "/" } else { path };
    match query {
        Some(q) if !q.is_empty() => format!("{effective_path}?{q}"),
        _ => effective_path.to_owned(),
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::needless_raw_strings,
    clippy::needless_raw_string_hashes,
    reason = "tests"
)]
mod tests {
    use http::Method;

    use super::*;
    use crate::test_utils;

    #[tokio::test]
    async fn basic_regex_replacement() {
        let filter = make_filter(&[Op::Regex("^/v1/(.*)", "/v2/$1")]);
        let req = test_utils::make_request(Method::GET, "/v1/users?page=1");
        let mut ctx = test_utils::make_filter_context(&req);

        let action = filter.on_request(&mut ctx).await.unwrap();

        assert!(matches!(action, FilterAction::Continue));
        assert_eq!(
            ctx.rewritten_path.as_deref(),
            Some("/v2/users?page=1"),
            "regex should rewrite path and preserve query"
        );
    }

    #[tokio::test]
    async fn multiple_regex_replacements_applied_in_order() {
        let filter = make_filter(&[Op::Regex("^/api", "/service"), Op::Regex("^/service/v1", "/service/v2")]);
        let req = test_utils::make_request(Method::GET, "/api/v1/data");
        let mut ctx = test_utils::make_filter_context(&req);

        let action = filter.on_request(&mut ctx).await.unwrap();

        assert!(matches!(action, FilterAction::Continue));
        assert_eq!(
            ctx.rewritten_path.as_deref(),
            Some("/service/v2/data"),
            "multiple regex replacements should apply in order"
        );
    }

    #[tokio::test]
    async fn strip_query_params_removes_specified_preserves_others() {
        let filter = make_filter(&[Op::StripQuery(&["debug", "trace"])]);
        let req = test_utils::make_request(Method::GET, "/path?a=1&debug=true&b=2&trace=yes");
        let mut ctx = test_utils::make_filter_context(&req);

        let action = filter.on_request(&mut ctx).await.unwrap();

        assert!(matches!(action, FilterAction::Continue));
        assert_eq!(
            ctx.rewritten_path.as_deref(),
            Some("/path?a=1&b=2"),
            "strip should remove debug and trace, keep a and b"
        );
    }

    #[tokio::test]
    async fn add_query_params_appends() {
        let filter = make_filter(&[Op::AddQuery(&[("version", "2")])]);
        let req = test_utils::make_request(Method::GET, "/path?a=1");
        let mut ctx = test_utils::make_filter_context(&req);

        let action = filter.on_request(&mut ctx).await.unwrap();

        assert!(matches!(action, FilterAction::Continue));
        assert_eq!(
            ctx.rewritten_path.as_deref(),
            Some("/path?a=1&version=2"),
            "add should append version=2 to existing query"
        );
    }

    #[tokio::test]
    async fn combined_regex_and_query_manipulation() {
        let filter = make_filter(&[
            Op::Regex("^/old/(.*)", "/new/$1"),
            Op::StripQuery(&["debug"]),
            Op::AddQuery(&[("source", "gw")]),
        ]);
        let req = test_utils::make_request(Method::GET, "/old/resource?debug=1&keep=yes");
        let mut ctx = test_utils::make_filter_context(&req);

        let action = filter.on_request(&mut ctx).await.unwrap();

        assert!(matches!(action, FilterAction::Continue));
        assert_eq!(
            ctx.rewritten_path.as_deref(),
            Some("/new/resource?keep=yes&source=gw"),
            "combined ops should rewrite path, strip debug, add source"
        );
    }

    #[tokio::test]
    async fn path_only_rewrite_preserves_query_string() {
        let filter = make_filter(&[Op::Regex("^/a", "/b")]);
        let req = test_utils::make_request(Method::GET, "/a/thing?x=1&y=2");
        let mut ctx = test_utils::make_filter_context(&req);

        drop(filter.on_request(&mut ctx).await.unwrap());

        assert_eq!(
            ctx.rewritten_path.as_deref(),
            Some("/b/thing?x=1&y=2"),
            "path-only rewrite should preserve original query string"
        );
    }

    #[tokio::test]
    async fn query_only_rewrite_preserves_path() {
        let filter = make_filter(&[Op::StripQuery(&["secret"])]);
        let req = test_utils::make_request(Method::GET, "/keep/this/path?secret=abc&ok=1");
        let mut ctx = test_utils::make_filter_context(&req);

        drop(filter.on_request(&mut ctx).await.unwrap());

        assert_eq!(
            ctx.rewritten_path.as_deref(),
            Some("/keep/this/path?ok=1"),
            "query-only rewrite should preserve original path"
        );
    }

    #[tokio::test]
    async fn no_op_when_no_patterns_match() {
        let filter = make_filter(&[Op::Regex("^/nomatch", "/replaced")]);
        let req = test_utils::make_request(Method::GET, "/other/path?q=1");
        let mut ctx = test_utils::make_filter_context(&req);

        drop(filter.on_request(&mut ctx).await.unwrap());

        assert!(
            ctx.rewritten_path.is_none(),
            "rewritten_path should be None when no patterns match"
        );
    }

    #[tokio::test]
    async fn add_query_params_to_path_without_query() {
        let filter = make_filter(&[Op::AddQuery(&[("key", "val")])]);
        let req = test_utils::make_request(Method::GET, "/path");
        let mut ctx = test_utils::make_filter_context(&req);

        drop(filter.on_request(&mut ctx).await.unwrap());

        assert_eq!(
            ctx.rewritten_path.as_deref(),
            Some("/path?key=val"),
            "add_query_params should create query string when none exists"
        );
    }

    #[tokio::test]
    async fn strip_all_query_params_removes_query_string() {
        let filter = make_filter(&[Op::StripQuery(&["a", "b"])]);
        let req = test_utils::make_request(Method::GET, "/path?a=1&b=2");
        let mut ctx = test_utils::make_filter_context(&req);

        drop(filter.on_request(&mut ctx).await.unwrap());

        assert_eq!(
            ctx.rewritten_path.as_deref(),
            Some("/path"),
            "stripping all params should remove query string entirely"
        );
    }

    #[tokio::test]
    async fn from_config_empty_operations_is_noop() {
        let config = serde_yaml::from_str::<serde_yaml::Value>("operations: []").unwrap();
        let filter = UrlRewriteFilter::from_config(&config).unwrap();
        let req = test_utils::make_request(Method::GET, "/path?q=1");
        let mut ctx = test_utils::make_filter_context(&req);

        drop(filter.on_request(&mut ctx).await.unwrap());

        assert!(
            ctx.rewritten_path.is_none(),
            "empty operations should produce no rewrite"
        );
    }

    #[tokio::test]
    async fn from_config_invalid_regex_returns_error() {
        let config = serde_yaml::from_str::<serde_yaml::Value>(
            r#"
operations:
  - regex_replace:
      pattern: "[invalid"
      replacement: "/x"
"#,
        )
        .unwrap();
        let err = UrlRewriteFilter::from_config(&config).err();
        assert!(err.is_some(), "invalid regex should return error");
        assert!(
            err.unwrap().to_string().contains("invalid regex"),
            "error should mention invalid regex"
        );
    }

    #[tokio::test]
    async fn path_traversal_dot_dot_slash_normalized() {
        let filter = make_filter(&[Op::Regex("^/api/(.*)", "/internal/$1")]);
        let req = test_utils::make_request(Method::GET, "/api/../etc/passwd");
        let mut ctx = test_utils::make_filter_context(&req);

        drop(filter.on_request(&mut ctx).await.unwrap());

        assert_eq!(
            ctx.rewritten_path.as_deref(),
            Some("/etc/passwd"),
            "/../ in rewritten path should be normalized"
        );
    }

    #[tokio::test]
    async fn path_traversal_dot_slash_normalized() {
        let filter = make_filter(&[Op::Regex("^/app/(.*)", "/svc/$1")]);
        let req = test_utils::make_request(Method::GET, "/app/./config");
        let mut ctx = test_utils::make_filter_context(&req);

        drop(filter.on_request(&mut ctx).await.unwrap());

        assert_eq!(
            ctx.rewritten_path.as_deref(),
            Some("/svc/config"),
            "/./ in rewritten path should be normalized"
        );
    }

    #[tokio::test]
    async fn path_traversal_double_slash_normalized() {
        let filter = make_filter(&[Op::Regex("^/api/(.*)", "/v2/$1")]);
        let req = test_utils::make_request(Method::GET, "/api//secret");
        let mut ctx = test_utils::make_filter_context(&req);

        drop(filter.on_request(&mut ctx).await.unwrap());

        assert_eq!(
            ctx.rewritten_path.as_deref(),
            Some("/v2/secret"),
            "// in rewritten path should be collapsed"
        );
    }

    #[tokio::test]
    async fn encoded_traversal_percent_2e() {
        let filter = make_filter(&[Op::Regex("^/api/(.*)", "/v2/$1")]);
        let req = test_utils::make_request(Method::GET, "/api/%2e%2e%2fsecret");
        let mut ctx = test_utils::make_filter_context(&req);

        drop(filter.on_request(&mut ctx).await.unwrap());

        assert_eq!(
            ctx.rewritten_path.as_deref(),
            Some("/v2/%2e%2e%2fsecret"),
            "encoded traversal sequences should pass through raw"
        );
    }

    #[tokio::test]
    async fn null_byte_in_path() {
        let filter = make_filter(&[Op::Regex("^/api/(.*)", "/v2/$1")]);
        let req = test_utils::make_request(Method::GET, "/api/file%00.txt");
        let mut ctx = test_utils::make_filter_context(&req);

        drop(filter.on_request(&mut ctx).await.unwrap());

        assert_eq!(
            ctx.rewritten_path.as_deref(),
            Some("/v2/file%00.txt"),
            "null byte should pass through without special handling"
        );
    }

    #[tokio::test]
    async fn very_long_path() {
        let long_segment = "a".repeat(10_000);
        let path = format!("/api/{long_segment}");
        let filter = make_filter(&[Op::Regex("^/api/(.*)", "/v2/$1")]);
        let req = test_utils::make_request(Method::GET, &path);
        let mut ctx = test_utils::make_filter_context(&req);

        drop(filter.on_request(&mut ctx).await.unwrap());

        let expected = format!("/v2/{long_segment}");
        assert_eq!(
            ctx.rewritten_path.as_deref(),
            Some(expected.as_str()),
            "very long paths should be handled correctly"
        );
    }

    #[tokio::test]
    async fn unicode_in_path() {
        let filter = make_filter(&[Op::Regex("^/api/(.*)", "/v2/$1")]);
        let req = test_utils::make_request(Method::GET, "/api/%E4%B8%96%E7%95%8C");
        let mut ctx = test_utils::make_filter_context(&req);

        drop(filter.on_request(&mut ctx).await.unwrap());

        assert_eq!(
            ctx.rewritten_path.as_deref(),
            Some("/v2/%E4%B8%96%E7%95%8C"),
            "percent-encoded unicode should pass through"
        );
    }

    #[tokio::test]
    async fn empty_path_gets_slash() {
        let filter = make_filter(&[Op::AddQuery(&[("k", "v")])]);
        let req = test_utils::make_request(Method::GET, "/?existing=1");
        let mut ctx = test_utils::make_filter_context(&req);

        drop(filter.on_request(&mut ctx).await.unwrap());

        let rewritten = ctx.rewritten_path.as_deref().unwrap();
        assert!(
            rewritten.starts_with("/?") || rewritten.starts_with("/?"),
            "root path should be preserved: {rewritten}"
        );
        assert!(rewritten.contains("k=v"), "added param should appear: {rewritten}");
    }

    #[tokio::test]
    async fn root_path_only() {
        let filter = make_filter(&[Op::Regex("^/$", "/index")]);
        let req = test_utils::make_request(Method::GET, "/");
        let mut ctx = test_utils::make_filter_context(&req);

        drop(filter.on_request(&mut ctx).await.unwrap());

        assert_eq!(
            ctx.rewritten_path.as_deref(),
            Some("/index"),
            "root path should be rewritable"
        );
    }

    #[tokio::test]
    async fn query_key_without_value() {
        let filter = make_filter(&[Op::StripQuery(&["other"])]);
        let req = test_utils::make_request(Method::GET, "/path?key&other=1");
        let mut ctx = test_utils::make_filter_context(&req);

        drop(filter.on_request(&mut ctx).await.unwrap());

        assert_eq!(
            ctx.rewritten_path.as_deref(),
            Some("/path?key"),
            "key without value should be preserved by strip"
        );
    }

    #[tokio::test]
    async fn query_with_duplicate_keys() {
        let filter = make_filter(&[Op::StripQuery(&["x"])]);
        let req = test_utils::make_request(Method::GET, "/path?a=1&x=2&a=3&x=4");
        let mut ctx = test_utils::make_filter_context(&req);

        drop(filter.on_request(&mut ctx).await.unwrap());

        assert_eq!(
            ctx.rewritten_path.as_deref(),
            Some("/path?a=1&a=3"),
            "all occurrences of stripped key should be removed"
        );
    }

    #[tokio::test]
    async fn query_with_encoded_ampersand_and_equals() {
        let filter = make_filter(&[Op::StripQuery(&["clean"])]);
        let req = test_utils::make_request(Method::GET, "/path?val=a%26b%3Dc&clean=1");
        let mut ctx = test_utils::make_filter_context(&req);

        drop(filter.on_request(&mut ctx).await.unwrap());

        assert_eq!(
            ctx.rewritten_path.as_deref(),
            Some("/path?val=a%26b%3Dc"),
            "encoded & and = in values should not split params"
        );
    }

    #[tokio::test]
    async fn regex_catastrophic_backtracking_does_not_hang() {
        let pattern = "(a+)+$";
        let filter = make_filter(&[Op::Regex(pattern, "/replaced")]);
        let input = format!("/{}b", "a".repeat(30));
        let req = test_utils::make_request(Method::GET, &input);
        let mut ctx = test_utils::make_filter_context(&req);

        drop(filter.on_request(&mut ctx).await.unwrap());

        assert!(
            ctx.rewritten_path.is_none(),
            "regex crate's backtracking protection should prevent hang"
        );
    }

    #[tokio::test]
    async fn replacement_with_group_references() {
        let filter = make_filter(&[Op::Regex(r"^/(\w+)/(\w+)", "/reversed/$2/$1")]);
        let req = test_utils::make_request(Method::GET, "/first/second/rest");
        let mut ctx = test_utils::make_filter_context(&req);

        drop(filter.on_request(&mut ctx).await.unwrap());

        assert_eq!(
            ctx.rewritten_path.as_deref(),
            Some("/reversed/second/first/rest"),
            "group references $1 and $2 should be substituted"
        );
    }

    #[tokio::test]
    async fn replacement_with_literal_dollar() {
        let filter = make_filter(&[Op::Regex("^/price", "/cost$$")]);
        let req = test_utils::make_request(Method::GET, "/price");
        let mut ctx = test_utils::make_filter_context(&req);

        drop(filter.on_request(&mut ctx).await.unwrap());

        assert_eq!(
            ctx.rewritten_path.as_deref(),
            Some("/cost$"),
            "literal $$ in replacement should produce single $"
        );
    }

    #[tokio::test]
    async fn path_with_trailing_slash() {
        let filter = make_filter(&[Op::Regex("^/api/v1/(.*)", "/api/v2/$1")]);
        let req = test_utils::make_request(Method::GET, "/api/v1/users/");
        let mut ctx = test_utils::make_filter_context(&req);

        drop(filter.on_request(&mut ctx).await.unwrap());

        assert_eq!(
            ctx.rewritten_path.as_deref(),
            Some("/api/v2/users/"),
            "trailing slash should be preserved"
        );
    }

    #[tokio::test]
    async fn path_without_trailing_slash() {
        let filter = make_filter(&[Op::Regex("^/api/v1/(.*)", "/api/v2/$1")]);
        let req = test_utils::make_request(Method::GET, "/api/v1/users");
        let mut ctx = test_utils::make_filter_context(&req);

        drop(filter.on_request(&mut ctx).await.unwrap());

        assert_eq!(
            ctx.rewritten_path.as_deref(),
            Some("/api/v2/users"),
            "path without trailing slash should not gain one"
        );
    }

    #[tokio::test]
    async fn strip_nonexistent_query_param_is_noop() {
        let filter = make_filter(&[Op::StripQuery(&["nonexistent"])]);
        let req = test_utils::make_request(Method::GET, "/path?a=1");
        let mut ctx = test_utils::make_filter_context(&req);

        drop(filter.on_request(&mut ctx).await.unwrap());

        assert!(
            ctx.rewritten_path.is_none(),
            "stripping nonexistent param should be a no-op"
        );
    }

    #[tokio::test]
    async fn strip_query_with_no_query_string_is_noop() {
        let filter = make_filter(&[Op::StripQuery(&["x"])]);
        let req = test_utils::make_request(Method::GET, "/path");
        let mut ctx = test_utils::make_filter_context(&req);

        drop(filter.on_request(&mut ctx).await.unwrap());

        assert!(
            ctx.rewritten_path.is_none(),
            "stripping from absent query string should be no-op"
        );
    }

    #[tokio::test]
    async fn regex_only_replaces_first_full_match() {
        let filter = make_filter(&[Op::Regex("foo", "bar")]);
        let req = test_utils::make_request(Method::GET, "/foo/foo/foo");
        let mut ctx = test_utils::make_filter_context(&req);

        drop(filter.on_request(&mut ctx).await.unwrap());

        assert_eq!(
            ctx.rewritten_path.as_deref(),
            Some("/bar/bar/bar"),
            "replace_all should replace all occurrences"
        );
    }

    #[tokio::test]
    async fn from_config_unknown_operation_returns_error() {
        let config = serde_yaml::from_str::<serde_yaml::Value>(
            r#"
operations:
  - unknown_op: {}
"#,
        )
        .unwrap();
        let result = UrlRewriteFilter::from_config(&config);
        assert!(result.is_err(), "unknown operation should return error");
        let err = result.err().unwrap();
        assert!(
            err.to_string().contains("unknown operation"),
            "error should mention unknown operation, got: {err}"
        );
    }

    #[tokio::test]
    async fn regex_replace_preserves_existing_rewritten_path() {
        let filter = make_filter(&[Op::Regex("^/a", "/b")]);
        let req = test_utils::make_request(Method::GET, "/a/resource");
        let mut ctx = test_utils::make_filter_context(&req);
        ctx.rewritten_path = Some("/previously/set".to_owned());

        drop(filter.on_request(&mut ctx).await.unwrap());

        assert_eq!(
            ctx.rewritten_path.as_deref(),
            Some("/b/resource"),
            "url_rewrite should overwrite prior rewritten_path based on original URI"
        );
    }

    #[tokio::test]
    async fn add_query_params_multiple_deterministic_order() {
        let config = serde_yaml::from_str::<serde_yaml::Value>(
            r#"
operations:
  - add_query_params:
      zebra: z
      alpha: a
      middle: m
"#,
        )
        .expect("valid yaml");
        let filter = UrlRewriteFilter::from_config(&config).expect("valid config");
        let req = test_utils::make_request(Method::GET, "/path");
        let mut ctx = test_utils::make_filter_context(&req);

        drop(filter.on_request(&mut ctx).await.expect("on_request ok"));

        assert_eq!(
            ctx.rewritten_path.as_deref(),
            Some("/path?alpha=a&middle=m&zebra=z"),
            "add_query_params should add in deterministic sorted order"
        );
    }

    #[tokio::test]
    async fn add_query_params_percent_encodes_values() {
        let filter = make_filter(&[Op::AddQuery(&[
            ("k1", "value with spaces"),
            ("k2", "a=b&c"),
            ("k3", "normal"),
        ])]);
        let req = test_utils::make_request(Method::GET, "/path");
        let mut ctx = test_utils::make_filter_context(&req);

        drop(filter.on_request(&mut ctx).await.expect("on_request ok"));

        let rewritten = ctx.rewritten_path.as_deref().expect("should rewrite");
        assert!(
            rewritten.contains("k1=value%20with%20spaces"),
            "spaces should be percent-encoded: {rewritten}"
        );
        assert!(
            rewritten.contains("k2=a%3Db%26c"),
            "= and & should be percent-encoded: {rewritten}"
        );
        assert!(
            rewritten.contains("k3=normal"),
            "plain values should pass through: {rewritten}"
        );
    }

    #[tokio::test]
    async fn strip_query_params_empty_name_list_is_noop() {
        let filter = make_filter(&[Op::StripQuery(&[])]);
        let req = test_utils::make_request(Method::GET, "/path?a=1&b=2");
        let mut ctx = test_utils::make_filter_context(&req);

        drop(filter.on_request(&mut ctx).await.expect("on_request ok"));

        assert!(
            ctx.rewritten_path.is_none(),
            "stripping with empty name list should be a no-op"
        );
    }

    #[tokio::test]
    async fn empty_regex_replace_pattern_matches_every_position() {
        let filter = make_filter(&[Op::Regex("", "x")]);
        let req = test_utils::make_request(Method::GET, "/ab");
        let mut ctx = test_utils::make_filter_context(&req);

        drop(filter.on_request(&mut ctx).await.expect("on_request ok"));

        assert_eq!(
            ctx.rewritten_path.as_deref(),
            Some("/x/xaxbx"),
            "empty pattern result should be normalized with leading slash"
        );
    }

    #[tokio::test]
    async fn multiple_keys_in_one_operation_map_processed() {
        let config = serde_yaml::from_str::<serde_yaml::Value>(
            r#"
operations:
  - strip_query_params:
      - remove_me
    add_query_params:
      added: yes
"#,
        )
        .expect("valid yaml");
        let filter = UrlRewriteFilter::from_config(&config).expect("valid config");
        let req = test_utils::make_request(Method::GET, "/path?remove_me=1&keep=2");
        let mut ctx = test_utils::make_filter_context(&req);

        drop(filter.on_request(&mut ctx).await.expect("on_request ok"));

        let rewritten = ctx.rewritten_path.as_deref().expect("should rewrite");
        assert!(rewritten.contains("keep=2"), "kept param should survive: {rewritten}");
        assert!(
            !rewritten.contains("remove_me"),
            "stripped param should be gone: {rewritten}"
        );
        assert!(
            rewritten.contains("added=yes"),
            "added param should appear: {rewritten}"
        );
    }

    #[tokio::test]
    async fn add_query_params_encodes_special_characters() {
        let filter = make_filter(&[Op::AddQuery(&[("key", "value with spaces&more=stuff")])]);
        let req = test_utils::make_request(Method::GET, "/path");
        let mut ctx = test_utils::make_filter_context(&req);

        drop(filter.on_request(&mut ctx).await.expect("on_request ok"));

        let rewritten = ctx.rewritten_path.as_deref().expect("should rewrite");
        assert!(
            !rewritten.contains(' '),
            "spaces should be percent-encoded: {rewritten}"
        );
        assert!(
            rewritten.contains("value%20with%20spaces"),
            "spaces should become %20: {rewritten}"
        );
        assert!(
            rewritten.contains("%26more%3Dstuff"),
            "& and = should be encoded: {rewritten}"
        );
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// Describes a test operation for building filters concisely.
    enum Op<'a> {
        /// Regex pattern and replacement.
        Regex(&'a str, &'a str),
        /// List of query param names to strip.
        StripQuery(&'a [&'a str]),
        /// List of (key, value) pairs to add.
        AddQuery(&'a [(&'a str, &'a str)]),
    }

    /// Build a [`UrlRewriteFilter`] from a slice of test operations.
    fn make_filter(ops: &[Op<'_>]) -> UrlRewriteFilter {
        let operations = ops
            .iter()
            .map(|op| match op {
                Op::Regex(pat, repl) => Operation::RegexReplace {
                    pattern: Regex::new(pat).unwrap(),
                    replacement: (*repl).to_owned(),
                },
                Op::StripQuery(names) => Operation::StripQueryParams(names.iter().map(|s| (*s).to_owned()).collect()),
                Op::AddQuery(pairs) => {
                    Operation::AddQueryParams(pairs.iter().map(|(k, v)| ((*k).to_owned(), (*v).to_owned())).collect())
                },
            })
            .collect();
        UrlRewriteFilter { operations }
    }
}
