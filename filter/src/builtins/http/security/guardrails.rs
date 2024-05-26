//! Rejects requests matching string or regex guardrail rules.

use async_trait::async_trait;
use bytes::Bytes;
use regex::{Regex, RegexBuilder};
use serde::Deserialize;

use crate::{
    FilterAction, FilterError, Rejection,
    body::{BodyAccess, BodyMode},
    factory::parse_filter_config,
    filter::{HttpFilter, HttpFilterContext},
};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Default maximum body size for body inspection (1 MiB).
const DEFAULT_MAX_BODY_BYTES: usize = 1_048_576;

/// Maximum allowed regex pattern length (characters).
const MAX_REGEX_PATTERN_LEN: usize = 1024;

/// Maximum compiled regex automaton size (bytes, 1 MiB).
const MAX_REGEX_SIZE: usize = 1_048_576;

// -----------------------------------------------------------------------------
// RuleConfig
// -----------------------------------------------------------------------------

/// Deserialized YAML config for a single guardrail rule.
#[derive(Debug, Deserialize)]
struct RuleConfig {
    /// What to inspect: `"header"` or `"body"`.
    target: String,

    /// Header name (required when `target` is `"header"`).
    name: Option<String>,

    /// Literal substring match (case-sensitive).
    contains: Option<String>,

    /// Regex pattern match.
    pattern: Option<String>,

    /// Invert the match: reject when the content does NOT
    /// match. For negated header rules, a missing header
    /// also triggers rejection. Defaults to `false`.
    #[serde(default)]
    negate: bool,
}

/// Deserialized YAML config for the guardrails filter.
#[derive(Debug, Deserialize)]
struct GuardrailsConfig {
    /// List of rules to evaluate.
    rules: Vec<RuleConfig>,
}

// -----------------------------------------------------------------------------
// Compiled Rule
// -----------------------------------------------------------------------------

/// What a rule inspects.
#[derive(Debug, Clone)]
enum RuleTarget {
    /// Inspect a named request header.
    Header(String),

    /// Inspect the request body.
    Body,
}

/// How a rule matches content.
#[derive(Debug, Clone)]
enum RuleMatcher {
    /// Literal substring match (case-sensitive).
    Contains(String),

    /// Pre-compiled regex.
    Pattern(Regex),
}

/// A compiled guardrail rule ready for per-request evaluation.
#[derive(Debug, Clone)]
struct CompiledRule {
    /// What to inspect.
    target: RuleTarget,

    /// How to match.
    matcher: RuleMatcher,

    /// When true, the rule triggers on non-match instead of match.
    negate: bool,
}

impl CompiledRule {
    /// Check whether `haystack` matches this rule.
    fn matches(&self, haystack: &str) -> bool {
        match &self.matcher {
            RuleMatcher::Contains(needle) => haystack.contains(needle.as_str()),
            RuleMatcher::Pattern(re) => re.is_match(haystack),
        }
    }
}

// -----------------------------------------------------------------------------
// GuardrailsFilter
// -----------------------------------------------------------------------------

/// Rejects requests matching string or regex rules against headers and/or body content.
///
/// # YAML configuration
///
/// ```yaml
/// filter: guardrails
/// rules:
///   # Block requests from bad bots
///   - target: header
///     name: "User-Agent"
///     pattern: "bad-bot.*"
///   # Block SQL injection in body
///   - target: body
///     contains: "DROP TABLE"
///   # Require body to look like JSON (reject if NOT matching)
///   - target: body
///     pattern: "^\\{.*\\}$"
///     negate: true
/// ```
///
/// # Example
///
/// ```
/// use praxis_filter::GuardrailsFilter;
///
/// let yaml: serde_yaml::Value = serde_yaml::from_str(r#"
/// rules:
///   - target: header
///     name: User-Agent
///     contains: bad-bot
/// "#).unwrap();
/// let filter = GuardrailsFilter::from_config(&yaml).unwrap();
/// assert_eq!(filter.name(), "guardrails");
/// ```
pub struct GuardrailsFilter {
    /// Compiled rules for per-request evaluation.
    rules: Vec<CompiledRule>,

    /// Whether any rule targets the body (pre-computed at init).
    needs_body: bool,
}

impl GuardrailsFilter {
    /// Create a guardrails filter from parsed YAML config.
    ///
    /// Compiles all regex patterns at init time. Returns an error
    /// if a rule has an invalid regex, missing fields, or unknown
    /// target.
    ///
    /// ```
    /// use praxis_filter::GuardrailsFilter;
    ///
    /// let yaml: serde_yaml::Value = serde_yaml::from_str(r#"
    /// rules:
    ///   - target: body
    ///     pattern: "SELECT.*FROM"
    /// "#).unwrap();
    /// let filter = GuardrailsFilter::from_config(&yaml).unwrap();
    /// assert_eq!(filter.name(), "guardrails");
    /// ```
    pub fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        let cfg: GuardrailsConfig = parse_filter_config("guardrails", config)?;

        if cfg.rules.is_empty() {
            return Err("guardrails: 'rules' must not be empty".into());
        }

        let mut rules = Vec::with_capacity(cfg.rules.len());
        let mut needs_body = false;

        for rule in &cfg.rules {
            let target = parse_target(rule)?;
            let matcher = parse_matcher(rule)?;

            if matches!(target, RuleTarget::Body) {
                needs_body = true;
            }

            rules.push(CompiledRule {
                target,
                matcher,
                negate: rule.negate,
            });
        }

        Ok(Box::new(Self { rules, needs_body }))
    }

    /// Check all header-targeted rules against the request headers.
    fn check_headers(&self, ctx: &HttpFilterContext<'_>) -> bool {
        for rule in &self.rules {
            let RuleTarget::Header(ref header_name) = rule.target else {
                continue;
            };

            let matched = ctx
                .request
                .headers
                .get(header_name.as_str())
                .and_then(|val| val.to_str().ok())
                .is_some_and(|s| rule.matches(s));

            let triggered = if rule.negate { !matched } else { matched };

            if triggered {
                tracing::info!(
                    header = %header_name,
                    negate = rule.negate,
                    "guardrails: header rule triggered, rejecting"
                );
                return true;
            }
        }
        false
    }

    /// Check all body-targeted rules against the request body.
    fn check_body(&self, body: &str) -> bool {
        for rule in &self.rules {
            if !matches!(rule.target, RuleTarget::Body) {
                continue;
            }

            let matched = rule.matches(body);
            let triggered = if rule.negate { !matched } else { matched };

            if triggered {
                tracing::info!(negate = rule.negate, "guardrails: body rule triggered, rejecting");
                return true;
            }
        }
        false
    }
}

/// Rejection response for guardrails violations.
fn unauthorized() -> FilterAction {
    FilterAction::Reject(Rejection::status(401).with_body(b"Unauthorized" as &[u8]))
}

#[async_trait]
impl HttpFilter for GuardrailsFilter {
    fn name(&self) -> &'static str {
        "guardrails"
    }

    fn request_body_access(&self) -> BodyAccess {
        if self.needs_body {
            BodyAccess::ReadOnly
        } else {
            BodyAccess::None
        }
    }

    fn request_body_mode(&self) -> BodyMode {
        if self.needs_body {
            BodyMode::Buffer {
                max_bytes: DEFAULT_MAX_BODY_BYTES,
            }
        } else {
            BodyMode::Stream
        }
    }

    async fn on_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        if self.check_headers(ctx) {
            return Ok(unauthorized());
        }
        Ok(FilterAction::Continue)
    }

    async fn on_request_body(
        &self,
        _ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        _end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        let Some(chunk) = body.as_ref() else {
            return Ok(FilterAction::Continue);
        };

        let text = String::from_utf8_lossy(chunk);
        if self.check_body(&text) {
            return Ok(unauthorized());
        }

        Ok(FilterAction::Continue)
    }
}

// -----------------------------------------------------------------------------
// Config Parsing
// -----------------------------------------------------------------------------

/// Parse the target field from a rule config.
fn parse_target(rule: &RuleConfig) -> Result<RuleTarget, FilterError> {
    match rule.target.as_str() {
        "header" => {
            let name = rule
                .name
                .as_ref()
                .ok_or_else(|| -> FilterError { "guardrails: 'name' is required for header rules".into() })?;
            if name.is_empty() {
                return Err("guardrails: 'name' must not be empty".into());
            }
            Ok(RuleTarget::Header(name.clone()))
        },
        "body" => Ok(RuleTarget::Body),
        other => Err(format!("guardrails: unknown target '{other}', expected 'header' or 'body'").into()),
    }
}

/// Parse the matcher (contains or pattern) from a rule config.
///
/// Regex patterns are subject to length and compiled-size limits
/// to prevent configurations from consuming excessive memory.
fn parse_matcher(rule: &RuleConfig) -> Result<RuleMatcher, FilterError> {
    match (&rule.contains, &rule.pattern) {
        (Some(s), None) => {
            if s.is_empty() {
                return Err("guardrails: 'contains' must not be empty".into());
            }
            Ok(RuleMatcher::Contains(s.clone()))
        },
        (None, Some(p)) => {
            if p.is_empty() {
                return Err("guardrails: 'pattern' must not be empty".into());
            }
            if p.len() > MAX_REGEX_PATTERN_LEN {
                return Err(format!(
                    "guardrails: regex pattern exceeds {MAX_REGEX_PATTERN_LEN} character limit ({} chars)",
                    p.len()
                )
                .into());
            }
            let re = RegexBuilder::new(p)
                .size_limit(MAX_REGEX_SIZE)
                .build()
                .map_err(|e| -> FilterError { format!("guardrails: invalid regex '{p}': {e}").into() })?;
            Ok(RuleMatcher::Pattern(re))
        },
        (Some(_), Some(_)) => Err("guardrails: use 'contains' or 'pattern', not both".into()),
        (None, None) => Err("guardrails: each rule must have 'contains' or 'pattern'".into()),
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a header-contains rule for testing.
    fn header_contains(name: &str, needle: &str) -> CompiledRule {
        CompiledRule {
            target: RuleTarget::Header(name.to_string()),
            matcher: RuleMatcher::Contains(needle.to_string()),
            negate: false,
        }
    }

    /// Build a negated header-contains rule for testing.
    fn header_not_contains(name: &str, needle: &str) -> CompiledRule {
        CompiledRule {
            target: RuleTarget::Header(name.to_string()),
            matcher: RuleMatcher::Contains(needle.to_string()),
            negate: true,
        }
    }

    /// Build a header-pattern rule for testing.
    fn header_pattern(name: &str, re: &str) -> CompiledRule {
        CompiledRule {
            target: RuleTarget::Header(name.to_string()),
            matcher: RuleMatcher::Pattern(Regex::new(re).unwrap()),
            negate: false,
        }
    }

    /// Build a body-contains rule for testing.
    fn body_contains(needle: &str) -> CompiledRule {
        CompiledRule {
            target: RuleTarget::Body,
            matcher: RuleMatcher::Contains(needle.to_string()),
            negate: false,
        }
    }

    /// Build a negated body-contains rule for testing.
    fn body_not_contains(needle: &str) -> CompiledRule {
        CompiledRule {
            target: RuleTarget::Body,
            matcher: RuleMatcher::Contains(needle.to_string()),
            negate: true,
        }
    }

    /// Build a body-pattern rule for testing.
    fn body_pattern(re: &str) -> CompiledRule {
        CompiledRule {
            target: RuleTarget::Body,
            matcher: RuleMatcher::Pattern(Regex::new(re).unwrap()),
            negate: false,
        }
    }

    /// Build a negated body-pattern rule for testing.
    fn body_not_pattern(re: &str) -> CompiledRule {
        CompiledRule {
            target: RuleTarget::Body,
            matcher: RuleMatcher::Pattern(Regex::new(re).unwrap()),
            negate: true,
        }
    }

    /// Build a filter from compiled rules.
    fn make_filter(rules: Vec<CompiledRule>) -> GuardrailsFilter {
        let needs_body = rules.iter().any(|r| matches!(r.target, RuleTarget::Body));
        GuardrailsFilter { rules, needs_body }
    }

    #[test]
    fn from_config_parses_header_contains() {
        let yaml: serde_yaml::Value = serde_yaml::from_str(
            r#"
            rules:
              - target: header
                name: User-Agent
                contains: bad-bot
            "#,
        )
        .unwrap();
        let filter = GuardrailsFilter::from_config(&yaml).unwrap();
        assert_eq!(filter.name(), "guardrails", "filter name should be guardrails");
    }

    #[test]
    fn from_config_parses_body_pattern() {
        let yaml: serde_yaml::Value = serde_yaml::from_str(
            r#"
            rules:
              - target: body
                pattern: "DROP\\s+TABLE"
            "#,
        )
        .unwrap();
        let filter = GuardrailsFilter::from_config(&yaml).unwrap();
        assert_eq!(filter.name(), "guardrails", "body pattern config should parse");
    }

    #[test]
    fn from_config_rejects_empty_rules() {
        let yaml: serde_yaml::Value = serde_yaml::from_str("rules: []").unwrap();
        let err = GuardrailsFilter::from_config(&yaml).err().expect("should fail");
        assert!(
            err.to_string().contains("must not be empty"),
            "should reject empty rules, got: {err}"
        );
    }

    #[test]
    fn from_config_rejects_unknown_target() {
        let yaml: serde_yaml::Value = serde_yaml::from_str(
            r#"
            rules:
              - target: cookie
                contains: evil
            "#,
        )
        .unwrap();
        let err = GuardrailsFilter::from_config(&yaml).err().expect("should fail");
        assert!(
            err.to_string().contains("unknown target"),
            "should reject unknown target, got: {err}"
        );
    }

    #[test]
    fn from_config_rejects_header_without_name() {
        let yaml: serde_yaml::Value = serde_yaml::from_str(
            r#"
            rules:
              - target: header
                contains: evil
            "#,
        )
        .unwrap();
        let err = GuardrailsFilter::from_config(&yaml).err().expect("should fail");
        assert!(
            err.to_string().contains("'name' is required"),
            "should require name for header rules, got: {err}"
        );
    }

    #[test]
    fn from_config_rejects_empty_name() {
        let yaml: serde_yaml::Value = serde_yaml::from_str(
            r#"
            rules:
              - target: header
                name: ""
                contains: evil
            "#,
        )
        .unwrap();
        let err = GuardrailsFilter::from_config(&yaml).err().expect("should fail");
        assert!(
            err.to_string().contains("'name' must not be empty"),
            "should reject empty name, got: {err}"
        );
    }

    #[test]
    fn from_config_rejects_both_contains_and_pattern() {
        let yaml: serde_yaml::Value = serde_yaml::from_str(
            r#"
            rules:
              - target: body
                contains: evil
                pattern: "evil.*"
            "#,
        )
        .unwrap();
        let err = GuardrailsFilter::from_config(&yaml).err().expect("should fail");
        assert!(
            err.to_string().contains("not both"),
            "should reject both matchers, got: {err}"
        );
    }

    #[test]
    fn from_config_rejects_no_matcher() {
        let yaml: serde_yaml::Value = serde_yaml::from_str(
            r#"
            rules:
              - target: body
            "#,
        )
        .unwrap();
        let err = GuardrailsFilter::from_config(&yaml).err().expect("should fail");
        assert!(
            err.to_string().contains("must have 'contains' or 'pattern'"),
            "should require a matcher, got: {err}"
        );
    }

    #[test]
    fn from_config_rejects_invalid_regex() {
        let yaml: serde_yaml::Value = serde_yaml::from_str(
            r#"
            rules:
              - target: body
                pattern: "[invalid"
            "#,
        )
        .unwrap();
        let err = GuardrailsFilter::from_config(&yaml).err().expect("should fail");
        assert!(
            err.to_string().contains("invalid regex"),
            "should report invalid regex, got: {err}"
        );
    }

    #[test]
    fn from_config_rejects_empty_contains() {
        let yaml: serde_yaml::Value = serde_yaml::from_str(
            r#"
            rules:
              - target: body
                contains: ""
            "#,
        )
        .unwrap();
        let err = GuardrailsFilter::from_config(&yaml).err().expect("should fail");
        assert!(
            err.to_string().contains("'contains' must not be empty"),
            "should reject empty contains, got: {err}"
        );
    }

    #[test]
    fn from_config_rejects_empty_pattern() {
        let yaml: serde_yaml::Value = serde_yaml::from_str(
            r#"
            rules:
              - target: body
                pattern: ""
            "#,
        )
        .unwrap();
        let err = GuardrailsFilter::from_config(&yaml).err().expect("should fail");
        assert!(
            err.to_string().contains("'pattern' must not be empty"),
            "should reject empty pattern, got: {err}"
        );
    }

    #[test]
    fn contains_matcher_matches_substring() {
        let rule = body_contains("DROP TABLE");
        assert!(rule.matches("SELECT 1; DROP TABLE users"), "should match substring");
    }

    #[test]
    fn contains_matcher_rejects_non_match() {
        let rule = body_contains("DROP TABLE");
        assert!(!rule.matches("SELECT 1 FROM users"), "should not match unrelated text");
    }

    #[test]
    fn contains_matcher_is_case_sensitive() {
        let rule = body_contains("DROP TABLE");
        assert!(!rule.matches("drop table users"), "contains should be case-sensitive");
    }

    #[test]
    fn pattern_matcher_matches_regex() {
        let rule = body_pattern(r"DROP\s+TABLE");
        assert!(
            rule.matches("DROP   TABLE users"),
            "regex should match whitespace variants"
        );
    }

    #[test]
    fn pattern_matcher_rejects_non_match() {
        let rule = body_pattern(r"DROP\s+TABLE");
        assert!(
            !rule.matches("SELECT 1 FROM users"),
            "regex should not match unrelated text"
        );
    }

    #[test]
    fn body_access_with_body_rules() {
        let f = make_filter(vec![body_contains("evil")]);
        assert_eq!(
            f.request_body_access(),
            BodyAccess::ReadOnly,
            "body rules need ReadOnly access"
        );
        assert_eq!(
            f.request_body_mode(),
            BodyMode::Buffer {
                max_bytes: DEFAULT_MAX_BODY_BYTES
            },
            "body rules need Buffer mode"
        );
    }

    #[test]
    fn body_access_without_body_rules() {
        let f = make_filter(vec![header_contains("User-Agent", "bot")]);
        assert_eq!(
            f.request_body_access(),
            BodyAccess::None,
            "header-only rules need no body access"
        );
        assert_eq!(
            f.request_body_mode(),
            BodyMode::Stream,
            "header-only rules use Stream mode"
        );
    }

    #[tokio::test]
    async fn header_contains_rejects_match() {
        let f = make_filter(vec![header_contains("user-agent", "bad-bot")]);
        let mut req = crate::test_utils::make_request(http::Method::GET, "/");
        req.headers.insert("user-agent", "bad-bot/1.0".parse().unwrap());
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let action = f.on_request(&mut ctx).await.unwrap();
        assert!(
            matches!(action, FilterAction::Reject(r) if r.status == 401),
            "matching header should reject with 401"
        );
    }

    #[tokio::test]
    async fn header_contains_allows_non_match() {
        let f = make_filter(vec![header_contains("user-agent", "bad-bot")]);
        let mut req = crate::test_utils::make_request(http::Method::GET, "/");
        req.headers.insert("user-agent", "good-bot/1.0".parse().unwrap());
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let action = f.on_request(&mut ctx).await.unwrap();
        assert!(
            matches!(action, FilterAction::Continue),
            "non-matching header should continue"
        );
    }

    #[tokio::test]
    async fn header_pattern_rejects_match() {
        let f = make_filter(vec![header_pattern("user-agent", r"bad-bot.*")]);
        let mut req = crate::test_utils::make_request(http::Method::GET, "/");
        req.headers.insert("user-agent", "bad-bot/2.0".parse().unwrap());
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let action = f.on_request(&mut ctx).await.unwrap();
        assert!(
            matches!(action, FilterAction::Reject(r) if r.status == 401),
            "matching header regex should reject with 401"
        );
    }

    #[tokio::test]
    async fn missing_header_does_not_match() {
        let f = make_filter(vec![header_contains("x-evil", "evilmonkey")]);
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let action = f.on_request(&mut ctx).await.unwrap();
        assert!(
            matches!(action, FilterAction::Continue),
            "missing header should not trigger rule"
        );
    }

    #[tokio::test]
    async fn body_contains_rejects_match() {
        let f = make_filter(vec![body_contains("DROP TABLE")]);
        let req = crate::test_utils::make_request(http::Method::POST, "/api");
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let mut body = Some(Bytes::from_static(b"SELECT 1; DROP TABLE users;"));
        let action = f.on_request_body(&mut ctx, &mut body, true).await.unwrap();
        assert!(
            matches!(action, FilterAction::Reject(r) if r.status == 401),
            "matching body content should reject with 401"
        );
    }

    #[tokio::test]
    async fn body_contains_allows_clean_content() {
        let f = make_filter(vec![body_contains("DROP TABLE")]);
        let req = crate::test_utils::make_request(http::Method::POST, "/api");
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let mut body = Some(Bytes::from_static(b"SELECT 1 FROM users"));
        let action = f.on_request_body(&mut ctx, &mut body, true).await.unwrap();
        assert!(
            matches!(action, FilterAction::Continue),
            "clean body content should continue"
        );
    }

    #[tokio::test]
    async fn body_pattern_rejects_match() {
        let f = make_filter(vec![body_pattern(r"(?i)drop\s+table")]);
        let req = crate::test_utils::make_request(http::Method::POST, "/api");
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let mut body = Some(Bytes::from_static(b"drop  table users"));
        let action = f.on_request_body(&mut ctx, &mut body, true).await.unwrap();
        assert!(
            matches!(action, FilterAction::Reject(r) if r.status == 401),
            "matching body regex should reject with 401"
        );
    }

    #[tokio::test]
    async fn none_body_continues() {
        let f = make_filter(vec![body_contains("evil")]);
        let req = crate::test_utils::make_request(http::Method::POST, "/api");
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let mut body: Option<Bytes> = None;
        let action = f.on_request_body(&mut ctx, &mut body, true).await.unwrap();
        assert!(matches!(action, FilterAction::Continue), "None body should continue");
    }

    #[tokio::test]
    async fn multiple_rules_first_match_rejects() {
        let f = make_filter(vec![
            header_contains("x-safe", "good"),
            header_contains("x-evil", "bad"),
        ]);
        let mut req = crate::test_utils::make_request(http::Method::GET, "/");
        req.headers.insert("x-evil", "bad-value".parse().unwrap());
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let action = f.on_request(&mut ctx).await.unwrap();
        assert!(
            matches!(action, FilterAction::Reject(r) if r.status == 401),
            "any matching rule should trigger rejection"
        );
    }

    #[tokio::test]
    async fn rejection_includes_body() {
        let f = make_filter(vec![header_contains("x-bad", "yes")]);
        let mut req = crate::test_utils::make_request(http::Method::GET, "/");
        req.headers.insert("x-bad", "yes".parse().unwrap());
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let action = f.on_request(&mut ctx).await.unwrap();
        match action {
            FilterAction::Reject(r) => {
                assert_eq!(r.status, 401, "rejection status should be 401");
                assert_eq!(
                    r.body.as_deref(),
                    Some(b"Unauthorized" as &[u8]),
                    "rejection body should be 'Unauthorized'"
                );
            },
            _ => panic!("expected rejection"),
        }
    }

    #[test]
    fn multi_rule_config_with_negate_parses() {
        let yaml: serde_yaml::Value = serde_yaml::from_str(
            r#"
            rules:
              - target: header
                name: User-Agent
                pattern: "bad-bot.*"
              - target: body
                contains: "DROP TABLE"
              - target: header
                name: X-Authorized
                contains: "trusted"
                negate: true
              - target: body
                pattern: "^\\{.*\\}$"
                negate: true
            "#,
        )
        .unwrap();
        let filter = GuardrailsFilter::from_config(&yaml).unwrap();
        assert_eq!(filter.name(), "guardrails", "mixed negate config should parse");
    }

    #[test]
    fn negate_defaults_to_false() {
        let yaml: serde_yaml::Value = serde_yaml::from_str(
            r#"
            rules:
              - target: body
                contains: evil
            "#,
        )
        .unwrap();
        let filter = GuardrailsFilter::from_config(&yaml).unwrap();
        assert_eq!(filter.name(), "guardrails", "negate should default to false");
    }

    #[tokio::test]
    async fn negated_header_rejects_when_not_matching() {
        let f = make_filter(vec![header_not_contains("x-auth", "trusted")]);
        let mut req = crate::test_utils::make_request(http::Method::GET, "/");
        req.headers.insert("x-auth", "unknown".parse().unwrap());
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let action = f.on_request(&mut ctx).await.unwrap();
        assert!(
            matches!(action, FilterAction::Reject(r) if r.status == 401),
            "negated rule should reject when header does not contain expected value"
        );
    }

    #[tokio::test]
    async fn negated_header_allows_when_matching() {
        let f = make_filter(vec![header_not_contains("x-auth", "trusted")]);
        let mut req = crate::test_utils::make_request(http::Method::GET, "/");
        req.headers.insert("x-auth", "trusted-client".parse().unwrap());
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let action = f.on_request(&mut ctx).await.unwrap();
        assert!(
            matches!(action, FilterAction::Continue),
            "negated rule should allow when header contains expected value"
        );
    }

    #[tokio::test]
    async fn negated_header_rejects_when_header_missing() {
        let f = make_filter(vec![header_not_contains("x-auth", "trusted")]);
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let action = f.on_request(&mut ctx).await.unwrap();
        assert!(
            matches!(action, FilterAction::Reject(r) if r.status == 401),
            "negated rule should reject when header is absent"
        );
    }

    #[tokio::test]
    async fn negated_body_rejects_when_not_matching() {
        let f = make_filter(vec![body_not_contains("APPROVED")]);
        let req = crate::test_utils::make_request(http::Method::POST, "/api");
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let mut body = Some(Bytes::from_static(b"some random content"));
        let action = f.on_request_body(&mut ctx, &mut body, true).await.unwrap();
        assert!(
            matches!(action, FilterAction::Reject(r) if r.status == 401),
            "negated body rule should reject when content does not match"
        );
    }

    #[tokio::test]
    async fn negated_body_allows_when_matching() {
        let f = make_filter(vec![body_not_contains("APPROVED")]);
        let req = crate::test_utils::make_request(http::Method::POST, "/api");
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let mut body = Some(Bytes::from_static(b"request APPROVED by admin"));
        let action = f.on_request_body(&mut ctx, &mut body, true).await.unwrap();
        assert!(
            matches!(action, FilterAction::Continue),
            "negated body rule should allow when content matches"
        );
    }

    #[tokio::test]
    async fn negated_body_pattern_rejects_non_json() {
        let f = make_filter(vec![body_not_pattern(r"^\{.*\}$")]);
        let req = crate::test_utils::make_request(http::Method::POST, "/api");
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let mut body = Some(Bytes::from_static(b"not json at all"));
        let action = f.on_request_body(&mut ctx, &mut body, true).await.unwrap();
        assert!(
            matches!(action, FilterAction::Reject(r) if r.status == 401),
            "negated pattern should reject body not matching expected shape"
        );
    }

    #[test]
    fn from_config_rejects_pattern_exceeding_length_limit() {
        let long_pattern = "a".repeat(MAX_REGEX_PATTERN_LEN + 1);
        let yaml: serde_yaml::Value = serde_yaml::from_str(&format!(
            r#"
            rules:
              - target: body
                pattern: "{long_pattern}"
            "#,
        ))
        .unwrap();
        let err = GuardrailsFilter::from_config(&yaml).err().expect("should fail");
        assert!(
            err.to_string().contains("character limit"),
            "should reject oversized pattern, got: {err}"
        );
    }

    #[test]
    fn from_config_accepts_pattern_at_length_limit() {
        let pattern = "a".repeat(MAX_REGEX_PATTERN_LEN);
        let yaml: serde_yaml::Value = serde_yaml::from_str(&format!(
            r#"
            rules:
              - target: body
                pattern: "{pattern}"
            "#,
        ))
        .unwrap();
        let filter = GuardrailsFilter::from_config(&yaml);
        assert!(filter.is_ok(), "pattern at exact limit should be accepted");
    }

    #[tokio::test]
    async fn negated_body_pattern_allows_json() {
        let f = make_filter(vec![body_not_pattern(r"^\{.*\}$")]);
        let req = crate::test_utils::make_request(http::Method::POST, "/api");
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let mut body = Some(Bytes::from_static(b"{\"key\":\"value\"}"));
        let action = f.on_request_body(&mut ctx, &mut body, true).await.unwrap();
        assert!(
            matches!(action, FilterAction::Continue),
            "negated pattern should allow body matching expected shape"
        );
    }
}
