// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! [`GuardrailsFilter`] implementation and `HttpFilter` trait impl.

use async_trait::async_trait;
use bytes::Bytes;

use super::{
    config::{DEFAULT_MAX_BODY_BYTES, GuardrailsAction, GuardrailsConfig},
    rule::{CompiledRule, RuleMatcher, RuleTarget, parse_matcher, parse_target},
};
use crate::{
    FilterAction, FilterError, FilterResultSet, Rejection,
    body::{BodyAccess, BodyMode},
    factory::parse_filter_config,
    filter::{HttpFilter, HttpFilterContext},
};

// -----------------------------------------------------------------------------
// GuardrailsFilter
// -----------------------------------------------------------------------------

/// Rejects requests matching string, regex, or PII rules against headers
/// and/or body content.
///
/// # YAML configuration
///
/// ```yaml
/// filter: guardrails
/// action: flag            # or "reject" (default)
/// rules:
///   # Detect PII in a header
///   - target: header
///     name: "Authorization"
///     contains: [ssn, credit_card, email]
///   # Detect PII in body
///   - target: body
///     contains: [ssn, credit_card, phone, email]
///   # Block SQL injection in body
///   - target: body
///     contains: "DROP TABLE"
///   # Block requests from bad bots
///   - target: header
///     name: "User-Agent"
///     pattern: "bad-bot.*"
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
/// let yaml: serde_yaml::Value = serde_yaml::from_str(
///     r#"
/// rules:
///   - target: header
///     name: User-Agent
///     contains: bad-bot
/// "#,
/// )
/// .unwrap();
/// let filter = GuardrailsFilter::from_config(&yaml).unwrap();
/// assert_eq!(filter.name(), "guardrails");
/// ```
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent pre-computed rule facts, not a state machine"
)]
pub struct GuardrailsFilter {
    /// What to do when a rule matches.
    pub(super) action: GuardrailsAction,

    /// Whether any rule targets the body (pre-computed at init).
    pub(super) needs_body: bool,

    /// Whether any body rule is a `Contains` match (pre-computed at
    /// init), so the per-body lowercase decision costs no rule scan.
    pub(super) has_body_contains: bool,

    /// Reject bodies exceeding the inspection buffer limit.
    pub(super) reject_oversized: bool,

    /// Compiled rules for per-request evaluation.
    pub(super) rules: Vec<CompiledRule>,
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
    /// let yaml: serde_yaml::Value = serde_yaml::from_str(
    ///     r#"
    /// rules:
    ///   - target: body
    ///     pattern: "SELECT.*FROM"
    /// "#,
    /// )
    /// .unwrap();
    /// let filter = GuardrailsFilter::from_config(&yaml).unwrap();
    /// assert_eq!(filter.name(), "guardrails");
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if rules are empty or contain invalid regex.
    ///
    /// [`FilterError`]: crate::FilterError
    pub fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        let cfg: GuardrailsConfig = parse_filter_config("guardrails", config)?;

        if cfg.rules.is_empty() {
            return Err("guardrails: 'rules' must not be empty".into());
        }

        let mut rules = Vec::with_capacity(cfg.rules.len());
        let mut needs_body = false;
        let mut has_body_contains = false;

        for rule in &cfg.rules {
            let target = parse_target(rule)?;
            let matcher = parse_matcher(rule)?;

            if matches!(target, RuleTarget::Body) {
                needs_body = true;
                if matches!(matcher, RuleMatcher::Contains(_)) {
                    has_body_contains = true;
                }
            }

            rules.push(CompiledRule {
                target,
                matcher,
                negate: rule.negate,
            });
        }

        Ok(Box::new(Self {
            action: cfg.action,
            needs_body,
            has_body_contains,
            reject_oversized: cfg.reject_oversized,
            rules,
        }))
    }

    /// Return the appropriate [`FilterAction`] when a rule matches.
    fn blocked_action(&self) -> FilterAction {
        match self.action {
            GuardrailsAction::Reject => forbidden(),
            GuardrailsAction::Flag => FilterAction::Continue,
        }
    }

    /// Check all header-targeted rules against the request headers.
    fn check_headers(&self, ctx: &HttpFilterContext<'_>) -> bool {
        self.rules.iter().any(|rule| match &rule.target {
            RuleTarget::Header(header_name) => header_rule_triggered(rule, header_name, ctx),
            RuleTarget::Body => false,
        })
    }

    /// Check all body-targeted rules against the request body.
    ///
    /// Lowercases the body once for all `Contains` rules to avoid
    /// re-allocating per rule. Only allocates when at least one
    /// body-targeted `Contains` rule exists.
    fn check_body(&self, body: &str) -> bool {
        let body_lower = self.has_body_contains.then(|| body.to_lowercase());
        for rule in &self.rules {
            if !matches!(rule.target, RuleTarget::Body) {
                continue;
            }

            let is_rule_match = rule.eval(body, body_lower.as_deref());
            let rule_matches = if rule.negate {
                !is_rule_match.matched
            } else {
                is_rule_match.matched
            };

            if rule_matches {
                tracing::info!(
                    negate = rule.negate,
                    pii_kind = ?is_rule_match.pii_kind,
                    "guardrails: body rule triggered"
                );
                return true;
            }
        }
        false
    }
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
            BodyMode::StreamBuffer {
                max_bytes: Some(DEFAULT_MAX_BODY_BYTES),
            }
        } else {
            BodyMode::Stream
        }
    }

    async fn on_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        if self.check_headers(ctx) {
            write_result(ctx, "blocked");
            return Ok(self.blocked_action());
        }

        if !self.needs_body {
            write_result(ctx, "passed");
        }

        Ok(FilterAction::Continue)
    }

    async fn on_request_body(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        if !end_of_stream {
            return Ok(FilterAction::Continue);
        }

        let Some(chunk) = body.as_ref() else {
            write_result(ctx, "passed");
            return Ok(FilterAction::Continue);
        };

        if self.reject_oversized && self.needs_body && chunk.len() >= DEFAULT_MAX_BODY_BYTES {
            tracing::info!(
                body_len = chunk.len(),
                limit = DEFAULT_MAX_BODY_BYTES,
                "guardrails: rejecting oversized body (exceeds inspection limit)"
            );
            write_result(ctx, "blocked");
            return Ok(FilterAction::Reject(Rejection::status(413)));
        }

        let Ok(text) = std::str::from_utf8(chunk) else {
            tracing::info!("guardrails: rejecting non-UTF-8 body");
            write_result(ctx, "blocked");
            return Ok(self.blocked_action());
        };
        if self.check_body(text) {
            write_result(ctx, "blocked");
            return Ok(self.blocked_action());
        }

        write_result(ctx, "passed");
        Ok(FilterAction::Continue)
    }
}

// -----------------------------------------------------------------------------
// Utility Functions
// -----------------------------------------------------------------------------

/// Evaluate one header-targeted rule; returns whether it triggered.
///
/// Values are decoded lossily rather than dropped: a value that is not valid
/// UTF-8 (obs-text) must still be inspected, or a blocking rule would fail
/// open (e.g. `User-Agent: bad-bot\xFF` evading a `bad-bot` reject rule while
/// the upstream reads it as `bad-bot`). A non-ASCII pattern additionally
/// cannot be faithfully evaluated over an undecodable value — the replacement
/// character destroys exactly the bytes the pattern targets (a Latin-1
/// encoding of the pattern sails past the lossy match while a lenient
/// upstream reads the original) — so that combination fails closed like the
/// body path.
fn header_rule_triggered(rule: &CompiledRule, header_name: &str, ctx: &HttpFilterContext<'_>) -> bool {
    let (is_rule_match, undecodable) = scan_header_values(rule, header_name, ctx);

    if is_rule_match.is_none() && undecodable && !rule.is_ascii_only() {
        tracing::info!(
            header = %header_name,
            "guardrails: non-UTF-8 header value cannot be checked against a \
             non-ASCII pattern; failing closed"
        );
        return true;
    }

    let rule_matches = if rule.negate {
        is_rule_match.is_none()
    } else {
        is_rule_match.is_some()
    };

    if rule_matches {
        tracing::info!(
            header = %header_name,
            negate = rule.negate,
            pii_kind = ?is_rule_match.and_then(|ev| ev.pii_kind),
            "guardrails: header rule triggered"
        );
        return true;
    }
    false
}

/// Scan a rule's header values, returning the first match and whether any
/// value failed UTF-8 decoding (lossily replaced).
fn scan_header_values(
    rule: &CompiledRule,
    header_name: &str,
    ctx: &HttpFilterContext<'_>,
) -> (Option<super::rule::RuleEval>, bool) {
    let mut undecodable = false;
    let is_rule_match = ctx
        .request
        .headers
        .get_all(header_name)
        .iter()
        .map(|val| {
            let s = String::from_utf8_lossy(val.as_bytes());
            if matches!(s, std::borrow::Cow::Owned(_)) {
                undecodable = true;
            }
            s
        })
        .find_map(|s| {
            let ev = rule.eval(&s, None);
            ev.matched.then_some(ev)
        });
    (is_rule_match, undecodable)
}

/// Write a guardrails status result to the filter context.
///
/// `blocked` is sticky: a later `passed` (e.g. from the body phase when
/// no body rule matched) must not downgrade a `blocked` written by the
/// header phase, or a request the header rule flagged would be recorded
/// as passed and any branch chain keyed on the result would admit it.
fn write_result(ctx: &mut HttpFilterContext<'_>, status: &'static str) {
    let already_blocked = ctx.filter_results.get("guardrails").and_then(|rs| rs.get("status")) == Some("blocked");
    if status == "passed" && already_blocked {
        tracing::debug!("guardrails already blocked; not downgrading to passed");
        return;
    }
    let mut rs = FilterResultSet::new();
    if let Err(e) = rs.set("status", status) {
        tracing::warn!(error = %e, "failed to write guardrails result");
        return;
    }
    ctx.filter_results.insert("guardrails", rs);
    tracing::debug!(status, "guardrails result written");
}

/// Rejection response for guardrails violations.
fn forbidden() -> FilterAction {
    FilterAction::Reject(Rejection::status(403).with_body(b"Forbidden".as_slice()))
}
