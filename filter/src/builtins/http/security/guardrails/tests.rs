// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Tests for the guardrails filter.

use bytes::Bytes;
use regex::Regex;

use super::{
    GuardrailsFilter,
    config::DEFAULT_MAX_BODY_BYTES,
    pii::PiiKind,
    rule::{CompiledRule, RuleMatcher, RuleTarget},
};
use crate::{FilterAction, FilterResultSet, filter::HttpFilter as _};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn body_access_with_body_rules() {
    use crate::body::{BodyAccess, BodyMode};
    let f = make_filter(vec![body_contains("evil")]);
    assert_eq!(
        f.request_body_access(),
        BodyAccess::ReadOnly,
        "body rules need ReadOnly access"
    );
    assert_eq!(
        f.request_body_mode(),
        BodyMode::StreamBuffer {
            max_bytes: Some(DEFAULT_MAX_BODY_BYTES)
        },
        "body rules need StreamBuffer mode"
    );
}

#[test]
fn body_access_without_body_rules() {
    use crate::body::{BodyAccess, BodyMode};
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
        matches!(action, FilterAction::Reject(r) if r.status == 403),
        "matching header should reject with 403"
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
        matches!(action, FilterAction::Reject(r) if r.status == 403),
        "matching header regex should reject with 403"
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
        matches!(action, FilterAction::Reject(r) if r.status == 403),
        "matching body content should reject with 403"
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
        matches!(action, FilterAction::Reject(r) if r.status == 403),
        "matching body regex should reject with 403"
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
        matches!(action, FilterAction::Reject(r) if r.status == 403),
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
            assert_eq!(r.status, 403, "rejection status should be 403");
            assert_eq!(
                r.body.as_deref(),
                Some(b"Forbidden".as_slice()),
                "rejection body should be 'Forbidden'"
            );
        },
        _ => panic!("expected rejection"),
    }
}

#[tokio::test]
async fn negated_header_rejects_when_not_matching() {
    let f = make_filter(vec![header_not_contains("x-auth", "trusted")]);
    let mut req = crate::test_utils::make_request(http::Method::GET, "/");
    req.headers.insert("x-auth", "unknown".parse().unwrap());
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = f.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Reject(r) if r.status == 403),
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
        matches!(action, FilterAction::Reject(r) if r.status == 403),
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
        matches!(action, FilterAction::Reject(r) if r.status == 403),
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
        matches!(action, FilterAction::Reject(r) if r.status == 403),
        "negated pattern should reject body not matching expected shape"
    );
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

#[tokio::test]
async fn header_reject_writes_blocked_result() {
    let f = make_filter(vec![header_contains("x-bad", "yes")]);
    let mut req = crate::test_utils::make_request(http::Method::GET, "/");
    req.headers.insert("x-bad", "yes".parse().unwrap());
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let _action = f.on_request(&mut ctx).await.unwrap();
    assert_result(&ctx.filter_results, "blocked");
}

#[tokio::test]
async fn header_pass_writes_passed_result() {
    let f = make_filter(vec![header_contains("x-bad", "yes")]);
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let _action = f.on_request(&mut ctx).await.unwrap();
    assert_result(&ctx.filter_results, "passed");
}

#[tokio::test]
async fn body_reject_writes_blocked_result() {
    let f = make_filter(vec![body_contains("DROP TABLE")]);
    let req = crate::test_utils::make_request(http::Method::POST, "/api");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let mut body = Some(Bytes::from_static(b"SELECT 1; DROP TABLE users;"));
    let _action = f.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert_result(&ctx.filter_results, "blocked");
}

#[tokio::test]
async fn body_pass_writes_passed_result() {
    let f = make_filter(vec![body_contains("DROP TABLE")]);
    let req = crate::test_utils::make_request(http::Method::POST, "/api");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let mut body = Some(Bytes::from_static(b"SELECT 1 FROM users"));
    let _action = f.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert_result(&ctx.filter_results, "passed");
}

#[tokio::test]
async fn none_body_writes_passed_result() {
    let f = make_filter(vec![body_contains("evil")]);
    let req = crate::test_utils::make_request(http::Method::POST, "/api");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let mut body: Option<Bytes> = None;
    let _action = f.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert_result(&ctx.filter_results, "passed");
}

#[tokio::test]
async fn header_only_filter_writes_passed_without_body_phase() {
    let f = make_filter(vec![header_contains("user-agent", "bad-bot")]);
    let mut req = crate::test_utils::make_request(http::Method::GET, "/");
    req.headers.insert("user-agent", "good-bot/1.0".parse().unwrap());
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let _action = f.on_request(&mut ctx).await.unwrap();
    assert_result(&ctx.filter_results, "passed");
}

#[tokio::test]
async fn flag_action_continues_on_match() {
    let f = make_flag_filter(vec![header_contains("x-bad", "yes")]);
    let mut req = crate::test_utils::make_request(http::Method::GET, "/");
    req.headers.insert("x-bad", "yes".parse().unwrap());
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = f.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "flag action should continue even on match"
    );
    assert_result(&ctx.filter_results, "blocked");
}

#[tokio::test]
async fn flag_action_body_continues_on_match() {
    let f = make_flag_filter(vec![body_contains("DROP TABLE")]);
    let req = crate::test_utils::make_request(http::Method::POST, "/api");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let mut body = Some(Bytes::from_static(b"SELECT 1; DROP TABLE users;"));
    let action = f.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "flag action should continue even on body match"
    );
    assert_result(&ctx.filter_results, "blocked");
}

#[tokio::test]
async fn body_filter_defers_result_to_body_phase() {
    let f = make_filter(vec![body_contains("evil")]);
    let req = crate::test_utils::make_request(http::Method::POST, "/api");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let _action = f.on_request(&mut ctx).await.unwrap();
    assert!(
        !ctx.filter_results.contains_key("guardrails"),
        "body-targeting filter should not write results in on_request"
    );
}

// -----------------------------------------------------------------------------
// PII Rule Tests
// -----------------------------------------------------------------------------

#[tokio::test]
async fn pii_ssn_rejects_body() {
    let f = make_filter(vec![body_pii(&[PiiKind::Ssn])]);
    let req = crate::test_utils::make_request(http::Method::POST, "/api");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let mut body = Some(Bytes::from_static(b"my ssn is 123-45-6789 thanks"));
    let action = f.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(
        matches!(action, FilterAction::Reject(r) if r.status == 403),
        "SSN in body should be rejected"
    );
    assert_result(&ctx.filter_results, "blocked");
}

#[tokio::test]
async fn pii_ssn_allows_clean_body() {
    let f = make_filter(vec![body_pii(&[PiiKind::Ssn])]);
    let req = crate::test_utils::make_request(http::Method::POST, "/api");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let mut body = Some(Bytes::from_static(b"no sensitive data here"));
    let action = f.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(matches!(action, FilterAction::Continue), "clean body should pass");
    assert_result(&ctx.filter_results, "passed");
}

#[tokio::test]
async fn pii_credit_card_rejects_16_digit() {
    let f = make_filter(vec![body_pii(&[PiiKind::CreditCard])]);
    let req = crate::test_utils::make_request(http::Method::POST, "/api");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let mut body = Some(Bytes::from_static(b"card: 4111-1111-1111-1111"));
    let action = f.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(
        matches!(action, FilterAction::Reject(r) if r.status == 403),
        "credit card number should be rejected"
    );
}

#[tokio::test]
async fn pii_credit_card_rejects_amex() {
    let f = make_filter(vec![body_pii(&[PiiKind::CreditCard])]);
    let req = crate::test_utils::make_request(http::Method::POST, "/api");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let mut body = Some(Bytes::from_static(b"amex: 3782-822463-10005"));
    let action = f.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(
        matches!(action, FilterAction::Reject(r) if r.status == 403),
        "Amex card number should be rejected"
    );
}

#[tokio::test]
async fn pii_credit_card_rejects_mastercard() {
    let f = make_filter(vec![body_pii(&[PiiKind::CreditCard])]);
    let req = crate::test_utils::make_request(http::Method::POST, "/api");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let mut body = Some(Bytes::from_static(b"card: 5111-1111-1111-1118"));
    let action = f.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(
        matches!(action, FilterAction::Reject(r) if r.status == 403),
        "Mastercard (traditional range) should be rejected"
    );
}

#[tokio::test]
async fn pii_credit_card_rejects_mastercard_2series_low_boundary() {
    let f = make_filter(vec![body_pii(&[PiiKind::CreditCard])]);
    let req = crate::test_utils::make_request(http::Method::POST, "/api");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    // 2221 is the lowest valid 2-series Mastercard prefix.
    let mut body = Some(Bytes::from_static(b"card: 2221-0000-0000-0000"));
    let action = f.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(
        matches!(action, FilterAction::Reject(r) if r.status == 403),
        "Mastercard 2-series lower boundary (2221) should be rejected"
    );
}

#[tokio::test]
async fn pii_credit_card_rejects_mastercard_2series_high_boundary() {
    let f = make_filter(vec![body_pii(&[PiiKind::CreditCard])]);
    let req = crate::test_utils::make_request(http::Method::POST, "/api");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    // 2720 is the highest valid 2-series Mastercard prefix.
    let mut body = Some(Bytes::from_static(b"card: 2720-0000-0000-0000"));
    let action = f.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(
        matches!(action, FilterAction::Reject(r) if r.status == 403),
        "Mastercard 2-series upper boundary (2720) should be rejected"
    );
}

#[tokio::test]
async fn pii_credit_card_rejects_discover() {
    let f = make_filter(vec![body_pii(&[PiiKind::CreditCard])]);
    let req = crate::test_utils::make_request(http::Method::POST, "/api");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let mut body = Some(Bytes::from_static(b"card: 6011-1111-1111-1117"));
    let action = f.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(
        matches!(action, FilterAction::Reject(r) if r.status == 403),
        "Discover card number should be rejected"
    );
}

#[tokio::test]
async fn pii_phone_rejects_us_format() {
    let f = make_filter(vec![body_pii(&[PiiKind::Phone])]);
    let req = crate::test_utils::make_request(http::Method::POST, "/api");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let mut body = Some(Bytes::from_static(b"call me at (555) 867-5309"));
    let action = f.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(
        matches!(action, FilterAction::Reject(r) if r.status == 403),
        "US phone number should be rejected"
    );
}

#[tokio::test]
async fn pii_phone_rejects_with_country_code() {
    let f = make_filter(vec![body_pii(&[PiiKind::Phone])]);
    let req = crate::test_utils::make_request(http::Method::POST, "/api");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let mut body = Some(Bytes::from_static(b"call +1-555-867-5309"));
    let action = f.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(
        matches!(action, FilterAction::Reject(r) if r.status == 403),
        "phone with country code should be rejected"
    );
}

#[tokio::test]
async fn pii_email_rejects_address() {
    let f = make_filter(vec![body_pii(&[PiiKind::Email])]);
    let req = crate::test_utils::make_request(http::Method::POST, "/api");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let mut body = Some(Bytes::from_static(b"send to user@example.com please"));
    let action = f.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(
        matches!(action, FilterAction::Reject(r) if r.status == 403),
        "email address should be rejected"
    );
}

#[tokio::test]
async fn pii_email_allows_no_email() {
    let f = make_filter(vec![body_pii(&[PiiKind::Email])]);
    let req = crate::test_utils::make_request(http::Method::POST, "/api");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let mut body = Some(Bytes::from_static(b"just some text with an @ but no valid email"));
    let action = f.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(matches!(action, FilterAction::Continue), "non-email @ should pass");
}

#[tokio::test]
async fn pii_combined_rejects_any_match() {
    let f = make_filter(vec![body_pii(PiiKind::ALL)]);
    let req = crate::test_utils::make_request(http::Method::POST, "/api");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let mut body = Some(Bytes::from_static(b"my email is foo@bar.com"));
    let action = f.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(
        matches!(action, FilterAction::Reject(r) if r.status == 403),
        "any PII match in combined filter should reject"
    );
}

#[tokio::test]
async fn pii_combined_allows_clean() {
    let f = make_filter(vec![body_pii(PiiKind::ALL)]);
    let req = crate::test_utils::make_request(http::Method::POST, "/api");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let mut body = Some(Bytes::from_static(b"perfectly clean content"));
    let action = f.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "clean body should pass all PII rules"
    );
}

#[test]
fn pii_from_config_yaml() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r"
rules:
  - target: body
    contains: [ssn, credit_card, email]
",
    )
    .unwrap();
    let filter = GuardrailsFilter::from_config(&yaml).unwrap();
    assert_eq!(filter.name(), "guardrails");
}

#[test]
fn pii_mixed_with_other_rules_from_config() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
rules:
  - target: body
    contains: [ssn, phone]
  - target: body
    contains: "DROP TABLE"
"#,
    )
    .unwrap();
    let filter = GuardrailsFilter::from_config(&yaml).unwrap();
    assert_eq!(filter.name(), "guardrails");
}

#[test]
fn pii_on_header_from_config_yaml() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r"
rules:
  - target: header
    name: Authorization
    contains: [ssn, email]
",
    )
    .unwrap();
    let filter = GuardrailsFilter::from_config(&yaml).unwrap();
    assert_eq!(filter.name(), "guardrails");
}

#[tokio::test]
async fn pii_header_rejects_match() {
    let f = make_filter(vec![header_pii("x-data", &[PiiKind::Ssn])]);
    let mut req = crate::test_utils::make_request(http::Method::GET, "/");
    req.headers.insert("x-data", "ssn=123-45-6789".parse().unwrap());
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = f.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Reject(r) if r.status == 403),
        "SSN in header should be rejected"
    );
}

#[tokio::test]
async fn pii_header_allows_clean() {
    let f = make_filter(vec![header_pii("x-data", &[PiiKind::Ssn])]);
    let mut req = crate::test_utils::make_request(http::Method::GET, "/");
    req.headers.insert("x-data", "nothing sensitive".parse().unwrap());
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = f.on_request(&mut ctx).await.unwrap();
    assert!(matches!(action, FilterAction::Continue), "clean header should continue");
}

#[tokio::test]
async fn pii_flag_action_continues_on_body_match() {
    let f = make_flag_filter(vec![body_pii(PiiKind::ALL)]);
    let req = crate::test_utils::make_request(http::Method::POST, "/api");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let mut body = Some(Bytes::from_static(b"my ssn is 123-45-6789"));
    let action = f.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "flag action should continue even on PII match"
    );
    assert_result(&ctx.filter_results, "blocked");
}

#[tokio::test]
async fn pii_flag_action_continues_on_header_match() {
    let f = make_flag_filter(vec![header_pii("x-data", &[PiiKind::Email])]);
    let mut req = crate::test_utils::make_request(http::Method::GET, "/");
    req.headers.insert("x-data", "user@example.com".parse().unwrap());
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = f.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "flag action should continue even on header PII match"
    );
    assert_result(&ctx.filter_results, "blocked");
}

#[test]
fn pii_empty_list_errors() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r"
rules:
  - target: body
    contains: []
",
    )
    .unwrap();
    assert!(
        GuardrailsFilter::from_config(&yaml).is_err(),
        "empty PII contains list should fail"
    );
}

// -----------------------------------------------------------------------------
// Oversized Body Tests
// -----------------------------------------------------------------------------

#[tokio::test]
async fn reject_oversized_body_returns_413() {
    let f = make_oversized_filter(vec![body_contains("needle")]);
    let req = crate::test_utils::make_request(http::Method::POST, "/api");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let oversized = Bytes::from(vec![b'x'; DEFAULT_MAX_BODY_BYTES]);
    let mut body = Some(oversized);
    let action = f.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(
        matches!(action, FilterAction::Reject(r) if r.status == 413),
        "body at the inspection limit with reject_oversized should return 413"
    );
    assert_result(&ctx.filter_results, "blocked");
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Assert that the guardrails filter wrote the expected status result.
fn assert_result(results: &std::collections::HashMap<&'static str, FilterResultSet>, expected: &str) {
    let rs = results.get("guardrails").expect("guardrails result should be present");
    assert_eq!(
        rs.get("status"),
        Some(expected),
        "guardrails status should be '{expected}'"
    );
}

/// Build a header-contains rule for testing.
fn header_contains(name: &str, needle: &str) -> CompiledRule {
    CompiledRule {
        target: RuleTarget::Header(name.to_owned()),
        matcher: RuleMatcher::Contains(needle.to_lowercase()),
        negate: false,
    }
}

/// Build a negated header-contains rule for testing.
fn header_not_contains(name: &str, needle: &str) -> CompiledRule {
    CompiledRule {
        target: RuleTarget::Header(name.to_owned()),
        matcher: RuleMatcher::Contains(needle.to_lowercase()),
        negate: true,
    }
}

/// Build a header-pattern rule for testing.
fn header_pattern(name: &str, re: &str) -> CompiledRule {
    CompiledRule {
        target: RuleTarget::Header(name.to_owned()),
        matcher: RuleMatcher::Pattern(Regex::new(re).unwrap()),
        negate: false,
    }
}

/// Build a body-contains rule for testing.
fn body_contains(needle: &str) -> CompiledRule {
    CompiledRule {
        target: RuleTarget::Body,
        matcher: RuleMatcher::Contains(needle.to_lowercase()),
        negate: false,
    }
}

/// Build a negated body-contains rule for testing.
fn body_not_contains(needle: &str) -> CompiledRule {
    CompiledRule {
        target: RuleTarget::Body,
        matcher: RuleMatcher::Contains(needle.to_lowercase()),
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

/// Build a guardrails filter from compiled rules with default reject action.
fn make_filter(rules: Vec<CompiledRule>) -> GuardrailsFilter {
    let needs_body = rules.iter().any(|r| matches!(r.target, RuleTarget::Body));
    GuardrailsFilter {
        action: super::config::GuardrailsAction::Reject,
        needs_body,
        reject_oversized: false,
        rules,
    }
}

/// Build a guardrails filter from compiled rules with flag action.
fn make_flag_filter(rules: Vec<CompiledRule>) -> GuardrailsFilter {
    let needs_body = rules.iter().any(|r| matches!(r.target, RuleTarget::Body));
    GuardrailsFilter {
        action: super::config::GuardrailsAction::Flag,
        needs_body,
        reject_oversized: false,
        rules,
    }
}

/// Build a guardrails filter with `reject_oversized` enabled.
fn make_oversized_filter(rules: Vec<CompiledRule>) -> GuardrailsFilter {
    let needs_body = rules.iter().any(|r| matches!(r.target, RuleTarget::Body));
    GuardrailsFilter {
        action: super::config::GuardrailsAction::Reject,
        needs_body,
        reject_oversized: true,
        rules,
    }
}

/// Build a body PII rule for testing.
fn body_pii(kinds: &[PiiKind]) -> CompiledRule {
    CompiledRule {
        target: RuleTarget::Body,
        matcher: RuleMatcher::Pii(kinds.to_vec()),
        negate: false,
    }
}

/// Build a header PII rule for testing.
fn header_pii(name: &str, kinds: &[PiiKind]) -> CompiledRule {
    CompiledRule {
        target: RuleTarget::Header(name.to_owned()),
        matcher: RuleMatcher::Pii(kinds.to_vec()),
        negate: false,
    }
}
