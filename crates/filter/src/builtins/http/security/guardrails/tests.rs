// SPDX-License-Identifier: Apache-2.0
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
        BodyAccess::ReadOnly(crate::BodyRequirement::Required),
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

#[test]
fn flag_action_keeps_body_rules_required_for_downstream_enforcement() {
    let f = make_flag_filter(vec![body_contains("DROP TABLE")]);
    assert_eq!(
        f.request_body_access(),
        crate::body::BodyAccess::ReadOnly(crate::BodyRequirement::Required),
        "flag results may feed a later enforcement branch, so body evaluation cannot be optional"
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
async fn header_contains_rejects_non_utf8_near_miss() {
    let f = make_filter(vec![header_contains("user-agent", "bad-bot")]);
    let mut req = crate::test_utils::make_request(http::Method::GET, "/");
    req.headers
        .insert("user-agent", http::HeaderValue::from_bytes(b"bad-bot\xff").unwrap());
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = f.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Reject(r) if r.status == 403),
        "a non-UTF-8 near-miss must still be blocked (fail closed)"
    );
}

#[tokio::test]
async fn non_ascii_rule_fails_closed_on_undecodable_header() {
    let f = make_filter(vec![header_contains("user-agent", "b\u{e4}d")]);
    let mut req = crate::test_utils::make_request(http::Method::GET, "/");
    req.headers
        .insert("user-agent", http::HeaderValue::from_bytes(b"b\xe4d").unwrap());
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = f.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Reject(r) if r.status == 403),
        "an undecodable value checked by a non-ASCII rule must fail closed"
    );
}

#[tokio::test]
async fn non_ascii_pattern_rule_fails_closed_on_undecodable_header() {
    let f = make_filter(vec![header_pattern("user-agent", "b\u{e4}d")]);
    let mut req = crate::test_utils::make_request(http::Method::GET, "/");
    req.headers
        .insert("user-agent", http::HeaderValue::from_bytes(b"b\xe4d").unwrap());
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = f.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Reject(r) if r.status == 403),
        "an undecodable value checked by a non-ASCII regex rule must fail closed"
    );
}

#[tokio::test]
async fn pii_rule_evaluates_faithfully_on_undecodable_header() {
    let f = make_filter(vec![header_pii("user-agent", &[PiiKind::Email])]);
    let mut req = crate::test_utils::make_request(http::Method::GET, "/");
    req.headers
        .insert("user-agent", http::HeaderValue::from_bytes(b"plain\xff").unwrap());
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = f.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "a PII rule must not fail closed on an unrelated non-UTF-8 value"
    );
}

#[tokio::test]
async fn ascii_rule_allows_unrelated_undecodable_header() {
    let f = make_filter(vec![header_contains("user-agent", "bad-bot")]);
    let mut req = crate::test_utils::make_request(http::Method::GET, "/");
    req.headers
        .insert("user-agent", http::HeaderValue::from_bytes(b"good\xff").unwrap());
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = f.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "an ASCII rule must not false-positive on an unrelated non-UTF-8 value"
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
async fn flag_header_block_not_downgraded_by_body_pass() {
    let f = make_flag_filter(vec![header_contains("x-bad", "yes"), body_contains("DROP TABLE")]);
    let mut req = crate::test_utils::make_request(http::Method::POST, "/api");
    req.headers.insert("x-bad", "yes".parse().unwrap());
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let a1 = f.on_request(&mut ctx).await.unwrap();
    assert!(matches!(a1, FilterAction::Continue), "flag continues");
    assert_result(&ctx.filter_results, "blocked");

    let mut body = Some(Bytes::from_static(b"a harmless payload"));
    let a2 = f.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(matches!(a2, FilterAction::Continue), "flag continues on body");
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
// Duplicate Header and JSON Escape Tests
// -----------------------------------------------------------------------------

#[tokio::test]
async fn negated_header_rule_rejects_any_nonconforming_duplicate()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let f = make_filter(vec![header_not_pattern("content-type", "^application/json$")?]);
    let mut req = crate::test_utils::make_request(http::Method::POST, "/");
    req.headers.append("content-type", "application/json".parse()?);
    req.headers.append("content-type", "text/xml".parse()?);
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = f.on_request(&mut ctx).await?;
    assert!(
        matches!(action, FilterAction::Reject(r) if r.status == 403),
        "one non-conforming duplicate must trigger a negated rule"
    );
    Ok(())
}

#[tokio::test]
async fn negated_header_rule_passes_all_conforming_duplicates() -> Result<(), Box<dyn std::error::Error + Send + Sync>>
{
    let f = make_filter(vec![header_not_pattern("content-type", "^application/json$")?]);
    let mut req = crate::test_utils::make_request(http::Method::POST, "/");
    req.headers.append("content-type", "application/json".parse()?);
    req.headers.append("content-type", "application/json".parse()?);
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = f.on_request(&mut ctx).await?;
    assert!(
        matches!(action, FilterAction::Continue),
        "all conforming duplicates should pass a negated rule"
    );
    Ok(())
}

#[tokio::test]
async fn negated_header_rule_rejects_absent_header() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let f = make_filter(vec![header_not_pattern("content-type", "^application/json$")?]);
    let req = crate::test_utils::make_request(http::Method::POST, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = f.on_request(&mut ctx).await?;
    assert!(
        matches!(action, FilterAction::Reject(r) if r.status == 403),
        "absent header should trigger a negated rule"
    );
    Ok(())
}

#[tokio::test]
async fn json_unicode_escape_does_not_bypass_body_rule() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let f = make_filter(vec![body_contains("drop table")]);
    let req = crate::test_utils::make_request(http::Method::POST, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let mut body = Some(Bytes::from_static(br#"{"q":"drop\u0020table"}"#));
    let action = f.on_request_body(&mut ctx, &mut body, true).await?;
    assert!(
        matches!(action, FilterAction::Reject(r) if r.status == 403),
        "escaped content must be matched after JSON decoding"
    );
    assert_result(&ctx.filter_results, "blocked");
    Ok(())
}

#[tokio::test]
async fn json_escaped_object_key_is_inspected() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let f = make_filter(vec![body_contains("drop table")]);
    let req = crate::test_utils::make_request(http::Method::POST, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let mut body = Some(Bytes::from_static(br#"{"drop\u0020table":1}"#));
    let action = f.on_request_body(&mut ctx, &mut body, true).await?;
    assert!(
        matches!(action, FilterAction::Reject(r) if r.status == 403),
        "escaped object keys must be matched after JSON decoding"
    );
    Ok(())
}

#[tokio::test]
async fn non_json_body_with_backslash_unchanged() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let f = make_filter(vec![body_contains("drop table")]);
    let req = crate::test_utils::make_request(http::Method::POST, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let mut body = Some(Bytes::from_static(br"plain drop\u0020table text"));
    let action = f.on_request_body(&mut ctx, &mut body, true).await?;
    assert!(
        matches!(action, FilterAction::Continue),
        "non-JSON bodies are matched on raw text only"
    );
    Ok(())
}

#[tokio::test]
async fn negated_body_rule_unaffected_by_json_decoding() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let f = make_filter(vec![body_not_contains("required")]);
    let req = crate::test_utils::make_request(http::Method::POST, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let mut body = Some(Bytes::from_static(br#"{"q":"required\u0020value"}"#));
    let action = f.on_request_body(&mut ctx, &mut body, true).await?;
    assert!(
        matches!(action, FilterAction::Continue),
        "negated body rules keep raw-text semantics"
    );
    Ok(())
}

#[tokio::test]
async fn json_too_deep_to_inspect_fails_closed() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let f = make_filter(vec![body_contains("drop table")]);
    let req = crate::test_utils::make_request(http::Method::POST, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let nested = format!("{}\"\\u0041\"{}", "[".repeat(200), "]".repeat(200));
    let mut body = Some(Bytes::from(nested));
    let action = f.on_request_body(&mut ctx, &mut body, true).await?;
    assert!(
        matches!(action, FilterAction::Reject(r) if r.status == 403),
        "JSON nested beyond the parser limit must fail closed"
    );
    Ok(())
}

#[tokio::test]
async fn long_pii_samples_and_equal_length_near_misses_are_selective() {
    let cases = [
        (PiiKind::Email, "user@example.com", "user.example.com"),
        (PiiKind::Ssn, "123-45-6789", "123-45-678x"),
        (PiiKind::Phone, "555-867-5309", "555-867-530x"),
        (PiiKind::CreditCard, "4111-1111-1111-1111", "4111-1111-1111-111x"),
    ];
    for (kind, positive, negative) in cases {
        assert_eq!(positive.len(), negative.len());
        for offset in [0, 15, 16, 31, 32, 63, 64, 524_288, 1_048_000] {
            for (sample, blocked) in [(positive, true), (negative, false)] {
                let filter = make_filter(vec![body_pii(&[kind])]);
                let request = crate::test_utils::make_request(http::Method::POST, "/");
                let mut ctx = crate::test_utils::make_filter_context(&request);
                // Spaces keep the ASCII word boundaries of each detector intact.
                let mut text = vec![b' '; 1_048_576];
                text[offset..offset + sample.len()].copy_from_slice(sample.as_bytes());
                let mut body = Some(Bytes::from(text));
                let original = body.clone();
                let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
                assert_eq!(
                    matches!(action, FilterAction::Reject(r) if r.status == 403),
                    blocked,
                    "{kind:?} at {offset}: {sample}"
                );
                assert_result(&ctx.filter_results, if blocked { "blocked" } else { "passed" });
                assert_eq!(body, original);
            }
        }
    }
}

/// An object key is one leaf, and every array string is one further leaf.
fn wide_json(string_leaves: usize, escaped: bool, sentinel: Option<&str>) -> String {
    let mut values = vec![if escaped { r#""\u0061""# } else { r#""a""# }; string_leaves];
    // The array is traversed in reverse; its first element is visited last.
    if let Some(value) = sentinel {
        values[0] = value;
    }
    format!(r#"{{"key":[{},null,1,true]}}"#, values.join(","))
}

#[tokio::test]
async fn decoded_leaf_budget_counts_keys_and_fails_closed_for_both_actions() {
    for flag in [false, true] {
        for leaves in [9_999, 10_000, 10_001] {
            for escaped in [false, true] {
                let filter = if flag {
                    make_flag_filter(vec![body_pii(&[PiiKind::Ssn])])
                } else {
                    make_filter(vec![body_pii(&[PiiKind::Ssn])])
                };
                let request = crate::test_utils::make_request(http::Method::POST, "/");
                let mut ctx = crate::test_utils::make_filter_context(&request);
                let mut body = Some(Bytes::from(wide_json(leaves - 1, escaped, None)));
                let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
                let blocked = escaped && leaves > 10_000;
                assert_eq!(
                    matches!(action, FilterAction::Reject(r) if r.status == 403),
                    blocked && !flag
                );
                assert_result(&ctx.filter_results, if blocked { "blocked" } else { "passed" });
            }
        }
    }
}

#[tokio::test]
async fn decoded_depth_failure_sets_blocked_in_reject_and_flag_modes() {
    let padding = "x".repeat(900_000);
    for depth in [125, 126, 127, 128, 129] {
        let text = format!(
            r#"{{"padding":"{padding}","deep":{}"\u0061"{}}}"#,
            "[".repeat(depth),
            "]".repeat(depth)
        );
        let parseable = serde_json::from_str::<serde_json::Value>(&text).is_ok();
        for flag in [false, true] {
            let filter = if flag {
                make_flag_filter(vec![body_contains("forbidden")])
            } else {
                make_filter(vec![body_contains("forbidden")])
            };
            let request = crate::test_utils::make_request(http::Method::POST, "/");
            let mut ctx = crate::test_utils::make_filter_context(&request);
            let mut body = Some(Bytes::copy_from_slice(text.as_bytes()));
            let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
            assert_eq!(
                matches!(action, FilterAction::Reject(r) if r.status == 403),
                !parseable && !flag,
                "depth {depth}"
            );
            assert_result(&ctx.filter_results, if parseable { "passed" } else { "blocked" });
        }
    }
}

#[tokio::test]
async fn a_long_clean_body_cannot_downgrade_a_flagged_header() {
    let filter = make_flag_filter(vec![header_contains("x-danger", "blocked"), body_contains("forbidden")]);
    let mut request = crate::test_utils::make_request(http::Method::POST, "/");
    request.headers.insert("x-danger", "blocked".parse().unwrap());
    let mut ctx = crate::test_utils::make_filter_context(&request);
    assert!(matches!(
        filter.on_request(&mut ctx).await.unwrap(),
        FilterAction::Continue
    ));
    assert_result(&ctx.filter_results, "blocked");
    let mut body = Some(Bytes::from(vec![b'x'; 900_000]));
    assert!(matches!(
        filter.on_request_body(&mut ctx, &mut body, true).await.unwrap(),
        FilterAction::Continue
    ));
    assert_result(&ctx.filter_results, "blocked");
}

#[tokio::test]
async fn escaped_pii_in_late_visited_values_and_keys_is_inspected() {
    let filter = make_filter(vec![body_pii(&[PiiKind::Ssn])]);
    let escaped_ssn = r#""123\u002d45\u002d6789""#;
    let cases = [
        wide_json(9_999, true, Some(escaped_ssn)),
        format!(
            r#"{{"padding":"{}","nested":[{{"123\u002d45\u002d6789":1}}]}}"#,
            "x".repeat(900_000)
        ),
    ];
    for text in cases {
        let request = crate::test_utils::make_request(http::Method::POST, "/");
        let mut ctx = crate::test_utils::make_filter_context(&request);
        let mut body = Some(Bytes::from(text));
        let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
        assert!(matches!(action, FilterAction::Reject(r) if r.status == 403));
        assert_result(&ctx.filter_results, "blocked");
    }
    // 10,001 leaves must fail closed even when the escaped PII is visited last.
    let request = crate::test_utils::make_request(http::Method::POST, "/");
    let mut ctx = crate::test_utils::make_filter_context(&request);
    let mut body = Some(Bytes::from(wide_json(10_000, true, Some(escaped_ssn))));
    assert!(
        matches!(filter.on_request_body(&mut ctx, &mut body, true).await.unwrap(), FilterAction::Reject(r) if r.status == 403)
    );
    assert_result(&ctx.filter_results, "blocked");
}

#[tokio::test]
async fn oversized_policy_is_inclusive_and_independent_of_flag_action() {
    for flag in [false, true] {
        for reject_oversized in [false, true] {
            for size in [
                DEFAULT_MAX_BODY_BYTES - 1,
                DEFAULT_MAX_BODY_BYTES,
                DEFAULT_MAX_BODY_BYTES + 1,
            ] {
                for contains_pii in [false, true] {
                    assert_oversized_policy_case(flag, reject_oversized, (size, contains_pii)).await;
                }
            }
        }
    }
}

/// Verify both the action and recorded result at one size and policy setting.
async fn assert_oversized_policy_case(flag: bool, reject_oversized: bool, (size, contains_pii): (usize, bool)) {
    let mut filter = body_action_filter(flag, body_pii(&[PiiKind::Ssn]));
    filter.reject_oversized = reject_oversized;
    let request = crate::test_utils::make_request(http::Method::POST, "/");
    let mut ctx = crate::test_utils::make_filter_context(&request);
    let mut bytes = vec![b' '; size];
    if contains_pii {
        bytes[size - 11..].copy_from_slice(b"123-45-6789");
    }
    let mut body = Some(Bytes::from(bytes));
    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    let over = reject_oversized && size >= DEFAULT_MAX_BODY_BYTES;
    let expected = match (over, contains_pii, flag) {
        (true, ..) => Some(413),
        (false, true, false) => Some(403),
        _ => None,
    };
    let status = match action {
        FilterAction::Reject(rejection) => Some(rejection.status),
        _ => None,
    };
    assert_eq!(
        status, expected,
        "flag={flag} reject_oversized={reject_oversized} size={size} pii={contains_pii}"
    );
    assert_result(
        &ctx.filter_results,
        if over || contains_pii { "blocked" } else { "passed" },
    );
}

#[tokio::test]
async fn long_raw_decoded_negated_and_invalid_inputs_preserve_actions() {
    for flag in [false, true] {
        for (rule, suffix, blocked) in [
            (body_contains("forbidden"), "forbidden", true),
            (body_contains("forbidden"), "forbiddeX", false),
            (body_pattern("forbidden$"), "forbidden", true),
            (body_pattern("forbidden$"), "forbiddeX", false),
            (body_not_contains("required"), "required", false),
            (body_not_contains("required"), "requireX", true),
        ] {
            let body = Bytes::from(format!("{}{suffix}", " ".repeat(900_000)));
            assert_long_body_action(flag, rule, body, blocked).await;
        }
        assert_long_body_action(flag, body_contains("forbidden"), Bytes::from(vec![0xFF; 900_000]), true).await;
    }
}

/// Check the action and recorded result for long matching or undecodable input.
async fn assert_long_body_action(flag: bool, rule: CompiledRule, body: Bytes, blocked: bool) {
    let filter = body_action_filter(flag, rule);
    let request = crate::test_utils::make_request(http::Method::POST, "/");
    let mut ctx = crate::test_utils::make_filter_context(&request);
    let action = filter.on_request_body(&mut ctx, &mut Some(body), true).await.unwrap();
    assert_eq!(
        matches!(action, FilterAction::Reject(r) if r.status == 403),
        blocked && !flag
    );
    assert_result(&ctx.filter_results, if blocked { "blocked" } else { "passed" });
}

/// Use the requested flag or rejection action with one body rule.
fn body_action_filter(flag: bool, rule: CompiledRule) -> GuardrailsFilter {
    if flag {
        make_flag_filter(vec![rule])
    } else {
        make_filter(vec![rule])
    }
}

#[tokio::test]
async fn long_near_matches_and_escape_runs_do_not_hide_tail_matches() {
    for (rule, prefix, positive, negative) in [
        (
            body_contains("forbidden"),
            "\\".repeat(900_000),
            " forbidden",
            " forbiddeX",
        ),
        (
            body_pattern("forbidden$"),
            ".".repeat(900_000),
            " forbidden",
            " forbiddeX",
        ),
        (
            body_pii(&[PiiKind::Ssn]),
            "9".repeat(900_000),
            " 123-45-6789",
            " 123-45-678x",
        ),
    ] {
        let filter = make_filter(vec![rule]);
        for (tail, blocked) in [(positive, true), (negative, false)] {
            let request = crate::test_utils::make_request(http::Method::POST, "/");
            let mut ctx = crate::test_utils::make_filter_context(&request);
            let mut body = Some(Bytes::from(format!("{prefix}{tail}")));
            let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
            assert_eq!(matches!(action, FilterAction::Reject(r) if r.status == 403), blocked);
            assert_result(&ctx.filter_results, if blocked { "blocked" } else { "passed" });
        }
    }
}

#[tokio::test]
async fn late_decoded_literal_and_regex_matches_honor_actions() {
    for flag in [false, true] {
        for is_pattern in [false, true] {
            for (tail, blocked) in [(r"for\u0062idden", true), (r"for\u0062iddeX", false)] {
                let rule = if is_pattern {
                    body_pattern("forbidden")
                } else {
                    body_contains("forbidden")
                };
                let filter = if flag {
                    make_flag_filter(vec![rule])
                } else {
                    make_filter(vec![rule])
                };
                let request = crate::test_utils::make_request(http::Method::POST, "/");
                let mut ctx = crate::test_utils::make_filter_context(&request);
                let mut body = Some(Bytes::from(format!(
                    r#"{{"padding":"{}","value":"{tail}"}}"#,
                    "x".repeat(900_000)
                )));
                let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
                assert_eq!(
                    matches!(action, FilterAction::Reject(r) if r.status == 403),
                    blocked && !flag
                );
                assert_result(&ctx.filter_results, if blocked { "blocked" } else { "passed" });
            }
        }
    }
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

/// Build a negated header-pattern rule for testing.
fn header_not_pattern(name: &str, re: &str) -> Result<CompiledRule, regex::Error> {
    Ok(CompiledRule {
        target: RuleTarget::Header(name.to_owned()),
        matcher: RuleMatcher::Pattern(Regex::new(re)?),
        negate: true,
    })
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
    let has_body_contains = rules
        .iter()
        .any(|r| matches!(r.target, RuleTarget::Body) && matches!(r.matcher, RuleMatcher::Contains(_)));
    GuardrailsFilter {
        action: super::config::GuardrailsAction::Reject,
        needs_body,
        has_body_contains,
        has_non_negated_body_rules: rules.iter().any(|r| matches!(r.target, RuleTarget::Body) && !r.negate),
        reject_oversized: false,
        rules,
    }
}

/// Build a guardrails filter from compiled rules with flag action.
fn make_flag_filter(rules: Vec<CompiledRule>) -> GuardrailsFilter {
    let needs_body = rules.iter().any(|r| matches!(r.target, RuleTarget::Body));
    let has_body_contains = rules
        .iter()
        .any(|r| matches!(r.target, RuleTarget::Body) && matches!(r.matcher, RuleMatcher::Contains(_)));
    GuardrailsFilter {
        action: super::config::GuardrailsAction::Flag,
        needs_body,
        has_body_contains,
        has_non_negated_body_rules: rules.iter().any(|r| matches!(r.target, RuleTarget::Body) && !r.negate),
        reject_oversized: false,
        rules,
    }
}

/// Build a guardrails filter with `reject_oversized` enabled.
fn make_oversized_filter(rules: Vec<CompiledRule>) -> GuardrailsFilter {
    let needs_body = rules.iter().any(|r| matches!(r.target, RuleTarget::Body));
    let has_body_contains = rules
        .iter()
        .any(|r| matches!(r.target, RuleTarget::Body) && matches!(r.matcher, RuleMatcher::Contains(_)));
    GuardrailsFilter {
        action: super::config::GuardrailsAction::Reject,
        needs_body,
        has_body_contains,
        has_non_negated_body_rules: rules.iter().any(|r| matches!(r.target, RuleTarget::Body) && !r.negate),
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
