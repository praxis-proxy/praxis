// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Head-phase admission: which policies admit before the body is read, what
//! the head judges the request by, and how later phases reuse its work.

use bytes::Bytes;
use http::{HeaderName, HeaderValue};

use super::{
    config::{ContextField, PolicyFilterConfig},
    construction::head_identity_blocker,
    filter::PolicyFilter,
    rate_limit_tests::{
        Calls, HOST_LIMITERS, TOOL_SUBJECT_LIMIT, context, filter, filter_config, plugins, recorded_policy, rejection,
        request,
    },
    request_state::{RequestState, state, state_mut},
};
use crate::{
    BodyMode, FilterAction, FilterEntry, FilterPipeline, FilterRegistry,
    context::TrustedHeaderMutation,
    filter::{HttpFilter as _, HttpFilterContext},
    test_utils::make_filter_context,
};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Global rule admitting only `alice` at `http.request`.
const ALICE_ONLY: &str = "  authorization:
    pre_invocation:
      - \"require(subject.id == 'alice')\"
";

/// A tool route that replaces the global resolver with its own, beside a
/// recorded pre-identity limiter.
const ROUTE_REPLACES_GLOBAL: &str = "plugins:
  - name: who
    kind: {kind}
    hooks: [identity.resolve]
    capabilities: [read_headers]
  - name: key
    kind: {kind}
    hooks: [identity.resolve]
    capabilities: [read_headers]
  - name: pre
    kind: {kind}
    hooks: [ratelimit.pre_identity]
    capabilities: [read_headers]
global:
  authentication: [who]
  rate_limits: [pre]
routes:
  - tool: echo
    authentication:
      replace_inherited: true
      steps: [key]
    authorization:
      pre_invocation:
        - \"require(authenticated)\"
";

/// One `tools/call` body for `echo`.
const TOOL_CALL: &[u8] =
    br#"{"jsonrpc":"2.0","id":"call-7","method":"tools/call","params":{"name":"echo","arguments":{}}}"#;

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn an_identity_only_policy_admits_at_the_head() {
    let (_dir, path, calls) = recorded_policy("test/head-identity", &HOST_LIMITERS.replace("{deny}", "{}"));
    let filter = filter(path);
    assert!(filter.runs_request_head());
    let req = request(Some("alice"));
    let mut ctx = context(&req, 1);
    assert!(matches!(head(&filter, &mut ctx).await, FilterAction::Continue));
    assert_eq!(plugins(&calls), ["pre", "who", "post"]);
    assert!(state(&ctx).is_some_and(RequestState::is_admitted));

    assert!(matches!(
        filter.on_request(&mut ctx).await.unwrap(),
        FilterAction::Continue
    ));
    let mut body = Some(Bytes::from_static(b"{}"));
    assert!(matches!(
        filter.on_request_body(&mut ctx, &mut body, true).await.unwrap(),
        FilterAction::BodyDone
    ));
    assert_eq!(
        plugins(&calls),
        ["pre", "who", "post"],
        "later phases reuse the head's work"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_head_limiter_denial_rejects_before_identity_runs() {
    let deny = "{deny: ratelimit.exceeded}";
    let (_dir, path, calls) = recorded_policy("test/head-limit-deny", &HOST_LIMITERS.replace("{deny}", deny));
    let filter = filter(path);
    let req = request(Some("alice"));
    let mut ctx = context(&req, 1);
    assert_eq!(rejection(head(&filter, &mut ctx).await).status, 429);
    assert_eq!(plugins(&calls), ["pre"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_http_policy_authorizes_with_the_head_identity() {
    let yaml = format!("{}{ALICE_ONLY}", HOST_LIMITERS.replace("{deny}", "{}"));
    let (_dir, path, calls) = recorded_policy("test/head-http", &yaml);
    let filter = filter(path);
    for (user, denied) in [("bob", true), ("alice", false)] {
        calls.lock().unwrap().clear();
        let req = request(Some(user));
        let mut ctx = context(&req, 1);
        assert!(
            matches!(head(&filter, &mut ctx).await, FilterAction::Continue),
            "{user}"
        );
        assert!(
            !state(&ctx).is_some_and(RequestState::is_admitted),
            "{user}: authorization is due"
        );
        let action = filter.on_request(&mut ctx).await.unwrap();
        assert_eq!(matches!(action, FilterAction::Reject(_)), denied, "{user}: {action:?}");
        assert_eq!(plugins(&calls), ["pre", "who", "post"], "{user}: one resolution");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_pre_read_http_policy_authorizes_on_the_first_chunk() {
    let yaml = format!("{}{ALICE_ONLY}", HOST_LIMITERS.replace("{deny}", "{}"));
    let (_dir, path, calls) = recorded_policy("test/head-http-pre-read", &yaml);
    let filter = filter(path);
    let req = request(Some("bob"));
    let mut ctx = context(&req, 1);
    assert!(matches!(head(&filter, &mut ctx).await, FilterAction::Continue));
    let mut body = Some(Bytes::from_static(b"{}"));
    let action = filter.on_request_body(&mut ctx, &mut body, false).await.unwrap();
    assert_eq!(rejection(action).status, 403, "denied before a later body filter acts");

    let req = request(Some("alice"));
    let mut ctx = context(&req, 1);
    calls.lock().unwrap().clear();
    assert!(matches!(head(&filter, &mut ctx).await, FilterAction::Continue));
    let action = filter.on_request_body(&mut ctx, &mut body, false).await.unwrap();
    assert!(matches!(action, FilterAction::BodyDone), "got {action:?}");
    assert!(matches!(
        filter.on_request(&mut ctx).await.unwrap(),
        FilterAction::Continue
    ));
    assert_eq!(plugins(&calls), ["pre", "who", "post"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_entity_policy_holds_the_head_identity_for_the_route() {
    let (_dir, path, calls) = recorded_policy("test/head-entity", TOOL_SUBJECT_LIMIT);
    let filter = filter(path);
    assert!(filter.runs_request_head());
    let req = request(Some("alice"));
    let mut ctx = context(&req, 1);
    assert!(matches!(head(&filter, &mut ctx).await, FilterAction::Continue));
    assert_eq!(plugins(&calls), ["who"], "the baseline resolution");
    assert!(matches!(
        filter.on_request(&mut ctx).await.unwrap(),
        FilterAction::Continue
    ));
    assert_eq!(plugins(&calls), ["who"], "the request phase does not resolve again");
    assert!(matches!(tool_body(&filter, &mut ctx).await, FilterAction::BodyDone));
    assert_eq!(plugins(&calls), ["who", "who"], "the route resolution");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_context_table_lost_after_the_head_fails_the_body_closed() {
    let (_dir, path, _calls) = recorded_policy("test/head-lost-table", TOOL_SUBJECT_LIMIT);
    let filter = filter(path);
    let req = request(Some("alice"));
    let mut ctx = context(&req, 1);
    assert!(matches!(head(&filter, &mut ctx).await, FilterAction::Continue));
    assert!(matches!(state_mut(&mut ctx).take_table(), Ok(Some(_))));
    let mut body = Some(Bytes::from_static(TOOL_CALL));
    ctx.filter_metadata
        .insert("mcp.method", "tools/call")
        .expect("entry must fit in the filter's metadata");
    ctx.filter_metadata
        .insert("mcp.name", "echo")
        .expect("entry must fit in the filter's metadata");
    assert!(
        filter.on_request_body(&mut ctx, &mut body, true).await.is_err(),
        "no hook runs on a fresh table after the head's was lost"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_additive_route_keeps_authentication_at_the_head() {
    let yaml = ROUTE_REPLACES_GLOBAL.replace("      replace_inherited: true\n", "");
    let (_dir, path, calls) = recorded_policy("test/head-route-adds", &yaml);
    let filter = filter(path);
    assert!(matches!(filter.request_body_mode(), BodyMode::Stream));
    let req = request(Some("alice"));
    let mut ctx = context(&req, 1);
    assert!(matches!(head(&filter, &mut ctx).await, FilterAction::Continue));
    assert_eq!(
        plugins(&calls),
        ["pre", "who"],
        "the global resolver judges at the head: the route only appends to it"
    );
    assert!(matches!(tool_body(&filter, &mut ctx).await, FilterAction::BodyDone));
    assert_eq!(plugins(&calls), ["pre", "who", "who", "key"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_policy_without_authentication_neither_defers_nor_buffers() {
    let yaml = "routes:
  - tool: echo
    authorization:
      pre_invocation:
        - \"allow\"
";
    let (_dir, path, _calls) = recorded_policy("test/head-no-auth", yaml);
    let filter = filter(path);
    assert!(filter.runs_request_head());
    assert!(matches!(filter.request_body_mode(), BodyMode::Stream));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_route_that_replaces_global_authentication_defers_identity() {
    let (_dir, path, calls) = recorded_policy("test/head-route-replaces", ROUTE_REPLACES_GLOBAL);
    let filter = filter(path);
    assert!(filter.runs_request_head(), "the limiter still runs at the head");
    let req = request(Some("alice"));
    let mut ctx = context(&req, 1);
    assert!(matches!(head(&filter, &mut ctx).await, FilterAction::Continue));
    assert_eq!(plugins(&calls), ["pre"], "no global resolution at the head");
    assert!(matches!(tool_body(&filter, &mut ctx).await, FilterAction::BodyDone));
    assert_eq!(plugins(&calls), ["pre", "key"], "only the route resolver judged it");
    assert!(matches!(
        filter.on_request(&mut ctx).await.unwrap(),
        FilterAction::Continue
    ));
    assert_eq!(plugins(&calls), ["pre", "key"], "the request phase runs no gate");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_deferred_identity_buffers_the_body_until_the_route_decides() {
    let (_dir, path, _calls) = recorded_policy("test/head-deferred-buffer", ROUTE_REPLACES_GLOBAL);
    assert!(matches!(
        filter(path).request_body_mode(),
        BodyMode::StreamBuffer { max_bytes: Some(_) }
    ));
    let (_dir, path, _calls) = recorded_policy("test/head-gated-stream", TOOL_SUBJECT_LIMIT);
    assert!(
        matches!(filter(path).request_body_mode(), BodyMode::Stream),
        "a policy gated at the head keeps streaming"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn later_header_mutations_do_not_change_what_the_head_judged() {
    let yaml = format!("{}{ALICE_ONLY}", HOST_LIMITERS.replace("{deny}", "{}"));
    let (_dir, path, calls) = recorded_policy("test/head-later-mutation", &yaml);
    let filter = filter(path);
    let req = request(Some("bob"));
    let mut ctx = context(&req, 1);
    assert!(matches!(head(&filter, &mut ctx).await, FilterAction::Continue));
    ctx.request_headers_to_set
        .push((HeaderName::from_static("x-user"), HeaderValue::from_static("alice")));
    let action = filter.on_request(&mut ctx).await.unwrap();
    assert_eq!(
        rejection(action).status,
        403,
        "identity judges the request as it arrived, plus trusted head mutations"
    );
    assert_eq!(subject_of(&calls, "who"), "bob");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_replaced_global_resolver_without_a_limiter_still_defers_identity() {
    let yaml = ROUTE_REPLACES_GLOBAL.replace("  rate_limits: [pre]\n", "").replace(
        "  - name: pre\n    kind: {kind}\n    hooks: [ratelimit.pre_identity]\n    capabilities: [read_headers]\n",
        "",
    );
    let (_dir, path, calls) = recorded_policy("test/head-route-no-limit", &yaml);
    let filter = filter(path);
    assert!(filter.runs_request_head());
    assert!(matches!(filter.request_body_mode(), BodyMode::StreamBuffer { .. }));
    let req = request(Some("alice"));
    let mut ctx = context(&req, 1);
    assert!(matches!(head(&filter, &mut ctx).await, FilterAction::Continue));
    assert!(plugins(&calls).is_empty(), "the global gate never ran");
    assert!(matches!(tool_body(&filter, &mut ctx).await, FilterAction::BodyDone));
    assert_eq!(plugins(&calls), ["key"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_deferred_policy_limiter_still_rejects_at_the_head() {
    let yaml = ROUTE_REPLACES_GLOBAL.replace(
        "    capabilities: [read_headers]\nglobal:",
        "    capabilities: [read_headers]\n    config: {deny: ratelimit.exceeded}\nglobal:",
    );
    let (_dir, path, calls) = recorded_policy("test/head-deferred-deny", &yaml);
    let filter = filter(path);
    let req = request(Some("alice"));
    let mut ctx = context(&req, 1);
    assert_eq!(rejection(head(&filter, &mut ctx).await).status, 429);
    assert_eq!(plugins(&calls), ["pre"]);
    assert!(
        !state(&ctx).is_some_and(RequestState::gate_done),
        "a denied head defers nothing"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_route_judged_policy_skips_the_global_gate_when_the_head_did_not_run() {
    let (_dir, path, calls) = recorded_policy("test/head-route-skipped", ROUTE_REPLACES_GLOBAL);
    let filter = filter(path);
    let req = request(Some("alice"));
    let mut ctx = context(&req, 1);
    assert!(matches!(tool_body(&filter, &mut ctx).await, FilterAction::BodyDone));
    assert_eq!(
        plugins(&calls),
        ["pre", "key"],
        "the route resolves identity and charges the limiter once"
    );
    assert!(matches!(
        filter.on_request(&mut ctx).await.unwrap(),
        FilterAction::Continue
    ));
    assert_eq!(plugins(&calls), ["pre", "key"], "no global gate in the request phase");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_deferred_identity_the_route_never_judged_fails_closed() {
    let (_dir, path, calls) = recorded_policy("test/head-route-undecided", ROUTE_REPLACES_GLOBAL);
    let filter = filter(path);
    let req = request(None);
    let mut ctx = context(&req, 1);
    assert!(matches!(head(&filter, &mut ctx).await, FilterAction::Continue));
    let denied = rejection(filter.on_request(&mut ctx).await.unwrap());
    assert_eq!(denied.status, 500);
    assert!(
        denied
            .headers
            .iter()
            .any(|(name, value)| name == "X-Policy-Violation" && value == "config.identity_not_judged"),
        "{:?}",
        denied.headers
    );
    assert_eq!(plugins(&calls), ["pre"], "no resolver admitted the request");
}

#[tokio::test(flavor = "multi_thread")]
async fn context_headers_keep_admission_out_of_the_head() {
    let (_dir, path, _calls) = recorded_policy("test/head-context", &HOST_LIMITERS.replace("{deny}", "{}"));
    let cfg = PolicyFilterConfig {
        context_headers: [(ContextField::AgentConversationId, "x-praxis-conversation".to_owned())].into(),
        ..filter_config(path)
    };
    assert!(!PolicyFilter::new(cfg, None).unwrap().runs_request_head());
}

#[tokio::test(flavor = "multi_thread")]
async fn context_headers_still_leave_a_replacing_route_to_judge_alone() {
    let (_dir, path, calls) = recorded_policy("test/head-context-route", ROUTE_REPLACES_GLOBAL);
    let cfg = PolicyFilterConfig {
        context_headers: [(ContextField::AgentConversationId, "x-praxis-conversation".to_owned())].into(),
        ..filter_config(path)
    };
    let filter = PolicyFilter::new(cfg, None).unwrap();
    assert!(!filter.runs_request_head());
    assert!(matches!(filter.request_body_mode(), BodyMode::StreamBuffer { .. }));
    let req = request(Some("alice"));
    let mut ctx = context(&req, 1);
    assert!(matches!(tool_body(&filter, &mut ctx).await, FilterAction::BodyDone));
    assert!(matches!(
        filter.on_request(&mut ctx).await.unwrap(),
        FilterAction::Continue
    ));
    assert_eq!(plugins(&calls), ["pre", "key"], "only the route resolver judged it");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_head_judges_headers_as_earlier_head_filters_left_them() {
    let (_dir, path, calls) = recorded_policy("test/head-mutations", &HOST_LIMITERS.replace("{deny}", "{}"));
    let filter = filter(path);
    let x_user = HeaderName::from_static("x-user");
    for (case, mutate, expected) in head_mutations() {
        calls.lock().unwrap().clear();
        let req = request(Some("mallory"));
        let mut ctx = context(&req, 1);
        mutate(&mut ctx, &x_user);
        let _admitted = head(&filter, &mut ctx).await;
        assert_eq!(subject_of(&calls, "who"), expected, "{case}");
        assert_eq!(
            subject_of(&calls, "post"),
            expected,
            "{case}: the post-identity limiter sees the head's subject"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_pipeline_runs_each_stage_once_across_the_head_and_request_phases() {
    let (_dir, path, calls) = recorded_policy("test/head-pipeline-a", &HOST_LIMITERS.replace("{deny}", "{}"));
    let (_other_dir, other_path, other_calls) =
        recorded_policy("test/head-pipeline-b", &HOST_LIMITERS.replace("{deny}", "{}"));
    let yaml = format!("- filter: policy\n  config_path: {path}\n- filter: policy\n  config_path: {other_path}\n");
    let mut entries: Vec<FilterEntry> = serde_yaml::from_str(&yaml).unwrap();
    let pipeline = FilterPipeline::build(&mut entries, &FilterRegistry::with_builtins()).unwrap();
    assert!(pipeline.has_request_head_phase());
    let req = request(Some("alice"));
    let mut ctx = make_filter_context(&req);
    let action = pipeline.execute_http_request_head(&mut ctx).await.unwrap();
    assert!(matches!(action, FilterAction::Continue), "head: {action:?}");
    let action = pipeline.execute_http_request(&mut ctx).await.unwrap();
    assert!(matches!(action, FilterAction::Continue), "request: {action:?}");
    assert_eq!(plugins(&calls), ["pre", "who", "post"]);
    assert_eq!(plugins(&other_calls), ["pre", "who", "post"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn only_an_earlier_filter_that_can_end_the_request_moves_admission_out_of_the_head() {
    let (_dir, path, _calls) = recorded_policy("test/head-ordering", &HOST_LIMITERS.replace("{deny}", "{}"));
    let cases = [
        ("forwarded_headers", "- filter: forwarded_headers\n", true),
        (
            "headers",
            "- filter: headers\n  request_add:\n    - name: x-a\n      value: b\n",
            true,
        ),
        (
            "grpc_timeout",
            "- filter: grpc_timeout\n  max_timeout_ms: 1000\n",
            false,
        ),
        (
            "router",
            "- filter: router\n  routes:\n    - path_prefix: /\n      cluster: backend\n",
            false,
        ),
    ];
    for (case, earlier, head) in cases {
        let yaml = format!("{earlier}- filter: policy\n  config_path: {path}\n");
        let mut entries: Vec<FilterEntry> = serde_yaml::from_str(&yaml).unwrap();
        let pipeline = FilterPipeline::build(&mut entries, &FilterRegistry::with_builtins()).unwrap();
        assert_eq!(pipeline.has_request_head_phase(), head, "{case}");
    }
}

#[test]
fn only_dropped_or_head_only_steps_keep_the_global_resolver_from_the_head() {
    for (case, yaml, blocker) in additive_layouts()
        .into_iter()
        .chain(blocking_layouts())
        .chain(http_group_layouts())
    {
        let yaml = format!("{PLUGINS}{yaml}");
        let config = ppe::praxis_policy_core::config::parse_config(&yaml).unwrap();
        let found = head_identity_blocker(&config);
        match blocker {
            None => assert_eq!(found, None, "{case}"),
            Some(section) => assert!(
                found.as_deref().is_some_and(|reason| reason.contains(section)),
                "{case}: {found:?}"
            ),
        }
    }
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Layouts whose sections only append to the global resolver.
fn additive_layouts() -> [(&'static str, String, Option<&'static str>); 5] {
    let global = "global:\n  authentication: [who]\n";
    [
        ("global only", format!("{global}routes:\n  - tool: echo\n"), None),
        ("no authentication", "routes:\n  - tool: echo\n".to_owned(), None),
        (
            "an additive route",
            format!("{global}routes:\n  - tool: echo\n    authentication: [key]\n"),
            None,
        ),
        (
            "an additive entity default",
            format!("{global}  defaults:\n    tool:\n      authentication: [key]\nroutes:\n  - tool: echo\n"),
            None,
        ),
        (
            "an additive group",
            format!(
                "{global}groups:\n  keyed:\n    authentication: [key]\nroutes:\n  - tool: echo\n    groups: keyed\n"
            ),
            None,
        ),
    ]
}

/// Layouts that keep the global resolver from judging at the head, and the
/// section the reason names.
fn blocking_layouts() -> [(&'static str, String, Option<&'static str>); 4] {
    let global = "global:\n  authentication: [who]\n";
    let replacing = "authentication:\n      replace_inherited: true\n      steps: [key]\n";
    [
        (
            "a replacing route",
            format!("{global}routes:\n  - tool: echo\n    {replacing}"),
            Some("routes[0]"),
        ),
        (
            "a replacing entity default",
            format!(
                "{global}  defaults:\n    tool:\n      {}routes:\n  - tool: echo\n",
                replacing.replace("\n      ", "\n        ")
            ),
            Some("global.defaults.tool"),
        ),
        (
            "a replacing group",
            format!("{global}groups:\n  keyed:\n    {replacing}routes:\n  - tool: echo\n    groups: keyed\n"),
            Some("groups.keyed"),
        ),
        (
            "additive http defaults",
            format!("{global}  defaults:\n    http:\n      authentication: [key]\nroutes:\n  - tool: echo\n"),
            Some("global.defaults.http"),
        ),
    ]
}

/// An `http:` route joining a group whose steps the head would run, alongside
/// an entity route that doesn't join it.
fn http_group_layouts() -> [(&'static str, String, Option<&'static str>); 1] {
    [(
        "an http route joining an additive group",
        "global:\n  authentication: [who]\ngroups:\n  keyed:\n    authentication: [key]\nroutes:\n  - http:\n      \
         path_prefix: /admin\n    groups: keyed\n  - tool: echo\n"
            .to_owned(),
        Some("`routes[0]` joins `groups.keyed`"),
    )]
}

/// Queue one head-filter mutation of a header on a context.
type Mutate = fn(&mut HttpFilterContext<'_>, &HeaderName);

/// Two identity plugins the authentication cases name.
const PLUGINS: &str = "plugins:
  - name: who
    kind: builtin/noop
    hooks: [identity.resolve]
  - name: key
    kind: builtin/noop
    hooks: [identity.resolve]
";

/// Head-filter mutations of `x-user`, and the subject the head should see.
fn head_mutations() -> [(&'static str, Mutate, &'static str); 4] {
    [
        (
            "ordered set",
            |ctx, name| ctx.pre_read_mutations.push(set(name)),
            "carol",
        ),
        (
            "ordered remove",
            |ctx, name| ctx.pre_read_mutations.push(TrustedHeaderMutation::Remove(name.clone())),
            "",
        ),
        (
            "grouped set",
            |ctx, name| ctx.request_headers_to_set.push((name.clone(), value())),
            "carol",
        ),
        (
            "grouped remove",
            |ctx, name| ctx.request_headers_to_remove.push(name.clone()),
            "",
        ),
    ]
}

/// Run the head phase.
async fn head(filter: &PolicyFilter, ctx: &mut HttpFilterContext<'_>) -> FilterAction {
    filter.on_request_head(ctx).await.unwrap()
}

/// Run the classified `echo` tool call's body phase.
async fn tool_body(filter: &PolicyFilter, ctx: &mut HttpFilterContext<'_>) -> FilterAction {
    ctx.filter_metadata
        .insert("mcp.method", "tools/call")
        .expect("entry must fit in the filter's metadata");
    ctx.filter_metadata
        .insert("mcp.name", "echo")
        .expect("entry must fit in the filter's metadata");
    let mut body = Some(Bytes::from_static(TOOL_CALL));
    filter.on_request_body(ctx, &mut body, true).await.unwrap()
}

/// The subject `plugin` last saw.
fn subject_of(calls: &Calls, plugin: &str) -> String {
    calls
        .lock()
        .unwrap()
        .iter()
        .rev()
        .find(|(name, ..)| name == plugin)
        .map_or_else(|| panic!("{plugin} never ran"), |(.., subject)| subject.clone())
}

/// A trusted set of `name` to the sanitized user.
fn set(name: &HeaderName) -> TrustedHeaderMutation {
    TrustedHeaderMutation::Set(name.clone(), value())
}

/// The sanitized user.
fn value() -> HeaderValue {
    HeaderValue::from_static("carol")
}
