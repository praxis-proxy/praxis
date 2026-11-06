// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

#![expect(
    clippy::tests_outside_test_module,
    reason = "test functions live in this cfg(test) module"
)]

//! What the policy engine sees of the downstream request: query credentials,
//! the raw query on every hook, the scheme, the `DPoP` URL, and fail-closed
//! delegation beside a credential the filter cannot strip.

use std::sync::{Arc, Mutex};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::Bytes;
use http::{HeaderValue, Method};
use openssl::{
    bn::BigNumContext,
    ec::{EcGroup, EcKey, PointConversionForm},
    ecdsa::EcdsaSig,
    hash::{MessageDigest, hash},
    nid::Nid,
    pkey::{PKey, Private},
    sign::Signer,
};
use serde_json::{Value, json};
use tempfile::TempDir;

use super::{
    construction::refuse_query_credentials_with_delegation,
    feature_tests::{filter_config, write_policy},
    filter::{PolicyFilter, attach_delegated_tokens},
};
use crate::{
    AuthenticatedIdentity, FilterAction, Rejection,
    filter::HttpFilter as _,
    test_utils::{make_filter_context, make_request},
};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// The key the fixture directory knows; also the secret the log and body
/// assertions look for.
const TEST_API_KEY: &str = "sk-test-alice";

/// SHA-256 of [`TEST_API_KEY`].
///
/// [`TEST_API_KEY`]: TEST_API_KEY
const TEST_API_KEY_DIGEST: &str = "sha256:4d692786b022a5d5a48381dcaf1e5e346366feb5579a1d699de2991d153b05f9";

/// A pure-L7 policy authenticating with an API key at `{credential}` and
/// running `{rules}` (an `authorization:` body).
const API_KEY_POLICY: &str = r#"plugins:
  - name: api-keys
    kind: identity/api-key
    hooks: [identity.resolve]
    on_error: fail
    capabilities: [read_headers, read_query]
    config:
      credential: {credential}
      prefix: "sk-test-"
      provider:
        kind: file
        path: "{keys}"
        index: sha256
      record_map:
        subject:
          id: user
global:
  authentication: [api-keys]
  authorization:
{rules}
"#;

/// The query credential.
const QUERY_CREDENTIAL: &str = "{ kind: query_param, name: api_key }";

/// The header credential.
const HEADER_CREDENTIAL: &str = "{ kind: header, name: X-Api-Key }";

/// Rules admitting any authenticated caller.
const AUTHENTICATED: &str = "    pre_invocation:\n      - \"require(authenticated)\"";

/// A delegator plugin naming the `token.delegate` hook, enough to parse.
const DELEGATOR: &str = "  - name: exchange
    kind: delegator/oauth
    hooks: [token.delegate]
    config: {}
";

/// The issuer of the `DPoP`-bound fixture tokens.
const DPOP_ISSUER: &str = "https://dpop.idp.test";

/// The URL `DPoP` clients address.
const EXTERNAL_BASE_URL: &str = "https://api.praxis.test";

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn a_query_api_key_authenticates() {
    let (_dir, filter) = api_key_filter(QUERY_CREDENTIAL, AUTHENTICATED);
    let req = request(&format!("/widgets?api_key={TEST_API_KEY}&view=full"), &[]);
    let mut ctx = make_filter_context(&req);
    let action = filter.on_request(&mut ctx).await.expect("the filter runs");
    assert!(matches!(action, FilterAction::Continue), "got {action:?}");
    assert_eq!(
        ctx.extensions
            .get::<AuthenticatedIdentity>()
            .map(AuthenticatedIdentity::subject_id),
        Some("alice"),
        "the key in the query must resolve its subject"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_duplicate_or_encoded_duplicate_query_credential_is_denied() {
    let (_dir, filter) = api_key_filter(QUERY_CREDENTIAL, AUTHENTICATED);
    for (uri, case) in [
        (
            format!("/w?api_key={TEST_API_KEY}&api_key=sk-test-bob"),
            "a repeated name",
        ),
        (
            format!("/w?api_key={TEST_API_KEY}&api%5Fkey=sk-test-bob"),
            "a percent-encoded repeat",
        ),
    ] {
        let rejection = header_phase(&filter, &request(&uri, &[]), false)
            .await
            .unwrap_or_else(|| panic!("{case} must be denied"));
        assert_eq!(rejection.status, 401, "{case}");
        assert_eq!(violation(&rejection), Some("auth.ambiguous_credential"), "{case}");
        assert!(
            !body_text(&rejection).contains(TEST_API_KEY),
            "{case}: the denial must not echo the key"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn no_query_and_a_bare_question_mark_reach_policy_differently() {
    let rules = "    pre_invocation:\n      - \"require(authenticated)\"\n      - \"http.query == '': deny('bare query', 'test.bare_query')\"";
    let (_dir, filter) = api_key_filter(HEADER_CREDENTIAL, rules);
    let key = [("x-api-key", TEST_API_KEY)];
    assert!(
        header_phase(&filter, &request("/widgets", &key), false).await.is_none(),
        "no query leaves `http.query` absent, so the rule cannot match"
    );
    let rejection = header_phase(&filter, &request("/widgets?", &key), false)
        .await
        .expect("a bare `?` is an empty query and must match");
    assert_eq!(violation(&rejection), Some("test.bare_query"));
}

#[tokio::test(flavor = "multi_thread")]
async fn the_scheme_comes_from_downstream_tls() {
    let rules = "    pre_invocation:\n      - \"require(authenticated)\"\n      - \"http.scheme != 'https': deny('plaintext', 'test.plaintext')\"";
    let (_dir, filter) = api_key_filter(HEADER_CREDENTIAL, rules);
    let key = ("x-api-key", TEST_API_KEY);
    assert!(
        header_phase(&filter, &request("/", &[key]), true).await.is_none(),
        "a TLS connection is https"
    );
    let spoofed = request("/", &[key, ("x-forwarded-proto", "https")]);
    let rejection = header_phase(&filter, &spoofed, false)
        .await
        .expect("X-Forwarded-Proto must not make a plaintext request https");
    assert_eq!(violation(&rejection), Some("test.plaintext"));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_trusted_proxy_chain_sets_the_client_address() {
    let rules = "    pre_invocation:\n      - \"require(authenticated)\"\n      - \"http.client_address != '203.0.113.7': deny('other client', 'test.other_client')\"";
    let (_dir, filter) = api_key_filter_trusting(HEADER_CREDENTIAL, rules, &["10.0.0.0/8"]);
    let req = request(
        "/",
        &[
            ("x-api-key", TEST_API_KEY),
            ("x-forwarded-for", "203.0.113.7, 10.0.0.1"),
        ],
    );
    for (peer, admitted) in [("10.0.0.2", true), ("198.51.100.9", false)] {
        let mut ctx = make_filter_context(&req);
        ctx.current_filter_id = Some(0);
        ctx.client_addr = Some(peer.parse().expect("address"));
        let action = filter.on_request(&mut ctx).await.expect("the filter runs");
        match action {
            FilterAction::Continue => assert!(admitted, "peer {peer}: a spoofed XFF must not pass"),
            FilterAction::Reject(rejection) => {
                assert!(!admitted, "peer {peer}: the forwarded client must reach policy");
                assert_eq!(violation(&rejection), Some("test.other_client"));
            },
            other => panic!("unexpected action {other:?}"),
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_trusted_proxy_chain_sets_the_client_address_without_a_filter_id() {
    let rules = "    pre_invocation:\n      - \"require(authenticated)\"\n      - \"http.client_address != '203.0.113.7': deny('other client', 'test.other_client')\"";
    let (_dir, filter) = api_key_filter_trusting(HEADER_CREDENTIAL, rules, &["10.0.0.0/8"]);
    let req = request(
        "/",
        &[
            ("x-api-key", TEST_API_KEY),
            ("x-forwarded-for", "203.0.113.7, 10.0.0.1"),
        ],
    );
    let mut ctx = make_filter_context(&req);
    ctx.client_addr = Some("10.0.0.2".parse().expect("address"));
    let action = filter.on_request(&mut ctx).await.expect("the filter runs");
    assert!(
        matches!(action, FilterAction::Continue),
        "the forwarded client must reach policy, got {action:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_original_query_reaches_the_response_hook() {
    let query = format!("api_key={TEST_API_KEY}&view=full");
    let rules = format!(
        "    pre_invocation:\n      - \"require(authenticated)\"\n    post_invocation:\n      - \"http.query == '{query}': deny('seen', 'test.query_seen')\""
    );
    let (_dir, filter) = api_key_filter(QUERY_CREDENTIAL, &rules);
    assert!(filter.response_hook().is_some(), "the policy declares a response half");

    let original = request(&format!("/widgets?{query}"), &[]);
    let mut ctx = make_filter_context(&original);
    ctx.current_filter_id = Some(0);
    let action = filter.on_request(&mut ctx).await.expect("the header phase runs");
    assert!(matches!(action, FilterAction::Continue), "got {action:?}");

    let rewritten = request("/v2/widgets", &[]);
    let mut response_ctx = make_filter_context(&rewritten);
    response_ctx.current_filter_id = Some(0);
    response_ctx.extensions = std::mem::take(&mut ctx.extensions);
    response_ctx.filter_state = std::mem::take(&mut ctx.filter_state);
    let mut response = crate::test_utils::make_response();
    response_ctx.response_header = Some(&mut response);
    let action = filter
        .on_response(&mut response_ctx)
        .await
        .expect("the response phase runs");
    let FilterAction::Reject(rejection) = action else {
        panic!("the response rule must see the original query, got {action:?}");
    };
    assert_eq!(violation(&rejection), Some("test.query_seen"));
}

#[tokio::test(flavor = "multi_thread")]
#[expect(clippy::too_many_lines, reason = "linear header-then-body lifecycle")]
async fn the_original_query_reaches_a_later_cmf_hook() {
    let dir = TempDir::new().expect("create tempdir");
    let keys = dir.path().join("keys.yaml");
    std::fs::write(
        &keys,
        format!("keys:\n  - hash: \"{TEST_API_KEY_DIGEST}\"\n    user: alice\n"),
    )
    .expect("write keys.yaml");
    let base = API_KEY_POLICY
        .replace("{credential}", QUERY_CREDENTIAL)
        .replace("{rules}", AUTHENTICATED)
        .replace("{keys}", keys.to_str().expect("utf8"));
    let yaml = format!(
        "{base}{}",
        "routes:\n  - tool: echo\n    authorization:\n      pre_invocation:\n        - \"http.query == 'api_key=sk-test-alice': deny('seen', 'test.query_seen')\"\n"
    );
    let (_policy_dir, path) = write_policy(&yaml);
    let filter = PolicyFilter::new(filter_config(path), None).expect("the entity policy builds");

    let original = request(&format!("/mcp?api_key={TEST_API_KEY}"), &[]);
    let mut ctx = make_filter_context(&original);
    ctx.current_filter_id = Some(0);
    let action = filter.on_request(&mut ctx).await.expect("the header gate runs");
    assert!(matches!(action, FilterAction::Continue), "got {action:?}");

    let stripped = request("/mcp", &[]);
    let mut body_ctx = make_filter_context(&stripped);
    body_ctx.current_filter_id = Some(0);
    body_ctx.extensions = std::mem::take(&mut ctx.extensions);
    body_ctx.filter_state = std::mem::take(&mut ctx.filter_state);
    body_ctx.set_metadata("mcp.method", "tools/call");
    body_ctx.set_metadata("mcp.name", "echo");
    let body = Bytes::from_static(br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo"}}"#);
    let action = filter
        .on_request_body(&mut body_ctx, &mut Some(body), true)
        .await
        .expect("the body phase runs");
    let FilterAction::Reject(rejection) = action else {
        panic!("the tool rule must see the original query, got {action:?}");
    };
    assert_eq!(violation(&rejection), Some("test.query_seen"));
}

#[test]
fn delegation_beside_a_query_credential_is_rejected_without_leaking_it() {
    use ppe::praxis_policy_core::extensions::Credential;

    let ext = delegation_extensions(Credential::QueryParam {
        name: "api_key".to_owned(),
    });
    let req = make_request(Method::GET, "/widgets?api_key=sk-test-alice");
    let mut ctx = make_filter_context(&req);
    let (result, logs) = capture_logs(|| attach_delegated_tokens(&mut ctx, Some(&ext)));
    let rejection = result.expect_err("the query credential cannot be stripped, so delegation must fail closed");
    assert_eq!(rejection.status, 500);
    assert_eq!(violation(&rejection), Some("policy.unstrippable_credential"));
    assert!(
        ctx.request_headers_to_set.is_empty() && ctx.request_headers_to_remove.is_empty(),
        "nothing is attached or stripped on a refusal"
    );
    for (label, secret) in [
        ("the inbound key", TEST_API_KEY),
        ("the delegated token", "delegated-secret"),
    ] {
        assert!(
            !body_text(&rejection).contains(secret),
            "the body must not carry {label}"
        );
        assert!(!logs.contains(secret), "the logs must not carry {label}");
    }
    assert!(logs.contains("refusing to forward a delegated token"), "got {logs}");
}

#[test]
fn a_delegation_with_no_valid_header_is_rejected_without_leaking_it() {
    use ppe::praxis_policy_core::extensions::Credential;

    let ext = delegation_extensions_to(
        Credential::Header {
            name: "X-Api-Key".to_owned(),
        },
        "not a header",
    );
    let req = make_request(Method::GET, "/widgets");
    let mut ctx = make_filter_context(&req);
    let (result, logs) = capture_logs(|| attach_delegated_tokens(&mut ctx, Some(&ext)));
    let rejection = result.expect_err("a delegation that attaches nothing must fail closed");
    assert_eq!(rejection.status, 500);
    assert_eq!(violation(&rejection), Some("policy.delegation_failed"));
    assert!(
        ctx.request_headers_to_set.is_empty() && ctx.request_headers_to_remove.is_empty(),
        "nothing is attached or stripped on a refusal"
    );
    for (label, secret) in [
        ("the inbound key", TEST_API_KEY),
        ("the delegated token", "delegated-secret"),
    ] {
        assert!(
            !body_text(&rejection).contains(secret),
            "the body must not carry {label}"
        );
        assert!(!logs.contains(secret), "the logs must not carry {label}");
    }
}

#[test]
fn delegation_beside_a_header_credential_strips_it() {
    use ppe::praxis_policy_core::extensions::Credential;

    let ext = delegation_extensions(Credential::Header {
        name: "X-Api-Key".to_owned(),
    });
    let req = make_request(Method::GET, "/widgets");
    let mut ctx = make_filter_context(&req);
    assert_eq!(
        attach_delegated_tokens(&mut ctx, Some(&ext)).expect("a header strips"),
        1
    );
    assert_eq!(
        ctx.request_headers_to_remove
            .iter()
            .map(http::HeaderName::as_str)
            .collect::<Vec<_>>(),
        ["x-api-key"],
        "the inbound header is removed"
    );
}

#[test]
fn a_query_credential_beside_delegation_is_refused_at_construction() {
    let yaml = API_KEY_POLICY
        .replace("{credential}", QUERY_CREDENTIAL)
        .replace("{rules}", AUTHENTICATED)
        .replace("{keys}", "/unused.yaml")
        .replace("global:\n", &format!("{DELEGATOR}global:\n"));
    let parsed = ppe::praxis_policy_core::config::parse_config(&yaml).expect("the fixture parses");
    let error = refuse_query_credentials_with_delegation(&parsed)
        .expect_err("a query credential beside delegation must be refused")
        .to_string();
    assert!(
        error.contains("'api-keys'") && error.contains("query parameter"),
        "the refusal must name the plugin and the location: {error}"
    );

    let (_dir, path) = write_policy(&yaml);
    let Err(error) = PolicyFilter::new(filter_config(path), None) else {
        panic!("construction must refuse the policy");
    };
    assert!(error.to_string().contains("'api-keys'"), "got {error}");

    let header = yaml.replace(QUERY_CREDENTIAL, HEADER_CREDENTIAL);
    let parsed = ppe::praxis_policy_core::config::parse_config(&header).expect("the fixture parses");
    assert!(
        refuse_query_credentials_with_delegation(&parsed).is_ok(),
        "a header credential can be stripped, so delegation is allowed"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[expect(clippy::too_many_lines, reason = "test fixture: the YAML literal is the bulk")]
async fn a_dpop_proof_for_a_spoofed_host_is_denied() {
    let issuer_key = p256_key();
    let client_key = p256_key();
    let public = String::from_utf8(issuer_key.public_key_to_pem().expect("public PEM")).expect("utf8 PEM");
    let yaml = format!(
        "plugins:
  - name: jwt-user
    kind: identity/jwt
    hooks: [identity.resolve]
    mode: sequential
    on_error: fail
    capabilities: [read_headers]
    config:
      credential: {{ kind: header, name: Authorization }}
      trusted_issuers:
        - issuer: \"{DPOP_ISSUER}\"
          audiences: [api]
          algorithms: [ES256]
          decoding_key: {{ kind: pem, pem: {public:?} }}
          dpop: {{ mode: required, algorithms: [ES256], external_base_url: \"{EXTERNAL_BASE_URL}\" }}
      claim_mapper: standard
global:
  authentication: [jwt-user]
  authorization:
    pre_invocation:
      - \"require(authenticated)\"
"
    );
    let (_dir, path) = write_policy(&yaml);
    let filter = PolicyFilter::new(filter_config(path), None).expect("the DPoP policy builds");

    let send = |htu: &str| {
        let token = es256(&dpop_token_claims(&client_key), &issuer_key, "JWT", None);
        let proof = dpop_proof(&client_key, htu, &token);
        request(
            "/widgets",
            &[
                ("host", "evil.example"),
                ("authorization", &format!("DPoP {token}")),
                ("dpop", &proof),
            ],
        )
    };
    let spoofed = send("https://evil.example/widgets");
    let rejection = header_phase(&filter, &spoofed, true)
        .await
        .expect("a proof for the spoofed host must be denied");
    assert_eq!(violation(&rejection), Some("auth.dpop_invalid"));

    let bound = send(&format!("{EXTERNAL_BASE_URL}/widgets"));
    assert!(
        header_phase(&filter, &bound, true).await.is_none(),
        "a proof for the external base URL verifies whatever Host says"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// A filter over [`API_KEY_POLICY`] with `credential` and `rules`; the
/// returned directory holds the policy and key file.
///
/// [`API_KEY_POLICY`]: API_KEY_POLICY
fn api_key_filter(credential: &str, rules: &str) -> (TempDir, PolicyFilter) {
    api_key_filter_trusting(credential, rules, &[])
}

/// [`api_key_filter`] trusting `trusted_proxies` to report the client.
///
/// [`api_key_filter`]: api_key_filter
fn api_key_filter_trusting(credential: &str, rules: &str, trusted_proxies: &[&str]) -> (TempDir, PolicyFilter) {
    let dir = TempDir::new().expect("create tempdir");
    let keys = dir.path().join("keys.yaml");
    std::fs::write(
        &keys,
        format!("keys:\n  - hash: \"{TEST_API_KEY_DIGEST}\"\n    user: alice\n"),
    )
    .expect("write keys.yaml");
    let yaml = API_KEY_POLICY
        .replace("{credential}", credential)
        .replace("{rules}", rules)
        .replace("{keys}", keys.to_str().expect("a UTF-8 tempdir path"));
    let path = dir.path().join("policy.yaml");
    std::fs::write(&path, yaml).expect("write policy.yaml");
    let mut cfg = filter_config(path.to_str().expect("utf8").to_owned());
    cfg.trusted_proxies = trusted_proxies.iter().map(|cidr| (*cidr).to_owned()).collect();
    let filter = PolicyFilter::new(cfg, None).expect("the API-key policy builds");
    (dir, filter)
}

/// A `GET uri` request carrying `headers`.
fn request(uri: &str, headers: &[(&'static str, &str)]) -> crate::Request {
    let mut req = make_request(Method::GET, uri);
    for (name, value) in headers {
        req.headers
            .insert(*name, HeaderValue::from_str(value).expect("header value"));
    }
    req
}

/// Run `on_request` over `req` and return the rejection, if any.
async fn header_phase(filter: &PolicyFilter, req: &crate::Request, tls: bool) -> Option<Rejection> {
    let mut ctx = make_filter_context(req);
    ctx.downstream_tls = tls;
    match filter.on_request(&mut ctx).await.expect("the filter runs") {
        FilterAction::Continue => None,
        FilterAction::Reject(rejection) => Some(rejection),
        other => panic!("the header phase must Continue or Reject, got {other:?}"),
    }
}

/// The `X-Policy-Violation` code on `rejection`.
fn violation(rejection: &Rejection) -> Option<&str> {
    rejection
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("X-Policy-Violation"))
        .map(|(_, value)| value.as_str())
}

/// The rejection body as text.
fn body_text(rejection: &Rejection) -> String {
    String::from_utf8_lossy(rejection.body.as_deref().unwrap_or_default()).into_owned()
}

/// Extensions carrying an inbound credential at `source` and one delegated
/// token for `Authorization`.
fn delegation_extensions(source: ppe::praxis_policy_core::extensions::Credential) -> ppe::prelude::Extensions {
    delegation_extensions_to(source, "Authorization")
}

/// Extensions carrying an inbound credential at `source` and one delegated
/// token for `outbound_header`.
fn delegation_extensions_to(
    source: ppe::praxis_policy_core::extensions::Credential,
    outbound_header: &str,
) -> ppe::prelude::Extensions {
    use chrono::{Duration, Utc};
    use ppe::praxis_policy_core::extensions::raw_credentials::{
        DelegationKey, DelegationMode, RawCredentialsExtension, RawDelegatedToken, RawInboundToken, TokenKind,
        TokenRole,
    };

    let mut creds = RawCredentialsExtension::default();
    creds.inbound_tokens.insert(
        TokenRole::User,
        RawInboundToken::new(TEST_API_KEY, source, TokenKind::Opaque),
    );
    creds.delegated_tokens.insert(
        DelegationKey::new(DelegationMode::OnBehalfOfUser, "api", Vec::new()).with_subject_id("alice"),
        RawDelegatedToken::new(
            "delegated-secret",
            outbound_header,
            "api",
            Vec::<String>::new(),
            Utc::now() + Duration::hours(1),
        ),
    );
    ppe::prelude::Extensions {
        raw_credentials: Some(Arc::new(creds)),
        ..Default::default()
    }
}

/// Access-token claims bound to `client`.
fn dpop_token_claims(client: &EcKey<Private>) -> Value {
    let now = now();
    json!({
        "iss": DPOP_ISSUER, "aud": "api", "sub": "alice", "iat": now, "exp": now + 300,
        "jti": fresh_jti(), "cnf": { "jkt": thumbprint(client) },
    })
}

/// A `DPoP` proof for `GET htu` binding `token`, signed by `client`.
fn dpop_proof(client: &EcKey<Private>, htu: &str, token: &str) -> String {
    let ath = URL_SAFE_NO_PAD.encode(hash(MessageDigest::sha256(), token.as_bytes()).expect("SHA-256"));
    let claims = json!({ "htm": "GET", "htu": htu, "iat": now(), "jti": fresh_jti(), "ath": ath });
    es256(&claims, client, "dpop+jwt", Some(jwk(client)))
}

/// A compact ES256 JWS over `claims`.
fn es256(claims: &Value, key: &EcKey<Private>, typ: &str, jwk: Option<Value>) -> String {
    let mut header = json!({ "alg": "ES256", "typ": typ });
    if let Some(jwk) = jwk {
        header["jwk"] = jwk;
    }
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    );
    let pkey = PKey::from_ec_key(key.clone()).expect("EC PKey");
    let mut signer = Signer::new(MessageDigest::sha256(), &pkey).expect("signer");
    signer.update(input.as_bytes()).expect("feed signer");
    let der = EcdsaSig::from_der(&signer.sign_to_vec().expect("sign")).expect("DER signature");
    let mut raw = der.r().to_vec_padded(32).expect("R");
    raw.extend(der.s().to_vec_padded(32).expect("S"));
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(raw))
}

/// The public JWK of `key`.
fn jwk(key: &EcKey<Private>) -> Value {
    let mut bn = BigNumContext::new().expect("BN context");
    let point = key
        .public_key()
        .to_bytes(key.group(), PointConversionForm::UNCOMPRESSED, &mut bn)
        .expect("point");
    let (x, y) = (point.get(1..33).expect("x"), point.get(33..65).expect("y"));
    json!({ "kty": "EC", "crv": "P-256", "x": URL_SAFE_NO_PAD.encode(x), "y": URL_SAFE_NO_PAD.encode(y) })
}

/// The RFC 7638 thumbprint of `key`.
fn thumbprint(key: &EcKey<Private>) -> String {
    let jwk = jwk(key);
    let canonical = format!(
        r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
        jwk["x"].as_str().expect("x"),
        jwk["y"].as_str().expect("y")
    );
    URL_SAFE_NO_PAD.encode(hash(MessageDigest::sha256(), canonical.as_bytes()).expect("SHA-256"))
}

/// A fresh P-256 key.
fn p256_key() -> EcKey<Private> {
    EcKey::generate(&EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).expect("P-256")).expect("generate key")
}

/// Seconds since the epoch.
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs()
}

/// A random `jti`.
fn fresh_jti() -> String {
    let mut random = [0_u8; 16];
    openssl::rand::rand_bytes(&mut random).expect("random bytes");
    URL_SAFE_NO_PAD.encode(random)
}

/// Run `run` with every event on this thread, at every level, formatted into
/// the returned string.
fn capture_logs<T>(run: impl FnOnce() -> T) -> (T, String) {
    /// Test log capture buffer.
    #[derive(Clone, Default)]
    struct Sink(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Sink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("sink lock").extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Sink {
        type Writer = Self;

        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    let sink = Sink::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(sink.clone())
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .finish();
    let result = tracing::subscriber::with_default(subscriber, run);
    let bytes = sink.0.lock().expect("sink lock").clone();
    (result, String::from_utf8_lossy(&bytes).into_owned())
}
