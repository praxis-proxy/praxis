// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Integration coverage for a policy backed by a live JWKS endpoint.

use std::{
    collections::HashMap,
    io::{Read as _, Write as _},
    net::{SocketAddr, TcpListener},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use praxis_core::config::Config;
use praxis_test_utils::{
    example_config_path, free_port, http_send, parse_status, patch_yaml, start_backend_with_shutdown, start_proxy,
};

const ISSUER: &str = "https://idp.example.com";
const AUDIENCE: &str = "praxis-policy-example";
const KEY_ID: &str = "praxis-jwks-test-key";

/// Signing secret published by the test JWKS.
const SECRET: &[u8] = b"praxis-jwks-integration-secret-not-for-production";
const SECRET_B64URL: &str = "cHJheGlzLWp3a3MtaW50ZWdyYXRpb24tc2VjcmV0LW5vdC1mb3ItcHJvZHVjdGlvbg";

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn a_token_signed_by_the_published_jwks_key_is_accepted() {
    let jwks = JwksEndpoint::start();
    let backend_guard = start_backend_with_shutdown("ok");
    let policy_dir = tempfile::TempDir::new().expect("create tempdir");
    let policy_path = write_jwks_policy(&policy_dir, jwks.address);

    let proxy_port = free_port();
    let config = load_jwks_policy_example(proxy_port, backend_guard.port(), &policy_path);
    let proxy = start_proxy(&config);

    assert!(jwks.fetches() >= 1, "constructing the filter must fetch the key set");

    let token = mint_jwks_signed_jwt("alice");
    let body = r#"{"jsonrpc":"2.0","id":1,"method":"service/invoke","params":{"name":"echo","arguments":{}}}"#;
    let raw = http_send(
        proxy.addr(),
        &format!(
            "POST /rpc HTTP/1.1\r\n\
             Host: localhost\r\n\
             Authorization: Bearer {token}\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             \r\n\
             {body}",
            body.len(),
        ),
    );

    assert_eq!(
        parse_status(&raw),
        200,
        "a token signed by the fetched key must resolve identity; raw response:\n{raw}",
    );
    assert!(
        raw.contains("ok"),
        "the allow path must reach the backend; raw response:\n{raw}",
    );
}

#[test]
fn a_token_signed_by_an_unpublished_key_is_rejected() {
    let jwks = JwksEndpoint::start();
    let backend_guard = start_backend_with_shutdown("ok");
    let policy_dir = tempfile::TempDir::new().expect("create tempdir");
    let policy_path = write_jwks_policy(&policy_dir, jwks.address);

    let proxy_port = free_port();
    let config = load_jwks_policy_example(proxy_port, backend_guard.port(), &policy_path);
    let proxy = start_proxy(&config);

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after epoch")
        .as_secs();
    let claims = serde_json::json!({
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "mallory",
        "iat": now,
        "exp": now + 300,
    });
    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some(KEY_ID.to_owned());
    let token = encode(
        &header,
        &claims,
        &EncodingKey::from_secret(b"a different secret entirely"),
    )
    .expect("sign with the wrong key");

    let body = r#"{"jsonrpc":"2.0","id":1,"method":"service/invoke","params":{"name":"echo","arguments":{}}}"#;
    let raw = http_send(
        proxy.addr(),
        &format!(
            "POST /rpc HTTP/1.1\r\n\
             Host: localhost\r\n\
             Authorization: Bearer {token}\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             \r\n\
             {body}",
            body.len(),
        ),
    );

    assert_eq!(
        parse_status(&raw),
        401,
        "a signature the fetched key set cannot verify must be rejected; raw response:\n{raw}",
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Local JWKS test server.
struct JwksEndpoint {
    /// Listening address.
    address: SocketAddr,

    /// Number of served documents.
    fetches: Arc<AtomicUsize>,
}

impl JwksEndpoint {
    /// Start the server with one symmetric key.
    fn start() -> Self {
        let document =
            format!(r#"{{"keys":[{{"kty":"oct","use":"sig","alg":"HS256","kid":"{KEY_ID}","k":"{SECRET_B64URL}"}}]}}"#);
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n{document}",
            document.len()
        );

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind JWKS listener");
        let address = listener.local_addr().expect("JWKS listener address");
        let fetches = Arc::new(AtomicUsize::new(0));

        let served = Arc::clone(&fetches);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                let served = Arc::clone(&served);
                let response = response.clone();
                std::thread::spawn(move || {
                    let mut head = Vec::new();
                    let mut byte = [0_u8; 1];
                    while !head.ends_with(b"\r\n\r\n") {
                        match stream.read(&mut byte) {
                            Ok(0) | Err(_) => return,
                            Ok(_) => head.push(byte[0]),
                        }
                    }
                    served.fetch_add(1, Ordering::SeqCst);
                    let _ignored = stream.write_all(response.as_bytes());
                    let _ignored = stream.flush();
                });
            }
        });

        Self { address, fetches }
    }

    /// Return the number of served documents.
    fn fetches(&self) -> usize {
        self.fetches.load(Ordering::SeqCst)
    }
}

/// Mint a JWT signed by the published test key.
fn mint_jwks_signed_jwt(subject: &str) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after epoch")
        .as_secs();
    let claims = serde_json::json!({
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": subject,
        "iat": now,
        "exp": now + 300,
    });
    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some(KEY_ID.to_owned());
    encode(&header, &claims, &EncodingKey::from_secret(SECRET)).expect("sign JWKS-keyed JWT")
}

/// Write a policy that loads keys from `jwks`.
fn write_jwks_policy(dir: &tempfile::TempDir, jwks: SocketAddr) -> String {
    let path = dir.path().join("policy.yaml");
    let yaml = format!(
        r#"plugins:
  - name: jwt-user
    kind: identity/jwt
    hooks: [identity.resolve]
    mode: sequential
    on_error: fail
    capabilities:
      - perform_http
    config:
      header: Authorization
      trusted_issuers:
        - issuer: "{ISSUER}"
          audiences: ["{AUDIENCE}"]
          algorithms: ["HS256"]
          decoding_key:
            kind: jwks_url
            url: "http://{jwks}/jwks"
            insecure_http: true
          leeway_seconds: 60
      claim_mapper: standard

global:
  authentication:
    - jwt-user
"#
    );
    std::fs::write(&path, yaml).expect("write JWKS policy document");
    path.to_str().expect("utf8 policy path").to_owned()
}

/// Load the policy example with the test ports and policy document.
fn load_jwks_policy_example(proxy_port: u16, backend_port: u16, policy_path: &str) -> Config {
    let example = example_config_path("security/policy.yaml");
    let raw = std::fs::read_to_string(&example).unwrap_or_else(|e| panic!("read {example}: {e}"));
    let with_policy = raw.replace("/etc/praxis/policy.yaml", policy_path).replace(
        "        require_protocol_metadata: true",
        "        require_protocol_metadata: true\n        allow_private_idp: true",
    );
    let patched = patch_yaml(
        &with_policy,
        proxy_port,
        &HashMap::from([("127.0.0.1:3000", backend_port)]),
    );
    Config::from_yaml(&patched).unwrap_or_else(|e| panic!("parse the JWKS policy example: {e}"))
}
