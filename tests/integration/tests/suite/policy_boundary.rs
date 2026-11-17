// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Wire regressions for inference output policy at the response boundary.

use std::{
    io::{BufReader, Write as _},
    net::TcpStream,
    sync::mpsc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use openssl::{hash::MessageDigest, pkey::PKey, sign::Signer};
use pingora_core::protocols::http::compression::Algorithm;
use praxis_core::config::Config;
use praxis_test_utils::{H1Completion, bind_unique_port, free_port, read_h1_response, start_proxy};

const SECRET: &str = "REPLACE-WITH-A-PROPERLY-RANDOM-SHARED-SECRET-DO-NOT-COMMIT";
const REQUEST_BODY: &str = r#"{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}"#;
#[cfg(feature = "pingora")]
const FORBIDDEN_COMPLETION: &str =
    "SENTINEL with enough room for a fitted denial envelope in the final JSON completion";

/// Create the signed bearer token used by the local policy fixture.
fn bearer_token() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs();
    let claims = serde_json::json!({
        "iss":"https://idp.example.com","aud":"praxis-policy-example","sub":"agent",
        "iat":now,"exp":now + 300
    });
    let header = serde_json::json!({"alg":"HS256","typ":"JWT"});
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    );
    let key = PKey::hmac(SECRET.as_bytes()).expect("HMAC key");
    let mut signer = Signer::new(MessageDigest::sha256(), &key).expect("HMAC signer");
    signer.update(input.as_bytes()).expect("signing input");
    format!(
        "{input}.{}",
        URL_SAFE_NO_PAD.encode(signer.sign_to_vec().expect("signature"))
    )
}

/// Write an admitted inference policy with one response rule.
fn policy_file(rule: &str) -> (tempfile::TempDir, String) {
    let dir = tempfile::TempDir::new().expect("policy directory");
    let path = dir.path().join("policy.yaml");
    let yaml = format!(
        "plugins:\n  - name: jwt-user\n    kind: identity/jwt\n    hooks:\n      - identity.resolve\n    on_error: fail\n    config:\n      header: Authorization\n      trusted_issuers:\n        - issuer: https://idp.example.com\n          audiences: [praxis-policy-example]\n          algorithms: [HS256]\n          decoding_key:\n            kind: secret\n            secret: {SECRET}\n          leeway_seconds: 60\n      claim_mapper: standard\nglobal:\n  authentication:\n    - jwt-user\nroutes:\n  - llm: \"*\"\n    authorization:\n      pre_invocation:\n        - \"require(authenticated)\"\n      post_invocation:\n        - \"{rule}\"\n"
    );
    std::fs::write(&path, yaml).expect("write policy");
    (dir, path.to_str().expect("UTF-8 path").to_owned())
}

/// Build a one-upstream proxy with buffered response policy.
fn proxy_config(proxy_port: u16, backend_port: u16, policy: &str) -> Config {
    let yaml = format!(
        "listeners:\n  - name: default\n    address: 127.0.0.1:{proxy_port}\n    filter_chains: [main]\nfilter_chains:\n  - name: main\n    filters:\n      - filter: policy\n        config_path: {policy}\n        body_access: read_write\n        llm:\n          require_model: true\n      - filter: router\n        routes:\n          - path_prefix: /v1/\n            cluster: inference\n      - filter: load_balancer\n        clusters:\n          - name: inference\n            endpoints: [\"127.0.0.1:{backend_port}\"]\ninsecure_options:\n  allow_private_endpoints: true\n"
    );
    Config::from_yaml(&yaml).expect("proxy config")
}

/// Send one admitted HTTP/1 request and collect the complete response.
fn request_response(addr: &str) -> (praxis_test_utils::H1Response, Vec<u8>) {
    let token = bearer_token();
    let mut stream = TcpStream::connect(addr).expect("proxy connection");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("read timeout");
    write!(stream, "POST /v1/chat/completions HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{REQUEST_BODY}", REQUEST_BODY.len()).expect("send request");
    let mut body = Vec::new();
    let response = read_h1_response(&mut BufReader::new(stream), false, 1_048_576, |part| {
        body.extend_from_slice(part);
        Ok(())
    });
    (response, body)
}

/// Whether the wire response carries a named header value.
fn has_header(response: &praxis_test_utils::H1Response, name: &str, value: &str) -> bool {
    response
        .headers
        .iter()
        .any(|(header, field)| header == name && field == value)
}

/// Release a gated SSE backend even if an assertion exits the test early.
struct SseRelease(Option<mpsc::Sender<()>>);

impl SseRelease {
    /// Send the normal release signal once.
    fn release(&mut self) {
        if let Some(sender) = self.0.take() {
            let _sent = sender.send(());
        }
    }
}

impl Drop for SseRelease {
    fn drop(&mut self) {
        self.release();
    }
}

#[test]
fn encoded_completion_denial_has_plaintext_headers() {
    let (_dir, policy) = policy_file("authenticated: deny('withheld', 'output_withheld')");
    let (listener, backend_port) = bind_unique_port();
    let backend = std::thread::spawn(move || {
        for original in [&br#"{"choices":[{"message":{"content":"SENTINEL"}}]}"#[..], &b"0"[..]] {
            let encoded = Algorithm::Gzip
                .compressor(1)
                .expect("gzip compressor")
                .encode(original, true)
                .expect("gzip bytes");
            let (mut stream, _) = listener.accept().expect("backend accept");
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .expect("backend timeout");
            praxis_test_utils::read_http_request(&mut stream);
            write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", encoded.len()).expect("response head");
            stream.write_all(&encoded).expect("response body");
        }
    });
    let proxy = start_proxy(&proxy_config(free_port(), backend_port, &policy));
    for case in ["ordinary completion", "tiny scalar"] {
        let (response, body) = request_response(proxy.addr());
        assert_eq!(response.status, Some(403), "{case}: local reject: {response:?}");
        assert_eq!(
            response.completion,
            Some(H1Completion::ContentLength),
            "{case}: complete denial"
        );
        assert_eq!(response.abort, None, "{case}: readable denial");
        assert!(
            has_header(&response, "content-type", "application/json"),
            "{case}: JSON denial"
        );
        assert!(
            !response.headers.iter().any(|(name, _)| name == "content-encoding"),
            "{case}: plaintext denial has no gzip label",
        );
        let parsed: serde_json::Value = serde_json::from_slice(&body).expect("complete denial JSON");
        assert_eq!(parsed["error"]["code"], "llm.response_unreadable", "{case}");
        assert!(
            !body.windows(8).any(|part| part == b"SENTINEL"),
            "{case}: provider content hidden"
        );
    }
    backend.join().expect("backend thread");
}

#[test]
fn declared_json_suffix_denies_unreadable_completion_on_the_wire() {
    let (_dir, policy) = policy_file("authenticated: deny('withheld', 'output_withheld')");
    let (listener, backend_port) = bind_unique_port();
    let malformed = b"{\"choices\":[{\"message\":{\"content\":\"SENTINEL with enough room for a fitted denial envelope from the response body\"}}],\"broken\":";
    let opaque = b"opaque provider response";
    let backend = std::thread::spawn(move || {
        for (content_type, body) in [
            ("application/problem+json", malformed.as_slice()),
            ("audio/mpeg", opaque.as_slice()),
        ] {
            let (mut stream, _) = listener.accept().expect("backend accept");
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .expect("backend timeout");
            praxis_test_utils::read_http_request(&mut stream);
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .expect("response head");
            stream.write_all(body).expect("response body");
        }
    });
    let proxy = start_proxy(&proxy_config(free_port(), backend_port, &policy));
    let (response, body) = request_response(proxy.addr());
    assert_eq!(
        response.status,
        Some(200),
        "response body denial keeps committed status"
    );
    assert_eq!(response.completion, Some(H1Completion::ContentLength));
    assert_eq!(body.len(), malformed.len(), "committed length remains valid");
    assert!(!body.windows(8).any(|part| part == b"SENTINEL"));
    let denial: serde_json::Value = serde_json::from_slice(&body).expect("fitted denial JSON");
    assert_eq!(denial["error"]["code"], "llm.response_unreadable");

    let (response, body) = request_response(proxy.addr());
    assert_eq!(response.status, Some(200));
    assert_eq!(response.completion, Some(H1Completion::ContentLength));
    assert_eq!(
        body.as_slice(),
        opaque.as_slice(),
        "opaque response remains outside JSON inspection"
    );
    backend.join().expect("backend thread");
}

#[test]
fn final_sse_completion_releases_the_first_event_before_upstream_eof() {
    let (_dir, policy) = policy_file("authenticated: deny('withheld', 'output_withheld')");
    let (listener, backend_port) = bind_unique_port();
    let (first_sent, first_ready) = mpsc::channel();
    let (release, release_rx) = mpsc::channel();
    let mut release = SseRelease(Some(release));
    let backend = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("backend accept");
        praxis_test_utils::read_http_request(&mut stream);
        let first = b"data: first\n\n";
        write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:X}\r\n", first.len()).expect("SSE head");
        stream.write_all(first).expect("first event");
        stream.write_all(b"\r\n").expect("chunk ending");
        stream.flush().expect("flush first event");
        first_sent.send(()).expect("first event signal");
        release_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("release final event");
        let last = b"data: SENTINEL\n\n";
        write!(stream, "{:X}\r\n", last.len()).expect("last chunk size");
        stream.write_all(last).expect("last event");
        stream.write_all(b"\r\n0\r\n\r\n").expect("SSE EOF");
    });
    let proxy = start_proxy(&proxy_config(free_port(), backend_port, &policy));
    let (part_tx, part_rx) = mpsc::channel();
    let addr = proxy.addr().to_owned();
    let reader = std::thread::spawn(move || {
        let token = bearer_token();
        let mut stream = TcpStream::connect(&addr).expect("proxy connection");
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("read timeout");
        write!(stream, "POST /v1/chat/completions HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{REQUEST_BODY}", REQUEST_BODY.len()).expect("send request");
        let mut body = Vec::new();
        let response = read_h1_response(&mut BufReader::new(stream), false, 1_048_576, |part| {
            body.extend_from_slice(part);
            part_tx.send(part.to_vec()).expect("stream observation");
            Ok(())
        });
        (response, body)
    });
    first_ready
        .recv_timeout(Duration::from_secs(10))
        .expect("backend wrote first event");
    let expected = b"data: first\n\n";
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut observed = Vec::new();
    while observed.len() < expected.len() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        assert!(
            !remaining.is_zero(),
            "first SSE event must reach client before backend EOF"
        );
        let part = part_rx
            .recv_timeout(remaining)
            .expect("first SSE event must reach client before backend EOF");
        observed.extend_from_slice(&part);
        assert!(
            expected.starts_with(&observed),
            "the first streamed bytes must be the first SSE event: {observed:?}"
        );
    }
    assert_eq!(observed, expected);
    release.release();
    let (response, body) = reader.join().expect("response reader");
    assert_eq!(response.status, Some(200));
    assert_eq!(response.completion, Some(H1Completion::Chunked));
    assert_eq!(body, b"data: first\n\ndata: SENTINEL\n\n");
    backend.join().expect("backend thread");
}

#[cfg(feature = "pingora")]
#[test]
fn early_hints_cannot_disable_completion_policy() {
    let rule = format!("result == '{FORBIDDEN_COMPLETION}': deny('withheld', 'output_withheld')");
    let (_dir, policy) = policy_file(&rule);
    let (listener, backend_port) = bind_unique_port();
    let (first_sent, first_ready) = mpsc::channel();
    let (release, release_rx) = mpsc::channel();
    let original = format!(r#"{{"choices":[{{"message":{{"content":"{FORBIDDEN_COMPLETION}"}}}}]}}"#);
    let backend = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("backend accept");
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("backend timeout");
        praxis_test_utils::read_http_request(&mut stream);
        write!(stream, "HTTP/1.1 103 Early Hints\r\nContent-Type: text/event-stream\r\n\r\nHTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:X}\r\n", original.len()).expect("final head");
        stream.write_all(original.as_bytes()).expect("first body chunk");
        stream.write_all(b"\r\n").expect("chunk trailer");
        stream.flush().expect("flush first chunk");
        first_sent.send(()).expect("signal first chunk");
        release_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("release final chunk");
        stream.write_all(b"0\r\n\r\n").expect("terminating chunk");
        let (mut clean_stream, _) = listener.accept().expect("clean accept");
        praxis_test_utils::read_http_request(&mut clean_stream);
        let clean = br#"{"choices":[{"message":{"content":"clean"}}]}"#;
        write!(
            clean_stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            clean.len()
        )
        .expect("clean head");
        clean_stream.write_all(clean).expect("clean body");
    });
    let proxy = start_proxy(&proxy_config(free_port(), backend_port, &policy));
    let (body_tx, body_rx) = mpsc::channel();
    let addr = proxy.addr().to_owned();
    let reader = std::thread::spawn(move || {
        let token = bearer_token();
        let mut stream = TcpStream::connect(&addr).expect("proxy connection");
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("read timeout");
        write!(stream, "POST /v1/chat/completions HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{REQUEST_BODY}", REQUEST_BODY.len()).expect("send request");
        let mut body = Vec::new();
        let response = read_h1_response(&mut BufReader::new(stream), false, 1_048_576, |part| {
            body.extend_from_slice(part);
            body_tx.send(part.to_vec()).expect("body observation");
            Ok(())
        });
        (response, body)
    });
    first_ready
        .recv_timeout(Duration::from_secs(10))
        .expect("upstream first chunk");
    assert!(
        matches!(
            body_rx.recv_timeout(Duration::from_millis(500)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ),
        "no JSON bytes may release before EOF",
    );
    release.send(()).expect("release upstream terminator");
    let (response, body) = reader.join().expect("response reader");
    assert_eq!(
        response.interim_statuses,
        vec![103],
        "Early Hints must traverse Pingora"
    );
    assert_eq!(response.status, Some(200));
    assert!(response.completion.is_some(), "denial body must finish");
    assert!(
        !body.windows(8).any(|part| part == b"SENTINEL"),
        "forbidden bytes reached the client"
    );
    let denied: serde_json::Value = serde_json::from_slice(&body).expect("fitted policy denial");
    assert_eq!(denied["error"]["code"], "output_withheld");
    let (clean_response, clean_body) = request_response(proxy.addr());
    assert_eq!(clean_response.status, Some(200));
    assert_eq!(
        clean_body, br#"{"choices":[{"message":{"content":"clean"}}]}"#,
        "ordinary JSON remains intact"
    );
    backend.join().expect("backend thread");
}
