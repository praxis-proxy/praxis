// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Long request Via chains are preserved and extended at the forwarding boundary.

use praxis_core::config::Config;
use praxis_test_utils::{
    free_port, parse_body, parse_status, simple_proxy_yaml, start_header_echo_backend, start_proxy,
};

#[test]
fn long_request_via_chain_preserved_and_extended() {
    let backend = start_header_echo_backend();
    let config = Config::from_yaml(&simple_proxy_yaml(free_port(), backend.port())).unwrap();
    let proxy = start_proxy(&config);
    let incoming = (0..64)
        .map(|index| format!("1.1 hop{index}.example"))
        .collect::<Vec<_>>()
        .join(", ");
    let request = format!("GET / HTTP/1.1\r\nHost: localhost\r\nVia: {incoming}\r\nConnection: close\r\n\r\n");
    let raw = super::test_utils::send_text(proxy.addr(), &request);
    assert_eq!(parse_status(&raw), 200, "long Via chain must reach the backend");
    let body = parse_body(&raw);
    let forwarded = body
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("via").then(|| value.trim())
        })
        .expect("backend must receive Via");
    assert_eq!(
        forwarded,
        format!("{incoming}, 1.1 praxis"),
        "preserve all entries and append exactly one proxy hop"
    );
    assert_eq!(
        forwarded.split(',').count(),
        65,
        "every incoming hop must survive forwarding"
    );
}
