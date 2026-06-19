// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Header injection, Vary handling, and Private Network Access (PNA) support.

use super::CorsFilter;
use crate::Rejection;

// -----------------------------------------------------------------------------
// Preflight Rejection Builder
// -----------------------------------------------------------------------------

/// Build a preflight 204 rejection with full CORS headers.
pub(super) fn build_preflight_rejection(
    filter: &CorsFilter,
    origin: &str,
    request: &crate::context::Request,
) -> Rejection {
    let acao = filter.acao_value(origin);

    let mut r = Rejection::status(204)
        .with_header("Access-Control-Allow-Origin", acao)
        .with_header("Access-Control-Allow-Methods", &filter.methods_header)
        .with_header("Access-Control-Max-Age", &filter.max_age_header);

    if !filter.headers_header.is_empty() {
        r = r.with_header("Access-Control-Allow-Headers", &filter.headers_header);
    }
    if filter.allow_credentials {
        r = r.with_header("Access-Control-Allow-Credentials", "true");
    }
    if filter.allow_private_network
        && request
            .headers
            .get("access-control-request-private-network")
            .is_some_and(|v| v == "true")
    {
        r = r.with_header("Access-Control-Allow-Private-Network", "true");
    }

    if filter.allow_private_network {
        r.with_header(
            "Vary",
            "Origin, Access-Control-Request-Method, Access-Control-Request-Headers, Access-Control-Request-Private-Network",
        )
    } else {
        r.with_header(
            "Vary",
            "Origin, Access-Control-Request-Method, Access-Control-Request-Headers",
        )
    }
}

// -----------------------------------------------------------------------------
// Response Header Injection
// -----------------------------------------------------------------------------

/// Inject CORS response headers for an allowed origin.
pub(super) fn inject_response_headers(filter: &CorsFilter, origin: &str, resp: &mut crate::context::Response) {
    let acao = filter.acao_value(origin);
    if let Ok(v) = acao.parse() {
        resp.headers.insert("access-control-allow-origin", v);
    }
    if filter.allow_credentials {
        resp.headers.insert(
            "access-control-allow-credentials",
            http::HeaderValue::from_static("true"),
        );
    }
    if !filter.expose_header.is_empty()
        && let Ok(v) = filter.expose_header.parse()
    {
        resp.headers.insert("access-control-expose-headers", v);
    }
    if filter.policy.needs_vary() {
        filter.append_vary(resp);
    }
}
