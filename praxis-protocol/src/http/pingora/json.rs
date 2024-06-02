//! Utility for building JSON HTTP responses.

use http::Response;

// -----------------------------------------------------------------------------
// JSON
// -----------------------------------------------------------------------------

/// Build an HTTP response with `Content-Type: application/json`.
pub(crate) fn json_response(status: u16, body: &'static [u8]) -> Response<Vec<u8>> {
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(body.to_vec())
        .expect("valid json response")
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sets_status_code() {
        let resp = json_response(200, b"{}");
        assert_eq!(resp.status().as_u16(), 200);
    }

    #[test]
    fn sets_body() {
        let body = b"{\"key\":\"value\"}";
        let resp = json_response(200, body);
        assert_eq!(resp.body(), body);
    }
}
