//! Transport-agnostic HTTP request and response metadata.
//!
//! These types decouple filters from the underlying HTTP library
//! (e.g. Pingora, Hyper, etc) keeping the filter API portable.

use http::{HeaderMap, Method, StatusCode, Uri};

// -----------------------------------------------------------------------------
// Request
// -----------------------------------------------------------------------------

/// HTTP request metadata.
///
/// ```
/// use praxis_filter::Request;
/// use http::{Method, Uri, HeaderMap};
///
/// let req = Request {
///     method: Method::GET,
///     uri: Uri::from_static("/api/users"),
///     headers: HeaderMap::new(),
/// };
/// assert_eq!(req.uri.path(), "/api/users");
/// ```
#[derive(Debug, Clone)]

pub struct Request {
    /// HTTP header map.
    pub headers: HeaderMap,

    /// HTTP method.
    pub method: Method,

    /// Request URI.
    pub uri: Uri,
}

// -----------------------------------------------------------------------------
// Response
// -----------------------------------------------------------------------------

/// HTTP response metadata.
///
/// ```
/// use praxis_filter::Response;
/// use http::{HeaderMap, StatusCode};
///
/// let mut resp = Response {
///     status: StatusCode::OK,
///     headers: HeaderMap::new(),
/// };
/// resp.headers.insert("x-custom", "value".parse().unwrap());
/// assert_eq!(resp.status, StatusCode::OK);
/// ```
#[derive(Debug)]

pub struct Response {
    /// HTTP header map.
    pub headers: HeaderMap,

    /// HTTP status code.
    pub status: StatusCode,
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_fields_are_accessible() {
        let req = Request {
            method: Method::POST,
            uri: "/submit".parse().unwrap(),
            headers: HeaderMap::new(),
        };
        assert_eq!(req.method, Method::POST);
        assert_eq!(req.uri.path(), "/submit");
        assert!(req.headers.is_empty());
    }

    #[test]
    fn response_header_mutation() {
        let mut resp = Response {
            status: StatusCode::OK,
            headers: HeaderMap::new(),
        };
        resp.headers.insert("x-powered-by", "praxis".parse().unwrap());
        assert_eq!(resp.headers["x-powered-by"], "praxis");
    }

    #[test]
    fn response_status_codes() {
        for code in [200u16, 404, 500] {
            let resp = Response {
                status: StatusCode::from_u16(code).unwrap(),
                headers: HeaderMap::new(),
            };
            assert_eq!(resp.status.as_u16(), code);
        }
    }
}
