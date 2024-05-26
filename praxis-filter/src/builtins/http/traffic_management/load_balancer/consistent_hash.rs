//! Consistent-hash endpoint selection for session affinity.

use crate::filter::HttpFilterContext;

// ----------------------------------------------------------------------------
// ConsistentHash
// ----------------------------------------------------------------------------

/// Routes each request to the same endpoint by hashing a stable request
/// attribute.  Useful for session-affinity scenarios.
pub(super) struct ConsistentHash {
    /// Expanded endpoint list (weights applied via repetition).
    endpoints: Vec<String>,

    /// Header whose value is hashed.  Falls back to the URI path when `None`
    /// or when the header is absent from the request.
    header: Option<String>,
}

impl ConsistentHash {
    /// Create a consistent-hash selector with an optional hash-key header.
    pub(super) fn new(endpoints: Vec<String>, header: Option<String>) -> Self {
        Self { endpoints, header }
    }

    /// Hash the request key and return the corresponding endpoint.
    pub(super) fn select(&self, ctx: &HttpFilterContext<'_>) -> &str {
        debug_assert!(
            !self.endpoints.is_empty(),
            "consistent-hash requires at least one endpoint"
        );
        let key: &str = self
            .header
            .as_deref()
            .and_then(|h| ctx.request.headers.get(h))
            .and_then(|v| v.to_str().ok())
            .unwrap_or_else(|| ctx.request.uri.path());

        let idx = fnv1a(key) as usize % self.endpoints.len();

        &self.endpoints[idx]
    }
}

/// FNV-1a 64-bit hash (fast)
fn fnv1a(s: &str) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in s.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_key_same_endpoint() {
        let ch = ConsistentHash::new(vec!["10.0.0.1:80".to_string(), "10.0.0.2:80".to_string()], None);
        let req = crate::test_utils::make_request(http::Method::GET, "/stable-path");
        let ctx = crate::test_utils::make_filter_context(&req);

        let first = ch.select(&ctx).to_owned();
        let second = ch.select(&ctx).to_owned();
        assert_eq!(first, second);
    }

    #[test]
    fn different_keys_may_differ() {
        let ch = ConsistentHash::new(vec!["10.0.0.1:80".to_string(), "10.0.0.2:80".to_string()], None);
        let req_a = crate::test_utils::make_request(http::Method::GET, "/path-a");
        let ctx_a = crate::test_utils::make_filter_context(&req_a);
        let req_b = crate::test_utils::make_request(http::Method::GET, "/path-b");
        let ctx_b = crate::test_utils::make_filter_context(&req_b);

        // With two endpoints there is a reasonable chance these land on
        // different endpoints; just verify neither panics.
        let _ = ch.select(&ctx_a);
        let _ = ch.select(&ctx_b);
    }
}
