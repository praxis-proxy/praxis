//! Consistent-hash endpoint selection for session affinity.

use std::sync::Arc;

use praxis_core::health::ClusterHealthState;

use super::WeightedEndpoint;
use crate::context::HttpFilterContext;

// -----------------------------------------------------------------------------
// ConsistentHash
// -----------------------------------------------------------------------------

/// Routes each request to the same endpoint by hashing a stable request
/// attribute. Virtual nodes are proportional to endpoint weight.
pub(super) struct ConsistentHash {
    /// Deduplicated endpoint list with weights and original indices.
    endpoints: Vec<WeightedEndpoint>,

    /// Virtual-node ring: each entry is an index into `endpoints`.
    /// Built by expanding each endpoint proportionally to its weight.
    ring: Vec<usize>,

    /// Header whose value is hashed. Falls back to the URI path when `None`
    /// or when the header is absent from the request.
    header: Option<String>,
}

impl ConsistentHash {
    /// Create a consistent-hash selector with weight-proportional virtual nodes.
    pub(super) fn new(endpoints: Vec<WeightedEndpoint>, header: Option<String>) -> Self {
        let ring: Vec<usize> = endpoints
            .iter()
            .enumerate()
            .flat_map(|(i, ep)| std::iter::repeat_n(i, ep.weight as usize))
            .collect();
        debug_assert!(!ring.is_empty(), "consistent-hash requires at least one endpoint");
        Self {
            endpoints,
            ring,
            header,
        }
    }

    /// Hash the request key and return the corresponding healthy endpoint.
    ///
    /// Skips unhealthy endpoints by probing adjacent ring slots, falling
    /// back to the original selection if all are unhealthy.
    pub(super) fn select(&self, ctx: &HttpFilterContext<'_>, health: Option<&ClusterHealthState>) -> Arc<str> {
        let key: &str = self
            .header
            .as_deref()
            .and_then(|h| ctx.request.headers.get(h))
            .and_then(|v| v.to_str().ok())
            .unwrap_or_else(|| ctx.request.uri.path());

        let len = self.ring.len();
        let start = fnv1a(key) as usize % len;

        if let Some(state) = health {
            for offset in 0..len {
                let ring_idx = (start + offset) % len;
                let ep = &self.endpoints[self.ring[ring_idx]];
                if ep.index < state.len() && state[ep.index].is_healthy() {
                    return Arc::clone(&ep.address);
                }
            }
        }

        Arc::clone(&self.endpoints[self.ring[start]].address)
    }
}

/// FNV-1a 64-bit hash (fast).
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
    use std::sync::Arc;

    use praxis_core::health::EndpointHealth;

    use super::*;

    #[test]
    fn same_key_same_endpoint() {
        let ch = ConsistentHash::new(
            vec![
                WeightedEndpoint {
                    address: Arc::from("10.0.0.1:80"),
                    weight: 1,
                    index: 0,
                },
                WeightedEndpoint {
                    address: Arc::from("10.0.0.2:80"),
                    weight: 1,
                    index: 1,
                },
            ],
            None,
        );
        let req = crate::test_utils::make_request(http::Method::GET, "/stable-path");
        let ctx = crate::test_utils::make_filter_context(&req);

        let first = ch.select(&ctx, None);
        let second = ch.select(&ctx, None);
        assert_eq!(first, second, "same key should always select same endpoint");
    }

    #[test]
    fn different_keys_select_different_endpoints() {
        let ch = ConsistentHash::new(
            vec![
                WeightedEndpoint {
                    address: Arc::from("10.0.0.1:80"),
                    weight: 1,
                    index: 0,
                },
                WeightedEndpoint {
                    address: Arc::from("10.0.0.2:80"),
                    weight: 1,
                    index: 1,
                },
            ],
            None,
        );
        let req_a = crate::test_utils::make_request(http::Method::GET, "/path-a");
        let ctx_a = crate::test_utils::make_filter_context(&req_a);
        let req_b = crate::test_utils::make_request(http::Method::GET, "/path-b");
        let ctx_b = crate::test_utils::make_filter_context(&req_b);

        let ep_a = ch.select(&ctx_a, None);
        let ep_b = ch.select(&ctx_b, None);
        assert_ne!(
            ep_a, ep_b,
            "FNV-1a of /path-a and /path-b should not collide with only 2 endpoints"
        );
    }

    #[test]
    fn header_based_hashing_different_values_route_differently() {
        let endpoints: Vec<WeightedEndpoint> = (0..10)
            .map(|i| WeightedEndpoint {
                address: Arc::from(format!("10.0.0.{i}:80").as_str()),
                weight: 1,
                index: i,
            })
            .collect();
        let ch = ConsistentHash::new(endpoints, Some("X-User-Id".to_string()));
        let req_a = make_request_with_header("/same", "X-User-Id", "user-alice");
        let ctx_a = crate::test_utils::make_filter_context(&req_a);
        let req_b = make_request_with_header("/same", "X-User-Id", "user-bob");
        let ctx_b = crate::test_utils::make_filter_context(&req_b);
        let ep_a = ch.select(&ctx_a, None);
        let ep_b = ch.select(&ctx_b, None);
        assert_ne!(ep_a, ep_b, "different header values should map to different endpoints");
    }

    #[test]
    fn header_based_hashing_same_value_same_endpoint() {
        let endpoints = vec![
            WeightedEndpoint {
                address: Arc::from("10.0.0.1:80"),
                weight: 1,
                index: 0,
            },
            WeightedEndpoint {
                address: Arc::from("10.0.0.2:80"),
                weight: 1,
                index: 1,
            },
        ];
        let ch = ConsistentHash::new(endpoints, Some("X-User-Id".to_string()));
        let req_a = make_request_with_header("/a", "X-User-Id", "user-42");
        let ctx_a = crate::test_utils::make_filter_context(&req_a);
        let req_b = make_request_with_header("/b", "X-User-Id", "user-42");
        let ctx_b = crate::test_utils::make_filter_context(&req_b);
        assert_eq!(
            ch.select(&ctx_a, None),
            ch.select(&ctx_b, None),
            "same header value should always route to same endpoint"
        );
    }

    #[test]
    fn missing_header_falls_back_to_uri_path() {
        let eps = || {
            vec![
                WeightedEndpoint {
                    address: Arc::from("10.0.0.1:80"),
                    weight: 1,
                    index: 0,
                },
                WeightedEndpoint {
                    address: Arc::from("10.0.0.2:80"),
                    weight: 1,
                    index: 1,
                },
            ]
        };
        let ch = ConsistentHash::new(eps(), Some("X-User-Id".to_string()));
        let ch_path = ConsistentHash::new(eps(), None);
        let req = crate::test_utils::make_request(http::Method::GET, "/fallback-path");
        let ctx = crate::test_utils::make_filter_context(&req);
        assert_eq!(
            ch.select(&ctx, None),
            ch_path.select(&ctx, None),
            "missing header should fall back to URI path hashing"
        );
    }

    #[test]
    fn stability_across_repeated_calls() {
        let endpoints: Vec<WeightedEndpoint> = (0..5)
            .map(|i| WeightedEndpoint {
                address: Arc::from(format!("10.0.0.{i}:80").as_str()),
                weight: 1,
                index: i,
            })
            .collect();
        let ch = ConsistentHash::new(endpoints, None);

        let paths = ["/api/v1/users", "/checkout", "/search?q=rust", "/", "/health"];
        for path in &paths {
            let req = crate::test_utils::make_request(http::Method::GET, path);
            let ctx = crate::test_utils::make_filter_context(&req);
            let first = ch.select(&ctx, None);
            for call in 1..=100 {
                let ctx = crate::test_utils::make_filter_context(&req);
                assert_eq!(
                    ch.select(&ctx, None),
                    first,
                    "path {path} must map to the same endpoint on call {call}"
                );
            }
        }
    }

    #[test]
    fn add_endpoint_redistribution() {
        let original: Vec<WeightedEndpoint> = (0..3)
            .map(|i| WeightedEndpoint {
                address: Arc::from(format!("10.0.0.{i}:80").as_str()),
                weight: 1,
                index: i,
            })
            .collect();
        let mut expanded = original.clone();
        expanded.push(WeightedEndpoint {
            address: Arc::from("10.0.0.3:80"),
            weight: 1,
            index: 3,
        });

        let ch_original = ConsistentHash::new(original, None);
        let ch_expanded = ConsistentHash::new(expanded, None);

        let keys: Vec<String> = (0..200).map(|i| format!("/key-{i}")).collect();

        let mut stable_count = 0usize;
        for key in &keys {
            let req = crate::test_utils::make_request(http::Method::GET, key);
            let ctx = crate::test_utils::make_filter_context(&req);
            let before = ch_original.select(&ctx, None);
            let ctx = crate::test_utils::make_filter_context(&req);
            let after = ch_expanded.select(&ctx, None);
            if before == after {
                stable_count += 1;
            }
        }

        assert!(
            stable_count > 0,
            "at least some keys should remain on the same endpoint after adding one"
        );
        assert!(
            stable_count < keys.len(),
            "not all keys should stay on the same endpoint when the modulus changes from 3 to 4"
        );

        let disruption_ratio = 1.0 - (stable_count as f64 / keys.len() as f64);
        assert!(
            disruption_ratio > 0.5,
            "modulo-based hashing should disrupt most keys when adding an endpoint \
             (disruption={disruption_ratio:.3}, stable={stable_count}/{})",
            keys.len()
        );
    }

    #[test]
    fn remove_endpoint_redistribution() {
        let original: Vec<WeightedEndpoint> = (0..4)
            .map(|i| WeightedEndpoint {
                address: Arc::from(format!("10.0.0.{i}:80").as_str()),
                weight: 1,
                index: i,
            })
            .collect();
        let reduced: Vec<WeightedEndpoint> = original[..3].to_vec();
        let original_addrs: Vec<Arc<str>> = original.iter().map(|ep| Arc::clone(&ep.address)).collect();

        let ch_original = ConsistentHash::new(original, None);
        let ch_reduced = ConsistentHash::new(reduced.clone(), None);

        let keys: Vec<String> = (0..200).map(|i| format!("/path-{i}")).collect();

        let mut stable_count = 0usize;
        let mut moved_to_valid = 0usize;
        let removed = &original_addrs[3];
        let reduced_addrs: Vec<Arc<str>> = reduced.iter().map(|ep| Arc::clone(&ep.address)).collect();

        for key in &keys {
            let req = crate::test_utils::make_request(http::Method::GET, key);
            let ctx = crate::test_utils::make_filter_context(&req);
            let before = ch_original.select(&ctx, None);
            let ctx = crate::test_utils::make_filter_context(&req);
            let after = ch_reduced.select(&ctx, None);

            assert_ne!(
                &*after, &**removed,
                "key {key} must not map to removed endpoint {removed}"
            );

            if before == after {
                stable_count += 1;
            }

            if reduced_addrs.contains(&after) {
                moved_to_valid += 1;
            }
        }

        assert_eq!(moved_to_valid, keys.len(), "every key must map to a surviving endpoint");
        assert!(
            stable_count > 0,
            "at least some keys should remain stable after removing an endpoint"
        );
        assert!(
            stable_count < keys.len(),
            "not all keys can stay on the same endpoint when modulus shrinks from 4 to 3"
        );
    }

    #[test]
    fn weight_stability() {
        let endpoints = vec![
            WeightedEndpoint {
                address: Arc::from("10.0.0.1:80"),
                weight: 3,
                index: 0,
            },
            WeightedEndpoint {
                address: Arc::from("10.0.0.2:80"),
                weight: 1,
                index: 1,
            },
        ];
        let ch = ConsistentHash::new(endpoints, None);

        let keys: Vec<String> = (0..300).map(|i| format!("/weighted-{i}")).collect();

        let mut ep1_count = 0usize;
        let mut ep2_count = 0usize;

        for key in &keys {
            let req = crate::test_utils::make_request(http::Method::GET, key);
            let ctx = crate::test_utils::make_filter_context(&req);
            let selected = ch.select(&ctx, None);

            let req2 = crate::test_utils::make_request(http::Method::GET, key);
            let ctx2 = crate::test_utils::make_filter_context(&req2);
            assert_eq!(
                ch.select(&ctx2, None),
                selected,
                "weighted hashing must be deterministic for key {key}"
            );

            match &*selected {
                "10.0.0.1:80" => ep1_count += 1,
                "10.0.0.2:80" => ep2_count += 1,
                other => panic!("unexpected endpoint {other}"),
            }
        }

        let ep1_ratio = ep1_count as f64 / keys.len() as f64;
        let expected_ep1_ratio = 0.75;
        let tolerance = 0.10;
        assert!(
            (ep1_ratio - expected_ep1_ratio).abs() < tolerance,
            "endpoint 10.0.0.1 ratio {ep1_ratio:.3} should be near {expected_ep1_ratio} \
             (ep1={ep1_count}, ep2={ep2_count}, tolerance={tolerance})"
        );
    }

    #[test]
    fn weight_stability_selection_unchanged_across_calls() {
        let endpoints = vec![
            WeightedEndpoint {
                address: Arc::from("10.0.0.1:80"),
                weight: 2,
                index: 0,
            },
            WeightedEndpoint {
                address: Arc::from("10.0.0.2:80"),
                weight: 2,
                index: 1,
            },
            WeightedEndpoint {
                address: Arc::from("10.0.0.3:80"),
                weight: 1,
                index: 2,
            },
        ];
        let ch = ConsistentHash::new(endpoints, None);

        let keys: Vec<String> = (0..50).map(|i| format!("/stable-weight-{i}")).collect();
        let mut selections: Vec<Arc<str>> = Vec::with_capacity(keys.len());

        for key in &keys {
            let req = crate::test_utils::make_request(http::Method::GET, key);
            let ctx = crate::test_utils::make_filter_context(&req);
            selections.push(ch.select(&ctx, None));
        }

        for round in 1..=10 {
            for (i, key) in keys.iter().enumerate() {
                let req = crate::test_utils::make_request(http::Method::GET, key);
                let ctx = crate::test_utils::make_filter_context(&req);
                assert_eq!(
                    ch.select(&ctx, None),
                    selections[i],
                    "key {key} changed endpoint on round {round}"
                );
            }
        }
    }

    #[test]
    fn skips_unhealthy() {
        let ch = ConsistentHash::new(
            vec![
                WeightedEndpoint {
                    address: Arc::from("10.0.0.1:80"),
                    weight: 1,
                    index: 0,
                },
                WeightedEndpoint {
                    address: Arc::from("10.0.0.2:80"),
                    weight: 1,
                    index: 1,
                },
                WeightedEndpoint {
                    address: Arc::from("10.0.0.3:80"),
                    weight: 1,
                    index: 2,
                },
            ],
            None,
        );
        let state: ClusterHealthState = Arc::new(vec![
            EndpointHealth::new(),
            EndpointHealth::new(),
            EndpointHealth::new(),
        ]);
        state[1].mark_unhealthy();

        let paths = ["/a", "/b", "/c", "/d", "/e", "/f", "/g", "/h"];
        for path in &paths {
            let req = crate::test_utils::make_request(http::Method::GET, path);
            let ctx = crate::test_utils::make_filter_context(&req);
            let selected = ch.select(&ctx, Some(&state));
            assert_ne!(
                &*selected, "10.0.0.2:80",
                "unhealthy endpoint should never be selected for path {path}"
            );
        }
    }

    #[test]
    fn panic_mode_when_all_unhealthy() {
        let ch = ConsistentHash::new(
            vec![
                WeightedEndpoint {
                    address: Arc::from("10.0.0.1:80"),
                    weight: 1,
                    index: 0,
                },
                WeightedEndpoint {
                    address: Arc::from("10.0.0.2:80"),
                    weight: 1,
                    index: 1,
                },
            ],
            None,
        );
        let state: ClusterHealthState = Arc::new(vec![EndpointHealth::new(), EndpointHealth::new()]);
        state[0].mark_unhealthy();
        state[1].mark_unhealthy();

        let req = crate::test_utils::make_request(http::Method::GET, "/panic");
        let ctx = crate::test_utils::make_filter_context(&req);
        let selected = ch.select(&ctx, Some(&state));
        assert!(
            &*selected == "10.0.0.1:80" || &*selected == "10.0.0.2:80",
            "panic mode should still return an endpoint, got: {selected}"
        );
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// Build a [`Request`] with a single custom header attached.
    ///
    /// [`Request`]: crate::Request
    fn make_request_with_header(path: &str, header: &str, value: &str) -> crate::Request {
        let mut req = crate::test_utils::make_request(http::Method::GET, path);
        req.headers.insert(
            http::header::HeaderName::from_bytes(header.as_bytes()).unwrap(),
            http::header::HeaderValue::from_str(value).unwrap(),
        );
        req
    }
}
