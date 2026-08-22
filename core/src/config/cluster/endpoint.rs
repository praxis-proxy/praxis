// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Upstream endpoint definition with optional weighting.

use serde::{Deserialize, Serialize};

// -----------------------------------------------------------------------------
// Endpoint
// -----------------------------------------------------------------------------

/// A single upstream endpoint, with an optional forwarding weight.
///
/// Accepts either a plain `"host:port"` string (weight defaults to 1) or an
/// object with an explicit `weight` field:
///
/// ```yaml
/// endpoints:
///   - "10.0.0.1:8080"
///   - address: "10.0.0.2:8080"
///     weight: 3
/// ```
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(untagged, try_from = "EndpointRaw")]
pub enum Endpoint {
    /// Plain `host:port` string; weight is implicitly 1.
    Simple(String),

    /// Endpoint with an explicit address and forwarding weight.
    Weighted {
        /// Socket address as `host:port`.
        address: String,

        /// Relative forwarding weight. Higher values receive proportionally more
        /// traffic. Defaults to 1.
        #[serde(default = "default_weight")]
        weight: u32,
    },
}

/// Serde default for [`Endpoint::Weighted::weight`].
fn default_weight() -> u32 {
    1
}

/// Raw deserialization target for [`Endpoint`].
///
/// The untagged enum's struct variant silently absorbs unknown keys, so a
/// typo like `wieght: 3` would parse as weight 1 with no error. The raw
/// shape collects unrecognized keys and [`TryFrom`] rejects them by name.
#[derive(Deserialize)]
#[serde(untagged)]
enum EndpointRaw {
    /// Plain `host:port` string.
    Simple(String),

    /// Endpoint object form.
    Weighted(WeightedEndpointRaw),
}

/// Object form of an endpoint, capturing unknown keys for rejection.
#[derive(Deserialize)]
struct WeightedEndpointRaw {
    /// Socket address as `host:port`.
    address: String,

    /// Relative forwarding weight.
    #[serde(default = "default_weight")]
    weight: u32,

    /// Every key not matched above; must be empty.
    #[serde(flatten)]
    unknown: std::collections::HashMap<String, serde_yaml::Value>,
}

impl TryFrom<EndpointRaw> for Endpoint {
    type Error = String;

    fn try_from(raw: EndpointRaw) -> Result<Self, Self::Error> {
        match raw {
            EndpointRaw::Simple(address) => Ok(Self::Simple(address)),
            EndpointRaw::Weighted(w) => {
                if !w.unknown.is_empty() {
                    let mut keys: Vec<&str> = w.unknown.keys().map(String::as_str).collect();
                    keys.sort_unstable();
                    return Err(format!(
                        "endpoint '{}': unknown field(s): {}; expected only 'address' and 'weight'",
                        w.address,
                        keys.join(", ")
                    ));
                }
                Ok(Self::Weighted {
                    address: w.address,
                    weight: w.weight,
                })
            },
        }
    }
}

impl Endpoint {
    /// Returns the `host:port` address string.
    ///
    /// ```
    /// use praxis_core::config::Endpoint;
    ///
    /// let simple: Endpoint = "10.0.0.1:8080".into();
    /// assert_eq!(simple.address(), "10.0.0.1:8080");
    /// ```
    pub fn address(&self) -> &str {
        match self {
            Self::Simple(s) => s,
            Self::Weighted { address, .. } => address,
        }
    }

    /// Returns the forwarding weight (1 for `Simple` endpoints).
    ///
    /// ```
    /// use praxis_core::config::Endpoint;
    ///
    /// let simple: Endpoint = "10.0.0.1:8080".into();
    /// assert_eq!(simple.weight(), 1);
    /// ```
    pub fn weight(&self) -> u32 {
        match self {
            Self::Simple(_) => 1,
            Self::Weighted { weight, .. } => *weight,
        }
    }
}

impl From<String> for Endpoint {
    fn from(s: String) -> Self {
        Self::Simple(s)
    }
}

impl From<&str> for Endpoint {
    fn from(s: &str) -> Self {
        Self::Simple(s.to_owned())
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::needless_raw_strings,
    clippy::needless_raw_string_hashes,
    reason = "tests use unwrap/expect/indexing/raw strings for brevity"
)]
mod tests {
    use super::*;

    #[test]
    fn simple_endpoint_has_weight_one() {
        let ep: Endpoint = "10.0.0.1:8080".into();
        assert_eq!(ep.address(), "10.0.0.1:8080", "simple endpoint address mismatch");
        assert_eq!(ep.weight(), 1, "simple endpoint should default to weight 1");
    }

    #[test]
    fn weighted_endpoint_preserves_weight() {
        let yaml = r#"
address: "10.0.0.2:8080"
weight: 3
"#;
        let ep: Endpoint = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(ep.address(), "10.0.0.2:8080", "weighted endpoint address mismatch");
        assert_eq!(ep.weight(), 3, "weighted endpoint should preserve configured weight");
    }

    #[test]
    fn weighted_endpoint_defaults_weight_to_one() {
        let yaml = "address: \"10.0.0.1:80\"";
        let ep: Endpoint = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(ep.weight(), 1, "omitted weight should default to 1");
    }

    #[test]
    fn from_string() {
        let ep = Endpoint::from("10.0.0.1:80".to_owned());
        assert_eq!(ep.address(), "10.0.0.1:80", "From<String> should preserve address");
    }

    #[test]
    fn parse_mixed_list() {
        let yaml = r#"
- "10.0.0.1:8080"
- address: "10.0.0.2:8080"
  weight: 3
"#;
        let eps: Vec<Endpoint> = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(eps.len(), 2, "mixed list should parse two endpoints");
        assert_eq!(eps[0].weight(), 1, "simple entry should have weight 1");
        assert_eq!(eps[1].weight(), 3, "weighted entry should have weight 3");
    }

    #[test]
    fn typoed_weight_key_rejected() {
        let yaml = "address: \"10.0.0.2:8080\"\nwieght: 3\n";
        let err = serde_yaml::from_str::<Endpoint>(yaml).unwrap_err();
        assert!(
            err.to_string().contains("wieght"),
            "a typoed weight key must be rejected by name, got: {err}"
        );
    }

    #[test]
    fn unknown_endpoint_key_rejected() {
        let yaml = "address: \"10.0.0.2:8080\"\nweight: 3\nmax_conns: 7\n";
        let err = serde_yaml::from_str::<Endpoint>(yaml).unwrap_err();
        assert!(
            err.to_string().contains("max_conns"),
            "unknown endpoint keys must be rejected by name, got: {err}"
        );
    }
}
