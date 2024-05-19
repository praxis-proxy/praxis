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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]

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
mod tests {
    use super::*;

    #[test]
    fn simple_endpoint_has_weight_one() {
        let ep: Endpoint = "10.0.0.1:8080".into();
        assert_eq!(ep.address(), "10.0.0.1:8080");
        assert_eq!(ep.weight(), 1);
    }

    #[test]
    fn weighted_endpoint_preserves_weight() {
        let yaml = r#"
address: "10.0.0.2:8080"
weight: 3
"#;
        let ep: Endpoint = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(ep.address(), "10.0.0.2:8080");
        assert_eq!(ep.weight(), 3);
    }

    #[test]
    fn weighted_endpoint_defaults_weight_to_one() {
        let yaml = "address: \"10.0.0.1:80\"";
        let ep: Endpoint = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(ep.weight(), 1);
    }

    #[test]
    fn from_string() {
        let ep = Endpoint::from("10.0.0.1:80".to_owned());
        assert_eq!(ep.address(), "10.0.0.1:80");
    }

    #[test]
    fn parse_mixed_list() {
        let yaml = r#"
- "10.0.0.1:8080"
- address: "10.0.0.2:8080"
  weight: 3
"#;
        let eps: Vec<Endpoint> = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(eps.len(), 2);
        assert_eq!(eps[0].weight(), 1);
        assert_eq!(eps[1].weight(), 3);
    }
}
