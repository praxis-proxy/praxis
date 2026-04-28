// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Chain reference: named or inline chain definition for branch chains.

use serde::Deserialize;

use super::filters::FilterEntry;

// -----------------------------------------------------------------------------
// ChainRef
// -----------------------------------------------------------------------------

/// A reference to a chain: named or inline.
///
/// Named references point to a top-level chain in
/// `filter_chains`. Inline definitions embed filters
/// directly in the branch configuration.
///
/// ```
/// use praxis_core::config::ChainRef;
///
/// let named: ChainRef = serde_yaml::from_str(r#""my_chain""#).unwrap();
/// assert!(matches!(named, ChainRef::Named(ref s) if s == "my_chain"));
///
/// let inline: ChainRef = serde_yaml::from_str(
///     r#"
/// name: inline_chain
/// filters:
///   - filter: headers
/// "#,
/// )
/// .unwrap();
/// assert!(matches!(inline, ChainRef::Inline { ref name, .. } if name == "inline_chain"));
/// ```
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum ChainRef {
    /// Inline chain definition.
    Inline {
        /// Globally unique chain name.
        name: String,

        /// Ordered list of filters.
        filters: Vec<FilterEntry>,
    },

    /// Reference to a top-level named chain.
    Named(String),
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::needless_raw_strings,
    clippy::needless_raw_string_hashes,
    clippy::panic,
    reason = "tests use unwrap/expect/indexing/raw strings for brevity"
)]
mod tests {
    use super::*;

    #[test]
    fn parse_named_ref() {
        let chain_ref: ChainRef = serde_yaml::from_str(r#""my_chain""#).unwrap();
        assert!(
            matches!(chain_ref, ChainRef::Named(ref s) if s == "my_chain"),
            "should parse as Named variant"
        );
    }

    #[test]
    fn parse_inline_ref() {
        let yaml = r#"
name: inline_chain
filters:
  - filter: headers
"#;
        let chain_ref: ChainRef = serde_yaml::from_str(yaml).unwrap();
        match chain_ref {
            ChainRef::Inline { name, filters } => {
                assert_eq!(name, "inline_chain", "inline chain name mismatch");
                assert_eq!(filters.len(), 1, "inline chain should have 1 filter");
            },
            ChainRef::Named(_) => panic!("should parse as Inline variant"),
        }
    }

    #[test]
    fn parse_inline_with_multiple_filters() {
        let yaml = r#"
name: multi
filters:
  - filter: headers
  - filter: cors
"#;
        let chain_ref: ChainRef = serde_yaml::from_str(yaml).unwrap();
        match chain_ref {
            ChainRef::Inline { filters, .. } => {
                assert_eq!(filters.len(), 2, "should have 2 filters");
            },
            ChainRef::Named(_) => panic!("should parse as Inline variant"),
        }
    }

    #[test]
    fn parse_named_in_sequence() {
        let yaml = r#"
- chain_a
- chain_b
"#;
        let refs: Vec<ChainRef> = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(refs.len(), 2, "should have 2 chain refs");
        assert!(
            matches!(&refs[0], ChainRef::Named(s) if s == "chain_a"),
            "first ref should be Named 'chain_a'"
        );
        assert!(
            matches!(&refs[1], ChainRef::Named(s) if s == "chain_b"),
            "second ref should be Named 'chain_b'"
        );
    }

    #[test]
    fn parse_mixed_sequence() {
        let yaml = r#"
- chain_a
- name: inline
  filters:
    - filter: router
"#;
        let refs: Vec<ChainRef> = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(refs.len(), 2, "should have 2 chain refs");
        assert!(
            matches!(&refs[0], ChainRef::Named(s) if s == "chain_a"),
            "first should be Named"
        );
        assert!(matches!(&refs[1], ChainRef::Inline { .. }), "second should be Inline");
    }
}
