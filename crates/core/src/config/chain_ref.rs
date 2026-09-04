// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Chain reference: named or inline chain definition for branch chains.
//!
//! A branch references the filters it runs either by name, pointing at a
//! top-level `filter_chains` entry so a chain can be shared across
//! branches, or inline, embedding filters directly where reuse is not
//! needed. This is a config-time (pipelining) construct: named chains
//! are resolved and concatenated into concrete pipelines at startup, not
//! selected at request time.

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
#[derive(Clone, Debug, Deserialize, serde::Serialize)]
#[serde(untagged, try_from = "ChainRefRaw")]
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

/// Raw deserialization target for [`ChainRef`].
///
/// The untagged enum's struct variant silently absorbs unknown keys, so a
/// branch-level field (`rejoin`, `on_result`, `max_iterations`) mis-indented
/// onto an inline chain entry would be dropped without a diagnostic. The raw
/// shape collects unrecognized keys and [`TryFrom`] rejects them by name.
#[derive(Deserialize)]
#[serde(untagged)]
enum ChainRefRaw {
    /// Inline chain object form.
    Inline(InlineChainRaw),

    /// Named chain reference.
    Named(String),
}

/// Object form of an inline chain, capturing unknown keys for rejection.
#[derive(Deserialize)]
struct InlineChainRaw {
    /// Globally unique chain name.
    name: String,

    /// Ordered list of filters.
    filters: Vec<FilterEntry>,

    /// Every key not matched above; must be empty.
    #[serde(flatten)]
    unknown: std::collections::HashMap<String, serde_yaml::Value>,
}

impl TryFrom<ChainRefRaw> for ChainRef {
    type Error = String;

    fn try_from(raw: ChainRefRaw) -> Result<Self, Self::Error> {
        match raw {
            ChainRefRaw::Named(name) => Ok(Self::Named(name)),
            ChainRefRaw::Inline(inline) => {
                if !inline.unknown.is_empty() {
                    let mut keys: Vec<&str> = inline.unknown.keys().map(String::as_str).collect();
                    keys.sort_unstable();
                    return Err(format!(
                        "inline chain '{}': unknown field(s): {}; expected only 'name' and \
                         'filters' (branch-level fields like 'rejoin' belong on the branch, \
                         not the chain)",
                        inline.name,
                        keys.join(", ")
                    ));
                }
                Ok(Self::Inline {
                    name: inline.name,
                    filters: inline.filters,
                })
            },
        }
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
    clippy::panic,
    reason = "tests use unwrap/expect/indexing/raw strings for brevity"
)]
mod tests {
    use super::*;

    #[test]
    fn parse_named_ref() {
        let chain_ref: ChainRef = serde_yaml::from_str(r#""my_chain""#).unwrap();
        assert!(
            matches!(chain_ref, ChainRef::Named(s) if s == "my_chain"),
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

    #[test]
    fn inline_chain_with_misplaced_branch_field_rejected() {
        let yaml = "name: inline\nfilters:\n  - filter: router\nrejoin: next\n";
        let err = serde_yaml::from_str::<ChainRef>(yaml).unwrap_err();
        assert!(
            err.to_string().contains("rejoin"),
            "a branch-level key on an inline chain must be rejected by name, got: {err}"
        );
    }

    #[test]
    fn inline_chain_with_unknown_key_rejected() {
        let yaml = "name: inline\nfilters:\n  - filter: router\nfitlers: []\n";
        let err = serde_yaml::from_str::<ChainRef>(yaml).unwrap_err();
        assert!(
            err.to_string().contains("fitlers"),
            "typoed keys on an inline chain must be rejected by name, got: {err}"
        );
    }
}
