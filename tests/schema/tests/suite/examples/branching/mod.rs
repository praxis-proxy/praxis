// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Branching example configuration tests.

mod conditional_skip_to;
mod conditional_terminal;
mod cross_chain_flat;
mod multiple_branches;
mod named_chain_ref;
mod nested_branches;
mod reentrance;
mod unconditional_branch;

use std::collections::HashMap;

use praxis_test_utils::build_pipeline;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn all_branching_examples_parse_and_build() {
    let examples = [
        "branching/conditional-terminal.yaml",
        "branching/conditional-skip-to.yaml",
        "branching/cross-chain-flat.yaml",
        "branching/multiple-branches.yaml",
        "branching/named-chain-ref.yaml",
        "branching/nested-branches.yaml",
        "branching/reentrance.yaml",
        "branching/unconditional-branch.yaml",
    ];

    for filename in examples {
        let config =
            crate::example_utils::load_example_config(filename, 8080, HashMap::from([("127.0.0.1:3000", 3000)]));
        let pipeline = build_pipeline(&config);
        assert!(!pipeline.is_empty(), "{filename}: pipeline should not be empty");
    }
}
