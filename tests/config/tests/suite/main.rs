//! Configuration test suite for Praxis.
//!
//! Combines config validation (parsing and rejection of invalid
//! YAML) with example config tests (loading real example configs
//! and verifying runtime behavior).

mod common;
mod example_utils;
mod examples;
mod test_utils;

mod cluster;
mod cross_cutting;
mod edge_cases;
mod filter_chain;
mod listener;
mod route;
