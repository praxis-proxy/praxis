// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

#![forbid(unsafe_code)]

//! File descriptor resilience tests (#1288).
//!
//! Every test runs the real binary under load and measures its descriptor
//! table, so they run one at a time in their own test binary: no other test
//! competes for the CPU or the socket churn they depend on.

#![allow(
    clippy::allow_attributes_without_reason,
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::cast_lossless,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::clone_on_ref_ptr,
    clippy::cognitive_complexity,
    clippy::default_trait_access,
    clippy::disallowed_methods,
    clippy::doc_markdown,
    clippy::doc_nested_refdefs,
    clippy::expect_used,
    clippy::format_push_string,
    clippy::indexing_slicing,
    clippy::iter_over_hash_type,
    clippy::items_after_statements,
    clippy::len_zero,
    clippy::manual_is_multiple_of,
    clippy::manual_let_else,
    clippy::map_unwrap_or,
    clippy::map_with_unused_argument_over_ranges,
    clippy::min_ident_chars,
    clippy::needless_raw_string_hashes,
    clippy::needless_raw_strings,
    clippy::panic,
    clippy::print_stderr,
    clippy::redundant_closure_for_method_calls,
    clippy::shadow_unrelated,
    clippy::single_char_lifetime_names,
    clippy::string_add,
    clippy::struct_field_names,
    clippy::tests_outside_test_module,
    clippy::too_many_lines,
    clippy::unwrap_used,
    clippy::used_underscore_binding,
    clippy::useless_format,
    clippy::wildcard_enum_match_arm,
    reason = "test code"
)]

#[cfg(target_os = "linux")]
mod budget;
#[cfg(target_os = "linux")]
mod pressure;

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Serializes the tests in this binary.
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Raises this binary's own open file limit once, before its first test.
#[cfg(target_os = "linux")]
static RAISE_LIMIT: std::sync::Once = std::sync::Once::new();

/// Hold for the whole test so no other test in this binary runs meanwhile.
///
/// The first call also raises this process's soft open file limit to its hard
/// limit: the load these tests drive needs a client and a backend socket per
/// request here, beyond the 1024 a runner may start the tests with.
fn serial() -> std::sync::MutexGuard<'static, ()> {
    #[cfg(target_os = "linux")]
    RAISE_LIMIT.call_once(praxis_test_utils::raise_own_open_file_limit);
    SERIAL.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}
