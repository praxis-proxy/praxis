// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Programmatic JSON Pointer extract/add/replace/remove.
//!
//! One tokenizer walk copies unused subtrees as byte spans. YAML
//! [`JsonBodyFilter`](crate::builtins::JsonBodyFilter) compiles through the same builder.
//!
//! ```
//! use praxis_filter::json_ops::{ExtractDest, JsonOps, JsonValue};
//! use serde_json::json;
//!
//! let ops = JsonOps::builder()
//!     .extract("/model", ExtractDest::metadata("original.model"))?
//!     .add("/tenant", JsonValue::static_json(json!("acme"))?)?
//!     .add("/original_model", JsonValue::metadata("original.model"))?
//!     .remove("/password")?
//!     .replace("/model", JsonValue::static_json(json!("forced"))?)?
//!     .build()?;
//!
//! let body = br#"{"model":"old","password":"x"}"#;
//! let rewrite = ops.apply(body, None)?;
//! let out = rewrite.output.expect("mutating ops emit a body");
//! assert_eq!(
//!     serde_json::from_slice::<serde_json::Value>(&out).unwrap(),
//!     json!({"model":"forced","original_model":"old","tenant":"acme"})
//! );
//! # Ok::<(), praxis_filter::json_ops::JsonError>(())
//! ```

mod builder;
mod error;
mod index;
mod ops;
mod pointer;
mod rewrite;
mod simd_scan;
mod skip;
mod store;

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::needless_raw_strings,
    clippy::needless_raw_string_hashes,
    reason = "tests"
)]
mod tests;

// -----------------------------------------------------------------------------
// Re-exports
// -----------------------------------------------------------------------------

pub use builder::{JsonOps, JsonOpsBuilder, JsonRewrite, JsonValue};
pub use error::JsonError;
pub use ops::ExtractDest;
pub use store::{HttpJsonStore, JsonOpStore, MapStore};

// -----------------------------------------------------------------------------
// Fuzzing-only exports
// -----------------------------------------------------------------------------

// `cargo fuzz` compiles the whole dependency graph with `--cfg fuzzing`,
// which widens `find_json_string_delim`'s own visibility to `pub` (see
// `simd_scan.rs`); this re-export exists only in that build and carries no
// cost or surface in a normal one. `fuzz_simd_scan` calls it directly and
// checks it against an inlined scalar oracle.
#[cfg(fuzzing)]
pub use simd_scan::find_json_string_delim;
