// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis contributors

//! Portable value representations used across Praxis

/// A protocol- and format-agnostic scalar value.
///
/// `Value` is the common currency for passing typed data between components
/// that must not depend on any single serialization format (YAML, JSON, etc.).
/// Each variant owns its data, so a `Value` is self-contained and can be moved
/// or cloned across crate boundaries without borrowing from its source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    /// A UTF-8 text value.
    String(String),
    /// A set of bytes.
    Bytes(Vec<u8>),
    /// A boolean value.
    Bool(bool),
    /// A signed 64-bit integer.
    Int(i64),
    /// An unsigned 64-bit integer.
    UInt(u64),
    // Double is intentionally absent: raw f64 breaks Eq (NaN != NaN).
    // When float support is needed, ordered_float::NotNan<f64> is the path.
}

// -----------------------------------------------------------------------------
// Conversions
//
// A single `impl<T> From<T> for Value` is not possible: each source type maps to
// a distinct variant, so the impls are generated per type.
//
// `From` is reserved for conversions that cannot lose information: the source
// widens losslessly through `i64::from`/`u64::from`. Types whose value may not
// fit the target variant (`i128`/`u128`, and the platform-dependent
// `isize`/`usize`) get `TryFrom` instead, so the caller must handle the
// out-of-range case.
// -----------------------------------------------------------------------------

/// Generate `From<$src>` impls that widen losslessly into `$variant` via `$wide`.
macro_rules! impl_from_numeric {
    ($variant:ident, $wide:ty, $($src:ty),+ $(,)?) => {
        $(
            impl From<$src> for Value {
                fn from(value: $src) -> Self {
                    Self::$variant(<$wide>::from(value))
                }
            }
        )+
    };
}

impl_from_numeric!(Int, i64, i8, i16, i32, i64);
impl_from_numeric!(UInt, u64, u8, u16, u32, u64);

/// Generate `TryFrom<$src>` impls that narrow into `$variant` via `$wide`,
/// failing with [`std::num::TryFromIntError`] when the value is out of range.
macro_rules! impl_try_from_int {
    ($variant:ident, $wide:ty, $($src:ty),+ $(,)?) => {
        $(
            impl TryFrom<$src> for Value {
                type Error = std::num::TryFromIntError;

                fn try_from(value: $src) -> Result<Self, Self::Error> {
                    <$wide>::try_from(value).map(Self::$variant)
                }
            }
        )+
    };
}

impl_try_from_int!(Int, i64, i128, isize);
impl_try_from_int!(UInt, u64, u128, usize);

impl From<bool> for Value {
    fn from(value: bool) -> Self {
        Self::Bool(value)
    }
}

impl From<String> for Value {
    fn from(string: String) -> Self {
        Self::String(string)
    }
}

impl From<&str> for Value {
    fn from(str: &str) -> Self {
        Self::String(str.to_owned())
    }
}

impl From<Vec<u8>> for Value {
    fn from(bytes: Vec<u8>) -> Self {
        Self::Bytes(bytes)
    }
}

impl From<&[u8]> for Value {
    fn from(bytes: &[u8]) -> Self {
        Self::Bytes(bytes.to_vec())
    }
}
