// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! A load-balancing weight shared by route targets and endpoint config.

use serde::{Deserialize, Serialize};

/// A non-negative load-balancing weight.
///
/// The type carries the common representation only: route targets restrict the
/// accepted range to `1..=1000` during route validation, while endpoints may
/// use zero to remove an endpoint from rotation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(transparent)]
pub struct Weight(u32);

impl Weight {
    /// The default weight, one.
    pub const ONE: Self = Self(1);
    /// Weight zero, which removes an endpoint from rotation.
    pub const ZERO: Self = Self(0);

    /// Build a weight from its raw value.
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// The raw configured value.
    pub const fn get(self) -> u32 {
        self.0
    }
}

impl Default for Weight {
    fn default() -> Self {
        Self::ONE
    }
}

impl From<u16> for Weight {
    fn from(value: u16) -> Self {
        Self(u32::from(value))
    }
}

impl From<u32> for Weight {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<Weight> for u32 {
    fn from(weight: Weight) -> Self {
        weight.0
    }
}

impl From<Weight> for u64 {
    fn from(weight: Weight) -> Self {
        u64::from(weight.0)
    }
}
