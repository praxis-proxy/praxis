// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Condition predicates that gate filter execution.

mod request;
mod response;

pub use request::{Condition, ConditionMatch};
pub use response::{ResponseCondition, ResponseConditionMatch};

// -----------------------------------------------------------------------------
// Shared Deserialization Macro
// -----------------------------------------------------------------------------

/// Generates a `Deserialize` impl for a when/unless condition enum.
///
/// Both [`Condition`] and [`ResponseCondition`] follow the same
/// structure: a helper struct with optional `when` and `unless`
/// fields, matched into two variants with identical error arms.
///
/// # Arguments
///
/// * `$cond`   -- The condition enum type (e.g. `Condition`).
/// * `$match_` -- The inner match type (e.g. `ConditionMatch`).
/// * `$label`  -- Human-readable label for error messages (e.g. `"condition"`).
macro_rules! impl_condition_deserialize {
    ($cond:ident, $match_:ty, $label:expr) => {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct ConditionDeserHelper {
            /// The `when` predicate, if present.
            #[serde(default)]
            when: Option<$match_>,

            /// The `unless` predicate, if present.
            #[serde(default)]
            unless: Option<$match_>,
        }

        impl<'de> serde::Deserialize<'de> for $cond {
            fn deserialize<D: serde::de::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let helper = ConditionDeserHelper::deserialize(deserializer)?;
                match (helper.when, helper.unless) {
                    (Some(m), None) => Ok($cond::When(m)),
                    (None, Some(m)) => Ok($cond::Unless(m)),
                    (Some(_), Some(_)) => Err(serde::de::Error::custom(concat!(
                        $label,
                        " must have exactly one of 'when' or 'unless', not both"
                    ))),
                    (None, None) => Err(serde::de::Error::custom(concat!(
                        $label,
                        " must have either 'when' or 'unless'"
                    ))),
                }
            }
        }
    };
}

pub(crate) use impl_condition_deserialize;
