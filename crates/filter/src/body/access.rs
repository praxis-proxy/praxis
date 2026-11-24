// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Body access declarations for filter pipeline stages.

// -----------------------------------------------------------------------------
// BodyAccess
// -----------------------------------------------------------------------------

/// Whether a filter may skip declared body processing for an admitted request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BodyRequirement {
    /// The filter can safely miss the body for an admitted request.
    Optional,

    /// The request must not be admitted when this processing would be skipped.
    Required,
}

/// Declares body access rights and whether that processing is required.
///
/// ```
/// use praxis_filter::{BodyAccess, BodyRequirement};
///
/// let access = BodyAccess::default();
/// assert_eq!(access, BodyAccess::None);
/// ```
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum BodyAccess {
    /// No body access needed.
    #[default]
    None,

    /// Read-only access with an explicit processing requirement.
    ReadOnly(BodyRequirement),

    /// Read-write access with an explicit processing requirement.
    ReadWrite(BodyRequirement),
}

impl BodyAccess {
    /// Whether this declaration participates in body processing.
    pub const fn participates(self) -> bool {
        !matches!(self, Self::None)
    }

    /// Whether this declaration permits body mutation.
    pub const fn is_writable(self) -> bool {
        matches!(self, Self::ReadWrite(_))
    }

    /// Whether skipping this declared processing is forbidden.
    pub const fn is_required(self) -> bool {
        matches!(
            self,
            Self::ReadOnly(BodyRequirement::Required) | Self::ReadWrite(BodyRequirement::Required)
        )
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn body_access_default_is_none() {
        assert_eq!(
            BodyAccess::default(),
            BodyAccess::None,
            "default BodyAccess should be None"
        );
    }

    #[test]
    fn body_access_variants_are_distinct() {
        assert_ne!(
            BodyAccess::None,
            BodyAccess::ReadOnly(BodyRequirement::Optional),
            "None and ReadOnly should differ"
        );
        assert_ne!(
            BodyAccess::ReadOnly(BodyRequirement::Optional),
            BodyAccess::ReadWrite(BodyRequirement::Optional),
            "ReadOnly and ReadWrite should differ"
        );
        assert_ne!(
            BodyAccess::None,
            BodyAccess::ReadWrite(BodyRequirement::Optional),
            "None and ReadWrite should differ"
        );
    }
}
