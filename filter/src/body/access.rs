//! Body access declarations for filter pipeline stages.

// -----------------------------------------------------------------------------
// BodyAccess
// -----------------------------------------------------------------------------

/// Declares whether a filter needs access to request or response bodies.
///
/// ```
/// use praxis_filter::BodyAccess;
///
/// let access = BodyAccess::default();
/// assert_eq!(access, BodyAccess::None);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]

pub enum BodyAccess {
    /// No body access needed.
    #[default]
    None,

    /// Read-only access.
    ReadOnly,

    /// Read-write access.
    ReadWrite,
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
            BodyAccess::ReadOnly,
            "None and ReadOnly should differ"
        );
        assert_ne!(
            BodyAccess::ReadOnly,
            BodyAccess::ReadWrite,
            "ReadOnly and ReadWrite should differ"
        );
        assert_ne!(
            BodyAccess::None,
            BodyAccess::ReadWrite,
            "None and ReadWrite should differ"
        );
    }
}
