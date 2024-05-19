//! Runtime options passed from config into the server factory.

// -----------------------------------------------------------------------------
// RuntimeOptions
// -----------------------------------------------------------------------------

/// Runtime tuning passed from config into the server factory.
///
/// ```
/// use praxis_core::server::RuntimeOptions;
///
/// let opts = RuntimeOptions::default();
/// assert_eq!(opts.threads, 0);
/// assert!(opts.work_stealing);
///
/// let opts = RuntimeOptions { threads: 4, work_stealing: false };
/// assert_eq!(opts.threads, 4);
/// ```
#[derive(Debug, Clone)]
pub struct RuntimeOptions {
    /// Worker threads per service. `0` means auto-detect.
    pub threads: usize,

    /// Allow work-stealing between threads.
    pub work_stealing: bool,
}

impl Default for RuntimeOptions {
    fn default() -> Self {
        Self {
            threads: 0,
            work_stealing: true,
        }
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_has_zero_threads_and_work_stealing_true() {
        let opts = RuntimeOptions::default();

        assert_eq!(opts.threads, 0);
        assert!(opts.work_stealing);
    }

    #[test]
    fn explicit_fields_are_preserved() {
        let opts = RuntimeOptions {
            threads: 4,
            work_stealing: false,
        };

        assert_eq!(opts.threads, 4);
        assert!(!opts.work_stealing);
    }
}
