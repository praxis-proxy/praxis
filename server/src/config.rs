//! Configuration loading with fallback resolution.

use praxis_core::config::Config;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Built-in fallback configuration (static JSON response on `/`).
///
/// ```
/// let config = praxis_core::config::Config::from_yaml(praxis::DEFAULT_CONFIG).unwrap();
/// assert!(!config.listeners.is_empty());
/// ```
pub const DEFAULT_CONFIG: &str = include_str!("../../examples/configs/pipeline/default.yaml");

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

/// Load configuration from an explicit path, falling back to `praxis.yaml` in the working directory,
/// then the built-in default.
///
/// Terminates the process with a fatal error message on configuration failure.
///
/// ```no_run
/// let config = praxis::load_config(None);
/// assert!(!config.listeners.is_empty());
/// ```
pub fn load_config(explicit_path: Option<&str>) -> Config {
    Config::load(explicit_path, DEFAULT_CONFIG).unwrap_or_else(|e| fatal(&e))
}

// -----------------------------------------------------------------------------
// Utilities
// -----------------------------------------------------------------------------

/// Print a fatal error to stderr and exit the process.
#[allow(clippy::print_stderr)]
pub(crate) fn fatal(err: &dyn std::fmt::Display) -> ! {
    eprintln!("fatal: {err}");
    std::process::exit(1)
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use praxis_core::config::Config;

    use super::*;

    #[test]
    fn default_config_parses_successfully() {
        let config = Config::from_yaml(DEFAULT_CONFIG).expect("DEFAULT_CONFIG should parse");
        assert!(
            !config.listeners.is_empty(),
            "default config should define at least one listener"
        );
    }

    #[test]
    fn load_config_nonexistent_explicit_path_returns_error() {
        let result = Config::load(Some("/nonexistent/path/praxis.yaml"), DEFAULT_CONFIG);
        assert!(
            result.is_err(),
            "loading a nonexistent explicit path should return an error"
        );
    }

    #[test]
    fn load_config_none_with_valid_fallback_succeeds() {
        let config = Config::load(None, DEFAULT_CONFIG).expect("fallback YAML should parse successfully");
        assert!(
            !config.listeners.is_empty(),
            "fallback config should define at least one listener"
        );
        assert_eq!(
            config.listeners[0].name, "default",
            "fallback config listener name should be 'default'"
        );
    }
}
