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

/// Load configuration from an explicit path, falling back to
/// `praxis.yaml` in the working directory, then the built-in
/// default.
///
/// Terminates the process with a fatal error message on
/// configuration failure.
///
/// ```no_run
/// let config = praxis::load_config(None);
/// assert!(!config.listeners.is_empty());
/// ```
pub fn load_config(explicit_path: Option<&str>) -> Config {
    Config::load(explicit_path, DEFAULT_CONFIG).unwrap_or_else(|e| fatal(&e))
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/// Print a fatal error to stderr and exit the process.
#[allow(clippy::print_stderr)]
pub(crate) fn fatal(err: &dyn std::fmt::Display) -> ! {
    eprintln!("fatal: {err}");
    std::process::exit(1)
}
