//! Tracing subscriber setup shared by all Praxis binaries.

use praxis_core::config::Config;

// -----------------------------------------------------------------------------
// Tracing
// -----------------------------------------------------------------------------

/// Build an `EnvFilter` from `RUST_LOG` (or the given default)
/// merged with any `log_overrides` from the config.
fn build_env_filter(config: &Config) -> tracing_subscriber::EnvFilter {
    let base = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    if config.runtime.log_overrides.is_empty() {
        return base;
    }

    // Serialize the base filter back to a directive string, then
    // append the config-driven overrides so they take precedence.
    let mut directives = base.to_string();
    for (module, level) in &config.runtime.log_overrides {
        directives.push(',');
        directives.push_str(module);
        directives.push('=');
        directives.push_str(level);
    }

    tracing_subscriber::EnvFilter::new(directives)
}

/// Initialize the global tracing subscriber.
///
/// Set `PRAXIS_LOG_FORMAT=json` for structured JSON output.
/// Per-module overrides come from `runtime.log_overrides` in
/// the config YAML.
pub fn init_tracing(config: &Config) {
    let env_filter = build_env_filter(config);
    let json = std::env::var("PRAXIS_LOG_FORMAT").as_deref() == Ok("json");

    if json {
        tracing_subscriber::fmt().json().with_env_filter(env_filter).init();
    } else {
        tracing_subscriber::fmt().with_env_filter(env_filter).init();
    }
}
