//! `cargo xtask debug` — run praxis with dev settings.
//!
//! Enables debug logging, single-threaded runtime (by default),
//! a fast shutdown timeout, and the admin endpoint.

use clap::Parser;

// -----------------------------------------------------------------------------
// CLI Arguments
// -----------------------------------------------------------------------------

/// CLI arguments for `cargo xtask debug`.
#[derive(Parser)]
#[command(long_about = "Run praxis with development settings. \
                  Enables debug logging, admin endpoint \
                  (127.0.0.1:9090), and 3-second shutdown \
                  timeout.\n\n\
                  Runs single-threaded by default for easier \
                  debugging. Pass --multi-threaded to use the \
                  config's thread setting instead.")]
pub struct Args {
    /// Path to a YAML config file. Falls back to praxis.yaml
    /// in the current directory, then the built-in default.
    config: Option<String>,

    /// Use multi-threaded runtime instead of single-threaded.
    #[arg(long)]
    multi_threaded: bool,
}

// -----------------------------------------------------------------------------
// Entry Point
// -----------------------------------------------------------------------------

/// Load config and start the server with dev-friendly defaults.
pub fn run(args: &Args) {
    crate::init_tracing("debug");

    let mut config = praxis::load_config(args.config.as_deref());

    config.runtime.threads = if args.multi_threaded { config.runtime.threads } else { 1 };

    config.shutdown_timeout_secs = 3;

    for listener in &mut config.listeners {
        listener.address = crate::port::resolve_available(&listener.address);
    }

    if config.admin_address.is_none() {
        config.admin_address = Some("127.0.0.1:9090".to_owned());
    }

    praxis::run_server(config)
}
