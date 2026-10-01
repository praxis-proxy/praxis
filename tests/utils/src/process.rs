// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Test utilities for running the real `praxis` binary as a child process.
//!
//! Process-wide state such as the open file limit and the descriptor table
//! is shared by every test running in the same test binary, so tests that
//! measure or change it must observe a separate process.

use std::{
    fs,
    net::TcpStream,
    process::{Child, Command, ExitStatus, Stdio},
    time::{Duration, Instant},
};

use crate::praxis_bin;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// How long a spawned process may take to start listening.
pub const READY_TIMEOUT: Duration = Duration::from_secs(15);

// -----------------------------------------------------------------------------
// PraxisProcess
// -----------------------------------------------------------------------------

/// A running `praxis` child process with captured output.
///
/// Dropping it kills the process. Call [`PraxisProcess::terminate`] for a
/// graceful shutdown that also flushes buffered logs.
pub struct PraxisProcess {
    /// The child, `None` once terminated.
    child: Option<Child>,

    /// Holds the config file and captured output alive.
    dir: tempfile::TempDir,
}

impl PraxisProcess {
    /// Spawn `praxis` with `config_yaml` and wait until `ready_addr` accepts
    /// TCP connections.
    ///
    /// # Panics
    ///
    /// Panics if the process cannot be spawned or never becomes ready.
    pub fn spawn(config_yaml: &str, ready_addr: &str) -> Self {
        Self::spawn_with_ulimit(config_yaml, ready_addr, None)
    }

    /// Like [`PraxisProcess::spawn`], first running the shell `ulimit`
    /// arguments in `ulimit` (for example `"-S -n 512"`) so the child
    /// starts with those resource limits.
    ///
    /// # Panics
    ///
    /// Panics if the process cannot be spawned or never becomes ready.
    pub fn spawn_with_ulimit(config_yaml: &str, ready_addr: &str, ulimit: Option<&str>) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let config_path = dir.path().join("praxis.yaml");
        fs::write(&config_path, config_yaml).expect("write config");
        let stdout = fs::File::create(dir.path().join("stdout.log")).expect("create stdout log");
        let stderr = fs::File::create(dir.path().join("stderr.log")).expect("create stderr log");

        let prefix = ulimit.map_or_else(String::new, |args| format!("ulimit {args} && "));
        let child = Command::new("sh")
            .arg("-c")
            .arg(format!("{prefix}exec \"$0\" -c \"$1\""))
            .arg(praxis_bin())
            .arg(&config_path)
            .env("NO_COLOR", "1")
            .stdin(Stdio::null())
            .stdout(stdout)
            .stderr(stderr)
            .spawn()
            .expect("spawn praxis");
        let mut process = Self {
            child: Some(child),
            dir,
        };
        process.wait_ready(ready_addr);
        process
    }

    /// Process ID of the running `praxis`.
    ///
    /// # Panics
    ///
    /// Panics if the process was already terminated.
    pub fn pid(&self) -> u32 {
        self.child.as_ref().expect("process was terminated").id()
    }

    /// Captured stdout and stderr, with ANSI escapes removed.
    pub fn logs(&self) -> String {
        let read = |name: &str| fs::read_to_string(self.dir.path().join(name)).unwrap_or_default();
        strip_ansi(&format!("{}{}", read("stdout.log"), read("stderr.log")))
    }

    /// Send SIGTERM, wait for exit, and return the exit status. Buffered
    /// logs are flushed by the graceful shutdown.
    ///
    /// # Panics
    ///
    /// Panics if the process was already terminated or cannot be signalled.
    pub fn terminate(&mut self) -> ExitStatus {
        let mut child = self.child.take().expect("process was terminated");
        let _signalled = Command::new("kill")
            .args(["-TERM", &child.id().to_string()])
            .status()
            .expect("send SIGTERM");
        child.wait().expect("wait for praxis")
    }

    /// Number of descriptors the process holds open right now.
    ///
    /// # Panics
    ///
    /// Panics if `/proc/<pid>/fd` cannot be read.
    #[cfg(target_os = "linux")]
    pub fn open_fds(&self) -> usize {
        fs::read_dir(format!("/proc/{}/fd", self.pid()))
            .expect("read /proc/<pid>/fd")
            .count()
    }

    /// The process's `(soft, hard)` open file limit.
    ///
    /// # Panics
    ///
    /// Panics if `/proc/<pid>/limits` cannot be read or parsed.
    #[cfg(target_os = "linux")]
    pub fn open_file_limits(&self) -> (u64, u64) {
        open_file_limits_of(&format!("/proc/{}/limits", self.pid()))
    }

    /// Highest [`PraxisProcess::open_fds`] seen while `run` executes, sampled
    /// every `interval` on a background thread.
    ///
    /// # Panics
    ///
    /// Panics if the sampler thread panics.
    #[cfg(target_os = "linux")]
    pub fn peak_open_fds_during<T, F: FnOnce() -> T>(&self, interval: Duration, run: F) -> (usize, T) {
        let pid = self.pid();
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let sampler = {
            let stop = std::sync::Arc::clone(&stop);
            std::thread::spawn(move || {
                let mut peak = 0;
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    if let Ok(entries) = fs::read_dir(format!("/proc/{pid}/fd")) {
                        peak = peak.max(entries.count());
                    }
                    std::thread::sleep(interval);
                }
                peak
            })
        };
        let result = run();
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let peak = sampler.join().expect("fd sampler thread");
        (peak.max(self.open_fds()), result)
    }

    /// Poll until [`PraxisProcess::open_fds`] is at most `ceiling`, returning
    /// the last count seen.
    #[cfg(target_os = "linux")]
    pub fn wait_open_fds_at_most(&self, ceiling: usize, timeout: Duration) -> usize {
        let deadline = Instant::now() + timeout;
        loop {
            let open = self.open_fds();
            if open <= ceiling || Instant::now() >= deadline {
                return open;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Wait until `addr` accepts TCP connections.
    ///
    /// # Panics
    ///
    /// Panics with the captured logs if the process exits first or is not
    /// ready within [`READY_TIMEOUT`] (overridable like every readiness wait).
    fn wait_ready(&mut self, addr: &str) {
        let timeout = crate::net::wait::ready_timeout(READY_TIMEOUT);
        let deadline = Instant::now() + timeout;
        loop {
            if TcpStream::connect(addr).is_ok() {
                return;
            }
            let child = self.child.as_mut().expect("process was terminated");
            if let Ok(Some(status)) = child.try_wait() {
                panic!("praxis exited during startup with {status}:\n{}", self.logs());
            }
            assert!(
                Instant::now() < deadline,
                "praxis did not listen on {addr} within {timeout:?}:\n{}",
                self.logs()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for PraxisProcess {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _killed = child.kill();
            let _reaped = child.wait();
        }
    }
}

// -----------------------------------------------------------------------------
// Process Limits
// -----------------------------------------------------------------------------

/// The calling process's `(soft, hard)` open file limit.
///
/// # Panics
///
/// Panics if `/proc/self/limits` cannot be read or parsed.
#[cfg(target_os = "linux")]
pub fn own_open_file_limits() -> (u64, u64) {
    open_file_limits_of("/proc/self/limits")
}

/// Raise this test process's soft open file limit to its hard limit, as the
/// proxy does for itself.
///
/// Load helpers hold a client socket per request and the in-process backends
/// a server socket per connection, so a few hundred concurrent requests need
/// more than the 1024 soft limit containers and desktop sessions often start
/// with. Without this the test process, not the proxy under test, runs out,
/// and its backends quietly serve in waves instead of all at once.
///
/// # Panics
///
/// Panics if the limit cannot be read or raised.
#[cfg(target_os = "linux")]
pub fn raise_own_open_file_limit() {
    use nix::sys::resource::{Resource, getrlimit, setrlimit};

    let (soft, hard) = getrlimit(Resource::RLIMIT_NOFILE).expect("read the open file limit");
    if soft < hard {
        setrlimit(Resource::RLIMIT_NOFILE, hard, hard).expect("raise the soft open file limit to the hard limit");
    }
}

/// Parse the `Max open files` row of a `/proc/<pid>/limits` file.
#[cfg(target_os = "linux")]
fn open_file_limits_of(path: &str) -> (u64, u64) {
    let limits = fs::read_to_string(path).expect("read limits");
    let row = limits
        .lines()
        .find(|line| line.starts_with("Max open files"))
        .expect("limits has a Max open files row");
    let mut values = row
        .trim_start_matches("Max open files")
        .split_whitespace()
        .map(|value| value.parse::<u64>().unwrap_or(u64::MAX));
    let soft = values.next().expect("soft limit");
    let hard = values.next().expect("hard limit");
    (soft, hard)
}

// -----------------------------------------------------------------------------
// Utility Functions
// -----------------------------------------------------------------------------

/// Remove ANSI SGR escape sequences (`ESC [ ... m`).
fn strip_ansi(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(ch) = chars.next() {
        if ch == '\u{1b}' {
            for inner in chars.by_ref() {
                if inner == 'm' {
                    break;
                }
            }
        } else {
            out.push(ch);
        }
    }
    out
}
