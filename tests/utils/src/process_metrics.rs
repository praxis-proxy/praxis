// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! External process measurements for isolated test runs.

use std::{io, time::Instant};

/// A point-in-time sample of one process, not the whole test runner.
#[derive(Clone, Debug)]
pub struct ProcessSample {
    /// Sampling time in the test runner's monotonic clock.
    pub at: Instant,
    /// Resident bytes from Linux `/proc/<pid>/status` `VmRSS`.
    pub rss_bytes: Option<u64>,
    /// Lifetime resident high-water bytes from Linux `VmHWM`.
    pub peak_rss_bytes: Option<u64>,
    /// Anonymous resident bytes from `/proc/<pid>/status` `RssAnon`.
    pub anonymous_rss_bytes: Option<u64>,
    /// Cumulative user plus system CPU ticks from `/proc/<pid>/stat`.
    /// Tick frequency is platform-specific and has not been converted.
    pub cpu_ticks: Option<u64>,
    /// Descriptor count from `/proc/<pid>/fd`.
    pub open_fds: Option<usize>,
}

/// Sample process RSS, CPU ticks and file descriptors on Linux.
///
/// Missing optional kernel fields remain `None`. Process exit, permissions and
/// unreadable files return an error; they are never represented as zero.
///
/// # Errors
///
/// Returns the underlying I/O error when the process's procfs files cannot be read.
#[cfg(target_os = "linux")]
pub fn sample_process(pid: u32) -> io::Result<ProcessSample> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status"))?;
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let mut entries = std::fs::read_dir(format!("/proc/{pid}/fd"))?;
    let open_fds = entries.try_fold(0_usize, |count, entry| entry.map(|_| count + 1))?;
    Ok(ProcessSample {
        at: Instant::now(),
        rss_bytes: status_bytes(&status, "VmRSS:"),
        peak_rss_bytes: status_bytes(&status, "VmHWM:"),
        anonymous_rss_bytes: status_bytes(&status, "RssAnon:"),
        cpu_ticks: stat_cpu_ticks(&stat),
        open_fds: Some(open_fds),
    })
}

/// Report unavailable sampling on platforms without the Linux proc filesystem.
///
/// # Errors
///
/// Always returns [`io::ErrorKind::Unsupported`].
#[cfg(not(target_os = "linux"))]
pub fn sample_process(_pid: u32) -> io::Result<ProcessSample> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "process sampling requires Linux procfs",
    ))
}

/// Extract a procfs status size, which is reported in KiB.
#[cfg(target_os = "linux")]
fn status_bytes(status: &str, label: &str) -> Option<u64> {
    let line = status.lines().find_map(|line| line.strip_prefix(label))?;
    let mut parts = line.split_whitespace();
    let value = parts.next()?.parse::<u64>().ok()?;
    (parts.next()? == "kB").then(|| value.checked_mul(1_024)).flatten()
}

/// Extract user and system CPU ticks after the parenthesized process name.
#[cfg(target_os = "linux")]
fn stat_cpu_ticks(stat: &str) -> Option<u64> {
    let (_, fields) = stat.rsplit_once(") ")?;
    let mut fields = fields.split_whitespace();
    let user = fields.nth(11)?.parse::<u64>().ok()?;
    let system = fields.next()?.parse::<u64>().ok()?;
    user.checked_add(system)
}

#[cfg(test)]
#[cfg(target_os = "linux")]
mod tests {
    use super::{sample_process, stat_cpu_ticks, status_bytes};

    #[test]
    fn sample_own_process_reports_labeled_values() {
        let sample = sample_process(std::process::id()).unwrap();
        assert!(sample.rss_bytes.is_some_and(|bytes| bytes > 0));
        assert!(sample.peak_rss_bytes.is_some_and(|bytes| bytes > 0));
        assert!(sample.cpu_ticks.is_some());
        assert!(sample.open_fds.is_some_and(|count| count > 0));
    }

    #[test]
    fn parse_fields_handles_missing_values_and_parentheses_in_names() {
        assert_eq!(status_bytes("VmRSS: 12 kB\n", "VmRSS:"), Some(12_288));
        assert_eq!(status_bytes("VmRSS: 12 B\n", "VmRSS:"), None);
        assert_eq!(status_bytes("", "VmRSS:"), None);
        let stat = "1 (name with ) parentheses) S 1 2 3 4 5 6 7 8 9 10 11 12";
        assert_eq!(stat_cpu_ticks(stat), Some(23));
        assert_eq!(stat_cpu_ticks("invalid"), None);
    }
}
