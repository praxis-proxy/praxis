// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Graduated process pressure, sampled off the request path.
//!
//! Each resource is a ratio against its limit. A band turns that ratio into a
//! pressure from 0 to 1, and an exponential moving average keeps one sample
//! from flipping the value. This module only reports pressure. Shedding
//! actions are a later change; today's hard refuses stay where they are.
//!
//! Heap pressure uses anonymous resident memory (`RssAnon`) over the
//! configured RSS cap. That is the part of RSS where the allocator heap
//! lives, so file cache does not count as heap. Cgroup pressure uses the
//! working set kubelet uses (`memory.current` minus `inactive_file`) over
//! `memory.max`, taking the highest ratio from this cgroup and each
//! ancestor up to the cgroup root. A service cgroup is often left at
//! `memory.max=max` while the cap lives on a parent slice. CPU pressure
//! is Linux PSI "some" stall time, not how busy the cores are. On cgroup
//! v2 (kernels ≥ 4.20) the per-cgroup
//! `cpu.pressure` file is preferred so the gauge reflects this process's
//! cgroup, not the whole host. When the per-cgroup file is absent the
//! monitor falls back to host-wide `/proc/pressure/cpu`.

use std::path::{Path, PathBuf};

// -----------------------------------------------------------------------------
// Bands
// -----------------------------------------------------------------------------

/// Usage fraction where pressure starts, and where it reaches 1.
#[derive(Clone, Copy)]
struct Band {
    /// Pressure is 0 at and below this usage ratio.
    scaling: f64,
    /// Pressure is 1 at and above this usage ratio.
    saturation: f64,
}

/// Cgroup working set. Matches the proposal's 80% to 95% band.
const CGROUP_MEMORY: Band = Band {
    scaling: 0.80,
    saturation: 0.95,
};

/// Anonymous resident memory over the configured RSS cap.
const HEAP: Band = Band {
    scaling: 0.80,
    saturation: 0.95,
};

/// PSI "some" stall fraction. 10% of recent time stalled is the start;
/// 50% is saturated. A busy core with nothing waiting stays at 0.
const CPU: Band = Band {
    scaling: 0.10,
    saturation: 0.50,
};

/// Open connections over `runtime.max_connections`.
const CONNECTIONS: Band = Band {
    scaling: 0.70,
    saturation: 0.95,
};

/// Open descriptors over the process limit.
const FILE_DESCRIPTORS: Band = Band {
    scaling: 0.70,
    saturation: 0.95,
};

/// Weight of a new sample in the moving average. The rest stays with the
/// previous pressure, so a single noisy reading cannot flap the gauge.
const SMOOTHING: f64 = 0.3;

/// How often a background task should call [`Monitor::observe`].
pub const SAMPLE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

/// Pressure below this value is considered idle (no threshold crossed).
const IDLE_CEILING: f64 = 1e-9;

/// Pressure at or above this value means the resource is saturated.
const SATURATED_FLOOR: f64 = 1.0 - 1e-9;

/// Consecutive raw samples at the saturation threshold before logging
/// saturation. With smoothing 0.3, a gauge that starts at 0 reaches
/// [`SATURATED_FLOOR`] only after about 59 saturated samples. Three raw
/// samples is enough to ignore one spike and still warn within a few
/// seconds. The same count of samples below the threshold clears it.
const SUSTAINED_SATURATION_SAMPLES: u8 = 3;

// -----------------------------------------------------------------------------
// Pressure state transitions
// -----------------------------------------------------------------------------

/// Coarse state of a resource's smoothed pressure, used for log transitions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PressureState {
    /// Pressure is 0 — below the scaling threshold.
    Idle,
    /// Pressure is between 0 and 1 — inside the scaling band.
    Scaling,
    /// Usage is at the saturation threshold. The smoothed gauge may still
    /// be climbing; three consecutive raw saturated samples count.
    Saturated,
}

impl PressureState {
    /// Classify a smoothed pressure value into a coarse state.
    pub fn from_pressure(pressure: f64) -> Self {
        if pressure <= IDLE_CEILING {
            Self::Idle
        } else if pressure >= SATURATED_FLOOR {
            Self::Saturated
        } else {
            Self::Scaling
        }
    }
}

/// Tracks per-resource pressure state so the caller can log transitions.
///
/// Call [`TransitionTracker::update`] after each [`Monitor::observe`] to get
/// a list of `(resource, old_state, new_state)` transitions. Only state
/// *changes* are returned, so calling code can log without flooding.
#[derive(Default)]
pub struct TransitionTracker {
    /// Last known state per resource, indexed by [`resource_index`].
    states: [Option<PressureState>; 5],
    /// Consecutive raw samples at the saturation threshold, per resource.
    saturated_run: [u8; 5],
    /// Consecutive raw samples below the saturation threshold, per resource.
    clear_run: [u8; 5],
}

/// A pressure state transition for one resource.
pub struct Transition {
    /// Resource label (matches [`Pressures::iter`] labels).
    pub resource: &'static str,
    /// Previous state, or `None` if this is the first sample.
    pub from: Option<PressureState>,
    /// Current state.
    pub to: PressureState,
    /// Current smoothed pressure value.
    pub pressure: f64,
}

impl TransitionTracker {
    /// Compare the new pressures against the tracked state, returning any
    /// transitions. Resources with no sample are skipped.
    ///
    /// `raw_saturated` follows the same resource order as [`Monitor::raw_saturated`].
    /// `None` means that resource was not sampled, so the smoothed pressure
    /// alone decides the state. Three consecutive raw saturated samples log
    /// saturation while the gauge is still climbing, and the same run below
    /// the threshold is required to clear it.
    pub fn update(&mut self, pressures: Pressures, raw_saturated: [Option<bool>; 5]) -> Vec<Transition> {
        let mut transitions = Vec::new();
        for (resource, pressure) in pressures.iter() {
            let Some(idx) = resource_index(resource) else {
                continue;
            };
            if let Some(transition) = self.record_sample(idx, resource, pressure, raw_saturated) {
                transitions.push(transition);
            }
        }
        transitions
    }

    /// Update one resource and return a transition when its logged state changes.
    fn record_sample(
        &mut self,
        idx: usize,
        resource: &'static str,
        pressure: f64,
        raw_saturated: [Option<bool>; 5],
    ) -> Option<Transition> {
        let previous = self.states.get(idx).copied()?;
        let (mut saturated_run, mut clear_run) = self.runs(idx);
        let new_state = classify_transition(
            previous,
            PressureState::from_pressure(pressure),
            raw_saturated.get(idx).copied().flatten(),
            &mut saturated_run,
            &mut clear_run,
        );
        self.store_runs(idx, saturated_run, clear_run);
        if previous == Some(new_state) {
            return None;
        }
        if let Some(slot) = self.states.get_mut(idx) {
            *slot = Some(new_state);
        }
        Some(Transition {
            resource,
            from: previous,
            to: new_state,
            pressure,
        })
    }

    /// Consecutive saturated and clear raw samples for one resource.
    fn runs(&self, idx: usize) -> (u8, u8) {
        (
            self.saturated_run.get(idx).copied().unwrap_or(0),
            self.clear_run.get(idx).copied().unwrap_or(0),
        )
    }

    /// Store the runs from [`Self::runs`].
    fn store_runs(&mut self, idx: usize, saturated_run: u8, clear_run: u8) {
        if let Some(stored) = self.saturated_run.get_mut(idx) {
            *stored = saturated_run;
        }
        if let Some(stored) = self.clear_run.get_mut(idx) {
            *stored = clear_run;
        }
    }
}

/// Decide the logged state and advance the raw-sample runs.
///
/// A missing raw sample leaves the runs alone and follows the smoothed
/// pressure. Sustained raw saturation logs saturation early. A short dip
/// keeps a saturation warning until the same number of clear samples, and
/// a saturated sample after that dip does not drop the warning.
fn classify_transition(
    previous: Option<PressureState>,
    smoothed: PressureState,
    raw: Option<bool>,
    saturated_run: &mut u8,
    clear_run: &mut u8,
) -> PressureState {
    match raw {
        Some(true) => {
            *saturated_run = saturated_run.saturating_add(1);
            *clear_run = 0;
            if *saturated_run >= SUSTAINED_SATURATION_SAMPLES
                || smoothed == PressureState::Saturated
                || previous == Some(PressureState::Saturated)
            {
                PressureState::Saturated
            } else {
                smoothed
            }
        },
        Some(false) => {
            *saturated_run = 0;
            *clear_run = clear_run.saturating_add(1);
            if previous == Some(PressureState::Saturated)
                && smoothed != PressureState::Saturated
                && *clear_run < SUSTAINED_SATURATION_SAMPLES
            {
                PressureState::Saturated
            } else {
                smoothed
            }
        },
        None => smoothed,
    }
}

/// Index for a resource label in the tracker's state array.
fn resource_index(resource: &str) -> Option<usize> {
    match resource {
        "cgroup_memory" => Some(0),
        "heap" => Some(1),
        "cpu" => Some(2),
        "connections" => Some(3),
        "file_descriptors" => Some(4),
        _ => None,
    }
}

// -----------------------------------------------------------------------------
// Pressure
// -----------------------------------------------------------------------------

/// Latest smoothed pressure for each resource. `None` means that resource
/// has not produced a sample yet (no limit, or the kernel file is absent).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Pressures {
    /// Cgroup working set over `memory.max`.
    pub cgroup_memory: Option<f64>,
    /// Anonymous resident memory over the configured cap.
    pub heap: Option<f64>,
    /// CPU stall time, from PSI.
    pub cpu: Option<f64>,
    /// Open connections over the global cap.
    pub connections: Option<f64>,
    /// Open file descriptors over the process limit.
    pub file_descriptors: Option<f64>,
}

impl Pressures {
    /// Resource label and pressure, skipping resources with no sample.
    pub fn iter(self) -> impl Iterator<Item = (&'static str, f64)> {
        [
            ("cgroup_memory", self.cgroup_memory),
            ("heap", self.heap),
            ("cpu", self.cpu),
            ("connections", self.connections),
            ("file_descriptors", self.file_descriptors),
        ]
        .into_iter()
        .filter_map(|(resource, pressure)| pressure.map(|pressure| (resource, pressure)))
    }
}

/// Counts the caller already has. Kernel files are read inside [`Monitor::observe`].
#[derive(Clone, Copy)]
pub struct Inputs {
    /// `runtime.max_memory_bytes`. Without it there is no heap denominator.
    pub heap_max_bytes: Option<u64>,
    /// Connections in use and the global cap, when a cap is configured.
    pub connections: Option<(u64, u64)>,
    /// Open descriptors and the process limit, when the monitor is running.
    pub file_descriptors: Option<(u64, u64)>,
}

/// One raw usage ratio per resource, before the band and the average.
#[derive(Clone, Copy)]
struct Ratios {
    /// Working set over `memory.max`.
    cgroup_memory: Option<f64>,
    /// Anonymous resident bytes over the configured cap.
    heap: Option<f64>,
    /// PSI stall fraction.
    cpu: Option<f64>,
    /// Open connections over the global cap.
    connections: Option<f64>,
    /// Open descriptors over the process limit.
    file_descriptors: Option<f64>,
}

/// Holds the smoothed pressure between samples.
#[derive(Default)]
pub struct Monitor {
    /// Smoothed cgroup pressure, after the first finite-limit sample.
    cgroup_memory: Option<f64>,
    /// Smoothed heap pressure, after the first sample with a cap.
    heap: Option<f64>,
    /// Smoothed CPU stall pressure, after the first PSI sample.
    cpu: Option<f64>,
    /// Smoothed connection pressure, after the first capped sample.
    connections: Option<f64>,
    /// Smoothed descriptor pressure, after the first sample.
    file_descriptors: Option<f64>,
    /// Latest raw sample at saturation, in resource order. `None` if unsampled.
    raw_saturated: [Option<bool>; 5],
}

impl Monitor {
    /// Sample the process and fold the result into the smoothed pressure.
    ///
    /// A missing sample leaves that resource at its previous pressure, so a
    /// failed `/proc` read does not drop the gauge to zero.
    pub fn observe(&mut self, inputs: Inputs) -> Pressures {
        self.fold(Ratios {
            cgroup_memory: read_cgroup_ratio(),
            heap: inputs.heap_max_bytes.and_then(|max| usage_ratio(read_rss_anon()?, max)),
            cpu: read_cpu_stall(),
            connections: inputs.connections.and_then(|(used, limit)| usage_ratio(used, limit)),
            file_descriptors: inputs
                .file_descriptors
                .and_then(|(used, limit)| usage_ratio(used, limit)),
        })
    }

    /// Fold already-computed ratios. Tests use this so they do not read `/proc`.
    fn fold(&mut self, ratios: Ratios) -> Pressures {
        let (cgroup_memory, cgroup_raw) = step(self.cgroup_memory, ratios.cgroup_memory, CGROUP_MEMORY);
        let (heap, heap_raw) = step(self.heap, ratios.heap, HEAP);
        let (cpu, cpu_raw) = step(self.cpu, ratios.cpu, CPU);
        let (connections, connections_raw) = step(self.connections, ratios.connections, CONNECTIONS);
        let (file_descriptors, descriptors_raw) =
            step(self.file_descriptors, ratios.file_descriptors, FILE_DESCRIPTORS);
        self.cgroup_memory = cgroup_memory;
        self.heap = heap;
        self.cpu = cpu;
        self.connections = connections;
        self.file_descriptors = file_descriptors;
        self.raw_saturated = [cgroup_raw, heap_raw, cpu_raw, connections_raw, descriptors_raw];
        Pressures {
            cgroup_memory: self.cgroup_memory,
            heap: self.heap,
            cpu: self.cpu,
            connections: self.connections,
            file_descriptors: self.file_descriptors,
        }
    }

    /// Whether the latest raw sample was at the saturation threshold.
    ///
    /// Order is cgroup memory, heap, CPU, connections, file descriptors.
    /// `None` means that resource was not sampled this round.
    pub fn raw_saturated(&self) -> [Option<bool>; 5] {
        self.raw_saturated
    }
}

/// Advance one resource. A missing ratio keeps the previous pressure and
/// reports no raw sample. The boolean is whether this raw sample is saturated.
fn step(previous: Option<f64>, ratio: Option<f64>, band: Band) -> (Option<f64>, Option<bool>) {
    let Some(ratio) = ratio.filter(|ratio| ratio.is_finite() && *ratio >= 0.0) else {
        return (previous, None);
    };
    let sample = band_pressure(ratio, band);
    let smoothed = match previous {
        None => sample,
        Some(previous) => previous + SMOOTHING * (sample - previous),
    };
    (Some(smoothed), Some(sample >= SATURATED_FLOOR))
}

/// Linear pressure through the band, clamped to 0 and 1.
fn band_pressure(usage: f64, band: Band) -> f64 {
    if !usage.is_finite() || band.saturation <= band.scaling || usage <= band.scaling {
        return 0.0;
    }
    if usage >= band.saturation {
        return 1.0;
    }
    (usage - band.scaling) / (band.saturation - band.scaling)
}

/// `used / limit`, or `None` when the limit cannot be a denominator.
fn usage_ratio(used: u64, limit: u64) -> Option<f64> {
    (limit > 0).then_some(as_f64(used) / as_f64(limit))
}

/// Counts we sample sit far below 2^53, where this conversion is exact.
fn as_f64(value: u64) -> f64 {
    #[expect(
        clippy::as_conversions,
        clippy::cast_precision_loss,
        reason = "u64 to f64 has no lossless From; resource counts are far below 2^53"
    )]
    {
        value as f64
    }
}

// -----------------------------------------------------------------------------
// Kernel files
// -----------------------------------------------------------------------------

/// Highest cgroup v2 working-set ratio from this process's cgroup through
/// the cgroup root, or `None` when no visible ancestor has a finite limit.
fn read_cgroup_ratio() -> Option<f64> {
    let start = cgroup_dir()?;
    highest_cgroup_ratio(&start, Path::new("/sys/fs/cgroup"))
}

/// One cgroup directory's contribution to the ancestor walk.
enum CgroupLevel {
    /// `memory.max` is absent or `max`, so this level does not constrain.
    Unlimited,
    /// Working-set ratio against this level's finite `memory.max`.
    Ratio(f64),
    /// A finite limit is visible, but `memory.current` or `memory.stat`
    /// could not be read. Reporting the other levels would hide that cap.
    Unreadable,
}

/// Highest `(current - inactive_file) / memory.max` from `start` up through
/// `root`, inclusive.
///
/// The band is monotonic, so the highest ratio is also the highest pressure.
/// A finite limit whose current or stat file cannot be read fails the whole
/// sample and the previous pressure is kept.
fn highest_cgroup_ratio(start: &Path, root: &Path) -> Option<f64> {
    let mut dir = start.to_path_buf();
    let mut best: Option<f64> = None;
    loop {
        match cgroup_level_ratio(&dir) {
            CgroupLevel::Unlimited => {},
            CgroupLevel::Ratio(ratio) => {
                best = Some(best.map_or(ratio, |previous| previous.max(ratio)));
            },
            CgroupLevel::Unreadable => return None,
        }
        if dir == root {
            break;
        }
        let Some(parent) = dir.parent() else {
            break;
        };
        if !parent.starts_with(root) {
            break;
        }
        dir = parent.to_path_buf();
    }
    best
}

/// Classify one cgroup directory: unlimited, a ratio, or an unreadable cap.
fn cgroup_level_ratio(dir: &Path) -> CgroupLevel {
    let Some(max_text) = read_to_string(dir.join("memory.max")) else {
        return CgroupLevel::Unlimited;
    };
    let Some(max) = parse_memory_max(&max_text) else {
        return CgroupLevel::Unlimited;
    };
    let Some(current) = read_u64(dir.join("memory.current")) else {
        return CgroupLevel::Unreadable;
    };
    let Some(stat) = read_to_string(dir.join("memory.stat")) else {
        return CgroupLevel::Unreadable;
    };
    working_set_ratio(current, parse_inactive_file(&stat), max).map_or(CgroupLevel::Unlimited, CgroupLevel::Ratio)
}

/// Working-set ratio `(current - inactive_file) / max`.
fn working_set_ratio(current: u64, inactive: u64, max: u64) -> Option<f64> {
    usage_ratio(current.saturating_sub(inactive), max)
}

/// Anonymous resident bytes, from `RssAnon` in `/proc/self/status`.
fn read_rss_anon() -> Option<u64> {
    let status = read_to_string("/proc/self/status")?;
    for line in status.lines() {
        let Some(rest) = line.strip_prefix("RssAnon:") else {
            continue;
        };
        let kb: u64 = rest.trim().strip_suffix("kB")?.trim().parse().ok()?;
        return kb.checked_mul(1024);
    }
    None
}

/// Fraction of recent time in which some task was stalled on CPU.
///
/// Prefers the per-cgroup `cpu.pressure` file (cgroup v2, kernels ≥ 4.20)
/// so the gauge reflects this process's cgroup, not the whole host. Falls
/// back to host-wide `/proc/pressure/cpu` when the cgroup file is absent.
fn read_cpu_stall() -> Option<f64> {
    if let Some(dir) = cgroup_dir()
        && let Some(text) = read_to_string(dir.join("cpu.pressure"))
    {
        return parse_psi_some_avg10(&text);
    }
    parse_psi_some_avg10(&read_to_string("/proc/pressure/cpu")?)
}

/// File contents, or `None` when the path cannot be read.
fn read_to_string(path: impl AsRef<Path>) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

/// Integer file body, or `None` when the file is missing or not an integer.
fn read_u64(path: impl AsRef<Path>) -> Option<u64> {
    read_to_string(path)?.trim().parse().ok()
}

/// Directory of this process's cgroup v2, from the `0::` line in `/proc/self/cgroup`.
fn cgroup_dir() -> Option<PathBuf> {
    let text = read_to_string("/proc/self/cgroup")?;
    let path = cgroup_v2_path(&text)?;
    Some(PathBuf::from("/sys/fs/cgroup").join(path.trim_start_matches('/')))
}

/// Path from a cgroup v2 `/proc/self/cgroup` body. The controllers field is empty.
fn cgroup_v2_path(proc_cgroup: &str) -> Option<&str> {
    proc_cgroup.lines().find_map(|line| {
        let mut parts = line.splitn(3, ':');
        let _id = parts.next()?;
        let controllers = parts.next()?;
        let path = parts.next()?;
        controllers.is_empty().then_some(path)
    })
}

/// Byte cap from `memory.max`. The token `max` means the cgroup is unlimited.
fn parse_memory_max(text: &str) -> Option<u64> {
    let text = text.trim();
    if text.is_empty() || text == "max" {
        return None;
    }
    text.parse().ok().filter(|max| *max > 0)
}

/// `inactive_file` from a `memory.stat` body. Absent means nothing to subtract.
fn parse_inactive_file(stat: &str) -> u64 {
    for line in stat.lines() {
        let mut words = line.split_whitespace();
        if words.next() == Some("inactive_file") {
            return words.next().and_then(|value| value.parse().ok()).unwrap_or(0);
        }
    }
    0
}

/// `avg10` on the `some` line of a PSI file, as a fraction from 0 to 1.
fn parse_psi_some_avg10(text: &str) -> Option<f64> {
    for line in text.lines() {
        let Some(rest) = line.strip_prefix("some ") else {
            continue;
        };
        for field in rest.split_whitespace() {
            let Some(value) = field.strip_prefix("avg10=") else {
                continue;
            };
            let percent: f64 = value.parse().ok()?;
            if percent.is_finite() {
                return Some(percent / 100.0);
            }
        }
    }
    None
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
    use super::*;

    fn near(actual: f64, expected: f64) {
        assert!((actual - expected).abs() < 1e-9, "{actual} should be near {expected}");
    }

    /// A fresh directory tree for one cgroup-walk test.
    fn scratch(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("praxis-cgroup-{name}-{}", std::process::id()));
        let _removed = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    /// Write the three memory files a cgroup directory exposes.
    fn write_level(dir: &Path, current: &str, max: &str, stat: &str) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join("memory.current"), current).unwrap();
        std::fs::write(dir.join("memory.max"), max).unwrap();
        std::fs::write(dir.join("memory.stat"), stat).unwrap();
    }

    #[test]
    fn band_is_zero_until_scaling_and_one_at_saturation() {
        let band = Band {
            scaling: 0.80,
            saturation: 0.95,
        };
        near(band_pressure(0.70, band), 0.0);
        near(band_pressure(0.80, band), 0.0);
        near(band_pressure(0.875, band), 0.5);
        near(band_pressure(0.95, band), 1.0);
        near(band_pressure(1.2, band), 1.0);
        near(band_pressure(f64::NAN, band), 0.0);
    }

    #[test]
    fn a_flat_band_stays_at_zero() {
        near(
            band_pressure(
                1.0,
                Band {
                    scaling: 0.5,
                    saturation: 0.5,
                },
            ),
            0.0,
        );
    }

    #[test]
    fn the_first_sample_is_not_pulled_toward_zero() {
        let mut monitor = Monitor::default();
        let pressures = monitor.fold(Ratios {
            cgroup_memory: None,
            heap: None,
            cpu: None,
            connections: Some(1.0),
            file_descriptors: None,
        });
        near(pressures.connections.expect("first sample"), 1.0);
    }

    #[test]
    fn a_later_sample_moves_part_way() {
        let mut monitor = Monitor::default();
        monitor.fold(Ratios {
            cgroup_memory: None,
            heap: None,
            cpu: None,
            connections: Some(0.0),
            file_descriptors: None,
        });
        let pressures = monitor.fold(Ratios {
            cgroup_memory: None,
            heap: None,
            cpu: None,
            connections: Some(1.0),
            file_descriptors: None,
        });
        // 0 below the band is pressure 0. Full usage is pressure 1.
        // Smoothed: 0 + 0.3 * (1 - 0).
        near(pressures.connections.expect("smoothed"), SMOOTHING);
    }

    #[test]
    fn a_missing_sample_keeps_the_previous_pressure() {
        let mut monitor = Monitor::default();
        monitor.fold(Ratios {
            cgroup_memory: None,
            heap: None,
            cpu: Some(1.0),
            connections: None,
            file_descriptors: None,
        });
        let pressures = monitor.fold(Ratios {
            cgroup_memory: None,
            heap: None,
            cpu: None,
            connections: None,
            file_descriptors: None,
        });
        near(pressures.cpu.expect("kept"), 1.0);
        assert!(pressures.heap.is_none(), "heap was never sampled");
    }

    #[test]
    fn connection_inputs_use_the_band() {
        let mut monitor = Monitor::default();
        let below = monitor.observe(Inputs {
            heap_max_bytes: None,
            connections: Some((50, 100)),
            file_descriptors: None,
        });
        near(below.connections.expect("below scaling"), 0.0);

        let mut saturated = Monitor::default();
        let full = saturated.observe(Inputs {
            heap_max_bytes: None,
            connections: Some((95, 100)),
            file_descriptors: None,
        });
        near(full.connections.expect("at saturation"), 1.0);
    }

    #[test]
    fn a_zero_limit_is_not_a_ratio() {
        assert!(usage_ratio(1, 0).is_none(), "zero limit has no ratio");
    }

    #[test]
    fn cgroup_v2_path_ignores_v1_lines() {
        let body = "12:memory:/old\n0::/kubepods/pod\n";
        assert_eq!(cgroup_v2_path(body), Some("/kubepods/pod"));
    }

    #[test]
    fn unlimited_cgroup_is_not_a_max() {
        assert!(parse_memory_max("max").is_none());
        assert_eq!(parse_memory_max("1048576"), Some(1_048_576));
    }

    #[test]
    fn an_unlimited_leaf_uses_the_tightest_ancestor_limit() {
        let root = scratch("ancestor");
        let parent = root.join("slice");
        let leaf = parent.join("service");
        write_level(&root, "100", "max", "inactive_file 0\n");
        write_level(&parent, "900", "1000", "inactive_file 0\n");
        write_level(&leaf, "50", "max", "inactive_file 0\n");

        let ratio = highest_cgroup_ratio(&leaf, &root).expect("parent slice is the enforced cap");
        near(ratio, 0.9);
    }

    #[test]
    fn the_highest_ancestor_ratio_wins() {
        let root = scratch("highest");
        let parent = root.join("slice");
        let leaf = parent.join("service");
        write_level(&parent, "100", "1000", "inactive_file 0\n");
        write_level(&leaf, "950", "1000", "inactive_file 50\n");

        let ratio = highest_cgroup_ratio(&leaf, &root).expect("leaf working set is higher");
        near(ratio, 0.9);
    }

    #[test]
    fn every_unlimited_cgroup_publishes_no_ratio() {
        let root = scratch("unlimited");
        let leaf = root.join("service");
        write_level(&root, "100", "max", "inactive_file 0\n");
        write_level(&leaf, "50", "max", "inactive_file 0\n");

        assert!(
            highest_cgroup_ratio(&leaf, &root).is_none(),
            "memory.max=max on every visible cgroup is not a cap"
        );
    }

    #[test]
    fn an_unreadable_finite_limit_keeps_the_previous_sample() {
        let root = scratch("unreadable");
        let parent = root.join("slice");
        let leaf = parent.join("service");
        write_level(&leaf, "100", "1000", "inactive_file 0\n");
        std::fs::create_dir_all(&parent).unwrap();
        std::fs::write(parent.join("memory.max"), "1000\n").unwrap();
        std::fs::write(parent.join("memory.current"), "900\n").unwrap();

        assert!(
            highest_cgroup_ratio(&leaf, &root).is_none(),
            "a finite parent whose memory.stat is missing must not be ignored"
        );
    }

    #[test]
    fn inactive_file_is_subtracted_from_the_working_set() {
        let stat = "anon 10\ninactive_file 300\nactive_file 5\n";
        assert_eq!(parse_inactive_file(stat), 300);
        assert_eq!(parse_inactive_file("anon 10\n"), 0);
        let ratio = working_set_ratio(1_000, 300, 1_000).expect("finite limit");
        near(ratio, 0.7);
        assert!(working_set_ratio(1_000, 300, 0).is_none(), "zero max is not a ratio");
    }

    #[test]
    fn psi_some_avg10_is_a_fraction() {
        let text = "some avg10=12.50 avg60=1.00 avg300=0.10 total=9\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n";
        near(parse_psi_some_avg10(text).expect("psi"), 0.125);
    }

    #[test]
    fn iter_skips_resources_without_a_sample() {
        let pressures = Pressures {
            cgroup_memory: None,
            heap: Some(0.25),
            cpu: None,
            connections: None,
            file_descriptors: Some(1.0),
        };
        let labels: Vec<_> = pressures.iter().map(|(resource, _)| resource).collect();
        assert_eq!(labels, ["heap", "file_descriptors"]);
    }

    // -------------------------------------------------------------------------
    // PressureState
    // -------------------------------------------------------------------------

    #[test]
    fn pressure_state_classifies_correctly() {
        assert_eq!(PressureState::from_pressure(0.0), PressureState::Idle);
        assert_eq!(PressureState::from_pressure(0.5), PressureState::Scaling);
        assert_eq!(PressureState::from_pressure(1.0), PressureState::Saturated);
        assert_eq!(PressureState::from_pressure(1e-12), PressureState::Idle);
        assert_eq!(PressureState::from_pressure(0.999_999_999_9), PressureState::Saturated);
    }

    // -------------------------------------------------------------------------
    // TransitionTracker
    // -------------------------------------------------------------------------

    #[test]
    fn first_sample_produces_a_transition() {
        let mut tracker = TransitionTracker::default();
        let pressures = Pressures {
            cgroup_memory: None,
            heap: None,
            cpu: None,
            connections: Some(0.5),
            file_descriptors: None,
        };
        let transitions = tracker.update(pressures, [None; 5]);
        assert_eq!(transitions.len(), 1, "first sample should produce one transition");
        assert_eq!(transitions[0].resource, "connections");
        assert!(transitions[0].from.is_none(), "no previous state");
        assert_eq!(transitions[0].to, PressureState::Scaling);
    }

    #[test]
    fn same_state_produces_no_transition() {
        let mut tracker = TransitionTracker::default();
        let pressures = Pressures {
            cgroup_memory: None,
            heap: None,
            cpu: None,
            connections: Some(0.5),
            file_descriptors: None,
        };
        tracker.update(pressures, [None; 5]);
        let transitions = tracker.update(pressures, [None; 5]);
        assert!(transitions.is_empty(), "same state should produce no transitions");
    }

    #[test]
    fn state_change_produces_transition() {
        let mut tracker = TransitionTracker::default();
        let scaling = Pressures {
            cgroup_memory: None,
            heap: None,
            cpu: None,
            connections: Some(0.5),
            file_descriptors: None,
        };
        tracker.update(scaling, [None; 5]);

        let saturated = Pressures {
            cgroup_memory: None,
            heap: None,
            cpu: None,
            connections: Some(1.0),
            file_descriptors: None,
        };
        let transitions = tracker.update(saturated, [None; 5]);
        assert_eq!(transitions.len(), 1, "state change should produce one transition");
        assert_eq!(transitions[0].from, Some(PressureState::Scaling));
        assert_eq!(transitions[0].to, PressureState::Saturated);
    }

    #[test]
    fn clearing_produces_idle_transition() {
        let mut tracker = TransitionTracker::default();
        let saturated = Pressures {
            cgroup_memory: None,
            heap: None,
            cpu: None,
            connections: Some(1.0),
            file_descriptors: None,
        };
        tracker.update(saturated, [None; 5]);

        let idle = Pressures {
            cgroup_memory: None,
            heap: None,
            cpu: None,
            connections: Some(0.0),
            file_descriptors: None,
        };
        let transitions = tracker.update(idle, [None; 5]);
        assert_eq!(transitions.len(), 1, "clearing should produce one transition");
        assert_eq!(transitions[0].to, PressureState::Idle);
        assert_eq!(transitions[0].from, Some(PressureState::Saturated));
    }

    #[test]
    fn sustained_raw_saturation_warns_before_the_gauge_reaches_one() {
        let mut monitor = Monitor::default();
        let mut tracker = TransitionTracker::default();
        let idle = connection_ratio(&mut monitor, 0.0);
        tracker.update(idle, monitor.raw_saturated());

        let mut warned_on = None;
        let mut pressure_at_warn = 0.0;
        for sample in 1..=5 {
            let pressures = connection_ratio(&mut monitor, 1.0);
            let transitions = tracker.update(pressures, monitor.raw_saturated());
            if transitions
                .iter()
                .any(|transition| transition.to == PressureState::Saturated)
            {
                warned_on = Some(sample);
                pressure_at_warn = pressures.connections.expect("connections sampled");
                break;
            }
        }
        assert_eq!(
            warned_on,
            Some(3),
            "three saturated samples warn; smoothing needs about a minute to reach 1"
        );
        assert!(
            pressure_at_warn < 0.9,
            "the gauge is still climbing when saturation is logged, got {pressure_at_warn}"
        );
    }

    #[test]
    fn one_saturated_sample_stays_scaling() {
        let mut monitor = Monitor::default();
        let mut tracker = TransitionTracker::default();
        tracker.update(connection_ratio(&mut monitor, 0.0), monitor.raw_saturated());
        let pressures = connection_ratio(&mut monitor, 1.0);
        let transitions = tracker.update(pressures, monitor.raw_saturated());
        assert_eq!(transitions.len(), 1, "the first saturated sample leaves idle");
        assert_eq!(transitions[0].to, PressureState::Scaling);
    }

    #[test]
    fn one_dip_does_not_clear_saturation() {
        let mut monitor = Monitor::default();
        let mut tracker = TransitionTracker::default();
        tracker.update(connection_ratio(&mut monitor, 0.0), monitor.raw_saturated());
        let mut saw_saturated = false;
        for _ in 0..3 {
            let pressures = connection_ratio(&mut monitor, 1.0);
            let transitions = tracker.update(pressures, monitor.raw_saturated());
            saw_saturated |= transitions
                .iter()
                .any(|transition| transition.to == PressureState::Saturated);
        }
        assert!(saw_saturated, "three saturated samples enter saturation");
        let dip = connection_ratio(&mut monitor, 0.0);
        let during_dip = tracker.update(dip, monitor.raw_saturated());
        assert!(during_dip.is_empty(), "one sample below saturation keeps the warning");

        let mut cleared = false;
        for _ in 0..2 {
            let pressures = connection_ratio(&mut monitor, 0.0);
            let transitions = tracker.update(pressures, monitor.raw_saturated());
            cleared = transitions
                .iter()
                .any(|transition| transition.to != PressureState::Saturated);
        }
        assert!(cleared, "three samples below saturation clear the warning");
    }

    #[test]
    fn a_saturated_sample_after_one_dip_does_not_flap() {
        let mut monitor = Monitor::default();
        let mut tracker = TransitionTracker::default();
        tracker.update(connection_ratio(&mut monitor, 0.0), monitor.raw_saturated());
        for _ in 0..3 {
            tracker.update(connection_ratio(&mut monitor, 1.0), monitor.raw_saturated());
        }
        tracker.update(connection_ratio(&mut monitor, 0.0), monitor.raw_saturated());
        let returned = tracker.update(connection_ratio(&mut monitor, 1.0), monitor.raw_saturated());
        assert!(
            returned.is_empty(),
            "one clear sample then a saturated sample stays saturated, got {} transition(s)",
            returned.len()
        );
    }

    /// Fold one connection usage ratio and return the smoothed pressures.
    fn connection_ratio(monitor: &mut Monitor, ratio: f64) -> Pressures {
        monitor.fold(Ratios {
            cgroup_memory: None,
            heap: None,
            cpu: None,
            connections: Some(ratio),
            file_descriptors: None,
        })
    }
}
